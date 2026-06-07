"""WebSocket transport layer — thin wrappers around `websockets`.

No business logic, framing, or encryption lives here.  This module provides:

* ``Connection`` — shared send/recv interface for client and server sides.
* ``WebSocketClient`` — reconnecting client with exponential backoff.
* ``WebSocketServer`` — server that dispatches each connection to a handler.

All frames are binary (``websockets.Data`` opcode BINARY).
"""
from __future__ import annotations

import asyncio
import logging
import random
import ssl
from pathlib import Path
from typing import Callable, Awaitable

import websockets
import websockets.exceptions
from websockets import ServerConnection, ClientConnection

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConnectionLost(Exception):
    """Raised by WebSocketClient when the connection cannot be (re)established."""


# ---------------------------------------------------------------------------
# Connection — shared client/server interface
# ---------------------------------------------------------------------------

class Connection:
    """Thin wrapper around a websockets connection object."""

    def __init__(self, ws: ClientConnection | ServerConnection, remote_addr: str) -> None:
        self._ws = ws
        self.remote_addr = remote_addr

    async def send(self, data: bytes) -> None:
        """Send a binary frame."""
        await self._ws.send(data)

    async def recv(self) -> bytes:
        """Receive the next binary frame.

        Raises:
            websockets.exceptions.ConnectionClosed: when the peer closes.
        """
        msg = await self._ws.recv()
        if isinstance(msg, str):
            raise TypeError(f"received text frame, expected binary: {msg!r}")
        return msg

    async def close(self) -> None:
        await self._ws.close()


# ---------------------------------------------------------------------------
# WebSocketServer
# ---------------------------------------------------------------------------

Handler = Callable[[Connection], Awaitable[None]]


class WebSocketServer:
    """wss:// server that dispatches each connection to *handler*.

    Args:
        host:    Bind address (e.g. ``"0.0.0.0"`` or ``"localhost"``).
        port:    Bind port.
        handler: Async function called once per accepted connection.
        ssl_ctx: Optional TLS context.  Pass ``None`` for plain ws:// (tests).
    """

    def __init__(
        self,
        host: str,
        port: int,
        handler: Handler,
        *,
        ssl_ctx: ssl.SSLContext | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._handler = handler
        self._ssl_ctx = ssl_ctx
        self._server: websockets.Server | None = None

    async def _dispatch(self, ws: ServerConnection) -> None:
        addr = f"{ws.remote_address[0]}:{ws.remote_address[1]}" if ws.remote_address else "unknown"
        conn = Connection(ws, remote_addr=addr)
        try:
            await self._handler(conn)
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception:
            log.exception("unhandled error in WebSocket handler from %s", addr)

    async def serve(self) -> None:
        """Start listening.  Returns once the server socket is bound."""
        self._server = await websockets.serve(
            self._dispatch,
            self._host,
            self._port,
            ssl=self._ssl_ctx,
            compression=None,
            max_size=None,
        )
        log.info("WebSocketServer listening on %s:%d", self._host, self._port)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log.info("WebSocketServer closed")

    async def __aenter__(self) -> "WebSocketServer":
        await self.serve()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @property
    def port(self) -> int:
        """Actual bound port (useful when port=0 was requested)."""
        if self._server is None:
            raise RuntimeError("server not started")
        sockets = self._server.sockets
        if not sockets:
            raise RuntimeError("no sockets")
        return sockets[0].getsockname()[1]


# ---------------------------------------------------------------------------
# WebSocketClient
# ---------------------------------------------------------------------------

class WebSocketClient:
    """Reconnecting wss:// client with exponential backoff.

    Usage::

        client = WebSocketClient("ws://localhost:8765")
        conn = await client.connect()     # initial connect
        await conn.send(b"hello")
        data = await conn.recv()
        await client.reconnect()          # force reconnect (e.g. after ConnectionClosed)

    Or use the higher-level ``run`` method which owns the reconnect loop.

    Args:
        url:             WebSocket URL (``ws://`` or ``wss://``).
        ssl_ctx:         TLS context for ``wss://``.  None for plain ``ws://``.
        connect_timeout: Seconds to wait for the initial TCP + WS handshake.
        initial_delay:   First backoff delay in seconds.
        max_delay:       Backoff cap in seconds.
        max_retries:     Raise ``ConnectionLost`` after this many consecutive failures.
                         ``None`` means retry forever.
        jitter:          Add up to *jitter* seconds of random noise to each delay.
    """

    def __init__(
        self,
        url: str,
        *,
        ssl_ctx: ssl.SSLContext | None = None,
        connect_timeout: float = 10.0,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int | None = None,
        jitter: float = 0.5,
    ) -> None:
        self._url = url
        self._ssl_ctx = ssl_ctx
        self._connect_timeout = connect_timeout
        self._initial_delay = initial_delay
        self._max_delay = max_delay
        self._max_retries = max_retries
        self._jitter = jitter
        self._conn: Connection | None = None

    async def connect(self) -> Connection:
        """Establish a connection (no retry).

        Raises:
            ConnectionLost: if the connection attempt fails.
        """
        try:
            ws: ClientConnection = await asyncio.wait_for(
                websockets.connect(
                    self._url,
                    ssl=self._ssl_ctx,
                    compression=None,
                    max_size=None,
                    open_timeout=None,  # we wrap with wait_for ourselves
                ),
                timeout=self._connect_timeout,
            )
        except (OSError, websockets.exceptions.WebSocketException, asyncio.TimeoutError) as exc:
            raise ConnectionLost(f"failed to connect to {self._url}: {exc}") from exc

        remote = str(ws.remote_address) if ws.remote_address else self._url
        self._conn = Connection(ws, remote_addr=remote)
        log.debug("connected to %s", self._url)
        return self._conn

    async def connect_with_retry(self) -> Connection:
        """Connect with exponential backoff.

        Raises:
            ConnectionLost: after *max_retries* consecutive failures.
        """
        delay = self._initial_delay
        attempt = 0
        while True:
            try:
                return await self.connect()
            except ConnectionLost:
                attempt += 1
                if self._max_retries is not None and attempt >= self._max_retries:
                    raise ConnectionLost(
                        f"gave up connecting to {self._url} after {attempt} attempts"
                    )
                noise = random.uniform(0, self._jitter)
                wait = min(delay + noise, self._max_delay)
                log.warning(
                    "connection attempt %d failed, retrying in %.1fs", attempt, wait
                )
                await asyncio.sleep(wait)
                delay = min(delay * 2, self._max_delay)

    @property
    def connection(self) -> Connection | None:
        return self._conn

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None


# ---------------------------------------------------------------------------
# TLS context helpers
# ---------------------------------------------------------------------------

def client_ssl_context(ca_bundle: Path) -> ssl.SSLContext:
    """Return an SSL context that trusts *ca_bundle* and no system CAs."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(ca_bundle))
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def server_ssl_context(cert: Path, key: Path) -> ssl.SSLContext:
    """Return an SSL context for a wss:// server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx
