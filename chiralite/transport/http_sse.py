"""HTTP SSE transport — fallback for environments where WebSocket is blocked.

Client→server traffic uses HTTP POST.
Server→client traffic uses HTTP SSE (Server-Sent Events) on a persistent GET.

Handshake (2 round-trips):
    POST /v1/handshake          body=HELLO (plain JSON)  → CHALLENGE (plain JSON)
    POST /v1/handshake/{hid}    body=RESPONSE            → ACCEPT

Session (after handshake):
    POST /v1/session/{token}/msg          body=encrypted frame  → 202
    GET  /v1/session/{token}/events       → SSE stream

The session token (hex) is derived from the ACCEPT message and used to route
all subsequent requests to the correct session.

aiohttp is required: pip install aiohttp>=3.9
"""
from __future__ import annotations

import asyncio
import base64
import logging
import ssl
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import UUID

from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp import web

from chiralite.transport import IConnection

__all__ = [
    "ConnectionLostHttp",
    "HttpSseClientConn",
    "build_http_app",
]

log = logging.getLogger(__name__)

_HANDSHAKE_TIMEOUT = 30.0   # seconds per handshake step
_SESSION_TIMEOUT   = 10.0   # seconds for POST /msg
_SSE_RETRY_MS      = 3_000  # SSE retry hint sent to client

# ── Exceptions ─────────────────────────────────────────────────────────────────

class ConnectionLostHttp(Exception):
    """Raised by HttpSseClientConn when the server cannot be reached."""


# ── In-memory bidirectional connection ─────────────────────────────────────────

class _InMemConn:
    """IConnection backed by two asyncio queues.

    Used to bridge the handshake/session orchestrators (which expect an
    IConnection) with the HTTP handler coroutines that feed/drain those queues.

    From the perspective of the *local* side:
        send(data) → puts data into send_q (the remote's recv_q)
        recv()     → waits on recv_q (the remote puts data there via its send())
    """

    def __init__(
        self,
        send_q: asyncio.Queue[bytes],
        recv_q: asyncio.Queue[bytes],
        remote_addr: str,
    ) -> None:
        self.remote_addr = remote_addr
        self._sq = send_q
        self._rq = recv_q

    async def send(self, data: bytes) -> None:
        await self._sq.put(data)

    async def recv(self) -> bytes:
        return await self._rq.get()

    async def close(self) -> None:
        pass


def make_conn_pair(remote_addr: str) -> tuple[_InMemConn, _InMemConn]:
    """Return two ``_InMemConn`` objects wired together (like a socket pair)."""
    q_ab: asyncio.Queue[bytes] = asyncio.Queue()
    q_ba: asyncio.Queue[bytes] = asyncio.Queue()
    side_a = _InMemConn(send_q=q_ab, recv_q=q_ba, remote_addr=remote_addr)
    side_b = _InMemConn(send_q=q_ba, recv_q=q_ab, remote_addr=remote_addr)
    return side_a, side_b


# ── Client-side HTTP SSE connection ────────────────────────────────────────────

class HttpSseClientConn:
    """IConnection implemented over HTTP POST (send) + SSE (recv).

    Usage::

        conn = HttpSseClientConn("https://host:443", ssl_ctx=ctx)
        await conn.connect()
        framed = FramedConnection(conn)
        ...
        await conn.close()
    """

    def __init__(
        self,
        base_url: str,
        *,
        session_token: bytes,
        ssl_ctx: ssl.SSLContext | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token_hex = session_token.hex()
        self._ssl_ctx = ssl_ctx
        self._session: ClientSession | None = None
        self._sse_task: asyncio.Task[None] | None = None
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self.remote_addr: str = base_url

    @classmethod
    async def from_handshake(
        cls,
        base_url: str,
        *,
        ssl_ctx: ssl.SSLContext | None = None,
    ) -> tuple["HttpSseClientConn", _InMemConn]:
        """Perform the 2-step HTTP handshake and return the active connection.

        The returned ``_InMemConn`` is the *client side* of the in-memory pipe
        that ``perform_client_handshake()`` should use.  This method drives the
        HTTP exchange while the handshake coroutine drives the in-memory pipe.

        Typical usage::

            http_conn, pipe = await HttpSseClientConn.from_handshake(url)
            framed_pipe = FramedConnection(pipe)
            result = await perform_client_handshake(framed_pipe, ...)
            # result.session_token is now set; http_conn is ready
        """
        connector = TCPConnector(ssl=ssl_ctx)
        timeout = ClientTimeout(total=_HANDSHAKE_TIMEOUT)
        session = ClientSession(connector=connector, timeout=timeout)

        # pipe_client is given to perform_client_handshake
        # pipe_server drives our HTTP exchange
        pipe_client, pipe_server = make_conn_pair(base_url)

        async def _drive_handshake() -> bytes:
            """Shuttle HELLO/RESPONSE from the pipe to HTTP, return session_token."""
            # Step 1: get HELLO from handshake coroutine, POST it, get CHALLENGE back
            hello_bytes = await pipe_server.recv()
            async with session.post(
                f"{base_url}/v1/handshake", data=hello_bytes,
                headers={"Content-Type": "application/octet-stream"},
            ) as resp:
                resp.raise_for_status()
                body = await resp.read()
                hid = resp.headers.get("X-Chiralite-Hid", "")
            await pipe_server.send(body)   # give CHALLENGE to handshake coroutine

            # Step 2: get RESPONSE from handshake coroutine, POST it, get ACCEPT back
            response_bytes = await pipe_server.recv()
            async with session.post(
                f"{base_url}/v1/handshake/{hid}", data=response_bytes,
                headers={"Content-Type": "application/octet-stream"},
            ) as resp:
                resp.raise_for_status()
                accept_bytes = await resp.read()
                token_hex = resp.headers.get("X-Chiralite-Token", "")
            await pipe_server.send(accept_bytes)  # give ACCEPT to handshake coroutine

            return bytes.fromhex(token_hex)

        token = await _drive_handshake()
        conn = cls(base_url, session_token=token, ssl_ctx=ssl_ctx)
        conn._session = session
        await conn._start_sse()
        return conn, pipe_client

    async def _start_sse(self) -> None:
        """Start the background task that reads SSE events into _inbound."""
        self._sse_task = asyncio.create_task(self._sse_reader(), name="sse-reader")

    async def _sse_reader(self) -> None:
        """Background task: drain SSE stream into _inbound queue."""
        url = f"{self._base}/v1/session/{self._token_hex}/events"
        assert self._session is not None
        try:
            async with self._session.get(
                url,
                headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
                timeout=ClientTimeout(total=None),  # no timeout — persistent stream
            ) as resp:
                resp.raise_for_status()
                async for line_bytes in resp.content:
                    line = line_bytes.decode().strip()
                    if line.startswith("data:"):
                        payload = base64.b64decode(line[5:].strip())
                        await self._inbound.put(payload)
        except Exception as exc:
            log.debug("SSE reader exited: %s", exc)
            # Signal EOF to any waiting recv() caller
            await self._inbound.put(b"")

    async def send(self, data: bytes) -> None:
        """POST an encrypted frame to the server."""
        if self._session is None:
            raise ConnectionLostHttp("not connected")
        url = f"{self._base}/v1/session/{self._token_hex}/msg"
        try:
            async with self._session.post(
                url, data=data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=ClientTimeout(total=_SESSION_TIMEOUT),
            ) as resp:
                resp.raise_for_status()
        except Exception as exc:
            raise ConnectionLostHttp(f"POST /msg failed: {exc}") from exc

    async def recv(self) -> bytes:
        """Wait for the next SSE-delivered frame."""
        data = await self._inbound.get()
        if data == b"":
            raise ConnectionLostHttp("SSE stream closed")
        return data

    async def close(self) -> None:
        if self._sse_task is not None:
            self._sse_task.cancel()
            try:
                await self._sse_task
            except asyncio.CancelledError:
                pass
        if self._session is not None:
            await self._session.close()
            self._session = None


# ── Server-side HTTP application ───────────────────────────────────────────────

class _PendingHandshake:
    """State for a half-completed HTTP handshake (between step 1 and step 2)."""

    def __init__(self, remote_addr: str) -> None:
        # Queues: server side sees client→server in inq, server→client in outq
        self.inq:  asyncio.Queue[bytes] = asyncio.Queue()
        self.outq: asyncio.Queue[bytes] = asyncio.Queue()
        # server_conn is given to perform_server_handshake
        self.server_conn = _InMemConn(
            send_q=self.outq,
            recv_q=self.inq,
            remote_addr=remote_addr,
        )
        self.task: asyncio.Task[Any] | None = None
        self.session_token: bytes | None = None
        self.error: BaseException | None = None


class _ActiveSession:
    """State for an established HTTP session."""

    def __init__(self, remote_addr: str) -> None:
        self.inq:  asyncio.Queue[bytes] = asyncio.Queue()
        self.outq: asyncio.Queue[bytes] = asyncio.Queue()
        self.conn = _InMemConn(
            send_q=self.outq,
            recv_q=self.inq,
            remote_addr=remote_addr,
        )


SessionHandler = Callable[[IConnection], Awaitable[None]]


def build_http_app(on_connection: SessionHandler) -> web.Application:
    """Build the aiohttp Application for the HTTP SSE transport.

    Args:
        on_connection: async callable receiving an ``IConnection`` for each new
                       session.  Equivalent to the WebSocket handler in
                       ``WebSocketServer`` — it wraps the conn in a
                       ``FramedConnection``, runs the handshake and session loop.
    """
    # Shared state (lives in the closure — safe for single-process use)
    pending:  dict[str, _PendingHandshake] = {}   # hid → _PendingHandshake
    sessions: dict[str, _ActiveSession]   = {}   # token_hex → _ActiveSession

    # ------------------------------------------------------------------
    # Handshake step 1: POST /v1/handshake
    # ------------------------------------------------------------------

    async def handle_hello(request: web.Request) -> web.Response:
        hello_bytes = await request.read()
        remote = request.remote or "unknown"
        hid = uuid.uuid4().hex

        state = _PendingHandshake(remote_addr=remote)
        pending[hid] = state

        # Start the server handshake coroutine in a task; it will block at recv()
        # waiting for RESPONSE after it sends CHALLENGE.
        async def _run_handshake() -> None:
            await on_connection(state.server_conn)

        state.task = asyncio.create_task(_run_handshake(), name=f"hs-{hid}")

        # Feed HELLO into the handshake task, wait for CHALLENGE out
        await state.inq.put(hello_bytes)
        try:
            challenge_bytes = await asyncio.wait_for(state.outq.get(), _HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            pending.pop(hid, None)
            return web.Response(status=504, text="handshake timeout")

        return web.Response(
            body=challenge_bytes,
            content_type="application/octet-stream",
            headers={"X-Chiralite-Hid": hid},
        )

    # ------------------------------------------------------------------
    # Handshake step 2: POST /v1/handshake/{hid}
    # ------------------------------------------------------------------

    async def handle_response(request: web.Request) -> web.Response:
        hid = request.match_info["hid"]
        state = pending.pop(hid, None)
        if state is None:
            return web.Response(status=404, text="handshake not found")

        response_bytes = await request.read()
        await state.inq.put(response_bytes)

        # Wait for ACCEPT from the handshake task
        try:
            accept_bytes = await asyncio.wait_for(state.outq.get(), _HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError:
            return web.Response(status=504, text="handshake timeout")

        # Wait briefly for the task to store the session_token
        try:
            await asyncio.wait_for(state.outq.get(), 1.0)
        except asyncio.TimeoutError:
            pass

        if state.session_token is None:
            return web.Response(status=403, text="handshake rejected")

        token_hex = state.session_token.hex()
        session = _ActiveSession(remote_addr=request.remote or "unknown")
        sessions[token_hex] = session

        # Hand the session conn off to the on_connection handler
        # (the handshake task has already activated the codec; pass the session conn)
        asyncio.create_task(
            on_connection(session.conn), name=f"sess-{token_hex[:8]}"
        )

        return web.Response(
            body=accept_bytes,
            content_type="application/octet-stream",
            headers={"X-Chiralite-Token": token_hex},
        )

    # ------------------------------------------------------------------
    # Session: POST /v1/session/{token}/msg
    # ------------------------------------------------------------------

    async def handle_msg(request: web.Request) -> web.Response:
        token_hex = request.match_info["token"]
        session = sessions.get(token_hex)
        if session is None:
            return web.Response(status=404, text="session not found")
        data = await request.read()
        await session.inq.put(data)
        return web.Response(status=202)

    # ------------------------------------------------------------------
    # Session: GET /v1/session/{token}/events  (SSE stream)
    # ------------------------------------------------------------------

    async def handle_events(request: web.Request) -> web.StreamResponse:
        token_hex = request.match_info["token"]
        session = sessions.get(token_hex)
        if session is None:
            return web.Response(status=404, text="session not found")

        resp = web.StreamResponse(
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # disable nginx buffering
            }
        )
        await resp.prepare(request)
        await resp.write(f"retry: {_SSE_RETRY_MS}\n\n".encode())

        try:
            while True:
                frame = await session.outq.get()
                encoded = base64.b64encode(frame).decode()
                await resp.write(f"data: {encoded}\n\n".encode())
        except (asyncio.CancelledError, ConnectionResetError):
            pass
        finally:
            await resp.write_eof()

        return resp

    # ------------------------------------------------------------------
    # App assembly
    # ------------------------------------------------------------------

    app = web.Application()
    app.router.add_post("/v1/handshake",          handle_hello)
    app.router.add_post("/v1/handshake/{hid}",    handle_response)
    app.router.add_post("/v1/session/{token}/msg", handle_msg)
    app.router.add_get( "/v1/session/{token}/events", handle_events)
    return app
