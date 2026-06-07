"""Tests for chiralite/transport/websocket.py."""
from __future__ import annotations

import asyncio

import pytest
import websockets.exceptions

from chiralite.transport.websocket import (
    Connection,
    ConnectionLost,
    WebSocketClient,
    WebSocketServer,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _echo_handler():
    async def handler(conn: Connection) -> None:
        try:
            while True:
                data = await conn.recv()
                await conn.send(data)
        except websockets.exceptions.ConnectionClosed:
            pass
    return handler


def _close_immediately_handler():
    async def handler(conn: Connection) -> None:
        await conn.close()
    return handler


def _collect_handler(received: list[bytes]):
    async def handler(conn: Connection) -> None:
        try:
            while True:
                data = await conn.recv()
                received.append(data)
        except websockets.exceptions.ConnectionClosed:
            pass
    return handler


async def _free_port() -> int:
    """Bind a server on port 0 to discover a free port."""
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

class TestServerLifecycle:
    async def test_serve_and_close(self):
        server = WebSocketServer("127.0.0.1", 0, _echo_handler())
        await server.serve()
        port = server.port
        assert port > 0
        await server.close()

    async def test_context_manager(self):
        async with WebSocketServer("127.0.0.1", 0, _echo_handler()) as server:
            assert server.port > 0

    async def test_handler_exception_does_not_kill_server(self):
        async def bad_handler(conn: Connection) -> None:
            raise RuntimeError("boom")

        async with WebSocketServer("127.0.0.1", 0, bad_handler) as server:
            client = WebSocketClient(f"ws://127.0.0.1:{server.port}")
            # Connection is accepted, handler raises, but server stays alive
            try:
                conn = await client.connect()
                await conn.recv()  # may raise ConnectionClosed
            except (websockets.exceptions.ConnectionClosed, ConnectionLost):
                pass
            # Server still serves new connections
            conn2 = await client.connect()
            await conn2.close()


# ---------------------------------------------------------------------------
# Echo round-trip
# ---------------------------------------------------------------------------

class TestEcho:
    async def test_send_recv_binary(self):
        async with WebSocketServer("127.0.0.1", 0, _echo_handler()) as server:
            client = WebSocketClient(f"ws://127.0.0.1:{server.port}")
            conn = await client.connect()
            await conn.send(b"\x00\x01\x02\x03")
            data = await conn.recv()
            assert data == b"\x00\x01\x02\x03"
            await conn.close()

    async def test_multiple_frames(self):
        async with WebSocketServer("127.0.0.1", 0, _echo_handler()) as server:
            client = WebSocketClient(f"ws://127.0.0.1:{server.port}")
            conn = await client.connect()
            frames = [b"frame1", b"\xff" * 256, b""]
            for f in frames:
                await conn.send(f)
                assert await conn.recv() == f
            await conn.close()

    async def test_large_frame(self):
        payload = b"x" * (1024 * 1024)  # 1 MiB
        async with WebSocketServer("127.0.0.1", 0, _echo_handler()) as server:
            client = WebSocketClient(f"ws://127.0.0.1:{server.port}")
            conn = await client.connect()
            await conn.send(payload)
            data = await conn.recv()
            assert data == payload
            await conn.close()

    async def test_remote_addr_populated(self):
        received_addr: list[str] = []

        async def capture_handler(conn: Connection) -> None:
            received_addr.append(conn.remote_addr)
            await conn.close()

        async with WebSocketServer("127.0.0.1", 0, capture_handler) as server:
            client = WebSocketClient(f"ws://127.0.0.1:{server.port}")
            conn = await client.connect()
            try:
                await conn.recv()
            except websockets.exceptions.ConnectionClosed:
                pass
            await conn.close()

        assert received_addr
        assert "127.0.0.1" in received_addr[0]


# ---------------------------------------------------------------------------
# Client connect / ConnectionLost
# ---------------------------------------------------------------------------

class TestClientConnect:
    async def test_connect_refused_raises_connection_lost(self):
        port = await _free_port()
        client = WebSocketClient(
            f"ws://127.0.0.1:{port}",
            connect_timeout=1.0,
            max_retries=1,
        )
        with pytest.raises(ConnectionLost):
            await client.connect()

    async def test_connect_with_retry_exhausts_max_retries(self):
        port = await _free_port()
        client = WebSocketClient(
            f"ws://127.0.0.1:{port}",
            connect_timeout=0.2,
            initial_delay=0.05,
            max_delay=0.1,
            max_retries=2,
            jitter=0.0,
        )
        with pytest.raises(ConnectionLost):
            await client.connect_with_retry()

    async def test_close_without_connect_is_safe(self):
        client = WebSocketClient("ws://127.0.0.1:9999")
        await client.close()  # must not raise


# ---------------------------------------------------------------------------
# Reconnect behaviour
# ---------------------------------------------------------------------------

class TestReconnect:
    async def test_client_reconnects_after_server_close(self):
        connection_count = 0

        async def counting_handler(conn: Connection) -> None:
            nonlocal connection_count
            connection_count += 1
            await conn.close()

        async with WebSocketServer("127.0.0.1", 0, counting_handler) as server:
            url = f"ws://127.0.0.1:{server.port}"
            client = WebSocketClient(
                url,
                connect_timeout=2.0,
                initial_delay=0.05,
                max_delay=0.1,
                jitter=0.0,
                max_retries=None,
            )

            # First connect
            conn = await client.connect()
            try:
                await conn.recv()  # server closes immediately → ConnectionClosed
            except websockets.exceptions.ConnectionClosed:
                pass

            # Second connect (manual retry)
            conn2 = await client.connect()
            await conn2.close()

        assert connection_count >= 2

    async def test_multiple_clients_concurrently(self):
        received: list[bytes] = []

        async with WebSocketServer("127.0.0.1", 0, _collect_handler(received)) as server:
            url = f"ws://127.0.0.1:{server.port}"

            async def _send(payload: bytes) -> None:
                c = WebSocketClient(url)
                conn = await c.connect()
                await conn.send(payload)
                await conn.close()

            await asyncio.gather(
                _send(b"client-A"),
                _send(b"client-B"),
                _send(b"client-C"),
            )
            await asyncio.sleep(0.05)  # let handlers process

        assert sorted(received) == [b"client-A", b"client-B", b"client-C"]
