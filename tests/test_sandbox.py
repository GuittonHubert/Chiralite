"""Tests for chiralite/sandbox/tmpfs.py and chiralite/sandbox/clamav.py."""
from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest

from chiralite.sandbox.clamav import ClamdClient, SandboxError, ScanResult
from chiralite.sandbox.tmpfs import SandboxError as TmpfsSandboxError
from chiralite.sandbox.tmpfs import TmpfsWorkspace

# ---------------------------------------------------------------------------
# Fake clamd Unix-socket server
# ---------------------------------------------------------------------------

class _FakeClamd:
    """Minimal clamd INSTREAM server for testing."""

    def __init__(self, response: bytes) -> None:
        self._response = response
        self._server: asyncio.Server | None = None
        self.socket_path: Path | None = None
        self.received_data: bytes = b""

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            cmd = await reader.readuntil(b"\x00")
            if cmd == b"zPING\x00":
                writer.write(b"PONG\n")
                await writer.drain()
                return
            if cmd == b"zINSTREAM\x00":
                buf = bytearray()
                while True:
                    size_bytes = await reader.readexactly(4)
                    (size,) = struct.unpack(">I", size_bytes)
                    if size == 0:
                        break
                    chunk = await reader.readexactly(size)
                    buf.extend(chunk)
                self.received_data = bytes(buf)
                writer.write(self._response)
                await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self, socket_path: Path) -> None:
        self.socket_path = socket_path
        self._server = await asyncio.start_unix_server(
            self._handle, path=str(socket_path)
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()


@pytest.fixture
async def clean_clamd(tmp_path: Path):
    sock = tmp_path / "clamd.ctl"
    srv = _FakeClamd(b"stream: OK\n")
    await srv.start(sock)
    yield srv
    await srv.stop()


@pytest.fixture
async def infected_clamd(tmp_path: Path):
    sock = tmp_path / "clamd.ctl"
    srv = _FakeClamd(b"stream: Eicar-Test-Signature FOUND\n")
    await srv.start(sock)
    yield srv
    await srv.stop()


@pytest.fixture
async def error_clamd(tmp_path: Path):
    sock = tmp_path / "clamd.ctl"
    srv = _FakeClamd(b"ERROR: lzma unpack support not compiled in\n")
    await srv.start(sock)
    yield srv
    await srv.stop()


# ---------------------------------------------------------------------------
# TmpfsWorkspace
# ---------------------------------------------------------------------------

class TestTmpfsWorkspace:
    def test_workspace_created_on_enter(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="s1", transfer_id="t1") as ws:
            assert ws.path.is_dir()

    def test_workspace_removed_on_exit(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="s1", transfer_id="t1") as ws:
            wspath = ws.path
        assert not wspath.exists()

    def test_session_dir_removed_when_empty(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="s1", transfer_id="t1"):
            pass
        assert not (tmp_path / "s1").exists()

    def test_write_and_read(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t") as ws:
            dest = ws.write("file.bin", b"\xde\xad\xbe\xef")
            assert dest.exists()
            assert ws.read("file.bin") == b"\xde\xad\xbe\xef"

    def test_cleanup_on_exception(self, tmp_path: Path) -> None:
        wspath: Path | None = None
        try:
            with TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t") as ws:
                wspath = ws.path
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert wspath is not None
        assert not wspath.exists()

    def test_multiple_transfers_same_session(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t1") as ws1:
            ws1.write("a.bin", b"aaa")
            with TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t2") as ws2:
                ws2.write("b.bin", b"bbb")
        assert not (tmp_path / "s" / "t1").exists()
        assert not (tmp_path / "s" / "t2").exists()

    def test_missing_mount_raises(self, tmp_path: Path) -> None:
        with pytest.raises(TmpfsSandboxError, match="does not exist"):
            TmpfsWorkspace(tmp_path / "nonexistent", session_id="s", transfer_id="t")

    def test_path_before_enter_raises(self, tmp_path: Path) -> None:
        ws = TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t")
        with pytest.raises(TmpfsSandboxError):
            _ = ws.path

    def test_workspace_path_structure(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="mysession", transfer_id="mytransfer") as ws:
            assert ws.path == tmp_path / "mysession" / "mytransfer"

    def test_duplicate_workspace_raises(self, tmp_path: Path) -> None:
        with TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t"):
            with pytest.raises(TmpfsSandboxError):
                TmpfsWorkspace(tmp_path, session_id="s", transfer_id="t").__enter__()


# ---------------------------------------------------------------------------
# ClamdClient — scan results
# ---------------------------------------------------------------------------

class TestClamdScan:
    async def test_clean_result(self, clean_clamd: _FakeClamd) -> None:
        client = ClamdClient(socket_path=clean_clamd.socket_path, scan_timeout_s=5.0)
        result = await client.scan(b"safe content")
        assert result.is_clean
        assert result.virus_name is None
        assert result.error is None

    async def test_infected_result(self, infected_clamd: _FakeClamd) -> None:
        client = ClamdClient(socket_path=infected_clamd.socket_path, scan_timeout_s=5.0)
        result = await client.scan(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
        assert not result.is_clean
        assert result.virus_name == "Eicar-Test-Signature"
        assert result.error is None

    async def test_error_result(self, error_clamd: _FakeClamd) -> None:
        client = ClamdClient(socket_path=error_clamd.socket_path, scan_timeout_s=5.0)
        result = await client.scan(b"some data")
        assert not result.is_clean
        assert result.error is not None

    async def test_data_transmitted_correctly(self, clean_clamd: _FakeClamd) -> None:
        payload = b"hello world " * 1000
        client = ClamdClient(socket_path=clean_clamd.socket_path, scan_timeout_s=5.0)
        await client.scan(payload)
        assert clean_clamd.received_data == payload

    async def test_large_payload_chunked(self, clean_clamd: _FakeClamd) -> None:
        # >64 KiB — exercises the chunking loop
        payload = b"A" * (100 * 1024)
        client = ClamdClient(socket_path=clean_clamd.socket_path, scan_timeout_s=5.0)
        result = await client.scan(payload)
        assert result.is_clean
        assert clean_clamd.received_data == payload

    async def test_empty_payload(self, clean_clamd: _FakeClamd) -> None:
        client = ClamdClient(socket_path=clean_clamd.socket_path, scan_timeout_s=5.0)
        result = await client.scan(b"")
        assert result.is_clean

    async def test_unreachable_socket_raises(self, tmp_path: Path) -> None:
        client = ClamdClient(
            socket_path=tmp_path / "no-such.ctl", scan_timeout_s=2.0
        )
        with pytest.raises(SandboxError, match="cannot connect"):
            await client.scan(b"data")

    async def test_timeout_raises(self, tmp_path: Path) -> None:
        sock = tmp_path / "slow.ctl"

        # Server that accepts but never responds
        async def _slow(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(10)

        server = await asyncio.start_unix_server(_slow, path=str(sock))
        try:
            client = ClamdClient(socket_path=sock, scan_timeout_s=0.1)
            with pytest.raises(SandboxError, match="timed out"):
                await client.scan(b"data")
        finally:
            server.close()
            await server.wait_closed()


# ---------------------------------------------------------------------------
# ClamdClient — ping
# ---------------------------------------------------------------------------

class TestClamdPing:
    async def test_ping_clean_server(self, clean_clamd: _FakeClamd) -> None:
        client = ClamdClient(socket_path=clean_clamd.socket_path)
        assert await client.ping() is True

    async def test_ping_unreachable(self, tmp_path: Path) -> None:
        client = ClamdClient(socket_path=tmp_path / "missing.ctl")
        assert await client.ping() is False


# ---------------------------------------------------------------------------
# ScanResult helpers
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_clean(self) -> None:
        r = ScanResult.make_clean()
        assert r.is_clean
        assert str(r) == "CLEAN"

    def test_infected(self) -> None:
        r = ScanResult.make_infected("Eicar-Test-Signature")
        assert not r.is_clean
        assert r.virus_name == "Eicar-Test-Signature"
        assert str(r) == "INFECTED:Eicar-Test-Signature"

    def test_error(self) -> None:
        r = ScanResult.make_error("lzma not supported")
        assert not r.is_clean
        assert r.error == "lzma not supported"
        assert str(r) == "ERROR:lzma not supported"
