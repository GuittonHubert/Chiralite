"""Async ClamAV client via clamd Unix socket (INSTREAM protocol).

Never shells out to ``clamscan``.  The ``clamd`` daemon keeps virus signatures
loaded in memory; scan latency is ~5 ms for small files, compared to ~300 ms
for a ``clamscan`` subprocess startup.

INSTREAM wire format::

    C → zINSTREAM\\0
    C → <uint32 BE: chunk_size><chunk_bytes>   (repeat)
    C → \\x00\\x00\\x00\\x00                      (end-of-stream sentinel)
    S → "stream: OK\\n"                         (clean)
    S → "stream: <name> FOUND\\n"              (infected)
    S → "ERROR: <reason>\\n"                   (scan error)
"""
from __future__ import annotations

import asyncio
import dataclasses
import logging
import struct
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_SOCKET = Path("/var/run/clamav/clamd.ctl")
_DEFAULT_TIMEOUT = 30.0
_CHUNK_SIZE = 65536  # 64 KiB per INSTREAM chunk


class SandboxError(Exception):
    """Raised when the clamd connection fails or returns an unexpected response."""


@dataclasses.dataclass(frozen=True)
class ScanResult:
    """Result of a ClamAV INSTREAM scan."""

    is_clean: bool
    virus_name: str | None = None   # set when is_clean=False and no error
    error: str | None = None        # set on scan error (clamd malfunction)

    @classmethod
    def make_clean(cls) -> "ScanResult":
        return cls(is_clean=True)

    @classmethod
    def make_infected(cls, virus_name: str) -> "ScanResult":
        return cls(is_clean=False, virus_name=virus_name)

    @classmethod
    def make_error(cls, reason: str) -> "ScanResult":
        return cls(is_clean=False, error=reason)

    def __str__(self) -> str:
        if self.is_clean:
            return "CLEAN"
        if self.virus_name:
            return f"INFECTED:{self.virus_name}"
        return f"ERROR:{self.error}"


class ClamdClient:
    """Async client to a running ``clamd`` Unix socket daemon.

    Args:
        socket_path:   Path to the clamd Unix domain socket.
        scan_timeout_s: Seconds before the scan is cancelled.
    """

    def __init__(
        self,
        socket_path: Path = _DEFAULT_SOCKET,
        scan_timeout_s: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.socket_path = socket_path
        self.scan_timeout_s = scan_timeout_s

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """Send ``zPING\\0`` and verify the response is ``PONG``.

        Returns True on success, False if clamd is unreachable.
        """
        try:
            reader, writer = await self._connect()
            writer.write(b"zPING\x00")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5.0)
            writer.close()
            await writer.wait_closed()
            return resp.strip() == b"PONG"
        except Exception:
            return False

    async def scan(self, data: bytes) -> ScanResult:
        """Scan *data* in-memory via the INSTREAM protocol.

        Raises:
            SandboxError: if the clamd socket is unreachable or the response
                is malformed.
        """
        try:
            return await asyncio.wait_for(self._scan(data), timeout=self.scan_timeout_s)
        except asyncio.TimeoutError as exc:
            raise SandboxError(
                f"clamd scan timed out after {self.scan_timeout_s}s"
            ) from exc

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.open_unix_connection(str(self.socket_path))
        except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
            raise SandboxError(
                f"cannot connect to clamd at {self.socket_path}: {exc}"
            ) from exc

    async def _scan(self, data: bytes) -> ScanResult:
        reader, writer = await self._connect()
        try:
            # Send INSTREAM command
            writer.write(b"zINSTREAM\x00")

            # Stream data in chunks
            offset = 0
            while offset < len(data):
                chunk = data[offset : offset + _CHUNK_SIZE]
                writer.write(struct.pack(">I", len(chunk)))
                writer.write(chunk)
                offset += len(chunk)

            # End-of-stream sentinel
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()

            # Read response
            response_line = await reader.readline()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        return _parse_response(response_line.decode(errors="replace").strip())


def _parse_response(line: str) -> ScanResult:
    """Parse a clamd INSTREAM response line into a ScanResult."""
    if not line:
        raise SandboxError("clamd returned an empty response")

    if line == "stream: OK":
        return ScanResult.make_clean()

    if line.endswith(" FOUND"):
        # "stream: Eicar-Test-Signature FOUND"
        parts = line.removeprefix("stream: ").removesuffix(" FOUND")
        return ScanResult.make_infected(virus_name=parts)

    if line.startswith("ERROR:") or line.startswith("stream: ERROR"):
        reason = line.split(":", 1)[-1].strip()
        return ScanResult.make_error(reason=reason)

    raise SandboxError(f"unexpected clamd response: {line!r}")
