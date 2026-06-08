"""SyncEngine — drives outbound file transfers over an authenticated session.

Responsibilities
----------------
* Delta / full-content decision (DELTA_THRESHOLD = 0.80).
* Chunked TRANSFER_BEGIN → TRANSFER_CHUNK × N → TRANSFER_COMMIT sequence.
* Per-path serialization (ADR-009): at most one in-flight transfer per path.
* Waiting for TRANSFER_ACK / TRANSFER_NACK before releasing the per-path lock.

The engine is intentionally stateless across sessions: the caller is
responsible for creating a new ``SyncEngine`` instance after each reconnect.
"""
from __future__ import annotations

import asyncio
import time
from uuid import UUID, uuid4

from chiralite.delta import NoDeltaFound, compute_delta
from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import (
    FileDeleteMsg,
    FileEntry,
    FileRenameMsg,
    TransferAckMsg,
    TransferBeginMsg,
    TransferChunkMsg,
    TransferCommitMsg,
    TransferNackMsg,
)

__all__ = ["TransferError", "SyncEngine"]

# Maximum chunk payload in bytes (matches server.yaml default).
CHUNK_SIZE: int = 262_144  # 256 KiB

# If len(delta) / len(new_content) exceeds this, fall back to a full transfer.
DELTA_THRESHOLD: float = 0.80


class TransferError(Exception):
    """Raised when the server replies TRANSFER_NACK or an unexpected message."""


class SyncEngine:
    """Drives outbound sync operations for a single active session.

    Args:
        framed: An encrypted ``FramedConnection`` (post-handshake).
    """

    def __init__(self, framed: FramedConnection) -> None:
        self._framed = framed
        # Per-path lock: at most one transfer in flight per path (ADR-009).
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_write(
        self,
        entry: FileEntry,
        content: bytes,
        base_content: bytes | None = None,
    ) -> str:
        """Transfer a file write (create or modify) to the remote peer.

        Automatically decides between delta and full transfer:
        * If *base_content* is provided and the delta is ≤ DELTA_THRESHOLD of
          *content*, a delta transfer is performed.
        * Otherwise a full-content transfer is used.

        Args:
            entry:        FileEntry with metadata.  ``is_full`` and
                          ``delta_base_rapidhash`` are overridden internally.
            content:      Final (full) file bytes.
            base_content: Content of the known base file for delta computation.
                          ``None`` forces a full transfer.

        Returns:
            The ``scan_result`` string from the server's TRANSFER_ACK.

        Raises:
            TransferError: if the server returns TRANSFER_NACK.
        """
        wire_entry, payload = _prepare_payload(entry, content, base_content)
        async with self._path_lock(entry.path):
            return await self._do_transfer(wire_entry, payload)

    async def send_delete(self, path: str) -> None:
        """Send a FILE_DELETE message to the remote peer.

        Args:
            path: Relative POSIX path within the silo.
        """
        async with self._path_lock(path):
            await self._framed.send(
                FileDeleteMsg(path=path, recv_ts_ns=_now_ns())
            )

    async def send_rename(self, old_path: str, new_path: str) -> None:
        """Send a FILE_RENAME message to the remote peer.

        The per-path locks for *both* paths are acquired (in sorted order to
        avoid deadlocks) before sending.

        Args:
            old_path: Current relative POSIX path.
            new_path: Target relative POSIX path.
        """
        first, second = sorted([old_path, new_path])
        async with self._path_lock(first):
            async with self._path_lock(second):
                await self._framed.send(
                    FileRenameMsg(
                        old_path=old_path,
                        new_path=new_path,
                        recv_ts_ns=_now_ns(),
                    )
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _path_lock(self, path: str) -> asyncio.Lock:
        if path not in self._locks:
            self._locks[path] = asyncio.Lock()
        return self._locks[path]

    async def _do_transfer(self, entry: FileEntry, payload: bytes) -> str:
        """Send BEGIN → CHUNKs → COMMIT → wait for ACK/NACK."""
        transfer_id: UUID = uuid4()
        chunks = _split_chunks(payload)
        chunk_count = len(chunks)

        # TRANSFER_BEGIN
        await self._framed.send(
            TransferBeginMsg(
                transfer_id=transfer_id,
                entry=entry,
                total_size=len(payload),
                chunk_count=chunk_count,
            )
        )

        # TRANSFER_CHUNK × N
        for seq, chunk in enumerate(chunks):
            await self._framed.send(
                TransferChunkMsg(
                    transfer_id=transfer_id,
                    seq=seq,
                    data=chunk,
                )
            )

        # TRANSFER_COMMIT
        await self._framed.send(
            TransferCommitMsg(
                transfer_id=transfer_id,
                rapidhash=entry.rapidhash,
            )
        )

        # Wait for ACK or NACK
        msg = await self._framed.recv()
        if isinstance(msg, TransferAckMsg):
            if msg.transfer_id != transfer_id:
                raise TransferError(
                    f"ACK for unexpected transfer_id {msg.transfer_id}"
                )
            return msg.scan_result
        if isinstance(msg, TransferNackMsg):
            if msg.transfer_id != transfer_id:
                raise TransferError(
                    f"NACK for unexpected transfer_id {msg.transfer_id}"
                )
            raise TransferError(f"transfer rejected: {msg.reason}")
        raise TransferError(
            f"expected ACK/NACK, got {type(msg).__name__}"
        )


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _prepare_payload(
    entry: FileEntry,
    content: bytes,
    base_content: bytes | None,
) -> tuple[FileEntry, bytes]:
    """Decide delta vs full and build a wire-ready (entry, payload) pair."""
    if base_content is not None and entry.delta_base_rapidhash is not None:
        try:
            delta = compute_delta(base_content, content)
            if len(delta) / max(len(content), 1) <= DELTA_THRESHOLD:
                wire_entry = entry.model_copy(update={"is_full": False})
                return wire_entry, delta
        except NoDeltaFound:
            pass

    # Fall back to full transfer
    wire_entry = entry.model_copy(
        update={"is_full": True, "delta_base_rapidhash": None}
    )
    return wire_entry, content


def _split_chunks(data: bytes) -> list[bytes]:
    """Split *data* into CHUNK_SIZE-sized pieces (last chunk may be smaller)."""
    if not data:
        return [b""]
    chunks: list[bytes] = []
    offset = 0
    while offset < len(data):
        chunks.append(data[offset : offset + CHUNK_SIZE])
        offset += CHUNK_SIZE
    return chunks


def _now_ns() -> int:
    return time.time_ns()
