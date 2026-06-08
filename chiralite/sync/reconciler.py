"""On-connect index reconciliation between client and server.

The reconciler performs a single request/response exchange over an already-
authenticated ``FramedConnection`` to determine which files need to be sent.

::

    Client                          Server
      │                               │
      │──── SYNC_REQUEST ────────────►│
      │                               │  (server builds snapshot of its index)
      │◄─── SYNC_STATE ───────────────│
      │                               │
      │  diff(local_index, state)     │
      │  → list[FileEntry] to send    │
"""
from __future__ import annotations

from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import (
    FileEntry,
    FileEntrySnapshot,
    SyncRequestMsg,
    SyncStateMsg,
)
from chiralite.sync.index import SiloIndex

__all__ = ["ReconcileError", "client_request_sync", "server_handle_sync_request"]


class ReconcileError(Exception):
    """Raised when the reconcile exchange fails or produces an unexpected message."""


async def client_request_sync(
    framed: FramedConnection,
    local_index: SiloIndex,
) -> list[FileEntry]:
    """Send SYNC_REQUEST, receive SYNC_STATE, and return the diff.

    Args:
        framed:      Active (encrypted) FramedConnection to the server.
        local_index: The client's current SiloIndex.

    Returns:
        List of FileEntry objects representing what the local index has that
        the remote does not (or has an older version of).

    Raises:
        ReconcileError: if the server replies with an unexpected message type.
    """
    await framed.send(SyncRequestMsg())

    msg = await framed.recv()
    if not isinstance(msg, SyncStateMsg):
        raise ReconcileError(f"expected SYNC_STATE, got {type(msg).__name__}")

    remote_snapshot: dict[str, object] = {
        path: entry.model_dump()
        for path, entry in msg.records.items()
    }
    return local_index.diff(remote_snapshot)


async def server_handle_sync_request(
    framed: FramedConnection,
    local_index: SiloIndex,
) -> None:
    """Receive SYNC_REQUEST and reply with the current SYNC_STATE snapshot.

    Args:
        framed:      Active (encrypted) FramedConnection to the client.
        local_index: The server's current SiloIndex for this silo.

    Raises:
        ReconcileError: if the client sends an unexpected message type.
    """
    msg = await framed.recv()
    if not isinstance(msg, SyncRequestMsg):
        raise ReconcileError(f"expected SYNC_REQUEST, got {type(msg).__name__}")

    snapshot = local_index.to_snapshot()
    records: dict[str, FileEntrySnapshot] = {
        path: FileEntrySnapshot.model_validate(data)
        for path, data in snapshot.items()
    }
    await framed.send(
        SyncStateMsg(
            silo_id=local_index.silo_id,
            node_id=local_index.node_id,
            records=records,
        )
    )
