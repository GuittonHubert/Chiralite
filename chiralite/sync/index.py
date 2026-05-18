"""In-memory sync state: FileRecord, SiloIndex, and typed events.

No I/O lives here — the index is purely in-memory.  Durability is provided by
the EventJournal (sync/journal.py) which replays pending entries on startup.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Literal
from uuid import UUID

from chiralite.protocol.messages import FileEntry


# ---------------------------------------------------------------------------
# FileRecord — one row in the SiloIndex
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class FileRecord:
    """In-memory representation of a tracked file."""

    rapidhash: int    # uint64, change-detection key
    size: int
    mtime_s: int      # Unix seconds (int64)
    mtime_ns: int     # sub-second nanoseconds, 0–999_999_999 (int32)
    recv_ts_ns: int   # server clock at last sync — LWW tiebreaker
    mode: int         # POSIX permission bits
    uid_name: str     # symbolic only, never numeric
    gid_name: str
    deleted: bool = False  # tombstone: True means the file no longer exists


# ---------------------------------------------------------------------------
# Typed sync events
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class WriteEvent:
    """A file was created or modified."""

    path: str
    rapidhash: int
    size: int
    mtime_s: int
    mtime_ns: int
    recv_ts_ns: int
    mode: int
    uid_name: str
    gid_name: str


@dataclasses.dataclass(frozen=True)
class DeleteEvent:
    """A file was removed."""

    path: str
    recv_ts_ns: int


@dataclasses.dataclass(frozen=True)
class RenameEvent:
    """A file was renamed / moved within the silo."""

    old_path: str
    new_path: str
    recv_ts_ns: int


SyncEvent = WriteEvent | DeleteEvent | RenameEvent


# ---------------------------------------------------------------------------
# ConflictInfo — returned by apply_event on an LWW overwrite
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ConflictInfo:
    path: str
    winner: Literal["local", "incoming"]
    kept_rapidhash: int
    overwritten_rapidhash: int
    kept_recv_ts_ns: int
    overwritten_recv_ts_ns: int


# ---------------------------------------------------------------------------
# SiloIndex
# ---------------------------------------------------------------------------

class SiloIndex:
    """In-memory index of all files tracked for a single silo.

    Every mutation goes through ``apply_event``.  The index itself never
    performs I/O; callers (the EventJournal) are responsible for durability.
    """

    def __init__(self, silo_id: UUID, node_id: str) -> None:
        self.silo_id = silo_id
        self.node_id = node_id
        self.records: dict[str, FileRecord] = {}

    # ------------------------------------------------------------------
    # Snapshot / serialisation
    # ------------------------------------------------------------------

    def to_snapshot(self) -> dict[str, dict[str, object]]:
        """Return a plain-dict snapshot suitable for a SYNC_STATE message.

        The dict shape matches ``FileEntrySnapshot`` field names so the caller
        can construct ``SyncStateMsg(records=index.to_snapshot(), ...)``.
        """
        return {
            path: {
                "rapidhash": rec.rapidhash,
                "size": rec.size,
                "mode": rec.mode,
                "uid_name": rec.uid_name,
                "gid_name": rec.gid_name,
                "mtime_s": rec.mtime_s,
                "mtime_ns": rec.mtime_ns,
                "recv_ts_ns": rec.recv_ts_ns,
                "deleted": rec.deleted,
            }
            for path, rec in self.records.items()
        }

    # ------------------------------------------------------------------
    # Diff — what does the remote need from us?
    # ------------------------------------------------------------------

    def diff(self, remote: dict[str, Any]) -> list[FileEntry]:
        """Compare this index against a remote snapshot.

        Returns the ``FileEntry`` objects representing files this node needs
        to send: files the remote is missing entirely (``is_full=True``) and
        files where the content differs (``is_full=False``, delta possible).

        ``remote`` is a mapping of path → anything with a ``rapidhash``
        attribute or key (accepts both plain dicts and ``FileEntrySnapshot``
        Pydantic models).
        """
        result: list[FileEntry] = []
        for path, record in self.records.items():
            if record.deleted:
                continue
            remote_entry = remote.get(path)
            if remote_entry is None:
                result.append(_to_file_entry(path, record, is_full=True, base_rapidhash=None))
            else:
                remote_rh = _get_rapidhash(remote_entry)
                if remote_rh != record.rapidhash:
                    result.append(
                        _to_file_entry(path, record, is_full=False, base_rapidhash=remote_rh)
                    )
        return result

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def apply_event(self, event: SyncEvent) -> ConflictInfo | None:
        """Apply a sync event to the index, performing LWW conflict resolution.

        Returns ``ConflictInfo`` when an existing record was overwritten (or
        kept) due to a recv_ts_ns conflict; returns ``None`` otherwise.
        """
        if isinstance(event, WriteEvent):
            return self._apply_write(event)
        if isinstance(event, DeleteEvent):
            return self._apply_delete(event)
        if isinstance(event, RenameEvent):
            return self._apply_rename(event)
        # Exhaustive match — should never reach here with a valid SyncEvent.
        raise TypeError(f"unknown event type: {type(event)!r}")  # pragma: no cover

    def _apply_write(self, event: WriteEvent) -> ConflictInfo | None:
        existing = self.records.get(event.path)
        new_record = FileRecord(
            rapidhash=event.rapidhash,
            size=event.size,
            mtime_s=event.mtime_s,
            mtime_ns=event.mtime_ns,
            recv_ts_ns=event.recv_ts_ns,
            mode=event.mode,
            uid_name=event.uid_name,
            gid_name=event.gid_name,
            deleted=False,
        )

        if existing is None or existing.deleted:
            self.records[event.path] = new_record
            return None

        # LWW: strictly higher recv_ts_ns wins; ties keep the existing record.
        if event.recv_ts_ns > existing.recv_ts_ns:
            self.records[event.path] = new_record
            return ConflictInfo(
                path=event.path,
                winner="incoming",
                kept_rapidhash=new_record.rapidhash,
                overwritten_rapidhash=existing.rapidhash,
                kept_recv_ts_ns=event.recv_ts_ns,
                overwritten_recv_ts_ns=existing.recv_ts_ns,
            )
        if event.recv_ts_ns < existing.recv_ts_ns:
            return ConflictInfo(
                path=event.path,
                winner="local",
                kept_rapidhash=existing.rapidhash,
                overwritten_rapidhash=new_record.rapidhash,
                kept_recv_ts_ns=existing.recv_ts_ns,
                overwritten_recv_ts_ns=event.recv_ts_ns,
            )
        # Equal timestamps: keep existing (idempotent redelivery).
        return None

    def _apply_delete(self, event: DeleteEvent) -> ConflictInfo | None:
        existing = self.records.get(event.path)
        if existing is None or existing.deleted:
            return None
        # Delete only wins if it is at least as recent as the existing write.
        if event.recv_ts_ns >= existing.recv_ts_ns:
            self.records[event.path] = dataclasses.replace(
                existing,
                deleted=True,
                recv_ts_ns=event.recv_ts_ns,
            )
        return None

    def _apply_rename(self, event: RenameEvent) -> ConflictInfo | None:
        existing = self.records.get(event.old_path)
        if existing is None or existing.deleted:
            return None

        # Remove the old entry and place it at the new path.
        del self.records[event.old_path]
        conflict: ConflictInfo | None = None

        target = self.records.get(event.new_path)
        if target is not None and not target.deleted:
            if event.recv_ts_ns >= target.recv_ts_ns:
                conflict = ConflictInfo(
                    path=event.new_path,
                    winner="incoming",
                    kept_rapidhash=existing.rapidhash,
                    overwritten_rapidhash=target.rapidhash,
                    kept_recv_ts_ns=event.recv_ts_ns,
                    overwritten_recv_ts_ns=target.recv_ts_ns,
                )
            else:
                # Target at new_path is newer; put old_path back as deleted.
                self.records[event.old_path] = dataclasses.replace(existing, deleted=True)
                return ConflictInfo(
                    path=event.new_path,
                    winner="local",
                    kept_rapidhash=target.rapidhash,
                    overwritten_rapidhash=existing.rapidhash,
                    kept_recv_ts_ns=target.recv_ts_ns,
                    overwritten_recv_ts_ns=event.recv_ts_ns,
                )

        self.records[event.new_path] = dataclasses.replace(
            existing, recv_ts_ns=event.recv_ts_ns
        )
        return conflict

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Return the number of tracked paths (including tombstones)."""
        return len(self.records)

    def active_count(self) -> int:
        """Return the number of non-deleted entries."""
        return sum(1 for r in self.records.values() if not r.deleted)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _get_rapidhash(entry: Any) -> int:
    """Extract rapidhash from either a plain dict or a FileEntrySnapshot."""
    if isinstance(entry, dict):
        return int(entry["rapidhash"])
    return int(entry.rapidhash)


def _to_file_entry(
    path: str,
    record: FileRecord,
    *,
    is_full: bool,
    base_rapidhash: int | None,
) -> FileEntry:
    return FileEntry(
        path=path,
        rapidhash=record.rapidhash,
        size=record.size,
        mode=record.mode,
        uid_name=record.uid_name,
        gid_name=record.gid_name,
        mtime_s=record.mtime_s,
        mtime_ns=record.mtime_ns,
        is_full=is_full,
        delta_base_rapidhash=base_rapidhash,
    )
