"""Durable event journal for SiloIndex.

On startup the journal loads a checkpoint snapshot (if one exists) and
then replays any NDJSON entries appended since the last checkpoint.
Every append() call fsyncs the journal file before mutating the
in-memory index, so a crash at any point leaves the index reconstructible.

File layout (all inside the caller-supplied directory):
  journal.ndjson   — append-only NDJSON event log
  checkpoint.json  — latest full index snapshot (written atomically)
"""
from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

from chiralite.sync.index import (
    ConflictInfo,
    DeleteEvent,
    FileRecord,
    RenameEvent,
    SiloIndex,
    SyncEvent,
    WriteEvent,
)

_JOURNAL_NAME = "journal.ndjson"
_CHECKPOINT_NAME = "checkpoint.json"


class JournalError(Exception):
    """Raised when the journal or checkpoint file cannot be parsed."""


class EventJournal:
    """Durable wrapper around SiloIndex.

    Persists every mutation to an append-only NDJSON journal and supports
    atomic checkpointing to bound replay time on restart.

    Usage::

        with EventJournal(Path("/var/lib/chiralite/silo-1"), silo_id, node) as j:
            j.append(write_event)
            j.checkpoint()   # compact: snapshot → clear journal
    """

    def __init__(self, directory: Path, silo_id: UUID, node_id: str) -> None:
        self._dir = directory
        self._journal_path = directory / _JOURNAL_NAME
        self._checkpoint_path = directory / _CHECKPOINT_NAME
        self._index = SiloIndex(silo_id=silo_id, node_id=node_id)
        self._load()
        self._fp = self._journal_path.open("a", encoding="utf-8")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def index(self) -> SiloIndex:
        return self._index

    def append(self, event: SyncEvent) -> ConflictInfo | None:
        """Persist *event* to the journal, then apply it to the in-memory index.

        The journal entry is fsynced before the index is mutated so that a
        crash after a successful fsync can never leave the index ahead of the
        durable log.

        Returns whatever ``SiloIndex.apply_event`` returns (a
        ``ConflictInfo`` or ``None``).
        """
        line = json.dumps(_event_to_dict(event), separators=(",", ":"))
        self._fp.write(line + "\n")
        self._fp.flush()
        os.fsync(self._fp.fileno())
        return self._index.apply_event(event)

    def checkpoint(self) -> None:
        """Atomically persist a full index snapshot, then truncate the journal.

        Sequence (crash-safe on POSIX):
        1. Write snapshot to ``checkpoint.tmp``
        2. fsync the tmp file
        3. Atomic rename → ``checkpoint.json``
        4. fsync the containing directory
        5. Truncate ``journal.ndjson`` (fsync the empty file)
        6. Reopen journal in append mode
        """
        snap = {
            "silo_id": str(self._index.silo_id),
            "node_id": self._index.node_id,
            "records": self._index.to_snapshot(),
        }
        tmp = self._checkpoint_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snap, separators=(",", ":")), encoding="utf-8")
        with tmp.open("rb") as f:
            os.fsync(f.fileno())
        tmp.rename(self._checkpoint_path)
        _fsync_dir(self._dir)

        # Truncate the journal.
        self._fp.close()
        with self._journal_path.open("w", encoding="utf-8") as f:
            f.flush()
            os.fsync(f.fileno())
        self._fp = self._journal_path.open("a", encoding="utf-8")

    def close(self) -> None:
        """Flush and close the open journal file handle."""
        self._fp.close()

    def __enter__(self) -> "EventJournal":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._checkpoint_path.exists():
            _load_checkpoint(self._checkpoint_path, self._index)
        if self._journal_path.exists():
            _replay_journal(self._journal_path, self._index)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _event_to_dict(event: SyncEvent) -> dict[str, Any]:
    d: dict[str, Any] = dataclasses.asdict(event)
    if isinstance(event, WriteEvent):
        d["kind"] = "write"
    elif isinstance(event, DeleteEvent):
        d["kind"] = "delete"
    else:
        d["kind"] = "rename"
    return d


def _dict_to_event(d: dict[str, Any]) -> SyncEvent:
    d = dict(d)  # shallow copy — we pop "kind"
    kind = d.pop("kind")
    if kind == "write":
        return WriteEvent(**d)
    if kind == "delete":
        return DeleteEvent(**d)
    if kind == "rename":
        return RenameEvent(**d)
    raise JournalError(f"unknown event kind: {kind!r}")


def _load_checkpoint(path: Path, index: SiloIndex) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise JournalError(f"corrupt checkpoint: {exc}") from exc
    for rel_path, rec in data.get("records", {}).items():
        try:
            index.records[rel_path] = FileRecord(
                rapidhash=rec["rapidhash"],
                size=rec["size"],
                mtime_s=rec["mtime_s"],
                mtime_ns=rec["mtime_ns"],
                recv_ts_ns=rec["recv_ts_ns"],
                mode=rec["mode"],
                uid_name=rec["uid_name"],
                gid_name=rec["gid_name"],
                deleted=rec.get("deleted", False),
            )
        except (KeyError, TypeError) as exc:
            raise JournalError(f"corrupt checkpoint record for {rel_path!r}: {exc}") from exc


def _replay_journal(path: Path, index: SiloIndex) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise JournalError(f"cannot read journal: {exc}") from exc
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            event = _dict_to_event(d)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise JournalError(f"corrupt journal entry at line {lineno}: {exc}") from exc
        index.apply_event(event)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
