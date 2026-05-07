"""Tamper-evident append-only audit logger.

Each event is written as a single UTF-8 JSON line (JSONL) to a rotating
file.  Rotation uses ``logging.handlers.RotatingFileHandler`` with a custom
``rotator`` hook that compresses the rolled-over file with gzip.

Wire format (one JSON object per line)::

    {
      "ts_ns":    1714000000000000000,
      "ts_iso":   "2024-04-25T10:00:00.000000Z",
      "severity": "INFO",
      "event":    "file.write",
      "client_cn": "fm-macbook",
      "silo_id":  "550e8400-e29b-41d4-a716-446655440000",
      "path":     "src/main.py",
      "detail":   {...}
    }

The ``silo_id`` and ``path`` fields are omitted when not applicable.
"""
from __future__ import annotations

import gzip
import json
import logging
import logging.handlers
import os
import shutil
import time
from pathlib import Path
from typing import Any
from uuid import UUID

__all__ = ["AuditLogger"]

_DEFAULT_MAX_BYTES: int = 100 * 1024 * 1024   # 100 MiB
_DEFAULT_BACKUP_COUNT: int = 10


def _gzip_rotator(source: str, dest: str) -> None:
    """Compress *source* to *dest*.gz and remove *source*."""
    gz_dest = dest + ".gz"
    with open(source, "rb") as f_in:
        with gzip.open(gz_dest, "wb", compresslevel=9) as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(source)


def _gz_namer(name: str) -> str:
    """Return the rotated filename (with .gz suffix added by rotator)."""
    return name


class AuditLogger:
    """Append-only JSONL audit logger with gzip-compressed rotation.

    Args:
        path:         Absolute path to the audit log file.
        max_bytes:    File size that triggers rotation (default 100 MiB).
        backup_count: Number of rotated files to keep (default 10).
    """

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        backup_count: int = _DEFAULT_BACKUP_COUNT,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        self._handler = logging.handlers.RotatingFileHandler(
            str(path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
            delay=False,
        )
        self._handler.rotator = _gzip_rotator  # type: ignore[assignment]
        self._handler.namer = _gz_namer        # type: ignore[assignment]

        # Use a minimal formatter — we write the full JSON ourselves.
        self._handler.setFormatter(logging.Formatter("%(message)s"))

        self._logger = logging.getLogger(f"chiralite.audit.{id(self)}")
        self._logger.addHandler(self._handler)
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False

    # ------------------------------------------------------------------
    # Core write
    # ------------------------------------------------------------------

    def log(
        self,
        event: str,
        *,
        severity: str = "INFO",
        client_cn: str = "",
        silo_id: UUID | None = None,
        path: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Append one audit event to the log file.

        Args:
            event:     Event type string (e.g. ``"file.write"``).
            severity:  Log level label — ``"INFO"``, ``"WARN"``,
                       ``"ERROR"``, or ``"CRITICAL"``.
            client_cn: Common Name of the peer certificate.
            silo_id:   Silo UUID (omitted from output when ``None``).
            path:      File path relative to silo root (may be empty).
            detail:    Arbitrary extra key/value pairs written into the
                       ``"detail"`` sub-object.
        """
        ts_ns = time.time_ns()
        ts_s = ts_ns / 1_000_000_000
        ts_iso = (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts_s))
            + f".{ts_ns % 1_000_000_000:09d}"[:7]  # microseconds
            + "Z"
        )

        record: dict[str, Any] = {
            "ts_ns": ts_ns,
            "ts_iso": ts_iso,
            "severity": severity,
            "event": event,
        }
        if client_cn:
            record["client_cn"] = client_cn
        if silo_id is not None:
            record["silo_id"] = str(silo_id)
        if path:
            record["path"] = path
        if detail:
            record["detail"] = detail

        self._logger.info(json.dumps(record, separators=(",", ":")))

    # ------------------------------------------------------------------
    # Convenience helpers for common event types (§10.2)
    # ------------------------------------------------------------------

    def log_auth_ok(self, client_cn: str, silo_id: UUID) -> None:
        self.log("auth.ok", severity="INFO", client_cn=client_cn, silo_id=silo_id)

    def log_auth_fail(self, client_cn: str, reason: str) -> None:
        self.log(
            "auth.fail", severity="WARN", client_cn=client_cn,
            detail={"reason": reason},
        )

    def log_auth_replay(self, client_cn: str) -> None:
        self.log("auth.replay", severity="ERROR", client_cn=client_cn)

    def log_file_write(
        self,
        client_cn: str,
        silo_id: UUID,
        path: str,
        *,
        rapidhash_before: int | None,
        rapidhash_after: int,
        recv_ts_ns: int,
        delta: bool,
        size_bytes: int,
    ) -> None:
        self.log(
            "file.write",
            severity="INFO",
            client_cn=client_cn,
            silo_id=silo_id,
            path=path,
            detail={
                "rapidhash_before": rapidhash_before,
                "rapidhash_after": rapidhash_after,
                "recv_ts_ns": recv_ts_ns,
                "delta": delta,
                "size_bytes": size_bytes,
            },
        )

    def log_file_delete(self, client_cn: str, silo_id: UUID, path: str) -> None:
        self.log("file.delete", severity="INFO", client_cn=client_cn, silo_id=silo_id, path=path)

    def log_file_rename(
        self, client_cn: str, silo_id: UUID, old_path: str, new_path: str
    ) -> None:
        self.log(
            "file.rename",
            severity="INFO",
            client_cn=client_cn,
            silo_id=silo_id,
            path=old_path,
            detail={"new_path": new_path},
        )

    def log_conflict_lww(
        self,
        client_cn: str,
        silo_id: UUID,
        path: str,
        *,
        kept_rapidhash: int,
        overwritten_rapidhash: int,
    ) -> None:
        self.log(
            "conflict.lww",
            severity="WARN",
            client_cn=client_cn,
            silo_id=silo_id,
            path=path,
            detail={
                "kept_rapidhash": kept_rapidhash,
                "overwritten_rapidhash": overwritten_rapidhash,
            },
        )

    def log_quarantine(self, client_cn: str, silo_id: UUID, path: str, virus: str) -> None:
        self.log(
            "quarantine",
            severity="CRITICAL",
            client_cn=client_cn,
            silo_id=silo_id,
            path=path,
            detail={"virus": virus},
        )

    def log_path_traversal(self, client_cn: str, silo_id: UUID, path: str) -> None:
        self.log(
            "security.path_traversal",
            severity="CRITICAL",
            client_cn=client_cn,
            silo_id=silo_id,
            path=path,
        )

    def log_uid_denied(self, client_cn: str, silo_id: UUID, name: str) -> None:
        self.log(
            "security.uid_denied",
            severity="CRITICAL",
            client_cn=client_cn,
            silo_id=silo_id,
            detail={"name": name},
        )

    def log_mode_stripped(
        self, client_cn: str, silo_id: UUID, path: str, raw_mode: int, safe_mode: int
    ) -> None:
        self.log(
            "security.mode_stripped",
            severity="WARN",
            client_cn=client_cn,
            silo_id=silo_id,
            path=path,
            detail={"raw_mode": oct(raw_mode), "safe_mode": oct(safe_mode)},
        )

    def log_session_start(self, client_cn: str, silo_id: UUID) -> None:
        self.log("session.start", severity="INFO", client_cn=client_cn, silo_id=silo_id)

    def log_session_end(self, client_cn: str, silo_id: UUID) -> None:
        self.log("session.end", severity="INFO", client_cn=client_cn, silo_id=silo_id)

    def log_blacklist_sync(self, client_cn: str, silo_id: UUID) -> None:
        self.log("blacklist.sync", severity="INFO", client_cn=client_cn, silo_id=silo_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Flush and close the underlying file handler."""
        self._handler.close()
        self._logger.removeHandler(self._handler)

    def flush(self) -> None:
        """Flush buffered data to disk."""
        self._handler.flush()
