"""Atomic file writer for silo jail destinations.

Pipeline::

    jail.resolve(relative_path)          # blocks traversal / symlink escape
    dest.parent.mkdir(parents=True)      # create parent dirs
    aiofiles.open(tmp, "wb") + fsync     # write + durability
    sanitize_mode + lchown + chmod       # safe metadata
    os.utime(ns=...)                     # split mtime from FileEntry
    tmp.rename(dest)                     # atomic on POSIX (same filesystem)

On any error after the temp file is created, the temp file is removed before
re-raising.  The destination is never partially written.
"""
from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import aiofiles

from chiralite.fs.jail import PathJail
from chiralite.fs.permissions import (
    UnknownOwnerError,
    lookup_gid,
    lookup_uid,
    sanitize_mode,
)
from chiralite.protocol.messages import FileEntry

__all__ = ["WriteError", "atomic_write"]


class WriteError(Exception):
    """Raised when the atomic write pipeline fails."""


async def atomic_write(
    jail: PathJail,
    relative_path: str,
    content: bytes,
    entry: FileEntry,
) -> None:
    """Write *content* atomically to *relative_path* within *jail*.

    Args:
        jail:          Silo jail; ``jail.resolve`` is called on *relative_path*.
        relative_path: POSIX path relative to the jail root.
        content:       Final file bytes (after delta decode + verification).
        entry:         Metadata from the wire manifest; mode and ownership
                       are sanitized before application.

    Raises:
        JailbreakError: if *relative_path* escapes the jail.
        WriteError:     on any I/O or ownership error.
    """
    dest = jail.resolve(relative_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    tmp = dest.parent / f".chiralite_tmp_{uuid4().hex}"
    try:
        # Write + fsync
        async with aiofiles.open(tmp, "wb") as fh:
            await fh.write(content)
            await fh.flush()
            os.fsync(fh.fileno())

        # Resolve ownership
        try:
            uid = lookup_uid(entry.uid_name)
            gid = lookup_gid(entry.gid_name)
        except UnknownOwnerError as exc:
            raise WriteError(str(exc)) from exc

        # Apply safe metadata
        mode = sanitize_mode(entry.mode, is_dir=False)
        os.lchown(tmp, uid, gid)
        os.chmod(tmp, mode)

        # Set mtime from manifest (informational; server recv_ts is the LWW key)
        mtime_total_ns = entry.mtime_s * 1_000_000_000 + entry.mtime_ns
        os.utime(tmp, ns=(mtime_total_ns, mtime_total_ns))

        # Atomic rename — guaranteed on POSIX when src and dst share a filesystem
        tmp.rename(dest)

    except (WriteError, OSError) as exc:
        tmp.unlink(missing_ok=True)
        if isinstance(exc, WriteError):
            raise
        raise WriteError(f"atomic_write failed for {relative_path!r}: {exc}") from exc
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
