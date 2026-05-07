"""Filesystem watcher for a single silo root.

Wraps `watchdog` to emit typed sync events (WriteEvent / DeleteEvent /
RenameEvent) to an asyncio queue, with:
  - pathspec gitignore-style blacklist filtering
  - per-file debouncing with an absolute cap and bulk-flush safety valve
  - clean async start/stop lifecycle
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable, Sequence

import pathspec
from watchdog.events import (
    DirDeletedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from chiralite.hash import rapidhash
from chiralite.sync.index import DeleteEvent, RenameEvent, SyncEvent, WriteEvent

log = logging.getLogger(__name__)

_DEFAULT_DEBOUNCE_MS = 200
_DEFAULT_MAX_DELAY_MS = 1500
_DEFAULT_MAX_DIRTY_FILES = 50


# ---------------------------------------------------------------------------
# Internal debouncer (runs in the watchdog Observer thread)
# ---------------------------------------------------------------------------

class _Debouncer:
    """Per-file debounce logic.  All methods called from the Observer thread."""

    def __init__(
        self,
        root: Path,
        spec: pathspec.PathSpec,
        on_flush: Callable[[str, str], None],  # (path, op) where op in {write, delete, rename_src}
        on_rename_flush: Callable[[str, str], None],  # (old, new)
        debounce_ms: int,
        max_delay_ms: int,
        max_dirty_files: int,
    ) -> None:
        self._root = root
        self._spec = spec
        self._on_flush = on_flush
        self._on_rename_flush = on_rename_flush
        self._debounce_s = debounce_ms / 1000.0
        self._max_delay_s = max_delay_ms / 1000.0
        self._max_dirty_files = max_dirty_files

        self._lock = threading.Lock()
        # path → (op, t_first, timer)
        self._dirty: dict[str, tuple[str, float, threading.Timer | None]] = {}
        # path → (old_path, new_path) for rename ops
        self._renames: dict[str, tuple[str, str]] = {}

    def _is_blocked(self, rel: str) -> bool:
        return self._spec.match_file(rel)

    def _rel(self, abs_path: str) -> str | None:
        try:
            return str(Path(abs_path).relative_to(self._root))
        except ValueError:
            return None

    def on_write(self, abs_path: str) -> None:
        rel = self._rel(abs_path)
        if rel is None or self._is_blocked(rel):
            return
        with self._lock:
            self._schedule(rel, "write")

    def on_delete(self, abs_path: str) -> None:
        rel = self._rel(abs_path)
        if rel is None or self._is_blocked(rel):
            return
        with self._lock:
            # Cancel any pending write — delete wins immediately
            self._cancel(rel)
            self._flush_now(rel, "delete")

    def on_rename(self, abs_src: str, abs_dst: str) -> None:
        src = self._rel(abs_src)
        dst = self._rel(abs_dst)
        src_blocked = src is None or self._is_blocked(src)
        dst_blocked = dst is None or self._is_blocked(dst)

        with self._lock:
            if src_blocked and dst_blocked:
                return
            if src_blocked:
                # Renamed from outside silo: treat as new write
                if dst is not None:
                    self._schedule(dst, "write")
                return
            if dst_blocked:
                # Renamed out of silo: treat as delete
                self._cancel(src)
                self._flush_now(src, "delete")
                return
            # Both inside silo: proper rename
            self._cancel(src)
            self._renames[dst] = (src, dst)  # type: ignore[assignment]
            self._flush_now(dst, "rename")

    def _schedule(self, rel: str, op: str) -> None:
        """(Re)schedule a debounce flush for rel. Lock must be held."""
        now = time.monotonic()
        existing = self._dirty.get(rel)
        if existing:
            _, t_first, old_timer = existing
            if old_timer is not None:
                old_timer.cancel()
            elapsed = now - t_first
            remaining_cap = self._max_delay_s - elapsed
            delay = min(self._debounce_s, max(remaining_cap, 0))
        else:
            t_first = now
            delay = self._debounce_s

        timer = threading.Timer(delay, self._timer_fired, args=(rel,))
        timer.daemon = True
        timer.start()
        self._dirty[rel] = (op, t_first, timer)

        if len(self._dirty) > self._max_dirty_files:
            self._flush_all_locked()

    def _cancel(self, rel: str) -> None:
        """Cancel any pending timer for rel. Lock must be held."""
        entry = self._dirty.pop(rel, None)
        if entry:
            _, _, timer = entry
            if timer is not None:
                timer.cancel()
        self._renames.pop(rel, None)

    def _timer_fired(self, rel: str) -> None:
        with self._lock:
            entry = self._dirty.pop(rel, None)
            if entry is None:
                return
            op, _, _ = entry
        self._dispatch(rel, op)

    def _flush_now(self, rel: str, op: str) -> None:
        """Immediately flush (no timer). Lock must be held."""
        self._dirty.pop(rel, None)
        self._dispatch(rel, op)

    def _flush_all_locked(self) -> None:
        """Flush everything immediately. Lock must be held."""
        items = list(self._dirty.items())
        self._dirty.clear()
        for rel, (op, _, timer) in items:
            if timer is not None:
                timer.cancel()
            self._dispatch(rel, op)

    def _dispatch(self, rel: str, op: str) -> None:
        if op == "rename":
            rename = self._renames.pop(rel, None)
            if rename:
                self._on_rename_flush(rename[0], rename[1])
            else:
                self._on_flush(rel, "write")
        else:
            self._on_flush(rel, op)

    def flush_all(self) -> None:
        """Flush all pending dirty files immediately (called on stop)."""
        with self._lock:
            self._flush_all_locked()


# ---------------------------------------------------------------------------
# watchdog event handler
# ---------------------------------------------------------------------------

class _Handler(FileSystemEventHandler):
    def __init__(self, debouncer: _Debouncer) -> None:
        super().__init__()
        self._d = debouncer

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._d.on_write(str(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._d.on_write(str(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            # Emit deletes for all paths under this dir (best-effort)
            self._d.on_delete(str(event.src_path) + "/")
        else:
            self._d.on_delete(str(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if isinstance(event, (FileMovedEvent, DirMovedEvent)):
            self._d.on_rename(str(event.src_path), str(event.dest_path))
        elif isinstance(event, DirDeletedEvent):
            self._d.on_delete(str(event.src_path) + "/")


# ---------------------------------------------------------------------------
# SiloWatcher — public API
# ---------------------------------------------------------------------------

class SiloWatcher:
    """Filesystem watcher for one silo root directory.

    Usage::

        watcher = SiloWatcher(root=Path("/srv/silo"), blacklist=["**/.git/**"])
        await watcher.start()
        async for event in watcher:
            ...
        await watcher.stop()

    Or equivalently, use it as an async context manager::

        async with SiloWatcher(...) as watcher:
            async for event in watcher:
                ...
    """

    def __init__(
        self,
        root: Path,
        blacklist: Sequence[str] = (),
        *,
        debounce_ms: int = _DEFAULT_DEBOUNCE_MS,
        max_delay_ms: int = _DEFAULT_MAX_DELAY_MS,
        max_dirty_files: int = _DEFAULT_MAX_DIRTY_FILES,
    ) -> None:
        self._root = root.resolve()
        self._spec = pathspec.PathSpec.from_lines("gitignore", blacklist)
        self._debounce_ms = debounce_ms
        self._max_delay_ms = max_delay_ms
        self._max_dirty_files = max_dirty_files

        self._queue: asyncio.Queue[SyncEvent] = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._observer: Observer | None = None
        self._debouncer: _Debouncer | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._debouncer = _Debouncer(
            root=self._root,
            spec=self._spec,
            on_flush=self._on_flush,
            on_rename_flush=self._on_rename_flush,
            debounce_ms=self._debounce_ms,
            max_delay_ms=self._max_delay_ms,
            max_dirty_files=self._max_dirty_files,
        )
        handler = _Handler(self._debouncer)
        self._observer = Observer()
        self._observer.schedule(handler, str(self._root), recursive=True)
        self._observer.start()
        log.debug("SiloWatcher started on %s", self._root)

    async def stop(self) -> None:
        if self._debouncer is not None:
            self._debouncer.flush_all()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None
        log.debug("SiloWatcher stopped")

    async def __aenter__(self) -> "SiloWatcher":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()

    def __aiter__(self) -> "SiloWatcher":
        return self

    async def __anext__(self) -> SyncEvent:
        return await self._queue.get()

    # ------------------------------------------------------------------
    # Queue helpers (called from Observer thread via loop.call_soon_threadsafe)
    # ------------------------------------------------------------------

    def _put(self, event: SyncEvent) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)

    def _on_flush(self, rel: str, op: str) -> None:
        abs_path = self._root / rel
        now_ns = time.time_ns()

        if op == "delete":
            self._put(DeleteEvent(path=rel, recv_ts_ns=now_ns))
            return

        # op == "write": stat + hash the file
        try:
            st = os.stat(abs_path)
        except OSError:
            # File disappeared between event and flush — emit delete
            self._put(DeleteEvent(path=rel, recv_ts_ns=now_ns))
            return

        try:
            content = abs_path.read_bytes()
        except OSError:
            self._put(DeleteEvent(path=rel, recv_ts_ns=now_ns))
            return

        mtime_ns_total = st.st_mtime_ns
        mtime_s = mtime_ns_total // 1_000_000_000
        mtime_ns = mtime_ns_total % 1_000_000_000

        import grp
        import pwd

        try:
            uid_name = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            uid_name = str(st.st_uid)
        try:
            gid_name = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            gid_name = str(st.st_gid)

        self._put(
            WriteEvent(
                path=rel,
                rapidhash=rapidhash(content),
                size=st.st_size,
                mtime_s=mtime_s,
                mtime_ns=mtime_ns,
                recv_ts_ns=now_ns,
                mode=stat_mode(st.st_mode),
                uid_name=uid_name,
                gid_name=gid_name,
            )
        )

    def _on_rename_flush(self, old: str, new: str) -> None:
        now_ns = time.time_ns()
        # If destination doesn't exist (e.g. moved out of silo), treat as delete
        abs_new = self._root / new
        if not abs_new.exists():
            self._put(DeleteEvent(path=old, recv_ts_ns=now_ns))
            return
        self._put(RenameEvent(old_path=old, new_path=new, recv_ts_ns=now_ns))


def stat_mode(raw_mode: int) -> int:
    """Extract the POSIX permission bits (lower 12 bits) from st_mode."""
    return raw_mode & 0o7777
