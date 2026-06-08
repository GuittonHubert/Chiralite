"""Isolated working directory under a tmpfs mount point.

The mount point (``/run/chiralite/sandbox``) is pre-mounted by the system
at server startup.  Each transfer gets its own subdirectory; the entire
subtree is removed unconditionally when the context manager exits.

Unverified content is never written to the real jail — it goes here first,
then ClamAV scans it, and only on ``CLEAN`` does the caller move it via
``atomic_write``.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from types import TracebackType
from typing import Type

_DEFAULT_MOUNT = Path("/run/chiralite/sandbox")


class SandboxError(Exception):
    """Raised on workspace creation / access failures."""


class TmpfsWorkspace:
    """Isolated directory under the sandbox mount point.

    Usage::

        with TmpfsWorkspace(mount_point, session_id="abc", transfer_id="xyz") as ws:
            ws.write("payload.bin", data)
            content = ws.read("payload.bin")
            # ws.path is the workspace directory
        # directory is deleted here, even if an exception was raised

    Args:
        mount_point:  Pre-mounted tmpfs base directory.
        session_id:   Identifies the session (e.g. connection UUID as str).
        transfer_id:  Identifies the transfer within the session.
    """

    def __init__(
        self,
        mount_point: Path = _DEFAULT_MOUNT,
        *,
        session_id: str,
        transfer_id: str,
    ) -> None:
        if not mount_point.exists():
            raise SandboxError(f"sandbox mount point does not exist: {mount_point}")
        self._ws = mount_point / session_id / transfer_id
        self._entered = False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "TmpfsWorkspace":
        try:
            self._ws.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise SandboxError(f"workspace already exists: {self._ws}") from exc
        except OSError as exc:
            raise SandboxError(f"failed to create workspace {self._ws}: {exc}") from exc
        self._entered = True
        return self

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._cleanup()

    # ------------------------------------------------------------------
    # File helpers
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        """The workspace directory path."""
        if not self._entered:
            raise SandboxError("workspace not entered — use as a context manager")
        return self._ws

    def write(self, name: str, data: bytes) -> Path:
        """Write *data* to ``{workspace}/{name}`` and return the full path."""
        dest = self.path / name
        dest.write_bytes(data)
        return dest

    def read(self, name: str) -> bytes:
        """Read and return the contents of ``{workspace}/{name}``."""
        return (self.path / name).read_bytes()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        shutil.rmtree(self._ws, ignore_errors=True)
        # Remove the session directory if it is now empty
        try:
            self._ws.parent.rmdir()
        except OSError:
            pass
