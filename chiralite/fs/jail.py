"""Jail-safe path resolution for a silo root directory.

``PathJail.resolve`` walks each path component individually.  If the
accumulated prefix is a symlink, it is resolved and verified against the
root before the next component is appended.  This prevents both ``..``
traversal and symlink-based escapes regardless of how deeply they are
nested.
"""
from __future__ import annotations

from pathlib import Path


class JailbreakError(Exception):
    """Raised when a path resolves to a location outside the silo root."""


class PathJail:
    """Resolves relative paths within a fixed silo root, blocking escapes.

    Example::

        jail = PathJail(Path("/var/lib/chiralite/silo-1"))
        abs_path = jail.resolve("docs/readme.txt")   # safe
        jail.resolve("../../etc/passwd")              # raises JailbreakError
    """

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    @property
    def root(self) -> Path:
        return self._root

    def resolve(self, rel_path: str) -> Path:
        """Return the absolute path for *rel_path* inside the jail.

        Each path component is applied to the running candidate in turn.
        If the resulting candidate is an existing symlink it is resolved
        and the resolved target is checked against the root before
        continuing.  Non-existent tails (new files) are permitted.

        Raises:
            JailbreakError: if a ``..`` component is found or if any
                symlink resolves to a location outside the root.
        """
        candidate = self._root
        for part in Path(rel_path).parts:
            if part in ("", "."):
                continue
            if part == "..":
                raise JailbreakError(
                    f"path traversal component '..' in: {rel_path!r}"
                )
            candidate = candidate / part
            if candidate.is_symlink():
                resolved = candidate.resolve()
                if not resolved.is_relative_to(self._root):
                    raise JailbreakError(
                        f"symlink {candidate!r} escapes silo root {self._root!r}"
                    )
                candidate = resolved
        return candidate

    def check(self, path: Path) -> None:
        """Verify that *path* (already absolute) lies inside the jail.

        Resolves all symlinks in *path* before checking.

        Raises:
            JailbreakError: if *path* is outside the root.
        """
        if not path.resolve().is_relative_to(self._root):
            raise JailbreakError(
                f"{path!r} is outside silo root {self._root!r}"
            )
