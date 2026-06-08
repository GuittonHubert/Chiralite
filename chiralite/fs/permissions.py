"""POSIX attribute application — mode bits and ownership.

``apply_posix_attrs`` is the single entry point for setting metadata on a
path after its content has been written.  ``lchown`` is used so that
symlinks themselves are updated rather than their targets (matching the
behaviour expected when the daemon reconstructs symlink entries).
"""
from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path


# ---------------------------------------------------------------------------
# Mode sanitization
# ---------------------------------------------------------------------------

FORBIDDEN_BITS = 0o7000   # setuid | setgid | sticky — always stripped
MAX_FILE_MODE  = 0o644
MAX_DIR_MODE   = 0o755
SERVER_UMASK   = 0o022    # applied after ceiling


def sanitize_mode(raw: int, *, is_dir: bool) -> int:
    """Strip dangerous bits and apply the server-side mode ceiling.

    Always removes setuid (04000), setgid (02000), and sticky (01000).
    Caps at ``MAX_DIR_MODE`` (0o755) for directories and ``MAX_FILE_MODE``
    (0o644) for files.  Applies ``SERVER_UMASK`` (0o022) last.
    """
    mode = raw & ~FORBIDDEN_BITS
    ceiling = MAX_DIR_MODE if is_dir else MAX_FILE_MODE
    return mode & ceiling & ~SERVER_UMASK


# ---------------------------------------------------------------------------
# Ownership resolution
# ---------------------------------------------------------------------------

class UnknownOwnerError(Exception):
    """A uid_name or gid_name could not be resolved on this system."""


def lookup_uid(name: str) -> int:
    """Return the numeric UID for *name*.

    Raises:
        UnknownOwnerError: if *name* is not in the local passwd database.
    """
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        raise UnknownOwnerError(f"unknown user: {name!r}") from None


def lookup_gid(name: str) -> int:
    """Return the numeric GID for *name*.

    Raises:
        UnknownOwnerError: if *name* is not in the local group database.
    """
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        raise UnknownOwnerError(f"unknown group: {name!r}") from None


def apply_posix_attrs(
    path: Path,
    mode: int,
    uid_name: str,
    gid_name: str,
) -> None:
    """Apply *mode* bits and *uid_name*/*gid_name* ownership to *path*.

    Order: ``chmod`` first, then ``lchown``.  ``lchown`` does not follow
    symlinks, which is intentional — when the daemon recreates a symlink
    entry it sets ownership on the link itself.

    Raises:
        UnknownOwnerError: if either *uid_name* or *gid_name* is absent
            from the local passwd/group database.
    """
    uid = lookup_uid(uid_name)
    gid = lookup_gid(gid_name)
    os.chmod(path, mode)
    os.lchown(path, uid, gid)
