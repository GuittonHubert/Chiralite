"""Tests for filesystem/writer.py and fs/permissions.py sanitize_mode."""
from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path
from uuid import uuid4

import pytest

from chiralite.filesystem.writer import WriteError, atomic_write
from chiralite.fs.jail import JailbreakError, PathJail
from chiralite.fs.permissions import (
    FORBIDDEN_BITS,
    MAX_DIR_MODE,
    MAX_FILE_MODE,
    SERVER_UMASK,
    sanitize_mode,
)
from chiralite.protocol.messages import FileEntry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _current_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def _entry(
    path: str,
    *,
    mode: int = 0o644,
    uid_name: str | None = None,
    gid_name: str | None = None,
    mtime_s: int = 1_700_000_000,
    mtime_ns: int = 123_456_789,
    content: bytes = b"hello",
) -> FileEntry:
    return FileEntry(
        path=path,
        rapidhash=1,
        size=len(content),
        mode=mode,
        uid_name=uid_name or _current_user(),
        gid_name=gid_name or _current_group(),
        mtime_s=mtime_s,
        mtime_ns=mtime_ns,
        is_full=True,
    )


# ---------------------------------------------------------------------------
# sanitize_mode
# ---------------------------------------------------------------------------

class TestSanitizeMode:
    def test_setuid_stripped(self) -> None:
        raw = 0o4755   # setuid + rwxr-xr-x
        assert sanitize_mode(raw, is_dir=False) & 0o4000 == 0

    def test_setgid_stripped(self) -> None:
        raw = 0o2755
        assert sanitize_mode(raw, is_dir=False) & 0o2000 == 0

    def test_sticky_stripped(self) -> None:
        raw = 0o1755
        assert sanitize_mode(raw, is_dir=False) & 0o1000 == 0

    def test_all_forbidden_bits_stripped(self) -> None:
        raw = FORBIDDEN_BITS | 0o777
        assert sanitize_mode(raw, is_dir=False) & FORBIDDEN_BITS == 0

    def test_file_ceiling_applied(self) -> None:
        # 0o666 > MAX_FILE_MODE (0o644): write bits for group/other stripped
        assert sanitize_mode(0o666, is_dir=False) <= MAX_FILE_MODE

    def test_dir_ceiling_applied(self) -> None:
        assert sanitize_mode(0o777, is_dir=True) <= MAX_DIR_MODE

    def test_umask_applied(self) -> None:
        # 0o644 & ~0o022 = 0o644 (umask removes write bits from group/other)
        result = sanitize_mode(0o644, is_dir=False)
        assert result & SERVER_UMASK == 0

    def test_typical_file_mode_unchanged(self) -> None:
        # 0o644 is already safe
        assert sanitize_mode(0o644, is_dir=False) == 0o644

    def test_typical_dir_mode_unchanged(self) -> None:
        assert sanitize_mode(0o755, is_dir=True) == 0o755

    def test_zero_mode(self) -> None:
        assert sanitize_mode(0, is_dir=False) == 0

    def test_world_writable_capped(self) -> None:
        result = sanitize_mode(0o777, is_dir=False)
        assert result <= MAX_FILE_MODE


# ---------------------------------------------------------------------------
# atomic_write — happy path
# ---------------------------------------------------------------------------

class TestAtomicWrite:
    async def test_file_content_correct(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        content = b"hello world"
        entry = _entry("out.txt", content=content)
        await atomic_write(jail, "out.txt", content, entry)
        assert (tmp_path / "out.txt").read_bytes() == content

    async def test_file_at_destination(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        await atomic_write(jail, "file.bin", b"data", _entry("file.bin"))
        assert (tmp_path / "file.bin").exists()

    async def test_no_temp_file_left(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        await atomic_write(jail, "f.bin", b"x", _entry("f.bin"))
        temps = list(tmp_path.glob(".chiralite_tmp_*"))
        assert temps == []

    async def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        await atomic_write(jail, "a/b/c/file.txt", b"deep", _entry("a/b/c/file.txt"))
        assert (tmp_path / "a" / "b" / "c" / "file.txt").read_bytes() == b"deep"

    async def test_mode_applied(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        await atomic_write(jail, "m.txt", b"x", _entry("m.txt", mode=0o644))
        st = (tmp_path / "m.txt").stat()
        assert stat.S_IMODE(st.st_mode) == 0o644

    async def test_setuid_stripped_on_write(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        await atomic_write(jail, "s.txt", b"x", _entry("s.txt", mode=0o4755))
        st = (tmp_path / "s.txt").stat()
        assert stat.S_IMODE(st.st_mode) & 0o4000 == 0

    async def test_mtime_applied(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        mtime_s = 1_700_000_000
        mtime_ns = 500_000_000
        await atomic_write(jail, "t.txt", b"x", _entry("t.txt", mtime_s=mtime_s, mtime_ns=mtime_ns))
        st = (tmp_path / "t.txt").stat()
        expected_ns = mtime_s * 1_000_000_000 + mtime_ns
        assert st.st_mtime_ns == pytest.approx(expected_ns, abs=1_000_000)

    async def test_overwrite_existing(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        dest = tmp_path / "existing.txt"
        dest.write_bytes(b"old")
        await atomic_write(jail, "existing.txt", b"new", _entry("existing.txt"))
        assert dest.read_bytes() == b"new"

    async def test_large_content(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        content = os.urandom(1024 * 1024)  # 1 MiB
        await atomic_write(jail, "big.bin", content, _entry("big.bin", content=content))
        assert (tmp_path / "big.bin").read_bytes() == content


# ---------------------------------------------------------------------------
# atomic_write — error handling
# ---------------------------------------------------------------------------

class TestAtomicWriteErrors:
    async def test_path_traversal_raises_jailbreak(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            await atomic_write(jail, "../escape.txt", b"x", _entry("escape.txt"))

    async def test_unknown_uid_name_raises(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        entry = _entry("f.txt", uid_name="no_such_user_xyzzy")
        with pytest.raises(WriteError, match="unknown user"):
            await atomic_write(jail, "f.txt", b"x", entry)

    async def test_unknown_gid_name_raises(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        entry = _entry("f.txt", gid_name="no_such_group_xyzzy")
        with pytest.raises(WriteError, match="unknown group"):
            await atomic_write(jail, "f.txt", b"x", entry)

    async def test_no_temp_file_on_uid_error(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        entry = _entry("f.txt", uid_name="no_such_user_xyzzy")
        try:
            await atomic_write(jail, "f.txt", b"x", entry)
        except WriteError:
            pass
        temps = list(tmp_path.glob(".chiralite_tmp_*"))
        assert temps == []
