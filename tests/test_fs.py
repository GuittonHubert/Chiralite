"""Tests for fs/jail.py and fs/permissions.py."""
from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path

import pytest

from chiralite.fs.jail import JailbreakError, PathJail
from chiralite.fs.permissions import UnknownOwnerError, apply_posix_attrs, lookup_gid, lookup_uid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _current_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


# ---------------------------------------------------------------------------
# PathJail — normal resolution
# ---------------------------------------------------------------------------

class TestPathJailResolve:
    def test_simple_filename(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        assert jail.resolve("file.txt") == tmp_path.resolve() / "file.txt"

    def test_nested_path(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        assert jail.resolve("a/b/c.txt") == tmp_path.resolve() / "a" / "b" / "c.txt"

    def test_nonexistent_path_allowed(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        result = jail.resolve("does/not/exist.txt")
        assert result == tmp_path.resolve() / "does" / "not" / "exist.txt"

    def test_root_property(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        assert jail.root == tmp_path.resolve()

    def test_dot_component_ignored(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        assert jail.resolve("a/./b") == tmp_path.resolve() / "a" / "b"

    def test_empty_string_returns_root(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        assert jail.resolve("") == tmp_path.resolve()

    def test_single_dot_returns_root(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        assert jail.resolve(".") == tmp_path.resolve()


# ---------------------------------------------------------------------------
# PathJail — symlink handling
# ---------------------------------------------------------------------------

class TestPathJailSymlinks:
    def test_absolute_symlink_within_jail(self, tmp_path: Path) -> None:
        target = tmp_path / "real.txt"
        target.write_text("hello")
        link = tmp_path / "link.txt"
        link.symlink_to(target.resolve())   # absolute symlink, still inside jail
        jail = PathJail(tmp_path)
        assert jail.resolve("link.txt") == target.resolve()

    def test_relative_symlink_within_jail(self, tmp_path: Path) -> None:
        target = tmp_path / "real.txt"
        target.write_text("x")
        link = tmp_path / "alias.txt"
        link.symlink_to("real.txt")   # relative symlink
        jail = PathJail(tmp_path)
        assert jail.resolve("alias.txt") == target.resolve()

    def test_symlink_to_subdir_within_jail(self, tmp_path: Path) -> None:
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "f.txt").write_text("data")
        link = tmp_path / "sub_link"
        link.symlink_to(subdir.resolve())
        jail = PathJail(tmp_path)
        result = jail.resolve("sub_link/f.txt")
        assert result == (subdir / "f.txt").resolve()

    def test_symlink_escaping_jail_raises(self, tmp_path: Path) -> None:
        evil = tmp_path / "evil"
        evil.symlink_to("/tmp")
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError, match="escapes silo root"):
            jail.resolve("evil")

    def test_symlink_via_subpath_escaping_raises(self, tmp_path: Path) -> None:
        evil = tmp_path / "evil"
        evil.symlink_to("/tmp")
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            jail.resolve("evil/passwd")

    def test_nested_escaping_symlink_raises(self, tmp_path: Path) -> None:
        subdir = tmp_path / "sub"
        subdir.mkdir()
        link = subdir / "escape"
        link.symlink_to("/etc")
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            jail.resolve("sub/escape/shadow")


# ---------------------------------------------------------------------------
# PathJail — path traversal
# ---------------------------------------------------------------------------

class TestPathJailTraversal:
    def test_dotdot_at_start_raises(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError, match=r"\.\."):
            jail.resolve("../escape.txt")

    def test_dotdot_in_middle_raises(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            jail.resolve("a/../../escape.txt")

    def test_dotdot_at_end_raises(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            jail.resolve("a/b/..")


# ---------------------------------------------------------------------------
# PathJail — check()
# ---------------------------------------------------------------------------

class TestPathJailCheck:
    def test_path_inside_jail_passes(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        jail.check(tmp_path / "some" / "file.txt")   # should not raise

    def test_root_itself_passes(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        jail.check(tmp_path)

    def test_path_outside_jail_raises(self, tmp_path: Path) -> None:
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            jail.check(Path("/etc/passwd"))

    def test_symlink_outside_jail_raises(self, tmp_path: Path) -> None:
        evil = tmp_path / "evil"
        evil.symlink_to("/etc")
        jail = PathJail(tmp_path)
        with pytest.raises(JailbreakError):
            jail.check(evil)

    def test_check_resolves_symlinks(self, tmp_path: Path) -> None:
        target = tmp_path / "real.txt"
        target.write_text("hi")
        link = tmp_path / "link.txt"
        link.symlink_to(target.resolve())
        jail = PathJail(tmp_path)
        jail.check(link)   # should not raise — resolves to inside jail


# ---------------------------------------------------------------------------
# lookup_uid / lookup_gid
# ---------------------------------------------------------------------------

class TestLookup:
    def test_lookup_uid_current_user(self) -> None:
        uid = lookup_uid(_current_user())
        assert uid == os.getuid()

    def test_lookup_gid_current_group(self) -> None:
        gid = lookup_gid(_current_group())
        assert gid == os.getgid()

    def test_lookup_uid_unknown_raises(self) -> None:
        with pytest.raises(UnknownOwnerError, match="unknown user"):
            lookup_uid("__no_such_user_chiralite__")

    def test_lookup_gid_unknown_raises(self) -> None:
        with pytest.raises(UnknownOwnerError, match="unknown group"):
            lookup_gid("__no_such_group_chiralite__")


# ---------------------------------------------------------------------------
# apply_posix_attrs
# ---------------------------------------------------------------------------

class TestApplyPosixAttrs:
    def test_mode_applied(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        apply_posix_attrs(f, 0o600, _current_user(), _current_group())
        assert stat.S_IMODE(f.stat().st_mode) == 0o600

    def test_mode_644(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        apply_posix_attrs(f, 0o644, _current_user(), _current_group())
        assert stat.S_IMODE(f.stat().st_mode) == 0o644

    def test_ownership_set(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        apply_posix_attrs(f, 0o644, _current_user(), _current_group())
        st = f.stat()
        assert st.st_uid == os.getuid()
        assert st.st_gid == os.getgid()

    def test_unknown_user_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        with pytest.raises(UnknownOwnerError):
            apply_posix_attrs(f, 0o644, "__no_such_user__", _current_group())

    def test_unknown_group_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        with pytest.raises(UnknownOwnerError):
            apply_posix_attrs(f, 0o644, _current_user(), "__no_such_group__")

    def test_apply_on_symlink_sets_link_ownership(self, tmp_path: Path) -> None:
        target = tmp_path / "real.txt"
        target.write_text("data")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        # apply to the symlink itself — lchown does not follow
        apply_posix_attrs(link, 0o644, _current_user(), _current_group())
        lst = os.lstat(link)
        assert lst.st_uid == os.getuid()
        assert lst.st_gid == os.getgid()
