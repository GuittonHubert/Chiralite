"""Tests for sync/index.py — FileRecord, SiloIndex, events, and LWW resolution."""
from __future__ import annotations

from uuid import uuid4

import pytest

from chiralite.sync.index import (
    ConflictInfo,
    DeleteEvent,
    FileRecord,
    RenameEvent,
    SiloIndex,
    WriteEvent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SILO_ID = uuid4()
NODE_ID = "test-node"


def _make_index() -> SiloIndex:
    return SiloIndex(silo_id=SILO_ID, node_id=NODE_ID)


def _write(
    path: str = "a.txt",
    rapidhash: int = 1,
    size: int = 100,
    mtime_s: int = 1_000,
    mtime_ns: int = 0,
    recv_ts_ns: int = 1_000,
    mode: int = 0o644,
    uid_name: str = "alice",
    gid_name: str = "staff",
) -> WriteEvent:
    return WriteEvent(
        path=path,
        rapidhash=rapidhash,
        size=size,
        mtime_s=mtime_s,
        mtime_ns=mtime_ns,
        recv_ts_ns=recv_ts_ns,
        mode=mode,
        uid_name=uid_name,
        gid_name=gid_name,
    )


def _delete(path: str = "a.txt", recv_ts_ns: int = 2_000) -> DeleteEvent:
    return DeleteEvent(path=path, recv_ts_ns=recv_ts_ns)


def _rename(
    old_path: str = "a.txt",
    new_path: str = "b.txt",
    recv_ts_ns: int = 2_000,
) -> RenameEvent:
    return RenameEvent(old_path=old_path, new_path=new_path, recv_ts_ns=recv_ts_ns)


# ---------------------------------------------------------------------------
# FileRecord
# ---------------------------------------------------------------------------

class TestFileRecord:
    def test_default_not_deleted(self) -> None:
        r = FileRecord(
            rapidhash=42, size=10, mtime_s=0, mtime_ns=0,
            recv_ts_ns=0, mode=0o644, uid_name="u", gid_name="g",
        )
        assert r.deleted is False

    def test_mutable(self) -> None:
        r = FileRecord(
            rapidhash=1, size=1, mtime_s=0, mtime_ns=0,
            recv_ts_ns=0, mode=0o644, uid_name="u", gid_name="g",
        )
        r.deleted = True
        assert r.deleted is True


# ---------------------------------------------------------------------------
# SiloIndex — basic properties
# ---------------------------------------------------------------------------

class TestSiloIndexBasics:
    def test_empty_index(self) -> None:
        idx = _make_index()
        assert len(idx) == 0
        assert idx.active_count() == 0

    def test_silo_id_and_node_id_stored(self) -> None:
        idx = _make_index()
        assert idx.silo_id == SILO_ID
        assert idx.node_id == NODE_ID

    def test_len_includes_tombstones(self) -> None:
        idx = _make_index()
        idx.apply_event(_write())
        idx.apply_event(_delete())
        assert len(idx) == 1       # tombstone still in records
        assert idx.active_count() == 0

    def test_active_count_excludes_deleted(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt"))
        idx.apply_event(_write("b.txt", rapidhash=2))
        idx.apply_event(_delete("a.txt"))
        assert idx.active_count() == 1


# ---------------------------------------------------------------------------
# WriteEvent
# ---------------------------------------------------------------------------

class TestApplyWrite:
    def test_insert_new_file(self) -> None:
        idx = _make_index()
        conflict = idx.apply_event(_write())
        assert conflict is None
        assert "a.txt" in idx.records
        assert idx.records["a.txt"].rapidhash == 1

    def test_overwrite_with_newer_ts_returns_conflict(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        conflict = idx.apply_event(_write(rapidhash=99, recv_ts_ns=2_000))
        assert isinstance(conflict, ConflictInfo)
        assert conflict.winner == "incoming"
        assert conflict.kept_rapidhash == 99
        assert conflict.overwritten_rapidhash == 1
        assert idx.records["a.txt"].rapidhash == 99

    def test_older_event_loses_returns_conflict(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=2_000))
        conflict = idx.apply_event(_write(rapidhash=7, recv_ts_ns=1_000))
        assert isinstance(conflict, ConflictInfo)
        assert conflict.winner == "local"
        assert conflict.kept_rapidhash == 1
        assert conflict.overwritten_rapidhash == 7
        assert idx.records["a.txt"].rapidhash == 1  # unchanged

    def test_equal_ts_is_idempotent(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        conflict = idx.apply_event(_write(rapidhash=99, recv_ts_ns=1_000))
        assert conflict is None
        assert idx.records["a.txt"].rapidhash == 1  # original kept

    def test_write_after_tombstone_creates_fresh_record(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        idx.apply_event(_delete(recv_ts_ns=2_000))
        conflict = idx.apply_event(_write(rapidhash=5, recv_ts_ns=500))
        assert conflict is None
        assert idx.records["a.txt"].rapidhash == 5
        assert not idx.records["a.txt"].deleted

    def test_conflict_info_fields(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(rapidhash=10, recv_ts_ns=1_000))
        conflict = idx.apply_event(_write(rapidhash=20, recv_ts_ns=3_000))
        assert conflict is not None
        assert conflict.path == "a.txt"
        assert conflict.kept_recv_ts_ns == 3_000
        assert conflict.overwritten_recv_ts_ns == 1_000


# ---------------------------------------------------------------------------
# DeleteEvent
# ---------------------------------------------------------------------------

class TestApplyDelete:
    def test_delete_existing_file(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        idx.apply_event(_delete(recv_ts_ns=2_000))
        assert idx.records["a.txt"].deleted is True

    def test_delete_nonexistent_is_noop(self) -> None:
        idx = _make_index()
        conflict = idx.apply_event(_delete())
        assert conflict is None
        assert "a.txt" not in idx.records

    def test_delete_already_deleted_is_noop(self) -> None:
        idx = _make_index()
        idx.apply_event(_write())
        idx.apply_event(_delete(recv_ts_ns=2_000))
        conflict = idx.apply_event(_delete(recv_ts_ns=3_000))
        assert conflict is None

    def test_delete_older_than_existing_is_ignored(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=5_000))
        idx.apply_event(_delete(recv_ts_ns=1_000))
        assert not idx.records["a.txt"].deleted

    def test_delete_equal_ts_wins(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        idx.apply_event(_delete(recv_ts_ns=1_000))
        assert idx.records["a.txt"].deleted is True

    def test_delete_updates_recv_ts_ns(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        idx.apply_event(_delete(recv_ts_ns=9_000))
        assert idx.records["a.txt"].recv_ts_ns == 9_000

    def test_delete_returns_no_conflict_info(self) -> None:
        idx = _make_index()
        idx.apply_event(_write(recv_ts_ns=1_000))
        conflict = idx.apply_event(_delete(recv_ts_ns=2_000))
        assert conflict is None


# ---------------------------------------------------------------------------
# RenameEvent
# ---------------------------------------------------------------------------

class TestApplyRename:
    def test_rename_moves_record(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt"))
        idx.apply_event(_rename("a.txt", "b.txt"))
        assert "a.txt" not in idx.records
        assert idx.records["b.txt"].rapidhash == 1

    def test_rename_nonexistent_is_noop(self) -> None:
        idx = _make_index()
        conflict = idx.apply_event(_rename("a.txt", "b.txt"))
        assert conflict is None
        assert "b.txt" not in idx.records

    def test_rename_deleted_source_is_noop(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt"))
        idx.apply_event(_delete("a.txt", recv_ts_ns=2_000))
        conflict = idx.apply_event(_rename("a.txt", "b.txt", recv_ts_ns=3_000))
        assert conflict is None

    def test_rename_overwrites_stale_target(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=1, recv_ts_ns=1_000))
        idx.apply_event(_write("b.txt", rapidhash=2, recv_ts_ns=1_000))
        conflict = idx.apply_event(_rename("a.txt", "b.txt", recv_ts_ns=5_000))
        assert conflict is not None
        assert conflict.winner == "incoming"
        assert conflict.kept_rapidhash == 1
        assert conflict.overwritten_rapidhash == 2
        assert idx.records["b.txt"].rapidhash == 1

    def test_rename_loses_to_newer_target(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=1, recv_ts_ns=1_000))
        idx.apply_event(_write("b.txt", rapidhash=2, recv_ts_ns=9_000))
        conflict = idx.apply_event(_rename("a.txt", "b.txt", recv_ts_ns=5_000))
        assert conflict is not None
        assert conflict.winner == "local"
        # old_path should be tombstoned
        assert idx.records["a.txt"].deleted is True
        # target unchanged
        assert idx.records["b.txt"].rapidhash == 2

    def test_rename_updates_recv_ts_ns(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", recv_ts_ns=1_000))
        idx.apply_event(_rename("a.txt", "b.txt", recv_ts_ns=7_000))
        assert idx.records["b.txt"].recv_ts_ns == 7_000


# ---------------------------------------------------------------------------
# apply_event — unknown type guard
# ---------------------------------------------------------------------------

class TestApplyEventUnknown:
    def test_unknown_type_raises_type_error(self) -> None:
        idx = _make_index()
        with pytest.raises(TypeError):
            idx.apply_event("not-an-event")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# to_snapshot
# ---------------------------------------------------------------------------

class TestToSnapshot:
    def test_empty_snapshot(self) -> None:
        assert _make_index().to_snapshot() == {}

    def test_snapshot_contains_all_fields(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=7, size=42, mtime_s=100, mtime_ns=999,
                                recv_ts_ns=5_000, mode=0o644, uid_name="u", gid_name="g"))
        snap = idx.to_snapshot()
        assert "a.txt" in snap
        rec = snap["a.txt"]
        assert rec["rapidhash"] == 7
        assert rec["size"] == 42
        assert rec["mtime_s"] == 100
        assert rec["mtime_ns"] == 999
        assert rec["recv_ts_ns"] == 5_000
        assert rec["mode"] == 0o644
        assert rec["uid_name"] == "u"
        assert rec["gid_name"] == "g"
        assert rec["deleted"] is False

    def test_snapshot_includes_tombstones(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt"))
        idx.apply_event(_delete("a.txt", recv_ts_ns=9_000))
        snap = idx.to_snapshot()
        assert snap["a.txt"]["deleted"] is True


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

class TestDiff:
    def test_diff_returns_full_entry_for_missing_remote(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=1))
        entries = idx.diff({})
        assert len(entries) == 1
        assert entries[0].path == "a.txt"
        assert entries[0].is_full is True
        assert entries[0].delta_base_rapidhash is None

    def test_diff_returns_delta_entry_for_changed_file(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=42))
        remote = {"a.txt": {"rapidhash": 7}}
        entries = idx.diff(remote)
        assert len(entries) == 1
        assert entries[0].is_full is False
        assert entries[0].delta_base_rapidhash == 7

    def test_diff_skips_unchanged_files(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=5))
        remote = {"a.txt": {"rapidhash": 5}}
        assert idx.diff(remote) == []

    def test_diff_skips_deleted_files(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=1))
        idx.apply_event(_delete("a.txt", recv_ts_ns=9_000))
        assert idx.diff({}) == []

    def test_diff_accepts_object_with_rapidhash_attribute(self) -> None:
        from chiralite.protocol.messages import FileEntrySnapshot
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=10))
        snap = FileEntrySnapshot(
            rapidhash=99, size=0, mode=0o644,
            uid_name="u", gid_name="g",
            mtime_s=0, mtime_ns=0, recv_ts_ns=0,
        )
        entries = idx.diff({"a.txt": snap})
        assert len(entries) == 1
        assert entries[0].delta_base_rapidhash == 99

    def test_diff_multiple_files(self) -> None:
        idx = _make_index()
        idx.apply_event(_write("a.txt", rapidhash=1))
        idx.apply_event(_write("b.txt", rapidhash=2))
        idx.apply_event(_write("c.txt", rapidhash=3))
        remote = {"b.txt": {"rapidhash": 2}}  # b.txt unchanged
        entries = idx.diff(remote)
        paths = {e.path for e in entries}
        assert paths == {"a.txt", "c.txt"}
        # a.txt and c.txt are missing from remote → full transfers
        for e in entries:
            assert e.is_full is True
