"""Tests for sync/journal.py — EventJournal persistence and crash recovery."""
from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from chiralite.sync.index import DeleteEvent, RenameEvent, WriteEvent
from chiralite.sync.journal import EventJournal, JournalError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SILO_ID = uuid4()
NODE_ID = "test-node"


def _journal(tmp_path: Path) -> EventJournal:
    return EventJournal(tmp_path, silo_id=SILO_ID, node_id=NODE_ID)


def _write(
    path: str = "a.txt",
    rapidhash: int = 1,
    size: int = 100,
    recv_ts_ns: int = 1_000,
) -> WriteEvent:
    return WriteEvent(
        path=path, rapidhash=rapidhash, size=size,
        mtime_s=0, mtime_ns=0, recv_ts_ns=recv_ts_ns,
        mode=0o644, uid_name="alice", gid_name="staff",
    )


def _delete(path: str = "a.txt", recv_ts_ns: int = 2_000) -> DeleteEvent:
    return DeleteEvent(path=path, recv_ts_ns=recv_ts_ns)


def _rename(
    old_path: str = "a.txt", new_path: str = "b.txt", recv_ts_ns: int = 2_000,
) -> RenameEvent:
    return RenameEvent(old_path=old_path, new_path=new_path, recv_ts_ns=recv_ts_ns)


# ---------------------------------------------------------------------------
# Fresh journal
# ---------------------------------------------------------------------------

class TestFreshJournal:
    def test_empty_index_on_fresh_start(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            assert len(j.index) == 0

    def test_silo_id_and_node_id_propagated(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            assert j.index.silo_id == SILO_ID
            assert j.index.node_id == NODE_ID

    def test_journal_file_created_on_first_append(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write())
        assert (tmp_path / "journal.ndjson").exists()


# ---------------------------------------------------------------------------
# append — in-memory effect
# ---------------------------------------------------------------------------

class TestAppendInMemory:
    def test_append_write_event(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=42))
            assert j.index.records["a.txt"].rapidhash == 42

    def test_append_delete_event(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", recv_ts_ns=1_000))
            j.append(_delete("a.txt", recv_ts_ns=2_000))
            assert j.index.records["a.txt"].deleted is True

    def test_append_rename_event(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt"))
            j.append(_rename("a.txt", "b.txt"))
            assert "a.txt" not in j.index.records
            assert "b.txt" in j.index.records

    def test_append_returns_conflict_info(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write(recv_ts_ns=1_000))
            conflict = j.append(_write(rapidhash=99, recv_ts_ns=2_000))
        assert conflict is not None
        assert conflict.winner == "incoming"

    def test_append_returns_none_on_no_conflict(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            result = j.append(_write())
        assert result is None


# ---------------------------------------------------------------------------
# Persistence — replay on reopen
# ---------------------------------------------------------------------------

class TestReplayOnReopen:
    def test_write_event_survives_reopen(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=7))

        with _journal(tmp_path) as j:
            assert j.index.records["a.txt"].rapidhash == 7

    def test_delete_event_survives_reopen(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", recv_ts_ns=1_000))
            j.append(_delete("a.txt", recv_ts_ns=9_000))

        with _journal(tmp_path) as j:
            assert j.index.records["a.txt"].deleted is True

    def test_rename_event_survives_reopen(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=3))
            j.append(_rename("a.txt", "b.txt"))

        with _journal(tmp_path) as j:
            assert "a.txt" not in j.index.records
            assert j.index.records["b.txt"].rapidhash == 3

    def test_multiple_events_replayed_in_order(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("x.txt", rapidhash=1, recv_ts_ns=1_000))
            j.append(_write("x.txt", rapidhash=2, recv_ts_ns=2_000))  # LWW overwrite

        with _journal(tmp_path) as j:
            assert j.index.records["x.txt"].rapidhash == 2

    def test_journal_accumulates_across_reopens(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt"))

        with _journal(tmp_path) as j:
            j.append(_write("b.txt", rapidhash=2))

        with _journal(tmp_path) as j:
            assert "a.txt" in j.index.records
            assert "b.txt" in j.index.records


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------

class TestCheckpoint:
    def test_checkpoint_creates_file(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt"))
            j.checkpoint()
        assert (tmp_path / "checkpoint.json").exists()

    def test_checkpoint_clears_journal(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt"))
            j.checkpoint()
        content = (tmp_path / "journal.ndjson").read_text()
        assert content == ""

    def test_state_survives_checkpoint_and_reopen(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=55))
            j.checkpoint()

        with _journal(tmp_path) as j:
            assert j.index.records["a.txt"].rapidhash == 55

    def test_events_after_checkpoint_survive_reopen(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=1))
            j.checkpoint()
            j.append(_write("b.txt", rapidhash=2))

        with _journal(tmp_path) as j:
            assert j.index.records["a.txt"].rapidhash == 1
            assert j.index.records["b.txt"].rapidhash == 2

    def test_checkpoint_preserves_tombstones(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", recv_ts_ns=1_000))
            j.append(_delete("a.txt", recv_ts_ns=2_000))
            j.checkpoint()

        with _journal(tmp_path) as j:
            assert j.index.records["a.txt"].deleted is True

    def test_replay_after_checkpoint_is_idempotent(self, tmp_path: Path) -> None:
        """Journal entries that pre-date the checkpoint must not corrupt the index."""
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=10, recv_ts_ns=1_000))
            j.checkpoint()
            # Manually put old journal content back to simulate a crash between
            # checkpoint rename and journal truncation.
            (tmp_path / "journal.ndjson").write_text(
                '{"kind":"write","path":"a.txt","rapidhash":10,'
                '"size":100,"mtime_s":0,"mtime_ns":0,"recv_ts_ns":1000,'
                '"mode":420,"uid_name":"alice","gid_name":"staff"}\n'
            )

        with _journal(tmp_path) as j:
            # Equal recv_ts_ns → keep existing (idempotent).
            assert j.index.records["a.txt"].rapidhash == 10
            assert j.index.active_count() == 1

    def test_multiple_checkpoints(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write("a.txt", rapidhash=1))
            j.checkpoint()
            j.append(_write("b.txt", rapidhash=2))
            j.checkpoint()
            j.append(_write("c.txt", rapidhash=3))

        with _journal(tmp_path) as j:
            assert j.index.active_count() == 3


# ---------------------------------------------------------------------------
# Corrupt files
# ---------------------------------------------------------------------------

class TestCorruption:
    def test_corrupt_checkpoint_raises(self, tmp_path: Path) -> None:
        (tmp_path / "checkpoint.json").write_text("not valid json", encoding="utf-8")
        with pytest.raises(JournalError, match="corrupt checkpoint"):
            _journal(tmp_path)

    def test_corrupt_journal_line_raises(self, tmp_path: Path) -> None:
        (tmp_path / "journal.ndjson").write_text("not valid json\n", encoding="utf-8")
        with pytest.raises(JournalError, match="corrupt journal entry"):
        # Journal is opened after load, so we need to suppress the close error.
            try:
                _journal(tmp_path)
            except JournalError:
                raise

    def test_unknown_kind_raises(self, tmp_path: Path) -> None:
        (tmp_path / "journal.ndjson").write_text(
            '{"kind":"unknown","path":"x"}\n', encoding="utf-8"
        )
        with pytest.raises(JournalError):
            _journal(tmp_path)

    def test_missing_field_in_journal_raises(self, tmp_path: Path) -> None:
        (tmp_path / "journal.ndjson").write_text(
            '{"kind":"write","path":"a.txt"}\n', encoding="utf-8"
        )
        with pytest.raises(JournalError):
            _journal(tmp_path)

    def test_blank_lines_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "journal.ndjson").write_text(
            '\n\n'
            '{"kind":"write","path":"a.txt","rapidhash":1,"size":0,'
            '"mtime_s":0,"mtime_ns":0,"recv_ts_ns":0,'
            '"mode":420,"uid_name":"u","gid_name":"g"}\n'
            '\n',
            encoding="utf-8",
        )
        with _journal(tmp_path) as j:
            assert "a.txt" in j.index.records


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_close_on_exit(self, tmp_path: Path) -> None:
        j = _journal(tmp_path)
        j.__exit__(None, None, None)
        assert j._fp.closed

    def test_with_statement(self, tmp_path: Path) -> None:
        with _journal(tmp_path) as j:
            j.append(_write())
        assert j._fp.closed
