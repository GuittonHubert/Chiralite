"""Tests for security/audit.py and security/ratelimit.py."""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from uuid import UUID

import pytest

from chiralite.security.audit import AuditLogger
from chiralite.security.ratelimit import RateLimitExceeded, RateLimiter

_SILO = UUID("550e8400-e29b-41d4-a716-446655440001")
_CN = "test-client"


# ---------------------------------------------------------------------------
# AuditLogger — format
# ---------------------------------------------------------------------------

class TestAuditLoggerFormat:
    def _read_lines(self, path: Path) -> list[dict]:
        return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]

    def test_log_creates_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("test.event")
        logger.close()
        assert log_path.exists()

    def test_log_is_valid_json(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("test.event")
        logger.close()
        lines = self._read_lines(log_path)
        assert len(lines) == 1

    def test_required_fields_present(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("some.event", severity="WARN")
        logger.close()
        record = self._read_lines(log_path)[0]
        assert "ts_ns" in record
        assert "ts_iso" in record
        assert record["severity"] == "WARN"
        assert record["event"] == "some.event"

    def test_ts_ns_is_positive_int(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("x")
        logger.close()
        record = self._read_lines(log_path)[0]
        assert isinstance(record["ts_ns"], int)
        assert record["ts_ns"] > 0

    def test_ts_iso_format(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("x")
        logger.close()
        ts_iso = self._read_lines(log_path)[0]["ts_iso"]
        assert ts_iso.endswith("Z")
        assert "T" in ts_iso

    def test_client_cn_included(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("auth.ok", client_cn=_CN)
        logger.close()
        assert self._read_lines(log_path)[0]["client_cn"] == _CN

    def test_silo_id_included(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("session.start", silo_id=_SILO)
        logger.close()
        record = self._read_lines(log_path)[0]
        assert record["silo_id"] == str(_SILO)

    def test_path_included(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("file.write", path="src/main.py")
        logger.close()
        assert self._read_lines(log_path)[0]["path"] == "src/main.py"

    def test_detail_included(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("file.write", detail={"size_bytes": 42})
        logger.close()
        assert self._read_lines(log_path)[0]["detail"]["size_bytes"] == 42

    def test_empty_optional_fields_omitted(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("ping")
        logger.close()
        record = self._read_lines(log_path)[0]
        assert "client_cn" not in record
        assert "silo_id" not in record
        assert "path" not in record
        assert "detail" not in record

    def test_multiple_events_multiple_lines(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("event.a")
        logger.log("event.b")
        logger.log("event.c")
        logger.close()
        lines = self._read_lines(log_path)
        assert len(lines) == 3
        assert [r["event"] for r in lines] == ["event.a", "event.b", "event.c"]

    def test_parent_dirs_created(self, tmp_path: Path) -> None:
        log_path = tmp_path / "sub" / "dir" / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("x")
        logger.close()
        assert log_path.exists()


# ---------------------------------------------------------------------------
# AuditLogger — convenience helpers
# ---------------------------------------------------------------------------

class TestAuditLoggerHelpers:
    def _get_record(self, tmp_path: Path, fn) -> dict:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        fn(logger)
        logger.close()
        return json.loads(log_path.read_text().splitlines()[0])

    def test_log_auth_ok(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_auth_ok(_CN, _SILO))
        assert r["event"] == "auth.ok"
        assert r["severity"] == "INFO"
        assert r["client_cn"] == _CN

    def test_log_auth_fail(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_auth_fail(_CN, "bad sig"))
        assert r["event"] == "auth.fail"
        assert r["severity"] == "WARN"
        assert r["detail"]["reason"] == "bad sig"

    def test_log_auth_replay(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_auth_replay(_CN))
        assert r["event"] == "auth.replay"
        assert r["severity"] == "ERROR"

    def test_log_file_write(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path,
            lambda l: l.log_file_write(
                _CN, _SILO, "src/main.py",
                rapidhash_before=111, rapidhash_after=222,
                recv_ts_ns=999, delta=True, size_bytes=512,
            ),
        )
        assert r["event"] == "file.write"
        assert r["detail"]["delta"] is True
        assert r["detail"]["size_bytes"] == 512

    def test_log_file_delete(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_file_delete(_CN, _SILO, "x.py"))
        assert r["event"] == "file.delete"
        assert r["path"] == "x.py"

    def test_log_file_rename(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path, lambda l: l.log_file_rename(_CN, _SILO, "old.py", "new.py")
        )
        assert r["event"] == "file.rename"
        assert r["detail"]["new_path"] == "new.py"

    def test_log_conflict_lww(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path,
            lambda l: l.log_conflict_lww(
                _CN, _SILO, "x.py", kept_rapidhash=1, overwritten_rapidhash=2
            ),
        )
        assert r["event"] == "conflict.lww"
        assert r["severity"] == "WARN"

    def test_log_quarantine(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path, lambda l: l.log_quarantine(_CN, _SILO, "bad.exe", "Eicar")
        )
        assert r["event"] == "quarantine"
        assert r["severity"] == "CRITICAL"
        assert r["detail"]["virus"] == "Eicar"

    def test_log_path_traversal(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path, lambda l: l.log_path_traversal(_CN, _SILO, "../etc/passwd")
        )
        assert r["event"] == "security.path_traversal"
        assert r["severity"] == "CRITICAL"

    def test_log_uid_denied(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path, lambda l: l.log_uid_denied(_CN, _SILO, "root")
        )
        assert r["event"] == "security.uid_denied"
        assert r["severity"] == "CRITICAL"

    def test_log_mode_stripped(self, tmp_path: Path) -> None:
        r = self._get_record(
            tmp_path,
            lambda l: l.log_mode_stripped(_CN, _SILO, "x.py", 0o4755, 0o644),
        )
        assert r["event"] == "security.mode_stripped"
        assert r["severity"] == "WARN"

    def test_log_session_start(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_session_start(_CN, _SILO))
        assert r["event"] == "session.start"

    def test_log_session_end(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_session_end(_CN, _SILO))
        assert r["event"] == "session.end"

    def test_log_blacklist_sync(self, tmp_path: Path) -> None:
        r = self._get_record(tmp_path, lambda l: l.log_blacklist_sync(_CN, _SILO))
        assert r["event"] == "blacklist.sync"


# ---------------------------------------------------------------------------
# AuditLogger — rotation
# ---------------------------------------------------------------------------

class TestAuditLoggerRotation:
    def test_rotation_creates_gz_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        # tiny max_bytes forces rotation after the first event
        logger = AuditLogger(log_path, max_bytes=1, backup_count=3)
        logger.log("event.a")
        logger.log("event.b")  # triggers rotation of event.a
        logger.flush()
        logger.close()

        gz_files = list(tmp_path.glob("*.gz"))
        assert len(gz_files) >= 1

    def test_rotated_gz_is_valid_gzip(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_bytes=1, backup_count=3)
        logger.log("event.a")
        logger.log("event.b")
        logger.flush()
        logger.close()

        for gz_file in tmp_path.glob("*.gz"):
            with gzip.open(gz_file, "rb") as f:
                content = f.read()
            assert len(content) > 0

    def test_rotated_gz_contains_valid_json(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_bytes=1, backup_count=3)
        logger.log("event.x")
        logger.log("event.y")
        logger.flush()
        logger.close()

        for gz_file in tmp_path.glob("*.gz"):
            with gzip.open(gz_file, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        record = json.loads(line)
                        assert "event" in record


# ---------------------------------------------------------------------------
# RateLimiter — basic behavior
# ---------------------------------------------------------------------------

class TestRateLimiterBasic:
    def test_within_limit_returns_true(self) -> None:
        rl = RateLimiter(limit=5, window_s=1.0)
        for _ in range(5):
            assert rl.check("key") is True

    def test_exceeding_limit_returns_false(self) -> None:
        rl = RateLimiter(limit=3, window_s=1.0)
        for _ in range(3):
            rl.check("key")
        assert rl.check("key") is False

    def test_require_raises_on_excess(self) -> None:
        rl = RateLimiter(limit=2, window_s=1.0)
        rl.require("key")
        rl.require("key")
        with pytest.raises(RateLimitExceeded, match="rate limit exceeded"):
            rl.require("key")

    def test_different_keys_independent(self) -> None:
        rl = RateLimiter(limit=1, window_s=1.0)
        assert rl.check("alice") is True
        assert rl.check("bob") is True
        assert rl.check("alice") is False   # alice exhausted, bob still ok
        assert rl.check("bob") is False

    def test_rejected_calls_not_counted(self) -> None:
        rl = RateLimiter(limit=2, window_s=10.0)
        rl.check("k")
        rl.check("k")
        # limit reached; next three calls rejected
        assert rl.check("k") is False
        assert rl.check("k") is False
        assert rl.check("k") is False
        # still only 2 hits recorded; still at limit
        assert rl.remaining("k") == 0

    def test_remaining_decrements(self) -> None:
        rl = RateLimiter(limit=5, window_s=10.0)
        assert rl.remaining("k") == 5
        rl.check("k")
        assert rl.remaining("k") == 4

    def test_remaining_zero_when_full(self) -> None:
        rl = RateLimiter(limit=2, window_s=10.0)
        rl.check("k")
        rl.check("k")
        assert rl.remaining("k") == 0

    def test_reset_clears_hits(self) -> None:
        rl = RateLimiter(limit=1, window_s=10.0)
        rl.check("k")
        assert rl.check("k") is False
        rl.reset("k")
        assert rl.check("k") is True

    def test_reset_unknown_key_no_error(self) -> None:
        rl = RateLimiter(limit=5, window_s=1.0)
        rl.reset("nonexistent")  # no exception

    def test_limit_one(self) -> None:
        rl = RateLimiter(limit=1, window_s=1.0)
        assert rl.check("x") is True
        assert rl.check("x") is False

    def test_invalid_limit_raises(self) -> None:
        with pytest.raises(ValueError, match="limit"):
            RateLimiter(limit=0, window_s=1.0)

    def test_invalid_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_s"):
            RateLimiter(limit=10, window_s=0.0)


# ---------------------------------------------------------------------------
# RateLimiter — window expiry
# ---------------------------------------------------------------------------

class TestRateLimiterWindowExpiry:
    def test_hits_expire_after_window(self) -> None:
        rl = RateLimiter(limit=2, window_s=0.05)
        rl.check("k")
        rl.check("k")
        assert rl.check("k") is False
        time.sleep(0.06)
        # Window has passed; all 2 slots are available again
        assert rl.check("k") is True

    def test_remaining_after_expiry(self) -> None:
        rl = RateLimiter(limit=3, window_s=0.05)
        rl.check("k")
        rl.check("k")
        assert rl.remaining("k") == 1
        time.sleep(0.06)
        assert rl.remaining("k") == 3
