"""Tests for protocol/messages.py — models, validators, and discriminated union."""
from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from chiralite.protocol.messages import (
    AcceptMsg,
    AnyMsg,
    AuthErrorMsg,
    BlacklistSyncMsg,
    ChallengeMsg,
    ConflictNotifyMsg,
    DirCreateMsg,
    DirDeleteMsg,
    DirRenameMsg,
    FileDeleteMsg,
    FileEntry,
    FileEntrySnapshot,
    FileRenameMsg,
    FileWriteMsg,
    HelloMsg,
    MsgType,
    PingMsg,
    PongMsg,
    ResponseMsg,
    SessionEndMsg,
    SyncRequestMsg,
    SyncStateMsg,
    TransferAckMsg,
    TransferBeginMsg,
    TransferChunkMsg,
    TransferCommitMsg,
    TransferNackMsg,
    parse_json,
    parse_msg,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SILO_ID = uuid4()
TRANSFER_ID = uuid4()
NONCE = b"\xab" * 32
CHALLENGE = b"\xcd" * 32
SIG = b"\xef" * 64
ECDH_PUB = b"\x12" * 32
TOKEN = b"\x34" * 16


def _full_entry(**overrides: object) -> FileEntry:
    defaults: dict[str, object] = dict(
        path="src/main.py",
        rapidhash=42,
        size=1024,
        mode=0o644,
        uid_name="alice",
        gid_name="staff",
        mtime_s=1_700_000_000,
        mtime_ns=123_456_789,
        is_full=True,
    )
    defaults.update(overrides)
    return FileEntry(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# MsgType
# ---------------------------------------------------------------------------

class TestMsgType:
    def test_all_values_are_strings(self) -> None:
        for member in MsgType:
            assert isinstance(member.value, str)

    def test_count(self) -> None:
        assert len(MsgType) == 23

    def test_handshake_values(self) -> None:
        assert MsgType.HELLO == "hello"
        assert MsgType.AUTH_ERROR == "auth_error"

    def test_transfer_values(self) -> None:
        assert MsgType.TRANSFER_BEGIN == "transfer.begin"
        assert MsgType.TRANSFER_NACK == "transfer.nack"


# ---------------------------------------------------------------------------
# FileEntry
# ---------------------------------------------------------------------------

class TestFileEntry:
    def test_valid_full_transfer(self) -> None:
        e = _full_entry()
        assert e.path == "src/main.py"
        assert e.is_full is True
        assert e.delta_base_rapidhash is None

    def test_valid_delta_transfer(self) -> None:
        e = _full_entry(is_full=False, delta_base_rapidhash=99)
        assert e.delta_base_rapidhash == 99

    def test_empty_path_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            _full_entry(path="")

    def test_absolute_path_rejected(self) -> None:
        with pytest.raises(ValidationError, match="absolute"):
            _full_entry(path="/etc/passwd")

    def test_dotdot_rejected(self) -> None:
        with pytest.raises(ValidationError, match="traversal"):
            _full_entry(path="../../etc/shadow")

    def test_null_byte_in_path_rejected(self) -> None:
        with pytest.raises(ValidationError, match="null byte"):
            _full_entry(path="foo\x00bar")

    def test_mtime_ns_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            _full_entry(mtime_ns=1_000_000_000)  # > 999_999_999
        with pytest.raises(ValidationError):
            _full_entry(mtime_ns=-1)

    def test_rapidhash_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            _full_entry(rapidhash=-1)
        with pytest.raises(ValidationError):
            _full_entry(rapidhash=2**64)

    def test_negative_size_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _full_entry(size=-1)

    def test_mode_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            _full_entry(mode=0o10000)  # > 0o7777

    def test_symlink_requires_target(self) -> None:
        with pytest.raises(ValidationError, match="symlink_target is required"):
            _full_entry(is_symlink=True, symlink_target=None)

    def test_non_symlink_forbids_target(self) -> None:
        with pytest.raises(ValidationError, match="must be None"):
            _full_entry(is_symlink=False, symlink_target="foo/bar")

    def test_symlink_target_traversal_rejected(self) -> None:
        with pytest.raises(ValidationError, match="traversal"):
            _full_entry(is_symlink=True, symlink_target="../../evil")

    def test_delta_without_base_rejected(self) -> None:
        with pytest.raises(ValidationError, match="delta_base_rapidhash is required"):
            _full_entry(is_full=False, delta_base_rapidhash=None)

    def test_full_with_base_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must be None for a full"):
            _full_entry(is_full=True, delta_base_rapidhash=7)

    def test_frozen(self) -> None:
        e = _full_entry()
        with pytest.raises(ValidationError):
            e.path = "other.py"  # type: ignore[misc]

    def test_json_roundtrip(self) -> None:
        e = _full_entry()
        e2 = FileEntry.model_validate_json(e.model_dump_json())
        assert e == e2


# ---------------------------------------------------------------------------
# Handshake messages
# ---------------------------------------------------------------------------

class TestHandshakeMsgs:
    def test_hello_roundtrip(self) -> None:
        msg = HelloMsg(
            client_cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
            nonce_c=NONCE,
            ts_ns=1_700_000_000_000_000_000,
            silo_id=SILO_ID,
        )
        back = HelloMsg.model_validate_json(msg.model_dump_json())
        assert back.nonce_c == NONCE
        assert back.silo_id == SILO_ID

    def test_challenge_roundtrip(self) -> None:
        msg = ChallengeMsg(server_cert_pem="pem", nonce_s=NONCE, challenge=CHALLENGE)
        back = ChallengeMsg.model_validate_json(msg.model_dump_json())
        assert back.challenge == CHALLENGE

    def test_response_roundtrip(self) -> None:
        msg = ResponseMsg(sig_c=SIG, ecdh_pub_c=ECDH_PUB)
        back = ResponseMsg.model_validate_json(msg.model_dump_json())
        assert back.ecdh_pub_c == ECDH_PUB

    def test_accept_roundtrip(self) -> None:
        msg = AcceptMsg(
            sig_s=SIG, ecdh_pub_s=ECDH_PUB,
            session_token=TOKEN, silo_id_ack=SILO_ID,
        )
        assert AcceptMsg.model_validate_json(msg.model_dump_json()).silo_id_ack == SILO_ID

    def test_auth_error(self) -> None:
        msg = AuthErrorMsg(reason="certificate expired")
        assert msg.type == MsgType.AUTH_ERROR


# ---------------------------------------------------------------------------
# Sync-control messages
# ---------------------------------------------------------------------------

class TestSyncMsgs:
    def test_sync_request(self) -> None:
        msg = SyncRequestMsg()
        assert msg.type == MsgType.SYNC_REQUEST

    def test_sync_state_roundtrip(self) -> None:
        snap = FileEntrySnapshot(
            rapidhash=1, size=100, mode=0o644,
            uid_name="bob", gid_name="staff",
            mtime_s=1_700_000_000, mtime_ns=0,
            recv_ts_ns=1_700_000_000_000_000_001,
        )
        msg = SyncStateMsg(silo_id=SILO_ID, node_id="server-1", records={"a.txt": snap})
        back = SyncStateMsg.model_validate_json(msg.model_dump_json())
        assert back.records["a.txt"].rapidhash == 1

    def test_blacklist_sync(self) -> None:
        msg = BlacklistSyncMsg(patterns=["**/.git/**", "**/*.pyc"])
        assert len(msg.patterns) == 2


# ---------------------------------------------------------------------------
# File-event messages
# ---------------------------------------------------------------------------

class TestFileEventMsgs:
    def test_file_write_msg(self) -> None:
        msg = FileWriteMsg(transfer_id=TRANSFER_ID, entry=_full_entry())
        assert msg.entry.path == "src/main.py"

    def test_file_delete_valid(self) -> None:
        msg = FileDeleteMsg(path="old/file.txt", recv_ts_ns=123)
        assert msg.path == "old/file.txt"

    def test_file_delete_traversal_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FileDeleteMsg(path="../escape.txt", recv_ts_ns=0)

    def test_file_rename(self) -> None:
        msg = FileRenameMsg(old_path="a.txt", new_path="b.txt", recv_ts_ns=0)
        assert msg.new_path == "b.txt"

    def test_dir_create(self) -> None:
        msg = DirCreateMsg(path="src/new", mode=0o755, uid_name="alice", gid_name="staff")
        assert msg.mode == 0o755

    def test_dir_delete(self) -> None:
        DirDeleteMsg(path="old/dir")

    def test_dir_rename(self) -> None:
        DirRenameMsg(old_path="src/old", new_path="src/new")


# ---------------------------------------------------------------------------
# Transfer messages
# ---------------------------------------------------------------------------

class TestTransferMsgs:
    def test_transfer_begin_roundtrip(self) -> None:
        msg = TransferBeginMsg(
            transfer_id=TRANSFER_ID,
            entry=_full_entry(),
            total_size=4096,
            chunk_count=2,
        )
        back = TransferBeginMsg.model_validate_json(msg.model_dump_json())
        assert back.transfer_id == TRANSFER_ID

    def test_transfer_chunk_roundtrip(self) -> None:
        msg = TransferChunkMsg(transfer_id=TRANSFER_ID, seq=0, data=b"\xde\xad\xbe\xef")
        back = TransferChunkMsg.model_validate_json(msg.model_dump_json())
        assert back.data == b"\xde\xad\xbe\xef"

    def test_transfer_commit(self) -> None:
        msg = TransferCommitMsg(transfer_id=TRANSFER_ID, rapidhash=2**63)
        assert msg.rapidhash == 2**63

    def test_transfer_ack(self) -> None:
        msg = TransferAckMsg(transfer_id=TRANSFER_ID, scan_result="clean")
        assert msg.type == MsgType.TRANSFER_ACK

    def test_transfer_nack(self) -> None:
        msg = TransferNackMsg(transfer_id=TRANSFER_ID, reason="quarantine")
        assert msg.reason == "quarantine"

    def test_chunk_count_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            TransferBeginMsg(
                transfer_id=TRANSFER_ID, entry=_full_entry(),
                total_size=0, chunk_count=0,
            )


# ---------------------------------------------------------------------------
# Session messages
# ---------------------------------------------------------------------------

class TestSessionMsgs:
    def test_ping_pong(self) -> None:
        ping = PingMsg(ts_ns=999)
        pong = PongMsg(ts_ns=ping.ts_ns)
        assert pong.ts_ns == 999

    def test_session_end_default_reason(self) -> None:
        msg = SessionEndMsg()
        assert msg.reason == ""

    def test_conflict_notify(self) -> None:
        msg = ConflictNotifyMsg(
            path="src/main.py",
            silo_id=SILO_ID,
            kept_rapidhash=100,
            overwritten_rapidhash=50,
            recv_ts_ns=1_700_000_000_000_000_000,
        )
        assert msg.kept_rapidhash == 100


# ---------------------------------------------------------------------------
# Discriminated union — parse_msg / parse_json
# ---------------------------------------------------------------------------

class TestParseMsg:
    def _serialise(self, msg: object) -> dict[str, object]:
        from pydantic import TypeAdapter
        raw = TypeAdapter(AnyMsg).dump_python(msg, mode="json")  # type: ignore[arg-type]
        assert isinstance(raw, dict)
        return raw

    def test_dispatches_hello(self) -> None:
        msg = HelloMsg(
            client_cert_pem="pem", nonce_c=NONCE,
            ts_ns=0, silo_id=SILO_ID,
        )
        parsed = parse_msg(self._serialise(msg))
        assert isinstance(parsed, HelloMsg)

    def test_dispatches_ping(self) -> None:
        parsed = parse_msg({"type": "ping", "ts_ns": 42})
        assert isinstance(parsed, PingMsg)
        assert parsed.ts_ns == 42

    def test_dispatches_session_end(self) -> None:
        parsed = parse_msg({"type": "session.end", "reason": "shutdown"})
        assert isinstance(parsed, SessionEndMsg)

    def test_unknown_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            parse_msg({"type": "unknown.type"})

    def test_parse_json_bytes(self) -> None:
        raw = b'{"type": "pong", "ts_ns": 7}'
        parsed = parse_json(raw)
        assert isinstance(parsed, PongMsg)
        assert parsed.ts_ns == 7

    def test_parse_json_str(self) -> None:
        parsed = parse_json('{"type": "sync.request"}')
        assert isinstance(parsed, SyncRequestMsg)

    def test_all_msg_types_round_trip(self) -> None:
        """Every concrete message type survives a JSON round-trip through parse_json."""
        messages: list[object] = [
            HelloMsg(client_cert_pem="p", nonce_c=NONCE, ts_ns=0, silo_id=SILO_ID),
            ChallengeMsg(server_cert_pem="p", nonce_s=NONCE, challenge=CHALLENGE),
            ResponseMsg(sig_c=SIG, ecdh_pub_c=ECDH_PUB),
            AcceptMsg(sig_s=SIG, ecdh_pub_s=ECDH_PUB, session_token=TOKEN, silo_id_ack=SILO_ID),
            AuthErrorMsg(reason="bad cert"),
            SyncRequestMsg(),
            SyncStateMsg(silo_id=SILO_ID, node_id="n1", records={}),
            BlacklistSyncMsg(patterns=[]),
            FileWriteMsg(transfer_id=TRANSFER_ID, entry=_full_entry()),
            FileDeleteMsg(path="x.py", recv_ts_ns=0),
            FileRenameMsg(old_path="a.py", new_path="b.py", recv_ts_ns=0),
            DirCreateMsg(path="d", mode=0o755, uid_name="u", gid_name="g"),
            DirDeleteMsg(path="d"),
            DirRenameMsg(old_path="d1", new_path="d2"),
            TransferBeginMsg(transfer_id=TRANSFER_ID, entry=_full_entry(), total_size=1, chunk_count=1),
            TransferChunkMsg(transfer_id=TRANSFER_ID, seq=0, data=b"x"),
            TransferCommitMsg(transfer_id=TRANSFER_ID, rapidhash=0),
            TransferAckMsg(transfer_id=TRANSFER_ID, scan_result="clean"),
            TransferNackMsg(transfer_id=TRANSFER_ID, reason="err"),
            ConflictNotifyMsg(path="f", silo_id=SILO_ID, kept_rapidhash=1, overwritten_rapidhash=2, recv_ts_ns=0),
            PingMsg(ts_ns=1),
            PongMsg(ts_ns=1),
            SessionEndMsg(),
        ]
        from pydantic import TypeAdapter
        adapter: TypeAdapter[AnyMsg] = TypeAdapter(AnyMsg)  # type: ignore[type-arg]
        for msg in messages:
            raw = adapter.dump_json(msg)  # type: ignore[arg-type]
            parsed = parse_json(raw)
            assert type(parsed) is type(msg)
