"""Tests for protocol/framing.py and protocol/state_machine.py."""
from __future__ import annotations

import asyncio
import os

import pytest

from chiralite.crypto.payload import FrameError, PayloadCodec, ReplayError
from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import (
    AcceptMsg,
    AuthErrorMsg,
    BlacklistSyncMsg,
    ChallengeMsg,
    HelloMsg,
    PingMsg,
    PongMsg,
    ResponseMsg,
    SessionEndMsg,
    SyncRequestMsg,
    TransferAckMsg,
)
from chiralite.protocol.state_machine import (
    InvalidTransition,
    SessionState,
    SessionStateMachine,
)
from chiralite.transport.websocket import Connection

# ---------------------------------------------------------------------------
# Fake in-process Connection backed by asyncio queues
# ---------------------------------------------------------------------------

def _pipe() -> tuple[FramedConnection, FramedConnection]:
    """Return two FramedConnections connected by in-memory queues."""
    q_ab: asyncio.Queue[bytes] = asyncio.Queue()
    q_ba: asyncio.Queue[bytes] = asyncio.Queue()

    class _FakeWS:
        def __init__(self, send_q: asyncio.Queue[bytes], recv_q: asyncio.Queue[bytes]) -> None:
            self._sq = send_q
            self._rq = recv_q

        async def send(self, data: bytes) -> None:
            await self._sq.put(data)

        async def recv(self) -> bytes:
            return await self._rq.get()

        async def close(self) -> None:
            pass

        remote_address = ("127.0.0.1", 9999)

    conn_a = Connection(_FakeWS(q_ab, q_ba), remote_addr="127.0.0.1:9999")  # type: ignore[arg-type]
    conn_b = Connection(_FakeWS(q_ba, q_ab), remote_addr="127.0.0.1:9999")  # type: ignore[arg-type]
    return FramedConnection(conn_a), FramedConnection(conn_b)


def _codec_pair(
    key: bytes | None = None,
    token: bytes | None = None,
) -> tuple[PayloadCodec, PayloadCodec]:
    k = key or os.urandom(32)
    t = token or os.urandom(16)
    return PayloadCodec(k, t), PayloadCodec(k, t)


# ---------------------------------------------------------------------------
# FramedConnection — plain mode (handshake)
# ---------------------------------------------------------------------------

class TestPlainMode:
    async def test_hello_round_trip(self):
        import uuid
        a, b = _pipe()
        hello = HelloMsg(
            client_cert_pem="-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq\n-----END CERTIFICATE-----\n",
            nonce_c=os.urandom(32),
            ts_ns=1_700_000_000_000_000_000,
            silo_id=uuid.uuid4(),
        )
        await a.send_plain(hello)
        received = await b.recv_plain()
        assert isinstance(received, HelloMsg)
        assert received.nonce_c == hello.nonce_c
        assert received.silo_id == hello.silo_id

    async def test_challenge_round_trip(self):
        a, b = _pipe()
        msg = ChallengeMsg(
            server_cert_pem="-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n",
            nonce_s=os.urandom(32),
            challenge=os.urandom(32),
        )
        await a.send_plain(msg)
        received = await b.recv_plain()
        assert isinstance(received, ChallengeMsg)
        assert received.challenge == msg.challenge

    async def test_response_round_trip(self):
        a, b = _pipe()
        msg = ResponseMsg(sig_c=os.urandom(64), ecdh_pub_c=os.urandom(32))
        await a.send_plain(msg)
        received = await b.recv_plain()
        assert isinstance(received, ResponseMsg)
        assert received.ecdh_pub_c == msg.ecdh_pub_c

    async def test_accept_round_trip(self):
        import uuid
        a, b = _pipe()
        msg = AcceptMsg(
            sig_s=os.urandom(64),
            ecdh_pub_s=os.urandom(32),
            session_token=os.urandom(32),
            silo_id_ack=uuid.uuid4(),
        )
        await a.send_plain(msg)
        received = await b.recv_plain()
        assert isinstance(received, AcceptMsg)
        assert received.session_token == msg.session_token

    async def test_auth_error_round_trip(self):
        a, b = _pipe()
        msg = AuthErrorMsg(reason="timestamp out of range")
        await a.send_plain(msg)
        received = await b.recv_plain()
        assert isinstance(received, AuthErrorMsg)
        assert received.reason == "timestamp out of range"

    async def test_malformed_json_raises(self):
        a, b = _pipe()
        # Inject raw garbage directly into the queue
        await a._conn.send(b"not json at all {{{")
        with pytest.raises(Exception):  # pydantic ValidationError or json decode error
            await b.recv_plain()

    async def test_unknown_msg_type_raises(self):
        a, b = _pipe()
        await a._conn.send(b'{"type": "unknown.type"}')
        with pytest.raises(Exception):
            await b.recv_plain()


# ---------------------------------------------------------------------------
# FramedConnection — encrypted mode
# ---------------------------------------------------------------------------

class TestEncryptedMode:
    async def test_ping_pong_round_trip(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        ping = PingMsg(ts_ns=123_456_789)
        await a.send(ping)
        received = await b.recv()
        assert isinstance(received, PingMsg)
        assert received.ts_ns == 123_456_789

    async def test_multiple_messages_increment_seq(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        for i in range(5):
            await a.send(PingMsg(ts_ns=i))
            msg = await b.recv()
            assert isinstance(msg, PingMsg)
            assert msg.ts_ns == i

    async def test_bidirectional(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        await a.send(PingMsg(ts_ns=1))
        await b.send(PongMsg(ts_ns=1))

        recv_b = await b.recv()
        recv_a = await a.recv()
        assert isinstance(recv_b, PingMsg)
        assert isinstance(recv_a, PongMsg)

    async def test_session_end_round_trip(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        await a.send(SessionEndMsg(reason="shutdown"))
        msg = await b.recv()
        assert isinstance(msg, SessionEndMsg)
        assert msg.reason == "shutdown"

    async def test_sync_request_round_trip(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        await a.send(SyncRequestMsg())
        msg = await b.recv()
        assert isinstance(msg, SyncRequestMsg)

    async def test_blacklist_sync_round_trip(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        patterns = ["**/.git/**", "**/*.pyc", "**/node_modules/**"]
        await a.send(BlacklistSyncMsg(patterns=patterns))
        msg = await b.recv()
        assert isinstance(msg, BlacklistSyncMsg)
        assert msg.patterns == patterns


# ---------------------------------------------------------------------------
# FramedConnection — guard rails
# ---------------------------------------------------------------------------

class TestGuardRails:
    async def test_send_without_activate_raises(self):
        a, _ = _pipe()
        with pytest.raises(FrameError):
            await a.send(PingMsg(ts_ns=0))

    async def test_recv_without_activate_raises(self):
        a, b = _pipe()
        codec_a, _ = _codec_pair()
        a.activate(codec_a)
        await a.send(PingMsg(ts_ns=0))
        # b has no codec — recv should raise
        with pytest.raises(FrameError):
            await b.recv()

    async def test_double_activate_raises(self):
        a, _ = _pipe()
        codec1, codec2 = _codec_pair()
        a.activate(codec1)
        with pytest.raises(FrameError):
            a.activate(codec2)

    async def test_tampered_frame_raises(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        # Produce a valid frame then corrupt the GCM tag before b sees it
        await a.send(PingMsg(ts_ns=99))
        frame = await b._conn.recv()                   # intercept from a→b queue
        bad = bytearray(frame)
        bad[-1] ^= 0xFF                               # flip last byte of GCM tag
        # Inject the corrupted frame directly into b's recv queue
        b._conn._ws._rq.put_nowait(bytes(bad))        # type: ignore[attr-defined]
        with pytest.raises(FrameError):
            await b.recv()

    async def test_replay_raises(self):
        a, b = _pipe()
        codec_a, codec_b = _codec_pair()
        a.activate(codec_a)
        b.activate(codec_b)

        await a.send(PingMsg(ts_ns=0))
        frame = await b._conn.recv()        # intercept from a→b queue
        # Inject the same frame twice directly into b's recv queue
        rq = b._conn._ws._rq               # type: ignore[attr-defined]
        rq.put_nowait(frame)
        rq.put_nowait(frame)
        # First recv: seq=0, OK
        await b.recv()
        # Second recv: seq=0 again → ReplayError
        with pytest.raises(ReplayError):
            await b.recv()

    async def test_is_encrypted_flag(self):
        a, _ = _pipe()
        assert not a.is_encrypted
        codec, _ = _codec_pair()
        a.activate(codec)
        assert a.is_encrypted

    async def test_remote_addr_delegated(self):
        a, _ = _pipe()
        assert a.remote_addr == "127.0.0.1:9999"


# ---------------------------------------------------------------------------
# SessionStateMachine
# ---------------------------------------------------------------------------

class TestSessionStateMachine:
    def test_initial_state_is_idle(self):
        sm = SessionStateMachine()
        assert sm.state == SessionState.IDLE

    def test_idle_to_connecting(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.CONNECTING)
        assert sm.state == SessionState.CONNECTING

    def test_full_happy_path(self):
        sm = SessionStateMachine()
        path = [
            SessionState.CONNECTING,
            SessionState.AUTHENTICATING,
            SessionState.SYNCING,
            SessionState.ACTIVE,
        ]
        for state in path:
            sm.transition(state)
        assert sm.state == SessionState.ACTIVE

    def test_active_to_idle(self):
        sm = SessionStateMachine()
        for s in [SessionState.CONNECTING, SessionState.AUTHENTICATING,
                  SessionState.SYNCING, SessionState.ACTIVE]:
            sm.transition(s)
        sm.transition(SessionState.IDLE)
        assert sm.state == SessionState.IDLE

    def test_reconnect_from_connecting(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.CONNECTING)
        sm.transition(SessionState.RECONNECTING)
        assert sm.state == SessionState.RECONNECTING

    def test_reconnect_from_authenticating(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.CONNECTING)
        sm.transition(SessionState.AUTHENTICATING)
        sm.transition(SessionState.RECONNECTING)
        assert sm.state == SessionState.RECONNECTING

    def test_reconnect_from_syncing(self):
        sm = SessionStateMachine()
        for s in [SessionState.CONNECTING, SessionState.AUTHENTICATING, SessionState.SYNCING]:
            sm.transition(s)
        sm.transition(SessionState.RECONNECTING)
        assert sm.state == SessionState.RECONNECTING

    def test_reconnect_from_active(self):
        sm = SessionStateMachine()
        for s in [SessionState.CONNECTING, SessionState.AUTHENTICATING,
                  SessionState.SYNCING, SessionState.ACTIVE]:
            sm.transition(s)
        sm.transition(SessionState.RECONNECTING)
        assert sm.state == SessionState.RECONNECTING

    def test_reconnecting_back_to_connecting(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.CONNECTING)
        sm.transition(SessionState.RECONNECTING)
        sm.transition(SessionState.CONNECTING)
        assert sm.state == SessionState.CONNECTING

    def test_reconnecting_to_idle(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.CONNECTING)
        sm.transition(SessionState.RECONNECTING)
        sm.transition(SessionState.IDLE)
        assert sm.state == SessionState.IDLE

    def test_invalid_idle_to_active_raises(self):
        sm = SessionStateMachine()
        with pytest.raises(InvalidTransition):
            sm.transition(SessionState.ACTIVE)

    def test_invalid_connecting_to_active_raises(self):
        sm = SessionStateMachine()
        sm.transition(SessionState.CONNECTING)
        with pytest.raises(InvalidTransition):
            sm.transition(SessionState.ACTIVE)

    def test_invalid_active_to_connecting_raises(self):
        sm = SessionStateMachine()
        for s in [SessionState.CONNECTING, SessionState.AUTHENTICATING,
                  SessionState.SYNCING, SessionState.ACTIVE]:
            sm.transition(s)
        with pytest.raises(InvalidTransition):
            sm.transition(SessionState.CONNECTING)

    def test_invalid_idle_to_reconnecting_raises(self):
        sm = SessionStateMachine()
        with pytest.raises(InvalidTransition):
            sm.transition(SessionState.RECONNECTING)

    def test_is_active(self):
        sm = SessionStateMachine()
        assert not sm.is_active()
        for s in [SessionState.CONNECTING, SessionState.AUTHENTICATING,
                  SessionState.SYNCING, SessionState.ACTIVE]:
            sm.transition(s)
        assert sm.is_active()

    def test_is_live(self):
        sm = SessionStateMachine()
        assert not sm.is_live()
        sm.transition(SessionState.CONNECTING)
        assert sm.is_live()
        sm.transition(SessionState.RECONNECTING)
        assert not sm.is_live()

    def test_repr(self):
        sm = SessionStateMachine()
        assert "idle" in repr(sm)
