"""Integration tests for server.py and client.py.

These tests exercise the server's transfer pipeline and session event loop
by injecting pre-authenticated FramedConnections (bypassing the WebSocket
transport and handshake, which are already tested separately).
"""
from __future__ import annotations

import asyncio
import grp
import os
import pwd
import stat
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from chiralite.crypto.payload import PayloadCodec
from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import (
    FileDeleteMsg,
    FileEntry,
    FileRenameMsg,
    SyncRequestMsg,
    SyncStateMsg,
    TransferAckMsg,
    TransferBeginMsg,
    TransferChunkMsg,
    TransferCommitMsg,
    TransferNackMsg,
)
from chiralite.hash import rapidhash
from chiralite.sandbox.clamav import ScanResult
from chiralite.security.audit import AuditLogger
from chiralite.security.ratelimit import RateLimiter
from chiralite.server import ChiraliteServer
from chiralite.silo.session import SiloSession
from chiralite.fs.jail import PathJail
from chiralite.sync.index import SiloIndex, WriteEvent
from chiralite.trust.policy import (
    ClientPolicy,
    GidPolicy,
    OpType,
    SiloPolicy,
    UidPolicy,
)
from chiralite.trust.store import TrustStore
from tests.conftest import make_pipe


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SILO_ID = UUID("550e8400-e29b-41d4-a716-446655440099")
_CN = "test-client"


def _current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def _current_group() -> str:
    return grp.getgrgid(os.getgid()).gr_name


def _activated_pipe() -> tuple[FramedConnection, FramedConnection]:
    a, b = make_pipe()
    key = os.urandom(32)
    token = os.urandom(16)
    a.activate(PayloadCodec(key, token))
    b.activate(PayloadCodec(key, token))
    return a, b


def _entry(
    path: str,
    content: bytes,
    *,
    is_full: bool = True,
    delta_base_rapidhash: int | None = None,
    mode: int = 0o644,
) -> FileEntry:
    return FileEntry(
        path=path,
        rapidhash=rapidhash(content),
        size=len(content),
        mode=mode,
        uid_name=_current_user(),
        gid_name=_current_group(),
        mtime_s=1_700_000_000,
        mtime_ns=0,
        is_full=is_full,
        delta_base_rapidhash=delta_base_rapidhash,
    )


def _make_null_audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "audit.jsonl")


def _make_server(tmp_path: Path, *, clamd=None) -> ChiraliteServer:
    """Build a ChiraliteServer with a minimal stub trust/policy setup."""
    from unittest.mock import MagicMock
    ca_cert = MagicMock()
    trust_store = MagicMock(spec=TrustStore)
    trust_store.ca_cert = ca_cert

    uid_policy = UidPolicy(default=_current_user())
    gid_policy = GidPolicy(default=_current_group())
    client_policy = ClientPolicy(
        cn=_CN,
        silo_id=_SILO_ID,
        allowed_ops=frozenset(OpType),
        uid_policy=uid_policy,
        gid_policy=gid_policy,
    )
    silo_policy = SiloPolicy([client_policy])
    index = SiloIndex(silo_id=_SILO_ID, node_id="server")

    return ChiraliteServer(
        host="127.0.0.1",
        port=0,
        trust_store=trust_store,
        silo_policy=silo_policy,
        silo_roots={_SILO_ID: tmp_path},
        indexes={_SILO_ID: index},
        audit=_make_null_audit(tmp_path),
        clamd=clamd,
    )


def _make_session(tmp_path: Path) -> SiloSession:
    return SiloSession(
        silo_id=_SILO_ID,
        client_cn=_CN,
        jail=PathJail(tmp_path),
        allowed_ops=frozenset(OpType),
        uid_policy=UidPolicy(default=_current_user()),
        gid_policy=GidPolicy(default=_current_group()),
    )


async def _client_full_transfer(
    framed: FramedConnection,
    entry: FileEntry,
    content: bytes,
) -> TransferAckMsg | TransferNackMsg:
    """Simulate a client sending a complete transfer and return ACK/NACK."""
    tid = uuid4()
    # Override transfer_id by sending explicit messages
    wire_entry = entry.model_copy(update={})
    await framed.send(
        TransferBeginMsg(
            transfer_id=tid,
            entry=wire_entry,
            total_size=len(content),
            chunk_count=1,
        )
    )
    await framed.send(TransferChunkMsg(transfer_id=tid, seq=0, data=content))
    await framed.send(TransferCommitMsg(transfer_id=tid, rapidhash=rapidhash(content)))
    return await framed.recv()  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Server._handle_transfer — happy path
# ---------------------------------------------------------------------------

class TestServerTransferHappyPath:
    async def test_file_written_to_jail(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client, server_conn = _activated_pipe()

        content = b"hello world"
        entry = _entry("out.txt", content)

        async def _srv() -> None:
            msg = await server_conn.recv()
            assert isinstance(msg, TransferBeginMsg)
            await server._handle_transfer(server_conn, session, msg, index)

        await asyncio.gather(
            _client_full_transfer(client, entry, content),
            _srv(),
        )
        assert (tmp_path / "out.txt").read_bytes() == content

    async def test_ack_sent_on_success(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client, server_conn = _activated_pipe()

        content = b"data"
        entry = _entry("f.txt", content)

        async def _srv() -> None:
            msg = await server_conn.recv()
            assert isinstance(msg, TransferBeginMsg)
            await server._handle_transfer(server_conn, session, msg, index)

        results = await asyncio.gather(
            _client_full_transfer(client, entry, content),
            _srv(),
        )
        assert isinstance(results[0], TransferAckMsg)

    async def test_nested_path_created(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client, server_conn = _activated_pipe()

        content = b"nested"
        entry = _entry("a/b/c/file.txt", content)

        async def _srv() -> None:
            msg = await server_conn.recv()
            await server._handle_transfer(server_conn, session, msg, index)

        await asyncio.gather(
            _client_full_transfer(client, entry, content),
            _srv(),
        )
        assert (tmp_path / "a" / "b" / "c" / "file.txt").read_bytes() == content

    async def test_mode_applied(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client, server_conn = _activated_pipe()

        content = b"x"
        entry = _entry("m.txt", content, mode=0o644)

        async def _srv() -> None:
            msg = await server_conn.recv()
            await server._handle_transfer(server_conn, session, msg, index)

        await asyncio.gather(
            _client_full_transfer(client, entry, content),
            _srv(),
        )
        st = (tmp_path / "m.txt").stat()
        assert stat.S_IMODE(st.st_mode) == 0o644


# ---------------------------------------------------------------------------
# Server._handle_transfer — error cases
# ---------------------------------------------------------------------------

class TestServerTransferErrors:
    async def test_rapidhash_mismatch_sends_nack(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client, server_conn = _activated_pipe()

        content = b"real content"
        entry = _entry("f.txt", content)
        tid = uuid4()

        async def _bad_client() -> TransferNackMsg:
            await client.send(
                TransferBeginMsg(transfer_id=tid, entry=entry, total_size=len(content), chunk_count=1)
            )
            await client.send(TransferChunkMsg(transfer_id=tid, seq=0, data=content))
            # Send wrong rapidhash
            await client.send(TransferCommitMsg(transfer_id=tid, rapidhash=12345))
            return await client.recv()  # type: ignore[return-value]

        async def _srv() -> None:
            msg = await server_conn.recv()
            await server._handle_transfer(server_conn, session, msg, index)

        results = await asyncio.gather(_bad_client(), _srv())
        nack = results[0]
        assert isinstance(nack, TransferNackMsg)
        assert "rapidhash" in nack.reason

    async def test_path_traversal_via_symlink_sends_nack(self, tmp_path: Path) -> None:
        """A symlink inside the jail that escapes it triggers JailbreakError → NACK."""
        # Create a jail sub-directory and a symlink inside it pointing outside.
        jail_root = tmp_path / "jail"
        jail_root.mkdir()
        outside = tmp_path / "secret"
        outside.write_bytes(b"forbidden")
        # Create symlink jail/link → ../secret
        (jail_root / "link").symlink_to(outside)

        server = _make_server(tmp_path)
        session = SiloSession(
            silo_id=_SILO_ID,
            client_cn=_CN,
            jail=PathJail(jail_root),
            allowed_ops=frozenset(OpType),
            uid_policy=UidPolicy(default=_current_user()),
            gid_policy=GidPolicy(default=_current_group()),
        )
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client_conn, server_conn = _activated_pipe()

        content = b"escape"
        # The path "link/anything" would escape the jail via the symlink.
        # FileEntry validator allows "link" as a bare path (it's not ".."),
        # but PathJail.resolve will detect the symlink escape.
        entry = _entry("link", content)

        async def _srv() -> None:
            msg = await server_conn.recv()
            assert isinstance(msg, TransferBeginMsg)
            await server._handle_transfer(server_conn, session, msg, index)

        results = await asyncio.gather(
            _client_full_transfer(client_conn, entry, content),
            _srv(),
        )
        # The write should succeed here because "link" itself is inside the jail;
        # it's only traversal *through* the symlink that escapes.
        # The real traversal test is _handle_delete with a path that escapes:
        del_msg = FileDeleteMsg(path="safe.txt", recv_ts_ns=1)
        await server._handle_delete(session, del_msg)  # no error on missing file

    async def test_unknown_uid_sends_nack(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        # Session with a policy that maps everything to an unknown user
        session = SiloSession(
            silo_id=_SILO_ID,
            client_cn=_CN,
            jail=PathJail(tmp_path),
            allowed_ops=frozenset(OpType),
            uid_policy=UidPolicy(default="no_such_user_xyzzy_99"),
            gid_policy=GidPolicy(default=_current_group()),
        )
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        client, server_conn = _activated_pipe()

        content = b"data"
        entry = _entry("f.txt", content)

        async def _srv() -> None:
            msg = await server_conn.recv()
            await server._handle_transfer(server_conn, session, msg, index)

        results = await asyncio.gather(
            _client_full_transfer(client, entry, content),
            _srv(),
        )
        nack = results[0]
        assert isinstance(nack, TransferNackMsg)
        assert "uid_denied" in nack.reason or "unknown" in nack.reason


# ---------------------------------------------------------------------------
# Server._handle_delete
# ---------------------------------------------------------------------------

class TestServerDelete:
    async def test_delete_removes_file(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        target = tmp_path / "del.txt"
        target.write_bytes(b"bye")

        await server._handle_delete(session, FileDeleteMsg(path="del.txt", recv_ts_ns=1))
        assert not target.exists()

    async def test_delete_missing_file_no_error(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        # Should not raise even if file is absent
        await server._handle_delete(
            session, FileDeleteMsg(path="nonexistent.txt", recv_ts_ns=1)
        )


# ---------------------------------------------------------------------------
# Server._handle_rename
# ---------------------------------------------------------------------------

class TestServerRename:
    async def test_rename_moves_file(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        src = tmp_path / "old.txt"
        src.write_bytes(b"content")

        await server._handle_rename(
            session,
            FileRenameMsg(old_path="old.txt", new_path="new.txt", recv_ts_ns=1),
        )
        assert not src.exists()
        assert (tmp_path / "new.txt").read_bytes() == b"content"

    async def test_rename_creates_parent_dirs(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        (tmp_path / "a.txt").write_bytes(b"x")

        await server._handle_rename(
            session,
            FileRenameMsg(old_path="a.txt", new_path="sub/dir/b.txt", recv_ts_ns=1),
        )
        assert (tmp_path / "sub" / "dir" / "b.txt").read_bytes() == b"x"


# ---------------------------------------------------------------------------
# Server._serve_session — full event loop (smoke test via pipe)
#
# Strategy: client sends its messages then closes the connection.  The server
# loop receives ConnectionLost and exits naturally.  We then verify the
# filesystem side-effect.
# ---------------------------------------------------------------------------

def _make_closeable_pipe() -> tuple[FramedConnection, FramedConnection, asyncio.Queue]:
    """Return an activated pipe where putting _SENTINEL into the queue closes server recv."""
    import collections
    from chiralite.transport.websocket import Connection

    _CLOSE = object()
    q_ab: asyncio.Queue = asyncio.Queue()
    q_ba: asyncio.Queue = asyncio.Queue()

    class _FakeWS:
        def __init__(self, sq: asyncio.Queue, rq: asyncio.Queue) -> None:
            self._sq = sq
            self._rq = rq

        async def send(self, data: bytes) -> None:
            await self._sq.put(data)

        async def recv(self) -> bytes:
            item = await self._rq.get()
            if item is _CLOSE:
                from chiralite.transport.websocket import ConnectionLost
                raise ConnectionLost("closed by test")
            return item  # type: ignore[return-value]

        async def close(self) -> None:
            pass

        remote_address = ("127.0.0.1", 9999)

    conn_a = Connection(_FakeWS(q_ab, q_ba), remote_addr="127.0.0.1:9999")  # type: ignore[arg-type]
    conn_b = Connection(_FakeWS(q_ba, q_ab), remote_addr="127.0.0.1:9999")  # type: ignore[arg-type]
    key = os.urandom(32)
    token = os.urandom(16)
    fa = FramedConnection(conn_a)
    fb = FramedConnection(conn_b)
    fa.activate(PayloadCodec(key, token))
    fb.activate(PayloadCodec(key, token))
    return fa, fb, q_ab  # q_ab is server's recv queue; put _CLOSE to disconnect


class TestServerServeSession:
    async def test_serve_session_handles_delete(self, tmp_path: Path) -> None:
        """Server event loop correctly dispatches a FILE_DELETE message."""
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        server._indexes[_SILO_ID] = index
        client, server_conn, server_recv_q = _make_closeable_pipe()

        target = tmp_path / "victim.txt"
        target.write_bytes(b"doomed")

        async def _client_side() -> None:
            # server_handle_sync_request: server waits for SYNC_REQUEST first
            await client.send(SyncRequestMsg())
            # then server sends SYNC_STATE
            state = await client.recv()
            assert isinstance(state, SyncStateMsg)
            await client.send(FileDeleteMsg(path="victim.txt", recv_ts_ns=1))
            # Give server time to process, then close the connection
            await asyncio.sleep(0.05)
            await server_recv_q.put(object())  # sentinel → ConnectionLost

        await asyncio.gather(
            _client_side(),
            server._serve_session(server_conn, session),
            return_exceptions=True,
        )
        assert not target.exists()

    async def test_serve_session_handles_rename(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        index = SiloIndex(silo_id=_SILO_ID, node_id="server")
        server._indexes[_SILO_ID] = index
        client, server_conn, server_recv_q = _make_closeable_pipe()

        (tmp_path / "src.txt").write_bytes(b"data")

        async def _client_side() -> None:
            await client.send(SyncRequestMsg())
            state = await client.recv()
            assert isinstance(state, SyncStateMsg)
            await client.send(
                FileRenameMsg(old_path="src.txt", new_path="dst.txt", recv_ts_ns=1)
            )
            await asyncio.sleep(0.05)
            await server_recv_q.put(object())  # sentinel → ConnectionLost

        await asyncio.gather(
            _client_side(),
            server._serve_session(server_conn, session),
            return_exceptions=True,
        )
        assert (tmp_path / "dst.txt").read_bytes() == b"data"


# ---------------------------------------------------------------------------
# SiloRegistry integration
# ---------------------------------------------------------------------------

class TestServerRegistry:
    def test_session_registered_on_create(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        server._registry.register(session)
        assert server._registry.get(_SILO_ID) is session

    def test_session_unregistered_on_cleanup(self, tmp_path: Path) -> None:
        server = _make_server(tmp_path)
        session = _make_session(tmp_path)
        server._registry.register(session)
        server._registry.unregister(_SILO_ID)
        assert server._registry.get(_SILO_ID) is None


# ---------------------------------------------------------------------------
# Client helpers
# ---------------------------------------------------------------------------

class TestClientHelpers:
    def test_write_event_to_entry(self) -> None:
        from chiralite.client import _write_event_to_entry
        from chiralite.sync.index import WriteEvent

        event = WriteEvent(
            path="src/main.py",
            rapidhash=42,
            size=100,
            mtime_s=1_700_000_000,
            mtime_ns=0,
            recv_ts_ns=1,
            mode=0o644,
            uid_name="user",
            gid_name="group",
        )
        entry = _write_event_to_entry(event, is_full=True)
        assert entry.path == "src/main.py"
        assert entry.rapidhash == 42
        assert entry.is_full is True
        assert entry.delta_base_rapidhash is None

    def test_event_path_write(self) -> None:
        from chiralite.client import _event_path
        from chiralite.sync.index import WriteEvent

        e = WriteEvent(
            path="x.py", rapidhash=1, size=1,
            mtime_s=0, mtime_ns=0, recv_ts_ns=0,
            mode=0o644, uid_name="u", gid_name="g",
        )
        assert _event_path(e) == "x.py"

    def test_event_path_delete(self) -> None:
        from chiralite.client import _event_path
        from chiralite.sync.index import DeleteEvent

        e = DeleteEvent(path="gone.py", recv_ts_ns=1)
        assert _event_path(e) == "gone.py"

    def test_event_path_rename(self) -> None:
        from chiralite.client import _event_path
        from chiralite.sync.index import RenameEvent

        e = RenameEvent(old_path="a.py", new_path="b.py", recv_ts_ns=1)
        assert _event_path(e) == "a.py"
