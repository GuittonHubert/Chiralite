"""Tests for sync/engine.py and sync/reconciler.py."""
from __future__ import annotations

import asyncio
import os
from uuid import UUID, uuid4

import pytest

from chiralite.crypto.payload import PayloadCodec
from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import (
    FileDeleteMsg,
    FileEntry,
    FileEntrySnapshot,
    FileRenameMsg,
    SyncRequestMsg,
    SyncStateMsg,
    TransferAckMsg,
    TransferBeginMsg,
    TransferChunkMsg,
    TransferCommitMsg,
    TransferNackMsg,
)
from chiralite.sync.engine import CHUNK_SIZE, SyncEngine, TransferError
from chiralite.sync.index import SiloIndex, WriteEvent
from chiralite.sync.reconciler import (
    ReconcileError,
    client_request_sync,
    server_handle_sync_request,
)
from tests.conftest import make_pipe


def _activated_pipe() -> tuple[FramedConnection, FramedConnection]:
    """Return an in-memory pipe with both ends in encrypted mode."""
    a, b = make_pipe()
    key = os.urandom(32)
    token = os.urandom(16)
    a.activate(PayloadCodec(key, token))
    b.activate(PayloadCodec(key, token))
    return a, b


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SILO_ID = UUID("550e8400-e29b-41d4-a716-446655440001")


def _entry(
    path: str = "file.txt",
    *,
    rapidhash: int = 123456789,
    size: int = 5,
    mode: int = 0o644,
    uid_name: str = "user",
    gid_name: str = "group",
    mtime_s: int = 1_700_000_000,
    mtime_ns: int = 0,
    is_full: bool = True,
    delta_base_rapidhash: int | None = None,
) -> FileEntry:
    return FileEntry(
        path=path,
        rapidhash=rapidhash,
        size=size,
        mode=mode,
        uid_name=uid_name,
        gid_name=gid_name,
        mtime_s=mtime_s,
        mtime_ns=mtime_ns,
        is_full=is_full,
        delta_base_rapidhash=delta_base_rapidhash,
    )


def _index_with_record(
    path: str = "file.txt",
    rapidhash: int = 111,
    size: int = 5,
) -> SiloIndex:
    idx = SiloIndex(silo_id=_SILO_ID, node_id="node-a")
    idx.apply_event(
        WriteEvent(
            path=path,
            rapidhash=rapidhash,
            size=size,
            mtime_s=1_700_000_000,
            mtime_ns=0,
            recv_ts_ns=1,
            mode=0o644,
            uid_name="user",
            gid_name="group",
        )
    )
    return idx


async def _ack_server(framed_b: object) -> None:
    """Consume BEGIN + CHUNKs + COMMIT from framed_b and send ACK."""
    begin: TransferBeginMsg = await framed_b.recv()  # type: ignore[assignment]
    assert isinstance(begin, TransferBeginMsg)
    for _ in range(begin.chunk_count):
        chunk = await framed_b.recv()
        assert isinstance(chunk, TransferChunkMsg)
    commit: TransferCommitMsg = await framed_b.recv()  # type: ignore[assignment]
    assert isinstance(commit, TransferCommitMsg)
    await framed_b.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))


async def _nack_server(framed_b: object, reason: str = "quarantine") -> None:
    begin: TransferBeginMsg = await framed_b.recv()  # type: ignore[assignment]
    for _ in range(begin.chunk_count):
        await framed_b.recv()
    await framed_b.recv()  # commit
    await framed_b.send(TransferNackMsg(transfer_id=begin.transfer_id, reason=reason))


# ---------------------------------------------------------------------------
# SyncEngine — send_write (full transfer)
# ---------------------------------------------------------------------------

class TestSyncEngineFullTransfer:
    async def test_begin_has_correct_entry(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry = _entry(rapidhash=999, size=5)

        await asyncio.gather(
            engine.send_write(entry, b"hello"),
            _ack_server(server),
        )

    async def test_begin_chunk_count_correct(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        content = b"x" * (CHUNK_SIZE + 1)  # two chunks
        entry = _entry(size=len(content))

        async def _check_server() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            assert begin.chunk_count == 2
            for _ in range(2):
                await server.recv()
            await server.recv()  # commit
            await server.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))

        await asyncio.gather(
            engine.send_write(entry, content),
            _check_server(),
        )

    async def test_all_chunks_transmitted(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        content = b"A" * (CHUNK_SIZE * 3 + 17)
        entry = _entry(size=len(content))

        assembled = bytearray()

        async def _collect_server() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            for _ in range(begin.chunk_count):
                chunk: TransferChunkMsg = await server.recv()  # type: ignore[assignment]
                assembled.extend(chunk.data)
            await server.recv()  # commit
            await server.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))

        await asyncio.gather(
            engine.send_write(entry, content),
            _collect_server(),
        )
        assert bytes(assembled) == content

    async def test_returns_scan_result(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry = _entry()

        async def _srv() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            await server.recv()  # chunk
            await server.recv()  # commit
            await server.send(
                TransferAckMsg(transfer_id=begin.transfer_id, scan_result="infected:Eicar")
            )

        results = await asyncio.gather(
            engine.send_write(entry, b"x" * 5),
            _srv(),
        )
        assert results[0] == "infected:Eicar"

    async def test_nack_raises_transfer_error(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry = _entry()

        async def _do_write() -> None:
            with pytest.raises(TransferError, match="quarantine"):
                await engine.send_write(entry, b"virus")

        await asyncio.gather(
            _do_write(),
            _nack_server(server, reason="quarantine"),
        )

    async def test_small_content_single_chunk(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry = _entry(size=3)

        async def _check() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            assert begin.chunk_count == 1
            chunk: TransferChunkMsg = await server.recv()  # type: ignore[assignment]
            assert chunk.data == b"abc"
            await server.recv()  # commit
            await server.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))

        await asyncio.gather(
            engine.send_write(entry, b"abc"),
            _check(),
        )

    async def test_is_full_forced_when_no_base(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry = _entry(is_full=False, delta_base_rapidhash=999)

        async def _check() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            # No base_content supplied → forced full transfer
            assert begin.entry.is_full is True
            assert begin.entry.delta_base_rapidhash is None
            for _ in range(begin.chunk_count):
                await server.recv()
            await server.recv()  # commit
            await server.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))

        await asyncio.gather(
            engine.send_write(entry, b"data"),
            _check(),
        )


# ---------------------------------------------------------------------------
# SyncEngine — send_write (delta transfer)
# ---------------------------------------------------------------------------

class TestSyncEngineDeltaTransfer:
    async def test_delta_used_when_small_enough(self) -> None:
        """A one-byte change produces a delta well below DELTA_THRESHOLD."""
        client, server = _activated_pipe()
        engine = SyncEngine(client)

        old = b"hello world " * 100   # 1200 bytes — gives delta room to shine
        new = old[:-1] + b"!"
        entry = _entry(
            size=len(new),
            rapidhash=42,
            is_full=False,
            delta_base_rapidhash=99,
        )

        async def _check() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            assert begin.entry.is_full is False
            for _ in range(begin.chunk_count):
                await server.recv()
            await server.recv()  # commit
            await server.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))

        await asyncio.gather(
            engine.send_write(entry, new, base_content=old),
            _check(),
        )

    async def test_fallback_to_full_when_no_delta_found(self) -> None:
        """Completely unrelated content → NoDeltaFound → fall back to full."""
        import os
        client, server = _activated_pipe()
        engine = SyncEngine(client)

        old = os.urandom(512)
        new = os.urandom(512)
        entry = _entry(
            size=len(new),
            rapidhash=55,
            is_full=False,
            delta_base_rapidhash=88,
        )

        async def _check() -> None:
            begin: TransferBeginMsg = await server.recv()  # type: ignore[assignment]
            assert begin.entry.is_full is True
            for _ in range(begin.chunk_count):
                await server.recv()
            await server.recv()  # commit
            await server.send(TransferAckMsg(transfer_id=begin.transfer_id, scan_result="clean"))

        await asyncio.gather(
            engine.send_write(entry, new, base_content=old),
            _check(),
        )


# ---------------------------------------------------------------------------
# SyncEngine — send_delete
# ---------------------------------------------------------------------------

class TestSyncEngineDelete:
    async def test_delete_sends_file_delete_msg(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)

        await engine.send_delete("src/main.py")
        msg = await server.recv()
        assert isinstance(msg, FileDeleteMsg)
        assert msg.path == "src/main.py"

    async def test_delete_recv_ts_ns_is_positive(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)

        await engine.send_delete("x.txt")
        msg: FileDeleteMsg = await server.recv()  # type: ignore[assignment]
        assert msg.recv_ts_ns > 0


# ---------------------------------------------------------------------------
# SyncEngine — send_rename
# ---------------------------------------------------------------------------

class TestSyncEngineRename:
    async def test_rename_sends_file_rename_msg(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)

        await engine.send_rename("old.txt", "new.txt")
        msg = await server.recv()
        assert isinstance(msg, FileRenameMsg)
        assert msg.old_path == "old.txt"
        assert msg.new_path == "new.txt"

    async def test_rename_recv_ts_ns_is_positive(self) -> None:
        client, server = _activated_pipe()
        engine = SyncEngine(client)

        await engine.send_rename("a.txt", "b.txt")
        msg: FileRenameMsg = await server.recv()  # type: ignore[assignment]
        assert msg.recv_ts_ns > 0


# ---------------------------------------------------------------------------
# SyncEngine — per-path serialization (ADR-009)
# ---------------------------------------------------------------------------

class TestPerPathSerialization:
    async def test_second_write_waits_for_ack(self) -> None:
        """Two concurrent writes on the same path must be serialized."""
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry = _entry()
        order: list[str] = []

        async def _first_write() -> None:
            order.append("write1-start")
            await engine.send_write(entry, b"v1")
            order.append("write1-done")

        async def _second_write() -> None:
            await asyncio.sleep(0)
            order.append("write2-start")
            await engine.send_write(entry, b"v2")
            order.append("write2-done")

        async def _sequential_ack() -> None:
            await _ack_server(server)
            await _ack_server(server)

        await asyncio.gather(
            _first_write(),
            _second_write(),
            _sequential_ack(),
        )
        assert order.index("write1-done") < order.index("write2-done")

    async def test_concurrent_different_paths_do_not_block(self) -> None:
        """Writes on different paths can proceed independently."""
        client, server = _activated_pipe()
        engine = SyncEngine(client)
        entry_a = _entry(path="a.txt")
        entry_b = _entry(path="b.txt")
        done: list[str] = []

        async def _write_a() -> None:
            await engine.send_write(entry_a, b"aaa")
            done.append("a")

        async def _write_b() -> None:
            await engine.send_write(entry_b, b"bbb")
            done.append("b")

        async def _dual_ack() -> None:
            await _ack_server(server)
            await _ack_server(server)

        await asyncio.gather(
            _write_a(),
            _write_b(),
            _dual_ack(),
        )
        assert set(done) == {"a", "b"}


# ---------------------------------------------------------------------------
# Reconciler — client_request_sync
# ---------------------------------------------------------------------------

class TestClientRequestSync:
    async def test_sends_sync_request(self) -> None:
        client, server = _activated_pipe()
        local_idx = SiloIndex(silo_id=_SILO_ID, node_id="node-a")

        async def _srv() -> None:
            msg = await server.recv()
            assert isinstance(msg, SyncRequestMsg)
            await server.send(
                SyncStateMsg(silo_id=_SILO_ID, node_id="node-b", records={})
            )

        results = await asyncio.gather(
            client_request_sync(client, local_idx),
            _srv(),
        )
        assert results[0] == []

    async def test_diff_returns_missing_files(self) -> None:
        client, server = _activated_pipe()
        local_idx = _index_with_record("src/main.py", rapidhash=111, size=10)

        async def _srv() -> None:
            await server.recv()  # SYNC_REQUEST
            await server.send(
                SyncStateMsg(silo_id=_SILO_ID, node_id="node-b", records={})
            )

        results = await asyncio.gather(
            client_request_sync(client, local_idx),
            _srv(),
        )
        diff = results[0]
        assert len(diff) == 1
        assert diff[0].path == "src/main.py"
        assert diff[0].is_full is True

    async def test_diff_returns_changed_files(self) -> None:
        client, server = _activated_pipe()
        local_idx = _index_with_record("f.txt", rapidhash=999, size=10)

        async def _srv() -> None:
            await server.recv()
            await server.send(
                SyncStateMsg(
                    silo_id=_SILO_ID,
                    node_id="node-b",
                    records={
                        "f.txt": FileEntrySnapshot(
                            rapidhash=111,
                            size=5,
                            mode=0o644,
                            uid_name="user",
                            gid_name="group",
                            mtime_s=1_700_000_000,
                            mtime_ns=0,
                            recv_ts_ns=1,
                        )
                    },
                )
            )

        results = await asyncio.gather(
            client_request_sync(client, local_idx),
            _srv(),
        )
        diff = results[0]
        assert len(diff) == 1
        assert diff[0].is_full is False
        assert diff[0].delta_base_rapidhash == 111

    async def test_unexpected_msg_raises_reconcile_error(self) -> None:
        client, server = _activated_pipe()
        local_idx = SiloIndex(silo_id=_SILO_ID, node_id="node-a")

        async def _srv() -> None:
            await server.recv()
            await server.send(SyncRequestMsg())  # wrong type

        async def _do_sync() -> None:
            with pytest.raises(ReconcileError, match="expected SYNC_STATE"):
                await client_request_sync(client, local_idx)

        await asyncio.gather(_do_sync(), _srv())


# ---------------------------------------------------------------------------
# Reconciler — server_handle_sync_request
# ---------------------------------------------------------------------------

class TestServerHandleSyncRequest:
    async def test_sends_sync_state(self) -> None:
        client, server = _activated_pipe()
        local_idx = SiloIndex(silo_id=_SILO_ID, node_id="node-server")

        async def _cli() -> None:
            await client.send(SyncRequestMsg())
            msg = await client.recv()
            assert isinstance(msg, SyncStateMsg)
            assert msg.silo_id == _SILO_ID
            assert msg.node_id == "node-server"

        await asyncio.gather(
            _cli(),
            server_handle_sync_request(server, local_idx),
        )

    async def test_snapshot_contains_records(self) -> None:
        client, server = _activated_pipe()
        local_idx = _index_with_record("readme.txt", rapidhash=777, size=42)

        async def _cli() -> None:
            await client.send(SyncRequestMsg())
            msg: SyncStateMsg = await client.recv()  # type: ignore[assignment]
            assert "readme.txt" in msg.records
            assert msg.records["readme.txt"].rapidhash == 777

        await asyncio.gather(
            _cli(),
            server_handle_sync_request(server, local_idx),
        )

    async def test_unexpected_msg_raises_reconcile_error(self) -> None:
        client, server = _activated_pipe()
        local_idx = SiloIndex(silo_id=_SILO_ID, node_id="server")

        async def _cli() -> None:
            await client.send(SyncStateMsg(silo_id=_SILO_ID, node_id="x", records={}))

        async def _do_handle() -> None:
            with pytest.raises(ReconcileError, match="expected SYNC_REQUEST"):
                await server_handle_sync_request(server, local_idx)

        await asyncio.gather(_cli(), _do_handle())

    async def test_round_trip_reconcile(self) -> None:
        """Full round-trip: client diff reflects what server index contains."""
        client_conn, server_conn = _activated_pipe()

        client_idx = _index_with_record("a.py", rapidhash=10, size=100)
        server_idx = SiloIndex(silo_id=_SILO_ID, node_id="server")  # empty

        results = await asyncio.gather(
            client_request_sync(client_conn, client_idx),
            server_handle_sync_request(server_conn, server_idx),
        )
        diff = results[0]
        assert len(diff) == 1
        assert diff[0].path == "a.py"
        assert diff[0].is_full is True
