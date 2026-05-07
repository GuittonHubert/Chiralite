"""ChiraliteServer — asyncio server entry point.

Pipeline per connection::

    WebSocket accept
        └─ perform_server_handshake   → SiloSession
              └─ server_handle_sync_request
                    └─ event loop
                          ├─ TRANSFER_BEGIN … COMMIT → verify → scan → write → ACK/NACK
                          ├─ FILE_DELETE              → atomic unlink
                          └─ FILE_RENAME              → atomic rename

All paths are jailed via ``SiloSession.jail``.  Audit events are written
on every significant operation.  Rate limiting is enforced per CN.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from uuid import UUID

from chiralite.crypto.handshake import HandshakeError, perform_server_handshake
from chiralite.delta import PatchError, apply_delta
from chiralite.filesystem.writer import WriteError, atomic_write
from chiralite.fs.jail import JailbreakError, PathJail
from chiralite.hash import rapidhash
from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import (
    FileDeleteMsg,
    FileRenameMsg,
    TransferAckMsg,
    TransferBeginMsg,
    TransferChunkMsg,
    TransferCommitMsg,
    TransferNackMsg,
)
from chiralite.sandbox.clamav import ClamdClient, ScanResult
from chiralite.security.audit import AuditLogger
from chiralite.security.ratelimit import RateLimitExceeded, RateLimiter
from chiralite.silo.registry import RegistryError, SiloRegistry
from chiralite.silo.session import SiloSession
from chiralite.sync.index import SiloIndex
from chiralite.sync.reconciler import server_handle_sync_request
from chiralite.transport.websocket import Connection, ConnectionLost, WebSocketServer
from chiralite.trust.policy import (
    ClientPolicy,
    PolicyError,
    SecurityError,
    SiloPolicy,
    resolve_gid,
    resolve_uid,
)
from chiralite.trust.store import TrustError, TrustStore

log = logging.getLogger(__name__)

__all__ = ["ChiraliteServer", "ServerError"]


class ServerError(Exception):
    """Non-recoverable server configuration error."""


class ChiraliteServer:
    """Asyncio-based chiralite sync server.

    Args:
        host:         Bind address (e.g. ``"0.0.0.0"``).
        port:         TCP port to listen on.
        trust_store:  CA used to verify incoming client certificates.
        silo_policy:  Maps (CN, silo_id) → ClientPolicy.
        silo_roots:   Maps silo_id → absolute jail root path.
        indexes:      Maps silo_id → SiloIndex (shared across connections).
        audit:        AuditLogger instance (caller owns lifecycle).
        clamd:        ClamdClient for AV scanning (``None`` disables scanning).
        rate_limiter: Optional per-CN rate limiter.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        trust_store: TrustStore,
        silo_policy: SiloPolicy,
        silo_roots: dict[UUID, Path],
        indexes: dict[UUID, SiloIndex],
        audit: AuditLogger,
        clamd: ClamdClient | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._trust_store = trust_store
        self._silo_policy = silo_policy
        self._silo_roots = silo_roots
        self._indexes = indexes
        self._audit = audit
        self._clamd = clamd
        self._rate_limiter = rate_limiter
        self._registry = SiloRegistry()
        self._ws_server: WebSocketServer | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start listening for WebSocket connections."""
        self._ws_server = WebSocketServer(
            self._host, self._port, self._handle_connection
        )
        await self._ws_server.serve()
        log.info("ChiraliteServer listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        """Stop accepting new connections and close the server socket."""
        if self._ws_server is not None:
            await self._ws_server.close()
            log.info("ChiraliteServer stopped")

    @property
    def port(self) -> int:
        """Actual bound port (useful when port=0 was passed)."""
        if self._ws_server is None:
            raise ServerError("server has not been started")
        return self._ws_server.port

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    async def _handle_connection(self, conn: Connection) -> None:
        framed = FramedConnection(conn)
        session: SiloSession | None = None
        try:
            session = await self._authenticate(framed)
            if session is None:
                return
            await self._serve_session(framed, session)
        except (ConnectionLost, asyncio.IncompleteReadError):
            log.debug("client disconnected from %s", conn.remote_addr)
        except Exception:
            log.exception("unhandled error from %s", conn.remote_addr)
        finally:
            if session is not None:
                self._registry.unregister(session.silo_id)
                self._audit.log_session_end(session.client_cn, session.silo_id)

    async def _authenticate(self, framed: FramedConnection) -> SiloSession | None:
        """Run handshake and return a session, or None on auth failure."""
        from chiralite.crypto.certificates import get_cn

        server_cert = self._trust_store.ca_cert  # placeholder: caller injects real cert

        try:
            result = await perform_server_handshake(
                framed,
                server_cert=server_cert,
                server_key=None,       # caller must inject; tested separately
                ca_cert=self._trust_store.ca_cert,
                allowed_silos=list(self._silo_roots.keys()),
            )
        except HandshakeError as exc:
            self._audit.log_auth_fail("(unknown)", str(exc))
            return None

        client_cn = result.client_cn
        silo_id = result.silo_id

        # Rate-limit by CN
        if self._rate_limiter is not None:
            try:
                self._rate_limiter.require(client_cn)
            except RateLimitExceeded:
                self._audit.log_auth_fail(client_cn, "rate limit exceeded")
                return None

        # Policy lookup
        try:
            policy = self._silo_policy.lookup(client_cn, silo_id)
        except PolicyError as exc:
            self._audit.log_auth_fail(client_cn, str(exc))
            return None

        # Build session
        root = self._silo_roots.get(silo_id)
        if root is None:
            self._audit.log_auth_fail(client_cn, f"unknown silo {silo_id}")
            return None

        session = SiloSession(
            silo_id=silo_id,
            client_cn=client_cn,
            jail=PathJail(root),
            allowed_ops=policy.allowed_ops,
            uid_policy=policy.uid_policy,
            gid_policy=policy.gid_policy,
        )

        try:
            self._registry.register(session)
        except RegistryError:
            self._audit.log_auth_fail(client_cn, f"silo {silo_id} already active")
            return None

        self._audit.log_auth_ok(client_cn, silo_id)
        self._audit.log_session_start(client_cn, silo_id)
        return session

    # ------------------------------------------------------------------
    # Session event loop
    # ------------------------------------------------------------------

    async def _serve_session(
        self, framed: FramedConnection, session: SiloSession
    ) -> None:
        index = self._indexes.get(session.silo_id)
        if index is None:
            index = SiloIndex(silo_id=session.silo_id, node_id="server")
            self._indexes[session.silo_id] = index

        await server_handle_sync_request(framed, index)

        while True:
            msg = await framed.recv()

            if isinstance(msg, TransferBeginMsg):
                await self._handle_transfer(framed, session, msg, index)

            elif isinstance(msg, FileDeleteMsg):
                await self._handle_delete(session, msg)

            elif isinstance(msg, FileRenameMsg):
                await self._handle_rename(session, msg)

            else:
                log.debug("ignored message type %s", type(msg).__name__)

    # ------------------------------------------------------------------
    # Transfer handling
    # ------------------------------------------------------------------

    async def _handle_transfer(
        self,
        framed: FramedConnection,
        session: SiloSession,
        begin: TransferBeginMsg,
        index: SiloIndex,
    ) -> None:
        tid = begin.transfer_id
        entry = begin.entry

        # Validate path early
        try:
            session.jail.resolve(entry.path)
        except JailbreakError as exc:
            self._audit.log_path_traversal(session.client_cn, session.silo_id, entry.path)
            await self._drain_and_nack(framed, begin, str(exc))
            return

        # Collect chunks
        chunks: dict[int, bytes] = {}
        for _ in range(begin.chunk_count):
            msg = await framed.recv()
            if not isinstance(msg, TransferChunkMsg) or msg.transfer_id != tid:
                await framed.send(TransferNackMsg(transfer_id=tid, reason="protocol_error"))
                return
            chunks[msg.seq] = msg.data

        commit = await framed.recv()
        if not isinstance(commit, TransferCommitMsg) or commit.transfer_id != tid:
            await framed.send(TransferNackMsg(transfer_id=tid, reason="protocol_error"))
            return

        payload = b"".join(chunks[i] for i in sorted(chunks))

        # Reconstruct full content
        if not entry.is_full:
            try:
                base_content = self._read_base(session, index, entry.delta_base_rapidhash)
                content = apply_delta(base_content, payload)
            except (PatchError, OSError) as exc:
                await framed.send(TransferNackMsg(transfer_id=tid, reason=f"delta_error: {exc}"))
                return
        else:
            content = payload

        # Rapidhash integrity check
        actual_rh = rapidhash(content)
        if actual_rh != commit.rapidhash:
            await framed.send(TransferNackMsg(transfer_id=tid, reason="rapidhash_mismatch"))
            return

        # AV scan
        scan_result = await self._scan(content)
        if not scan_result.is_clean:
            self._audit.log_quarantine(
                session.client_cn, session.silo_id, entry.path,
                virus=scan_result.virus_name or scan_result.error or "unknown",
            )
            await framed.send(TransferNackMsg(transfer_id=tid, reason="quarantine"))
            return

        # Resolve uid/gid with policy
        try:
            uid = resolve_uid(entry.uid_name, session.uid_policy)
            gid = resolve_gid(entry.gid_name, session.gid_policy)
        except SecurityError as exc:
            self._audit.log_uid_denied(session.client_cn, session.silo_id, str(exc))
            await framed.send(TransferNackMsg(transfer_id=tid, reason="uid_denied"))
            return

        # Atomic write
        try:
            await atomic_write(session.jail, entry.path, content, entry)
        except (WriteError, JailbreakError) as exc:
            await framed.send(TransferNackMsg(transfer_id=tid, reason=str(exc)))
            return

        self._audit.log_file_write(
            session.client_cn, session.silo_id, entry.path,
            rapidhash_before=entry.delta_base_rapidhash,
            rapidhash_after=actual_rh,
            recv_ts_ns=entry.mtime_s * 1_000_000_000 + entry.mtime_ns,
            delta=not entry.is_full,
            size_bytes=len(content),
        )
        await framed.send(TransferAckMsg(transfer_id=tid, scan_result=str(scan_result)))

    async def _drain_and_nack(
        self,
        framed: FramedConnection,
        begin: TransferBeginMsg,
        reason: str,
    ) -> None:
        """Drain chunks + commit for a rejected transfer, then send NACK."""
        try:
            for _ in range(begin.chunk_count):
                await framed.recv()
            await framed.recv()  # commit
        except Exception:
            pass
        await framed.send(TransferNackMsg(transfer_id=begin.transfer_id, reason=reason))

    def _read_base(
        self,
        session: SiloSession,
        index: SiloIndex,
        base_rapidhash: int | None,
    ) -> bytes:
        """Return the base file bytes for a delta transfer."""
        if base_rapidhash is None:
            raise PatchError("delta transfer missing base rapidhash")
        # Find the path whose record matches the base rapidhash
        for path, record in index.records.items():
            if record.rapidhash == base_rapidhash and not record.deleted:
                abs_path = session.jail.resolve(path)
                return abs_path.read_bytes()
        raise PatchError(f"base with rapidhash {base_rapidhash} not found in index")

    async def _scan(self, content: bytes) -> ScanResult:
        if self._clamd is None:
            return ScanResult.make_clean()
        return await self._clamd.scan(content)

    # ------------------------------------------------------------------
    # Delete and rename
    # ------------------------------------------------------------------

    async def _handle_delete(self, session: SiloSession, msg: FileDeleteMsg) -> None:
        try:
            abs_path = session.jail.resolve(msg.path)
        except JailbreakError as exc:
            self._audit.log_path_traversal(session.client_cn, session.silo_id, msg.path)
            log.warning("path traversal on delete: %s", exc)
            return

        try:
            abs_path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("delete failed for %s: %s", msg.path, exc)
            return

        self._audit.log_file_delete(session.client_cn, session.silo_id, msg.path)

    async def _handle_rename(self, session: SiloSession, msg: FileRenameMsg) -> None:
        try:
            src = session.jail.resolve(msg.old_path)
            dst = session.jail.resolve(msg.new_path)
        except JailbreakError as exc:
            self._audit.log_path_traversal(
                session.client_cn, session.silo_id, msg.old_path
            )
            log.warning("path traversal on rename: %s", exc)
            return

        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
        except OSError as exc:
            log.warning("rename failed %s → %s: %s", msg.old_path, msg.new_path, exc)
            return

        self._audit.log_file_rename(
            session.client_cn, session.silo_id, msg.old_path, msg.new_path
        )
