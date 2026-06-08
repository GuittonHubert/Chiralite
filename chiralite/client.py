"""ChiraliteClient — asyncio client entry point.

Per-silo lifecycle::

    connect_with_retry
        └─ perform_client_handshake
              └─ SiloWatcher.start
                    └─ client_request_sync → drain diff via SyncEngine
                          └─ watcher event loop → SyncEngine
                                └─ on ConnectionLost → reconnect

Each silo runs in an independent asyncio task; a disconnect on one silo
does not affect others.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from chiralite.crypto.handshake import HandshakeError, perform_client_handshake
from chiralite.protocol.framing import FramedConnection
from chiralite.protocol.messages import FileEntry
from chiralite.security.audit import AuditLogger
from chiralite.sync.engine import SyncEngine, TransferError
from chiralite.sync.index import (
    DeleteEvent,
    RenameEvent,
    SiloIndex,
    SyncEvent,
    WriteEvent,
)
from chiralite.sync.reconciler import client_request_sync
from chiralite.sync.watcher import SiloWatcher
from chiralite.transport.websocket import ConnectionLost, WebSocketClient
from chiralite.trust.store import TrustStore

log = logging.getLogger(__name__)

__all__ = ["ChiraliteClient", "SiloClientConfig"]


class SiloClientConfig:
    """Configuration for one silo on the client side.

    Args:
        silo_id:    Silo UUID declared in HELLO.
        local_path: Local directory to watch and sync.
        blacklist:  Glob patterns to ignore (pathspec / gitignore style).
    """

    def __init__(
        self,
        silo_id: UUID,
        local_path: Path,
        blacklist: list[str] | None = None,
    ) -> None:
        self.silo_id = silo_id
        self.local_path = local_path
        self.blacklist: list[str] = blacklist or []


# Private key type alias
_PrivKey = ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey


class ChiraliteClient:
    """Manages one or more silo connections to the chiralite server.

    Args:
        server_url:   WebSocket URL (e.g. ``"wss://host:443"``).
        client_cert:  The client's X.509 certificate.
        client_key:   The private key matching *client_cert*.
        trust_store:  CA used to verify the server certificate.
        silos:        List of silo configurations to manage.
        audit:        AuditLogger (caller owns lifecycle).
    """

    def __init__(
        self,
        server_url: str,
        *,
        client_cert: x509.Certificate,
        client_key: _PrivKey,
        trust_store: TrustStore,
        silos: list[SiloClientConfig],
        audit: AuditLogger,
    ) -> None:
        self._url = server_url
        self._client_cert = client_cert
        self._client_key = client_key
        self._trust_store = trust_store
        self._silos = silos
        self._audit = audit
        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start all silo tasks and run until ``stop()`` is called."""
        tasks = [
            asyncio.create_task(self._run_silo_with_retry(cfg))
            for cfg in self._silos
        ]
        await self._stop_event.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self) -> None:
        """Signal all silo tasks to stop after the current iteration."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Per-silo loop
    # ------------------------------------------------------------------

    async def _run_silo_with_retry(self, cfg: SiloClientConfig) -> None:
        """Connect, sync, and watch — reconnecting on any disconnect."""
        while not self._stop_event.is_set():
            try:
                await self._run_silo_once(cfg)
            except asyncio.CancelledError:
                break
            except (HandshakeError, ConnectionLost, OSError) as exc:
                log.warning(
                    "silo %s disconnected: %s — reconnecting in 5s", cfg.silo_id, exc
                )
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    pass

    async def _run_silo_once(self, cfg: SiloClientConfig) -> None:
        """One connect-sync-watch cycle for *cfg*."""
        ws_client = WebSocketClient(self._url)
        conn = await ws_client.connect_with_retry()
        framed = FramedConnection(conn)

        result = await perform_client_handshake(
            framed,
            silo_id=cfg.silo_id,
            client_cert=self._client_cert,
            client_key=self._client_key,
            ca_cert=self._trust_store.ca_cert,
        )

        self._audit.log_auth_ok("(self)", cfg.silo_id)
        self._audit.log_session_start("(self)", cfg.silo_id)

        index = SiloIndex(silo_id=cfg.silo_id, node_id="client")
        engine = SyncEngine(framed)

        async with SiloWatcher(
            cfg.local_path,
            blacklist=cfg.blacklist,
        ) as watcher:
            # Initial reconciliation: send everything the server is missing
            diff = await client_request_sync(framed, index)
            for entry in diff:
                await self._send_entry(engine, entry, cfg.local_path)

            # Forward watcher events
            async for event in watcher:
                if self._stop_event.is_set():
                    break
                await self._dispatch_event(engine, event, cfg.local_path)

        self._audit.log_session_end("(self)", cfg.silo_id)

    # ------------------------------------------------------------------
    # Event dispatch
    # ------------------------------------------------------------------

    async def _dispatch_event(
        self,
        engine: SyncEngine,
        event: SyncEvent,
        local_path: Path,
    ) -> None:
        try:
            if isinstance(event, WriteEvent):
                abs_path = local_path / event.path
                content = await asyncio.get_event_loop().run_in_executor(
                    None, abs_path.read_bytes
                )
                entry = _write_event_to_entry(event, is_full=True)
                await engine.send_write(entry, content)

            elif isinstance(event, DeleteEvent):
                await engine.send_delete(event.path)

            elif isinstance(event, RenameEvent):
                await engine.send_rename(event.old_path, event.new_path)

        except TransferError as exc:
            log.warning("transfer rejected by server for %r: %s", _event_path(event), exc)
        except OSError as exc:
            log.warning("could not read %r: %s", _event_path(event), exc)

    async def _send_entry(
        self,
        engine: SyncEngine,
        entry: FileEntry,
        local_path: Path,
    ) -> None:
        """Send one entry from the reconciliation diff."""
        try:
            abs_path = local_path / entry.path
            content = await asyncio.get_event_loop().run_in_executor(
                None, abs_path.read_bytes
            )
            await engine.send_write(entry, content)
        except TransferError as exc:
            log.warning("server rejected %r: %s", entry.path, exc)
        except OSError as exc:
            log.warning("could not read %r for initial sync: %s", entry.path, exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_event_to_entry(event: WriteEvent, *, is_full: bool) -> FileEntry:
    return FileEntry(
        path=event.path,
        rapidhash=event.rapidhash,
        size=event.size,
        mode=event.mode,
        uid_name=event.uid_name,
        gid_name=event.gid_name,
        mtime_s=event.mtime_s,
        mtime_ns=event.mtime_ns,
        is_full=is_full,
        delta_base_rapidhash=None,
    )


def _event_path(event: SyncEvent) -> str:
    if isinstance(event, WriteEvent):
        return event.path
    if isinstance(event, DeleteEvent):
        return event.path
    if isinstance(event, RenameEvent):
        return event.old_path
    return "(unknown)"
