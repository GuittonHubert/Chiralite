"""SiloRegistry — tracks active SiloSession objects.

The registry is the single authoritative source of active sessions for a
running server process.  It is asyncio-safe (all mutations happen on the
event-loop thread; no explicit locking is needed).
"""
from __future__ import annotations

from uuid import UUID

from chiralite.silo.session import SiloSession

__all__ = ["RegistryError", "SiloRegistry"]


class RegistryError(Exception):
    """Raised when a session registration constraint is violated."""


class SiloRegistry:
    """Maps silo UUIDs to their active ``SiloSession``.

    A silo may only have one active session at a time.  Attempting to register
    a second session for the same ``silo_id`` raises ``RegistryError``.
    """

    def __init__(self) -> None:
        self._sessions: dict[UUID, SiloSession] = {}

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def register(self, session: SiloSession) -> None:
        """Add *session* to the registry.

        Raises:
            RegistryError: if a session for ``session.silo_id`` already exists.
        """
        if session.silo_id in self._sessions:
            raise RegistryError(
                f"silo {session.silo_id} already has an active session"
            )
        self._sessions[session.silo_id] = session

    def unregister(self, silo_id: UUID) -> SiloSession | None:
        """Remove and return the session for *silo_id*, or None if absent."""
        return self._sessions.pop(silo_id, None)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, silo_id: UUID) -> SiloSession | None:
        """Return the session for *silo_id*, or None if not registered."""
        return self._sessions.get(silo_id)

    def require(self, silo_id: UUID) -> SiloSession:
        """Return the session for *silo_id*.

        Raises:
            RegistryError: if no session is registered for *silo_id*.
        """
        session = self._sessions.get(silo_id)
        if session is None:
            raise RegistryError(f"no active session for silo {silo_id}")
        return session

    @property
    def active_sessions(self) -> list[SiloSession]:
        """Return a snapshot list of all currently registered sessions."""
        return list(self._sessions.values())

    def __len__(self) -> int:
        return len(self._sessions)

    def __contains__(self, silo_id: object) -> bool:
        return silo_id in self._sessions
