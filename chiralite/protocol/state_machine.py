"""Connection state machine for a single chiralite silo session.

States::

    IDLE ──► CONNECTING ──► AUTHENTICATING ──► SYNCING ──► ACTIVE
                  ▲                │                │         │
                  │                ▼                ▼         ▼
                  │          RECONNECTING ◄──────────────────-┘
                  └──────────────────┘
                  (RECONNECTING → CONNECTING or IDLE)

``ACTIVE → IDLE`` is used for a clean, intentional shutdown.
All other disconnects go through ``RECONNECTING``.
"""
from __future__ import annotations

from enum import Enum


class SessionState(str, Enum):
    IDLE            = "idle"
    CONNECTING      = "connecting"
    AUTHENTICATING  = "authenticating"
    SYNCING         = "syncing"
    ACTIVE          = "active"
    RECONNECTING    = "reconnecting"


# Allowed state transitions.
_TRANSITIONS: dict[SessionState, frozenset[SessionState]] = {
    SessionState.IDLE:           frozenset({SessionState.CONNECTING}),
    SessionState.CONNECTING:     frozenset({SessionState.AUTHENTICATING,
                                            SessionState.RECONNECTING}),
    SessionState.AUTHENTICATING: frozenset({SessionState.SYNCING,
                                            SessionState.RECONNECTING}),
    SessionState.SYNCING:        frozenset({SessionState.ACTIVE,
                                            SessionState.RECONNECTING}),
    SessionState.ACTIVE:         frozenset({SessionState.RECONNECTING,
                                            SessionState.IDLE}),
    SessionState.RECONNECTING:   frozenset({SessionState.CONNECTING,
                                            SessionState.IDLE}),
}


class InvalidTransition(Exception):
    """Raised when a requested state transition is not in the allowed set."""


class SessionStateMachine:
    """Finite state machine for one silo session connection lifecycle.

    Thread-safety: not thread-safe.  All calls must be made from the same
    asyncio event loop task.
    """

    def __init__(self) -> None:
        self._state = SessionState.IDLE

    @property
    def state(self) -> SessionState:
        return self._state

    def transition(self, to: SessionState) -> None:
        """Move to state *to*.

        Raises:
            InvalidTransition: if the transition is not permitted from the
                current state.
        """
        allowed = _TRANSITIONS.get(self._state, frozenset())
        if to not in allowed:
            raise InvalidTransition(
                f"transition {self._state.value!r} → {to.value!r} is not allowed; "
                f"permitted: {[s.value for s in sorted(allowed, key=lambda s: s.value)]}"
            )
        self._state = to

    def is_active(self) -> bool:
        return self._state == SessionState.ACTIVE

    def is_live(self) -> bool:
        """True while the session is in any non-idle, non-reconnecting state."""
        return self._state in (
            SessionState.CONNECTING,
            SessionState.AUTHENTICATING,
            SessionState.SYNCING,
            SessionState.ACTIVE,
        )

    def __repr__(self) -> str:
        return f"SessionStateMachine(state={self._state.value!r})"
