"""Silo access policy — UID/GID resolution and per-CN operation permissions.

Security invariants enforced here (§3.4):
- Names in the hardcoded deny list are always rejected, regardless of config.
- UID 0 is never returned, even if the mapping resolves to it.
- Numeric UID/GID strings are treated as names and checked against the deny
  list; they never bypass symbolic resolution.
"""
from __future__ import annotations

import dataclasses
import grp
import pwd
from enum import Enum
from uuid import UUID

__all__ = [
    "OpType",
    "UidPolicy",
    "GidPolicy",
    "ClientPolicy",
    "SiloPolicy",
    "PolicyError",
    "SecurityError",
    "resolve_uid",
    "resolve_gid",
]

# ---------------------------------------------------------------------------
# Hardcoded deny lists (§3.4 — not overridable by configuration)
# ---------------------------------------------------------------------------

_DENIED_UID_NAMES: frozenset[str] = frozenset(
    {"root", "daemon", "bin", "sys", "www-data", "sudo", "wheel", "shadow", "0"}
)

_DENIED_GID_NAMES: frozenset[str] = frozenset(
    {"root", "daemon", "bin", "sys", "www-data", "sudo", "wheel", "shadow", "0"}
)


# ---------------------------------------------------------------------------
# OpType
# ---------------------------------------------------------------------------

class OpType(str, Enum):
    READ   = "READ"
    WRITE  = "WRITE"
    DELETE = "DELETE"
    RENAME = "RENAME"


# ---------------------------------------------------------------------------
# Policy dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class UidPolicy:
    """Server-side UID resolution policy for a silo.

    Attributes:
        map:     Explicit name → name overrides (e.g. ``{"fm": "deploy"}``).
        default: Fallback name when the incoming name has no mapping
                 and is not in the deny list (e.g. ``"nobody"``).
        deny:    Additional denied names on top of the hardcoded list.
    """

    map: dict[str, str] = dataclasses.field(default_factory=dict)
    default: str = "nobody"
    deny: frozenset[str] = dataclasses.field(default_factory=frozenset)


@dataclasses.dataclass(frozen=True)
class GidPolicy:
    """Server-side GID resolution policy for a silo."""

    map: dict[str, str] = dataclasses.field(default_factory=dict)
    default: str = "nogroup"
    deny: frozenset[str] = dataclasses.field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Per-client access record and silo-level policy
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ClientPolicy:
    """Access policy for one CN within one silo."""

    cn: str
    silo_id: UUID
    allowed_ops: frozenset[OpType]
    uid_policy: UidPolicy
    gid_policy: GidPolicy


class SiloPolicy:
    """Maps (CN, silo_id) pairs to ``ClientPolicy`` objects.

    Args:
        entries: Iterable of ``ClientPolicy`` records loaded from config.
    """

    def __init__(self, entries: list[ClientPolicy]) -> None:
        self._map: dict[tuple[str, UUID], ClientPolicy] = {
            (e.cn, e.silo_id): e for e in entries
        }

    def lookup(self, cn: str, silo_id: UUID) -> ClientPolicy:
        """Return the policy for *cn* accessing *silo_id*.

        Raises:
            PolicyError: if the CN is not authorised for the silo.
        """
        key = (cn, silo_id)
        policy = self._map.get(key)
        if policy is None:
            raise PolicyError(
                f"client {cn!r} is not authorised for silo {silo_id}"
            )
        return policy

    def has_op(self, cn: str, silo_id: UUID, op: OpType) -> bool:
        """Return True if *cn* may perform *op* on *silo_id*."""
        try:
            return op in self.lookup(cn, silo_id).allowed_ops
        except PolicyError:
            return False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PolicyError(Exception):
    """Raised when a CN is not authorised for a silo or operation."""


class SecurityError(Exception):
    """Raised when UID/GID resolution would violate a security constraint."""


# ---------------------------------------------------------------------------
# UID/GID resolution
# ---------------------------------------------------------------------------

def resolve_uid(name: str, policy: UidPolicy) -> int:
    """Resolve a symbolic user name to a numeric UID using *policy*.

    Resolution order:
    1. Reject if *name* is in the hardcoded or policy-level deny list.
    2. Apply ``policy.map`` override (key → local user name).
    3. Fall back to ``policy.default`` if not in map.
    4. Resolve the resulting name via ``pwd.getpwnam``.
    5. Reject if the resolved UID is 0.

    Args:
        name:   Symbolic name received from the wire (never numeric).
        policy: The UID policy for this silo.

    Returns:
        A non-zero numeric UID.

    Raises:
        SecurityError: if *name* is denied, resolves to uid 0, or is unknown.
    """
    _check_denied_uid(name, policy.deny)
    local_name = policy.map.get(name, policy.default)
    return _lookup_uid_safe(local_name)


def resolve_gid(name: str, policy: GidPolicy) -> int:
    """Resolve a symbolic group name to a numeric GID using *policy*.

    Raises:
        SecurityError: if *name* is denied, resolves to gid 0, or is unknown.
    """
    _check_denied_gid(name, policy.deny)
    local_name = policy.map.get(name, policy.default)
    return _lookup_gid_safe(local_name)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_denied_uid(name: str, extra_deny: frozenset[str]) -> None:
    all_denied = _DENIED_UID_NAMES | extra_deny
    if name in all_denied:
        raise SecurityError(f"uid name denied: {name!r}")


def _check_denied_gid(name: str, extra_deny: frozenset[str]) -> None:
    all_denied = _DENIED_GID_NAMES | extra_deny
    if name in all_denied:
        raise SecurityError(f"gid name denied: {name!r}")


def _lookup_uid_safe(name: str) -> int:
    try:
        uid = pwd.getpwnam(name).pw_uid
    except KeyError:
        raise SecurityError(f"unknown user: {name!r}") from None
    if uid == 0:
        raise SecurityError(f"resolved uid 0 is forbidden (user {name!r})")
    return uid


def _lookup_gid_safe(name: str) -> int:
    try:
        gid = grp.getgrnam(name).gr_gid
    except KeyError:
        raise SecurityError(f"unknown group: {name!r}") from None
    if gid == 0:
        raise SecurityError(f"resolved gid 0 is forbidden (group {name!r})")
    return gid
