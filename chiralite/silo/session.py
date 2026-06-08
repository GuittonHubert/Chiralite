"""SiloSession — per-silo runtime state after a successful handshake.

One ``SiloSession`` is created per authenticated WebSocket connection and
holds everything needed to validate and execute file operations within the
silo jail.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from uuid import UUID

from chiralite.fs.jail import PathJail
from chiralite.trust.policy import GidPolicy, OpType, UidPolicy

__all__ = ["SiloSession"]


@dataclasses.dataclass
class SiloSession:
    """Active runtime state for one authenticated silo connection.

    Attributes:
        silo_id:      Silo UUID, validated against policy at handshake time.
        client_cn:    Common Name from the client's certificate.
        jail:         ``PathJail`` rooted at the silo's server directory.
        allowed_ops:  Set of operations this client is permitted to perform.
        uid_policy:   UID resolution policy for this silo.
        gid_policy:   GID resolution policy for this silo.
        blacklist:    Active glob patterns; paths matching these are ignored.
    """

    silo_id: UUID
    client_cn: str
    jail: PathJail
    allowed_ops: frozenset[OpType]
    uid_policy: UidPolicy
    gid_policy: GidPolicy
    blacklist: list[str] = dataclasses.field(default_factory=list)

    @property
    def jail_root(self) -> Path:
        """Convenience accessor for the jail's root path."""
        return self.jail.root

    def permits(self, op: OpType) -> bool:
        """Return True if this session allows *op*."""
        return op in self.allowed_ops
