"""SiloConfig — Pydantic model for a single silo's YAML configuration block.

Matches the structure documented in §9.3 of CLAUDE.md::

    silos:
      - id: "550e8400-e29b-41d4-a716-446655440000"
        name: "project-alpha"
        server_root: /srv/chiralite/alpha
        allowed_clients:
          - cn: "fm-macbook"
            ops: [READ, WRITE, DELETE, RENAME]
        uid_policy:
          map: {"fm": "deploy"}
          default: "nobody"
          deny: ["root", ...]
        ...
"""
from __future__ import annotations

from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from chiralite.trust.policy import GidPolicy, OpType, UidPolicy

__all__ = [
    "AllowedClientConfig",
    "UidPolicyConfig",
    "GidPolicyConfig",
    "SandboxConfig",
    "TransferConfig",
    "BurstConfig",
    "IgnoreConfig",
    "SiloConfig",
]


class UidPolicyConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    map: dict[str, str] = Field(default_factory=dict)
    default: str = "nobody"
    deny: list[str] = Field(default_factory=list)

    def to_policy(self) -> UidPolicy:
        return UidPolicy(
            map=dict(self.map),
            default=self.default,
            deny=frozenset(self.deny),
        )


class GidPolicyConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    map: dict[str, str] = Field(default_factory=dict)
    default: str = "nogroup"
    deny: list[str] = Field(default_factory=list)

    def to_policy(self) -> GidPolicy:
        return GidPolicy(
            map=dict(self.map),
            default=self.default,
            deny=frozenset(self.deny),
        )


class AllowedClientConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    cn: str
    ops: list[OpType] = Field(default_factory=lambda: list(OpType))


class SandboxConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_reconstructed_size_mb: int = 256
    scan_timeout_s: float = 30.0


class TransferConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    chunk_size_bytes: int = 262_144
    delta_threshold: float = 0.80


class BurstConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    debounce_ms: int = 200
    max_delay_ms: int = 1_500
    max_dirty_files: int = 50


class IgnoreConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    blacklist_extra: list[str] = Field(default_factory=list)
    whitelist: list[str] = Field(default_factory=list)


class SiloConfig(BaseModel):
    """Complete configuration for one silo."""

    model_config = ConfigDict(frozen=True)

    id: UUID
    name: str
    server_root: Path
    allowed_clients: list[AllowedClientConfig] = Field(default_factory=list)
    uid_policy: UidPolicyConfig = Field(default_factory=UidPolicyConfig)
    gid_policy: GidPolicyConfig = Field(default_factory=GidPolicyConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    transfer: TransferConfig = Field(default_factory=TransferConfig)
    burst: BurstConfig = Field(default_factory=BurstConfig)
    ignore: IgnoreConfig = Field(default_factory=IgnoreConfig)
