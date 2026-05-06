"""Wire-protocol message models for the chiralite sync daemon.

All messages exchanged after the WebSocket upgrade are AES-256-GCM encrypted
JSON payloads (see payload.py).  This module defines the Pydantic models for
every message type and a discriminated union for single-call deserialization.

Binary fields (nonces, signatures, keys, chunk data) are typed as ``bytes``
so that Pydantic serialises them as base64 strings in JSON automatically.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Any, Literal
from uuid import UUID

import base64

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator
from pydantic.functional_serializers import PlainSerializer
from pydantic.functional_validators import BeforeValidator


# ---------------------------------------------------------------------------
# Helpers / constrained types
# ---------------------------------------------------------------------------

_UINT64_MAX = (1 << 64) - 1


def _decode_wirebytes(v: object) -> bytes:
    """Accept raw bytes (Python) or a base64 string (JSON)."""
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return base64.b64decode(v)
    raise ValueError(f"expected bytes or base64 str, got {type(v).__name__}")


# ``bytes`` that round-trips transparently:
#   - Python construction: pass raw bytes
#   - JSON output: base64-encoded string
#   - JSON input: base64 string decoded back to bytes
WireBytes = Annotated[
    bytes,
    BeforeValidator(_decode_wirebytes),
    PlainSerializer(lambda v: base64.b64encode(v).decode(), return_type=str, when_used="json"),
]

# Annotated int constrained to [0, 2^64-1] — used for rapidhash fields.
RapidHashInt = Annotated[int, Field(ge=0, le=_UINT64_MAX)]

# mtime sub-second part: [0, 999_999_999] nanoseconds.
MtimeNsInt = Annotated[int, Field(ge=0, le=999_999_999)]

# POSIX permission bits: 12 bits max (includes setuid/setgid/sticky).
FileModeInt = Annotated[int, Field(ge=0, le=0o7777)]

# Non-negative file size in bytes.
FileSizeInt = Annotated[int, Field(ge=0)]


# ---------------------------------------------------------------------------
# MsgType enum
# ---------------------------------------------------------------------------

class MsgType(str, Enum):
    # Handshake
    HELLO           = "hello"
    CHALLENGE       = "challenge"
    RESPONSE        = "response"
    ACCEPT          = "accept"
    AUTH_ERROR      = "auth_error"

    # Sync control
    SYNC_REQUEST    = "sync.request"
    SYNC_STATE      = "sync.state"
    BLACKLIST_SYNC  = "blacklist.sync"

    # File events
    FILE_WRITE      = "file.write"
    FILE_DELETE     = "file.delete"
    FILE_RENAME     = "file.rename"
    DIR_CREATE      = "dir.create"
    DIR_DELETE      = "dir.delete"
    DIR_RENAME      = "dir.rename"

    # Transfer (chunked data delivery)
    TRANSFER_BEGIN  = "transfer.begin"
    TRANSFER_CHUNK  = "transfer.chunk"
    TRANSFER_COMMIT = "transfer.commit"
    TRANSFER_ACK    = "transfer.ack"
    TRANSFER_NACK   = "transfer.nack"

    # Conflict notification
    CONFLICT_NOTIFY = "conflict.notify"

    # Session keepalive / teardown
    PING            = "ping"
    PONG            = "pong"
    SESSION_END     = "session.end"


# ---------------------------------------------------------------------------
# Shared sub-models
# ---------------------------------------------------------------------------

def _validate_relative_path(v: str) -> str:
    """Reject paths that would escape the silo jail at the protocol level."""
    if not v:
        raise ValueError("path must not be empty")
    if "\x00" in v:
        raise ValueError("null byte in path")
    if v.startswith("/"):
        raise ValueError("absolute path not allowed")
    if ".." in v.split("/"):
        raise ValueError("path traversal component (..) not allowed")
    return v


class FileEntry(BaseModel):
    """Metadata record for a single file as transmitted over the wire.

    Identity is determined by the triple (path, size, rapidhash).
    Binary delta support is signalled by ``is_full`` / ``delta_base_rapidhash``.
    """

    model_config = ConfigDict(frozen=True)

    path: str
    rapidhash: RapidHashInt
    size: FileSizeInt
    mode: FileModeInt
    uid_name: str
    gid_name: str

    # Split mtime — avoids float64 precision loss for large int64 values in JSON.
    mtime_s: int    # Unix seconds (int64)
    mtime_ns: MtimeNsInt  # sub-second nanoseconds, 0–999_999_999

    is_symlink: bool = False
    symlink_target: str | None = None

    # Delta fields
    is_full: bool
    delta_base_rapidhash: RapidHashInt | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        return _validate_relative_path(v)

    @field_validator("uid_name", "gid_name")
    @classmethod
    def validate_name_no_null(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("null byte in uid_name/gid_name")
        if not v:
            raise ValueError("uid_name/gid_name must not be empty")
        return v

    @field_validator("symlink_target")
    @classmethod
    def validate_symlink_target(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_relative_path(v)

    @model_validator(mode="after")
    def validate_symlink_consistency(self) -> "FileEntry":
        if self.is_symlink and self.symlink_target is None:
            raise ValueError("symlink_target is required when is_symlink=True")
        if not self.is_symlink and self.symlink_target is not None:
            raise ValueError("symlink_target must be None when is_symlink=False")
        return self

    @model_validator(mode="after")
    def validate_delta_consistency(self) -> "FileEntry":
        if self.is_full and self.delta_base_rapidhash is not None:
            raise ValueError("delta_base_rapidhash must be None for a full transfer")
        if not self.is_full and self.delta_base_rapidhash is None:
            raise ValueError("delta_base_rapidhash is required for a delta transfer")
        return self


class FileEntrySnapshot(BaseModel):
    """Index record sent in SYNC_STATE — includes server-side recv_ts_ns for LWW."""

    model_config = ConfigDict(frozen=True)

    rapidhash: RapidHashInt
    size: FileSizeInt
    mode: FileModeInt
    uid_name: str
    gid_name: str
    mtime_s: int
    mtime_ns: MtimeNsInt
    recv_ts_ns: int = Field(ge=0)
    deleted: bool = False


# ---------------------------------------------------------------------------
# Handshake messages
# ---------------------------------------------------------------------------

class HelloMsg(BaseModel):
    type: Literal[MsgType.HELLO] = MsgType.HELLO
    client_cert_pem: str    # PEM text
    nonce_c: WireBytes    # 32 random bytes, base64 in JSON
    ts_ns: int              # client Unix clock, nanoseconds
    silo_id: UUID


class ChallengeMsg(BaseModel):
    type: Literal[MsgType.CHALLENGE] = MsgType.CHALLENGE
    server_cert_pem: str
    nonce_s: WireBytes    # 32 random bytes
    challenge: WireBytes  # 32 random bytes


class ResponseMsg(BaseModel):
    type: Literal[MsgType.RESPONSE] = MsgType.RESPONSE
    sig_c: WireBytes      # sign(challenge ‖ nonce_s, client_key)
    ecdh_pub_c: WireBytes # X25519 ephemeral public key, 32 bytes


class AcceptMsg(BaseModel):
    type: Literal[MsgType.ACCEPT] = MsgType.ACCEPT
    sig_s: WireBytes          # sign(challenge ‖ nonce_c, server_key)
    ecdh_pub_s: WireBytes     # X25519 ephemeral public key, 32 bytes
    session_token: WireBytes
    silo_id_ack: UUID


class AuthErrorMsg(BaseModel):
    type: Literal[MsgType.AUTH_ERROR] = MsgType.AUTH_ERROR
    reason: str


# ---------------------------------------------------------------------------
# Sync-control messages
# ---------------------------------------------------------------------------

class SyncRequestMsg(BaseModel):
    type: Literal[MsgType.SYNC_REQUEST] = MsgType.SYNC_REQUEST


class SyncStateMsg(BaseModel):
    type: Literal[MsgType.SYNC_STATE] = MsgType.SYNC_STATE
    silo_id: UUID
    node_id: str
    records: dict[str, FileEntrySnapshot]  # path → snapshot


class BlacklistSyncMsg(BaseModel):
    type: Literal[MsgType.BLACKLIST_SYNC] = MsgType.BLACKLIST_SYNC
    patterns: list[str]


# ---------------------------------------------------------------------------
# File-event messages (metadata; data travels in TRANSFER_* messages)
# ---------------------------------------------------------------------------

class FileWriteMsg(BaseModel):
    """Announces an incoming file write; paired with a TRANSFER_* sequence."""

    type: Literal[MsgType.FILE_WRITE] = MsgType.FILE_WRITE
    transfer_id: UUID
    entry: FileEntry


class FileDeleteMsg(BaseModel):
    type: Literal[MsgType.FILE_DELETE] = MsgType.FILE_DELETE
    path: str
    recv_ts_ns: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        return _validate_relative_path(v)


class FileRenameMsg(BaseModel):
    type: Literal[MsgType.FILE_RENAME] = MsgType.FILE_RENAME
    old_path: str
    new_path: str
    recv_ts_ns: int = Field(ge=0)

    @field_validator("old_path", "new_path")
    @classmethod
    def validate_paths(cls, v: str) -> str:
        return _validate_relative_path(v)


class DirCreateMsg(BaseModel):
    type: Literal[MsgType.DIR_CREATE] = MsgType.DIR_CREATE
    path: str
    mode: FileModeInt
    uid_name: str
    gid_name: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        return _validate_relative_path(v)


class DirDeleteMsg(BaseModel):
    type: Literal[MsgType.DIR_DELETE] = MsgType.DIR_DELETE
    path: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        return _validate_relative_path(v)


class DirRenameMsg(BaseModel):
    type: Literal[MsgType.DIR_RENAME] = MsgType.DIR_RENAME
    old_path: str
    new_path: str

    @field_validator("old_path", "new_path")
    @classmethod
    def validate_paths(cls, v: str) -> str:
        return _validate_relative_path(v)


# ---------------------------------------------------------------------------
# Transfer messages (chunked binary delivery)
# ---------------------------------------------------------------------------

class TransferBeginMsg(BaseModel):
    """Opens a chunked transfer for a file write."""

    type: Literal[MsgType.TRANSFER_BEGIN] = MsgType.TRANSFER_BEGIN
    transfer_id: UUID
    entry: FileEntry
    total_size: FileSizeInt  # bytes of content to follow (delta or full)
    chunk_count: int = Field(ge=1)


class TransferChunkMsg(BaseModel):
    type: Literal[MsgType.TRANSFER_CHUNK] = MsgType.TRANSFER_CHUNK
    transfer_id: UUID
    seq: int = Field(ge=0)       # 0-indexed chunk sequence
    data: WireBytes            # chunk bytes, base64 in JSON


class TransferCommitMsg(BaseModel):
    type: Literal[MsgType.TRANSFER_COMMIT] = MsgType.TRANSFER_COMMIT
    transfer_id: UUID
    rapidhash: RapidHashInt  # expected hash of fully reconstructed content


class TransferAckMsg(BaseModel):
    type: Literal[MsgType.TRANSFER_ACK] = MsgType.TRANSFER_ACK
    transfer_id: UUID
    scan_result: str  # "clean" | "infected:<virus>" | "error:<reason>"


class TransferNackMsg(BaseModel):
    type: Literal[MsgType.TRANSFER_NACK] = MsgType.TRANSFER_NACK
    transfer_id: UUID
    reason: str


# ---------------------------------------------------------------------------
# Conflict notification
# ---------------------------------------------------------------------------

class ConflictNotifyMsg(BaseModel):
    type: Literal[MsgType.CONFLICT_NOTIFY] = MsgType.CONFLICT_NOTIFY
    path: str
    silo_id: UUID
    kept_rapidhash: RapidHashInt
    overwritten_rapidhash: RapidHashInt
    recv_ts_ns: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        return _validate_relative_path(v)


# ---------------------------------------------------------------------------
# Session keepalive / teardown
# ---------------------------------------------------------------------------

class PingMsg(BaseModel):
    type: Literal[MsgType.PING] = MsgType.PING
    ts_ns: int = Field(ge=0)


class PongMsg(BaseModel):
    type: Literal[MsgType.PONG] = MsgType.PONG
    ts_ns: int = Field(ge=0)  # echoes the Ping ts_ns


class SessionEndMsg(BaseModel):
    type: Literal[MsgType.SESSION_END] = MsgType.SESSION_END
    reason: str = ""


# ---------------------------------------------------------------------------
# Discriminated union and parse helpers
# ---------------------------------------------------------------------------

AnyMsg = Annotated[
    HelloMsg
    | ChallengeMsg
    | ResponseMsg
    | AcceptMsg
    | AuthErrorMsg
    | SyncRequestMsg
    | SyncStateMsg
    | BlacklistSyncMsg
    | FileWriteMsg
    | FileDeleteMsg
    | FileRenameMsg
    | DirCreateMsg
    | DirDeleteMsg
    | DirRenameMsg
    | TransferBeginMsg
    | TransferChunkMsg
    | TransferCommitMsg
    | TransferAckMsg
    | TransferNackMsg
    | ConflictNotifyMsg
    | PingMsg
    | PongMsg
    | SessionEndMsg,
    Field(discriminator="type"),
]

_adapter: TypeAdapter[AnyMsg] = TypeAdapter(AnyMsg)


def parse_msg(data: dict[str, Any]) -> AnyMsg:
    """Deserialise a plain dict (already JSON-decoded) into the correct message type."""
    return _adapter.validate_python(data)


def parse_json(raw: str | bytes) -> AnyMsg:
    """Deserialise a raw JSON string or bytes into the correct message type."""
    return _adapter.validate_json(raw if isinstance(raw, bytes) else raw.encode())
