"""Block-based binary delta computation and application.

``compute_delta`` builds a rapidhash index of non-overlapping chunks in the
old content, then scans the new content in the same strides.  Matching
chunks become ``CopyOp`` instructions; non-matching strides are merged into
``InsertOp`` instructions.  ``apply_delta`` reconstructs the new content and
validates both source and target rapidhash values.

``delta_to_bytes`` / ``delta_from_bytes`` provide a compact binary codec
for wire transfer.
"""
from __future__ import annotations

import dataclasses
import struct
from typing import Union

from chiralite.hash import rapidhash as _rh

# Default block size for the differ (bytes).
BLOCK_SIZE = 4096


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DeltaError(Exception):
    """Raised when a serialised delta cannot be decoded."""


class PatchError(Exception):
    """Raised when a delta cannot be applied to the given base content."""


# ---------------------------------------------------------------------------
# Instruction types
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class CopyOp:
    """Copy *length* bytes from the source starting at *offset*."""

    offset: int
    length: int


@dataclasses.dataclass(frozen=True)
class InsertOp:
    """Insert *data* verbatim into the output."""

    data: bytes


Op = Union[CopyOp, InsertOp]


# ---------------------------------------------------------------------------
# Delta container
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Delta:
    """Ordered sequence of copy/insert instructions that transform old → new.

    ``source_rapidhash`` and ``target_rapidhash`` bind this delta to the
    exact pair of byte strings it was derived from; ``apply_delta`` checks
    both values and raises ``PatchError`` on mismatch.
    """

    ops: tuple[Op, ...]
    block_size: int
    source_rapidhash: int
    target_rapidhash: int


# ---------------------------------------------------------------------------
# Differ
# ---------------------------------------------------------------------------

def compute_delta(
    old: bytes,
    new: bytes,
    block_size: int = BLOCK_SIZE,
) -> Delta:
    """Compute a block-aligned delta from *old* to *new*.

    Algorithm:
    1. Divide *old* into non-overlapping *block_size*-byte chunks and
       build a rapidhash → [(offset, bytes)] index.
    2. Scan *new* in the same strides; a chunk whose rapidhash and bytes
       match an old chunk becomes a ``CopyOp``; anything else is appended
       to an accumulation buffer.
    3. Non-matching strides are flushed as a single merged ``InsertOp``
       whenever a ``CopyOp`` is emitted or at end-of-input.
    """
    # Build index of old blocks.
    old_index: dict[int, list[tuple[int, bytes]]] = {}
    for off in range(0, len(old), block_size):
        blk = old[off : off + block_size]
        h = _rh(blk)
        old_index.setdefault(h, []).append((off, blk))

    ops: list[Op] = []
    insert_buf = bytearray()
    pos = 0

    while pos < len(new):
        blk = new[pos : pos + block_size]
        match_offset: int | None = None
        for old_off, old_blk in old_index.get(_rh(blk), []):
            if old_blk == blk:
                match_offset = old_off
                break

        if match_offset is not None:
            if insert_buf:
                ops.append(InsertOp(data=bytes(insert_buf)))
                insert_buf.clear()
            ops.append(CopyOp(offset=match_offset, length=len(blk)))
        else:
            insert_buf += blk
        pos += len(blk)

    if insert_buf:
        ops.append(InsertOp(data=bytes(insert_buf)))

    return Delta(
        ops=tuple(ops),
        block_size=block_size,
        source_rapidhash=_rh(old),
        target_rapidhash=_rh(new),
    )


# ---------------------------------------------------------------------------
# Patcher
# ---------------------------------------------------------------------------

def apply_delta(old: bytes, delta: Delta) -> bytes:
    """Reconstruct target content by applying *delta* to *old*.

    Raises:
        PatchError: if the source rapidhash of *old* does not match
            ``delta.source_rapidhash``, if a ``CopyOp`` references bytes
            outside *old*, or if the result does not match
            ``delta.target_rapidhash``.
    """
    if _rh(old) != delta.source_rapidhash:
        raise PatchError(
            "source rapidhash mismatch — delta was computed against a different base"
        )

    out = bytearray()
    for op in delta.ops:
        if isinstance(op, CopyOp):
            end = op.offset + op.length
            if op.offset < 0 or end > len(old):
                raise PatchError(
                    f"COPY out of bounds: offset={op.offset}, length={op.length}, "
                    f"source_len={len(old)}"
                )
            out += old[op.offset : end]
        else:
            out += op.data

    result = bytes(out)
    if _rh(result) != delta.target_rapidhash:
        raise PatchError(
            "target rapidhash mismatch after applying delta — data is corrupt"
        )
    return result


# ---------------------------------------------------------------------------
# Binary codec
# ---------------------------------------------------------------------------
#
# Header (25 bytes):
#   [0:4]   magic b"CHLT"
#   [4]     version uint8
#   [5:9]   block_size uint32 big-endian
#   [9:17]  source_rapidhash uint64 little-endian
#   [17:25] target_rapidhash uint64 little-endian
#
# Op encoding:
#   COPY:   \x01 + offset uint64 BE + length uint32 BE  (13 bytes)
#   INSERT: \x02 + length uint32 BE + data               (5 + N bytes)

_MAGIC = b"CHLT"
_VERSION = 1
_HEADER_SIZE = 25
_OP_COPY = 0x01
_OP_INSERT = 0x02


def delta_to_bytes(delta: Delta) -> bytes:
    """Serialise *delta* to a compact binary blob for wire transfer."""
    buf = bytearray(_MAGIC)
    buf.append(_VERSION)
    buf += struct.pack(">I", delta.block_size)
    buf += struct.pack("<QQ", delta.source_rapidhash, delta.target_rapidhash)
    for op in delta.ops:
        if isinstance(op, CopyOp):
            buf.append(_OP_COPY)
            buf += struct.pack(">QI", op.offset, op.length)
        else:
            buf.append(_OP_INSERT)
            buf += struct.pack(">I", len(op.data))
            buf += op.data
    return bytes(buf)


def delta_from_bytes(data: bytes) -> Delta:
    """Deserialise a delta produced by ``delta_to_bytes``.

    Raises:
        DeltaError: on invalid magic, unsupported version, or truncated data.
    """
    if len(data) < _HEADER_SIZE:
        raise DeltaError("data too short to contain a valid delta header")
    if data[:4] != _MAGIC:
        raise DeltaError(f"invalid magic: {data[:4]!r}")
    version = data[4]
    if version != _VERSION:
        raise DeltaError(f"unsupported delta version: {version}")
    block_size = struct.unpack_from(">I", data, 5)[0]
    source_rh, target_rh = struct.unpack_from("<QQ", data, 9)

    ops: list[Op] = []
    pos = _HEADER_SIZE
    try:
        while pos < len(data):
            op_type = data[pos]
            pos += 1
            if op_type == _OP_COPY:
                offset, length = struct.unpack_from(">QI", data, pos)
                pos += 12
                ops.append(CopyOp(offset=offset, length=length))
            elif op_type == _OP_INSERT:
                length = struct.unpack_from(">I", data, pos)[0]
                pos += 4
                ops.append(InsertOp(data=data[pos : pos + length]))
                pos += length
            else:
                raise DeltaError(f"unknown op type: {op_type:#04x} at byte {pos - 1}")
    except struct.error as exc:
        raise DeltaError(f"truncated delta data: {exc}") from exc

    return Delta(
        ops=tuple(ops),
        block_size=block_size,
        source_rapidhash=source_rh,
        target_rapidhash=target_rh,
    )
