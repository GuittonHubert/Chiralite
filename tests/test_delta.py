"""Tests for chiralite/delta.py — differ, patcher, and binary codec."""
from __future__ import annotations

import dataclasses

import pytest

from chiralite.delta import (
    BLOCK_SIZE,
    CopyOp,
    Delta,
    DeltaError,
    InsertOp,
    PatchError,
    apply_delta,
    compute_delta,
    delta_from_bytes,
    delta_to_bytes,
)
from chiralite.hash import rapidhash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BS = 16  # small block size so tests stay tiny


def _fill(byte: int, n: int) -> bytes:
    return bytes([byte]) * n


def _round_trip(old: bytes, new: bytes, block_size: int = BS) -> bytes:
    return apply_delta(old, compute_delta(old, new, block_size))


# ---------------------------------------------------------------------------
# compute_delta — op structure
# ---------------------------------------------------------------------------

class TestComputeDelta:
    def test_identical_content_all_copy(self) -> None:
        data = _fill(0xAA, BS * 4)
        delta = compute_delta(data, data, BS)
        assert all(isinstance(op, CopyOp) for op in delta.ops)
        assert not any(isinstance(op, InsertOp) for op in delta.ops)

    def test_completely_different_all_insert(self) -> None:
        old = _fill(0x11, BS * 2)
        new = _fill(0x22, BS * 2)
        delta = compute_delta(old, new, BS)
        assert all(isinstance(op, InsertOp) for op in delta.ops)

    def test_append_produces_copy_then_insert(self) -> None:
        old = _fill(0xAA, BS)
        new = old + _fill(0xBB, BS)
        delta = compute_delta(old, new, BS)
        assert isinstance(delta.ops[0], CopyOp)
        assert isinstance(delta.ops[1], InsertOp)
        assert delta.ops[1].data == _fill(0xBB, BS)

    def test_prepend_produces_insert_then_copy(self) -> None:
        old = _fill(0xAA, BS)
        new = _fill(0xBB, BS) + old
        delta = compute_delta(old, new, BS)
        assert isinstance(delta.ops[0], InsertOp)
        assert isinstance(delta.ops[-1], CopyOp)

    def test_replace_middle_copy_insert_copy(self) -> None:
        block_a = _fill(0x01, BS)
        block_b = _fill(0x02, BS)
        block_c = _fill(0x03, BS)
        old = block_a + block_b + block_c
        new = block_a + _fill(0xFF, BS) + block_c
        delta = compute_delta(old, new, BS)
        assert isinstance(delta.ops[0], CopyOp)  # block_a
        assert isinstance(delta.ops[1], InsertOp)  # modified middle
        assert isinstance(delta.ops[2], CopyOp)  # block_c

    def test_empty_old_all_insert(self) -> None:
        new = _fill(0xAA, BS)
        delta = compute_delta(b"", new, BS)
        assert len(delta.ops) == 1
        assert isinstance(delta.ops[0], InsertOp)
        assert delta.ops[0].data == new

    def test_empty_new_no_ops(self) -> None:
        old = _fill(0xAA, BS)
        delta = compute_delta(old, b"", BS)
        assert delta.ops == ()

    def test_both_empty_no_ops(self) -> None:
        delta = compute_delta(b"", b"", BS)
        assert delta.ops == ()

    def test_partial_last_block(self) -> None:
        old = _fill(0xAA, BS)
        new = old + b"\xFF" * 5   # tail smaller than block_size
        delta = compute_delta(old, new, BS)
        assert isinstance(delta.ops[-1], InsertOp)
        assert delta.ops[-1].data == b"\xFF" * 5

    def test_hashes_recorded(self) -> None:
        old = b"hello"
        new = b"world"
        delta = compute_delta(old, new)
        assert delta.source_rapidhash == rapidhash(old)
        assert delta.target_rapidhash == rapidhash(new)

    def test_adjacent_misses_merged_into_one_insert(self) -> None:
        old = _fill(0xAA, BS * 3)
        new = _fill(0xBB, BS * 3)   # no matching blocks
        delta = compute_delta(old, new, BS)
        # All non-matching strides must be merged into a single InsertOp.
        assert len(delta.ops) == 1
        assert isinstance(delta.ops[0], InsertOp)
        assert len(delta.ops[0].data) == BS * 3

    def test_repeated_block_copies_from_first_occurrence(self) -> None:
        block = _fill(0x5A, BS)
        old = block * 3
        new = block  # single copy of the repeated block
        delta = compute_delta(old, new, BS)
        assert len(delta.ops) == 1
        assert isinstance(delta.ops[0], CopyOp)
        assert delta.ops[0].length == BS

    def test_default_block_size_constant(self) -> None:
        assert BLOCK_SIZE == 4096

    def test_custom_block_size(self) -> None:
        old = _fill(0xAA, 8)
        new = _fill(0xAA, 8)
        delta = compute_delta(old, new, block_size=8)
        assert delta.block_size == 8
        assert all(isinstance(op, CopyOp) for op in delta.ops)


# ---------------------------------------------------------------------------
# apply_delta — round-trips
# ---------------------------------------------------------------------------

class TestApplyDelta:
    def test_identical_round_trip(self) -> None:
        data = _fill(0xDE, BS * 4)
        assert _round_trip(data, data) == data

    def test_append_round_trip(self) -> None:
        old = _fill(0xAA, BS)
        new = old + _fill(0xBB, BS)
        assert _round_trip(old, new) == new

    def test_prepend_round_trip(self) -> None:
        old = _fill(0xAA, BS)
        new = _fill(0xBB, BS) + old
        assert _round_trip(old, new) == new

    def test_replace_middle_round_trip(self) -> None:
        old = _fill(0x01, BS) + _fill(0x02, BS) + _fill(0x03, BS)
        new = _fill(0x01, BS) + _fill(0xFF, BS) + _fill(0x03, BS)
        assert _round_trip(old, new) == new

    def test_completely_different_round_trip(self) -> None:
        old = _fill(0x11, BS * 2)
        new = _fill(0x22, BS * 2)
        assert _round_trip(old, new) == new

    def test_empty_to_content_round_trip(self) -> None:
        new = _fill(0xAA, BS)
        assert _round_trip(b"", new) == new

    def test_content_to_empty_round_trip(self) -> None:
        old = _fill(0xAA, BS)
        assert _round_trip(old, b"") == b""

    def test_both_empty_round_trip(self) -> None:
        assert _round_trip(b"", b"") == b""

    def test_wrong_source_hash_raises(self) -> None:
        old = b"hello"
        delta = compute_delta(old, b"world")
        with pytest.raises(PatchError, match="source rapidhash"):
            apply_delta(b"wrong", delta)

    def test_copy_out_of_bounds_raises(self) -> None:
        old = b"hi"
        bad_delta = Delta(
            ops=(CopyOp(offset=0, length=100),),
            block_size=BS,
            source_rapidhash=rapidhash(old),
            target_rapidhash=0,
        )
        with pytest.raises(PatchError, match="out of bounds"):
            apply_delta(old, bad_delta)

    def test_copy_negative_offset_raises(self) -> None:
        old = b"hello"
        bad_delta = Delta(
            ops=(CopyOp(offset=-1, length=1),),
            block_size=BS,
            source_rapidhash=rapidhash(old),
            target_rapidhash=0,
        )
        with pytest.raises(PatchError, match="out of bounds"):
            apply_delta(old, bad_delta)

    def test_target_hash_mismatch_raises(self) -> None:
        old = b"hello"
        new = b"world"
        delta = compute_delta(old, new)
        # Tamper with the expected target hash.
        bad_delta = dataclasses.replace(delta, target_rapidhash=0xDEADBEEF)
        with pytest.raises(PatchError, match="target rapidhash"):
            apply_delta(old, bad_delta)


# ---------------------------------------------------------------------------
# Binary codec
# ---------------------------------------------------------------------------

class TestDeltaCodec:
    def _make_delta(self) -> Delta:
        old = _fill(0xAA, BS) + _fill(0xBB, BS)
        new = _fill(0xAA, BS) + _fill(0xCC, BS)
        return compute_delta(old, new, BS)

    def test_round_trip(self) -> None:
        delta = self._make_delta()
        assert delta_from_bytes(delta_to_bytes(delta)) == delta

    def test_round_trip_preserves_ops(self) -> None:
        delta = self._make_delta()
        decoded = delta_from_bytes(delta_to_bytes(delta))
        assert len(decoded.ops) == len(delta.ops)
        for a, b in zip(decoded.ops, delta.ops):
            assert type(a) is type(b)

    def test_round_trip_preserves_hashes(self) -> None:
        delta = self._make_delta()
        decoded = delta_from_bytes(delta_to_bytes(delta))
        assert decoded.source_rapidhash == delta.source_rapidhash
        assert decoded.target_rapidhash == delta.target_rapidhash

    def test_empty_delta_round_trip(self) -> None:
        delta = compute_delta(b"hello", b"hello", BS)
        assert delta_from_bytes(delta_to_bytes(delta)) == delta

    def test_insert_only_round_trip(self) -> None:
        delta = compute_delta(b"", _fill(0xFF, 20), BS)
        decoded = delta_from_bytes(delta_to_bytes(delta))
        assert decoded == delta

    def test_invalid_magic_raises(self) -> None:
        data = b"XXXX" + b"\x00" * 21
        with pytest.raises(DeltaError, match="invalid magic"):
            delta_from_bytes(data)

    def test_unsupported_version_raises(self) -> None:
        raw = bytearray(delta_to_bytes(self._make_delta()))
        raw[4] = 99  # overwrite version byte
        with pytest.raises(DeltaError, match="unsupported"):
            delta_from_bytes(bytes(raw))

    def test_too_short_raises(self) -> None:
        with pytest.raises(DeltaError):
            delta_from_bytes(b"CHLT")

    def test_unknown_op_type_raises(self) -> None:
        raw = bytearray(delta_to_bytes(self._make_delta()))
        # Append a byte with an unrecognised op code.
        raw.append(0xFF)
        with pytest.raises(DeltaError, match="unknown op type"):
            delta_from_bytes(bytes(raw))

    def test_truncated_copy_op_raises(self) -> None:
        delta = self._make_delta()
        raw = delta_to_bytes(delta)
        # Truncate in the middle of the first op's payload.
        with pytest.raises(DeltaError, match="truncated"):
            delta_from_bytes(raw[:26])   # header(25) + op-type(1) only, no payload

    def test_apply_after_codec_round_trip(self) -> None:
        old = _fill(0xAA, BS) + _fill(0xBB, BS)
        new = _fill(0xAA, BS) + _fill(0xCC, BS)
        delta = compute_delta(old, new, BS)
        decoded = delta_from_bytes(delta_to_bytes(delta))
        assert apply_delta(old, decoded) == new
