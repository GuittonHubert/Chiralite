"""Tests for chiralite/delta.py — VCDIFF RFC 3284 differ and patcher."""
from __future__ import annotations

import os

import pytest

from chiralite.delta import (
    VCDIFF_MAGIC,
    NoDeltaFound,
    PatchError,
    apply_delta,
    compute_delta,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Minimum payload size for which xdelta3 reliably produces a shorter delta
# than the raw content (empirically: ≥ 50 bytes).
_MIN_SIZE = 512


def _fill(byte: int, n: int) -> bytes:
    return bytes([byte]) * n


def _round_trip(old: bytes, new: bytes) -> bytes:
    return apply_delta(old, compute_delta(old, new))


# ---------------------------------------------------------------------------
# VCDIFF format
# ---------------------------------------------------------------------------

class TestVCDiffFormat:
    def test_magic_bytes(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = old + _fill(0xBB, 64)
        delta = compute_delta(old, new)
        assert delta[:3] == VCDIFF_MAGIC

    def test_magic_constant_matches_rfc(self) -> None:
        assert VCDIFF_MAGIC == bytes([0xD6, 0xC3, 0xC4])

    def test_delta_is_bytes(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = old + b"\xff"
        assert isinstance(compute_delta(old, new), bytes)


# ---------------------------------------------------------------------------
# compute_delta / apply_delta — round-trips
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_append_to_end(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = old + _fill(0xBB, 64)
        assert _round_trip(old, new) == new

    def test_prepend_at_start(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = _fill(0xBB, 64) + old
        assert _round_trip(old, new) == new

    def test_replace_middle(self) -> None:
        head = _fill(0x01, _MIN_SIZE // 2)
        tail = _fill(0x03, _MIN_SIZE // 2)
        old = head + _fill(0x02, 128) + tail
        new = head + _fill(0xFF, 128) + tail
        assert _round_trip(old, new) == new

    def test_identical_content(self) -> None:
        data = _fill(0xCC, _MIN_SIZE)
        assert _round_trip(data, data) == data

    def test_completely_different_large_content(self) -> None:
        old = _fill(0x11, _MIN_SIZE)
        new = _fill(0x22, _MIN_SIZE)
        assert _round_trip(old, new) == new

    def test_random_source_append(self) -> None:
        old = os.urandom(4096)
        new = old + os.urandom(256)
        assert _round_trip(old, new) == new

    def test_shrink_content(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = old[: _MIN_SIZE // 2]
        assert _round_trip(old, new) == new

    def test_single_byte_change(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = bytearray(old)
        new[_MIN_SIZE // 2] = 0xFF
        new = bytes(new)
        assert _round_trip(old, new) == new

    def test_multiple_scattered_changes(self) -> None:
        old = _fill(0xAA, _MIN_SIZE * 4)
        new = bytearray(old)
        for i in range(0, len(new), _MIN_SIZE):
            new[i] ^= 0xFF
        assert _round_trip(old, bytes(new)) == bytes(new)


# ---------------------------------------------------------------------------
# NoDeltaFound
# ---------------------------------------------------------------------------

class TestNoDeltaFound:
    def test_tiny_unrelated_content(self) -> None:
        with pytest.raises(NoDeltaFound):
            compute_delta(b"hello", b"world")

    def test_empty_to_empty(self) -> None:
        # VCDIFF overhead exceeds the zero-byte target: NoDeltaFound expected.
        with pytest.raises(NoDeltaFound):
            compute_delta(b"", b"")

    def test_empty_source(self) -> None:
        # Empty old, small new: overhead > new_size → NoDeltaFound.
        with pytest.raises(NoDeltaFound):
            compute_delta(b"", b"hi")


# ---------------------------------------------------------------------------
# PatchError
# ---------------------------------------------------------------------------

class TestPatchError:
    def test_invalid_delta_bytes(self) -> None:
        with pytest.raises(PatchError):
            apply_delta(b"source", b"not a vcdiff stream")

    def test_truncated_delta(self) -> None:
        old = _fill(0xAA, _MIN_SIZE)
        new = old + _fill(0xBB, 64)
        delta = compute_delta(old, new)
        # xdelta3 returns empty bytes for a truncated-but-magic-valid stream;
        # apply_delta treats empty decode output as a PatchError.
        with pytest.raises(PatchError):
            apply_delta(old, delta[:5])

    def test_empty_delta_raises(self) -> None:
        with pytest.raises(PatchError):
            apply_delta(b"source", b"")

    # NOTE: apply_delta with a wrong source does NOT raise — VCDIFF carries no
    # source checksum.  Callers must verify source identity (e.g. rapidhash)
    # before calling apply_delta.
