"""Tests for chiralite/hash.py — CFFI rapidhash wrapper."""
from __future__ import annotations

import struct

import pytest

from chiralite.hash import RapidHash, new, rapidhash


class TestRapidhashFunction:
    def test_returns_int(self) -> None:
        assert isinstance(rapidhash(b"hello"), int)

    def test_deterministic(self) -> None:
        assert rapidhash(b"chiralite") == rapidhash(b"chiralite")

    def test_different_inputs_differ(self) -> None:
        assert rapidhash(b"foo") != rapidhash(b"bar")

    def test_empty_input(self) -> None:
        h = rapidhash(b"")
        assert isinstance(h, int)

    def test_seed_changes_output(self) -> None:
        assert rapidhash(b"data", seed=1) != rapidhash(b"data", seed=0)

    def test_seed_deterministic(self) -> None:
        assert rapidhash(b"data", seed=42) == rapidhash(b"data", seed=42)

    def test_uint64_range(self) -> None:
        h = rapidhash(b"test")
        assert 0 <= h < 2**64

    def test_accepts_bytearray(self) -> None:
        assert rapidhash(bytearray(b"hello")) == rapidhash(b"hello")

    def test_accepts_memoryview(self) -> None:
        buf = b"hello world"
        assert rapidhash(memoryview(buf)) == rapidhash(buf)

    def test_large_input(self) -> None:
        data = b"x" * 1_000_000
        h = rapidhash(data)
        assert 0 <= h < 2**64


class TestRapidHashObject:
    def test_new_equivalent_to_function(self) -> None:
        obj = new(b"hello")
        assert obj.intdigest() == rapidhash(b"hello")

    def test_update_accumulates(self) -> None:
        obj = new()
        obj.update(b"hel")
        obj.update(b"lo")
        assert obj.intdigest() == rapidhash(b"hello")

    def test_digest_is_8_bytes_le(self) -> None:
        obj = new(b"test")
        d = obj.digest()
        assert len(d) == 8
        assert struct.unpack("<Q", d)[0] == rapidhash(b"test")

    def test_hexdigest_is_16_chars(self) -> None:
        h = new(b"test").hexdigest()
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_copy_is_independent(self) -> None:
        a = new(b"hello")
        b = a.copy()
        b.update(b" world")
        assert a.intdigest() == rapidhash(b"hello")
        assert b.intdigest() == rapidhash(b"hello world")

    def test_name_and_sizes(self) -> None:
        obj = new()
        assert obj.name == "rapidhash"
        assert obj.digest_size == 8
        assert obj.block_size == 64
