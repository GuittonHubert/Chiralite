"""
Rapidhash (64-bit) CFFI wrapper with hashlib-compatible API.

Backed by the official C implementation (https://github.com/Nicoshev/rapidhash).
The C extension is compiled automatically on first import if it is absent.

Typical use::

    from chiralite.hash import rapidhash, new

    h: int = rapidhash(data)          # fastest — returns raw uint64
    obj = new(data)                    # hashlib-style object
    obj.update(more_data)
    print(obj.hexdigest())            # 16-char hex string
"""
from __future__ import annotations

import os
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cffi import FFI as _FFI


def _load_lib() -> tuple[object, object]:
    """Import the compiled CFFI extension, building it on first use if absent."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        from chiralite._rapidhash_c import ffi, lib  # type: ignore[import-untyped]

        return lib, ffi
    except ImportError:
        from chiralite._rapidhash_build import ffi as build_ffi  # type: ignore[import-untyped]

        build_ffi.compile(tmpdir=pkg_dir, verbose=False)
        from chiralite._rapidhash_c import ffi, lib  # type: ignore[import-untyped]

        return lib, ffi


_lib, _ffi = _load_lib()


def rapidhash(data: bytes | bytearray | memoryview, seed: int = 0) -> int:
    """
    Compute the rapidhash of data and return a uint64 integer.

    This is the primary use-site function for the sync index and wire protocol.
    ~10 GB/s throughput; safe to call on the event-loop hot path.
    """
    buf: bytes = bytes(data) if not isinstance(data, bytes) else data
    if seed == 0:
        return int(_lib.rh_call(buf, len(buf)))
    return int(_lib.rh_withSeed_call(buf, len(buf), seed))


class RapidHash:
    """
    Hashlib-compatible rapidhash digest object.

    Because rapidhash is not a Merkle–Damgård construction, update() buffers
    all data and the hash is computed in one pass at digest() time.
    """

    name = "rapidhash"
    digest_size = 8
    block_size = 64  # nominal; rapidhash has no fixed block structure

    def __init__(
        self,
        data: bytes | bytearray | memoryview = b"",
        seed: int = 0,
    ) -> None:
        self._buf = bytearray(data)
        self._seed = seed

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Append data to the internal buffer."""
        if isinstance(data, memoryview):
            self._buf += bytes(data)
        else:
            self._buf += data

    def digest(self) -> bytes:
        """Return the 8-byte little-endian uint64 digest."""
        return struct.pack("<Q", rapidhash(bytes(self._buf), self._seed))

    def hexdigest(self) -> str:
        """Return the 16-character lowercase hexadecimal digest."""
        return self.digest().hex()

    def intdigest(self) -> int:
        """Return the raw uint64 digest (most efficient for index comparisons)."""
        return rapidhash(bytes(self._buf), self._seed)

    def copy(self) -> "RapidHash":
        obj = RapidHash(seed=self._seed)
        obj._buf = bytearray(self._buf)
        return obj


def new(
    data: bytes | bytearray | memoryview = b"",
    seed: int = 0,
) -> RapidHash:
    """Create a new RapidHash object (hashlib.new-style entry point)."""
    return RapidHash(data, seed)
