"""
CFFI out-of-line builder for the rapidhash C extension.

Re-compile manually:
    python -m chiralite._rapidhash_build
"""
from __future__ import annotations

import os

from cffi import FFI

# Non-inline wrappers expose the static-inline rapidhash symbols.
# CFFI_SOURCE is embedded here so that hash.py can trigger a build without
# a separate subprocess.
_VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor")

ffi = FFI()

ffi.cdef("""
uint64_t rh_call(const void *key, size_t len);
uint64_t rh_withSeed_call(const void *key, size_t len, uint64_t seed);
""")

ffi.set_source(
    "_rapidhash_c",
    r"""
#include "rapidhash.h"

uint64_t rh_call(const void *key, size_t len) {
    return rapidhash(key, len);
}

uint64_t rh_withSeed_call(const void *key, size_t len, uint64_t seed) {
    return rapidhash_withSeed(key, len, seed);
}
""",
    include_dirs=[_VENDOR],
    extra_compile_args=["-O3", "-std=c11"],
)

if __name__ == "__main__":
    out = os.path.dirname(os.path.abspath(__file__))
    ffi.compile(tmpdir=out, verbose=True)
