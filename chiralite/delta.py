"""VCDIFF binary delta using xdelta3 (RFC 3284).

``compute_delta`` and ``apply_delta`` are thin wrappers around the xdelta3
C library, which produces and consumes standards-compliant VCDIFF streams
(RFC 3284, magic ``\\xD6\\xC3\\xC4\\x00``).

Note: VCDIFF does not embed a source checksum.  Callers that need
source-identity verification should compare ``rapidhash(old)`` out-of-band
before calling ``apply_delta``.
"""
from __future__ import annotations

import xdelta3
from xdelta3 import NoDeltaFound  # re-export: raised when delta ≥ len(new)

__all__ = ["NoDeltaFound", "PatchError", "compute_delta", "apply_delta"]

# VCDIFF magic (RFC 3284 §4.1)
VCDIFF_MAGIC = b"\xd6\xc3\xc4"


class PatchError(Exception):
    """Raised when a VCDIFF delta cannot be applied to the given source."""


def compute_delta(old: bytes, new: bytes) -> bytes:
    """Return a VCDIFF (RFC 3284) delta that transforms *old* into *new*.

    Raises:
        NoDeltaFound: when the encoded delta would be larger than *new*
            (e.g. completely unrelated content).  The caller should fall
            back to a full-content transfer in that case.
    """
    return xdelta3.encode(old, new)


def apply_delta(old: bytes, delta: bytes) -> bytes:
    """Reconstruct the target content by applying *delta* to *old*.

    Raises:
        PatchError: if *delta* is not a valid VCDIFF stream or cannot be
            decoded against *old*.

    Note: VCDIFF carries no source checksum, so a wrong *old* silently
    produces garbage output.  Verify source identity with ``rapidhash``
    before calling.
    """
    if not delta:
        raise PatchError("empty delta")
    if delta[:3] != VCDIFF_MAGIC:
        raise PatchError("not a VCDIFF stream")
    try:
        result = xdelta3.decode(old, delta)
    except (xdelta3.XDeltaError, Exception) as exc:
        raise PatchError(str(exc)) from exc
    if not result:
        raise PatchError("decode produced empty output — delta is likely truncated")
    return result
