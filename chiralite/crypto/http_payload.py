"""Stateless AES-256-GCM codec for HTTP-based transport.

Unlike ``PayloadCodec`` (which uses a monotonic sequence counter and requires
an ordered persistent stream), this codec generates a fresh random nonce per
message and is safe to use over independent HTTP requests.

Frame wire format:
    nonce       (12 B, random per message)
    ciphertext  + GCM tag (16 B)

AAD = session_token ‖ nonce

Replay protection is not built into the codec itself.  Callers that need
server-side replay detection should use ``SeenNonces``.
"""
from __future__ import annotations

import os
import time
from collections import OrderedDict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from chiralite.crypto.payload import FrameError

__all__ = ["HttpPayloadCodec", "SeenNonces"]

_NONCE_SIZE = 12
_GCM_TAG_SIZE = 16
_MIN_FRAME_SIZE = _NONCE_SIZE + _GCM_TAG_SIZE


class SeenNonces:
    """Bounded LRU nonce-seen set for server-side replay protection.

    Entries expire after *ttl_seconds*.  The set is bounded to *max_size*
    entries; the oldest entry is evicted when the bound is reached.

    Thread-safety: not thread-safe; designed for use within a single asyncio
    event loop.
    """

    def __init__(
        self,
        ttl_seconds: float = 300.0,
        max_size: int = 10_000,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._store: OrderedDict[bytes, float] = OrderedDict()  # nonce → expiry

    def check_and_record(self, nonce: bytes) -> None:
        """Record *nonce* or raise ``FrameError`` if it was already seen.

        Expired entries are pruned on each call.
        """
        now = time.monotonic()

        # Prune expired entries
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            del self._store[k]

        if nonce in self._store:
            raise FrameError("replayed nonce")

        if len(self._store) >= self._max_size:
            self._store.popitem(last=False)

        self._store[nonce] = now + self._ttl


class HttpPayloadCodec:
    """Stateless AES-256-GCM codec for HTTP requests.

    Args:
        key:           32-byte session key (from X25519 ECDH + HKDF handshake).
        session_token: 32-byte token included in the AAD of every frame.
    """

    def __init__(self, key: bytes, session_token: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"session key must be 32 bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)
        self._session_token = session_token

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* and return ``nonce ‖ ciphertext+tag``."""
        nonce = os.urandom(_NONCE_SIZE)
        aad = self._session_token + nonce
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    def decrypt(self, frame: bytes) -> bytes:
        """Decrypt and authenticate *frame*.

        Raises:
            FrameError: if the frame is too short or GCM authentication fails.
        """
        if len(frame) < _MIN_FRAME_SIZE:
            raise FrameError(f"frame too short: {len(frame)} < {_MIN_FRAME_SIZE}")
        nonce = frame[:_NONCE_SIZE]
        ciphertext = frame[_NONCE_SIZE:]
        aad = self._session_token + nonce
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise FrameError("GCM authentication failed") from exc
