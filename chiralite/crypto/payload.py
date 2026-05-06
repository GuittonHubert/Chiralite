from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SEQ_SIZE = 8       # uint64 BE
_NONCE_SIZE = 12    # 96-bit
_GCM_TAG_SIZE = 16
_MIN_FRAME_SIZE = _SEQ_SIZE + _NONCE_SIZE + _GCM_TAG_SIZE


class FrameError(Exception):
    """Raised on malformed frames or GCM authentication failures."""


class ReplayError(FrameError):
    """Raised when the seq number does not match the expected counter."""


class PayloadCodec:
    """
    Stateful AES-256-GCM codec for one WebSocket session.

    Frame wire format (binary):
        seq     (8 B, uint64 BE)
        nonce   (12 B, = seq zero-padded to 96 bits)
        ciphertext + GCM tag (16 B)

    AAD = session_token ‖ seq_bytes

    Maintains independent send / receive sequence counters so the same
    instance can be used for both directions of an echo-style test.
    In production, use separate instances per direction.
    """

    def __init__(self, key: bytes, session_token: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"session key must be 32 bytes, got {len(key)}")
        self._aesgcm = AESGCM(key)
        self._session_token = session_token
        self._send_seq = 0
        self._recv_seq = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt and frame plaintext as a single binary WebSocket message."""
        seq = self._send_seq
        self._send_seq += 1
        seq_bytes = struct.pack(">Q", seq)
        nonce = seq.to_bytes(_NONCE_SIZE, "big")
        aad = self._session_token + seq_bytes
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return seq_bytes + nonce + ciphertext

    def decrypt(self, frame: bytes) -> bytes:
        """Verify and decrypt a binary WebSocket frame. Raises on any anomaly."""
        if len(frame) < _MIN_FRAME_SIZE:
            raise FrameError(f"frame too short: {len(frame)} < {_MIN_FRAME_SIZE}")

        seq_bytes = frame[:_SEQ_SIZE]
        nonce = frame[_SEQ_SIZE : _SEQ_SIZE + _NONCE_SIZE]
        ciphertext = frame[_SEQ_SIZE + _NONCE_SIZE :]

        (seq,) = struct.unpack(">Q", seq_bytes)
        if seq != self._recv_seq:
            raise ReplayError(f"expected seq {self._recv_seq}, got {seq}")

        expected_nonce = seq.to_bytes(_NONCE_SIZE, "big")
        if nonce != expected_nonce:
            raise FrameError(f"nonce does not match seq {seq}")

        aad = self._session_token + seq_bytes
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise FrameError("GCM authentication failed") from exc

        self._recv_seq += 1
        return plaintext
