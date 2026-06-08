"""Tests for chiralite/crypto/http_payload.py — stateless GCM codec."""
from __future__ import annotations

import os
import time

import pytest

from chiralite.crypto.http_payload import HttpPayloadCodec, SeenNonces
from chiralite.crypto.payload import FrameError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _codec(key: bytes | None = None, token: bytes | None = None) -> HttpPayloadCodec:
    return HttpPayloadCodec(
        key=key or os.urandom(32),
        session_token=token or os.urandom(32),
    )


# ---------------------------------------------------------------------------
# HttpPayloadCodec — basic round-trips
# ---------------------------------------------------------------------------

class TestHttpPayloadCodecRoundTrip:
    def test_empty_plaintext(self) -> None:
        c = _codec()
        assert c.decrypt(c.encrypt(b"")) == b""

    def test_short_plaintext(self) -> None:
        c = _codec()
        assert c.decrypt(c.encrypt(b"hello")) == b"hello"

    def test_binary_payload(self) -> None:
        c = _codec()
        data = os.urandom(4096)
        assert c.decrypt(c.encrypt(data)) == data

    def test_each_call_different_nonce(self) -> None:
        c = _codec()
        f1 = c.encrypt(b"x")
        f2 = c.encrypt(b"x")
        assert f1[:12] != f2[:12], "two calls should produce different nonces"

    def test_different_key_decryption_fails(self) -> None:
        token = os.urandom(32)
        c1 = HttpPayloadCodec(key=os.urandom(32), session_token=token)
        c2 = HttpPayloadCodec(key=os.urandom(32), session_token=token)
        with pytest.raises(FrameError):
            c2.decrypt(c1.encrypt(b"secret"))

    def test_different_token_decryption_fails(self) -> None:
        key = os.urandom(32)
        c1 = HttpPayloadCodec(key=key, session_token=os.urandom(32))
        c2 = HttpPayloadCodec(key=key, session_token=os.urandom(32))
        with pytest.raises(FrameError):
            c2.decrypt(c1.encrypt(b"secret"))

    def test_tampered_ciphertext_fails(self) -> None:
        c = _codec()
        frame = bytearray(c.encrypt(b"data"))
        frame[-1] ^= 0xFF
        with pytest.raises(FrameError):
            c.decrypt(bytes(frame))

    def test_tampered_nonce_fails(self) -> None:
        c = _codec()
        frame = bytearray(c.encrypt(b"data"))
        frame[0] ^= 0xFF
        with pytest.raises(FrameError):
            c.decrypt(bytes(frame))

    def test_frame_too_short_raises(self) -> None:
        c = _codec()
        with pytest.raises(FrameError):
            c.decrypt(b"\x00" * 10)

    def test_invalid_key_length_raises(self) -> None:
        with pytest.raises(ValueError):
            HttpPayloadCodec(key=b"too_short", session_token=os.urandom(32))


# ---------------------------------------------------------------------------
# HttpPayloadCodec — statelessness: many independent instances same key/token
# ---------------------------------------------------------------------------

class TestStateless:
    def test_multiple_instances_share_key(self) -> None:
        key = os.urandom(32)
        token = os.urandom(32)
        enc = HttpPayloadCodec(key=key, session_token=token)
        dec = HttpPayloadCodec(key=key, session_token=token)
        data = b"shared session message"
        assert dec.decrypt(enc.encrypt(data)) == data

    def test_high_volume_no_nonce_collision(self) -> None:
        c = _codec()
        nonces = {c.encrypt(b"x")[:12] for _ in range(1000)}
        # Probability of collision in 1000 12-byte nonces is negligible
        assert len(nonces) == 1000


# ---------------------------------------------------------------------------
# SeenNonces
# ---------------------------------------------------------------------------

class TestSeenNonces:
    def test_first_nonce_accepted(self) -> None:
        s = SeenNonces()
        s.check_and_record(b"nonce1")  # must not raise

    def test_replay_raises(self) -> None:
        s = SeenNonces()
        n = os.urandom(12)
        s.check_and_record(n)
        with pytest.raises(FrameError, match="replayed"):
            s.check_and_record(n)

    def test_different_nonces_accepted(self) -> None:
        s = SeenNonces()
        for _ in range(100):
            s.check_and_record(os.urandom(12))

    def test_max_size_evicts_oldest(self) -> None:
        s = SeenNonces(max_size=3)
        nonces = [os.urandom(12) for _ in range(4)]
        for n in nonces[:3]:
            s.check_and_record(n)
        # Inserting a 4th evicts the first
        s.check_and_record(nonces[3])
        # The first nonce was evicted and can be re-inserted without error
        s.check_and_record(nonces[0])

    def test_expired_nonce_reaccepted(self) -> None:
        s = SeenNonces(ttl_seconds=0.05)
        n = os.urandom(12)
        s.check_and_record(n)
        time.sleep(0.1)
        # After TTL expiry the nonce should be purgeable and re-accepted
        s.check_and_record(n)
