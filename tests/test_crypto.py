"""Tests for crypto/certificates.py, crypto/session.py, and crypto/payload.py."""
from __future__ import annotations

import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from chiralite.crypto.certificates import (
    CertificateError,
    days_until_expiry,
    get_cn,
    load_cert,
    verify_chain,
)
from chiralite.crypto.payload import FrameError, PayloadCodec, ReplayError
from chiralite.crypto.session import EphemeralKey, SessionError


# ── certificates ──────────────────────────────────────────────────────────────

class TestLoadCert:
    def test_from_bytes(self, client_cert: x509.Certificate) -> None:
        pem = client_cert.public_bytes(Encoding.PEM)
        assert load_cert(pem).serial_number == client_cert.serial_number

    def test_from_str(self, client_cert: x509.Certificate) -> None:
        pem = client_cert.public_bytes(Encoding.PEM).decode()
        assert load_cert(pem).serial_number == client_cert.serial_number


class TestGetCN:
    def test_ed25519_cert(self, client_cert: x509.Certificate, client_cn: str) -> None:
        assert get_cn(client_cert) == client_cn

    def test_ecdsa_cert(self, server_cert: x509.Certificate) -> None:
        assert get_cn(server_cert) == "test-server"


class TestVerifyChain:
    def test_valid_ed25519_client(
        self, client_cert: x509.Certificate, ca_cert: x509.Certificate
    ) -> None:
        verify_chain(client_cert, ca_cert)  # must not raise

    def test_valid_ecdsa_server(
        self, server_cert: x509.Certificate, ca_cert: x509.Certificate
    ) -> None:
        verify_chain(server_cert, ca_cert)  # must not raise

    def test_wrong_ca_raises(
        self, client_cert: x509.Certificate, other_ca_cert: x509.Certificate
    ) -> None:
        with pytest.raises(CertificateError):
            verify_chain(client_cert, other_ca_cert)

    def test_expired_raises(
        self, expired_cert: x509.Certificate, ca_cert: x509.Certificate
    ) -> None:
        with pytest.raises(CertificateError, match="expired"):
            verify_chain(expired_cert, ca_cert)

    def test_days_until_expiry(self, client_cert: x509.Certificate) -> None:
        days = days_until_expiry(client_cert)
        assert 85 <= days <= 90


# ── session ───────────────────────────────────────────────────────────────────

class TestEphemeralKey:
    def test_public_key_is_32_bytes(self) -> None:
        assert len(EphemeralKey().public_bytes) == 32

    def test_two_keys_differ(self) -> None:
        assert EphemeralKey().public_bytes != EphemeralKey().public_bytes

    def test_ecdh_symmetric(self) -> None:
        nonce_c, nonce_s = os.urandom(32), os.urandom(32)
        a, b = EphemeralKey(), EphemeralKey()
        key_a = a.derive_session_key(b.public_bytes, nonce_c, nonce_s)
        key_b = b.derive_session_key(a.public_bytes, nonce_c, nonce_s)
        assert key_a == key_b
        assert len(key_a) == 32

    def test_different_nonces_produce_different_keys(self) -> None:
        # Use two fresh pairs so private keys aren't consumed
        a1, b1 = EphemeralKey(), EphemeralKey()
        a2, b2 = EphemeralKey(), EphemeralKey()
        key1 = a1.derive_session_key(b1.public_bytes, os.urandom(32), os.urandom(32))
        key2 = a2.derive_session_key(b2.public_bytes, os.urandom(32), os.urandom(32))
        assert key1 != key2

    def test_reuse_raises(self) -> None:
        a, b = EphemeralKey(), EphemeralKey()
        a.derive_session_key(b.public_bytes, os.urandom(32), os.urandom(32))
        with pytest.raises(SessionError, match="consumed"):
            a.derive_session_key(b.public_bytes, os.urandom(32), os.urandom(32))

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(SessionError):
            EphemeralKey().derive_session_key(b"\x00" * 16, os.urandom(32), os.urandom(32))


# ── payload ───────────────────────────────────────────────────────────────────

class TestPayloadCodec:
    def test_roundtrip(self, session_key: bytes, session_token: bytes) -> None:
        enc = PayloadCodec(session_key, session_token)
        dec = PayloadCodec(session_key, session_token)
        msg = b'{"type":"ping"}'
        assert dec.decrypt(enc.encrypt(msg)) == msg

    def test_multiple_messages_in_order(
        self, session_key: bytes, session_token: bytes
    ) -> None:
        enc = PayloadCodec(session_key, session_token)
        dec = PayloadCodec(session_key, session_token)
        msgs = [f"msg-{i}".encode() for i in range(8)]
        frames = [enc.encrypt(m) for m in msgs]
        assert [dec.decrypt(f) for f in frames] == msgs

    def test_replay_rejected(self, session_key: bytes, session_token: bytes) -> None:
        enc = PayloadCodec(session_key, session_token)
        dec = PayloadCodec(session_key, session_token)
        frame = enc.encrypt(b"hello")
        dec.decrypt(frame)
        with pytest.raises(ReplayError):
            dec.decrypt(frame)

    def test_out_of_order_rejected(
        self, session_key: bytes, session_token: bytes
    ) -> None:
        enc = PayloadCodec(session_key, session_token)
        dec = PayloadCodec(session_key, session_token)
        enc.encrypt(b"first")   # seq=0, discard
        frame1 = enc.encrypt(b"second")  # seq=1
        with pytest.raises(ReplayError):
            dec.decrypt(frame1)  # expected seq=0

    def test_frame_too_short(self, session_key: bytes, session_token: bytes) -> None:
        dec = PayloadCodec(session_key, session_token)
        with pytest.raises(FrameError):
            dec.decrypt(b"\x00" * 10)

    def test_corrupted_tag(self, session_key: bytes, session_token: bytes) -> None:
        enc = PayloadCodec(session_key, session_token)
        dec = PayloadCodec(session_key, session_token)
        frame = bytearray(enc.encrypt(b"secret"))
        frame[-1] ^= 0xFF
        with pytest.raises(FrameError):
            dec.decrypt(bytes(frame))

    def test_wrong_key_rejected(self, session_token: bytes) -> None:
        enc = PayloadCodec(os.urandom(32), session_token)
        dec = PayloadCodec(os.urandom(32), session_token)
        with pytest.raises(FrameError):
            dec.decrypt(enc.encrypt(b"hello"))

    def test_invalid_key_length(self, session_token: bytes) -> None:
        with pytest.raises(ValueError):
            PayloadCodec(b"\x00" * 16, session_token)
