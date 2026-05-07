"""Tests for crypto/handshake.py — adversarial inputs included."""
from __future__ import annotations

import os
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from chiralite.crypto.handshake import (
    HandshakeError,
    generate_challenge,
    generate_nonce,
    sign_challenge,
    validate_hello_timestamp,
    verify_signature,
)


class TestNonceAndChallenge:
    def test_nonce_length(self) -> None:
        assert len(generate_nonce()) == 32

    def test_challenge_length(self) -> None:
        assert len(generate_challenge()) == 32

    def test_nonces_are_unique(self) -> None:
        assert len({generate_nonce() for _ in range(200)}) == 200


class TestSignAndVerify:
    def test_ed25519_roundtrip(
        self, client_private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        data = os.urandom(64)
        sig = sign_challenge(data, client_private_key)
        verify_signature(data, sig, client_private_key.public_key())

    def test_ecdsa_roundtrip(
        self, server_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        data = os.urandom(64)
        sig = sign_challenge(data, server_private_key)
        verify_signature(data, sig, server_private_key.public_key())

    def test_tampered_data_rejected_ed25519(
        self, client_private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        sig = sign_challenge(b"original", client_private_key)
        with pytest.raises(HandshakeError):
            verify_signature(b"tampered", sig, client_private_key.public_key())

    def test_tampered_data_rejected_ecdsa(
        self, server_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        sig = sign_challenge(b"original", server_private_key)
        with pytest.raises(HandshakeError):
            verify_signature(b"tampered", sig, server_private_key.public_key())

    def test_wrong_key_rejected(self) -> None:
        key_a = ed25519.Ed25519PrivateKey.generate()
        key_b = ed25519.Ed25519PrivateKey.generate()
        sig = sign_challenge(b"data", key_a)
        with pytest.raises(HandshakeError):
            verify_signature(b"data", sig, key_b.public_key())

    def test_corrupted_signature_rejected(
        self, client_private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        sig = bytearray(sign_challenge(b"challenge", client_private_key))
        sig[0] ^= 0xFF
        with pytest.raises(HandshakeError):
            verify_signature(b"challenge", bytes(sig), client_private_key.public_key())

    def test_empty_signature_rejected(
        self, client_private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        with pytest.raises(HandshakeError):
            verify_signature(b"data", b"", client_private_key.public_key())


class TestTimestampValidation:
    def test_current_timestamp_accepted(self) -> None:
        validate_hello_timestamp(time.time_ns())

    def test_10s_old_accepted(self) -> None:
        validate_hello_timestamp(time.time_ns() - 10_000_000_000)

    def test_60s_old_rejected(self) -> None:
        with pytest.raises(HandshakeError):
            validate_hello_timestamp(time.time_ns() - 60_000_000_000)

    def test_60s_future_rejected(self) -> None:
        with pytest.raises(HandshakeError):
            validate_hello_timestamp(time.time_ns() + 60_000_000_000)

    def test_custom_tolerance_reject(self) -> None:
        ts = time.time_ns() - 5_000_000_000  # 5 s ago
        with pytest.raises(HandshakeError):
            validate_hello_timestamp(ts, tolerance_ns=3_000_000_000)  # 3 s window

    def test_custom_tolerance_accept(self) -> None:
        ts = time.time_ns() - 2_000_000_000  # 2 s ago
        validate_hello_timestamp(ts, tolerance_ns=5_000_000_000)  # 5 s window


class TestHandshakeProtocol:
    def test_client_response_payload(
        self, client_private_key: ed25519.Ed25519PrivateKey
    ) -> None:
        """Client signs challenge‖nonce_s for RESPONSE; server verifies."""
        challenge = generate_challenge()
        nonce_s = generate_nonce()
        payload = challenge + nonce_s
        sig = sign_challenge(payload, client_private_key)
        verify_signature(payload, sig, client_private_key.public_key())

    def test_server_accept_payload(
        self, server_private_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """Server signs challenge‖nonce_c for ACCEPT; client verifies."""
        challenge = generate_challenge()
        nonce_c = generate_nonce()
        payload = challenge + nonce_c
        sig = sign_challenge(payload, server_private_key)
        verify_signature(payload, sig, server_private_key.public_key())

    def test_cross_payload_rejected(
        self,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """Signature on challenge‖nonce_s must not verify against challenge‖nonce_c."""
        challenge = generate_challenge()
        nonce_s = generate_nonce()
        nonce_c = generate_nonce()
        sig = sign_challenge(challenge + nonce_s, client_private_key)
        with pytest.raises(HandshakeError):
            verify_signature(challenge + nonce_c, sig, client_private_key.public_key())
