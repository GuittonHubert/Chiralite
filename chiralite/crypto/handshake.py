from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

_NONCE_SIZE = 32
_CHALLENGE_SIZE = 32
_TIMESTAMP_TOLERANCE_NS = 30_000_000_000  # 30 seconds in nanoseconds

# Supported key types for challenge signing
_PrivateKey = ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey
_PublicKey = ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey


class HandshakeError(Exception):
    """Raised on handshake protocol violations (bad sig, stale timestamp, …)."""


def generate_nonce() -> bytes:
    """Return 32 cryptographically random bytes for use as a handshake nonce."""
    return os.urandom(_NONCE_SIZE)


def generate_challenge() -> bytes:
    """Return 32 cryptographically random bytes for use as a challenge."""
    return os.urandom(_CHALLENGE_SIZE)


def sign_challenge(data: bytes, private_key: _PrivateKey) -> bytes:
    """
    Sign data with an Ed25519 or ECDSA P-256 key, as used in
    RESPONSE (client signs challenge‖nonce_s) and
    ACCEPT  (server signs challenge‖nonce_c).
    """
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(data)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise HandshakeError(f"unsupported private key type: {type(private_key).__name__}")


def verify_signature(data: bytes, signature: bytes, public_key: _PublicKey) -> None:
    """
    Verify a signature produced by sign_challenge.
    Raises HandshakeError if the signature is invalid or the key type is unsupported.
    """
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise HandshakeError(f"unsupported public key type: {type(public_key).__name__}")
    except HandshakeError:
        raise
    except Exception as exc:
        raise HandshakeError("signature verification failed") from exc


def validate_hello_timestamp(
    ts_ns: int,
    *,
    tolerance_ns: int = _TIMESTAMP_TOLERANCE_NS,
) -> None:
    """
    Reject a HELLO whose timestamp deviates more than tolerance_ns from the server clock.
    Default tolerance is 30 seconds (as specified in the protocol).
    """
    now_ns = time.time_ns()
    drift_ns = abs(now_ns - ts_ns)
    if drift_ns > tolerance_ns:
        raise HandshakeError(
            f"HELLO timestamp rejected: drift {drift_ns // 1_000_000} ms"
            f" > {tolerance_ns // 1_000_000} ms tolerance"
        )
