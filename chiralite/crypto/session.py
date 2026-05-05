from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_SESSION_KEY_LENGTH = 32
_HKDF_INFO = b"chiralite-session-v1"


class SessionError(Exception):
    """Raised on session key derivation failures."""


class EphemeralKey:
    """
    X25519 ephemeral key pair for a single handshake.
    Intended for one-time use: derive_session_key zeroes the private key on first call.
    """

    def __init__(self) -> None:
        self._private: X25519PrivateKey | None = X25519PrivateKey.generate()
        self.public_bytes: bytes = self._private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def derive_session_key(
        self,
        remote_public_bytes: bytes,
        nonce_c: bytes,
        nonce_s: bytes,
    ) -> bytes:
        """
        Perform X25519 ECDH and derive a 256-bit session key via
        HKDF-SHA256(shared_secret, salt=nonce_c‖nonce_s, info="chiralite-session-v1").

        Raises SessionError on invalid remote key or all-zero shared secret
        (low-order point / small subgroup attack).
        """
        if self._private is None:
            raise SessionError("ephemeral key already consumed")
        if len(remote_public_bytes) != 32:
            raise SessionError(
                f"X25519 public key must be 32 bytes, got {len(remote_public_bytes)}"
            )
        try:
            remote_pub = X25519PublicKey.from_public_bytes(remote_public_bytes)
        except Exception as exc:
            raise SessionError(f"invalid remote public key: {exc}") from exc

        shared_secret = self._private.exchange(remote_pub)
        self._private = None  # consume key — prevent reuse

        if shared_secret == b"\x00" * 32:
            raise SessionError("X25519 exchange yielded all-zero shared secret")

        hkdf = HKDF(
            algorithm=SHA256(),
            length=_SESSION_KEY_LENGTH,
            salt=nonce_c + nonce_s,
            info=_HKDF_INFO,
        )
        return hkdf.derive(shared_secret)
