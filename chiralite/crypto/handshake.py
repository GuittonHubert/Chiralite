from __future__ import annotations

import dataclasses
import os
import time
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding

_NONCE_SIZE = 32
_CHALLENGE_SIZE = 32
_SESSION_TOKEN_SIZE = 32
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


# ---------------------------------------------------------------------------
# Handshake result types
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ClientHandshakeResult:
    """Result returned to the client after a successful handshake."""
    codec: object          # PayloadCodec — typed as object to avoid circular import
    session_token: bytes
    server_cn: str


@dataclasses.dataclass(frozen=True)
class ServerHandshakeResult:
    """Result returned to the server after a successful handshake."""
    codec: object          # PayloadCodec
    session_token: bytes
    client_cn: str
    silo_id: UUID


# ---------------------------------------------------------------------------
# High-level async orchestrators
# ---------------------------------------------------------------------------

async def perform_client_handshake(
    framed: object,  # FramedConnection — typed as object to avoid circular import
    silo_id: UUID,
    client_cert: x509.Certificate,
    client_key: _PrivateKey,
    ca_cert: x509.Certificate,
) -> ClientHandshakeResult:
    """Drive the client side of the HELLO/CHALLENGE/RESPONSE/ACCEPT exchange.

    Sends HELLO, receives CHALLENGE, sends RESPONSE, receives ACCEPT.
    On any protocol violation receives AUTH_ERROR or raises HandshakeError.

    Args:
        framed:      A ``FramedConnection`` in plain (pre-activation) mode.
        silo_id:     The silo UUID to include in HELLO.
        client_cert: Client's X.509 certificate (CA-signed).
        client_key:  Client's private key matching ``client_cert``.
        ca_cert:     Trusted CA certificate used to verify the server cert.

    Returns:
        ClientHandshakeResult with an activated PayloadCodec.
    """
    # Import here to avoid module-level circular dependency
    from chiralite.crypto.certificates import get_cn, verify_chain
    from chiralite.crypto.payload import PayloadCodec
    from chiralite.crypto.session import EphemeralKey
    from chiralite.protocol.messages import (
        AcceptMsg, AuthErrorMsg, ChallengeMsg, HelloMsg, ResponseMsg,
    )

    nonce_c = generate_nonce()
    ecdh_c = EphemeralKey()
    client_cert_pem = client_cert.public_bytes(Encoding.PEM).decode()

    # Step 1: HELLO
    await framed.send_plain(HelloMsg(  # type: ignore[attr-defined]
        client_cert_pem=client_cert_pem,
        nonce_c=nonce_c,
        ts_ns=time.time_ns(),
        silo_id=silo_id,
    ))

    # Step 2: CHALLENGE
    msg = await framed.recv_plain()  # type: ignore[attr-defined]
    if isinstance(msg, AuthErrorMsg):
        raise HandshakeError(f"server rejected HELLO: {msg.reason}")
    if not isinstance(msg, ChallengeMsg):
        raise HandshakeError(f"expected CHALLENGE, got {type(msg).__name__}")

    try:
        server_cert = _load_cert_pem(msg.server_cert_pem)
        verify_chain(server_cert, ca_cert)
        server_cn = get_cn(server_cert)
    except Exception as exc:
        raise HandshakeError(f"server certificate rejected: {exc}") from exc

    nonce_s = msg.nonce_s
    challenge = msg.challenge
    sig_c = sign_challenge(challenge + nonce_s, client_key)

    # Step 3: RESPONSE
    await framed.send_plain(ResponseMsg(  # type: ignore[attr-defined]
        sig_c=sig_c,
        ecdh_pub_c=ecdh_c.public_bytes,
    ))

    # Step 4: ACCEPT
    msg2 = await framed.recv_plain()  # type: ignore[attr-defined]
    if isinstance(msg2, AuthErrorMsg):
        raise HandshakeError(f"server rejected RESPONSE: {msg2.reason}")
    if not isinstance(msg2, AcceptMsg):
        raise HandshakeError(f"expected ACCEPT, got {type(msg2).__name__}")

    try:
        server_pub = server_cert.public_key()
        if not isinstance(server_pub, (_PublicKey.__args__)):  # type: ignore[attr-defined]
            raise HandshakeError(f"unsupported server key type: {type(server_pub).__name__}")
        verify_signature(challenge + nonce_c, msg2.sig_s, server_pub)  # type: ignore[arg-type]
    except HandshakeError:
        raise
    except Exception as exc:
        raise HandshakeError(f"server signature verification failed: {exc}") from exc

    session_key = ecdh_c.derive_session_key(
        remote_public_bytes=msg2.ecdh_pub_s,
        nonce_c=nonce_c,
        nonce_s=nonce_s,
    )
    session_token = bytes(msg2.session_token)
    codec = PayloadCodec(session_key, session_token)
    return ClientHandshakeResult(codec=codec, session_token=session_token, server_cn=server_cn)


async def perform_server_handshake(
    framed: object,  # FramedConnection
    server_cert: x509.Certificate,
    server_key: _PrivateKey,
    ca_cert: x509.Certificate,
    allowed_silos: dict[str, set[UUID]],
) -> ServerHandshakeResult:
    """Drive the server side of the HELLO/CHALLENGE/RESPONSE/ACCEPT exchange.

    Receives HELLO, validates it, sends CHALLENGE, receives RESPONSE,
    validates the signature, sends ACCEPT.

    Args:
        framed:        A ``FramedConnection`` in plain mode.
        server_cert:   Server's X.509 certificate.
        server_key:    Server's private key.
        ca_cert:       Trusted CA used to verify the client cert.
        allowed_silos: ``{client_cn: {allowed silo UUIDs}}``.  Pass an empty
                       dict to allow any silo (useful in tests).

    Returns:
        ServerHandshakeResult with an activated PayloadCodec.

    Raises:
        HandshakeError: on any protocol or policy violation.  An AUTH_ERROR
            message is sent to the client before raising.
    """
    from chiralite.crypto.certificates import get_cn, verify_chain
    from chiralite.crypto.payload import PayloadCodec
    from chiralite.crypto.session import EphemeralKey
    from chiralite.protocol.messages import (
        AcceptMsg, AuthErrorMsg, ChallengeMsg, HelloMsg, ResponseMsg,
    )

    async def _reject(reason: str) -> None:
        try:
            await framed.send_plain(AuthErrorMsg(reason=reason))  # type: ignore[attr-defined]
        except Exception:
            pass

    # Step 1: HELLO
    try:
        hello_msg = await framed.recv_plain()  # type: ignore[attr-defined]
    except Exception as exc:
        raise HandshakeError(f"failed to receive HELLO: {exc}") from exc

    if not isinstance(hello_msg, HelloMsg):
        await _reject(f"expected HELLO, got {type(hello_msg).__name__}")
        raise HandshakeError(f"expected HELLO, got {type(hello_msg).__name__}")

    # Validate timestamp
    try:
        validate_hello_timestamp(hello_msg.ts_ns)
    except HandshakeError as exc:
        await _reject(str(exc))
        raise

    # Validate client certificate
    try:
        client_cert = _load_cert_pem(hello_msg.client_cert_pem)
        verify_chain(client_cert, ca_cert)
        client_cn = get_cn(client_cert)
    except Exception as exc:
        err = f"client certificate rejected: {exc}"
        await _reject(err)
        raise HandshakeError(err) from exc

    # Validate silo policy
    silo_id = hello_msg.silo_id
    if allowed_silos and silo_id not in allowed_silos.get(client_cn, set()):
        err = f"silo {silo_id} not allowed for CN={client_cn!r}"
        await _reject(err)
        raise HandshakeError(err)

    nonce_c = hello_msg.nonce_c
    nonce_s = generate_nonce()
    challenge = generate_challenge()
    ecdh_s = EphemeralKey()
    server_cert_pem = server_cert.public_bytes(Encoding.PEM).decode()

    # Step 2: CHALLENGE
    await framed.send_plain(ChallengeMsg(  # type: ignore[attr-defined]
        server_cert_pem=server_cert_pem,
        nonce_s=nonce_s,
        challenge=challenge,
    ))

    # Step 3: RESPONSE
    try:
        resp_msg = await framed.recv_plain()  # type: ignore[attr-defined]
    except Exception as exc:
        raise HandshakeError(f"failed to receive RESPONSE: {exc}") from exc

    if not isinstance(resp_msg, ResponseMsg):
        await _reject(f"expected RESPONSE, got {type(resp_msg).__name__}")
        raise HandshakeError(f"expected RESPONSE, got {type(resp_msg).__name__}")

    # Verify client signature: sign(challenge ‖ nonce_s, client_key)
    try:
        client_pub = client_cert.public_key()
        if not isinstance(client_pub, (_PublicKey.__args__)):  # type: ignore[attr-defined]
            raise HandshakeError(f"unsupported client key type: {type(client_pub).__name__}")
        verify_signature(challenge + nonce_s, resp_msg.sig_c, client_pub)  # type: ignore[arg-type]
    except HandshakeError as exc:
        await _reject(str(exc))
        raise

    # Generate session token and sign ACCEPT
    session_token = os.urandom(_SESSION_TOKEN_SIZE)
    sig_s = sign_challenge(challenge + nonce_c, server_key)

    # Step 4: ACCEPT
    await framed.send_plain(AcceptMsg(  # type: ignore[attr-defined]
        sig_s=sig_s,
        ecdh_pub_s=ecdh_s.public_bytes,
        session_token=session_token,
        silo_id_ack=silo_id,
    ))

    session_key = ecdh_s.derive_session_key(
        remote_public_bytes=bytes(resp_msg.ecdh_pub_c),
        nonce_c=nonce_c,
        nonce_s=nonce_s,
    )
    codec = PayloadCodec(session_key, session_token)
    return ServerHandshakeResult(
        codec=codec,
        session_token=session_token,
        client_cn=client_cn,
        silo_id=silo_id,
    )


def _load_cert_pem(pem: str) -> x509.Certificate:
    from chiralite.crypto.certificates import load_cert
    return load_cert(pem)
