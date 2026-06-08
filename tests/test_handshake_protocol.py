"""Tests for the full HELLO/CHALLENGE/RESPONSE/ACCEPT protocol exchange."""
from __future__ import annotations

import asyncio
import uuid
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from chiralite.crypto.handshake import (
    HandshakeError,
    perform_client_handshake,
    perform_server_handshake,
)
from chiralite.crypto.payload import PayloadCodec
from chiralite.protocol.messages import PingMsg, PongMsg
from conftest import make_pipe

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_SILO_ID = UUID("550e8400-e29b-41d4-a716-446655440000")

# allowed_silos that permits any silo for any CN (used in happy-path tests)
_ANY_SILO: dict[str, set[UUID]] = {}


def _run_handshake(
    client_cert: x509.Certificate,
    client_key: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
    server_cert: x509.Certificate,
    server_key: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    *,
    silo_id: UUID = _SILO_ID,
    allowed_silos: dict[str, set[UUID]] | None = None,
    client_ca: x509.Certificate | None = None,
    server_ca: x509.Certificate | None = None,
) -> tuple[object, object]:
    """Run client + server handshakes concurrently, return (client_result, server_result)."""
    c_framed, s_framed = make_pipe()
    client_ca = client_ca or ca_cert
    server_ca = server_ca or ca_cert
    silos = allowed_silos if allowed_silos is not None else _ANY_SILO

    async def _run() -> tuple[object, object]:
        c_task = asyncio.create_task(
            perform_client_handshake(c_framed, silo_id, client_cert, client_key, server_ca)
        )
        s_task = asyncio.create_task(
            perform_server_handshake(s_framed, server_cert, server_key, client_ca, silos)
        )
        return await asyncio.gather(c_task, s_task)

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# Happy-path exchange
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_handshake_completes(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        client_res, server_res = _run_handshake(
            client_cert, client_private_key, server_cert, server_private_key, ca_cert
        )
        assert client_res is not None
        assert server_res is not None

    def test_client_result_has_server_cn(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        client_res, _ = _run_handshake(
            client_cert, client_private_key, server_cert, server_private_key, ca_cert
        )
        assert client_res.server_cn == "test-server"

    def test_server_result_has_client_cn(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        _, server_res = _run_handshake(
            client_cert, client_private_key, server_cert, server_private_key, ca_cert
        )
        assert server_res.client_cn == "test-client"

    def test_server_result_has_silo_id(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        _, server_res = _run_handshake(
            client_cert, client_private_key, server_cert, server_private_key, ca_cert,
            silo_id=_SILO_ID,
        )
        assert server_res.silo_id == _SILO_ID

    def test_session_tokens_match(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        client_res, server_res = _run_handshake(
            client_cert, client_private_key, server_cert, server_private_key, ca_cert
        )
        assert client_res.session_token == server_res.session_token

    def test_both_derive_same_session_key(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """Client and server can exchange encrypted messages after handshake."""
        c_framed, s_framed = make_pipe()
        silos: dict[str, set[UUID]] = {}

        async def _exchange() -> None:
            c_task = asyncio.create_task(
                perform_client_handshake(
                    c_framed, _SILO_ID, client_cert, client_private_key, ca_cert
                )
            )
            s_task = asyncio.create_task(
                perform_server_handshake(
                    s_framed, server_cert, server_private_key, ca_cert, silos
                )
            )
            c_res, s_res = await asyncio.gather(c_task, s_task)

            # Activate codecs on both sides
            c_framed.activate(c_res.codec)   # type: ignore[arg-type]
            s_framed.activate(s_res.codec)   # type: ignore[arg-type]

            # Client sends Ping, server replies Pong
            await c_framed.send(PingMsg(ts_ns=42))
            ping = await s_framed.recv()
            assert isinstance(ping, PingMsg)
            assert ping.ts_ns == 42

            await s_framed.send(PongMsg(ts_ns=42))
            pong = await c_framed.recv()
            assert isinstance(pong, PongMsg)
            assert pong.ts_ns == 42

        asyncio.get_event_loop().run_until_complete(_exchange())


# ---------------------------------------------------------------------------
# Silo policy enforcement
# ---------------------------------------------------------------------------

class TestSiloPolicy:
    def test_allowed_silo_accepted(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        allowed: dict[str, set[UUID]] = {"test-client": {_SILO_ID}}
        client_res, server_res = _run_handshake(
            client_cert, client_private_key, server_cert, server_private_key, ca_cert,
            silo_id=_SILO_ID, allowed_silos=allowed,
        )
        assert server_res.silo_id == _SILO_ID

    def test_disallowed_silo_raises(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        other_silo = uuid.uuid4()
        allowed: dict[str, set[UUID]] = {"test-client": {_SILO_ID}}
        with pytest.raises(HandshakeError):
            _run_handshake(
                client_cert, client_private_key, server_cert, server_private_key, ca_cert,
                silo_id=other_silo, allowed_silos=allowed,
            )

    def test_cn_not_in_policy_raises(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        # Policy exists but for a different CN
        allowed: dict[str, set[UUID]] = {"other-client": {_SILO_ID}}
        with pytest.raises(HandshakeError):
            _run_handshake(
                client_cert, client_private_key, server_cert, server_private_key, ca_cert,
                silo_id=_SILO_ID, allowed_silos=allowed,
            )


# ---------------------------------------------------------------------------
# Certificate validation failures
# ---------------------------------------------------------------------------

class TestCertificateValidation:
    def test_wrong_ca_for_client_cert_raises(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
        other_ca_cert: x509.Certificate,
    ) -> None:
        # Server uses a different CA → client cert not trusted
        with pytest.raises(HandshakeError):
            _run_handshake(
                client_cert, client_private_key, server_cert, server_private_key, ca_cert,
                client_ca=other_ca_cert,
            )

    def test_wrong_ca_for_server_cert_raises(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
        other_ca_cert: x509.Certificate,
    ) -> None:
        # Client uses a different CA → server cert not trusted
        with pytest.raises(HandshakeError):
            _run_handshake(
                client_cert, client_private_key, server_cert, server_private_key, ca_cert,
                server_ca=other_ca_cert,
            )

    def test_expired_client_cert_raises(
        self,
        expired_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        with pytest.raises(HandshakeError):
            _run_handshake(
                expired_cert, client_private_key, server_cert, server_private_key, ca_cert
            )


# ---------------------------------------------------------------------------
# Stale timestamp
# ---------------------------------------------------------------------------

class TestTimestamp:
    def test_stale_hello_timestamp_raises(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """A HELLO with ts_ns 60 s in the past is rejected by the server."""
        import time as _time
        from cryptography.hazmat.primitives.serialization import Encoding
        from chiralite.protocol.messages import HelloMsg

        c_framed, s_framed = make_pipe()
        stale_ns = _time.time_ns() - 60_000_000_000   # 60 s ago

        async def _stale_client() -> None:
            # Send HELLO with a stale timestamp then silently ignore the reply
            await c_framed.send_plain(HelloMsg(
                client_cert_pem=client_cert.public_bytes(Encoding.PEM).decode(),
                nonce_c=b"\xcc" * 32,
                ts_ns=stale_ns,
                silo_id=_SILO_ID,
            ))
            try:
                await c_framed.recv_plain()   # AUTH_ERROR expected
            except Exception:
                pass

        async def _run() -> None:
            c_task = asyncio.create_task(_stale_client())
            s_task = asyncio.create_task(
                perform_server_handshake(s_framed, server_cert, server_private_key, ca_cert, {})
            )
            await c_task
            with pytest.raises(HandshakeError):
                await s_task

        asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# Signature tampering
# ---------------------------------------------------------------------------

class TestSignatureTampering:
    def test_tampered_client_signature_raises(
        self,
        client_cert: x509.Certificate,
        client_private_key: ed25519.Ed25519PrivateKey,
        server_cert: x509.Certificate,
        server_private_key: ec.EllipticCurvePrivateKey,
        ca_cert: x509.Certificate,
    ) -> None:
        """Server receives a RESPONSE with a corrupted sig_c → HandshakeError."""
        from chiralite.protocol.messages import ResponseMsg

        c_framed, s_framed = make_pipe()

        async def _bad_client() -> None:
            from chiralite.crypto.session import EphemeralKey
            import time as _time
            from chiralite.protocol.messages import ChallengeMsg, HelloMsg
            from cryptography.hazmat.primitives.serialization import Encoding

            nonce_c = b"\xaa" * 32
            ecdh = EphemeralKey()
            await c_framed.send_plain(HelloMsg(
                client_cert_pem=client_cert.public_bytes(Encoding.PEM).decode(),
                nonce_c=nonce_c,
                ts_ns=_time.time_ns(),
                silo_id=_SILO_ID,
            ))
            await c_framed.recv_plain()   # consume CHALLENGE
            # Send RESPONSE with corrupted signature
            await c_framed.send_plain(ResponseMsg(
                sig_c=b"\x00" * 64,       # invalid signature
                ecdh_pub_c=ecdh.public_bytes,
            ))

        async def _run() -> None:
            c_task = asyncio.create_task(_bad_client())
            s_task = asyncio.create_task(
                perform_server_handshake(s_framed, server_cert, server_private_key, ca_cert, {})
            )
            await c_task
            with pytest.raises(HandshakeError):
                await s_task

        asyncio.get_event_loop().run_until_complete(_run())
