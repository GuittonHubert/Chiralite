from __future__ import annotations

import datetime
import os

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _sign(
    builder: x509.CertificateBuilder,
    issuer_key: ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
) -> x509.Certificate:
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        return builder.sign(issuer_key, algorithm=None)
    return builder.sign(issuer_key, algorithm=hashes.SHA256())


# ── CA ─────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def ca_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def ca_cert(ca_private_key: ed25519.Ed25519PrivateKey) -> x509.Certificate:
    now = _now_utc()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chiralite-test-ca")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    return _sign(builder, ca_private_key)


@pytest.fixture(scope="session")
def other_ca_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def other_ca_cert(other_ca_private_key: ed25519.Ed25519PrivateKey) -> x509.Certificate:
    now = _now_utc()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "chiralite-other-ca")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(other_ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    return _sign(builder, other_ca_private_key)


# ── Client cert (Ed25519) ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def client_cn() -> str:
    return "test-client"


@pytest.fixture(scope="session")
def client_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def client_cert(
    client_private_key: ed25519.Ed25519PrivateKey,
    ca_private_key: ed25519.Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    client_cn: str,
) -> x509.Certificate:
    now = _now_utc()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(client_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=90))
    )
    return _sign(builder, ca_private_key)


# ── Server cert (ECDSA P-256) ─────────────────────────────────────────────────

@pytest.fixture(scope="session")
def server_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def server_cert(
    server_private_key: ec.EllipticCurvePrivateKey,
    ca_private_key: ed25519.Ed25519PrivateKey,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    now = _now_utc()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-server")]))
        .issuer_name(ca_cert.subject)
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=90))
    )
    return _sign(builder, ca_private_key)


# ── Expired cert ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def expired_cert(
    client_private_key: ed25519.Ed25519PrivateKey,
    ca_private_key: ed25519.Ed25519PrivateKey,
    ca_cert: x509.Certificate,
) -> x509.Certificate:
    past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")]))
        .issuer_name(ca_cert.subject)
        .public_key(client_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(past - datetime.timedelta(days=90))
        .not_valid_after(past)
    )
    return _sign(builder, ca_private_key)


# ── Symmetric fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def session_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def session_token() -> bytes:
    return os.urandom(16)
