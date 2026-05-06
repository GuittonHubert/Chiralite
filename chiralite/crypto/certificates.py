from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID


class CertificateError(Exception):
    """Raised when certificate loading or chain verification fails."""


def load_cert(pem: bytes | str) -> x509.Certificate:
    """Parse a PEM-encoded X.509 certificate."""
    data = pem.encode() if isinstance(pem, str) else pem
    return x509.load_pem_x509_certificate(data)


def get_cn(cert: x509.Certificate) -> str:
    """Extract the Common Name from a certificate subject."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise CertificateError("certificate has no Common Name")
    value = attrs[0].value
    if not isinstance(value, str):
        raise CertificateError("certificate CN is not a string")
    return value


def verify_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """
    Verify that cert was signed by ca_cert and is currently valid.
    Raises CertificateError on expiry, not-yet-valid, or signature failure.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.not_valid_before_utc > now:
        raise CertificateError(f"certificate not yet valid (CN={get_cn(cert)!r})")
    if cert.not_valid_after_utc < now:
        raise CertificateError(f"certificate has expired (CN={get_cn(cert)!r})")

    ca_pub = ca_cert.public_key()
    try:
        if isinstance(ca_pub, ed25519.Ed25519PublicKey):
            ca_pub.verify(cert.signature, cert.tbs_certificate_bytes)
        elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
            hash_algo = cert.signature_hash_algorithm
            if hash_algo is None:
                raise CertificateError("ECDSA-signed cert is missing a hash algorithm")
            ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hash_algo))
        else:
            raise CertificateError(f"unsupported CA key type: {type(ca_pub).__name__}")
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError("signature verification failed") from exc


def days_until_expiry(cert: x509.Certificate) -> int:
    """Return the number of whole days until the certificate expires."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return (cert.not_valid_after_utc - now).days
