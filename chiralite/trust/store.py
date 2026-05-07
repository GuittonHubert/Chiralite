"""TrustStore — CA certificate bundle for peer verification.

``TrustStore`` holds the offline CA certificate and exposes a single
``verify_cert`` method.  The handshake layer calls it after receiving a
peer certificate to confirm chain and validity before using the public key
for challenge verification.
"""
from __future__ import annotations

from cryptography import x509

from chiralite.crypto.certificates import CertificateError, verify_chain

__all__ = ["TrustError", "TrustStore"]


class TrustError(Exception):
    """Raised when a certificate fails trust verification."""


class TrustStore:
    """Holds a CA certificate and verifies peer certificates against it.

    Args:
        ca_cert: The CA certificate that signs all trusted peer certificates.
    """

    def __init__(self, ca_cert: x509.Certificate) -> None:
        self._ca_cert = ca_cert

    @property
    def ca_cert(self) -> x509.Certificate:
        return self._ca_cert

    def verify_cert(self, cert: x509.Certificate) -> None:
        """Verify that *cert* is signed by the CA and currently valid.

        Args:
            cert: The peer certificate to verify.

        Raises:
            TrustError: if the certificate is expired, not yet valid, or the
                signature does not match the CA key.
        """
        try:
            verify_chain(cert, self._ca_cert)
        except CertificateError as exc:
            raise TrustError(str(exc)) from exc
