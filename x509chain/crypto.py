"""Signature verification helpers (purely local, no network)."""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa


def verify_signature(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Return True iff ``cert``'s signature verifies with ``issuer``'s key."""
    pub = issuer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        else:  # pragma: no cover - unsupported key types
            return False
    except InvalidSignature:
        return False
    return True


def fingerprint(cert: x509.Certificate) -> str:
    from cryptography.hazmat.primitives import hashes

    return cert.fingerprint(hashes.SHA256()).hex()
