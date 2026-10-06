"""Local certificate loading: PEM/DER from files, bytes, or memory only."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Union

from cryptography import x509

CertSource = Union[str, Path, bytes, x509.Certificate]


def load_pem(data: bytes) -> List[x509.Certificate]:
    """Load one or more certificates from PEM bytes."""
    return list(x509.load_pem_x509_certificates(data))


def load_der(data: bytes) -> x509.Certificate:
    """Load a single certificate from DER bytes."""
    return x509.load_der_x509_certificate(data)


def load_certificates(source: CertSource) -> List[x509.Certificate]:
    """Load certificates from a path, PEM/DER bytes, or an in-memory cert.

    - ``x509.Certificate`` instances are returned as-is (in-memory source).
    - ``bytes`` are sniffed: PEM if it contains a BEGIN block, else DER.
    - ``str``/``Path`` are read from the local filesystem only.
    """
    if isinstance(source, x509.Certificate):
        return [source]
    if isinstance(source, (str, Path)):
        data = Path(source).read_bytes()
    elif isinstance(source, bytes):
        data = source
    else:
        raise TypeError(f"unsupported certificate source: {type(source)!r}")

    if b"-----BEGIN" in data:
        return load_pem(data)
    return [load_der(data)]


def load_many(sources: Iterable[CertSource]) -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []
    for src in sources:
        certs.extend(load_certificates(src))
    return certs
