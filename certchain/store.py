"""Local certificate loading (PEM/DER) and trust-anchor store.

Everything is sourced from local files or in-memory objects.  This module
never performs any network access (no OCSP, CRL fetching, AIA chasing).
"""

from __future__ import annotations

import os
from typing import Dict, Iterable, List

from cryptography import x509
from cryptography.x509.oid import NameOID


def load_pem(data: bytes) -> List[x509.Certificate]:
    """Load one or more PEM certificates from a byte string."""
    certs: List[x509.Certificate] = []
    marker = b"-----END CERTIFICATE-----"
    begin = b"-----BEGIN CERTIFICATE-----"
    for block in data.split(marker):
        if begin in block:
            pem = block[block.index(begin):] + marker + b"\n"
            certs.append(x509.load_pem_x509_certificate(pem))
    if not certs:
        raise ValueError("no PEM certificates found in input")
    return certs


def load_der(data: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(data)


def load_file(path: str) -> List[x509.Certificate]:
    """Load certificates from a local file; format sniffed PEM vs DER."""
    with open(path, "rb") as fh:
        data = fh.read()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return load_pem(data)
    return [load_der(data)]


def load_directory(path: str) -> List[x509.Certificate]:
    """Load every certificate file inside a local directory."""
    certs: List[x509.Certificate] = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        if not name.lower().endswith((".pem", ".crt", ".cer", ".der")):
            continue
        certs.extend(load_file(full))
    return certs


class CertStore:
    """In-memory pool of untrusted intermediates plus explicit trust anchors."""

    def __init__(
        self,
        intermediates: Iterable[x509.Certificate] = (),
        trust_anchors: Iterable[x509.Certificate] = (),
    ):
        self.intermediates: List[x509.Certificate] = list(intermediates)
        self.trust_anchors: List[x509.Certificate] = list(trust_anchors)

    def add_intermediate(self, cert: x509.Certificate) -> None:
        self.intermediates.append(cert)

    def add_trust_anchor(self, cert: x509.Certificate) -> None:
        self.trust_anchors.append(cert)

    def candidates_by_subject(self) -> Dict[x509.Name, List[x509.Certificate]]:
        """Index intermediates and trust anchors by their subject name."""
        index: Dict[x509.Name, List[x509.Certificate]] = {}
        for cert in self.intermediates + self.trust_anchors:
            index.setdefault(cert.subject, []).append(cert)
        return index

    def is_trust_anchor(self, cert: x509.Certificate) -> bool:
        """Exact certificate match against the explicit anchor set.

        Trust is never inferred from names alone: the anchor's public key
        must also verify the child's signature (checked by the verifier).
        """
        return any(cert == anchor for anchor in self.trust_anchors)
