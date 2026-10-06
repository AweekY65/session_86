"""Local test fixtures: small root/intermediate/leaf hierarchies generated
in memory. Nothing here touches the network or any external service."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class CertSpec:
    cn: str
    is_ca: bool
    path_length: Optional[int] = None
    not_before: datetime = NOW - timedelta(days=1)
    not_after: datetime = NOW + timedelta(days=365)
    key_cert_sign: bool = True
    eku: Optional[list] = None
    issuer_key: object = None  # defaults to issuer's own key (honest signing)


@dataclass
class Hierarchy:
    """A root -> intermediate(s) -> leaf tree of keys and certificates."""

    keys: Dict[str, rsa.RSAPrivateKey] = field(default_factory=dict)
    certs: Dict[str, x509.Certificate] = field(default_factory=dict)

    def make(self, spec: CertSpec, issuer_cn: Optional[str] = None) -> x509.Certificate:
        key = _key()
        self.keys[spec.cn] = key
        if issuer_cn is None:
            issuer_name = _name(spec.cn)
            issuer_key = spec.issuer_key or key
        else:
            issuer_name = self.certs[issuer_cn].subject
            issuer_key = spec.issuer_key or self.keys[issuer_cn]

        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(spec.cn))
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(spec.not_before)
            .not_valid_after(spec.not_after)
            .add_extension(
                x509.BasicConstraints(ca=spec.is_ca, path_length=spec.path_length),
                critical=True,
            )
        )
        if spec.is_ca:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=spec.key_cert_sign,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        else:
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            if spec.eku:
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage(spec.eku), critical=False
                )
        cert = builder.sign(issuer_key, hashes.SHA256())
        self.certs[spec.cn] = cert
        return cert


@pytest.fixture()
def hierarchy() -> Hierarchy:
    """Standard valid chain: root -> intermediate -> leaf (serverAuth)."""
    h = Hierarchy()
    h.make(CertSpec("Test Root CA", is_ca=True, path_length=2))
    h.make(CertSpec("Test Intermediate CA", is_ca=True, path_length=0), "Test Root CA")
    h.make(
        CertSpec("leaf.example.test", is_ca=False, eku=[ExtendedKeyUsageOID.SERVER_AUTH]),
        "Test Intermediate CA",
    )
    return h
