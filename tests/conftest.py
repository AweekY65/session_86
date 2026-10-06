"""Test fixtures: small locally generated root/intermediate/leaf chains.

All certificates are generated in memory with the ``cryptography`` library;
nothing is fetched from the network.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
DAY = datetime.timedelta(days=1)


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_name(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "certchain-tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def build_cert(
    *,
    subject,
    issuer,
    subject_key,
    issuer_key,
    is_ca,
    path_length=None,
    not_before=None,
    not_after=None,
    key_cert_sign=None,
    eku=None,
    serial=None,
):
    not_before = not_before or (NOW - DAY)
    not_after = not_after or (NOW + 30 * DAY)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True,
        )
    )
    if key_cert_sign is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=not key_cert_sign,
                content_commitment=False,
                key_encipherment=not key_cert_sign,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def chain_factory():
    """Return a factory producing (root, intermediate, leaf, keys) tuples."""

    def factory(
        *,
        intermediate_path_length=None,
        leaf_not_before=None,
        leaf_not_after=None,
        intermediate_not_before=None,
        intermediate_not_after=None,
        leaf_is_ca=False,
        leaf_eku=(ExtendedKeyUsageOID.SERVER_AUTH,),
        intermediate_key_cert_sign=True,
        wrong_intermediate_issuer=False,
        forged_leaf_signature=False,
    ):
        root_key = make_key()
        intermediate_key = make_key()
        leaf_key = make_key()

        root_name = make_name("Test Root CA")
        intermediate_name = make_name("Test Intermediate CA")
        leaf_name = make_name("leaf.example.test")

        root = build_cert(
            subject=root_name,
            issuer=root_name,
            subject_key=root_key,
            issuer_key=root_key,
            is_ca=True,
            key_cert_sign=True,
        )

        if wrong_intermediate_issuer:
            # Intermediate claims to be issued by the root but is signed by
            # an unrelated key and carries a different issuer name.
            other_key = make_key()
            other_name = make_name("Unrelated Root CA")
            intermediate = build_cert(
                subject=intermediate_name,
                issuer=other_name,
                subject_key=intermediate_key,
                issuer_key=other_key,
                is_ca=True,
                path_length=intermediate_path_length,
                key_cert_sign=intermediate_key_cert_sign,
                not_before=intermediate_not_before,
                not_after=intermediate_not_after,
            )
        else:
            intermediate = build_cert(
                subject=intermediate_name,
                issuer=root_name,
                subject_key=intermediate_key,
                issuer_key=root_key,
                is_ca=True,
                path_length=intermediate_path_length,
                key_cert_sign=intermediate_key_cert_sign,
                not_before=intermediate_not_before,
                not_after=intermediate_not_after,
            )

        if forged_leaf_signature:
            # Leaf claims the intermediate as issuer but is signed by an
            # attacker-controlled key.
            attacker_key = make_key()
            leaf = build_cert(
                subject=leaf_name,
                issuer=intermediate_name,
                subject_key=leaf_key,
                issuer_key=attacker_key,
                is_ca=leaf_is_ca,
                eku=list(leaf_eku) if leaf_eku else None,
                not_before=leaf_not_before,
                not_after=leaf_not_after,
            )
        else:
            leaf = build_cert(
                subject=leaf_name,
                issuer=intermediate_name,
                subject_key=leaf_key,
                issuer_key=intermediate_key,
                is_ca=leaf_is_ca,
                eku=list(leaf_eku) if leaf_eku else None,
                not_before=leaf_not_before,
                not_after=leaf_not_after,
            )

        return {
            "root": root,
            "intermediate": intermediate,
            "leaf": leaf,
            "root_key": root_key,
            "intermediate_key": intermediate_key,
            "leaf_key": leaf_key,
        }

    return factory


@pytest.fixture
def pem_roundtrip(tmp_path):
    def write(cert, name):
        path = tmp_path / name
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(path)

    return write
