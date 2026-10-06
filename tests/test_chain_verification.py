"""End-to-end tests for the fully local X.509 chain verifier.

All certificates are generated in memory or under pytest's tmp_path.
No network access is required or performed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from x509chain import (
    ChainBuilder,
    ChainBuildingError,
    LocalChainVerifier,
    load_certificates,
)
from x509chain.validator import ChainValidator

from conftest import NOW, CertSpec, Hierarchy


def codes(result):
    return [d.code for d in result.diagnostics]


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------

class TestValidChain:
    def test_valid_chain_in_memory(self, hierarchy):
        v = LocalChainVerifier(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[hierarchy.certs["Test Intermediate CA"]],
            at_time=NOW,
        )
        result = v.verify(hierarchy.certs["leaf.example.test"])
        assert result.ok, result.diagnostics
        assert [c.subject.rfc4514_string() for c in result.chain] == [
            "CN=leaf.example.test",
            "CN=Test Intermediate CA",
            "CN=Test Root CA",
        ]

    def test_valid_chain_via_pem_and_der_files(self, hierarchy, tmp_path):
        root_pem = tmp_path / "root.pem"
        inter_der = tmp_path / "inter.der"
        leaf_pem = tmp_path / "leaf.pem"
        root_pem.write_bytes(
            hierarchy.certs["Test Root CA"].public_bytes(serialization.Encoding.PEM)
        )
        inter_der.write_bytes(
            hierarchy.certs["Test Intermediate CA"].public_bytes(serialization.Encoding.DER)
        )
        leaf_pem.write_bytes(
            hierarchy.certs["leaf.example.test"].public_bytes(serialization.Encoding.PEM)
        )
        v = LocalChainVerifier(
            trust_anchors=[root_pem], intermediates=[inter_der], at_time=NOW
        )
        assert v.verify(leaf_pem).ok

    def test_leaf_that_is_itself_anchor(self, hierarchy):
        root = hierarchy.certs["Test Root CA"]
        v = LocalChainVerifier(trust_anchors=[root], at_time=NOW)
        assert v.verify(root).ok

    def test_required_eku_satisfied(self, hierarchy):
        v = LocalChainVerifier(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[hierarchy.certs["Test Intermediate CA"]],
            at_time=NOW,
            required_eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        )
        assert v.verify(hierarchy.certs["leaf.example.test"]).ok


# --------------------------------------------------------------------------
# Time validity (injectable clock)
# --------------------------------------------------------------------------

class TestValidityPeriod:
    def test_expired_leaf(self, hierarchy):
        v = LocalChainVerifier(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[hierarchy.certs["Test Intermediate CA"]],
            at_time=NOW + timedelta(days=400),
        )
        result = v.verify(hierarchy.certs["leaf.example.test"])
        assert not result.ok
        assert "EXPIRED" in codes(result)

    def test_not_yet_valid_leaf(self, hierarchy):
        v = LocalChainVerifier(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[hierarchy.certs["Test Intermediate CA"]],
            at_time=NOW - timedelta(days=2),
        )
        result = v.verify(hierarchy.certs["leaf.example.test"])
        assert not result.ok
        assert "NOT_YET_VALID" in codes(result)

    def test_expired_intermediate_located(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("R", is_ca=True))
        h.make(
            CertSpec(
                "I",
                is_ca=True,
                not_after=NOW + timedelta(days=10),
            ),
            "R",
        )
        h.make(CertSpec("L", is_ca=False), "I")
        v = LocalChainVerifier(
            trust_anchors=[h.certs["R"]],
            intermediates=[h.certs["I"]],
            at_time=NOW + timedelta(days=20),
        )
        result = v.verify(h.certs["L"])
        assert not result.ok
        expired = [d for d in result.diagnostics if d.code == "EXPIRED"]
        assert expired and expired[0].position == 1
        assert expired[0].subject == "CN=I"


# --------------------------------------------------------------------------
# Issuer / signature problems
# --------------------------------------------------------------------------

class TestIssuerAndSignature:
    def test_incomplete_chain_missing_intermediate(self, hierarchy):
        v = LocalChainVerifier(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[],
            at_time=NOW,
        )
        result = v.verify(hierarchy.certs["leaf.example.test"])
        assert not result.ok
        assert "INCOMPLETE_CHAIN" in codes(result)
        diag = result.diagnostics[0]
        assert diag.position == 0
        assert "Test Intermediate CA" in diag.message

    def test_forged_signature_rejected(self, hierarchy):
        # Leaf carries the intermediate's issuer name but is signed by an
        # attacker's unrelated key.
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True))
        h.make(CertSpec("Inter", is_ca=True), "Root")
        h.make(
            CertSpec("forged-leaf", is_ca=False, issuer_key=attacker_key),
            "Inter",
        )
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Inter"]],
            at_time=NOW,
        )
        result = v.verify(h.certs["forged-leaf"])
        assert not result.ok
        assert "SIGNATURE_INVALID" in codes(result)

    def test_name_match_alone_is_not_trust(self, hierarchy):
        # A self-signed cert that merely copies the root's subject name must
        # not terminate the chain as a trusted anchor.
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rogue = (
            x509.CertificateBuilder()
            .subject_name(hierarchy.certs["Test Root CA"].subject)
            .issuer_name(hierarchy.certs["Test Root CA"].subject)
            .public_key(rogue_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(rogue_key, hashes.SHA256())
        )
        # Leaf issued "by the root name" but actually signed by the rogue key.
        h = hierarchy
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil")]))
            .issuer_name(h.certs["Test Root CA"].subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(rogue_key, hashes.SHA256())
        )
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Test Root CA"]],
            intermediates=[rogue],
            at_time=NOW,
        )
        result = v.verify(leaf)
        assert not result.ok
        # Rogue's self-signature verifies against itself, but it is not a
        # configured anchor, so the chain cannot terminate.
        assert "INCOMPLETE_CHAIN" in codes(result)

    def test_wrong_issuer_name(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True))
        h.make(CertSpec("Other Inter", is_ca=True), "Root")
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Other Inter"]],
            at_time=NOW,
        )
        result = v.verify(hierarchy.certs["leaf.example.test"])
        assert not result.ok
        assert "INCOMPLETE_CHAIN" in codes(result)


# --------------------------------------------------------------------------
# Basic Constraints / Key Usage / path length
# --------------------------------------------------------------------------

class TestExtensions:
    def test_leaf_misused_as_intermediate(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True))
        h.make(CertSpec("Fake CA", is_ca=False), "Root")  # not a CA!
        h.make(CertSpec("Victim Leaf", is_ca=False), "Fake CA")
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Fake CA"]],
            at_time=NOW,
        )
        result = v.verify(h.certs["Victim Leaf"])
        assert not result.ok
        assert "NOT_A_CA" in codes(result)
        diag = next(d for d in result.diagnostics if d.code == "NOT_A_CA")
        assert diag.position == 1

    def test_ca_without_key_cert_sign(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True))
        h.make(CertSpec("Inter", is_ca=True, key_cert_sign=False), "Root")
        h.make(CertSpec("Leaf", is_ca=False), "Inter")
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Inter"]],
            at_time=NOW,
        )
        result = v.verify(h.certs["Leaf"])
        assert not result.ok
        assert "KEY_USAGE_NOT_CA" in codes(result)

    def test_path_length_violation(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True, path_length=0))
        h.make(CertSpec("Inter", is_ca=True), "Root")
        h.make(CertSpec("Leaf", is_ca=False), "Inter")
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Inter"]],
            at_time=NOW,
        )
        result = v.verify(h.certs["Leaf"])
        assert not result.ok
        assert "PATH_LENGTH_EXCEEDED" in codes(result)

    def test_path_length_satisfied(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True, path_length=1))
        h.make(CertSpec("Inter", is_ca=True, path_length=0), "Root")
        h.make(CertSpec("Leaf", is_ca=False), "Inter")
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Inter"]],
            at_time=NOW,
        )
        assert v.verify(h.certs["Leaf"]).ok

    def test_eku_mismatch(self, hierarchy):
        h = Hierarchy()
        h.make(CertSpec("Root", is_ca=True))
        h.make(CertSpec("Inter", is_ca=True), "Root")
        h.make(
            CertSpec("Leaf", is_ca=False, eku=[ExtendedKeyUsageOID.CLIENT_AUTH]),
            "Inter",
        )
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Root"]],
            intermediates=[h.certs["Inter"]],
            at_time=NOW,
            required_eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        )
        result = v.verify(h.certs["Leaf"])
        assert not result.ok
        assert "EKU_MISMATCH" in codes(result)


# --------------------------------------------------------------------------
# Structural problems: cycles, ambiguity, depth
# --------------------------------------------------------------------------

class TestStructure:
    def _cross_signed_pair(self):
        """A <-> B: each names the other as issuer and signs accordingly."""
        key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name_a = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loop A")])
        name_b = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loop B")])

        def build(subject, issuer, pub, signer):
            return (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(pub)
                .serial_number(x509.random_serial_number())
                .not_valid_before(NOW - timedelta(days=1))
                .not_valid_after(NOW + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(signer, hashes.SHA256())
            )

        a = build(name_a, name_b, key_a.public_key(), key_b)
        b = build(name_b, name_a, key_b.public_key(), key_a)
        return a, b

    def test_cycle_detected(self, hierarchy):
        a, b = self._cross_signed_pair()
        builder = ChainBuilder(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[a, b],
        )
        with pytest.raises(ChainBuildingError) as excinfo:
            builder.build(a)
        assert "CHAIN_CYCLE" in [d.code for d in excinfo.value.diagnostics]

    def test_ambiguous_issuer_warns_but_verifies(self, hierarchy):
        # Two distinct intermediate certificates with the same subject and
        # the same key: both verify the leaf's signature.
        h = hierarchy
        inter_key = h.keys["Test Intermediate CA"]
        dup = (
            x509.CertificateBuilder()
            .subject_name(h.certs["Test Intermediate CA"].subject)
            .issuer_name(h.certs["Test Root CA"].subject)
            .public_key(inter_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1))
            .not_valid_after(NOW + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
            .sign(h.keys["Test Root CA"], hashes.SHA256())
        )
        v = LocalChainVerifier(
            trust_anchors=[h.certs["Test Root CA"]],
            intermediates=[h.certs["Test Intermediate CA"], dup],
            at_time=NOW,
        )
        result = v.verify(h.certs["leaf.example.test"])
        assert result.ok
        assert "AMBIGUOUS_ISSUER" in [w.code for w in result.warnings]

    def test_max_depth(self, hierarchy):
        builder = ChainBuilder(
            trust_anchors=[hierarchy.certs["Test Root CA"]],
            intermediates=[hierarchy.certs["Test Intermediate CA"]],
            max_depth=1,
        )
        with pytest.raises(ChainBuildingError) as excinfo:
            builder.build(hierarchy.certs["leaf.example.test"])
        assert "CHAIN_TOO_DEEP" in [d.code for d in excinfo.value.diagnostics]


# --------------------------------------------------------------------------
# Loader behaviour
# --------------------------------------------------------------------------

class TestLoader:
    def test_pem_bundle_and_der(self, hierarchy, tmp_path):
        bundle = tmp_path / "bundle.pem"
        bundle.write_bytes(
            hierarchy.certs["Test Root CA"].public_bytes(serialization.Encoding.PEM)
            + hierarchy.certs["Test Intermediate CA"].public_bytes(
                serialization.Encoding.PEM
            )
        )
        certs = load_certificates(bundle)
        assert len(certs) == 2
        der = hierarchy.certs["Test Root CA"].public_bytes(serialization.Encoding.DER)
        assert load_certificates(der)[0] == hierarchy.certs["Test Root CA"]
