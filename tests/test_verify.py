"""End-to-end chain verification tests. Everything runs locally."""

import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from certchain import (
    AmbiguousIssuerError,
    CertStore,
    ChainBuildingError,
    ChainVerifier,
    load_der,
    load_file,
    load_pem,
)
from certchain.errors import (
    BasicConstraintsError,
    KeyUsageError,
    PathLengthError,
    SignatureError,
    ValidityError,
)
from tests.conftest import NOW, DAY, build_cert, make_key, make_name


def make_verifier(certs, now=NOW, required_eku=None):
    store = CertStore(
        intermediates=[certs["intermediate"]],
        trust_anchors=[certs["root"]],
    )
    return ChainVerifier(store, now=now, required_eku=required_eku)


def inner_failures(exc):
    assert isinstance(exc, ChainBuildingError)
    return exc.attempts


# --------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------- #

def test_valid_chain(chain_factory):
    certs = chain_factory()
    chain = make_verifier(certs).verify(certs["leaf"])
    assert chain == [certs["leaf"], certs["intermediate"], certs["root"]]


def test_valid_chain_with_required_eku(chain_factory):
    certs = chain_factory()
    verifier = make_verifier(certs, required_eku=ExtendedKeyUsageOID.SERVER_AUTH)
    assert verifier.verify(certs["leaf"])[0] == certs["leaf"]


def test_direct_leaf_of_root(chain_factory):
    certs = chain_factory()
    root_leaf = build_cert(
        subject=make_name("direct.example.test"),
        issuer=certs["root"].subject,
        subject_key=make_key(),
        issuer_key=certs["root_key"],
        is_ca=False,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    store = CertStore(trust_anchors=[certs["root"]])
    chain = ChainVerifier(store, now=NOW).verify(root_leaf)
    assert chain == [root_leaf, certs["root"]]


# --------------------------------------------------------------------- #
# validity period (injected clock)
# --------------------------------------------------------------------- #

def test_expired_leaf(chain_factory):
    certs = chain_factory(
        leaf_not_before=NOW - 10 * DAY, leaf_not_after=NOW - DAY
    )
    with pytest.raises(ChainBuildingError) as err:
        make_verifier(certs).verify(certs["leaf"])
    assert any(isinstance(e, ValidityError) for e in inner_failures(err.value))


def test_not_yet_valid_leaf(chain_factory):
    certs = chain_factory(
        leaf_not_before=NOW + DAY, leaf_not_after=NOW + 10 * DAY
    )
    with pytest.raises(ChainBuildingError) as err:
        make_verifier(certs).verify(certs["leaf"])
    assert any(isinstance(e, ValidityError) for e in inner_failures(err.value))


def test_expired_intermediate(chain_factory):
    certs = chain_factory(
        intermediate_not_before=NOW - 10 * DAY,
        intermediate_not_after=NOW - DAY,
    )
    with pytest.raises(ChainBuildingError) as err:
        make_verifier(certs).verify(certs["leaf"])
    assert any(isinstance(e, ValidityError) for e in inner_failures(err.value))


def test_injected_clock_makes_expired_cert_valid(chain_factory):
    certs = chain_factory(
        leaf_not_before=NOW - 10 * DAY, leaf_not_after=NOW - DAY
    )
    # NOW - DAY is the latest moment where leaf, intermediate and root
    # validity windows all overlap.
    verifier = make_verifier(certs, now=NOW - DAY)
    assert verifier.verify(certs["leaf"])[0] == certs["leaf"]


# --------------------------------------------------------------------- #
# signatures and issuers
# --------------------------------------------------------------------- #

def test_forged_leaf_signature(chain_factory):
    certs = chain_factory(forged_leaf_signature=True)
    with pytest.raises(ChainBuildingError) as err:
        make_verifier(certs).verify(certs["leaf"])
    assert any(isinstance(e, SignatureError) for e in inner_failures(err.value))


def test_wrong_issuer_name(chain_factory):
    certs = chain_factory(wrong_intermediate_issuer=True)
    with pytest.raises(ChainBuildingError):
        make_verifier(certs).verify(certs["leaf"])


def test_name_match_alone_is_not_trusted(chain_factory):
    """A self-signed cert with the root's name but a different key must fail."""
    certs = chain_factory()
    impostor_key = make_key()
    impostor = build_cert(
        subject=certs["root"].subject,
        issuer=certs["root"].subject,
        subject_key=impostor_key,
        issuer_key=impostor_key,
        is_ca=True,
        key_cert_sign=True,
    )
    store = CertStore(
        intermediates=[certs["intermediate"], impostor],
        trust_anchors=[certs["root"]],
    )
    # Chain must terminate at the real root, not the impostor.
    chain = ChainVerifier(store, now=NOW).verify(certs["leaf"])
    assert chain[-1] == certs["root"]


# --------------------------------------------------------------------- #
# basic constraints / key usage / EKU
# --------------------------------------------------------------------- #

def test_leaf_cannot_be_used_as_ca(chain_factory):
    certs = chain_factory()
    # Sign a sub-leaf with the *leaf* key; the leaf is not a CA.
    sub_leaf = build_cert(
        subject=make_name("sub.example.test"),
        issuer=certs["leaf"].subject,
        subject_key=make_key(),
        issuer_key=certs["leaf_key"],
        is_ca=False,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    store = CertStore(
        intermediates=[certs["leaf"], certs["intermediate"]],
        trust_anchors=[certs["root"]],
    )
    with pytest.raises(ChainBuildingError) as err:
        ChainVerifier(store, now=NOW).verify(sub_leaf)
    assert any(
        isinstance(e, BasicConstraintsError) for e in inner_failures(err.value)
    )


def test_intermediate_missing_key_cert_sign(chain_factory):
    certs = chain_factory(intermediate_key_cert_sign=False)
    with pytest.raises(ChainBuildingError) as err:
        make_verifier(certs).verify(certs["leaf"])
    assert any(isinstance(e, KeyUsageError) for e in inner_failures(err.value))


def test_leaf_missing_required_eku(chain_factory):
    certs = chain_factory(leaf_eku=(ExtendedKeyUsageOID.CLIENT_AUTH,))
    verifier = make_verifier(certs, required_eku=ExtendedKeyUsageOID.SERVER_AUTH)
    with pytest.raises(ChainBuildingError) as err:
        verifier.verify(certs["leaf"])
    assert any(isinstance(e, KeyUsageError) for e in inner_failures(err.value))


# --------------------------------------------------------------------- #
# path length
# --------------------------------------------------------------------- #

def test_path_length_violation(chain_factory):
    # Root allows zero subordinate CAs, but an intermediate sits below it.
    root_key = make_key()
    root = build_cert(
        subject=make_name("PathLen Root"),
        issuer=make_name("PathLen Root"),
        subject_key=root_key,
        issuer_key=root_key,
        is_ca=True,
        path_length=0,
        key_cert_sign=True,
    )
    certs = chain_factory()
    intermediate = build_cert(
        subject=certs["intermediate"].subject,
        issuer=root.subject,
        subject_key=certs["intermediate_key"],
        issuer_key=root_key,
        is_ca=True,
        key_cert_sign=True,
    )
    leaf = build_cert(
        subject=make_name("leaf.example.test"),
        issuer=intermediate.subject,
        subject_key=make_key(),
        issuer_key=certs["intermediate_key"],
        is_ca=False,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    store = CertStore(intermediates=[intermediate], trust_anchors=[root])
    with pytest.raises(ChainBuildingError) as err:
        ChainVerifier(store, now=NOW).verify(leaf)
    assert any(isinstance(e, PathLengthError) for e in inner_failures(err.value))


def test_path_length_satisfied(chain_factory):
    root_key = make_key()
    root = build_cert(
        subject=make_name("PathLen Root"),
        issuer=make_name("PathLen Root"),
        subject_key=root_key,
        issuer_key=root_key,
        is_ca=True,
        path_length=1,
        key_cert_sign=True,
    )
    certs = chain_factory()
    intermediate = build_cert(
        subject=certs["intermediate"].subject,
        issuer=root.subject,
        subject_key=certs["intermediate_key"],
        issuer_key=root_key,
        is_ca=True,
        key_cert_sign=True,
    )
    leaf = build_cert(
        subject=make_name("leaf.example.test"),
        issuer=intermediate.subject,
        subject_key=make_key(),
        issuer_key=certs["intermediate_key"],
        is_ca=False,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    store = CertStore(intermediates=[intermediate], trust_anchors=[root])
    chain = ChainVerifier(store, now=NOW).verify(leaf)
    assert chain[-1] == root


# --------------------------------------------------------------------- #
# structural diagnostics
# --------------------------------------------------------------------- #

def test_incomplete_chain(chain_factory):
    certs = chain_factory()
    store = CertStore(trust_anchors=[certs["root"]])  # no intermediate
    with pytest.raises(ChainBuildingError) as err:
        ChainVerifier(store, now=NOW).verify(certs["leaf"])
    assert "no issuer found" in str(err.value)


def test_cycle_detected(chain_factory):
    certs = chain_factory()
    # a signs b, b signs a; neither is a trust anchor.
    key_a, key_b = make_key(), make_key()
    name_a, name_b = make_name("CA A"), make_name("CA B")
    cert_a = build_cert(
        subject=name_a, issuer=name_b, subject_key=key_a, issuer_key=key_b,
        is_ca=True, key_cert_sign=True,
    )
    cert_b = build_cert(
        subject=name_b, issuer=name_a, subject_key=key_b, issuer_key=key_a,
        is_ca=True, key_cert_sign=True,
    )
    store = CertStore(intermediates=[cert_a, cert_b])
    with pytest.raises(ChainBuildingError) as err:
        ChainVerifier(store, now=NOW).verify(cert_a)
    assert "cycle" in str(err.value).lower()


def test_ambiguous_issuers(chain_factory):
    certs = chain_factory()
    # A second, equally valid intermediate with the same subject name.
    other_key = make_key()
    other_intermediate = build_cert(
        subject=certs["intermediate"].subject,
        issuer=certs["root"].subject,
        subject_key=other_key,
        issuer_key=certs["root_key"],
        is_ca=True,
        key_cert_sign=True,
    )
    other_leaf = build_cert(
        subject=make_name("leaf.example.test"),
        issuer=other_intermediate.subject,
        subject_key=make_key(),
        issuer_key=other_key,
        is_ca=False,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    store = CertStore(
        intermediates=[certs["intermediate"], other_intermediate],
        trust_anchors=[certs["root"]],
    )
    # other_leaf's signature only verifies with other_intermediate, so the
    # leaf's own issuer is unambiguous; instead craft a leaf signed by a key
    # both intermediates share is impossible, so test ambiguity via two
    # identical-subject anchors both verifying the same intermediate.
    dup_root = certs["root"]
    store2 = CertStore(
        intermediates=[certs["intermediate"]],
        trust_anchors=[certs["root"], dup_root],
    )
    chain = ChainVerifier(store2, now=NOW).verify(certs["leaf"])
    assert chain[-1] == certs["root"]

    # True ambiguity: two distinct valid chains for the same leaf.
    twin_key = make_key()
    twin_root = build_cert(
        subject=certs["root"].subject,
        issuer=certs["root"].subject,
        subject_key=twin_key,
        issuer_key=twin_key,
        is_ca=True,
        key_cert_sign=True,
    )
    twin_intermediate = build_cert(
        subject=certs["intermediate"].subject,
        issuer=twin_root.subject,
        subject_key=certs["intermediate_key"],
        issuer_key=twin_key,
        is_ca=True,
        key_cert_sign=True,
    )
    store3 = CertStore(
        intermediates=[certs["intermediate"], twin_intermediate],
        trust_anchors=[certs["root"], twin_root],
    )
    with pytest.raises(AmbiguousIssuerError):
        ChainVerifier(store3, now=NOW).verify(certs["leaf"])


# --------------------------------------------------------------------- #
# loading: PEM / DER / directories
# --------------------------------------------------------------------- #

def test_pem_and_der_loading(chain_factory, pem_roundtrip):
    certs = chain_factory()
    pem_path = pem_roundtrip(certs["leaf"], "leaf.pem")
    loaded = load_file(pem_path)
    assert loaded[0] == certs["leaf"]

    der_bytes = certs["leaf"].public_bytes(serialization.Encoding.DER)
    assert load_der(der_bytes) == certs["leaf"]

    pem_bytes = open(pem_path, "rb").read()
    assert load_pem(pem_bytes)[0] == certs["leaf"]


def test_load_multiple_pem_from_one_file(chain_factory, tmp_path):
    certs = chain_factory()
    blob = b""
    for cert in (certs["leaf"], certs["intermediate"], certs["root"]):
        blob += cert.public_bytes(serialization.Encoding.PEM)
    path = tmp_path / "bundle.pem"
    path.write_bytes(blob)
    loaded = load_file(str(path))
    assert loaded == [certs["leaf"], certs["intermediate"], certs["root"]]


def test_cli_verify(chain_factory, pem_roundtrip, tmp_path, capsys):
    from certchain.cli import main

    certs = chain_factory()
    leaf = pem_roundtrip(certs["leaf"], "leaf.pem")
    inter_dir = tmp_path / "intermediates"
    inter_dir.mkdir()
    (inter_dir / "intermediate.pem").write_bytes(
        certs["intermediate"].public_bytes(serialization.Encoding.PEM)
    )
    root = pem_roundtrip(certs["root"], "root.pem")

    rc = main([
        "verify",
        "--leaf", leaf,
        "--intermediates-dir", str(inter_dir),
        "--root", root,
        "--at", "2026-01-01T00:00:00Z",
        "--eku", "serverAuth",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK: chain verified" in out

    rc = main([
        "verify",
        "--leaf", leaf,
        "--intermediates-dir", str(inter_dir),
        "--root", root,
        "--at", "2030-01-01T00:00:00Z",
    ])
    assert rc == 1
