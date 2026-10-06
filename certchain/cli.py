"""Command line interface: fully local chain verification.

Example:
    python -m certchain.cli verify \
        --leaf leaf.pem --intermediates-dir intermediates/ \
        --root root.pem --at 2026-01-01T00:00:00Z --eku serverAuth
"""

from __future__ import annotations

import argparse
import datetime
import sys

from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

from .errors import ChainError, describe_cert
from .store import CertStore, load_directory, load_file
from .verify import ChainVerifier

_EKU_NAMES = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "timeStamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "OCSPSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
}


def _parse_time(value: str) -> datetime.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _parse_eku(value: str) -> ObjectIdentifier:
    if value in _EKU_NAMES:
        return _EKU_NAMES[value]
    return ObjectIdentifier(value)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="certchain",
        description="Fully local X.509 chain verification (no network access).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="verify a leaf certificate chain")
    verify.add_argument("--leaf", required=True, help="leaf certificate (PEM/DER)")
    verify.add_argument(
        "--intermediate",
        action="append",
        default=[],
        help="intermediate certificate file (repeatable)",
    )
    verify.add_argument(
        "--intermediates-dir",
        action="append",
        default=[],
        help="directory of intermediate certificates (repeatable)",
    )
    verify.add_argument(
        "--root",
        action="append",
        required=True,
        help="trust anchor certificate file (repeatable)",
    )
    verify.add_argument(
        "--at",
        help="validation time, ISO-8601 (default: now); injectable for testing",
    )
    verify.add_argument(
        "--eku",
        help="required leaf extended key usage (name like serverAuth or an OID)",
    )
    args = parser.parse_args(argv)

    store = CertStore()
    for path in args.intermediate:
        for cert in load_file(path):
            store.add_intermediate(cert)
    for directory in args.intermediates_dir:
        for cert in load_directory(directory):
            store.add_intermediate(cert)
    for path in args.root:
        for cert in load_file(path):
            store.add_trust_anchor(cert)

    leafs = load_file(args.leaf)
    now = _parse_time(args.at) if args.at else None
    eku = _parse_eku(args.eku) if args.eku else None
    verifier = ChainVerifier(store, now=now, required_eku=eku)

    try:
        chain = verifier.verify(leafs[0])
    except ChainError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    print("OK: chain verified")
    for idx, cert in enumerate(chain):
        label = "leaf" if idx == 0 else ("trust anchor" if idx == len(chain) - 1 else "intermediate")
        print(f"  [{idx}] {label}: {describe_cert(cert)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
