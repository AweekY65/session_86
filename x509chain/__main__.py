"""Terminal entry point: fully local chain verification.

Example:
    python -m x509chain --root root.pem --intermediate inter.pem \
        --leaf leaf.pem --at-time 2026-01-01T00:00:00+00:00
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from cryptography.x509.oid import ExtendedKeyUsageOID

from .verifier import LocalChainVerifier

_EKU_NAMES = {
    "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
    "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
    "emailProtection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="x509chain",
        description="Fully local X.509 chain verification (no network access).",
    )
    parser.add_argument("--root", action="append", required=True,
                        help="PEM/DER trust anchor file (repeatable)")
    parser.add_argument("--intermediate", action="append", default=[],
                        help="PEM/DER intermediate pool file (repeatable)")
    parser.add_argument("--leaf", required=True, help="PEM/DER leaf certificate")
    parser.add_argument("--at-time", default=None,
                        help="ISO-8601 evaluation time (default: now)")
    parser.add_argument("--eku", action="append", choices=sorted(_EKU_NAMES),
                        default=[], help="Required leaf EKU purpose (repeatable)")
    args = parser.parse_args(argv)

    at_time = datetime.fromisoformat(args.at_time) if args.at_time else None
    required_eku = [_EKU_NAMES[name] for name in args.eku] or None

    verifier = LocalChainVerifier(
        trust_anchors=args.root,
        intermediates=args.intermediate,
        at_time=at_time,
        required_eku=required_eku,
    )
    result = verifier.verify(args.leaf)

    if result.ok:
        print("OK: chain verified")
        for i, cert in enumerate(result.chain):
            print(f"  [{i}] {cert.subject.rfc4514_string()}")
    else:
        print("FAILED: chain verification")
        for d in result.diagnostics:
            print(f"  {d}")
    for w in result.warnings:
        print(f"  warning: {w}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
