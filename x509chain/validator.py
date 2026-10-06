"""Chain validation: time, Basic Constraints, Key Usage, EKU, path length.

All checks are local and deterministic. The evaluation time is injectable
so expired / not-yet-valid certificates can be tested reliably.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Sequence

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from .errors import ChainVerificationError, Diagnostic


def _subject_str(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_ext(cert: x509.Certificate, ext_class):
    try:
        return cert.extensions.get_extension_for_class(ext_class).value
    except x509.ExtensionNotFound:
        return None


class ChainValidator:
    """Validates a signature-verified candidate chain.

    ``chain`` must be ordered leaf-first, with the trust anchor last.
    """

    def __init__(
        self,
        at_time: Optional[datetime] = None,
        required_eku: Optional[Sequence[x509.ObjectIdentifier]] = None,
        require_basic_constraints: bool = True,
    ):
        # Injectable clock: defaults to "now", but tests can pin any instant.
        self.at_time = _as_utc(at_time) if at_time else datetime.now(timezone.utc)
        self.required_eku = list(required_eku) if required_eku else None
        self.require_basic_constraints = require_basic_constraints

    def validate(self, chain: Sequence[x509.Certificate]) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        for pos, cert in enumerate(chain):
            is_anchor = pos == len(chain) - 1
            diagnostics += self._check_validity(cert, pos)
            diagnostics += self._check_basic_constraints(cert, pos, is_anchor)
            diagnostics += self._check_key_usage(cert, pos, is_anchor)
        diagnostics += self._check_path_length(chain)
        diagnostics += self._check_eku(chain[0])
        if diagnostics:
            raise ChainVerificationError(diagnostics)
        return diagnostics

    # -- individual checks --------------------------------------------------

    def _check_validity(self, cert, pos) -> List[Diagnostic]:
        out = []
        nb = _as_utc(cert.not_valid_before_utc)
        na = _as_utc(cert.not_valid_after_utc)
        if self.at_time < nb:
            out.append(
                Diagnostic(
                    "NOT_YET_VALID",
                    f"not valid before {nb.isoformat()} (evaluation time "
                    f"{self.at_time.isoformat()})",
                    pos,
                    _subject_str(cert),
                )
            )
        if self.at_time > na:
            out.append(
                Diagnostic(
                    "EXPIRED",
                    f"expired at {na.isoformat()} (evaluation time "
                    f"{self.at_time.isoformat()})",
                    pos,
                    _subject_str(cert),
                )
            )
        return out

    def _check_basic_constraints(self, cert, pos, is_anchor) -> List[Diagnostic]:
        bc = _get_ext(cert, x509.BasicConstraints)
        if bc is None:
            if is_anchor:
                return []  # trust is explicit local configuration
            if self.require_basic_constraints:
                return [
                    Diagnostic(
                        "MISSING_BASIC_CONSTRAINTS",
                        "non-anchor certificate lacks a Basic Constraints "
                        "extension; cannot confirm CA status",
                        pos,
                        _subject_str(cert),
                    )
                ]
            return []
        if pos > 0 and not is_anchor and not bc.ca:
            return [
                Diagnostic(
                    "NOT_A_CA",
                    "certificate is used as an issuer but Basic Constraints "
                    "does not assert CA=TRUE",
                    pos,
                    _subject_str(cert),
                )
            ]
        return []

    def _check_key_usage(self, cert, pos, is_anchor) -> List[Diagnostic]:
        ku = _get_ext(cert, x509.KeyUsage)
        if ku is None:
            return []
        if pos > 0 and not ku.key_cert_sign:
            return [
                Diagnostic(
                    "KEY_USAGE_NOT_CA",
                    "certificate is used as an issuer but its Key Usage does "
                    "not include keyCertSign",
                    pos,
                    _subject_str(cert),
                )
            ]
        return []

    def _check_path_length(self, chain) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        # path_len_constraint on a CA limits the number of *non-self-issued*
        # CA certificates that may follow it in the chain (below it).
        for pos in range(1, len(chain)):
            cert = chain[pos]
            bc = _get_ext(cert, x509.BasicConstraints)
            if bc is None or not bc.ca or bc.path_length is None:
                continue
            ca_below = sum(
                1
                for c in chain[1:pos]
                if (lambda b: b is not None and b.ca)(_get_ext(c, x509.BasicConstraints))
            )
            if ca_below > bc.path_length:
                out.append(
                    Diagnostic(
                        "PATH_LENGTH_EXCEEDED",
                        f"path length constraint {bc.path_length} violated: "
                        f"{ca_below} CA certificate(s) below this issuer",
                        pos,
                        _subject_str(cert),
                    )
                )
        return out

    def _check_eku(self, leaf) -> List[Diagnostic]:
        if not self.required_eku:
            return []
        eku = _get_ext(leaf, x509.ExtendedKeyUsage)
        if eku is None:
            return [
                Diagnostic(
                    "EKU_MISSING",
                    "leaf certificate has no Extended Key Usage extension but "
                    "specific purposes are required",
                    0,
                    _subject_str(leaf),
                )
            ]
        missing = [oid for oid in self.required_eku if oid not in eku]
        if missing:
            names = ", ".join(getattr(o, "_name", o.dotted_string) for o in missing)
            return [
                Diagnostic(
                    "EKU_MISMATCH",
                    f"leaf certificate is missing required EKU purpose(s): {names}",
                    0,
                    _subject_str(leaf),
                )
            ]
        return []


# Convenience re-export for callers configuring required purposes.
SERVER_AUTH = ExtendedKeyUsageOID.SERVER_AUTH
CLIENT_AUTH = ExtendedKeyUsageOID.CLIENT_AUTH
