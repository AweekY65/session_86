"""Candidate chain construction from a local certificate pool.

Chains are built purely from issuer/subject name matching plus actual
signature verification. A name match alone is never treated as trust.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from cryptography import x509

from .crypto import fingerprint, verify_signature
from .errors import ChainBuildingError, Diagnostic


def _subject_str(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _issuer_str(cert: x509.Certificate) -> str:
    return cert.issuer.rfc4514_string()


class ChainBuilder:
    """Builds candidate chains from a leaf up to a local trust anchor.

    ``trust_anchors`` is the explicit, locally configured set of trusted
    certificates. A chain terminates only when the current certificate's
    signature verifies against one of these anchors (or the certificate
    is itself a signature-valid self-signed anchor).
    """

    def __init__(
        self,
        trust_anchors: Sequence[x509.Certificate],
        intermediates: Sequence[x509.Certificate] = (),
        max_depth: int = 8,
    ):
        if not trust_anchors:
            raise ValueError("at least one local trust anchor is required")
        self.trust_anchors = list(trust_anchors)
        self.intermediates = list(intermediates)
        self.max_depth = max_depth
        self.warnings: List[Diagnostic] = []

    # -- public API ---------------------------------------------------------

    def build(self, leaf: x509.Certificate) -> List[x509.Certificate]:
        """Return a verified-signature chain ``[leaf, ..., anchor-issued root]``.

        The trust anchor itself is appended as the final element when the
        anchor is not already part of the chain (i.e. non-self-signed root
        is unusual; typically the last element *is* the anchor).
        """
        self.warnings = []
        chain, diagnostics = self._walk(leaf, [leaf], {fingerprint(leaf)})
        if chain is None:
            raise ChainBuildingError(diagnostics)
        self.warnings.extend(diagnostics)  # diagnostics here are warnings
        return chain

    # -- internals ----------------------------------------------------------

    def _walk(
        self,
        cert: x509.Certificate,
        path: List[x509.Certificate],
        seen: set,
    ) -> Tuple[Optional[List[x509.Certificate]], List[Diagnostic]]:
        diagnostics: List[Diagnostic] = []
        pos = len(path) - 1

        if len(path) > self.max_depth:
            diagnostics.append(
                Diagnostic(
                    "CHAIN_TOO_DEEP",
                    f"exceeded maximum chain depth of {self.max_depth}",
                    pos,
                    _subject_str(cert),
                )
            )
            return None, diagnostics

        # 1. Does a trust anchor issue this certificate (or is it one)?
        for anchor in self.trust_anchors:
            if fingerprint(cert) == fingerprint(anchor):
                # The certificate itself is a configured anchor: only trust
                # it if its (self-)signature actually verifies.
                if verify_signature(cert, anchor):
                    return list(path), diagnostics
                diagnostics.append(
                    Diagnostic(
                        "ANCHOR_SIGNATURE_INVALID",
                        "certificate matches a trust anchor by content but its "
                        "signature does not verify",
                        pos,
                        _subject_str(cert),
                    )
                )
                continue
            if cert.issuer == anchor.subject and verify_signature(cert, anchor):
                return list(path) + [anchor], diagnostics

        # 2. Find candidate issuers in the local intermediate pool.
        self_fp = fingerprint(cert)
        name_matches = [
            c
            for c in self.intermediates
            if c.subject == cert.issuer and fingerprint(c) != self_fp
        ]
        sig_valid = [c for c in name_matches if verify_signature(cert, c)]

        if not name_matches:
            diagnostics.append(
                Diagnostic(
                    "INCOMPLETE_CHAIN",
                    f"no local issuer found for issuer name '{_issuer_str(cert)}' "
                    "and no trust anchor verifies its signature",
                    pos,
                    _subject_str(cert),
                )
            )
            return None, diagnostics

        if not sig_valid:
            diagnostics.append(
                Diagnostic(
                    "SIGNATURE_INVALID",
                    f"{len(name_matches)} candidate issuer(s) matched the issuer "
                    f"name '{_issuer_str(cert)}' but none verifies the signature",
                    pos,
                    _subject_str(cert),
                )
            )
            return None, diagnostics

        if len(sig_valid) > 1:
            diagnostics.append(
                Diagnostic(
                    "AMBIGUOUS_ISSUER",
                    f"{len(sig_valid)} candidate issuers verify the signature; "
                    "trying each in pool order",
                    pos,
                    _subject_str(cert),
                )
            )

        best_failure: List[Diagnostic] = []
        for candidate in sig_valid:
            fp = fingerprint(candidate)
            if fp in seen:
                diagnostics.append(
                    Diagnostic(
                        "CHAIN_CYCLE",
                        f"candidate issuer '{_subject_str(candidate)}' is already "
                        "in the current path (cycle detected)",
                        pos,
                        _subject_str(cert),
                    )
                )
                continue
            chain, sub = self._walk(candidate, path + [candidate], seen | {fp})
            if chain is not None:
                return chain, diagnostics + sub
            best_failure = sub

        return None, diagnostics + best_failure
