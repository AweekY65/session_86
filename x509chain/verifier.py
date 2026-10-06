"""High-level, fully local X.509 chain verifier."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Sequence

from cryptography import x509

from .builder import ChainBuilder
from .errors import Diagnostic
from .loader import CertSource, load_many
from .validator import ChainValidator


@dataclass
class VerificationResult:
    """Outcome of a verification attempt."""

    ok: bool
    chain: List[x509.Certificate] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)
    warnings: List[Diagnostic] = field(default_factory=list)


class LocalChainVerifier:
    """Verifies certificate chains against a local trust-anchor set only.

    No OCSP, CRL fetching, AIA chasing, or any other network access is
    performed; revocation checking is intentionally out of scope.
    """

    def __init__(
        self,
        trust_anchors: Sequence[CertSource],
        intermediates: Sequence[CertSource] = (),
        at_time: Optional[datetime] = None,
        required_eku=None,
        max_depth: int = 8,
    ):
        anchors = load_many(trust_anchors)
        pool = load_many(intermediates)
        self._builder = ChainBuilder(anchors, pool, max_depth=max_depth)
        self._at_time = at_time
        self._required_eku = required_eku

    def verify(self, leaf: CertSource, extra_intermediates: Sequence[CertSource] = ()) -> VerificationResult:
        """Build and validate a chain for ``leaf``. Never raises for
        ordinary verification failures; inspect ``result.diagnostics``."""
        certs = load_many([leaf])
        if len(certs) != 1:
            return VerificationResult(
                ok=False,
                diagnostics=[
                    Diagnostic("LEAF_AMBIGUOUS", "expected exactly one leaf certificate")
                ],
            )
        builder = self._builder
        if extra_intermediates:
            builder = ChainBuilder(
                self._builder.trust_anchors,
                self._builder.intermediates + load_many(extra_intermediates),
                max_depth=self._builder.max_depth,
            )
        try:
            chain = builder.build(certs[0])
        except Exception as exc:
            diagnostics = getattr(exc, "diagnostics", None) or [
                Diagnostic("BUILD_FAILED", str(exc))
            ]
            return VerificationResult(ok=False, diagnostics=list(diagnostics))

        validator = ChainValidator(at_time=self._at_time, required_eku=self._required_eku)
        try:
            validator.validate(chain)
        except Exception as exc:
            diagnostics = getattr(exc, "diagnostics", None) or [
                Diagnostic("VALIDATION_FAILED", str(exc))
            ]
            return VerificationResult(
                ok=False, chain=chain, diagnostics=list(diagnostics),
                warnings=list(builder.warnings),
            )
        return VerificationResult(ok=True, chain=chain, warnings=list(builder.warnings))
