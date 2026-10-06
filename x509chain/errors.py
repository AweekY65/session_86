"""Diagnostic error types for the local X.509 chain verifier.

Every failure carries a stable ``code`` and an optional ``location`` so
callers can pinpoint which certificate in the candidate chain (and which
check) caused the failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Diagnostic:
    """A single, locatable problem (or warning) found during verification."""

    code: str
    message: str
    # Index into the candidate chain (0 = leaf), None if not chain-specific.
    position: Optional[int] = None
    # Human-readable subject of the offending certificate, when known.
    subject: Optional[str] = None

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        where = ""
        if self.position is not None:
            where = f" [chain position {self.position}]"
        if self.subject:
            where += f" [subject: {self.subject}]"
        return f"{self.code}{where}: {self.message}"


class ChainVerificationError(Exception):
    """Raised when chain building or validation fails.

    Carries the full list of diagnostics collected while exploring all
    candidate chains, so ambiguous situations (e.g. multiple candidate
    issuers) remain inspectable.
    """

    def __init__(self, diagnostics: List[Diagnostic]):
        self.diagnostics: List[Diagnostic] = list(diagnostics)
        summary = "; ".join(str(d) for d in self.diagnostics) or "verification failed"
        super().__init__(summary)


class ChainBuildingError(ChainVerificationError):
    """No candidate chain could be constructed (incomplete, cycle, ...)."""
