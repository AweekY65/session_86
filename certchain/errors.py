"""Diagnostic error types for certificate chain verification.

Every error carries a ``path`` attribute locating the failing certificate
inside the candidate chain (index 0 == leaf) plus a human readable reason,
so callers can pinpoint exactly which link failed and why.
"""

from __future__ import annotations

from typing import List, Optional


def describe_cert(cert) -> str:
    try:
        return cert.subject.rfc4514_string()
    except Exception:  # pragma: no cover - defensive
        return "<unparseable certificate>"


class ChainError(Exception):
    """Base class for all chain building / verification failures."""

    def __init__(self, reason: str, path: Optional[List[str]] = None):
        self.reason = reason
        self.path = path or []
        super().__init__(self.__str__())

    def __str__(self) -> str:
        if self.path:
            chain = " -> ".join(self.path)
            return f"{self.reason} [chain: {chain}]"
        return self.reason


class ChainBuildingError(ChainError):
    """Raised when no candidate chain can be constructed at all."""

    def __init__(
        self,
        reason: str,
        attempts: Optional[List["ChainError"]] = None,
        path: Optional[List[str]] = None,
    ):
        self.attempts = attempts or []
        super().__init__(reason, path=path)

    def __str__(self) -> str:
        lines = [self.reason]
        for attempt in self.attempts:
            lines.append(f"  candidate failed: {attempt}")
        return "\n".join(lines)


class IncompleteChainError(ChainBuildingError):
    """No issuer found for some certificate and no trust anchor reached."""


class CycleDetectedError(ChainBuildingError):
    """The issuer graph contains a loop."""


class AmbiguousIssuerError(ChainError):
    """More than one candidate issuer yields a fully valid chain."""

    def __init__(self, subject: str, chains: List[List[str]]):
        self.subject = subject
        self.chains = chains
        reason = (
            f"ambiguous issuers for {subject}: "
            f"{len(chains)} distinct valid chains found"
        )
        super().__init__(reason, path=chains[0] if chains else [])


class VerificationError(ChainError):
    """A semantic check (signature, validity, constraints, ...) failed."""


class SignatureError(VerificationError):
    """Digital signature verification failed for one link."""


class ValidityError(VerificationError):
    """Certificate expired or not yet valid at the injected time."""


class BasicConstraintsError(VerificationError):
    """CA flag / basic constraints violation."""


class KeyUsageError(VerificationError):
    """Key usage or extended key usage violation."""


class PathLengthError(VerificationError):
    """Basic constraints path length constraint violated."""
