"""Fully local X.509 certificate chain verification.

Everything (certificates, trust anchors, policy, time) comes from local
files or memory. No network access of any kind is performed.
"""

from .builder import ChainBuilder
from .errors import ChainBuildingError, ChainVerificationError, Diagnostic
from .loader import load_certificates, load_der, load_many, load_pem
from .validator import CLIENT_AUTH, SERVER_AUTH, ChainValidator
from .verifier import LocalChainVerifier, VerificationResult

__all__ = [
    "ChainBuilder",
    "ChainBuildingError",
    "ChainVerificationError",
    "ChainValidator",
    "Diagnostic",
    "LocalChainVerifier",
    "VerificationResult",
    "load_certificates",
    "load_der",
    "load_many",
    "load_pem",
    "SERVER_AUTH",
    "CLIENT_AUTH",
]

__version__ = "0.1.0"
