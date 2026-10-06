"""Chain construction and verification.

Verification order for every candidate chain (documented in README):

1.  Build candidate chains by matching issuer/subject names, then keep only
    links whose signature verifies with the issuer's public key.
2.  Terminate only at a certificate present in the explicit trust-anchor
    set; the anchor's key must verify the previous link's signature.
3.  Check NotBefore/NotAfter for every certificate at the injected time.
4.  Check Basic Constraints: every non-leaf must be a CA; a leaf without
    CA=TRUE must never appear as an issuer.
5.  Check Key Usage: CA certificates must assert keyCertSign.
6.  Check Extended Key Usage on the leaf against the required EKU policy.
7.  Check path length constraints along the chain.
"""

from __future__ import annotations

import datetime
from typing import List, Optional, Sequence, Set, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .errors import (
    AmbiguousIssuerError,
    BasicConstraintsError,
    ChainBuildingError,
    ChainError,
    CycleDetectedError,
    IncompleteChainError,
    KeyUsageError,
    PathLengthError,
    SignatureError,
    ValidityError,
    describe_cert,
)
from .store import CertStore


def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Raise InvalidSignature unless ``issuer``'s key signed ``child``."""
    pub = issuer.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            child.signature_hash_algorithm,
        )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pub.verify(child.signature, child.tbs_certificate_bytes)
    else:  # pragma: no cover - exotic key types
        raise ChainError(f"unsupported issuer public key type: {type(pub).__name__}")


def _path(chain: Sequence[x509.Certificate]) -> List[str]:
    return [describe_cert(c) for c in chain]


def _get_basic_constraints(cert: x509.Certificate):
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound:
        return None


def _get_key_usage(cert: x509.Certificate):
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return None


def _get_eku(cert: x509.Certificate):
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return None


class ChainVerifier:
    """Builds and verifies chains against a local :class:`CertStore`."""

    def __init__(
        self,
        store: CertStore,
        now: Optional[datetime.datetime] = None,
        required_eku: Optional[x509.ObjectIdentifier] = None,
    ):
        self.store = store
        # Injectable clock: pass any aware/naive datetime for stable tests.
        self.now = now or datetime.datetime.now(datetime.timezone.utc)
        self.required_eku = required_eku

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    def verify(self, leaf: x509.Certificate) -> List[x509.Certificate]:
        """Return the verified chain leaf-first, or raise a ChainError."""
        chains = self._build_chains(leaf)
        failures: List[ChainError] = []
        valid: List[List[x509.Certificate]] = []
        for chain in chains:
            try:
                self._verify_chain(chain)
                valid.append(chain)
            except ChainError as exc:
                failures.append(exc)
        # Deduplicate identical chains (e.g. the same anchor configured twice).
        unique: List[List[x509.Certificate]] = []
        seen_fp = set()
        for chain in valid:
            fp = tuple(c.fingerprint(hashes.SHA256()) for c in chain)
            if fp not in seen_fp:
                seen_fp.add(fp)
                unique.append(chain)
        valid = unique
        if not valid:
            if failures:
                raise ChainBuildingError(
                    "no candidate chain passed verification", attempts=failures
                )
            raise ChainBuildingError("no candidate chain could be constructed")
        if len(valid) > 1:
            raise AmbiguousIssuerError(
                describe_cert(leaf), [_path(c) for c in valid]
            )
        return valid[0]

    # ------------------------------------------------------------------ #
    # chain construction
    # ------------------------------------------------------------------ #
    def _build_chains(self, leaf: x509.Certificate) -> List[List[x509.Certificate]]:
        index = self.store.candidates_by_subject()
        results: List[List[x509.Certificate]] = []
        errors: List[ChainError] = []

        def walk(chain: List[x509.Certificate], seen: Set[Tuple[bytes, bytes]]):
            current = chain[-1]
            issuers = index.get(current.issuer, [])
            if not issuers:
                if self.store.is_trust_anchor(current):
                    results.append(list(chain))
                else:
                    errors.append(
                        IncompleteChainError(
                            f"no issuer found for {describe_cert(current)} "
                            "and certificate is not a configured trust anchor",
                            path=_path(chain),
                        )
                    )
                return
            progressed = False
            for issuer in issuers:
                key = (issuer.subject.public_bytes(), issuer.signature)
                if key in seen:
                    errors.append(
                        CycleDetectedError(
                            f"cycle detected at {describe_cert(issuer)}",
                            path=_path(chain) + [describe_cert(issuer)],
                        )
                    )
                    continue
                try:
                    verify_signature(current, issuer)
                except InvalidSignature:
                    errors.append(
                        SignatureError(
                            f"signature of {describe_cert(current)} does not "
                            f"verify with candidate issuer {describe_cert(issuer)}",
                            path=_path(chain) + [describe_cert(issuer)],
                        )
                    )
                    continue
                progressed = True
                if self.store.is_trust_anchor(issuer):
                    results.append(chain + [issuer])
                else:
                    walk(chain + [issuer], seen | {key})

        walk([leaf], {(leaf.subject.public_bytes(), leaf.signature)})
        if not results and not errors:
            errors.append(
                IncompleteChainError(
                    "could not reach any configured trust anchor",
                    path=[describe_cert(leaf)],
                )
            )
        if not results:
            raise ChainBuildingError(
                "failed to build a chain to a trust anchor", attempts=errors
            )
        return results

    # ------------------------------------------------------------------ #
    # chain verification
    # ------------------------------------------------------------------ #
    def _verify_chain(self, chain: List[x509.Certificate]) -> None:
        self._check_validity(chain)
        self._check_basic_constraints(chain)
        self._check_key_usage(chain)
        self._check_eku(chain)
        self._check_path_length(chain)

    def _check_validity(self, chain: List[x509.Certificate]) -> None:
        now = self.now
        for idx, cert in enumerate(chain):
            nb = cert.not_valid_before_utc
            na = cert.not_valid_after_utc
            cmp_now = now if now.tzinfo else now.replace(tzinfo=datetime.timezone.utc)
            if cmp_now < nb:
                raise ValidityError(
                    f"certificate not valid before {nb.isoformat()} "
                    f"(now={cmp_now.isoformat()})",
                    path=_path(chain[: idx + 1]),
                )
            if cmp_now > na:
                raise ValidityError(
                    f"certificate expired at {na.isoformat()} "
                    f"(now={cmp_now.isoformat()})",
                    path=_path(chain[: idx + 1]),
                )

    def _check_basic_constraints(self, chain: List[x509.Certificate]) -> None:
        # Every cert except the leaf acts as an issuer and must be a CA.
        for idx, cert in enumerate(chain):
            if idx == 0:
                continue  # the leaf is never used as an issuer here
            bc = _get_basic_constraints(cert)
            if bc is None or not bc.ca:
                raise BasicConstraintsError(
                    f"{describe_cert(cert)} is used as an issuer but is not a CA "
                    "(missing Basic Constraints or CA=FALSE)",
                    path=_path(chain[: idx + 1]),
                )

    def _check_key_usage(self, chain: List[x509.Certificate]) -> None:
        for idx, cert in enumerate(chain[1:], start=1):
            ku = _get_key_usage(cert)
            if ku is not None and not ku.key_cert_sign:
                raise KeyUsageError(
                    f"CA {describe_cert(cert)} lacks keyCertSign key usage",
                    path=_path(chain[: idx + 1]),
                )

    def _check_eku(self, chain: List[x509.Certificate]) -> None:
        if self.required_eku is None:
            return
        leaf = chain[0]
        eku = _get_eku(leaf)
        if eku is None:
            raise KeyUsageError(
                f"leaf {describe_cert(leaf)} has no Extended Key Usage "
                f"extension; required {self.required_eku.dotted_string}",
                path=_path(chain[:1]),
            )
        if self.required_eku not in eku and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
            raise KeyUsageError(
                f"leaf {describe_cert(leaf)} EKU does not include "
                f"{self.required_eku.dotted_string}",
                path=_path(chain[:1]),
            )

    def _check_path_length(self, chain: List[x509.Certificate]) -> None:
        # ca_count = number of non-self-issued CA certificates below the
        # cert currently being examined (RFC 5280 style accounting).
        ca_count = 0
        for idx in range(1, len(chain)):
            cert = chain[idx]
            bc = _get_basic_constraints(cert)
            if bc is not None and bc.ca and bc.path_length is not None:
                if ca_count > bc.path_length:
                    raise PathLengthError(
                        f"path length constraint {bc.path_length} of "
                        f"{describe_cert(cert)} exceeded by {ca_count} "
                        "subordinate CA certificate(s)",
                        path=_path(chain[: idx + 1]),
                    )
            # Count this cert if it is a non-self-issued CA.
            if cert.subject != cert.issuer:
                ca_count += 1
