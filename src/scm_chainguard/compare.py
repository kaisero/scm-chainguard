"""Comparison logic: local certificates vs SCM stores."""

from __future__ import annotations

import logging

from scm_chainguard.models import (
    CertType,
    ComparisonResult,
    LocalCertificate,
    ScmImportedCert,
    ScmPredefinedRoot,
)

logger = logging.getLogger(__name__)


def compare_roots(
    local_roots: list[LocalCertificate],
    scm_predefined: list[ScmPredefinedRoot],
    scm_imported: list[ScmImportedCert] | None = None,
) -> ComparisonResult:
    """Compare local root CAs against both predefined and imported SCM certs.

    A root is "present" if it matches either:
    - A predefined root CA by common name (case-insensitive), OR
    - An imported certificate by SHA-256 fingerprint or common name
    """
    # Build predefined lookup by CN
    predefined_cns: dict[str, str] = {}
    for entry in scm_predefined:
        if entry.common_name:
            predefined_cns[entry.common_name.lower()] = entry.name

    # Build imported lookups by SHA-256 and CN
    imported_shas: dict[str, str] = {}
    imported_cns: dict[str, str] = {}
    for cert in (scm_imported or []):
        if cert.sha256_fingerprint:
            imported_shas[cert.sha256_fingerprint] = cert.name
        if cert.common_name:
            imported_cns[cert.common_name.lower()] = cert.name

    present: list[tuple[LocalCertificate, str]] = []
    missing: list[LocalCertificate] = []

    for cert in local_roots:
        # Check predefined store by CN
        match_name = predefined_cns.get(cert.common_name.lower())
        # Check imported certs by SHA-256
        if match_name is None and cert.sha256_fingerprint:
            match_name = imported_shas.get(cert.sha256_fingerprint)
        # Check imported certs by CN
        if match_name is None:
            match_name = imported_cns.get(cert.common_name.lower())

        if match_name:
            present.append((cert, match_name))
        else:
            missing.append(cert)

    logger.info(
        "Root CA comparison: %d present, %d missing "
        "(of %d local, %d predefined + %d imported in SCM).",
        len(present), len(missing), len(local_roots),
        len(scm_predefined), len(scm_imported or []),
    )
    return ComparisonResult(
        cert_type=CertType.ROOT,
        present=present,
        missing=missing,
        total_local=len(local_roots),
        total_scm=len(scm_predefined) + len(scm_imported or []),
    )


def compare_intermediates(
    local_intermediates: list[LocalCertificate],
    scm_imported: list[ScmImportedCert],
) -> ComparisonResult:
    """Compare local intermediates against SCM imported certs by SHA-256 then CN."""
    scm_by_sha: dict[str, ScmImportedCert] = {}
    scm_by_cn: dict[str, ScmImportedCert] = {}
    for cert in scm_imported:
        if cert.sha256_fingerprint:
            scm_by_sha[cert.sha256_fingerprint] = cert
        if cert.common_name:
            scm_by_cn[cert.common_name.lower()] = cert

    present: list[tuple[LocalCertificate, str]] = []
    missing: list[LocalCertificate] = []

    for cert in local_intermediates:
        match = scm_by_sha.get(cert.sha256_fingerprint)
        if match is None:
            match = scm_by_cn.get(cert.common_name.lower())
        if match:
            present.append((cert, match.name))
        else:
            missing.append(cert)

    logger.info(
        "Intermediate comparison: %d present, %d missing (of %d local, %d SCM imported).",
        len(present), len(missing), len(local_intermediates), len(scm_imported),
    )
    return ComparisonResult(
        cert_type=CertType.INTERMEDIATE,
        present=present,
        missing=missing,
        total_local=len(local_intermediates),
        total_scm=len(scm_imported),
    )
