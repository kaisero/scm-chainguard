"""Parse CCADB CSV data: filter Chrome-trusted certs, walk certificate tree, attach PEMs."""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import replace

from scm_chainguard.models import CcadbCertificate, CertType

logger = logging.getLogger(__name__)


def parse_metadata(
    csv_text: str,
    include_intermediates: bool = False,
) -> tuple[dict[str, CcadbCertificate], dict[str, CcadbCertificate]]:
    """Parse CCADB metadata CSV and return Chrome-trusted roots and intermediates.

    Returns (roots_by_sha256, intermediates_by_sha256).
    If include_intermediates is False, the intermediates dict is empty.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    logger.info("Parsed %d total CCADB records.", len(rows))

    # Pass 1: Chrome-included roots
    roots: dict[str, CcadbCertificate] = {}
    for row in rows:
        if row.get("Certificate Record Type") != "Root Certificate":
            continue
        if row.get("Chrome Status", "").strip() != "Included":
            continue
        if row.get("Revocation Status", "").strip() not in ("", "Not Revoked"):
            continue
        sha256 = row.get("SHA-256 Fingerprint", "").strip().upper()
        if not sha256:
            continue
        name = row.get("Certificate Name", "").strip() or row.get("Common Name or Certificate Name", "").strip()
        roots[sha256] = CcadbCertificate(
            sha256_fingerprint=sha256,
            common_name=name,
            ca_owner=row.get("CA Owner", "").strip(),
            cert_type=CertType.ROOT,
        )
    logger.info("Found %d Chrome-included root certificates.", len(roots))

    if not include_intermediates:
        return roots, {}

    # Pass 2: Collect all valid Chrome-trusted intermediates
    all_intermediates: dict[str, CcadbCertificate] = {}
    for row in rows:
        if row.get("Certificate Record Type") != "Intermediate Certificate":
            continue
        chrome_status = row.get("Chrome Status", "").strip()
        if chrome_status not in ("Included", "Trusted"):
            continue
        if row.get("Revocation Status", "").strip() not in ("", "Not Revoked"):
            continue
        sha256 = row.get("SHA-256 Fingerprint", "").strip().upper()
        parent = row.get("Parent SHA-256 Fingerprint", "").strip().upper()
        if not sha256 or not parent:
            continue
        name = row.get("Certificate Name", "").strip() or row.get("Common Name or Certificate Name", "").strip()
        all_intermediates[sha256] = CcadbCertificate(
            sha256_fingerprint=sha256,
            common_name=name,
            ca_owner=row.get("CA Owner", "").strip(),
            cert_type=CertType.INTERMEDIATE,
            parent_sha256=parent,
        )

    # Walk the tree from roots
    intermediates = _walk_intermediate_tree(roots, all_intermediates)
    logger.info("Found %d trusted intermediate certificates (all levels).", len(intermediates))
    return roots, intermediates


def _walk_intermediate_tree(
    roots: dict[str, CcadbCertificate],
    all_intermediates: dict[str, CcadbCertificate],
) -> dict[str, CcadbCertificate]:
    """Walk the certificate tree from roots, collecting reachable intermediates."""
    result: dict[str, CcadbCertificate] = {}
    known = set(roots.keys())
    while True:
        added = 0
        for sha256, cert in all_intermediates.items():
            if sha256 in result:
                continue
            if cert.parent_sha256 in known:
                result[sha256] = cert
                added += 1
        if added == 0:
            break
        known |= set(result.keys())
    return result


def attach_pems(
    certs: dict[str, CcadbCertificate],
    pem_csv_texts: list[str],
) -> dict[str, CcadbCertificate]:
    """Parse PEM CSVs and return new dict with PEM data attached.

    Certs without matching PEM data are logged as warnings and excluded.
    """
    pem_lookup: dict[str, str] = {}
    for csv_text in pem_csv_texts:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            sha256 = row.get("SHA-256 Fingerprint", "").strip().upper()
            if sha256 not in certs or sha256 in pem_lookup:
                continue
            pem = (row.get("X.509 Certificate (PEM)", "") or row.get("PEM", "") or "").strip()
            if pem and "-----BEGIN CERTIFICATE-----" in pem:
                pem_lookup[sha256] = pem

    result: dict[str, CcadbCertificate] = {}
    missing = 0
    for sha256, cert in certs.items():
        pem = pem_lookup.get(sha256)
        if pem is None:
            logger.warning("No PEM data for certificate %s (%s)", sha256[:16], cert.common_name)
            missing += 1
            continue
        result[sha256] = replace(cert, pem=pem)

    if missing:
        logger.warning("%d certificates have no PEM data and were excluded.", missing)
    else:
        logger.info("All %d certificates have PEM data.", len(result))

    return result
