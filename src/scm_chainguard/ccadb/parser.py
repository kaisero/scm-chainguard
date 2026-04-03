"""Parse CCADB CSV data: filter trust-store certs, walk certificate tree, attach PEMs."""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import replace

from scm_chainguard.models import CcadbCertificate, CertType, TrustStore

logger = logging.getLogger(__name__)


def _is_included(row: dict[str, str], trust_store: TrustStore) -> bool:
    """Check if a row's status is 'Included' for the given store (or any store if ALL)."""
    if trust_store == TrustStore.ALL:
        return any(
            row.get(s.status_column, "").strip() == "Included"
            for s in TrustStore.individual_stores()
        )
    return row.get(trust_store.status_column, "").strip() == "Included"


def _is_trusted(row: dict[str, str], trust_store: TrustStore) -> bool:
    """Check if a row's status is 'Included' or 'Trusted' for the given store (or any store if ALL)."""
    if trust_store == TrustStore.ALL:
        return any(
            row.get(s.status_column, "").strip() in ("Included", "Trusted")
            for s in TrustStore.individual_stores()
        )
    return row.get(trust_store.status_column, "").strip() in ("Included", "Trusted")


def _is_distrusted(row: dict[str, str], trust_store: TrustStore) -> bool:
    """Check if a row's status is 'Removed' or 'Blocked' for the given store.

    For TrustStore.ALL: returns True only if at least one store has Removed/Blocked
    AND no store still has Included/Trusted status.
    """
    if trust_store == TrustStore.ALL:
        statuses = [row.get(s.status_column, "").strip() for s in TrustStore.individual_stores()]
        has_removed = any(s in ("Removed", "Blocked") for s in statuses)
        still_trusted = any(s in ("Included", "Trusted") for s in statuses)
        return has_removed and not still_trusted
    return row.get(trust_store.status_column, "").strip() in ("Removed", "Blocked")


def collect_distrusted_fingerprints(
    csv_text: str,
    trust_store: TrustStore = TrustStore.CHROME,
) -> set[str]:
    """Return SHA-256 fingerprints of root certs marked Removed/Blocked for the given store."""
    reader = csv.DictReader(io.StringIO(csv_text))
    fingerprints: set[str] = set()
    for row in reader:
        if row.get("Certificate Record Type") != "Root Certificate":
            continue
        if not _is_distrusted(row, trust_store):
            continue
        sha256 = row.get("SHA-256 Fingerprint", "").strip().upper()
        if sha256:
            fingerprints.add(sha256)
    logger.info("Found %d distrusted root certificates for store '%s'.", len(fingerprints), trust_store.value)
    return fingerprints


def parse_metadata(
    csv_text: str,
    include_intermediates: bool = False,
    trust_store: TrustStore = TrustStore.CHROME,
) -> tuple[dict[str, CcadbCertificate], dict[str, CcadbCertificate]]:
    """Parse CCADB metadata CSV and return trusted roots and intermediates for the given store.

    Returns (roots_by_sha256, intermediates_by_sha256).
    If include_intermediates is False, the intermediates dict is empty.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    logger.info("Parsed %d total CCADB records.", len(rows))

    # Pass 1: included roots
    roots: dict[str, CcadbCertificate] = {}
    for row in rows:
        if row.get("Certificate Record Type") != "Root Certificate":
            continue
        if not _is_included(row, trust_store):
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
    logger.info("Found %d %s-included root certificates.", len(roots), trust_store.value)

    if not include_intermediates:
        return roots, {}

    # Pass 2: Collect all valid trusted intermediates
    all_intermediates: dict[str, CcadbCertificate] = {}
    for row in rows:
        if row.get("Certificate Record Type") != "Intermediate Certificate":
            continue
        if not _is_trusted(row, trust_store):
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
