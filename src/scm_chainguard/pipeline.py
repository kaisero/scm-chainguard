"""Pipeline orchestration: fetch, compare, sync, and full run."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from scm_chainguard.ccadb.client import CcadbClient
from scm_chainguard.ccadb.parser import attach_pems, parse_metadata
from scm_chainguard.cert_utils import load_local_certs, sanitize_filename
from scm_chainguard.compare import compare_intermediates, compare_roots
from scm_chainguard.config import ScmConfig
from scm_chainguard.models import CertType, CleanupResult, ComparisonResult, SyncResult
from scm_chainguard.scm.auth import ScmAuthenticator
from scm_chainguard.scm.identity_client import IdentityClient
from scm_chainguard.scm.security_client import SecurityClient
from scm_chainguard.sync import sync_certificates

logger = logging.getLogger(__name__)


def run_fetch(config: ScmConfig, include_intermediates: bool = False) -> dict[str, Path]:
    """Download Chrome-trusted certificates from CCADB and save to output directory."""
    output = Path(config.output_dir)
    roots_dir = output / "roots"
    intermediates_dir = output / "intermediates"

    ccadb = CcadbClient(timeout=config.request_timeout)

    # Download and parse metadata
    metadata_csv = ccadb.download_metadata_csv()
    roots, intermediates = parse_metadata(metadata_csv, include_intermediates)

    # Merge all certs and download PEMs
    all_certs = {**roots, **intermediates}
    logger.info("Need PEM data for %d certificates.", len(all_certs))
    pem_csvs = ccadb.download_all_pem_csvs()
    all_certs = attach_pems(all_certs, pem_csvs)

    # Save root certs
    roots_dir.mkdir(parents=True, exist_ok=True)
    root_count = 0
    for sha256, cert in all_certs.items():
        if cert.cert_type != CertType.ROOT:
            continue
        filename = sanitize_filename(cert.common_name, sha256)
        (roots_dir / filename).write_text(
            cert.pem if cert.pem.endswith("\n") else cert.pem + "\n"
        )
        root_count += 1
    logger.info("Saved %d root certificates to %s", root_count, roots_dir)

    result = {"roots": roots_dir}

    # Save intermediate certs
    if include_intermediates:
        intermediates_dir.mkdir(parents=True, exist_ok=True)
        int_count = 0
        for sha256, cert in all_certs.items():
            if cert.cert_type != CertType.INTERMEDIATE:
                continue
            filename = sanitize_filename(cert.common_name, sha256)
            (intermediates_dir / filename).write_text(
                cert.pem if cert.pem.endswith("\n") else cert.pem + "\n"
            )
            int_count += 1
        logger.info("Saved %d intermediate certificates to %s", int_count, intermediates_dir)
        result["intermediates"] = intermediates_dir

    return result


def run_compare(
    config: ScmConfig, include_intermediates: bool = False,
) -> dict[str, ComparisonResult]:
    """Compare local certificates against SCM stores."""
    output = Path(config.output_dir)

    # Load local certs
    local_roots = load_local_certs(output / "roots", CertType.ROOT)
    logger.info("Loaded %d local root certificates.", len(local_roots))

    # Authenticate and fetch SCM state
    auth = ScmAuthenticator(config)
    identity = IdentityClient(config, auth)

    scm_predefined = identity.list_trusted_certificate_authorities()
    scm_imported = identity.list_certificates()

    results: dict[str, ComparisonResult] = {}
    # Roots: check against both predefined store AND imported certs
    results["roots"] = compare_roots(local_roots, scm_predefined, scm_imported)

    if include_intermediates:
        local_intermediates = load_local_certs(output / "intermediates", CertType.INTERMEDIATE)
        logger.info("Loaded %d local intermediate certificates.", len(local_intermediates))
        results["intermediates"] = compare_intermediates(local_intermediates, scm_imported)

    return results


def run_sync(
    config: ScmConfig,
    include_intermediates: bool = False,
    dry_run: bool = False,
) -> dict[str, SyncResult]:
    """Compare and sync missing certificates to SCM."""
    from scm_chainguard.cert_utils import CERT_PREFIX

    # Run comparison first
    comparisons = run_compare(config, include_intermediates)

    auth = ScmAuthenticator(config)
    identity = IdentityClient(config, auth)
    security = SecurityClient(config, auth)

    results: dict[str, SyncResult] = {}

    # Collect CG_-managed imported certs that are already present but may
    # not yet be in the trusted_root_CA list (e.g. from an interrupted sync).
    root_comp = comparisons["roots"]
    ensure_trusted = [
        scm_name for _, scm_name in root_comp.present
        if scm_name.startswith(CERT_PREFIX)
    ]
    if ensure_trusted:
        logger.info(
            "Found %d already-imported CG_ certificates to ensure in trusted root CA list.",
            len(ensure_trusted),
        )

    # Sync missing roots
    if root_comp.missing or ensure_trusted:
        if root_comp.missing:
            logger.info("Syncing %d missing root certificates...", len(root_comp.missing))
        results["roots"] = sync_certificates(
            root_comp.missing, identity, security, config,
            dry_run=dry_run, add_as_trusted_root=True,
            ensure_trusted=ensure_trusted,
        )
    else:
        logger.info("All root certificates are already present in SCM.")
        results["roots"] = SyncResult(dry_run=dry_run)

    # Sync missing intermediates
    if include_intermediates and "intermediates" in comparisons:
        int_comp = comparisons["intermediates"]
        if int_comp.missing:
            logger.info("Syncing %d missing intermediate certificates...", len(int_comp.missing))
            results["intermediates"] = sync_certificates(
                int_comp.missing, identity, security, config,
                dry_run=dry_run, add_as_trusted_root=False,
            )
        else:
            logger.info("All intermediate certificates are already present in SCM.")
            results["intermediates"] = SyncResult(dry_run=dry_run)

    return results


def run_full_pipeline(
    config: ScmConfig,
    include_intermediates: bool = False,
    dry_run: bool = False,
) -> dict:
    """Full pipeline: fetch -> compare -> sync."""
    logger.info("Starting full pipeline (include_intermediates=%s, dry_run=%s)",
                include_intermediates, dry_run)

    # Step 1: Fetch
    logger.info("=" * 60)
    logger.info("STEP 1: Fetching certificates from CCADB")
    logger.info("=" * 60)
    fetch_result = run_fetch(config, include_intermediates)

    # Step 2+3: Compare and Sync
    logger.info("=" * 60)
    logger.info("STEP 2: Comparing and syncing with SCM")
    logger.info("=" * 60)
    sync_results = run_sync(config, include_intermediates, dry_run)

    return {"fetch": fetch_result, "sync": sync_results}


def run_cleanup(config: ScmConfig, dry_run: bool = False) -> CleanupResult:
    """Remove expired CG_-managed certificates from SCM."""
    from scm_chainguard.cert_utils import CERT_PREFIX, is_cert_expired
    from scm_chainguard.logging_setup import get_audit_logger

    audit = get_audit_logger()
    result = CleanupResult(dry_run=dry_run)

    auth = ScmAuthenticator(config)
    identity = IdentityClient(config, auth)
    security = SecurityClient(config, auth)

    # List all imported certs and filter to CG_-managed ones
    all_certs = identity.list_certificates()
    managed = [c for c in all_certs if c.name.startswith(CERT_PREFIX)]
    logger.info("Found %d CG_-managed certificates (of %d total).", len(managed), len(all_certs))

    # Find expired ones
    expired = []
    for cert in managed:
        if not cert.pem:
            logger.warning("No PEM data for cert %r (id=%s), skipping.", cert.name, cert.id)
            continue
        try:
            if is_cert_expired(cert.pem):
                expired.append(cert)
        except Exception as e:
            logger.warning("Could not parse cert %r: %s", cert.name, e)

    if not expired:
        logger.info("No expired CG_-managed certificates found.")
        return result

    logger.info(
        "%s %d expired certificates...",
        "[DRY-RUN] Would remove" if dry_run else "Removing",
        len(expired),
    )

    # Remove from trusted root CA list
    expired_names = [c.name for c in expired]
    removed = security.remove_trusted_root_cas(expired_names, dry_run=dry_run)
    result.removed_from_trusted = removed

    # Delete certificates
    for cert in expired:
        if dry_run:
            audit.info("AUDIT: DRY_RUN would_delete cert=%r id=%s", cert.name, cert.id)
            result.deleted.append(cert.name)
            continue
        try:
            identity.delete_certificate(cert.id)
            audit.info("AUDIT: DELETE cert=%r id=%s status=success", cert.name, cert.id)
            result.deleted.append(cert.name)
        except Exception as e:
            audit.warning("AUDIT: DELETE cert=%r id=%s status=failed error=%r", cert.name, cert.id, str(e))
            result.failed.append((cert.name, str(e)))

    logger.info(
        "Cleanup complete: %d removed from trusted list, %d deleted, %d failed.",
        len(result.removed_from_trusted),
        len(result.deleted),
        len(result.failed),
    )
    return result
