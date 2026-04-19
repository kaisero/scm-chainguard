"""Pipeline orchestration: fetch, compare, sync, and full run."""

from __future__ import annotations

import logging
from pathlib import Path

from scm_chainguard.ccadb.client import CcadbClient
from scm_chainguard.ccadb.parser import attach_pems, collect_distrusted_fingerprints, parse_metadata
from scm_chainguard.cert_utils import CERT_PREFIX, load_local_certs, sanitize_filename
from scm_chainguard.compare import compare_intermediates, compare_roots
from scm_chainguard.config import ScmConfig
from scm_chainguard.models import CertType, CleanupResult, ComparisonResult, SyncResult, TrustStore
from scm_chainguard.scm.auth import ScmAuthenticator
from scm_chainguard.scm.identity_client import IdentityClient
from scm_chainguard.scm.security_client import SecurityClient
from scm_chainguard.sync import sync_certificates

logger = logging.getLogger(__name__)


def _save_certs(
    all_certs: dict,
    cert_type: CertType,
    directory: Path,
) -> int:
    """Save certificates of a given type to directory, returning count."""
    directory.mkdir(parents=True, exist_ok=True)
    count = 0
    for sha256, cert in all_certs.items():
        if cert.cert_type != cert_type:
            continue
        filename = sanitize_filename(cert.common_name, sha256)
        pem = cert.pem if cert.pem.endswith("\n") else cert.pem + "\n"
        (directory / filename).write_text(pem)
        count += 1
    return count


def run_fetch(
    config: ScmConfig,
    include_intermediates: bool = False,
    trust_store: TrustStore = TrustStore.CHROME,
) -> dict[str, Path]:
    """Download trusted certificates from CCADB and save to output directory."""
    output = Path(config.output_dir)
    roots_dir = output / "roots"

    ccadb = CcadbClient(timeout=config.request_timeout, verify=config.ssl_verify)

    metadata_csv = ccadb.download_metadata_csv()
    roots, intermediates = parse_metadata(metadata_csv, include_intermediates, trust_store=trust_store)

    all_certs = {**roots, **intermediates}
    logger.info("Need PEM data for %d certificates.", len(all_certs))
    pem_csvs = ccadb.download_all_pem_csvs()
    all_certs = attach_pems(all_certs, pem_csvs)

    root_count = _save_certs(all_certs, CertType.ROOT, roots_dir)
    logger.info("Saved %d root certificates to %s", root_count, roots_dir)

    result: dict[str, Path] = {"roots": roots_dir}

    if include_intermediates:
        intermediates_dir = output / "intermediates"
        int_count = _save_certs(all_certs, CertType.INTERMEDIATE, intermediates_dir)
        logger.info("Saved %d intermediate certificates to %s", int_count, intermediates_dir)
        result["intermediates"] = intermediates_dir

    return result


def run_compare(
    config: ScmConfig,
    include_intermediates: bool = False,
    *,
    trust_store: TrustStore = TrustStore.CHROME,
    auth: ScmAuthenticator | None = None,
    identity: IdentityClient | None = None,
) -> dict[str, ComparisonResult]:
    """Compare local certificates against SCM stores."""
    output = Path(config.output_dir)

    local_roots = load_local_certs(output / "roots", CertType.ROOT)
    logger.info("Loaded %d local root certificates.", len(local_roots))

    if auth is None:
        auth = ScmAuthenticator(config)
    if identity is None:
        identity = IdentityClient(config, auth)

    scm_predefined = identity.list_trusted_certificate_authorities()
    scm_imported = identity.list_certificates()

    results: dict[str, ComparisonResult] = {}
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
    trust_store: TrustStore = TrustStore.CHROME,
) -> dict[str, SyncResult]:
    """Compare and sync missing certificates to SCM."""
    auth = ScmAuthenticator(config)
    identity = IdentityClient(config, auth)
    security = SecurityClient(config, auth)

    comparisons = run_compare(config, include_intermediates, trust_store=trust_store, auth=auth, identity=identity)

    results: dict[str, SyncResult] = {}

    root_comp = comparisons["roots"]
    ensure_trusted = [scm_name for _, scm_name in root_comp.present if scm_name.startswith(CERT_PREFIX)]
    if ensure_trusted:
        logger.info(
            "Found %d already-imported CG_ certificates to ensure in trusted root CA list.",
            len(ensure_trusted),
        )

    if root_comp.missing or ensure_trusted:
        if root_comp.missing:
            logger.info("Syncing %d missing root certificates...", len(root_comp.missing))
        results["roots"] = sync_certificates(
            root_comp.missing,
            identity,
            security,
            config,
            dry_run=dry_run,
            add_as_trusted_root=True,
            ensure_trusted=ensure_trusted,
        )
    else:
        logger.info("All root certificates are already present in SCM.")
        results["roots"] = SyncResult(dry_run=dry_run)

    if include_intermediates and "intermediates" in comparisons:
        int_comp = comparisons["intermediates"]
        ensure_trusted_int = [scm_name for _, scm_name in int_comp.present if scm_name.startswith(CERT_PREFIX)]
        if ensure_trusted_int:
            logger.info(
                "Found %d already-imported CG_ intermediate certificates to ensure in trusted root CA list.",
                len(ensure_trusted_int),
            )

        if int_comp.missing or ensure_trusted_int:
            if int_comp.missing:
                logger.info("Syncing %d missing intermediate certificates...", len(int_comp.missing))
            results["intermediates"] = sync_certificates(
                int_comp.missing,
                identity,
                security,
                config,
                dry_run=dry_run,
                add_as_trusted_root=True,
                ensure_trusted=ensure_trusted_int,
            )
        else:
            logger.info("All intermediate certificates are already present in SCM.")
            results["intermediates"] = SyncResult(dry_run=dry_run)

    return results


def run_full_pipeline(
    config: ScmConfig,
    include_intermediates: bool = False,
    dry_run: bool = False,
    trust_store: TrustStore = TrustStore.CHROME,
) -> dict:
    """Full pipeline: fetch -> compare -> sync."""
    logger.info(
        "Starting full pipeline (store=%s, include_intermediates=%s, dry_run=%s)",
        trust_store.value,
        include_intermediates,
        dry_run,
    )

    logger.info("=" * 60)
    logger.info("STEP 1: Fetching certificates from CCADB")
    logger.info("=" * 60)
    fetch_result = run_fetch(config, include_intermediates, trust_store=trust_store)

    logger.info("=" * 60)
    logger.info("STEP 2: Comparing and syncing with SCM")
    logger.info("=" * 60)
    sync_results = run_sync(config, include_intermediates, dry_run, trust_store=trust_store)

    return {"fetch": fetch_result, "sync": sync_results}


def run_cleanup(
    config: ScmConfig,
    dry_run: bool = False,
    *,
    ignore_expiry_date: bool = False,
) -> CleanupResult:
    """Remove expired CG_-managed certificates from SCM.

    If *ignore_expiry_date* is True, **all** CG_-managed certificates are
    removed regardless of whether they have expired.
    """
    from scm_chainguard.logging_setup import get_audit_logger

    audit = get_audit_logger()
    result = CleanupResult(dry_run=dry_run)

    auth = ScmAuthenticator(config)
    identity = IdentityClient(config, auth)
    security = SecurityClient(config, auth)

    all_certs = identity.list_certificates()
    managed = [c for c in all_certs if c.name.startswith(CERT_PREFIX)]
    logger.info("Found %d CG_-managed certificates (of %d total).", len(managed), len(all_certs))

    if ignore_expiry_date:
        targets = [c for c in managed if c.pem]
        skipped = [c for c in managed if not c.pem]
        for cert in skipped:
            logger.warning("No PEM data for cert %r (id=%s), skipping.", cert.name, cert.id)
    else:
        from scm_chainguard.cert_utils import is_cert_expired

        targets = []
        for cert in managed:
            if not cert.pem:
                logger.warning("No PEM data for cert %r (id=%s), skipping.", cert.name, cert.id)
                continue
            try:
                if is_cert_expired(cert.pem):
                    targets.append(cert)
            except Exception as e:
                logger.warning("Could not parse cert %r: %s", cert.name, e, exc_info=True)

    if not targets:
        logger.info("No %sCG_-managed certificates found.", "" if ignore_expiry_date else "expired ")
        return result

    label = "all" if ignore_expiry_date else "expired"
    logger.info(
        "%s %d %s certificates...",
        "[DRY-RUN] Would remove" if dry_run else "Removing",
        len(targets),
        label,
    )

    target_names = [c.name for c in targets]
    removed = security.remove_trusted_root_cas(target_names, dry_run=dry_run)
    result.removed_from_trusted = removed

    for cert in targets:
        if dry_run:
            audit.info("AUDIT: DRY_RUN would_delete cert=%r id=%s", cert.name, cert.id)
            result.deleted.append(cert.name)
            continue
        try:
            identity.delete_certificate(cert.id)
            audit.info("AUDIT: DELETE cert=%r id=%s status=success", cert.name, cert.id)
            result.deleted.append(cert.name)
        except Exception as e:
            audit.warning(
                "AUDIT: DELETE cert=%r id=%s status=failed error=%r",
                cert.name,
                cert.id,
                str(e),
            )
            result.failed.append((cert.name, str(e)))

    logger.info(
        "Cleanup complete: %d removed from trusted list, %d deleted, %d failed.",
        len(result.removed_from_trusted),
        len(result.deleted),
        len(result.failed),
    )
    return result


def run_revoke(
    config: ScmConfig,
    dry_run: bool = False,
    trust_store: TrustStore = TrustStore.CHROME,
) -> CleanupResult:
    """Remove CG_-managed certificates from SCM that are distrusted (Removed/Blocked) in CCADB."""
    from scm_chainguard.logging_setup import get_audit_logger

    audit = get_audit_logger()
    result = CleanupResult(dry_run=dry_run)

    # 1. Fetch distrusted fingerprints from CCADB
    ccadb = CcadbClient(timeout=config.request_timeout, verify=config.ssl_verify)
    metadata_csv = ccadb.download_metadata_csv()
    distrusted = collect_distrusted_fingerprints(metadata_csv, trust_store)
    if not distrusted:
        logger.info("No distrusted certificates found in CCADB for store '%s'.", trust_store.value)
        return result

    # 2. Fetch CG_-managed certs from SCM
    auth = ScmAuthenticator(config)
    identity = IdentityClient(config, auth)
    security = SecurityClient(config, auth)

    all_certs = identity.list_certificates()
    managed = [c for c in all_certs if c.name.startswith(CERT_PREFIX)]
    logger.info("Found %d CG_-managed certificates (of %d total).", len(managed), len(all_certs))

    # 3. Intersect: managed certs whose SHA-256 is in the distrusted set
    to_revoke = [c for c in managed if c.sha256_fingerprint and c.sha256_fingerprint in distrusted]

    if not to_revoke:
        logger.info("No CG_-managed certificates match distrusted CCADB entries.")
        return result

    logger.info(
        "%s %d distrusted certificates...",
        "[DRY-RUN] Would revoke" if dry_run else "Revoking",
        len(to_revoke),
    )

    # 4. Remove from trusted root CA list
    revoke_names = [c.name for c in to_revoke]
    removed = security.remove_trusted_root_cas(revoke_names, dry_run=dry_run)
    result.removed_from_trusted = removed

    # 5. Delete certificate objects
    for cert in to_revoke:
        if dry_run:
            audit.info("AUDIT: DRY_RUN would_delete cert=%r id=%s reason=distrusted", cert.name, cert.id)
            result.deleted.append(cert.name)
            continue
        try:
            identity.delete_certificate(cert.id)
            audit.info("AUDIT: DELETE cert=%r id=%s status=success reason=distrusted", cert.name, cert.id)
            result.deleted.append(cert.name)
        except Exception as e:
            audit.warning(
                "AUDIT: DELETE cert=%r id=%s status=failed error=%r",
                cert.name,
                cert.id,
                str(e),
            )
            result.failed.append((cert.name, str(e)))

    logger.info(
        "Revoke complete: %d removed from trusted list, %d deleted, %d failed.",
        len(result.removed_from_trusted),
        len(result.deleted),
        len(result.failed),
    )
    return result
