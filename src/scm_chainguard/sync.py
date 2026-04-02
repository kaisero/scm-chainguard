"""Import missing certificates into SCM and update the trusted root CA list."""

from __future__ import annotations

import logging

from scm_chainguard.cert_utils import cert_import_name
from scm_chainguard.config import ScmConfig
from scm_chainguard.logging_setup import get_audit_logger
from scm_chainguard.models import LocalCertificate, SyncResult
from scm_chainguard.scm.identity_client import (
    CertificateImportError,
    ConflictError,
    IdentityClient,
)
from scm_chainguard.scm.security_client import SecurityClient

logger = logging.getLogger(__name__)
audit = get_audit_logger()

PROGRESS_REPORT_INTERVAL = 50

SKIP_ERRORS = {
    "Certificate is expired",
    "Unsupported digest or keys used in FIPS-CC mode",
}


def sync_certificates(
    missing: list[LocalCertificate],
    identity_client: IdentityClient,
    security_client: SecurityClient,
    config: ScmConfig,
    dry_run: bool = False,
    add_as_trusted_root: bool = True,
    ensure_trusted: list[str] | None = None,
) -> SyncResult:
    """Import missing certificates and optionally configure them as trusted roots.

    Args:
        ensure_trusted: Names of already-imported certs that should also be in
            the trusted_root_CA list (e.g. from a previous interrupted sync).
    """
    result = SyncResult(dry_run=dry_run)

    if not missing and not ensure_trusted:
        logger.info("No missing certificates to sync.")
        return result

    if missing:
        logger.info(
            "%s %d certificates...",
            "[DRY-RUN] Would import" if dry_run else "Importing",
            len(missing),
        )

    # Import certificates
    for i, cert in enumerate(missing, 1):
        name = cert_import_name(cert.filename)

        if dry_run:
            audit.info(
                "AUDIT: DRY_RUN would_import cert=%r folder=%r",
                name,
                config.cert_folder,
            )
            result.imported.append(name)
            continue

        try:
            identity_client.import_certificate(
                name, cert.pem, folder=config.cert_folder
            )
            audit.info(
                "AUDIT: IMPORT cert=%r folder=%r status=success",
                name,
                config.cert_folder,
            )
            result.imported.append(name)
        except ConflictError:
            audit.info(
                "AUDIT: IMPORT cert=%r status=skipped reason=already_exists", name
            )
            result.skipped.append(name)
        except CertificateImportError as e:
            if any(skip in str(e) for skip in SKIP_ERRORS):
                audit.info(
                    "AUDIT: IMPORT cert=%r status=skipped reason=%r", name, str(e)
                )
                result.skipped.append(name)
            else:
                audit.warning(
                    "AUDIT: IMPORT cert=%r status=failed error=%r", name, str(e)
                )
                result.failed.append((name, str(e)))

        if not dry_run and i % PROGRESS_REPORT_INTERVAL == 0:
            logger.info("  Progress: %d/%d certificates processed.", i, len(missing))

    # Update trusted root CA list — include both newly imported and already-imported-but-untrusted
    if add_as_trusted_root:
        all_to_trust = list(result.imported)
        if ensure_trusted:
            all_to_trust.extend(ensure_trusted)
        if all_to_trust:
            logger.info(
                "%s %d certificates to trusted root CA list...",
                "[DRY-RUN] Would ensure" if dry_run else "Ensuring",
                len(all_to_trust),
            )
            added = security_client.add_trusted_root_cas(all_to_trust, dry_run=dry_run)
            result.trusted_roots_added = added
            if added:
                audit.info(
                    "AUDIT: TRUSTED_ROOT_ADD certs=%d status=%s",
                    len(added),
                    "dry_run" if dry_run else "success",
                )

    # Summary
    logger.info(
        "Sync complete: %d imported, %d skipped, %d failed, %d trusted roots %s.",
        len(result.imported),
        len(result.skipped),
        len(result.failed),
        len(result.trusted_roots_added),
        "would be added" if dry_run else "added",
    )
    return result
