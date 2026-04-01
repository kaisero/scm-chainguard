"""Identity API client for managing imported certificates."""

from __future__ import annotations

import logging

import requests

from scm_chainguard.cert_utils import pem_to_base64, pem_to_sha256
from scm_chainguard.config import ScmConfig
from scm_chainguard.models import ScmImportedCert, ScmPredefinedRoot
from scm_chainguard.scm.auth import ScmAuthenticator

logger = logging.getLogger(__name__)


class ImportError(Exception):
    """Raised when a certificate import fails."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ConflictError(ImportError):
    """Raised on 409 Conflict (certificate already exists)."""
    pass


class IdentityClient:
    """CRUD operations on the SCM certificate store via the Identity API."""

    def __init__(self, config: ScmConfig, auth: ScmAuthenticator):
        self._config = config
        self._auth = auth
        self._session = requests.Session()

    def list_trusted_certificate_authorities(
        self, folder: str = "Prisma Access",
    ) -> list[ScmPredefinedRoot]:
        """List all predefined trusted root CAs (paginated)."""
        url = f"{self._config.identity_url}/trusted-certificate-authorities"
        all_cas: list[ScmPredefinedRoot] = []
        offset = 0
        limit = 200

        logger.debug("Listing trusted CAs from %s (folder=%s)", url, folder)

        while True:
            resp = self._session.get(
                url,
                headers=self._auth.bearer_headers(),
                params={"folder": folder, "limit": limit, "offset": offset},
                timeout=self._config.request_timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            page_items = data.get("data", [])
            total = data.get("total", 0)
            logger.debug(
                "  Page offset=%d: got %d items (total=%d)",
                offset, len(page_items), total,
            )

            for item in page_items:
                all_cas.append(
                    ScmPredefinedRoot(
                        name=item.get("name", ""),
                        common_name=item.get("common_name", "").strip(),
                        subject=item.get("subject", ""),
                        filename=item.get("filename", ""),
                        not_valid_after=item.get("not_valid_after", ""),
                        expiry_epoch=item.get("expiry_epoch", ""),
                    )
                )

            offset += limit
            if offset >= total:
                break

        logger.info("Found %d predefined trusted root CAs.", len(all_cas))
        return all_cas

    def list_certificates(self, folder: str = "Prisma Access") -> list[ScmImportedCert]:
        """List all imported certificates (paginated)."""
        url = f"{self._config.identity_url}/certificates"
        all_certs: list[ScmImportedCert] = []
        offset = 0
        limit = 200

        logger.debug("Listing certificates from %s (folder=%s)", url, folder)

        while True:
            resp = self._session.get(
                url,
                headers=self._auth.bearer_headers(),
                params={"folder": folder, "limit": limit, "offset": offset},
                timeout=self._config.request_timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            page_items = data.get("data", [])
            total = data.get("total", 0)
            logger.debug(
                "  Page offset=%d: got %d items (total=%d)",
                offset, len(page_items), total,
            )

            for item in page_items:
                pem = item.get("public_key", "")
                sha256 = None
                valid_pem = pem and "-----BEGIN CERTIFICATE-----" in pem
                if valid_pem:
                    try:
                        sha256 = pem_to_sha256(pem)
                    except Exception:
                        pass
                all_certs.append(
                    ScmImportedCert(
                        id=item.get("id", ""),
                        name=item.get("name", ""),
                        common_name=item.get("common_name", ""),
                        sha256_fingerprint=sha256,
                        folder=item.get("folder", ""),
                        pem=pem if valid_pem else None,
                    )
                )

            offset += limit
            if offset >= total:
                break

        logger.info("Found %d imported certificates in SCM.", len(all_certs))
        return all_certs

    def import_certificate(self, name: str, pem_text: str, folder: str = "All") -> dict:
        """Import a PEM certificate into SCM.

        Raises ConflictError on 409, ImportError on other failures.
        """
        url = f"{self._config.identity_url}/certificates:import"
        body = {
            "name": name,
            "certificate_file": pem_to_base64(pem_text),
            "format": "pem",
            "folder": folder,
        }
        logger.debug(
            "POST %s — name=%r folder=%r pem_length=%d",
            url, name, folder, len(pem_text),
        )
        resp = self._session.post(
            url,
            json=body,
            headers=self._auth.bearer_headers(),
            timeout=self._config.request_timeout,
        )
        logger.debug(
            "Response %d for cert %r: %s",
            resp.status_code, name, resp.text,
        )
        if resp.status_code == 409:
            raise ConflictError(f"Certificate '{name}' already exists", 409)
        if not resp.ok:
            # Extract the most detailed error message available
            msg = resp.text
            try:
                body = resp.json()
                errors = body.get("_errors", [])
                if errors:
                    error = errors[0]
                    details = error.get("details", {})
                    detail_errors = details.get("errors", []) if isinstance(details, dict) else []
                    if detail_errors:
                        msgs = [d.get("msg", "") or d.get("message", "") for d in detail_errors]
                        msg = "; ".join(m for m in msgs if m) or error.get("message", msg)
                    else:
                        msg = error.get("message", msg)
                    if isinstance(details, dict) and details:
                        msg = f"{msg} (details: {details})"
            except Exception:
                pass
            raise ImportError(
                f"HTTP {resp.status_code}: {msg}",
                resp.status_code,
            )

        logger.debug("Imported certificate '%s' to folder '%s'.", name, folder)
        return resp.json()

    def delete_certificate(self, cert_id: str) -> None:
        """Delete a certificate by ID.

        Raises ImportError on failure.
        """
        url = f"{self._config.identity_url}/certificates/{cert_id}"
        logger.debug("DELETE %s", url)
        resp = self._session.delete(
            url,
            headers=self._auth.bearer_headers(),
            timeout=self._config.request_timeout,
        )
        if not resp.ok:
            msg = resp.text
            try:
                body = resp.json()
                errors = body.get("_errors", [])
                if errors:
                    msg = errors[0].get("message", msg)
            except Exception:
                pass
            raise ImportError(
                f"HTTP {resp.status_code}: {msg}",
                resp.status_code,
            )
        logger.debug("Deleted certificate %s.", cert_id)
