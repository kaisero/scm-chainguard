"""Security API client for SSL decryption settings."""

from __future__ import annotations

import logging

import requests

from scm_chainguard.config import ScmConfig
from scm_chainguard.scm import extract_error_message
from scm_chainguard.scm.auth import ScmAuthenticator

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when an SSL decryption settings update fails."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class SecurityClient:
    """Manages SSL decryption settings (trusted root CA list)."""

    def __init__(self, config: ScmConfig, auth: ScmAuthenticator):
        self._config = config
        self._auth = auth
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> SecurityClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get_ssl_decryption_settings(self) -> dict | None:
        """Get the SSL decryption settings singleton."""
        url = f"{self._config.security_url}/ssl-decryption-settings"
        resp = self._session.get(
            url,
            headers=self._auth.bearer_headers(),
            params={"folder": self._config.ssl_settings_folder},
            timeout=self._config.request_timeout,
        )
        resp.raise_for_status()
        entries = resp.json().get("data", [])
        if not entries:
            logger.warning("No SSL decryption settings found.")
            return None
        return entries[0]

    def get_trusted_root_ca_list(self) -> list[str]:
        """Extract the trusted_root_CA name list from SSL decryption settings."""
        settings = self.get_ssl_decryption_settings()
        if settings is None:
            return []
        return settings.get("ssl_decrypt", {}).get("trusted_root_CA", [])

    def _put_settings(self, settings: dict) -> None:
        """PUT updated settings, raising SecurityError with full detail on failure."""
        url = f"{self._config.security_url}/ssl-decryption-settings"
        resp = self._session.put(
            url,
            json=settings,
            headers=self._auth.bearer_headers(),
            timeout=self._config.request_timeout,
        )
        if not resp.ok:
            raise SecurityError(
                f"HTTP {resp.status_code}: {extract_error_message(resp)}",
                resp.status_code,
            )

    def add_trusted_root_cas(
        self,
        cert_names: list[str],
        dry_run: bool = False,
    ) -> list[str]:
        """Add certificate names to the trusted_root_CA list.

        Returns list of names actually added (excluding already-present ones).
        """
        settings = self.get_ssl_decryption_settings()
        if settings is None:
            logger.error("Cannot update trusted roots: no SSL decryption settings found.")
            return []

        ssl_decrypt = settings.get("ssl_decrypt", {})
        current = set(ssl_decrypt.get("trusted_root_CA", []))
        to_add = [n for n in cert_names if n not in current]

        if not to_add:
            logger.info("All %d certificates are already in trusted_root_CA.", len(cert_names))
            return []

        if dry_run:
            logger.info("[DRY-RUN] Would add %d certificates to trusted_root_CA.", len(to_add))
            return to_add

        new_list = sorted(current | set(to_add))
        ssl_decrypt["trusted_root_CA"] = new_list
        settings["ssl_decrypt"] = ssl_decrypt

        self._put_settings(settings)
        logger.info("Added %d certificates to trusted_root_CA list.", len(to_add))
        return to_add

    def remove_trusted_root_cas(
        self,
        cert_names: list[str],
        dry_run: bool = False,
    ) -> list[str]:
        """Remove certificate names from the trusted_root_CA list.

        Returns list of names actually removed.
        """
        settings = self.get_ssl_decryption_settings()
        if settings is None:
            logger.error("Cannot update trusted roots: no SSL decryption settings found.")
            return []

        ssl_decrypt = settings.get("ssl_decrypt", {})
        current = ssl_decrypt.get("trusted_root_CA", [])
        names_to_remove = set(cert_names)
        to_remove = [n for n in current if n in names_to_remove]

        if not to_remove:
            logger.info("None of the %d certificates are in trusted_root_CA.", len(cert_names))
            return []

        if dry_run:
            logger.info(
                "[DRY-RUN] Would remove %d certificates from trusted_root_CA.",
                len(to_remove),
            )
            return to_remove

        new_list = [n for n in current if n not in names_to_remove]
        ssl_decrypt["trusted_root_CA"] = new_list
        settings["ssl_decrypt"] = ssl_decrypt

        self._put_settings(settings)
        logger.info("Removed %d certificates from trusted_root_CA list.", len(to_remove))
        return to_remove
