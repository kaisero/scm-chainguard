"""OAuth2 authentication for SCM APIs."""

from __future__ import annotations

import logging
import time

import requests

from scm_chainguard.config import ScmConfig

logger = logging.getLogger(__name__)

TOKEN_REFRESH_MARGIN = 60  # seconds before expiry to refresh


class AuthError(Exception):
    pass


class ScmAuthenticator:
    """Manages OAuth2 token lifecycle with automatic refresh."""

    def __init__(self, config: ScmConfig):
        self._config = config
        self._token: str | None = None
        self._expires_at: float = 0
        self._session = requests.Session()
        self._session.verify = config.ssl_verify

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> ScmAuthenticator:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get_token(self) -> str:
        """Return a valid token, refreshing if needed."""
        if self._token and time.time() < self._expires_at:
            return self._token
        self._refresh()
        return self._token  # type: ignore[return-value]

    def _refresh(self) -> None:
        url = f"{self._config.auth_url}/oauth2/access_token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "scope": f"tsg_id:{self._config.tsg_id}",
        }
        logger.debug(
            "POST %s payload=%s",
            url,
            {k: ("***" if k == "client_secret" else v) for k, v in payload.items()},
        )
        resp = self._session.post(url, data=payload, timeout=30)
        logger.debug("Response %d: %s", resp.status_code, resp.text)
        if not resp.ok:
            raise AuthError(f"Authentication failed: {resp.status_code} {resp.text}")
        data = resp.json()
        self._token = data["access_token"]
        expires_in = data.get("expires_in", 900)
        self._expires_at = time.time() + expires_in - TOKEN_REFRESH_MARGIN
        logger.info("Authenticated to SCM (token expires in %ds).", expires_in)

    def bearer_headers(self) -> dict[str, str]:
        """Headers for SCM APIs."""
        return {
            "Authorization": f"Bearer {self.get_token()}",
            "Content-Type": "application/json",
        }
