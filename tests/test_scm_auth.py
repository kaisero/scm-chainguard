"""Tests for SCM OAuth2 authentication."""

import time
import responses
import pytest
from scm_chainguard.scm.auth import AuthError, ScmAuthenticator
from tests.conftest import AUTH_URL


class TestScmAuthenticator:
    @responses.activate
    def test_authenticate_success(self, sample_config):
        responses.add(responses.POST, AUTH_URL,
                       json={"access_token": "tok-1", "expires_in": 900}, status=200)
        auth = ScmAuthenticator(sample_config)
        assert auth.get_token() == "tok-1"

    @responses.activate
    def test_token_caching(self, sample_config):
        responses.add(responses.POST, AUTH_URL,
                       json={"access_token": "tok-1", "expires_in": 900}, status=200)
        auth = ScmAuthenticator(sample_config)
        auth.get_token()
        auth.get_token()
        assert len(responses.calls) == 1

    @responses.activate
    def test_token_refresh_on_expiry(self, sample_config):
        responses.add(responses.POST, AUTH_URL,
                       json={"access_token": "tok-1", "expires_in": 1}, status=200)
        responses.add(responses.POST, AUTH_URL,
                       json={"access_token": "tok-2", "expires_in": 900}, status=200)
        auth = ScmAuthenticator(sample_config)
        auth.get_token()
        auth._expires_at = time.time() - 10  # force expiry
        assert auth.get_token() == "tok-2"

    @responses.activate
    def test_auth_failure_raises(self, sample_config):
        responses.add(responses.POST, AUTH_URL, json={"error": "invalid"}, status=401)
        auth = ScmAuthenticator(sample_config)
        with pytest.raises(AuthError):
            auth.get_token()

    def test_bearer_headers(self, mock_auth):
        headers = mock_auth.bearer_headers()
        assert headers["Authorization"] == "Bearer test-token"
        assert "Content-Type" in headers
