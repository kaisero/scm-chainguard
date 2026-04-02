"""Tests for Security API client (SSL decryption settings)."""

import responses
import pytest
from scm_chainguard.scm.security_client import SecurityClient, SecurityError
from tests.conftest import SECURITY_URL


SSL_SETTINGS_URL = f"{SECURITY_URL}/ssl-decryption-settings"

SAMPLE_SETTINGS = {
    "data": [
        {
            "folder": "All",
            "ssl_decrypt": {
                "trusted_root_CA": ["existing-cert"],
                "forward_trust_certificate": {"rsa": "test"},
            },
        }
    ],
    "total": 1,
}


class TestGetSslDecryptionSettings:
    @responses.activate
    def test_returns_settings(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        client = SecurityClient(sample_config, mock_auth)
        result = client.get_ssl_decryption_settings()
        assert result is not None
        assert "ssl_decrypt" in result

    @responses.activate
    def test_returns_none_when_empty(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json={"data": [], "total": 0}, status=200)
        client = SecurityClient(sample_config, mock_auth)
        assert client.get_ssl_decryption_settings() is None


class TestGetTrustedRootCaList:
    @responses.activate
    def test_extracts_list(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        client = SecurityClient(sample_config, mock_auth)
        result = client.get_trusted_root_ca_list()
        assert result == ["existing-cert"]


class TestAddTrustedRootCas:
    @responses.activate
    def test_adds_new_certs(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        responses.add(responses.PUT, SSL_SETTINGS_URL, json={"@status": "success"}, status=200)
        client = SecurityClient(sample_config, mock_auth)
        added = client.add_trusted_root_cas(["new-cert-1", "new-cert-2"])
        assert set(added) == {"new-cert-1", "new-cert-2"}
        # Verify PUT payload
        import json

        body = json.loads(responses.calls[1].request.body)
        trusted = body["ssl_decrypt"]["trusted_root_CA"]
        assert "existing-cert" in trusted
        assert "new-cert-1" in trusted

    @responses.activate
    def test_idempotent(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        client = SecurityClient(sample_config, mock_auth)
        added = client.add_trusted_root_cas(["existing-cert"])
        assert added == []
        assert len(responses.calls) == 1  # only GET, no PUT

    @responses.activate
    def test_dry_run(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        client = SecurityClient(sample_config, mock_auth)
        added = client.add_trusted_root_cas(["new-cert"], dry_run=True)
        assert added == ["new-cert"]
        assert len(responses.calls) == 1  # only GET, no PUT

    @responses.activate
    def test_put_error_raises_with_detail(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        responses.add(
            responses.PUT,
            SSL_SETTINGS_URL,
            json={
                "_errors": [
                    {
                        "code": "API_I00013",
                        "message": "Invalid Object",
                        "details": {
                            "errors": [{"msg": "'bad-cert' is not a valid reference"}],
                        },
                    }
                ],
            },
            status=400,
        )
        client = SecurityClient(sample_config, mock_auth)
        with pytest.raises(SecurityError, match="not a valid reference") as exc_info:
            client.add_trusted_root_cas(["bad-cert"])
        assert exc_info.value.status_code == 400


class TestRemoveTrustedRootCas:
    @responses.activate
    def test_removes_certs(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        responses.add(responses.PUT, SSL_SETTINGS_URL, json={"@status": "success"}, status=200)
        client = SecurityClient(sample_config, mock_auth)
        removed = client.remove_trusted_root_cas(["existing-cert"])
        assert removed == ["existing-cert"]
        # Verify PUT payload
        import json

        body = json.loads(responses.calls[1].request.body)
        trusted = body["ssl_decrypt"]["trusted_root_CA"]
        assert "existing-cert" not in trusted

    @responses.activate
    def test_no_match_skips_put(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        client = SecurityClient(sample_config, mock_auth)
        removed = client.remove_trusted_root_cas(["nonexistent-cert"])
        assert removed == []
        assert len(responses.calls) == 1  # only GET, no PUT

    @responses.activate
    def test_dry_run(self, sample_config, mock_auth):
        responses.add(responses.GET, SSL_SETTINGS_URL, json=SAMPLE_SETTINGS, status=200)
        client = SecurityClient(sample_config, mock_auth)
        removed = client.remove_trusted_root_cas(["existing-cert"], dry_run=True)
        assert removed == ["existing-cert"]
        assert len(responses.calls) == 1  # only GET, no PUT
