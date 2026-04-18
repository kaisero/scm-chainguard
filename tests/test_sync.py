"""Tests for sync logic."""

import logging
from unittest.mock import patch

import responses
from scm_chainguard.models import CertType, LocalCertificate
from scm_chainguard.scm.identity_client import IdentityClient
from scm_chainguard.scm.security_client import SecurityClient
from scm_chainguard.sync import sync_certificates
from tests.conftest import IDENTITY_URL, SECURITY_URL, SAMPLE_PEM


SSL_SETTINGS_URL = f"{SECURITY_URL}/ssl-decryption-settings"


def _missing_cert(name: str = "Test_CA_AABB1122") -> LocalCertificate:
    return LocalCertificate(
        filepath=f"/tmp/{name}.pem",
        filename=f"{name}.pem",
        common_name="Test CA",
        sha256_fingerprint="AABB1122",
        pem=SAMPLE_PEM,
        cert_type=CertType.ROOT,
    )


class TestSyncCertificates:
    @responses.activate
    def test_import_and_trust(self, sample_config, mock_auth):
        # Import
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"id": "new"},
            status=200,
        )
        # GET ssl settings
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )
        # PUT ssl settings
        responses.add(responses.PUT, SSL_SETTINGS_URL, json={"@status": "success"}, status=200)

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [_missing_cert()],
            identity,
            security,
            sample_config,
        )
        assert len(result.imported) == 1
        assert result.imported[0].startswith("CG_")
        assert len(result.trusted_roots_added) == 1

    @responses.activate
    def test_dry_run(self, sample_config, mock_auth):
        # GET ssl settings only (for dry run trusted root check)
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [_missing_cert()],
            identity,
            security,
            sample_config,
            dry_run=True,
        )
        assert result.dry_run is True
        assert len(result.imported) == 1
        # No POST or PUT calls (only GET for dry-run trusted root check)
        post_calls = [c for c in responses.calls if c.request.method == "POST"]
        put_calls = [c for c in responses.calls if c.request.method == "PUT"]
        assert len(post_calls) == 0
        assert len(put_calls) == 0

    @responses.activate
    def test_conflict_skipped(self, sample_config, mock_auth):
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"_errors": [{"message": "Name Not Unique"}]},
            status=409,
        )
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [_missing_cert()],
            identity,
            security,
            sample_config,
        )
        assert len(result.skipped) == 1
        assert len(result.imported) == 0

    def test_empty_list(self, sample_config, mock_auth):
        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates([], identity, security, sample_config)
        assert len(result.imported) == 0

    @responses.activate
    def test_ensure_trusted_adds_already_imported(self, sample_config, mock_auth):
        """Already-imported certs passed via ensure_trusted are added to trusted list."""
        # GET ssl settings
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )
        # PUT ssl settings
        responses.add(responses.PUT, SSL_SETTINGS_URL, json={"@status": "success"}, status=200)

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [],
            identity,
            security,
            sample_config,
            ensure_trusted=["CG_Existing_Cert_AABB1122"],
        )
        assert len(result.imported) == 0
        assert result.trusted_roots_added == ["CG_Existing_Cert_AABB1122"]

    @responses.activate
    def test_ensure_trusted_combined_with_imports(self, sample_config, mock_auth):
        """Newly imported and ensure_trusted names are both added to trusted list."""
        # Import
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"id": "new"},
            status=200,
        )
        # GET ssl settings
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )
        # PUT ssl settings
        responses.add(responses.PUT, SSL_SETTINGS_URL, json={"@status": "success"}, status=200)

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [_missing_cert()],
            identity,
            security,
            sample_config,
            ensure_trusted=["CG_Already_There_11223344"],
        )
        assert len(result.imported) == 1
        assert len(result.trusted_roots_added) == 2

    @responses.activate
    def test_ensure_trusted_skips_already_trusted(self, sample_config, mock_auth):
        """ensure_trusted names already in the list are not re-added."""
        # GET ssl settings — cert is already trusted
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={
                "data": [
                    {
                        "folder": "All",
                        "ssl_decrypt": {"trusted_root_CA": ["CG_Already_Trusted"]},
                    }
                ]
            },
            status=200,
        )

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [],
            identity,
            security,
            sample_config,
            ensure_trusted=["CG_Already_Trusted"],
        )
        assert result.trusted_roots_added == []
        # No PUT call needed
        put_calls = [c for c in responses.calls if c.request.method == "PUT"]
        assert len(put_calls) == 0

    @responses.activate
    def test_ensure_trusted_dry_run(self, sample_config, mock_auth):
        """Dry run with ensure_trusted shows what would be added without changes."""
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [],
            identity,
            security,
            sample_config,
            dry_run=True,
            ensure_trusted=["CG_Existing_Cert_AABB1122"],
        )
        assert result.trusted_roots_added == ["CG_Existing_Cert_AABB1122"]
        put_calls = [c for c in responses.calls if c.request.method == "PUT"]
        assert len(put_calls) == 0

    @responses.activate
    @patch("scm_chainguard.sync.is_cert_expired", return_value=True)
    def test_expired_cert_skipped_before_import(self, mock_expired, sample_config, mock_auth, caplog):
        """Expired certificates are skipped without making an API call."""
        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        with caplog.at_level(logging.WARNING, logger="scm_chainguard.sync"):
            result = sync_certificates(
                [_missing_cert()],
                identity,
                security,
                sample_config,
            )
        assert len(result.skipped) == 1
        assert len(result.imported) == 0
        # No HTTP calls should have been made for the import
        post_calls = [c for c in responses.calls if c.request.method == "POST"]
        assert len(post_calls) == 0
        assert "Skipping expired certificate" in caplog.text

    @responses.activate
    @patch("scm_chainguard.sync.is_cert_expired", side_effect=Exception("parse error"))
    def test_expired_check_parse_error_continues(self, mock_expired, sample_config, mock_auth):
        """If expiry check fails, import proceeds normally."""
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"id": "new"},
            status=200,
        )
        responses.add(
            responses.GET,
            SSL_SETTINGS_URL,
            json={"data": [{"folder": "All", "ssl_decrypt": {"trusted_root_CA": []}}]},
            status=200,
        )
        responses.add(responses.PUT, SSL_SETTINGS_URL, json={"@status": "success"}, status=200)

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        result = sync_certificates(
            [_missing_cert()],
            identity,
            security,
            sample_config,
        )
        assert len(result.imported) == 1
        assert len(result.skipped) == 0

    @responses.activate
    def test_skip_error_from_api_skipped(self, sample_config, mock_auth, caplog):
        """API errors matching SKIP_ERRORS are classified as skipped, not failed."""
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={
                "_errors": [
                    {
                        "code": "API_I00013",
                        "message": "Your configuration is not valid.",
                        "details": {
                            "errorType": "Operation Failed",
                            "message": "Import of CG_Test failed. Certificate is expired",
                            "errors": [],
                        },
                    }
                ]
            },
            status=400,
        )

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        with caplog.at_level(logging.WARNING, logger="scm_chainguard.sync"):
            result = sync_certificates(
                [_missing_cert()],
                identity,
                security,
                sample_config,
                add_as_trusted_root=False,
            )
        assert len(result.skipped) == 1
        assert len(result.failed) == 0
        assert "Skipping certificate" in caplog.text

    @responses.activate
    def test_non_skip_error_logged_as_error(self, sample_config, mock_auth, caplog):
        """Non-skip API errors are logged at ERROR level and added to failed list."""
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={
                "_errors": [
                    {
                        "message": "Unknown internal error",
                        "details": {},
                    }
                ]
            },
            status=500,
        )

        identity = IdentityClient(sample_config, mock_auth)
        security = SecurityClient(sample_config, mock_auth)
        with caplog.at_level(logging.ERROR, logger="scm_chainguard.sync"):
            result = sync_certificates(
                [_missing_cert()],
                identity,
                security,
                sample_config,
                add_as_trusted_root=False,
            )
        assert len(result.failed) == 1
        assert len(result.skipped) == 0
        assert "Failed to import certificate" in caplog.text
