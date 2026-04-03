"""Shared test fixtures."""

from __future__ import annotations


import pytest

from scm_chainguard.models import (
    CcadbCertificate,
    CertType,
    CleanupResult,
    ComparisonResult,
    LocalCertificate,
    SyncResult,
)

SAMPLE_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIICOjCCAcGgAwIBAgIQQvLM2htpN0RfFf51KBC49DAKBggqhkjOPQQDAzBfMQsw\n"
    "CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1T\n"
    "ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwHhcN\n"
    "MjEwMzIyMDAwMDAwWhcNNDYwMzIxMjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYG\n"
    "A1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBT\n"
    "ZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQA\n"
    "IgNiAAR2+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccC\n"
    "WvkEN/U0NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+\n"
    "6xnOQ6OjQjBAMB0GA1UdDgQWBBTRItpMWfFLXyY4qp3W7usNw/upYTAOBgNVHQ8B\n"
    "Af8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAn7qRa\n"
    "qCG76UeXlImldCBteU/IvZNeWBj7LRoAasm4PdCkT0RHlAFWovgzJQxC36oCMB3q\n"
    "4S6ILuH5px0CMk7yn2xVdOOurvulGu7t0vzCAxHrRVxgED1cf5kDW21USAGKcw==\n"
    "-----END CERTIFICATE-----\n"
)

# SHA-256 of the Sectigo cert above
SAMPLE_SHA256 = "C90F26F0FB1B4018B22227519B5CA2B53E2CA5B3BE5CF18EFE1BEF47380C5383"
SAMPLE_CN = "Sectigo Public Server Authentication Root E46"

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
IDENTITY_URL = "https://api.strata.paloaltonetworks.com/config/identity/v1"
SECURITY_URL = "https://api.strata.paloaltonetworks.com/config/security/v1"
TRUSTED_CA_URL = f"{IDENTITY_URL}/trusted-certificate-authorities"


@pytest.fixture
def sample_config():
    from scm_chainguard.config import ScmConfig

    return ScmConfig(
        client_id="test-id",
        client_secret="test-secret",
        tsg_id="123456",
    )


@pytest.fixture
def mock_auth(sample_config):
    """Return a pre-authenticated ScmAuthenticator with a fake token."""
    from scm_chainguard.scm.auth import ScmAuthenticator

    auth = ScmAuthenticator(sample_config)
    auth._token = "test-token"
    auth._expires_at = 9999999999
    return auth


SAMPLE_PEM_NO_NEWLINE = SAMPLE_PEM.rstrip("\n")


def mock_auth_response():
    """Add a mock auth token response to the responses library."""
    import responses

    responses.add(
        responses.POST,
        AUTH_URL,
        json={"access_token": "test-token", "expires_in": 900},
        status=200,
    )


@pytest.fixture
def make_ccadb_cert():
    """Factory fixture for CcadbCertificate with sensible defaults."""

    def _make(
        sha256: str = "AAAA0001",
        common_name: str = "Test Root CA",
        ca_owner: str = "Test Org",
        cert_type: CertType = CertType.ROOT,
        parent_sha256: str | None = None,
        pem: str | None = None,
    ) -> CcadbCertificate:
        return CcadbCertificate(
            sha256_fingerprint=sha256,
            common_name=common_name,
            ca_owner=ca_owner,
            cert_type=cert_type,
            parent_sha256=parent_sha256,
            pem=pem,
        )

    return _make


@pytest.fixture
def make_local_cert():
    """Factory fixture for LocalCertificate with sensible defaults."""

    def _make(
        common_name: str = "Test CA",
        sha256: str = "AABB1122",
        cert_type: CertType = CertType.ROOT,
        pem: str = SAMPLE_PEM,
        filename: str | None = None,
    ) -> LocalCertificate:
        fname = filename or f"{common_name.replace(' ', '_')}_{sha256[:8]}.pem"
        return LocalCertificate(
            filepath=f"/tmp/{fname}",
            filename=fname,
            common_name=common_name,
            sha256_fingerprint=sha256,
            pem=pem,
            cert_type=cert_type,
        )

    return _make


@pytest.fixture
def sample_comparison_result(make_local_cert):
    """Pre-built ComparisonResult with present and missing certs."""
    present_cert = make_local_cert(common_name="Present CA", sha256="1111AAAA")
    missing_cert = make_local_cert(common_name="Missing CA", sha256="2222BBBB")
    return ComparisonResult(
        cert_type=CertType.ROOT,
        present=[(present_cert, "CG_Present_CA_1111AAAA")],
        missing=[missing_cert],
        total_local=2,
        total_scm=10,
    )


@pytest.fixture
def sample_sync_result():
    """Pre-built SyncResult for CLI tests."""
    return SyncResult(
        imported=["CG_NewCert_AABB1122"],
        skipped=["CG_OldCert_CCDD3344"],
        failed=[],
        trusted_roots_added=["CG_NewCert_AABB1122"],
        dry_run=False,
    )


@pytest.fixture
def sample_cleanup_result():
    """Pre-built CleanupResult for CLI tests."""
    return CleanupResult(
        removed_from_trusted=["CG_Expired_AABB1122"],
        deleted=["CG_Expired_AABB1122"],
        failed=[],
        dry_run=False,
    )
