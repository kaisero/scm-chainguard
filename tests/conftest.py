"""Shared test fixtures."""

import pytest

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


def mock_auth_response():
    """Add a mock auth token response to the responses library."""
    import responses

    responses.add(
        responses.POST,
        AUTH_URL,
        json={"access_token": "test-token", "expires_in": 900},
        status=200,
    )
