"""Tests for Identity API client."""

import responses
import pytest
from scm_chainguard.scm.identity_client import (
    CertificateImportError,
    ConflictError,
    IdentityClient,
)
from tests.conftest import IDENTITY_URL, SAMPLE_PEM, TRUSTED_CA_URL


SAMPLE_TRUSTED_CA_RESPONSE = {
    "data": [
        {
            "name": "0001_Test_Root",
            "snippet": "predefined",
            "filename": "0001_Test_Root.cer",
            "subject": "/CN=Test Root",
            "common_name": "Test Root",
            "issuer": "/CN=Test Root",
            "serial_number": "00",
            "not_valid_after": "Dec 31 23:59:59 2040 GMT",
            "not_valid_before": "Jan 1 00:00:00 2020 GMT",
            "expiry_epoch": "2240611199",
        },
        {
            "name": "0002_Other_Root",
            "snippet": "predefined",
            "filename": "0002_Other_Root.cer",
            "subject": "/CN=Other Root",
            "common_name": "Other Root",
            "issuer": "/CN=Other Root",
            "serial_number": "01",
            "not_valid_after": "Jun 15 12:00:00 2035 GMT",
            "not_valid_before": "Jun 15 12:00:00 2015 GMT",
            "expiry_epoch": "2065867200",
        },
    ],
    "offset": 0,
    "total": 2,
    "limit": 200,
}


class TestListTrustedCertificateAuthorities:
    @responses.activate
    def test_returns_predefined_roots(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            TRUSTED_CA_URL,
            json=SAMPLE_TRUSTED_CA_RESPONSE,
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_trusted_certificate_authorities()
        assert len(result) == 2
        assert result[0].name == "0001_Test_Root"
        assert result[0].common_name == "Test Root"
        assert result[0].subject == "/CN=Test Root"
        assert result[0].filename == "0001_Test_Root.cer"
        assert result[0].not_valid_after == "Dec 31 23:59:59 2040 GMT"
        assert result[0].expiry_epoch == "2240611199"

    @responses.activate
    def test_pagination(self, sample_config, mock_auth):
        page1 = {
            "data": [
                {
                    "name": f"root_{i}",
                    "common_name": f"Root {i}",
                    "snippet": "predefined",
                }
                for i in range(200)
            ],
            "total": 346,
            "limit": 200,
            "offset": 0,
        }
        page2 = {
            "data": [
                {
                    "name": f"root_{i}",
                    "common_name": f"Root {i}",
                    "snippet": "predefined",
                }
                for i in range(200, 346)
            ],
            "total": 346,
            "limit": 200,
            "offset": 200,
        }
        responses.add(responses.GET, TRUSTED_CA_URL, json=page1, status=200)
        responses.add(responses.GET, TRUSTED_CA_URL, json=page2, status=200)
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_trusted_certificate_authorities()
        assert len(result) == 346

    @responses.activate
    def test_uses_bearer_auth(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            TRUSTED_CA_URL,
            json={"data": [], "total": 0, "limit": 200, "offset": 0},
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        client.list_trusted_certificate_authorities()
        assert "Authorization" in responses.calls[0].request.headers
        assert responses.calls[0].request.headers["Authorization"] == "Bearer test-token"

    @responses.activate
    def test_strips_common_name_whitespace(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            TRUSTED_CA_URL,
            json={
                "data": [
                    {
                        "name": "test",
                        "common_name": "  Padded CN  ",
                        "snippet": "predefined",
                    }
                ],
                "total": 1,
                "limit": 200,
                "offset": 0,
            },
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_trusted_certificate_authorities()
        assert result[0].common_name == "Padded CN"

    @responses.activate
    def test_empty_result(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            TRUSTED_CA_URL,
            json={"data": [], "total": 0, "limit": 200, "offset": 0},
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_trusted_certificate_authorities()
        assert result == []


class TestListCertificates:
    @responses.activate
    def test_single_page(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            f"{IDENTITY_URL}/certificates",
            json={
                "data": [
                    {
                        "id": "u1",
                        "name": "cert-1",
                        "folder": "All",
                        "common_name": "Test",
                    }
                ],
                "total": 1,
                "limit": 200,
                "offset": 0,
            },
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_certificates()
        assert len(result) == 1
        assert result[0].name == "cert-1"

    @responses.activate
    def test_pagination(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            f"{IDENTITY_URL}/certificates",
            json={
                "data": [
                    {
                        "id": f"u{i}",
                        "name": f"cert-{i}",
                        "folder": "All",
                        "common_name": "",
                    }
                    for i in range(200)
                ],
                "total": 250,
                "limit": 200,
                "offset": 0,
            },
            status=200,
        )
        responses.add(
            responses.GET,
            f"{IDENTITY_URL}/certificates",
            json={
                "data": [
                    {
                        "id": f"u{i}",
                        "name": f"cert-{i}",
                        "folder": "All",
                        "common_name": "",
                    }
                    for i in range(200, 250)
                ],
                "total": 250,
                "limit": 200,
                "offset": 200,
            },
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_certificates()
        assert len(result) == 250


class TestImportCertificate:
    @responses.activate
    def test_success(self, sample_config, mock_auth):
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"id": "new-id", "name": "test-cert"},
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.import_certificate("test-cert", SAMPLE_PEM)
        assert result["id"] == "new-id"

    @responses.activate
    def test_conflict_raises(self, sample_config, mock_auth):
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"_errors": [{"message": "Name Not Unique"}]},
            status=409,
        )
        client = IdentityClient(sample_config, mock_auth)
        with pytest.raises(ConflictError):
            client.import_certificate("test-cert", SAMPLE_PEM)

    @responses.activate
    def test_error_raises(self, sample_config, mock_auth):
        responses.add(
            responses.POST,
            f"{IDENTITY_URL}/certificates:import",
            json={"_errors": [{"message": "Invalid Object"}]},
            status=400,
        )
        client = IdentityClient(sample_config, mock_auth)
        with pytest.raises(CertificateImportError) as exc_info:
            client.import_certificate("test-cert", SAMPLE_PEM)
        assert exc_info.value.status_code == 400


class TestDeleteCertificate:
    @responses.activate
    def test_success(self, sample_config, mock_auth):
        responses.add(
            responses.DELETE,
            f"{IDENTITY_URL}/certificates/cert-123",
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        client.delete_certificate("cert-123")
        assert len(responses.calls) == 1

    @responses.activate
    def test_error_raises(self, sample_config, mock_auth):
        responses.add(
            responses.DELETE,
            f"{IDENTITY_URL}/certificates/cert-123",
            json={"_errors": [{"message": "Not Found"}]},
            status=404,
        )
        client = IdentityClient(sample_config, mock_auth)
        with pytest.raises(CertificateImportError) as exc_info:
            client.delete_certificate("cert-123")
        assert exc_info.value.status_code == 404


class TestListCertificatesIncludesPem:
    @responses.activate
    def test_pem_stored(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            f"{IDENTITY_URL}/certificates",
            json={
                "data": [
                    {
                        "id": "u1",
                        "name": "cert-1",
                        "folder": "All",
                        "common_name": "Test",
                        "public_key": SAMPLE_PEM,
                    }
                ],
                "total": 1,
                "limit": 200,
                "offset": 0,
            },
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_certificates()
        assert result[0].pem == SAMPLE_PEM

    @responses.activate
    def test_no_pem_stored_as_none(self, sample_config, mock_auth):
        responses.add(
            responses.GET,
            f"{IDENTITY_URL}/certificates",
            json={
                "data": [
                    {
                        "id": "u1",
                        "name": "cert-1",
                        "folder": "All",
                        "common_name": "Test",
                        "public_key": "",
                    }
                ],
                "total": 1,
                "limit": 200,
                "offset": 0,
            },
            status=200,
        )
        client = IdentityClient(sample_config, mock_auth)
        result = client.list_certificates()
        assert result[0].pem is None
