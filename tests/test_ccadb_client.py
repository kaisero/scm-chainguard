"""Tests for CCADB HTTP client."""

import responses
import pytest
from scm_chainguard.ccadb.client import CcadbClient, METADATA_URL, PEM_URL_TEMPLATE


class TestCcadbClient:
    @responses.activate
    def test_download_metadata_csv(self):
        responses.add(
            responses.GET, METADATA_URL, body="col1,col2\nval1,val2\n", status=200
        )
        client = CcadbClient(timeout=5)
        result = client.download_metadata_csv()
        assert "col1" in result

    @responses.activate
    def test_download_pem_csv(self):
        url = PEM_URL_TEMPLATE.format(decade="20200")
        responses.add(
            responses.GET, url, body="SHA-256 Fingerprint,PEM\nAA,BB\n", status=200
        )
        client = CcadbClient(timeout=5)
        result = client.download_pem_csv("20200")
        assert "SHA-256 Fingerprint" in result

    @responses.activate
    def test_download_all_pem_csvs(self):
        for decade in ("20000", "20100", "20200"):
            url = PEM_URL_TEMPLATE.format(decade=decade)
            responses.add(responses.GET, url, body=f"data_{decade}\n", status=200)
        client = CcadbClient(timeout=5)
        results = client.download_all_pem_csvs()
        assert len(results) == 3

    @responses.activate
    def test_download_timeout(self):
        responses.add(responses.GET, METADATA_URL, body=responses.ConnectionError())
        client = CcadbClient(timeout=5)
        with pytest.raises(Exception):
            client.download_metadata_csv()
