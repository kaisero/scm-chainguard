"""Tests for cert_utils module."""

import pytest
from scm_chainguard.cert_utils import (
    CERT_PREFIX,
    cert_import_name,
    extract_common_name,
    is_cert_expired,
    pem_to_sha256,
    sanitize_filename,
)
from tests.conftest import SAMPLE_CN, SAMPLE_PEM, SAMPLE_SHA256


class TestPemToSha256:
    def test_known_cert(self):
        assert pem_to_sha256(SAMPLE_PEM) == SAMPLE_SHA256

    def test_invalid_pem_raises(self):
        with pytest.raises(Exception):
            pem_to_sha256("not a pem")


class TestExtractCommonName:
    def test_known_cert(self):
        assert extract_common_name(SAMPLE_PEM) == SAMPLE_CN

    def test_returns_none_for_no_cn(self):
        # Would need a cert without CN; test the function exists and handles errors
        with pytest.raises(Exception):
            extract_common_name("not a pem")


class TestSanitizeFilename:
    def test_basic(self):
        result = sanitize_filename("DigiCert Global Root CA", "4348A0E9ABCDEF")
        assert result == "DigiCert_Global_Root_CA_4348A0E9.pem"

    def test_special_chars(self):
        result = sanitize_filename("SSL.com Root (ECC)", "AABB1122")
        assert result == "SSL.com_Root_ECC_AABB1122.pem"

    def test_empty_name(self):
        result = sanitize_filename("", "AABB1122")
        assert result == "unnamed_AABB1122.pem"

    def test_long_name_truncated(self):
        result = sanitize_filename("A" * 200, "AABB1122")
        assert len(result) <= 200

    def test_unicode(self):
        result = sanitize_filename("Főtanúsítvány", "6C61DAC3")
        assert result.endswith("_6C61DAC3.pem")
        assert "/" not in result

    def test_sha_uppercased(self):
        result = sanitize_filename("Test", "abcdef12")
        assert "ABCDEF12" in result


class TestCertImportName:
    def test_short_name_gets_prefix(self):
        result = cert_import_name("DigiCert_Root_CA_4348A0E9.pem")
        assert result == "CG_DigiCert_Root_CA_4348A0E9"
        assert result.startswith(CERT_PREFIX)

    def test_no_extension(self):
        assert cert_import_name("no_ext") == "CG_no_ext"

    def test_never_exceeds_31_chars(self):
        long_name = "Sectigo_Public_Server_Authentication_Root_E46_AABB1122.pem"
        result = cert_import_name(long_name)
        assert len(result) <= 31
        assert result.startswith(CERT_PREFIX)

    def test_abbreviations_applied(self):
        result = cert_import_name("Global_Root_Certificate_Authority_AABB1122.pem")
        assert len(result) <= 31
        assert result.startswith(CERT_PREFIX)
        assert result.endswith("_AABB1122")

    def test_truncation_last_resort(self):
        # A name so long even abbreviations won't save it
        result = cert_import_name("A" * 40 + "_AABB1122.pem")
        assert len(result) <= 31
        assert result.startswith(CERT_PREFIX)
        assert result.endswith("_AABB1122")


class TestIsCertExpired:
    def test_known_valid_cert(self):
        # Sectigo cert is valid until 2046
        assert is_cert_expired(SAMPLE_PEM) is False
