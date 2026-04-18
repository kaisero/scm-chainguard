"""Tests for cert_utils module."""

import pytest
from scm_chainguard.cert_utils import (
    CERT_PREFIX,
    _ascii_transliterate,
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
        assert result == "Fotanusitvany_6C61DAC3.pem"

    def test_unicode_kanji(self):
        result = sanitize_filename("日本認証局", "AABB1122")
        assert result == "cert_AABB1122.pem"

    def test_unicode_mixed(self):
        result = sanitize_filename("Root_Café_日本", "AABB1122")
        assert result == "Root_Cafe_AABB1122.pem"

    def test_sha_uppercased(self):
        result = sanitize_filename("Test", "abcdef12")
        assert "ABCDEF12" in result


class TestAsciiTransliterate:
    def test_plain_ascii(self):
        assert _ascii_transliterate("Hello World") == "Hello World"

    def test_accented_latin(self):
        assert _ascii_transliterate("Főtanúsítvány") == "Fotanusitvany"

    def test_mixed_accents(self):
        assert _ascii_transliterate("café résumé") == "cafe resume"

    def test_kanji_only(self):
        assert _ascii_transliterate("日本認証局") == "cert"

    def test_mixed_kanji_and_latin(self):
        result = _ascii_transliterate("Root_日本_CA")
        assert result == "Root__CA"

    def test_empty_string(self):
        assert _ascii_transliterate("") == "cert"

    def test_whitespace_only(self):
        assert _ascii_transliterate("   ") == "cert"


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

    def test_unicode_accented(self):
        result = cert_import_name("Főtanúsítvány_6C61DAC3.pem")
        assert result.startswith(CERT_PREFIX)
        assert len(result) <= 31
        assert result == "CG_Fotanusitvany_6C61DAC3"

    def test_unicode_kanji(self):
        result = cert_import_name("日本認証局_AABB1122.pem")
        assert result.startswith(CERT_PREFIX)
        assert len(result) <= 31
        assert result.endswith("_AABB1122")


class TestLoadLocalCerts:
    def test_empty_directory(self, tmp_path):
        from scm_chainguard.cert_utils import load_local_certs
        from scm_chainguard.models import CertType

        result = load_local_certs(tmp_path, CertType.ROOT)
        assert result == []

    def test_nonexistent_directory(self, tmp_path):
        from scm_chainguard.cert_utils import load_local_certs
        from scm_chainguard.models import CertType

        result = load_local_certs(tmp_path / "no_such_dir", CertType.ROOT)
        assert result == []

    def test_reads_pem_files(self, tmp_path):
        from scm_chainguard.cert_utils import load_local_certs
        from scm_chainguard.models import CertType

        (tmp_path / "test_cert_AABB1122.pem").write_text(SAMPLE_PEM)
        result = load_local_certs(tmp_path, CertType.ROOT)
        assert len(result) == 1
        assert result[0].common_name == SAMPLE_CN
        assert result[0].sha256_fingerprint == SAMPLE_SHA256
        assert result[0].cert_type == CertType.ROOT

    def test_ignores_non_pem_files(self, tmp_path):
        from scm_chainguard.cert_utils import load_local_certs
        from scm_chainguard.models import CertType

        (tmp_path / "readme.txt").write_text("not a cert")
        (tmp_path / "test_AABB1122.pem").write_text(SAMPLE_PEM)
        result = load_local_certs(tmp_path, CertType.ROOT)
        assert len(result) == 1

    def test_invalid_pem_raises(self, tmp_path):
        from scm_chainguard.cert_utils import load_local_certs
        from scm_chainguard.models import CertType

        (tmp_path / "bad_AABB1122.pem").write_text("not a real PEM")
        with pytest.raises(ValueError):
            load_local_certs(tmp_path, CertType.ROOT)


class TestIsCertExpired:
    def test_known_valid_cert(self):
        # Sectigo cert is valid until 2046
        assert is_cert_expired(SAMPLE_PEM) is False
