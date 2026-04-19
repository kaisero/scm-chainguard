"""Tests for PAN-OS 11.2 SSL/TLS Decryption certificate compatibility."""

from __future__ import annotations

import pytest
from cryptography.x509.oid import SignatureAlgorithmOID

from scm_chainguard.panos_compat import (
    CertAlgorithmInfo,
    CompatibilityReport,
    check_panos_compatibility,
    extract_algorithm_info,
    generate_text_report,
    is_panos_compatible,
)
from tests.conftest import SAMPLE_PEM


# ---------------------------------------------------------------------------
# TestCheckPanosCompatibility — unit tests for the rule engine
# ---------------------------------------------------------------------------
class TestCheckPanosCompatibility:
    def test_rsa_sha256_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSA_WITH_SHA256, "RSA", 2048, None)
        assert ok is True
        assert reasons == []

    def test_rsa_sha384_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSA_WITH_SHA384, "RSA", 4096, None)
        assert ok is True

    def test_rsa_sha512_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSA_WITH_SHA512, "RSA", 3072, None)
        assert ok is True

    def test_rsa_sha1_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSA_WITH_SHA1, "RSA", 2048, None)
        assert ok is True

    def test_rsa_md5_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSA_WITH_MD5, "RSA", 1024, None)
        assert ok is True

    def test_ecdsa_sha256_p256_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.ECDSA_WITH_SHA256, "ECDSA", 256, "secp256r1")
        assert ok is True

    def test_ecdsa_sha384_p384_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.ECDSA_WITH_SHA384, "ECDSA", 384, "secp384r1")
        assert ok is True

    def test_ecdsa_sha512_p521_compatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.ECDSA_WITH_SHA512, "ECDSA", 521, "secp521r1")
        assert ok is True

    def test_rsassa_pss_incompatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSASSA_PSS, "RSA", 4096, None)
        assert ok is False
        assert len(reasons) == 1
        assert "RSASSA-PSS" in reasons[0]

    def test_ed25519_incompatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.ED25519, "Ed25519", 256, None)
        assert ok is False
        assert any("Ed25519" in r for r in reasons)
        # Both sig algo and key type should be flagged
        assert any("Public key type" in r for r in reasons)

    def test_ed448_incompatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.ED448, "Ed448", 448, None)
        assert ok is False
        assert any("Ed448" in r for r in reasons)

    def test_ecdsa_non_nist_curve_incompatible(self):
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.ECDSA_WITH_SHA256, "ECDSA", 256, "brainpoolP256r1")
        assert ok is False
        assert any("brainpoolP256r1" in r for r in reasons)

    def test_dsa_key_type_incompatible(self):
        # DSA has no standard OID in SignatureAlgorithmOID, so use a generic unsupported OID
        ok, reasons = check_panos_compatibility(SignatureAlgorithmOID.RSA_WITH_SHA256, "DSA", 2048, None)
        assert ok is False
        assert any("Public key type DSA" in r for r in reasons)


# ---------------------------------------------------------------------------
# TestIsPanosCompatible — PEM-level convenience function
# ---------------------------------------------------------------------------
class TestIsPanosCompatible:
    def test_compatible_ecdsa_cert(self):
        """SAMPLE_PEM is ECDSA P-384 with SHA-384 — should be compatible."""
        ok, reasons = is_panos_compatible(SAMPLE_PEM)
        assert ok is True
        assert reasons == []

    def test_invalid_pem_raises(self):
        with pytest.raises(Exception):
            is_panos_compatible("not a PEM")


# ---------------------------------------------------------------------------
# TestExtractAlgorithmInfo — full info extraction
# ---------------------------------------------------------------------------
class TestExtractAlgorithmInfo:
    def test_extracts_ecdsa_p384(self):
        info = extract_algorithm_info(
            SAMPLE_PEM,
            sha256="C90F26F0",
            common_name="Test ECDSA Cert",
            ca_owner="Test Org",
            cert_type="root",
        )
        assert isinstance(info, CertAlgorithmInfo)
        assert info.public_key_type == "ECDSA"
        assert info.key_size == 384
        assert info.curve == "secp384r1"
        assert info.signature_algorithm_name == "ECDSA-SHA384"
        assert info.is_compatible is True
        assert info.incompatibility_reasons == ()

    def test_preserves_metadata(self):
        info = extract_algorithm_info(
            SAMPLE_PEM,
            sha256="AABB1122",
            common_name="My CA",
            ca_owner="My Org",
            cert_type="intermediate",
        )
        assert info.sha256_fingerprint == "AABB1122"
        assert info.common_name == "My CA"
        assert info.ca_owner == "My Org"
        assert info.cert_type == "intermediate"

    def test_invalid_pem_raises(self):
        with pytest.raises(Exception):
            extract_algorithm_info("garbage", "SHA", "CN", "Owner", "root")


# ---------------------------------------------------------------------------
# TestGenerateTextReport
# ---------------------------------------------------------------------------
class TestGenerateTextReport:
    def test_all_compatible(self):
        report = CompatibilityReport(total_certs=10, compatible_certs=10)
        text = generate_text_report(report)
        assert "All certificates are compatible" in text
        assert "Compatible:                   10" in text

    def test_with_incompatible(self):
        info = CertAlgorithmInfo(
            sha256_fingerprint="DEADBEEF",
            common_name="Bad CA",
            ca_owner="Bad Org",
            cert_type="intermediate",
            signature_algorithm_oid="1.2.840.113549.1.1.10",
            signature_algorithm_name="RSASSA-PSS",
            public_key_type="RSA",
            key_size=4096,
            curve=None,
            is_compatible=False,
            incompatibility_reasons=("RSASSA-PSS not supported",),
        )
        report = CompatibilityReport(
            total_certs=5,
            compatible_certs=4,
            incompatible_certs=1,
            incompatible=[info],
            by_reason={"RSASSA-PSS not supported": [info]},
        )
        text = generate_text_report(report)
        assert "Incompatible:                 1" in text
        assert "Bad CA" in text
        assert "RSASSA-PSS" in text
        assert "RSA 4096 bits" in text
