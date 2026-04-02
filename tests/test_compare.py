"""Tests for comparison logic."""

from scm_chainguard.compare import compare_intermediates, compare_roots
from scm_chainguard.models import (
    CertType,
    LocalCertificate,
    ScmImportedCert,
    ScmPredefinedRoot,
)


def _local_root(cn: str, sha: str = "AA00") -> LocalCertificate:
    return LocalCertificate(
        filepath=f"/tmp/{cn}.pem",
        filename=f"{cn}.pem",
        common_name=cn,
        sha256_fingerprint=sha,
        pem="---PEM---",
        cert_type=CertType.ROOT,
    )


def _local_int(cn: str, sha: str = "BB00") -> LocalCertificate:
    return LocalCertificate(
        filepath=f"/tmp/{cn}.pem",
        filename=f"{cn}.pem",
        common_name=cn,
        sha256_fingerprint=sha,
        pem="---PEM---",
        cert_type=CertType.INTERMEDIATE,
    )


def _scm_root(cn: str, name: str = "0001_Test") -> ScmPredefinedRoot:
    return ScmPredefinedRoot(name=name, common_name=cn)


def _scm_imported(cn: str, sha: str | None = None) -> ScmImportedCert:
    return ScmImportedCert(id="u1", name="test", common_name=cn, sha256_fingerprint=sha)


class TestCompareRoots:
    def test_all_present_predefined(self):
        local = [_local_root("DigiCert")]
        scm = [_scm_root("DigiCert")]
        result = compare_roots(local, scm)
        assert len(result.present) == 1
        assert len(result.missing) == 0

    def test_present_via_imported_sha256(self):
        """Root found in imported certs by SHA-256 (not in predefined)."""
        local = [_local_root("NewCA", sha="DEADBEEF")]
        imported = [_scm_imported("NewCA", sha="DEADBEEF")]
        result = compare_roots(local, [], imported)
        assert len(result.present) == 1
        assert len(result.missing) == 0

    def test_present_via_imported_cn(self):
        """Root found in imported certs by CN (not in predefined)."""
        local = [_local_root("NewCA", sha="AAAA")]
        imported = [_scm_imported("NewCA", sha=None)]
        result = compare_roots(local, [], imported)
        assert len(result.present) == 1

    def test_some_missing(self):
        local = [_local_root("DigiCert"), _local_root("NewCA")]
        scm = [_scm_root("DigiCert")]
        result = compare_roots(local, scm)
        assert len(result.present) == 1
        assert len(result.missing) == 1
        assert result.missing[0].common_name == "NewCA"

    def test_case_insensitive(self):
        local = [_local_root("digicert global ROOT")]
        scm = [_scm_root("DigiCert Global Root")]
        result = compare_roots(local, scm)
        assert len(result.present) == 1

    def test_duplicate_cn_all_match(self):
        local = [
            _local_root("GlobalSign", "AA01"),
            _local_root("GlobalSign", "AA02"),
            _local_root("GlobalSign", "AA03"),
        ]
        scm = [_scm_root("GlobalSign")]
        result = compare_roots(local, scm)
        assert len(result.present) == 3

    def test_predefined_and_imported_combined(self):
        """One root in predefined, another in imported — both detected."""
        local = [_local_root("OldCA", "AA01"), _local_root("NewCA", "BB02")]
        predefined = [_scm_root("OldCA")]
        imported = [_scm_imported("NewCA", sha="BB02")]
        result = compare_roots(local, predefined, imported)
        assert len(result.present) == 2
        assert len(result.missing) == 0

    def test_empty_scm(self):
        local = [_local_root("Test")]
        result = compare_roots(local, [])
        assert len(result.missing) == 1

    def test_empty_local(self):
        scm = [_scm_root("Test")]
        result = compare_roots([], scm)
        assert len(result.present) == 0
        assert len(result.missing) == 0


class TestCompareIntermediates:
    def test_match_by_sha256(self):
        local = [_local_int("Inter A", sha="DEADBEEF")]
        scm = [_scm_imported("Inter A", sha="DEADBEEF")]
        result = compare_intermediates(local, scm)
        assert len(result.present) == 1

    def test_fallback_to_cn(self):
        local = [_local_int("Inter A", sha="DIFFERENT")]
        scm = [_scm_imported("Inter A", sha=None)]
        result = compare_intermediates(local, scm)
        assert len(result.present) == 1

    def test_no_match(self):
        local = [_local_int("Inter A", sha="AAAA")]
        scm = [_scm_imported("Inter B", sha="BBBB")]
        result = compare_intermediates(local, scm)
        assert len(result.missing) == 1
