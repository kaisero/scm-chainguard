"""Tests for data models."""

import pytest
from scm_chainguard.models import (
    CcadbCertificate,
    CertType,
    CleanupResult,
    ComparisonResult,
    LocalCertificate,
    ScmImportedCert,
    ScmPredefinedRoot,
    SyncResult,
    TrustStore,
)


class TestCertType:
    def test_root_value(self):
        assert CertType.ROOT.value == "root"

    def test_intermediate_value(self):
        assert CertType.INTERMEDIATE.value == "intermediate"


class TestTrustStoreEnum:
    @pytest.mark.parametrize(
        "store,expected_column",
        [
            (TrustStore.CHROME, "Chrome Status"),
            (TrustStore.MOZILLA, "Mozilla Status"),
            (TrustStore.MICROSOFT, "Microsoft Status"),
            (TrustStore.APPLE, "Apple Status"),
        ],
        ids=["chrome", "mozilla", "microsoft", "apple"],
    )
    def test_status_column(self, store, expected_column):
        assert store.status_column == expected_column

    def test_all_raises_value_error(self):
        with pytest.raises(ValueError, match="ALL has no single status column"):
            TrustStore.ALL.status_column

    def test_individual_stores_excludes_all(self):
        stores = TrustStore.individual_stores()
        assert TrustStore.ALL not in stores

    def test_individual_stores_returns_four(self):
        assert len(TrustStore.individual_stores()) == 4

    def test_individual_stores_returns_list(self):
        assert isinstance(TrustStore.individual_stores(), list)

    @pytest.mark.parametrize(
        "store,expected_value",
        [
            (TrustStore.CHROME, "chrome"),
            (TrustStore.MOZILLA, "mozilla"),
            (TrustStore.MICROSOFT, "microsoft"),
            (TrustStore.APPLE, "apple"),
            (TrustStore.ALL, "all"),
        ],
    )
    def test_enum_string_values(self, store, expected_value):
        assert store.value == expected_value


class TestFrozenDataclasses:
    def test_ccadb_certificate_immutable(self):
        cert = CcadbCertificate(
            sha256_fingerprint="AA",
            common_name="Test",
            ca_owner="Org",
            cert_type=CertType.ROOT,
        )
        with pytest.raises(AttributeError):
            cert.common_name = "Changed"

    def test_local_certificate_immutable(self):
        cert = LocalCertificate(
            filepath="/tmp/test.pem",
            filename="test.pem",
            common_name="Test",
            sha256_fingerprint="AA",
            pem="---PEM---",
            cert_type=CertType.ROOT,
        )
        with pytest.raises(AttributeError):
            cert.common_name = "Changed"

    def test_scm_predefined_root_immutable(self):
        root = ScmPredefinedRoot(name="test", common_name="Test")
        with pytest.raises(AttributeError):
            root.name = "Changed"

    def test_scm_imported_cert_immutable(self):
        cert = ScmImportedCert(id="1", name="test", common_name="Test")
        with pytest.raises(AttributeError):
            cert.name = "Changed"

    def test_ccadb_certificate_defaults(self):
        cert = CcadbCertificate(
            sha256_fingerprint="AA",
            common_name="Test",
            ca_owner="Org",
            cert_type=CertType.ROOT,
        )
        assert cert.parent_sha256 is None
        assert cert.pem is None

    def test_scm_predefined_root_defaults(self):
        root = ScmPredefinedRoot(name="test", common_name="Test")
        assert root.subject == ""
        assert root.filename == ""
        assert root.not_valid_after == ""
        assert root.expiry_epoch == ""

    def test_scm_imported_cert_defaults(self):
        cert = ScmImportedCert(id="1", name="test", common_name="Test")
        assert cert.sha256_fingerprint is None
        assert cert.folder == ""
        assert cert.pem is None


class TestMutableDataclasses:
    def test_comparison_result_defaults(self):
        result = ComparisonResult(cert_type=CertType.ROOT)
        assert result.present == []
        assert result.missing == []
        assert result.total_local == 0
        assert result.total_scm == 0

    def test_sync_result_defaults(self):
        result = SyncResult()
        assert result.imported == []
        assert result.skipped == []
        assert result.failed == []
        assert result.trusted_roots_added == []
        assert result.dry_run is False

    def test_cleanup_result_defaults(self):
        result = CleanupResult()
        assert result.removed_from_trusted == []
        assert result.deleted == []
        assert result.failed == []
        assert result.dry_run is False

    def test_sync_result_mutable(self):
        result = SyncResult()
        result.imported.append("cert1")
        result.failed.append(("cert2", "error"))
        assert result.imported == ["cert1"]
        assert result.failed == [("cert2", "error")]

    def test_comparison_result_field_assignment(self):
        result = ComparisonResult(cert_type=CertType.ROOT)
        result.total_local = 10
        result.total_scm = 20
        assert result.total_local == 10
        assert result.total_scm == 20
