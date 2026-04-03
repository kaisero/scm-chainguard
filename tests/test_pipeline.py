"""Tests for pipeline orchestration."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest
from scm_chainguard.cert_utils import sanitize_filename
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
from scm_chainguard.pipeline import (
    _save_certs,
    run_cleanup,
    run_compare,
    run_fetch,
    run_full_pipeline,
    run_revoke,
    run_sync,
)
from tests.conftest import SAMPLE_PEM, SAMPLE_PEM_NO_NEWLINE, SAMPLE_SHA256


# ---------------------------------------------------------------------------
# TestSaveCerts — real file I/O with tmp_path
# ---------------------------------------------------------------------------
class TestSaveCerts:
    def _cert(self, cn: str, sha: str, cert_type: CertType, pem: str = SAMPLE_PEM) -> CcadbCertificate:
        return CcadbCertificate(
            sha256_fingerprint=sha,
            common_name=cn,
            ca_owner="Org",
            cert_type=cert_type,
            pem=pem,
        )

    def test_saves_only_matching_cert_type(self, tmp_path):
        certs = {
            "AA": self._cert("Root A", "AA", CertType.ROOT),
            "BB": self._cert("Inter B", "BB", CertType.INTERMEDIATE),
        }
        count = _save_certs(certs, CertType.ROOT, tmp_path / "out")
        assert count == 1
        files = list((tmp_path / "out").glob("*.pem"))
        assert len(files) == 1

    def test_creates_directory(self, tmp_path):
        target = tmp_path / "nested" / "dir"
        assert not target.exists()
        _save_certs({}, CertType.ROOT, target)
        assert target.is_dir()

    def test_appends_newline_if_missing(self, tmp_path):
        certs = {"AA": self._cert("Test", "AA", CertType.ROOT, pem=SAMPLE_PEM_NO_NEWLINE)}
        _save_certs(certs, CertType.ROOT, tmp_path)
        content = list(tmp_path.glob("*.pem"))[0].read_text()
        assert content.endswith("\n")

    def test_preserves_existing_newline(self, tmp_path):
        certs = {"AA": self._cert("Test", "AA", CertType.ROOT, pem=SAMPLE_PEM)}
        _save_certs(certs, CertType.ROOT, tmp_path)
        content = list(tmp_path.glob("*.pem"))[0].read_text()
        assert not content.endswith("\n\n")
        assert content.endswith("\n")

    def test_returns_count(self, tmp_path):
        certs = {
            "AA": self._cert("A", "AA", CertType.ROOT),
            "BB": self._cert("B", "BB", CertType.ROOT),
            "CC": self._cert("C", "CC", CertType.ROOT),
        }
        assert _save_certs(certs, CertType.ROOT, tmp_path) == 3

    def test_empty_dict_returns_zero(self, tmp_path):
        assert _save_certs({}, CertType.ROOT, tmp_path) == 0

    def test_filename_uses_sanitize(self, tmp_path):
        certs = {"AABB1122": self._cert("My Root CA", "AABB1122", CertType.ROOT)}
        _save_certs(certs, CertType.ROOT, tmp_path)
        expected = sanitize_filename("My Root CA", "AABB1122")
        assert (tmp_path / expected).exists()

    def test_mixed_types_count(self, tmp_path):
        certs = {
            f"R{i}": self._cert(f"Root {i}", f"R{i}", CertType.ROOT) for i in range(3)
        }
        certs.update({
            f"I{i}": self._cert(f"Int {i}", f"I{i}", CertType.INTERMEDIATE) for i in range(2)
        })
        assert _save_certs(certs, CertType.ROOT, tmp_path) == 3
        assert _save_certs(certs, CertType.INTERMEDIATE, tmp_path) == 2


# ---------------------------------------------------------------------------
# TestRunFetch
# ---------------------------------------------------------------------------
class TestRunFetch:
    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_roots_only(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_client = MockClient.return_value
        mock_client.download_metadata_csv.return_value = "csv-data"
        mock_client.download_all_pem_csvs.return_value = ["pem-csv"]
        mock_parse.return_value = ({}, {})
        mock_attach.return_value = {}

        result = run_fetch(config)
        assert "roots" in result
        assert "intermediates" not in result

    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_with_intermediates(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_client = MockClient.return_value
        mock_client.download_metadata_csv.return_value = "csv"
        mock_client.download_all_pem_csvs.return_value = ["pem"]
        mock_parse.return_value = ({}, {})
        mock_attach.return_value = {}

        result = run_fetch(config, include_intermediates=True)
        assert "roots" in result
        assert "intermediates" in result

    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_passes_trust_store_to_parse(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        MockClient.return_value.download_metadata_csv.return_value = "csv"
        MockClient.return_value.download_all_pem_csvs.return_value = []
        mock_parse.return_value = ({}, {})
        mock_attach.return_value = {}

        run_fetch(config, trust_store=TrustStore.MOZILLA)
        mock_parse.assert_called_once_with("csv", False, trust_store=TrustStore.MOZILLA)

    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_downloads_metadata_and_pems(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_client = MockClient.return_value
        mock_client.download_metadata_csv.return_value = "csv"
        mock_client.download_all_pem_csvs.return_value = ["p1", "p2"]
        mock_parse.return_value = ({}, {})
        mock_attach.return_value = {}

        run_fetch(config)
        mock_client.download_metadata_csv.assert_called_once()
        mock_client.download_all_pem_csvs.assert_called_once()

    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_uses_config_output_dir(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path / "custom"))
        MockClient.return_value.download_metadata_csv.return_value = "csv"
        MockClient.return_value.download_all_pem_csvs.return_value = []
        mock_parse.return_value = ({}, {})
        mock_attach.return_value = {}

        result = run_fetch(config)
        assert result["roots"] == tmp_path / "custom" / "roots"

    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_creates_output_directories(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        MockClient.return_value.download_metadata_csv.return_value = "csv"
        MockClient.return_value.download_all_pem_csvs.return_value = []
        mock_parse.return_value = ({}, {})
        mock_attach.return_value = {}

        run_fetch(config)
        assert (tmp_path / "roots").is_dir()

    @patch("scm_chainguard.pipeline.attach_pems")
    @patch("scm_chainguard.pipeline.parse_metadata")
    @patch("scm_chainguard.pipeline.CcadbClient")
    def test_attaches_pems_with_merged_certs(self, MockClient, mock_parse, mock_attach, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        roots = {"R1": MagicMock()}
        ints = {"I1": MagicMock()}
        MockClient.return_value.download_metadata_csv.return_value = "csv"
        MockClient.return_value.download_all_pem_csvs.return_value = ["pem"]
        mock_parse.return_value = (roots, ints)
        mock_attach.return_value = {}

        run_fetch(config, include_intermediates=True)
        # attach_pems should receive the union of roots + intermediates
        merged = mock_attach.call_args[0][0]
        assert "R1" in merged
        assert "I1" in merged


# ---------------------------------------------------------------------------
# TestRunCompare
# ---------------------------------------------------------------------------
class TestRunCompare:
    @patch("scm_chainguard.pipeline.compare_roots")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    @patch("scm_chainguard.pipeline.load_local_certs")
    def test_roots_only_default(self, mock_load, MockAuth, MockIdentity, mock_compare, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_load.return_value = []
        mock_identity = MockIdentity.return_value
        mock_identity.list_trusted_certificate_authorities.return_value = []
        mock_identity.list_certificates.return_value = []
        mock_compare.return_value = ComparisonResult(cert_type=CertType.ROOT)

        result = run_compare(config)
        assert "roots" in result
        assert "intermediates" not in result

    @patch("scm_chainguard.pipeline.compare_intermediates")
    @patch("scm_chainguard.pipeline.compare_roots")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    @patch("scm_chainguard.pipeline.load_local_certs")
    def test_with_intermediates(self, mock_load, MockAuth, MockIdentity, mock_compare_roots, mock_compare_int, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_load.return_value = []
        mock_identity = MockIdentity.return_value
        mock_identity.list_trusted_certificate_authorities.return_value = []
        mock_identity.list_certificates.return_value = []
        mock_compare_roots.return_value = ComparisonResult(cert_type=CertType.ROOT)
        mock_compare_int.return_value = ComparisonResult(cert_type=CertType.INTERMEDIATE)

        result = run_compare(config, include_intermediates=True)
        assert "roots" in result
        assert "intermediates" in result
        mock_compare_int.assert_called_once()

    @patch("scm_chainguard.pipeline.compare_roots")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    @patch("scm_chainguard.pipeline.load_local_certs")
    def test_creates_auth_and_identity(self, mock_load, MockAuth, MockIdentity, mock_compare, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_load.return_value = []
        MockIdentity.return_value.list_trusted_certificate_authorities.return_value = []
        MockIdentity.return_value.list_certificates.return_value = []
        mock_compare.return_value = ComparisonResult(cert_type=CertType.ROOT)

        run_compare(config)
        MockAuth.assert_called_once_with(config)
        MockIdentity.assert_called_once()

    @patch("scm_chainguard.pipeline.compare_roots")
    @patch("scm_chainguard.pipeline.load_local_certs")
    def test_uses_provided_auth_and_identity(self, mock_load, mock_compare, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_load.return_value = []
        mock_auth = MagicMock()
        mock_identity = MagicMock()
        mock_identity.list_trusted_certificate_authorities.return_value = []
        mock_identity.list_certificates.return_value = []
        mock_compare.return_value = ComparisonResult(cert_type=CertType.ROOT)

        run_compare(config, auth=mock_auth, identity=mock_identity)
        mock_identity.list_trusted_certificate_authorities.assert_called_once()
        mock_identity.list_certificates.assert_called_once()

    @patch("scm_chainguard.pipeline.compare_roots")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    @patch("scm_chainguard.pipeline.load_local_certs")
    def test_loads_certs_from_output_dir(self, mock_load, MockAuth, MockIdentity, mock_compare, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_load.return_value = []
        MockIdentity.return_value.list_trusted_certificate_authorities.return_value = []
        MockIdentity.return_value.list_certificates.return_value = []
        mock_compare.return_value = ComparisonResult(cert_type=CertType.ROOT)

        run_compare(config)
        mock_load.assert_called_once_with(tmp_path / "roots", CertType.ROOT)

    @patch("scm_chainguard.pipeline.compare_roots")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    @patch("scm_chainguard.pipeline.load_local_certs")
    def test_queries_scm_apis(self, mock_load, MockAuth, MockIdentity, mock_compare, sample_config, tmp_path):
        config = replace(sample_config, output_dir=str(tmp_path))
        mock_load.return_value = []
        mock_identity = MockIdentity.return_value
        mock_identity.list_trusted_certificate_authorities.return_value = ["pred"]
        mock_identity.list_certificates.return_value = ["imp"]
        mock_compare.return_value = ComparisonResult(cert_type=CertType.ROOT)

        run_compare(config)
        mock_compare.assert_called_once_with([], ["pred"], ["imp"])


# ---------------------------------------------------------------------------
# TestRunSync
# ---------------------------------------------------------------------------
class TestRunSync:
    def _make_present_pair(self, name: str, scm_name: str) -> tuple[LocalCertificate, str]:
        cert = LocalCertificate(
            filepath=f"/tmp/{name}.pem",
            filename=f"{name}.pem",
            common_name=name,
            sha256_fingerprint="AA",
            pem="---PEM---",
            cert_type=CertType.ROOT,
        )
        return (cert, scm_name)

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_syncs_missing_roots(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        missing = [MagicMock(spec=LocalCertificate)]
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=missing),
        }
        mock_sync.return_value = SyncResult(imported=["CG_Test"])

        result = run_sync(sample_config)
        mock_sync.assert_called_once()
        assert result["roots"].imported == ["CG_Test"]

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_no_missing_returns_empty_result(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, present=[], missing=[]),
        }

        result = run_sync(sample_config)
        mock_sync.assert_not_called()
        assert result["roots"].imported == []

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_ensure_trusted_from_cg_prefix(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        present = [
            self._make_present_pair("A", "CG_A_AAAA0001"),
            self._make_present_pair("B", "predefined_cert"),
        ]
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, present=present, missing=[]),
        }
        mock_sync.return_value = SyncResult()

        run_sync(sample_config)
        # sync_certificates should be called with ensure_trusted containing only CG_ names
        sync_call = mock_sync.call_args
        assert sync_call.kwargs.get("ensure_trusted") == ["CG_A_AAAA0001"]

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_dry_run_passed_through(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=[MagicMock()]),
        }
        mock_sync.return_value = SyncResult(dry_run=True)

        run_sync(sample_config, dry_run=True)
        assert mock_sync.call_args.kwargs["dry_run"] is True

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_with_intermediates(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=[]),
            "intermediates": ComparisonResult(cert_type=CertType.INTERMEDIATE, missing=[MagicMock()]),
        }
        mock_sync.return_value = SyncResult()

        result = run_sync(sample_config, include_intermediates=True)
        assert "intermediates" in result

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_intermediates_not_trusted_root(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=[]),
            "intermediates": ComparisonResult(cert_type=CertType.INTERMEDIATE, missing=[MagicMock()]),
        }
        mock_sync.return_value = SyncResult()

        run_sync(sample_config, include_intermediates=True)
        # The intermediates sync call should have add_as_trusted_root=False
        int_call = [c for c in mock_sync.call_args_list if c.kwargs.get("add_as_trusted_root") is False]
        assert len(int_call) == 1

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_constructs_clients(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=[]),
        }

        run_sync(sample_config)
        MockAuth.assert_called_once_with(sample_config)
        MockIdentity.assert_called_once()
        MockSecurity.assert_called_once()

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_trust_store_passed_to_compare(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=[]),
        }

        run_sync(sample_config, trust_store=TrustStore.APPLE)
        assert mock_compare.call_args.kwargs["trust_store"] == TrustStore.APPLE

    @patch("scm_chainguard.pipeline.sync_certificates")
    @patch("scm_chainguard.pipeline.run_compare")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_intermediates_no_missing_returns_empty(self, MockAuth, MockIdentity, MockSecurity, mock_compare, mock_sync, sample_config):
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, missing=[]),
            "intermediates": ComparisonResult(cert_type=CertType.INTERMEDIATE, missing=[]),
        }

        result = run_sync(sample_config, include_intermediates=True)
        assert result["intermediates"].imported == []


# ---------------------------------------------------------------------------
# TestRunFullPipeline
# ---------------------------------------------------------------------------
class TestRunFullPipeline:
    @patch("scm_chainguard.pipeline.run_sync")
    @patch("scm_chainguard.pipeline.run_fetch")
    def test_calls_fetch_then_sync(self, mock_fetch, mock_sync, sample_config):
        mock_fetch.return_value = {"roots": Path("/tmp/roots")}
        mock_sync.return_value = {"roots": SyncResult()}

        result = run_full_pipeline(sample_config)
        mock_fetch.assert_called_once()
        mock_sync.assert_called_once()
        assert "fetch" in result
        assert "sync" in result

    @patch("scm_chainguard.pipeline.run_sync")
    @patch("scm_chainguard.pipeline.run_fetch")
    def test_passes_all_params(self, mock_fetch, mock_sync, sample_config):
        mock_fetch.return_value = {}
        mock_sync.return_value = {}

        run_full_pipeline(sample_config, include_intermediates=True, dry_run=True, trust_store=TrustStore.ALL)
        mock_fetch.assert_called_once_with(sample_config, True, trust_store=TrustStore.ALL)
        mock_sync.assert_called_once_with(sample_config, True, True, trust_store=TrustStore.ALL)

    @patch("scm_chainguard.pipeline.run_sync")
    @patch("scm_chainguard.pipeline.run_fetch")
    def test_returns_combined_result(self, mock_fetch, mock_sync, sample_config):
        fetch_result = {"roots": Path("/tmp/roots")}
        sync_result = {"roots": SyncResult(imported=["CG_Test"])}
        mock_fetch.return_value = fetch_result
        mock_sync.return_value = sync_result

        result = run_full_pipeline(sample_config)
        assert result["fetch"] == fetch_result
        assert result["sync"] == sync_result

    @patch("scm_chainguard.pipeline.run_sync")
    @patch("scm_chainguard.pipeline.run_fetch")
    def test_dry_run_forwarded(self, mock_fetch, mock_sync, sample_config):
        mock_fetch.return_value = {}
        mock_sync.return_value = {}

        run_full_pipeline(sample_config, dry_run=True)
        assert mock_sync.call_args[0][2] is True  # dry_run positional arg

    @patch("scm_chainguard.pipeline.run_sync")
    @patch("scm_chainguard.pipeline.run_fetch")
    def test_trust_store_forwarded(self, mock_fetch, mock_sync, sample_config):
        mock_fetch.return_value = {}
        mock_sync.return_value = {}

        run_full_pipeline(sample_config, trust_store=TrustStore.MOZILLA)
        assert mock_fetch.call_args.kwargs["trust_store"] == TrustStore.MOZILLA
        assert mock_sync.call_args.kwargs["trust_store"] == TrustStore.MOZILLA


# ---------------------------------------------------------------------------
# TestRunCleanup
# ---------------------------------------------------------------------------
class TestRunCleanup:
    def _scm_cert(self, name: str, pem: str | None = SAMPLE_PEM, cert_id: str = "id1") -> ScmImportedCert:
        return ScmImportedCert(id=cert_id, name=name, common_name=name, pem=pem)

    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_no_managed_certs(self, MockAuth, MockIdentity, MockSecurity, sample_config):
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("Other_Cert"),
        ]

        result = run_cleanup(sample_config)
        assert result.deleted == []
        assert result.failed == []

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=False)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_no_expired_certs(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("CG_Valid_Cert"),
        ]

        result = run_cleanup(sample_config)
        assert result.deleted == []

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=True)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_expired_certs_deleted(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        cert = self._scm_cert("CG_Expired", cert_id="del1")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Expired"]
        MockIdentity.return_value.delete_certificate.return_value = None

        result = run_cleanup(sample_config)
        assert "CG_Expired" in result.deleted
        MockIdentity.return_value.delete_certificate.assert_called_once_with("del1")

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=True)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_removes_from_trusted_before_delete(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        cert = self._scm_cert("CG_Expired")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Expired"]

        result = run_cleanup(sample_config)
        MockSecurity.return_value.remove_trusted_root_cas.assert_called_once_with(
            ["CG_Expired"], dry_run=False
        )
        assert "CG_Expired" in result.removed_from_trusted

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=True)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_dry_run_skips_delete(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        cert = self._scm_cert("CG_Expired")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Expired"]

        result = run_cleanup(sample_config, dry_run=True)
        assert result.dry_run is True
        assert "CG_Expired" in result.deleted
        MockIdentity.return_value.delete_certificate.assert_not_called()

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=True)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_delete_failure_recorded(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        cert = self._scm_cert("CG_BadCert", cert_id="fail1")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_BadCert"]
        MockIdentity.return_value.delete_certificate.side_effect = RuntimeError("API error")

        result = run_cleanup(sample_config)
        assert len(result.failed) == 1
        assert result.failed[0][0] == "CG_BadCert"
        assert "API error" in result.failed[0][1]

    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_cert_without_pem_skipped(self, MockAuth, MockIdentity, MockSecurity, sample_config):
        cert = self._scm_cert("CG_NoPem", pem=None)
        MockIdentity.return_value.list_certificates.return_value = [cert]

        result = run_cleanup(sample_config)
        assert result.deleted == []

    @patch("scm_chainguard.cert_utils.is_cert_expired", side_effect=Exception("parse error"))
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_cert_parse_error_skipped(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        cert = self._scm_cert("CG_BadPem")
        MockIdentity.return_value.list_certificates.return_value = [cert]

        result = run_cleanup(sample_config)
        assert result.deleted == []
        assert result.failed == []

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=True)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_filters_only_cg_prefix(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("CG_Managed"),
            self._scm_cert("Other_Cert"),
            self._scm_cert("CG_Another"),
        ]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Managed", "CG_Another"]

        result = run_cleanup(sample_config)
        assert "CG_Managed" in result.deleted
        assert "CG_Another" in result.deleted
        assert "Other_Cert" not in result.deleted

    @patch("scm_chainguard.cert_utils.is_cert_expired", return_value=True)
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_returns_cleanup_result_type(self, MockAuth, MockIdentity, MockSecurity, mock_expired, sample_config):
        MockIdentity.return_value.list_certificates.return_value = [self._scm_cert("CG_Test")]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Test"]

        result = run_cleanup(sample_config)
        assert isinstance(result, CleanupResult)


# ---------------------------------------------------------------------------
# TestRunRevoke
# ---------------------------------------------------------------------------
class TestRunRevoke:
    def _scm_cert(self, name: str, sha256: str | None = None, cert_id: str = "id1") -> ScmImportedCert:
        return ScmImportedCert(id=cert_id, name=name, common_name=name, sha256_fingerprint=sha256)

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_no_distrusted_in_ccadb(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = set()

        result = run_revoke(sample_config)
        assert result.deleted == []
        MockIdentity.return_value.list_certificates.assert_not_called()

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_no_matching_managed_certs(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("CG_OtherCert", sha256="BEEF0001"),
        ]

        result = run_revoke(sample_config)
        assert result.deleted == []

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_revokes_matching_cert(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        cert = self._scm_cert("CG_DistrustedCA", sha256="DEAD0001", cert_id="del1")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_DistrustedCA"]

        result = run_revoke(sample_config)
        assert "CG_DistrustedCA" in result.deleted
        MockIdentity.return_value.delete_certificate.assert_called_once_with("del1")

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_dry_run_skips_delete(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        cert = self._scm_cert("CG_Distrusted", sha256="DEAD0001")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Distrusted"]

        result = run_revoke(sample_config, dry_run=True)
        assert result.dry_run is True
        assert "CG_Distrusted" in result.deleted
        MockIdentity.return_value.delete_certificate.assert_not_called()

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_delete_failure_recorded(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        cert = self._scm_cert("CG_BadCert", sha256="DEAD0001", cert_id="fail1")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_BadCert"]
        MockIdentity.return_value.delete_certificate.side_effect = RuntimeError("API error")

        result = run_revoke(sample_config)
        assert len(result.failed) == 1
        assert result.failed[0][0] == "CG_BadCert"

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_filters_only_cg_prefix(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("CG_Managed", sha256="DEAD0001"),
            self._scm_cert("Other_Cert", sha256="DEAD0001"),
        ]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Managed"]

        result = run_revoke(sample_config)
        assert "CG_Managed" in result.deleted
        assert "Other_Cert" not in result.deleted

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_skips_certs_without_fingerprint(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("CG_NoSha", sha256=None),
        ]

        result = run_revoke(sample_config)
        assert result.deleted == []

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_trust_store_passed_to_collect(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = set()

        run_revoke(sample_config, trust_store=TrustStore.MOZILLA)
        mock_collect.assert_called_once_with("csv", TrustStore.MOZILLA)

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_removes_from_trusted_before_delete(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        cert = self._scm_cert("CG_Revoked", sha256="DEAD0001")
        MockIdentity.return_value.list_certificates.return_value = [cert]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Revoked"]

        result = run_revoke(sample_config)
        MockSecurity.return_value.remove_trusted_root_cas.assert_called_once_with(
            ["CG_Revoked"], dry_run=False
        )
        assert "CG_Revoked" in result.removed_from_trusted

    @patch("scm_chainguard.pipeline.collect_distrusted_fingerprints")
    @patch("scm_chainguard.pipeline.CcadbClient")
    @patch("scm_chainguard.pipeline.SecurityClient")
    @patch("scm_chainguard.pipeline.IdentityClient")
    @patch("scm_chainguard.pipeline.ScmAuthenticator")
    def test_returns_cleanup_result_type(self, MockAuth, MockIdentity, MockSecurity, MockCcadb, mock_collect, sample_config):
        MockCcadb.return_value.download_metadata_csv.return_value = "csv"
        mock_collect.return_value = {"DEAD0001"}
        MockIdentity.return_value.list_certificates.return_value = [
            self._scm_cert("CG_Test", sha256="DEAD0001"),
        ]
        MockSecurity.return_value.remove_trusted_root_cas.return_value = ["CG_Test"]

        result = run_revoke(sample_config)
        assert isinstance(result, CleanupResult)
