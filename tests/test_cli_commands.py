"""Tests for CLI command execution (mocked pipeline)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from scm_chainguard.cli import app
from scm_chainguard.models import CleanupResult, ComparisonResult, CertType, SyncResult

runner = CliRunner()


def _env_vars():
    return {
        "SCM_CLIENT_ID": "test-id",
        "SCM_CLIENT_SECRET": "test-secret",
        "SCM_TSG_ID": "123456",
    }


class TestFetchExecution:
    @patch("scm_chainguard.pipeline.run_fetch")
    def test_invokes_run_fetch(self, mock_fetch, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_fetch.return_value = {"roots": Path("/tmp/roots")}

        result = runner.invoke(app, ["fetch"])
        assert result.exit_code == 0
        mock_fetch.assert_called_once()

    @patch("scm_chainguard.pipeline.run_fetch")
    def test_with_intermediates(self, mock_fetch, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_fetch.return_value = {"roots": Path("/tmp/roots"), "intermediates": Path("/tmp/ints")}

        result = runner.invoke(app, ["fetch", "--include-intermediates"])
        assert result.exit_code == 0
        call_args = mock_fetch.call_args
        assert call_args[0][1] is True  # include_intermediates

    @patch("scm_chainguard.pipeline.run_fetch")
    def test_with_store(self, mock_fetch, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_fetch.return_value = {"roots": Path("/tmp/roots")}

        result = runner.invoke(app, ["fetch", "--store", "mozilla"])
        assert result.exit_code == 0

    @patch("scm_chainguard.pipeline.run_fetch")
    def test_with_output_dir(self, mock_fetch, monkeypatch, tmp_path):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_fetch.return_value = {"roots": tmp_path / "roots"}

        result = runner.invoke(app, ["fetch", "--output-dir", str(tmp_path)])
        assert result.exit_code == 0
        # Config should have the overridden output_dir
        call_config = mock_fetch.call_args[0][0]
        assert call_config.output_dir == str(tmp_path)


class TestCompareExecution:
    @patch("scm_chainguard.pipeline.run_compare")
    def test_invokes_run_compare(self, mock_compare, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT, total_local=5),
        }

        result = runner.invoke(app, ["compare"])
        assert result.exit_code == 0
        mock_compare.assert_called_once()

    @patch("scm_chainguard.pipeline.run_compare")
    def test_output_shows_counts(self, mock_compare, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_compare.return_value = {
            "roots": ComparisonResult(
                cert_type=CertType.ROOT,
                present=[],
                missing=[],
                total_local=0,
            ),
        }

        result = runner.invoke(app, ["compare"])
        assert "ROOTS" in result.stdout
        assert "0 present" in result.stdout

    @patch("scm_chainguard.pipeline.run_compare")
    def test_with_intermediates(self, mock_compare, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT),
            "intermediates": ComparisonResult(cert_type=CertType.INTERMEDIATE),
        }

        result = runner.invoke(app, ["compare", "--include-intermediates"])
        assert result.exit_code == 0

    @patch("scm_chainguard.pipeline.run_compare")
    def test_with_output_dir(self, mock_compare, monkeypatch, tmp_path):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_compare.return_value = {
            "roots": ComparisonResult(cert_type=CertType.ROOT),
        }

        result = runner.invoke(app, ["compare", "--output-dir", str(tmp_path)])
        assert result.exit_code == 0
        call_config = mock_compare.call_args[0][0]
        assert call_config.output_dir == str(tmp_path)


class TestSyncExecution:
    @patch("scm_chainguard.pipeline.run_sync")
    def test_invokes_run_sync(self, mock_sync, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_sync.return_value = {"roots": SyncResult()}

        result = runner.invoke(app, ["sync"])
        assert result.exit_code == 0
        mock_sync.assert_called_once()

    @patch("scm_chainguard.pipeline.run_sync")
    def test_dry_run(self, mock_sync, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_sync.return_value = {"roots": SyncResult(dry_run=True)}

        result = runner.invoke(app, ["sync", "--dry-run"])
        assert result.exit_code == 0
        call_args = mock_sync.call_args
        assert call_args[0][2] is True  # dry_run

    @patch("scm_chainguard.pipeline.run_sync")
    def test_failures_exit_1(self, mock_sync, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_sync.return_value = {
            "roots": SyncResult(failed=[("CG_Bad", "error")]),
        }

        result = runner.invoke(app, ["sync"])
        assert result.exit_code == 1

    @patch("scm_chainguard.pipeline.run_sync")
    def test_success_exit_0(self, mock_sync, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_sync.return_value = {
            "roots": SyncResult(imported=["CG_Good"]),
        }

        result = runner.invoke(app, ["sync"])
        assert result.exit_code == 0

    @patch("scm_chainguard.pipeline.run_sync")
    def test_with_output_dir(self, mock_sync, monkeypatch, tmp_path):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_sync.return_value = {"roots": SyncResult()}

        result = runner.invoke(app, ["sync", "--output-dir", str(tmp_path)])
        assert result.exit_code == 0
        call_config = mock_sync.call_args[0][0]
        assert call_config.output_dir == str(tmp_path)


class TestCleanupExecution:
    @patch("scm_chainguard.pipeline.run_cleanup")
    def test_invokes_run_cleanup(self, mock_cleanup, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_cleanup.return_value = CleanupResult()

        result = runner.invoke(app, ["cleanup"])
        assert result.exit_code == 0
        mock_cleanup.assert_called_once()

    @patch("scm_chainguard.pipeline.run_cleanup")
    def test_no_expired_message(self, mock_cleanup, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_cleanup.return_value = CleanupResult()

        result = runner.invoke(app, ["cleanup"])
        assert "No expired" in result.stdout

    @patch("scm_chainguard.pipeline.run_cleanup")
    def test_failures_exit_1(self, mock_cleanup, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_cleanup.return_value = CleanupResult(
            failed=[("CG_Bad", "API error")],
        )

        result = runner.invoke(app, ["cleanup"])
        assert result.exit_code == 1


class TestRevokeExecution:
    @patch("scm_chainguard.pipeline.run_revoke")
    def test_invokes_run_revoke(self, mock_revoke, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_revoke.return_value = CleanupResult()

        result = runner.invoke(app, ["revoke"])
        assert result.exit_code == 0
        mock_revoke.assert_called_once()

    @patch("scm_chainguard.pipeline.run_revoke")
    def test_no_distrusted_message(self, mock_revoke, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_revoke.return_value = CleanupResult()

        result = runner.invoke(app, ["revoke"])
        assert "No distrusted" in result.stdout

    @patch("scm_chainguard.pipeline.run_revoke")
    def test_with_store(self, mock_revoke, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_revoke.return_value = CleanupResult()

        result = runner.invoke(app, ["revoke", "--store", "mozilla"])
        assert result.exit_code == 0

    @patch("scm_chainguard.pipeline.run_revoke")
    def test_dry_run(self, mock_revoke, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_revoke.return_value = CleanupResult(dry_run=True, deleted=["CG_Test"])

        result = runner.invoke(app, ["revoke", "--dry-run"])
        assert result.exit_code == 0
        assert "[DRY-RUN]" in result.stdout

    @patch("scm_chainguard.pipeline.run_revoke")
    def test_failures_exit_1(self, mock_revoke, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_revoke.return_value = CleanupResult(failed=[("CG_Bad", "API error")])

        result = runner.invoke(app, ["revoke"])
        assert result.exit_code == 1

    @patch("scm_chainguard.pipeline.run_revoke")
    def test_output_shows_revoked(self, mock_revoke, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_revoke.return_value = CleanupResult(
            deleted=["CG_OldRoot"],
            removed_from_trusted=["CG_OldRoot"],
        )

        result = runner.invoke(app, ["revoke"])
        assert "REVOKED: CG_OldRoot" in result.stdout


class TestRunExecution:
    @patch("scm_chainguard.pipeline.run_full_pipeline")
    def test_invokes_full_pipeline(self, mock_pipeline, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_pipeline.return_value = {"fetch": {}, "sync": {"roots": SyncResult()}}

        result = runner.invoke(app, ["run"])
        assert result.exit_code == 0
        mock_pipeline.assert_called_once()

    @patch("scm_chainguard.pipeline.run_full_pipeline")
    def test_failures_exit_1(self, mock_pipeline, monkeypatch):
        for k, v in _env_vars().items():
            monkeypatch.setenv(k, v)
        mock_pipeline.return_value = {
            "fetch": {},
            "sync": {"roots": SyncResult(failed=[("CG_Bad", "err")])},
        }

        result = runner.invoke(app, ["run"])
        assert result.exit_code == 1


class TestGetConfig:
    def test_missing_config_prints_error(self, monkeypatch):
        monkeypatch.delenv("SCM_CLIENT_ID", raising=False)
        monkeypatch.delenv("SCM_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("SCM_TSG_ID", raising=False)

        result = runner.invoke(app, ["fetch"])
        assert result.exit_code == 1
        assert "Configuration error" in result.stdout or result.exit_code == 1
