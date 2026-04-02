"""Tests for CLI interface."""

from typer.testing import CliRunner
from scm_chainguard.cli import app

runner = CliRunner()


class TestCliStructure:
    def test_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Chrome-trusted CA" in result.stdout

    def test_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.stdout

    def test_subcommands_listed(self):
        result = runner.invoke(app, ["--help"])
        for cmd in ["fetch", "compare", "sync", "cleanup", "run"]:
            assert cmd in result.stdout


class TestFetchCommand:
    def test_help(self):
        result = runner.invoke(app, ["fetch", "--help"])
        assert result.exit_code == 0
        assert "--include-intermediates" in result.stdout

    def test_missing_config(self, monkeypatch):
        monkeypatch.delenv("SCM_CLIENT_ID", raising=False)
        monkeypatch.delenv("SCM_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("SCM_TSG_ID", raising=False)
        result = runner.invoke(app, ["fetch"])
        assert result.exit_code == 1


class TestCompareCommand:
    def test_help(self):
        result = runner.invoke(app, ["compare", "--help"])
        assert result.exit_code == 0
        assert "--include-intermediates" in result.stdout


class TestSyncCommand:
    def test_help(self):
        result = runner.invoke(app, ["sync", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.stdout
        assert "--include-intermediates" in result.stdout


class TestCleanupCommand:
    def test_help(self):
        result = runner.invoke(app, ["cleanup", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.stdout


class TestRunCommand:
    def test_help(self):
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.stdout
