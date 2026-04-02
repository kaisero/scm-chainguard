"""Tests for configuration loading."""

import pytest
from scm_chainguard.config import ConfigError, ScmConfig, load_config


class TestLoadConfigFromEnv:
    def test_required_fields(self, monkeypatch):
        monkeypatch.setenv("SCM_CLIENT_ID", "id1")
        monkeypatch.setenv("SCM_CLIENT_SECRET", "secret1")
        monkeypatch.setenv("SCM_TSG_ID", "tsg1")
        config = load_config()
        assert config.client_id == "id1"
        assert config.client_secret == "secret1"
        assert config.tsg_id == "tsg1"

    def test_defaults(self, monkeypatch):
        monkeypatch.setenv("SCM_CLIENT_ID", "id1")
        monkeypatch.setenv("SCM_CLIENT_SECRET", "secret1")
        monkeypatch.setenv("SCM_TSG_ID", "tsg1")
        config = load_config()
        assert config.auth_url == "https://auth.apps.paloaltonetworks.com"
        assert config.scm_host == "api.strata.paloaltonetworks.com"
        assert config.cert_folder == "All"

    def test_optional_overrides(self, monkeypatch):
        monkeypatch.setenv("SCM_CLIENT_ID", "id1")
        monkeypatch.setenv("SCM_CLIENT_SECRET", "secret1")
        monkeypatch.setenv("SCM_TSG_ID", "tsg1")
        monkeypatch.setenv("SCM_HOST", "custom.host.com")
        config = load_config()
        assert config.scm_host == "custom.host.com"

    def test_missing_required_raises(self, monkeypatch):
        monkeypatch.delenv("SCM_CLIENT_ID", raising=False)
        monkeypatch.delenv("SCM_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("SCM_TSG_ID", raising=False)
        with pytest.raises(ConfigError, match="Missing required"):
            load_config()


class TestLoadConfigFromYaml:
    def test_yaml_config(self, tmp_path, monkeypatch):
        # Clear env vars so YAML values are used
        monkeypatch.delenv("SCM_CLIENT_ID", raising=False)
        monkeypatch.delenv("SCM_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("SCM_TSG_ID", raising=False)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("scm:\n  client_id: yaml-id\n  client_secret: yaml-secret\n  tsg_id: yaml-tsg\n")
        config = load_config(config_file)
        assert config.client_id == "yaml-id"

    def test_env_overrides_yaml(self, tmp_path, monkeypatch):
        # Clear all SCM env vars first, then set only the one we want to override
        monkeypatch.delenv("SCM_CLIENT_SECRET", raising=False)
        monkeypatch.delenv("SCM_TSG_ID", raising=False)
        config_file = tmp_path / "config.yaml"
        config_file.write_text("scm:\n  client_id: yaml-id\n  client_secret: yaml-secret\n  tsg_id: yaml-tsg\n")
        monkeypatch.setenv("SCM_CLIENT_ID", "env-id")
        config = load_config(config_file)
        assert config.client_id == "env-id"
        assert config.client_secret == "yaml-secret"

    def test_invalid_yaml_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("not_scm: {}")
        with pytest.raises(ConfigError, match="top-level 'scm' key"):
            load_config(config_file)


class TestScmConfigProperties:
    def test_identity_url(self):
        config = ScmConfig(client_id="a", client_secret="b", tsg_id="c")
        assert config.identity_url == "https://api.strata.paloaltonetworks.com/config/identity/v1"

    def test_security_url(self):
        config = ScmConfig(client_id="a", client_secret="b", tsg_id="c")
        assert config.security_url == "https://api.strata.paloaltonetworks.com/config/security/v1"

    def test_identity_url_custom_host(self):
        config = ScmConfig(client_id="a", client_secret="b", tsg_id="c", scm_host="custom.host.com")
        assert config.identity_url == "https://custom.host.com/config/identity/v1"
