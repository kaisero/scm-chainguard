"""Configuration loading: environment variables with optional YAML file override."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class ScmConfig:
    """SCM connection and operational configuration."""

    client_id: str
    client_secret: str
    tsg_id: str
    auth_url: str = "https://auth.apps.paloaltonetworks.com"
    scm_host: str = "api.strata.paloaltonetworks.com"
    cert_folder: str = "All"
    ssl_settings_folder: str = "Prisma Access"
    output_dir: str = "./output"
    request_timeout: int = 120

    @property
    def identity_url(self) -> str:
        return f"https://{self.scm_host}/config/identity/v1"

    @property
    def security_url(self) -> str:
        return f"https://{self.scm_host}/config/security/v1"


# Mapping: env var name -> ScmConfig field name
_ENV_MAP = {
    "SCM_CLIENT_ID": "client_id",
    "SCM_CLIENT_SECRET": "client_secret",
    "SCM_TSG_ID": "tsg_id",
    "SCM_AUTH_URL": "auth_url",
    "SCM_HOST": "scm_host",
    "SCM_CERT_FOLDER": "cert_folder",
    "SCM_SSL_SETTINGS_FOLDER": "ssl_settings_folder",
    "SCM_OUTPUT_DIR": "output_dir",
}

_REQUIRED_FIELDS = {"client_id", "client_secret", "tsg_id"}


def load_config(config_path: Path | None = None) -> ScmConfig:
    """Load configuration with priority: env vars > YAML file > defaults.

    Raises ConfigError if required fields are missing.
    """
    values: dict[str, Any] = {}

    # Layer 1: YAML file
    if config_path is not None:
        values.update(_load_yaml(config_path))

    # Layer 2: Environment variables (override YAML)
    for env_var, field_name in _ENV_MAP.items():
        val = os.environ.get(env_var)
        if val is not None:
            values[field_name] = val

    # Validate required fields
    missing = _REQUIRED_FIELDS - set(values.keys())
    if missing:
        fields = ", ".join(sorted(missing))
        env_vars = ", ".join(env for env, field in _ENV_MAP.items() if field in missing)
        raise ConfigError(f"Missing required configuration: {fields}. Set environment variables ({env_vars}) or provide a config file.")

    return ScmConfig(**values)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and flatten the 'scm' section of a YAML config file."""
    try:
        with path.open() as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"Failed to read config file {path}: {e}")

    if not isinstance(data, dict) or "scm" not in data:
        raise ConfigError("Config file must contain a top-level 'scm' key")

    scm_section = data["scm"]
    if not isinstance(scm_section, dict):
        raise ConfigError("Config 'scm' section must be a mapping")

    return {k: str(v) for k, v in scm_section.items() if v is not None}
