"""scm-chainguard: Manage trusted CA certificates in Strata Cloud Manager."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("scm-chainguard")
except PackageNotFoundError:
    __version__ = "0.0.0"
