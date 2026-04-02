"""Data models for certificates and comparison/sync results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CertType(Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"


@dataclass(frozen=True, slots=True)
class CcadbCertificate:
    """A certificate record from CCADB metadata."""

    sha256_fingerprint: str
    common_name: str
    ca_owner: str
    cert_type: CertType
    parent_sha256: str | None = None
    pem: str | None = None


@dataclass(frozen=True, slots=True)
class LocalCertificate:
    """A certificate loaded from a local PEM file."""

    filepath: str
    filename: str
    common_name: str
    sha256_fingerprint: str
    pem: str
    cert_type: CertType


@dataclass(frozen=True, slots=True)
class ScmPredefinedRoot:
    """A predefined trusted root CA from the SCM Identity API."""

    name: str
    common_name: str
    subject: str = ""
    filename: str = ""
    not_valid_after: str = ""
    expiry_epoch: str = ""


@dataclass(frozen=True, slots=True)
class ScmImportedCert:
    """An imported certificate from the SCM Identity API."""

    id: str
    name: str
    common_name: str
    sha256_fingerprint: str | None = None
    folder: str = ""
    pem: str | None = None


@dataclass(slots=True)
class ComparisonResult:
    """Result of comparing local certificates against SCM."""

    cert_type: CertType
    present: list[tuple[LocalCertificate, str]] = field(default_factory=list)
    missing: list[LocalCertificate] = field(default_factory=list)
    total_local: int = 0
    total_scm: int = 0


@dataclass(slots=True)
class SyncResult:
    """Result of a sync operation."""

    imported: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    trusted_roots_added: list[str] = field(default_factory=list)
    dry_run: bool = False


@dataclass(slots=True)
class CleanupResult:
    """Result of a cleanup operation."""

    removed_from_trusted: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    dry_run: bool = False
