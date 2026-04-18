"""Certificate utilities: SHA-256 fingerprints, CN extraction, filename sanitization."""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from scm_chainguard.models import CertType, LocalCertificate

logger = logging.getLogger(__name__)

MAX_FILENAME_LENGTH = 180


def pem_to_der(pem_text: str) -> bytes:
    """Extract DER bytes from PEM text."""
    lines = pem_text.strip().split("\n")
    b64 = "".join(line.strip() for line in lines if not line.startswith("-----"))
    return base64.b64decode(b64)


def pem_to_sha256(pem_text: str) -> str:
    """Compute uppercase hex SHA-256 fingerprint from PEM certificate."""
    return hashlib.sha256(pem_to_der(pem_text)).hexdigest().upper()


def extract_common_name(pem_text: str) -> str | None:
    """Extract the Common Name from a PEM certificate's subject."""
    cert = x509.load_pem_x509_certificate(pem_text.encode())
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cns[0].value if cns else None


def _ascii_transliterate(name: str) -> str:
    """Transliterate a Unicode string to ASCII.

    Uses NFKD normalization to decompose accented characters (e.g. ``í`` → ``i``,
    ``ó`` → ``o``), then strips any remaining non-ASCII characters.  If the
    result is empty (e.g. an all-kanji name), returns ``"cert"`` as a fallback.
    """
    decomposed = unicodedata.normalize("NFKD", name)
    ascii_str = decomposed.encode("ascii", "ignore").decode("ascii")
    if not ascii_str.strip():
        return "cert"
    return ascii_str


def sanitize_filename(name: str, sha256: str) -> str:
    """Build a filesystem-safe filename: {sanitized_name}_{SHA256[:8]}.pem"""
    if name:
        name = _ascii_transliterate(name)
    clean = re.sub(r"[^\w\s\-.]", "", name)
    clean = re.sub(r"\s+", "_", clean.strip())
    clean = re.sub(r"_+", "_", clean).strip("_")
    if not clean:
        clean = "unnamed"
    clean = clean[:MAX_FILENAME_LENGTH]
    return f"{clean}_{sha256[:8].upper()}.pem"


CERT_PREFIX = "CG_"
SCM_NAME_MAX = 31
_SHA_SUFFIX_LEN = 9  # _XXXXXXXX

# Ordered abbreviation rules — applied greedily until name fits.
# Longest/most-specific patterns first to avoid partial matches.
_ABBREVIATIONS = [
    ("Certification_Authority", "CA"),
    ("Certificate_Authority", "CA"),
    ("Root_Certificate_Authority", "RCA"),
    ("Authentication_Root", "Auth_R"),
    ("Authentication", "Auth"),
    ("Certification", "Cert"),
    ("Certificate", "Cert"),
    ("Authority", "Auth"),
    ("Trusted_Root", "TR"),
    ("TrustedRoot", "TR"),
    ("Global_Root", "GR"),
    ("GlobalRoot", "GR"),
    ("Root_CA", "RCA"),
    ("Public_Server", "Pub_Srv"),
    ("Communication", "Comm"),
    ("Security", "Sec"),
]


def cert_import_name(filename: str) -> str:
    """Derive an SCM-safe import name (max 31 chars) from a certificate filename.

    All managed certs are prefixed with CG_ for identification by cleanup.

    Strategy:
    1. Start with filename stem (without .pem)
    2. Transliterate non-ASCII characters to ASCII
    3. Reserve space for CG_ prefix
    4. Apply abbreviation rules iteratively until it fits
    5. If still too long, truncate the name part but keep the _SHA8 suffix
    """
    stem = _ascii_transliterate(filename.removesuffix(".pem"))
    max_len = SCM_NAME_MAX - len(CERT_PREFIX)

    if len(stem) <= max_len:
        return f"{CERT_PREFIX}{stem}"

    # Split into name and SHA suffix
    # Filename format: {name}_{8-hex-chars}.pem
    parts = stem.rsplit("_", 1)
    if len(parts) == 2 and len(parts[1]) == 8:
        name_part, sha_suffix = parts
    else:
        name_part, sha_suffix = stem, ""

    suffix = f"_{sha_suffix}" if sha_suffix else ""
    max_name = max_len - len(suffix)

    # Apply abbreviations
    abbreviated = name_part
    for pattern, replacement in _ABBREVIATIONS:
        if len(abbreviated) <= max_name:
            break
        abbreviated = abbreviated.replace(pattern, replacement)

    if len(abbreviated) <= max_name:
        return f"{CERT_PREFIX}{abbreviated}{suffix}"

    # Last resort: truncate name, keeping it readable (no trailing underscore)
    truncated = abbreviated[:max_name].rstrip("_")
    return f"{CERT_PREFIX}{truncated}{suffix}"


def pem_to_base64(pem_text: str) -> str:
    """Base64-encode full PEM text for the SCM import API."""
    return base64.b64encode(pem_text.encode()).decode()


def is_cert_expired(pem_text: str) -> bool:
    """Return True if the PEM certificate's notAfter date is in the past."""
    from datetime import datetime, timezone

    cert = x509.load_pem_x509_certificate(pem_text.encode())
    return cert.not_valid_after_utc < datetime.now(timezone.utc)


def load_local_certs(
    directory: Path,
    cert_type: CertType,
) -> list[LocalCertificate]:
    """Load all PEM certificates from a directory.

    Returns a list of LocalCertificate with CN, SHA-256, and PEM content.
    """
    from scm_chainguard.models import LocalCertificate

    certs = []
    if not directory.is_dir():
        return certs

    for path in sorted(directory.glob("*.pem")):
        pem = path.read_text()
        try:
            sha256 = pem_to_sha256(pem)
        except Exception:
            logger.warning("Failed to compute SHA-256 for %s", path.name, exc_info=True)
            sha256 = ""
        cn = extract_common_name(pem)
        if not cn:
            cn = path.stem.rsplit("_", 1)[0].replace("_", " ")
        certs.append(
            LocalCertificate(
                filepath=str(path),
                filename=path.name,
                common_name=cn,
                sha256_fingerprint=sha256,
                pem=pem,
                cert_type=cert_type,
            )
        )
    return certs
