"""PAN-OS 11.2 SSL/TLS Decryption certificate compatibility analysis."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import SignatureAlgorithmOID

logger = logging.getLogger(__name__)

# PAN-OS 11.2 supported signature algorithm OIDs for SSL/TLS Decryption
PANOS_SUPPORTED_SIG_OIDS = frozenset(
    {
        SignatureAlgorithmOID.RSA_WITH_MD5,
        SignatureAlgorithmOID.RSA_WITH_SHA1,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA384,
        SignatureAlgorithmOID.RSA_WITH_SHA512,
        SignatureAlgorithmOID.ECDSA_WITH_SHA1,
        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        SignatureAlgorithmOID.ECDSA_WITH_SHA384,
        SignatureAlgorithmOID.ECDSA_WITH_SHA512,
    }
)

# PAN-OS 11.2 supported ECDSA curves
PANOS_SUPPORTED_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

# Human-readable names for well-known signature OIDs
_SIG_OID_NAMES = {
    SignatureAlgorithmOID.RSA_WITH_MD5: "RSA-MD5",
    SignatureAlgorithmOID.RSA_WITH_SHA1: "RSA-SHA1",
    SignatureAlgorithmOID.RSA_WITH_SHA256: "RSA-SHA256",
    SignatureAlgorithmOID.RSA_WITH_SHA384: "RSA-SHA384",
    SignatureAlgorithmOID.RSA_WITH_SHA512: "RSA-SHA512",
    SignatureAlgorithmOID.ECDSA_WITH_SHA1: "ECDSA-SHA1",
    SignatureAlgorithmOID.ECDSA_WITH_SHA256: "ECDSA-SHA256",
    SignatureAlgorithmOID.ECDSA_WITH_SHA384: "ECDSA-SHA384",
    SignatureAlgorithmOID.ECDSA_WITH_SHA512: "ECDSA-SHA512",
    SignatureAlgorithmOID.RSASSA_PSS: "RSASSA-PSS",
    SignatureAlgorithmOID.ED25519: "Ed25519",
    SignatureAlgorithmOID.ED448: "Ed448",
}


@dataclass(frozen=True, slots=True)
class CertAlgorithmInfo:
    """Extracted algorithm information and compatibility result for one certificate."""

    sha256_fingerprint: str
    common_name: str
    ca_owner: str
    cert_type: str  # "root" or "intermediate"
    signature_algorithm_oid: str
    signature_algorithm_name: str
    public_key_type: str  # RSA, ECDSA, Ed25519, Ed448, DSA, Unknown
    key_size: int
    curve: str | None
    is_compatible: bool
    incompatibility_reasons: tuple[str, ...]


@dataclass(slots=True)
class CompatibilityReport:
    """Full compatibility analysis report."""

    total_certs: int = 0
    compatible_certs: int = 0
    incompatible_certs: int = 0
    parse_errors: int = 0
    trust_store: str = "chrome"
    include_roots: bool = True
    incompatible: list[CertAlgorithmInfo] = field(default_factory=list)
    by_reason: dict[str, list[CertAlgorithmInfo]] = field(default_factory=dict)


def _get_key_info(cert_obj: x509.Certificate) -> tuple[str, int, str | None]:
    """Extract public key type, size, and curve from a certificate."""
    pubkey = cert_obj.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", pubkey.key_size, None
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return "ECDSA", pubkey.key_size, pubkey.curve.name
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448", 448, None
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", pubkey.key_size, None
    return "Unknown", 0, None


def check_panos_compatibility(
    sig_oid: x509.ObjectIdentifier,
    key_type: str,
    key_size: int,
    curve: str | None,
) -> tuple[bool, list[str]]:
    """Check if a certificate's algorithms are compatible with PAN-OS 11.2 decryption.

    Returns (is_compatible, list_of_reasons).
    """
    reasons: list[str] = []

    # Signature algorithm check
    if sig_oid not in PANOS_SUPPORTED_SIG_OIDS:
        name = _SIG_OID_NAMES.get(sig_oid, sig_oid.dotted_string)
        if sig_oid == SignatureAlgorithmOID.RSASSA_PSS:
            reasons.append("RSASSA-PSS signature algorithm not supported by PAN-OS 11.2")
        elif sig_oid in (SignatureAlgorithmOID.ED25519, SignatureAlgorithmOID.ED448):
            reasons.append(f"{name} signature algorithm not supported by PAN-OS 11.2")
        else:
            reasons.append(f"Signature algorithm {name} (OID: {sig_oid.dotted_string}) not supported by PAN-OS 11.2")

    # Public key type check
    if key_type not in ("RSA", "ECDSA"):
        reasons.append(f"Public key type {key_type} not supported by PAN-OS 11.2")

    # ECDSA curve check
    if key_type == "ECDSA" and curve and curve not in PANOS_SUPPORTED_CURVES:
        reasons.append(f"ECDSA curve {curve} not supported by PAN-OS 11.2 (supported: P-256, P-384, P-521)")

    return len(reasons) == 0, reasons


def is_panos_compatible(pem_text: str) -> tuple[bool, list[str]]:
    """Check if a PEM certificate is compatible with PAN-OS 11.2 SSL/TLS decryption.

    Returns (is_compatible, list_of_reasons). Raises on parse failure.
    """
    cert_obj = x509.load_pem_x509_certificate(pem_text.encode())
    sig_oid = cert_obj.signature_algorithm_oid
    key_type, key_size, curve = _get_key_info(cert_obj)
    return check_panos_compatibility(sig_oid, key_type, key_size, curve)


def extract_algorithm_info(pem_text: str, sha256: str, common_name: str, ca_owner: str, cert_type: str) -> CertAlgorithmInfo:
    """Parse a certificate's PEM and extract algorithm details with compatibility check."""
    cert_obj = x509.load_pem_x509_certificate(pem_text.encode())

    sig_oid = cert_obj.signature_algorithm_oid
    sig_name = _SIG_OID_NAMES.get(sig_oid, sig_oid.dotted_string)

    key_type, key_size, curve = _get_key_info(cert_obj)
    is_compatible, reasons = check_panos_compatibility(sig_oid, key_type, key_size, curve)

    return CertAlgorithmInfo(
        sha256_fingerprint=sha256,
        common_name=common_name,
        ca_owner=ca_owner,
        cert_type=cert_type,
        signature_algorithm_oid=sig_oid.dotted_string,
        signature_algorithm_name=sig_name,
        public_key_type=key_type,
        key_size=key_size,
        curve=curve,
        is_compatible=is_compatible,
        incompatibility_reasons=tuple(reasons),
    )


def run_compatibility_analysis(
    trust_store: str = "chrome",
    include_roots: bool = True,
    timeout: int = 120,
    ssl_verify: bool = True,
) -> CompatibilityReport:
    """Fetch trusted CAs from CCADB and analyze PAN-OS 11.2 compatibility."""
    from scm_chainguard.ccadb.client import CcadbClient
    from scm_chainguard.ccadb.parser import attach_pems, parse_metadata
    from scm_chainguard.models import CcadbCertificate, TrustStore

    store = TrustStore(trust_store)
    report = CompatibilityReport(
        trust_store=trust_store,
        include_roots=include_roots,
    )

    with CcadbClient(timeout=timeout, verify=ssl_verify) as client:
        logger.info("Downloading CCADB metadata...")
        csv_text = client.download_metadata_csv()

        logger.info("Parsing metadata for %s trust store...", trust_store)
        roots, intermediates = parse_metadata(csv_text, include_intermediates=True, trust_store=store)

        certs_to_check: dict[str, CcadbCertificate] = {}
        if include_roots:
            certs_to_check.update(roots)
        certs_to_check.update(intermediates)

        logger.info(
            "Found %d roots and %d intermediates. Analyzing %d certificates.",
            len(roots),
            len(intermediates),
            len(certs_to_check),
        )

        logger.info("Downloading PEM data (3 decades)...")
        pem_csvs = client.download_all_pem_csvs()

    logger.info("Attaching PEM data to certificates...")
    certs_with_pem = attach_pems(certs_to_check, pem_csvs)

    logger.info("Analyzing %d certificates with PEM data...", len(certs_with_pem))
    by_reason: dict[str, list[CertAlgorithmInfo]] = defaultdict(list)

    for sha256, cert in certs_with_pem.items():
        report.total_certs += 1
        try:
            info = extract_algorithm_info(
                cert.pem,
                cert.sha256_fingerprint,
                cert.common_name,
                cert.ca_owner,
                cert.cert_type.value,
            )
        except Exception:
            logger.warning(
                "Failed to parse certificate %s (%s)",
                sha256[:16],
                cert.common_name,
                exc_info=True,
            )
            report.parse_errors += 1
            continue

        if info.is_compatible:
            report.compatible_certs += 1
        else:
            report.incompatible_certs += 1
            report.incompatible.append(info)
            for reason in info.incompatibility_reasons:
                by_reason[reason].append(info)

    report.by_reason = dict(by_reason)
    return report


def generate_text_report(report: CompatibilityReport) -> str:
    """Generate a human-readable text report."""
    lines: list[str] = []
    sep = "=" * 80
    lines.append(sep)
    lines.append("PAN-OS 11.2 SSL/TLS Decryption - Certificate Compatibility Report")
    lines.append(sep)
    cert_types = "Roots + Intermediates" if report.include_roots else "Intermediates only"
    lines.append(f"Trust Store: {report.trust_store}")
    lines.append(f"Certificate Types: {cert_types}")
    lines.append(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("-" * 80)
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  Total certificates analyzed:  {report.total_certs}")
    lines.append(f"  Compatible:                   {report.compatible_certs}")
    lines.append(f"  Incompatible:                 {report.incompatible_certs}")
    lines.append(f"  Parse errors:                 {report.parse_errors}")
    lines.append("")

    if not report.incompatible:
        lines.append("All certificates are compatible with PAN-OS 11.2 SSL/TLS Decryption.")
        lines.append(sep)
        return "\n".join(lines)

    lines.append("INCOMPATIBLE CERTIFICATES BY REASON")
    lines.append(sep)

    for reason, certs in sorted(report.by_reason.items()):
        lines.append("")
        lines.append(f"[{reason}] ({len(certs)} cert(s))")
        lines.append("-" * 80)
        for i, info in enumerate(sorted(certs, key=lambda c: c.common_name), 1):
            key_desc = f"{info.public_key_type} {info.key_size} bits"
            if info.curve:
                key_desc += f" ({info.curve})"
            lines.append(f"  {i}. {info.common_name}")
            lines.append(f"     CA Owner:    {info.ca_owner}")
            lines.append(f"     Type:        {info.cert_type.capitalize()}")
            lines.append(f"     Sig Algo:    {info.signature_algorithm_name} ({info.signature_algorithm_oid})")
            lines.append(f"     Key Type:    {key_desc}")
            lines.append(f"     SHA-256:     {info.sha256_fingerprint}")
            lines.append("")

    lines.append(sep)
    return "\n".join(lines)


def generate_json_report(report: CompatibilityReport) -> str:
    """Generate a JSON report."""
    data = {
        "summary": {
            "total_certs": report.total_certs,
            "compatible": report.compatible_certs,
            "incompatible": report.incompatible_certs,
            "parse_errors": report.parse_errors,
            "trust_store": report.trust_store,
            "include_roots": report.include_roots,
            "date": datetime.now(timezone.utc).isoformat(),
        },
        "incompatible_certificates": [asdict(c) for c in report.incompatible],
        "by_reason": {reason: [asdict(c) for c in certs] for reason, certs in report.by_reason.items()},
    }
    return json.dumps(data, indent=2)
