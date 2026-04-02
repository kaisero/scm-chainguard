"""Tests for CCADB CSV parser."""

from scm_chainguard.ccadb.parser import attach_pems, parse_metadata
from scm_chainguard.models import CertType

METADATA_CSV = (
    "Certificate Record Type,SHA-256 Fingerprint,Certificate Name,"
    "Common Name or Certificate Name,CA Owner,Chrome Status,"
    "Revocation Status,Parent SHA-256 Fingerprint\r\n"
    # Chrome-included root
    "Root Certificate,AAAA0001,Root A,Root A,Org A,Included,Not Revoked,\r\n"
    # Chrome-included root 2
    "Root Certificate,BBBB0002,Root B,Root B,Org B,Included,Not Revoked,\r\n"
    # Non-Chrome root (should be excluded)
    "Root Certificate,CCCC0003,Root C,Root C,Org C,Not Included,Not Revoked,\r\n"
    # Revoked root (should be excluded)
    "Root Certificate,DDDD0004,Root D,Root D,Org D,Included,Revoked,\r\n"
    # Valid intermediate under Root A
    "Intermediate Certificate,EEEE0005,Inter E,Inter E,Org A,Trusted,Not Revoked,AAAA0001\r\n"
    # Revoked intermediate (should be excluded)
    "Intermediate Certificate,FFFF0006,Inter F,Inter F,Org A,Trusted,Revoked,AAAA0001\r\n"
    # Orphan intermediate (parent not a root)
    "Intermediate Certificate,1111AAAA,Inter G,Inter G,Org X,Trusted,Not Revoked,ZZZZ9999\r\n"
    # Level-2 intermediate (parent is EEEE0005)
    "Intermediate Certificate,2222BBBB,Inter H,Inter H,Org A,Trusted,Not Revoked,EEEE0005\r\n"
)


class TestParseMetadata:
    def test_roots_only(self):
        roots, intermediates = parse_metadata(METADATA_CSV, include_intermediates=False)
        assert len(roots) == 2
        assert "AAAA0001" in roots
        assert "BBBB0002" in roots
        assert len(intermediates) == 0

    def test_filters_non_chrome(self):
        roots, _ = parse_metadata(METADATA_CSV)
        assert "CCCC0003" not in roots

    def test_filters_revoked_root(self):
        roots, _ = parse_metadata(METADATA_CSV)
        assert "DDDD0004" not in roots

    def test_with_intermediates(self):
        roots, intermediates = parse_metadata(METADATA_CSV, include_intermediates=True)
        assert "EEEE0005" in intermediates
        assert intermediates["EEEE0005"].cert_type == CertType.INTERMEDIATE

    def test_filters_revoked_intermediate(self):
        _, intermediates = parse_metadata(METADATA_CSV, include_intermediates=True)
        assert "FFFF0006" not in intermediates

    def test_orphan_excluded(self):
        _, intermediates = parse_metadata(METADATA_CSV, include_intermediates=True)
        assert "1111AAAA" not in intermediates

    def test_multi_level_tree_walk(self):
        _, intermediates = parse_metadata(METADATA_CSV, include_intermediates=True)
        assert "EEEE0005" in intermediates  # level 1
        assert "2222BBBB" in intermediates  # level 2

    def test_root_cert_type(self):
        roots, _ = parse_metadata(METADATA_CSV)
        assert roots["AAAA0001"].cert_type == CertType.ROOT
        assert roots["AAAA0001"].common_name == "Root A"


class TestAttachPems:
    PEM_CSV = (
        "SHA-256 Fingerprint,X.509 Certificate (PEM)\r\n"
        "AAAA0001,-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\r\n"
    )

    def test_attaches_pem(self):
        from scm_chainguard.models import CcadbCertificate, CertType

        certs = {
            "AAAA0001": CcadbCertificate(
                sha256_fingerprint="AAAA0001",
                common_name="Root A",
                ca_owner="Org",
                cert_type=CertType.ROOT,
            )
        }
        result = attach_pems(certs, [self.PEM_CSV])
        assert "AAAA0001" in result
        assert "BEGIN CERTIFICATE" in result["AAAA0001"].pem

    def test_missing_pem_excluded(self):
        from scm_chainguard.models import CcadbCertificate, CertType

        certs = {
            "ZZZZ9999": CcadbCertificate(
                sha256_fingerprint="ZZZZ9999",
                common_name="Missing",
                ca_owner="Org",
                cert_type=CertType.ROOT,
            )
        }
        result = attach_pems(certs, [self.PEM_CSV])
        assert "ZZZZ9999" not in result
