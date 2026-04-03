"""Tests for CCADB CSV parser."""

from scm_chainguard.ccadb.parser import attach_pems, collect_distrusted_fingerprints, parse_metadata
from scm_chainguard.models import CertType, TrustStore

# CSV header includes all four trust-store status columns
_HEADER = (
    "Certificate Record Type,SHA-256 Fingerprint,Certificate Name,"
    "Common Name or Certificate Name,CA Owner,"
    "Chrome Status,Mozilla Status,Microsoft Status,Apple Status,"
    "Revocation Status,Parent SHA-256 Fingerprint\r\n"
)

METADATA_CSV = _HEADER + (
    "Root Certificate,AAAA0001,Root A,Root A,Org A,"
    "Included,Included,Included,Included,Not Revoked,\r\n"
    "Root Certificate,BBBB0002,Root B,Root B,Org B,"
    "Included,Not Yet Included,Not Included,Included,Not Revoked,\r\n"
    "Root Certificate,CCCC0003,Root C,Root C,Org C,"
    "Not Included,Included,Not Included,Not Included,Not Revoked,\r\n"
    "Root Certificate,DDDD0004,Root D,Root D,Org D,"
    "Included,Included,Included,Included,Revoked,\r\n"
    "Intermediate Certificate,EEEE0005,Inter E,Inter E,Org A,"
    "Trusted,Trusted,Trusted,Trusted,Not Revoked,AAAA0001\r\n"
    "Intermediate Certificate,FFFF0006,Inter F,Inter F,Org A,"
    "Trusted,Trusted,Trusted,Trusted,Revoked,AAAA0001\r\n"
    "Intermediate Certificate,1111AAAA,Inter G,Inter G,Org X,"
    "Trusted,Trusted,Trusted,Trusted,Not Revoked,ZZZZ9999\r\n"
    "Intermediate Certificate,2222BBBB,Inter H,Inter H,Org A,"
    "Trusted,Trusted,Trusted,Trusted,Not Revoked,EEEE0005\r\n"
)


class TestParseMetadata:
    def test_roots_only(self):
        roots, intermediates = parse_metadata(METADATA_CSV, include_intermediates=False)
        assert len(roots) == 2
        assert "AAAA0001" in roots
        assert "BBBB0002" in roots
        assert len(intermediates) == 0

    def test_filters_not_included(self):
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
    PEM_CSV = "SHA-256 Fingerprint,X.509 Certificate (PEM)\r\nAAAA0001,-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\r\n"

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


class TestMultiStore:
    def test_mozilla_includes_mozilla_only_root(self):
        """CCCC0003 is Mozilla-included but Chrome-not-included."""
        roots, _ = parse_metadata(METADATA_CSV, trust_store=TrustStore.MOZILLA)
        assert "CCCC0003" in roots
        assert "AAAA0001" in roots

    def test_mozilla_excludes_not_yet_included(self):
        """BBBB0002 is 'Not Yet Included' in Mozilla."""
        roots, _ = parse_metadata(METADATA_CSV, trust_store=TrustStore.MOZILLA)
        assert "BBBB0002" not in roots

    def test_chrome_default_excludes_mozilla_only(self):
        """Default (Chrome) still excludes CCCC0003."""
        roots, _ = parse_metadata(METADATA_CSV)
        assert "CCCC0003" not in roots

    def test_apple_includes_bbbb0002(self):
        roots, _ = parse_metadata(METADATA_CSV, trust_store=TrustStore.APPLE)
        assert "BBBB0002" in roots

    def test_microsoft_excludes_cccc0003(self):
        roots, _ = parse_metadata(METADATA_CSV, trust_store=TrustStore.MICROSOFT)
        assert "CCCC0003" not in roots

    def test_revoked_excluded_all_stores(self):
        for store in TrustStore.individual_stores():
            roots, _ = parse_metadata(METADATA_CSV, trust_store=store)
            assert "DDDD0004" not in roots, f"{store.value} should exclude revoked root"

    def test_all_store_union(self):
        """ALL includes certs from any store."""
        roots, _ = parse_metadata(METADATA_CSV, trust_store=TrustStore.ALL)
        assert "AAAA0001" in roots  # in all stores
        assert "BBBB0002" in roots  # in chrome + apple
        assert "CCCC0003" in roots  # in mozilla only
        assert "DDDD0004" not in roots  # revoked

    def test_all_store_intermediates(self):
        roots, intermediates = parse_metadata(METADATA_CSV, include_intermediates=True, trust_store=TrustStore.ALL)
        assert "EEEE0005" in intermediates
        assert "2222BBBB" in intermediates

    def test_intermediates_with_mozilla(self):
        roots, intermediates = parse_metadata(METADATA_CSV, include_intermediates=True, trust_store=TrustStore.MOZILLA)
        assert "AAAA0001" in roots
        assert "EEEE0005" in intermediates


# CSV with Removed/Blocked entries for distrusted tests
_DISTRUSTED_HEADER = (
    "Certificate Record Type,SHA-256 Fingerprint,Certificate Name,"
    "Common Name or Certificate Name,CA Owner,"
    "Chrome Status,Mozilla Status,Microsoft Status,Apple Status,"
    "Revocation Status,Parent SHA-256 Fingerprint\r\n"
)

DISTRUSTED_CSV = _DISTRUSTED_HEADER + (
    # Active root — Included everywhere
    "Root Certificate,AAAA0001,Active Root,Active Root,Org A,"
    "Included,Included,Included,Included,Not Revoked,\r\n"
    # Removed from Chrome only, still Included in other stores
    "Root Certificate,RRRR0001,Removed Chrome Only,Removed Chrome Only,Org B,"
    "Removed,Included,Included,Included,Not Revoked,\r\n"
    # Blocked in Chrome, Not Included elsewhere
    "Root Certificate,BBBB0001,Blocked All,Blocked All,Org C,"
    "Blocked,Not Included,Not Included,Not Included,Not Revoked,\r\n"
    # Removed from ALL stores
    "Root Certificate,RRRR0002,Removed Everywhere,Removed Everywhere,Org D,"
    "Removed,Removed,Removed,Removed,Not Revoked,\r\n"
    # Removed from Chrome, still Included in Mozilla
    "Root Certificate,MMMM0001,Still Mozilla,Still Mozilla,Org E,"
    "Removed,Included,Not Included,Not Included,Not Revoked,\r\n"
    # Intermediate — should be ignored by collect_distrusted_fingerprints
    "Intermediate Certificate,IIII0001,Removed Inter,Removed Inter,Org A,"
    "Removed,Removed,Removed,Removed,Not Revoked,AAAA0001\r\n"
)


class TestCollectDistrustedFingerprints:
    def test_chrome_finds_removed_and_blocked(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.CHROME)
        assert "RRRR0001" in result  # Removed
        assert "BBBB0001" in result  # Blocked
        assert "RRRR0002" in result  # Removed
        assert "MMMM0001" in result  # Removed from Chrome
        assert "AAAA0001" not in result  # Included

    def test_chrome_count(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.CHROME)
        assert len(result) == 4

    def test_all_store_excludes_still_trusted(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.ALL)
        assert "RRRR0001" not in result  # Still Included in Mozilla/Microsoft/Apple
        assert "MMMM0001" not in result  # Still Included in Mozilla

    def test_all_store_includes_removed_everywhere(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.ALL)
        assert "RRRR0002" in result  # Removed in all stores
        assert "BBBB0001" in result  # Blocked in Chrome, Not Included elsewhere

    def test_ignores_intermediates(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.CHROME)
        assert "IIII0001" not in result

    def test_returns_set(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.CHROME)
        assert isinstance(result, set)

    def test_empty_csv(self):
        result = collect_distrusted_fingerprints(_DISTRUSTED_HEADER, TrustStore.CHROME)
        assert result == set()

    def test_mozilla_excludes_mozilla_included(self):
        result = collect_distrusted_fingerprints(DISTRUSTED_CSV, TrustStore.MOZILLA)
        assert "RRRR0002" in result  # Removed in Mozilla
        assert "RRRR0001" not in result  # Included in Mozilla
        assert "MMMM0001" not in result  # Included in Mozilla
