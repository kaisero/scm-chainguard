# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-04-19

### Added

- **PAN-OS 11.2 certificate compatibility check**: Certificates using algorithms unsupported by PAN-OS 11.2 SSL/TLS Decryption (RSASSA-PSS, EdDSA/Ed25519/Ed448, non-NIST curves, DSA) are now automatically skipped during sync with a clear warning log and audit trail. The check runs client-side before the API call, avoiding unnecessary import failures.
- **`--no-verify-ssl` global CLI flag**: Disables SSL certificate verification for all HTTP requests (CCADB and SCM API). Useful in environments behind TLS-intercepting proxies or upstream firewalls that inject self-signed certificates into the chain.

### Fixed

- **Snippet field leaking into SSL settings PUT payload**: The `_put_settings()` method now sends only `folder` and `ssl_decrypt` fields (explicit allowlist) instead of echoing the entire GET response, which included metadata fields like `snippet: "default"` that could cause the SCM API to misinterpret the request scope.
- **Truncated error messages from SCM API**: `extract_error_message()` now includes all detail fields from API error responses (e.g., `errorType`, `code`, `path`) as `key=value` pairs, providing full context instead of only the `message` field. This fixes truncated errors like `"Node cannot be deleted because of references from"` where the referencing context was previously discarded.

## [0.1.2] - 2026-04-18

### Fixed

- **Unicode certificate name handling**: Certificates with non-ASCII characters in their Common Name (e.g., accented Latin `í`, `ó`, or Japanese kanji) are now transliterated to ASCII before import using NFKD normalization. Names that are entirely non-ASCII fall back to a `cert` prefix. This prevents import failures caused by the SCM API rejecting unsupported encoded characters.
- **Intermediate certificates added to Trusted CA List**: Intermediate certificates are now added to the `trusted_root_CA` list after import, matching the existing behavior for root certificates. Previously they were imported but never added to the trusted list. Already-imported intermediates missing from the trusted list are also detected and added during sync.
- **Improved error logging for certificate import**: The SCM API error message (`details.message`) is now extracted and logged at ERROR level for failed imports and WARNING level for skipped certificates, making failures visible without `--debug`.
- **Skip expired certificates before import**: Certificates are now checked for expiry client-side before attempting the API call, avoiding unnecessary network round-trips and providing a clear warning log.

### Changed

- **CCADB data source upgraded from AllCertificateRecordsCSVFormatV3 to AllCertificateRecordsCSVFormatV4**.

## [0.1.1] - 2026-04-09

### Added

- **Debug logging for SCM API requests**: All HTTP requests to SCM (Identity, Security, and Auth APIs) now log the method, URL, parameters/payload, and response status/body at DEBUG level (`--debug`). The `client_secret` is masked in auth request logs.
- **`cleanup --ignore-expiry-date` flag**: New option to delete all CG_-managed certificates regardless of expiry status.

### Changed

- **Default `ssl_settings_folder` changed from "Prisma Access" to "All"**: SSL decryption settings now default to the Global folder, consistent with `cert_folder`. Override via `SCM_SSL_SETTINGS_FOLDER` env var or YAML config if needed.

## [0.1.0] - 2026-04-03

### Added

- **Multi-trust-store support**: Fetch, compare, and sync certificates from Chrome, Mozilla, Microsoft, Apple, or all trust stores via the `--store / -s` option. Chrome remains the default.
- **Revoke command**: New `revoke` command detects and removes `CG_`-managed certificates whose trust store status changed to Removed or Blocked in CCADB. Supports `--store` and `--dry-run`.

### Changed

- `parse_metadata()` accepts a `trust_store` parameter to filter by any supported store instead of hardcoding Chrome.
- `run_fetch()`, `run_compare()`, `run_sync()`, and `run_full_pipeline()` accept a `trust_store` parameter, propagated through the full pipeline.
- CLI commands `fetch`, `compare`, `sync`, and `run` now expose `--store / -s` with case-insensitive matching.
- Updated README with multi-store examples and documentation.

## [0.0.4] - 2026-04-01

### Added

- Initial release.
