# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
