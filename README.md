# scm-chainguard

**Manage Trusted CA certificates for Outbound Decryption in Strata Cloud Manager**

[![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

> **Beta:** This project is under active development. APIs, CLI flags, and behavior may change between releases. Use `--dry-run` to preview changes before applying them.

## Overview

scm-chainguard keeps your Strata Cloud Manager SSL decryption trust store in sync with publicly trusted CA certificates maintained by [CCADB](https://www.ccadb.org/). It downloads the latest root (and optionally intermediate) CA certificates from one or more trust stores (Chrome, Mozilla, Microsoft, Apple, or all), compares them against what is already configured in SCM, imports any missing certificates, and adds them to the trusted root CA list used for SSL decryption.

All managed certificates are prefixed with `CG_` so they can be identified and cleaned up independently.

## Features

- **Fetch** trusted root and intermediate CA certificates from CCADB (Chrome, Mozilla, Microsoft, Apple, or all stores)
- **Compare** local certificates against SCM predefined and imported certificate stores
- **Sync** missing certificates into SCM and configure them as trusted roots
- **Revoke** certificates that have been removed or blocked by the trust store
- **Cleanup** expired `CG_`-managed certificates from SCM
- **Dry-run mode** for all write operations

## Requirements

- Python >= 3.11
- An SCM service account with `client_id`, `client_secret`, and `tsg_id`

## Installation

```bash
pip install scm-chainguard
```

Or install from source:

```bash
git clone https://gitlab.com/dephell/scm-chainguard.git
cd scm-chainguard
pip install -e "."
```

## Configuration

Set environment variables:

```bash
export SCM_CLIENT_ID="your-client-id"
export SCM_CLIENT_SECRET="your-client-secret"
export SCM_TSG_ID="your-tsg-id"
```

Or use a YAML config file:

```yaml
scm:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  tsg_id: "your-tsg-id"
```

## Quick Start

```bash
# Download Chrome-trusted root CAs from CCADB (default store)
scm-chainguard fetch

# Fetch from a different trust store
scm-chainguard fetch --store mozilla
scm-chainguard fetch --store apple
scm-chainguard fetch --store microsoft

# Fetch from all trust stores at once
scm-chainguard fetch --store all

# Include intermediate certificates
scm-chainguard fetch --store chrome --include-intermediates

# Compare local certs against SCM
scm-chainguard compare
scm-chainguard compare --store mozilla

# Import missing certs and add as trusted roots (dry-run first)
scm-chainguard sync --dry-run
scm-chainguard sync
scm-chainguard sync --store all --include-intermediates

# Full pipeline: fetch -> compare -> sync
scm-chainguard run --dry-run
scm-chainguard run
scm-chainguard run --store mozilla

# Remove CG_-managed certificates distrusted by the trust store
scm-chainguard revoke --dry-run
scm-chainguard revoke
scm-chainguard revoke --store all

# Remove expired CG_-managed certificates
scm-chainguard cleanup --dry-run
scm-chainguard cleanup
```

### Common Options

| Option | Description |
|---|---|
| `--config / -c` | Path to YAML config file |
| `--debug` | Enable debug logging |
| `--log-file` | Write logs to file |
| `--dry-run / -n` | Show what would be done without making changes |
| `--include-intermediates / -i` | Include intermediate certificates |
| `--store / -s` | Trust store to filter by: `chrome` (default), `mozilla`, `microsoft`, `apple`, `all` |


### Disclaimer

`scm-chainguard` currently imports all certificates in the 'Global' folder due to an existing SCM API Implementation.

## License

Apache 2.0
