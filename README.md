# scm-chainguard

**Manage Chrome-trusted CA certificates in Palo Alto Strata Cloud Manager**

[![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

> **Beta:** This project is under active development. APIs, CLI flags, and behavior may change between releases. Use `--dry-run` to preview changes before applying them.

## Overview

scm-chainguard keeps your Palo Alto Strata Cloud Manager (SCM) SSL decryption trust store in sync with the Chrome Root Store maintained by [CCADB](https://www.ccadb.org/). It downloads the latest Chrome-trusted root (and optionally intermediate) CA certificates, compares them against what is already configured in SCM, imports any missing certificates, and adds them to the trusted root CA list used for SSL decryption.

All managed certificates are prefixed with `CG_` so they can be identified and cleaned up independently.

## Features

- **Fetch** Chrome-trusted root and intermediate CA certificates from CCADB
- **Compare** local certificates against SCM predefined and imported certificate stores
- **Sync** missing certificates into SCM and configure them as trusted roots
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
# Download Chrome-trusted root CAs from CCADB
scm-chainguard fetch

# Compare local certs against SCM
scm-chainguard compare

# Import missing certs and add as trusted roots (dry-run first)
scm-chainguard sync --dry-run
scm-chainguard sync

# Full pipeline: fetch -> compare -> sync
scm-chainguard run --dry-run
scm-chainguard run

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

## License

Apache 2.0
