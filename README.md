# lh-dns-guardian

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dns-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dns-guardian/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise dns infrastructure & email auth security developed by **Logihertz Systems (OPC) Private Limited**.

Validates BIND zone files, DNS records, DNSSEC chain integrity, SPF lookup limits, DKIM key strength, DMARC enforcement policies, CAA restrictions, and dangling CNAME subdomain takeover risks.

---

## Key Features

- **DNSSEC Cryptographic Chain Validation**: Verifies `DNSKEY`, parent `DS` delegation records, and zone `RRSIG` signatures.
- **Certificate Authority Authorization (CAA)**: Audits CAA records (`issue`, `issuewild`, `iodef`) to ensure authorized CA issuance.
- **AXFR Zone Transfer Protection**: Probes authoritative nameservers for unauthenticated full zone transfer misconfigurations.
- **SPF & DMARC Enforcement**: Evaluates Sender Policy Framework rules for `+all` risks and verifies strict DMARC quarantine/reject policies.
- **Subdomain Takeover Detection**: Checks CNAME and NS records against cloud provider fingerprints (AWS S3, GitHub Pages, Azure, Vercel).
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-SEC-001` | `CRITICAL` | DNSSEC is not enabled or published on target domain (missing DNSKEY/DS/RRSIG) |
| `LH-SEC-002` | `HIGH` | Incomplete DNSSEC chain (keys present without DS delegation or valid RRSIG) |
| `LH-CAA-001` | `HIGH` | Missing CAA records (any public CA may issue certificates for domain) |
| `LH-AXFR-001` | `CRITICAL` | Open AXFR full zone transfer permitted by authoritative nameserver |
| `LH-SPF-001` | `HIGH` | Missing SPF record on domain with mail services |
| `LH-SPF-002` | `HIGH` | Multiple SPF records published causing RFC 7208 PermError |
| `LH-SPF-003` | `CRITICAL` | Overly permissive SPF '+all' authorization mechanism allowing spoofing |
| `LH-SPF-005` | `HIGH` | Excessive SPF DNS lookups exceeding RFC 10-lookup evaluation limit |
| `LH-DMC-001` | `HIGH` | Missing DMARC policy record at _dmarc.<domain> |
| `LH-TKO-001` | `CRITICAL` | Dangling CNAME record points to unclaimed cloud provider resource |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dns-guardian.git
cd lh-dns-guardian

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-dns` (also accessible via `lh-dns`).

```bash
# Audit a live domain's DNS security posture
lh-dns audit-domain example.com

# Audit a local BIND zone file
lh-dns audit-zone /etc/bind/zones/db.example.com --format json

# Scan a list of subdomains for takeover vectors
lh-dns check-takeover subdomains.txt --format sarif --output takeover.sarif

# Specify custom nameservers for audit
lh-dns audit-domain example.com --nameserver 1.1.1.1
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
