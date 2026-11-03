# lh-dns-guardian

A comprehensive domain name resolution and DNS security posture validator by **Logihertz Systems OPC Pvt Ltd**.

`lh-dns-guardian` audits live domains and BIND master zone files to detect missing DNSSEC, weak or missing SPF and DMARC policies, missing CAA constraints, open AXFR zone transfers, and dangling subdomain takeover vulnerabilities.

---

## Features

- **DNSSEC Validation**: Verifies published `DNSKEY`, parent `DS` delegation records, and zone `RRSIG` signatures to prevent DNS spoofing and cache poisoning.
- **Certificate Authority Authorization (CAA)**: Audits CAA records (`issue`, `issuewild`, `iodef`) to ensure only authorized Certificate Authorities can issue TLS certificates for your domains.
- **Zone Transfer (AXFR) Protection**: Probes authoritative nameservers for unauthenticated full zone transfer misconfigurations that expose internal networks and unpublished subdomains.
- **SPF Policy Enforcement**: Validates Sender Policy Framework (RFC 7208) for overly permissive mechanisms (`+all`, `?all`), deprecated mechanisms (`ptr`), multiple records, and excessive DNS lookup chains exceeding the 10-lookup limit.
- **DMARC Compliance**: Audits `_dmarc` policy records (RFC 7489) for un-enforced monitoring policies (`p=none`), insecure subdomain policies (`sp=none`), partial enforcement (`pct < 100`), and missing aggregate reporting (`rua`).
- **Dangling Subdomain Takeover Detection**: Scans CNAME and NS records against signatures for major cloud providers:
  - **GitHub Pages** (`*.github.io`)
  - **Amazon Web Services (AWS) S3** (`*.s3.amazonaws.com`, `*.s3-website*.amazonaws.com`)
  - **Microsoft Azure** (`*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net`)
  - **Vercel** (`cname.vercel-dns.com`, `*.vercel.app`)
  - **Heroku** (`*.herokuapp.com`, `*.herokudns.com`)
  - **Dangling NS Delegations** (AWS Route53, Azure DNS)
- **Multi-Format Export**: Generates beautiful Rich terminal tables, structured JSON, or standard **OASIS SARIF v2.1.0** reports for integration with CI/CD and security scanners (such as GitHub Code Scanning).

---

## Installation

### Using uv (Recommended)

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard pip

```bash
pip install -e ".[dev]"
```

---

## CLI Usage

The command-line interface entry point is `lh-dns`.

```bash
lh-dns --help
```

### 1. Audit Live Domain

Audit an active domain name resolution posture against default or specified nameservers:

```bash
# Terminal table output
lh-dns audit-domain example.com --nameserver 8.8.8.8

# Structured JSON export
lh-dns audit-domain example.com --format json --output report.json

# OASIS SARIF v2.1.0 export
lh-dns audit-domain example.com --format sarif --output report.sarif
```

### 2. Audit BIND Zone File

Perform an offline audit of a BIND master zone file:

```bash
# Terminal table output
lh-dns audit-zone /etc/bind/zones/example.com.zone

# JSON report output
lh-dns audit-zone /etc/bind/zones/example.com.zone --format json --output zone-report.json
```

### 3. Scan Subdomains for Takeover Risks

Scan a list of subdomains for dangling CNAME and NS records:

```bash
# Scan subdomains listed in a text file (one per line)
lh-dns check-takeover subdomains.txt --nameserver 8.8.8.8 --format table

# Export findings to SARIF for security pipelines
lh-dns check-takeover subdomains.txt --format sarif --output takeover-findings.sarif
```

---

## Rule Reference

| Rule ID | Severity | Category | Description |
| :--- | :--- | :--- | :--- |
| **LH-SEC-001** | `HIGH` | DNSSEC | DNSSEC is not enabled (missing DNSKEY, DS, RRSIG). |
| **LH-SEC-002** | `MEDIUM` | DNSSEC | Incomplete DNSSEC (keys present without DS or RRSIG). |
| **LH-SEC-003** | `INFO` | DNSSEC | DNSSEC active and valid. |
| **LH-CAA-001** | `MEDIUM` | CAA | Missing CAA records (any public CA may issue certs). |
| **LH-CAA-002** | `INFO` | CAA | CAA policy configured with authorized CAs. |
| **LH-AXFR-001** | `CRITICAL` | Zone Transfer | Open AXFR zone transfer permitted by nameserver. |
| **LH-AXFR-002** | `INFO` | Zone Transfer | Zone transfers properly restricted. |
| **LH-SPF-001** | `HIGH` | SPF | Missing SPF record. |
| **LH-SPF-002** | `HIGH` | SPF | Multiple SPF records published (PermError). |
| **LH-SPF-003** | `CRITICAL` | SPF | Overly permissive `+all` mechanism. |
| **LH-SPF-004** | `MEDIUM` | SPF | Permissive neutral `?all` mechanism. |
| **LH-SPF-005** | `HIGH` | SPF | Excessive DNS lookups (>10 lookups limit). |
| **LH-SPF-006** | `MEDIUM` | SPF | Deprecated `ptr` mechanism in SPF. |
| **LH-SPF-007** | `INFO` | SPF | Strict `-all` policy enforced. |
| **LH-SPF-008** | `LOW` | SPF | SoftFail `~all` policy configured. |
| **LH-DMC-001** | `HIGH` | DMARC | Missing DMARC record at `_dmarc.<domain>`. |
| **LH-DMC-002** | `MEDIUM` | DMARC | Un-enforced DMARC policy (`p=none`). |
| **LH-DMC-003** | `LOW` | DMARC | Un-enforced subdomain policy (`sp=none`). |
| **LH-DMC-004** | `LOW` | DMARC | Partial DMARC enforcement percentage (`pct < 100`). |
| **LH-DMC-005** | `LOW` | DMARC | Missing aggregate reporting URI (`rua`). |
| **LH-DMC-006** | `INFO` | DMARC | DMARC policy enforced (`p=quarantine` / `p=reject`). |
| **LH-DMC-007** | `HIGH` | DMARC | Multiple DMARC records found (PermError). |
| **LH-TKO-001** | `CRITICAL` | Takeover | Dangling CNAME points to unclaimed cloud resource. |
| **LH-TKO-002** | `HIGH` | Takeover | Dangling NS delegation to inactive cloud nameserver. |
| **LH-TKO-003** | `INFO` | Takeover | Subdomain target resolved and verified. |

---

## Development & Testing

Run linting, security scans, and tests with:

```bash
# Linting
ruff check .

# Security scanning
bandit -r src

# Unit tests with coverage
pytest --cov=lh_dns_guardian --cov-report=term-missing
```

---

## License

This software is released under the **MIT License**. See [LICENSE](LICENSE) for details.  
Copyright (c) 2026 Logihertz Systems OPC Pvt Ltd.
