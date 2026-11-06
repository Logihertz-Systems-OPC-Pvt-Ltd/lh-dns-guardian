# Security Rules Reference: lh-dns-guardian

An enterprise domain name resolution & dns posture validator developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-dns-guardian`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-SEC-001` | `CRITICAL` | DNSSEC | DNSSEC is Not Enabled on Target Domain |
| `LH-SEC-002` | `HIGH` | DNSSEC | Incomplete DNSSEC Chain or Broken Delegation |
| `LH-CAA-001` | `HIGH` | CAA | Missing Certificate Authority Authorization (CAA) Records |
| `LH-AXFR-001` | `CRITICAL` | Zone Transfer | Open AXFR Full Zone Transfer Permitted by Nameserver |
| `LH-SPF-001` | `HIGH` | SPF | Missing SPF Record on Domain with Mail Infrastructure |
| `LH-SPF-002` | `HIGH` | SPF | Multiple SPF Records Published Causing PermError |
| `LH-SPF-003` | `CRITICAL` | SPF | Overly Permissive SPF '+all' Mechanism |
| `LH-SPF-005` | `HIGH` | SPF | Excessive SPF DNS Lookups Exceeding 10-Lookup Limit |
| `LH-DMC-001` | `HIGH` | DMARC | Missing DMARC Policy Record at _dmarc.<domain> |
| `LH-TKO-001` | `CRITICAL` | Takeover | Dangling CNAME Points to Unclaimed Cloud Resource |

---

## Granular Rule Specifications

### `LH-SEC-001`: DNSSEC is Not Enabled on Target Domain

- **Severity**: `CRITICAL`
- **Category**: `DNSSEC`
- **Description**: DNSSEC records (DNSKEY, DS, RRSIG) are not published, leaving domain vulnerable to spoofing.
- **Remediation**: Generate DNSSEC key pairs, publish DNSKEY records, and upload DS records to domain registrar.

---

### `LH-SEC-002`: Incomplete DNSSEC Chain or Broken Delegation

- **Severity**: `HIGH`
- **Category**: `DNSSEC`
- **Description**: DNSKEY records present without valid DS delegation at the parent zone or missing RRSIG.
- **Remediation**: Ensure parent registrar has published DS records matching the active Key Signing Key (KSK).

---

### `LH-CAA-001`: Missing Certificate Authority Authorization (CAA) Records

- **Severity**: `HIGH`
- **Category**: `CAA`
- **Description**: Missing CAA records allowing any public CA to issue TLS certificates for domain.
- **Remediation**: Publish CAA records with issue and issuewild tags restricting issuance to approved CAs.

---

### `LH-AXFR-001`: Open AXFR Full Zone Transfer Permitted by Nameserver

- **Severity**: `CRITICAL`
- **Category**: `Zone Transfer`
- **Description**: Authoritative nameserver responds to unauthenticated AXFR requests, exposing internal topology.
- **Remediation**: Restrict zone transfers strictly to secondary nameserver IP addresses via allow-transfer.

---

### `LH-SPF-001`: Missing SPF Record on Domain with Mail Infrastructure

- **Severity**: `HIGH`
- **Category**: `SPF`
- **Description**: Domain lacks TXT record defining Sender Policy Framework (SPF) rules.
- **Remediation**: Publish valid SPF TXT record (v=spf1) declaring authorized outbound mail servers.

---

### `LH-SPF-002`: Multiple SPF Records Published Causing PermError

- **Severity**: `HIGH`
- **Category**: `SPF`
- **Description**: Multiple SPF TXT records published at apex causing RFC 7208 PermError and validation bypass.
- **Remediation**: Merge all authorized senders into a single consolidated SPF TXT record.

---

### `LH-SPF-003`: Overly Permissive SPF '+all' Mechanism

- **Severity**: `CRITICAL`
- **Category**: `SPF`
- **Description**: SPF policy ends with +all allowing any host on the internet to send mail as this domain.
- **Remediation**: Change SPF terminal mechanism to strict -all (hard fail) or ~all (soft fail).

---

### `LH-SPF-005`: Excessive SPF DNS Lookups Exceeding 10-Lookup Limit

- **Severity**: `HIGH`
- **Category**: `SPF`
- **Description**: SPF policy requires more than 10 DNS lookups to evaluate, causing RFC PermError.
- **Remediation**: Flatten SPF includes and replace excessive domain lookups with ip4/ip6 CIDR blocks.

---

### `LH-DMC-001`: Missing DMARC Policy Record at _dmarc.<domain>

- **Severity**: `HIGH`
- **Category**: `DMARC`
- **Description**: Domain lacks DMARC TXT record, allowing spoofed emails to bypass recipient filters.
- **Remediation**: Publish DMARC record at _dmarc.<domain> enforcing p=quarantine or p=reject policy.

---

### `LH-TKO-001`: Dangling CNAME Points to Unclaimed Cloud Resource

- **Severity**: `CRITICAL`
- **Category**: `Takeover`
- **Description**: Subdomain CNAME resolves to unclaimed third-party cloud resource (S3, GitHub Pages, Azure).
- **Remediation**: Remove dangling CNAME record immediately or re-provision target cloud resource.

---
