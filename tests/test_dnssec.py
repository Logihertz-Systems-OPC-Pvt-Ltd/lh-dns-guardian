"""Unit tests for DNSSEC audit rule engine."""

from __future__ import annotations

from lh_dns_guardian.models import Severity
from lh_dns_guardian.rules.dnssec import audit_dnssec


def test_dnssec_missing() -> None:
    """Test detection of completely missing DNSSEC records."""
    findings = audit_dnssec("example.com", dnskey_records=[], ds_records=[], rrsig_records=[])
    assert len(findings) == 1
    assert findings[0].id == "LH-SEC-001"
    assert findings[0].severity == Severity.HIGH
    assert "not have DNSSEC enabled" in findings[0].description


def test_dnssec_incomplete() -> None:
    """Test detection of incomplete DNSSEC setup (DNSKEY present but missing DS or RRSIG)."""
    findings = audit_dnssec(
        "example.com",
        dnskey_records=["257 3 13 mdsswU..."],
        ds_records=[],
        rrsig_records=[],
    )
    assert len(findings) == 1
    assert findings[0].id == "LH-SEC-002"
    assert findings[0].severity == Severity.MEDIUM
    assert "missing: parent DS delegation, zone RRSIG signatures" in findings[0].description


def test_dnssec_active() -> None:
    """Test verification of fully signed and active DNSSEC zone."""
    findings = audit_dnssec(
        "example.com",
        dnskey_records=["257 3 13 mdsswU..."],
        ds_records=["12345 13 2 49fd..."],
        rrsig_records=["SOA 13 2 3600 ..."],
    )
    assert len(findings) == 1
    assert findings[0].id == "LH-SEC-003"
    assert findings[0].severity == Severity.INFO
