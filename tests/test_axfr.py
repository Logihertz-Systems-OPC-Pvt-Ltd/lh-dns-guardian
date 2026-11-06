"""Unit tests for AXFR zone transfer vulnerability detection."""

from __future__ import annotations

from lh_dns_guardian.models import Severity
from lh_dns_guardian.rules.axfr import audit_axfr


def test_axfr_open_vulnerability() -> None:
    """Test flagging of open AXFR zone transfer."""
    nameservers = ["ns1.example.com", "ns2.example.com"]

    def mock_check(zone: str, ns: str) -> bool:
        return ns == "ns1.example.com"

    findings = audit_axfr("example.com", nameservers=nameservers, check_fn=mock_check)
    assert len(findings) == 1
    assert findings[0].id == "LH-AXFR-001"
    assert findings[0].severity == Severity.CRITICAL
    assert "ns1.example.com" in findings[0].description


def test_axfr_protected() -> None:
    """Test verification when all nameservers refuse AXFR transfers."""
    nameservers = ["ns1.example.com", "ns2.example.com"]
    findings = audit_axfr("example.com", nameservers=nameservers, check_fn=lambda z, n: False)
    assert len(findings) == 1
    assert findings[0].id == "LH-AXFR-002"
    assert findings[0].severity == Severity.INFO
