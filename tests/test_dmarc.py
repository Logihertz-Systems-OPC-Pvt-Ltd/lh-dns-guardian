"""Unit tests for DMARC validation rules."""

from __future__ import annotations

from lh_dns_guardian.models import Severity
from lh_dns_guardian.rules.dmarc import audit_dmarc


def test_dmarc_missing() -> None:
    """Test flagging missing DMARC record."""
    findings = audit_dmarc("example.com", txt_records=[])
    assert len(findings) == 1
    assert findings[0].id == "LH-DMC-001"
    assert findings[0].severity == Severity.HIGH


def test_dmarc_multiple_records() -> None:
    """Test flagging multiple DMARC records on _dmarc."""
    txts = [
        "v=DMARC1; p=reject",
        "v=DMARC1; p=none",
    ]
    findings = audit_dmarc("example.com", txt_records=txts)
    assert any(f.id == "LH-DMC-007" and f.severity == Severity.HIGH for f in findings)


def test_dmarc_policy_none() -> None:
    """Test flagging un-enforced policy p=none."""
    txts = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
    findings = audit_dmarc("example.com", txt_records=txts)
    assert any(f.id == "LH-DMC-002" and f.severity == Severity.MEDIUM for f in findings)


def test_dmarc_policy_enforced() -> None:
    """Test pass for enforced policy p=reject or p=quarantine."""
    txts = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    findings = audit_dmarc("example.com", txt_records=txts)
    assert any(f.id == "LH-DMC-006" and f.severity == Severity.INFO for f in findings)


def test_dmarc_subdomain_policy_none() -> None:
    """Test flagging sp=none when p=reject."""
    txts = ["v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"]
    findings = audit_dmarc("example.com", txt_records=txts)
    assert any(f.id == "LH-DMC-003" and f.severity == Severity.LOW for f in findings)


def test_dmarc_pct_less_than_100() -> None:
    """Test flagging pct < 100."""
    txts = ["v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"]
    findings = audit_dmarc("example.com", txt_records=txts)
    assert any(f.id == "LH-DMC-004" and f.severity == Severity.LOW for f in findings)


def test_dmarc_missing_rua() -> None:
    """Test flagging missing aggregate reporting rua."""
    txts = ["v=DMARC1; p=reject"]
    findings = audit_dmarc("example.com", txt_records=txts)
    assert any(f.id == "LH-DMC-005" and f.severity == Severity.LOW for f in findings)

