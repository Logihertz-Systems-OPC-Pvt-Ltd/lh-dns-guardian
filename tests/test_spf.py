# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        tests.test_spf
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Sender Policy Framework (SPF) rules and lookup chain counter."""

from __future__ import annotations

from typing import Dict, List

from lh_dns_guardian.models import Severity
from lh_dns_guardian.rules.spf import audit_spf, count_spf_lookups


def test_spf_missing() -> None:
    """Test detection of missing SPF record."""
    findings = audit_spf("example.com", txt_records=[])
    assert len(findings) == 1
    assert findings[0].id == "LH-SPF-001"
    assert findings[0].severity == Severity.HIGH


def test_spf_multiple_records() -> None:
    """Test flagging of multiple SPF records violating RFC 7208."""
    txts = [
        "v=spf1 ip4:192.0.2.1 -all",
        "v=spf1 include:_spf.google.com ~all",
    ]
    findings = audit_spf("example.com", txt_records=txts)
    multiple_finding = next((f for f in findings if f.id == "LH-SPF-002"), None)
    assert multiple_finding is not None
    assert multiple_finding.severity == Severity.HIGH


def test_spf_permissive_plus_all() -> None:
    """Test flagging of overly permissive +all mechanism."""
    findings = audit_spf("example.com", txt_records=["v=spf1 +all"])
    assert any(f.id == "LH-SPF-003" and f.severity == Severity.CRITICAL for f in findings)


def test_spf_permissive_question_all() -> None:
    """Test flagging of permissive neutral ?all mechanism."""
    findings = audit_spf("example.com", txt_records=["v=spf1 ?all"])
    assert any(f.id == "LH-SPF-004" and f.severity == Severity.MEDIUM for f in findings)


def test_spf_strict_minus_all() -> None:
    """Test validation of strict -all mechanism."""
    findings = audit_spf("example.com", txt_records=["v=spf1 ip4:192.0.2.0/24 -all"])
    assert any(f.id == "LH-SPF-007" and f.severity == Severity.INFO for f in findings)


def test_spf_softfail_tilde_all() -> None:
    """Test flagging of SoftFail ~all mechanism."""
    findings = audit_spf("example.com", txt_records=["v=spf1 ip4:192.0.2.0/24 ~all"])
    assert any(f.id == "LH-SPF-008" and f.severity == Severity.LOW for f in findings)


def test_spf_deprecated_ptr() -> None:
    """Test detection of deprecated ptr mechanism."""
    findings = audit_spf("example.com", txt_records=["v=spf1 ptr -all"])
    assert any(f.id == "LH-SPF-006" and f.severity == Severity.MEDIUM for f in findings)


def test_spf_excessive_lookups_direct() -> None:
    """Test direct SPF mechanism counting exceeding 10 lookups."""
    # 11 lookup mechanisms (a, mx, includes)
    record = (
        "v=spf1 a mx "
        "include:spf1.com include:spf2.com include:spf3.com "
        "include:spf4.com include:spf5.com include:spf6.com "
        "include:spf7.com include:spf8.com include:spf9.com -all"
    )
    count = count_spf_lookups(record)
    assert count == 11
    findings = audit_spf("example.com", txt_records=[record])
    assert any(f.id == "LH-SPF-005" and f.severity == Severity.HIGH for f in findings)


def test_spf_excessive_lookups_recursive() -> None:
    """Test recursive lookup traversal through include: chains."""
    mock_dns: Dict[str, List[str]] = {
        "example.com": ["v=spf1 include:inc1.example.com include:inc2.example.com -all"],
        "inc1.example.com": ["v=spf1 a mx include:sub1.example.com include:sub2.example.com -all"],
        "inc2.example.com": ["v=spf1 a mx include:sub3.example.com include:sub4.example.com -all"],
        "sub1.example.com": ["v=spf1 a mx -all"],
        "sub2.example.com": ["v=spf1 a mx -all"],
        "sub3.example.com": ["v=spf1 a mx -all"],
        "sub4.example.com": ["v=spf1 a mx -all"],
    }

    def resolve_mock(dom: str) -> List[str]:
        return mock_dns.get(dom, [])

    findings = audit_spf(
        "example.com",
        txt_records=mock_dns["example.com"],
        resolve_fn=resolve_mock,
    )
    # Total lookups: root (2) + inc1 (4) + sub1 (2) + sub2 (2) + inc2 (4) + sub3/4 (4) > 10
    assert any(f.id == "LH-SPF-005" and f.severity == Severity.HIGH for f in findings)


def test_spf_redirect_modifier() -> None:
    """Test SPF evaluation following redirect= modifier."""
    mock_records: Dict[str, List[str]] = {
        "example.com": ["v=spf1 redirect=_spf.example.org"],
        "_spf.example.org": ["v=spf1 a mx -all"],
    }
    findings = audit_spf(
        "example.com",
        txt_records=mock_records["example.com"],
        resolve_fn=lambda d: mock_records.get(d, []),
    )
    assert any(f.id == "LH-SPF-007" for f in findings)
