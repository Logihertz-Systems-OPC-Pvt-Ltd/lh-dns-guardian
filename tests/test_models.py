"""Unit tests for models and data structures."""

from __future__ import annotations

from datetime import datetime, timezone

from lh_dns_guardian.models import AuditReport, Finding, FindingCategory, Severity


def test_severity_properties() -> None:
    """Test severity rank and SARIF level mappings."""
    assert Severity.CRITICAL.rank == 5
    assert Severity.HIGH.rank == 4
    assert Severity.MEDIUM.rank == 3
    assert Severity.LOW.rank == 2
    assert Severity.INFO.rank == 1

    assert Severity.CRITICAL.sarif_level == "error"
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.LOW.sarif_level == "note"
    assert Severity.INFO.sarif_level == "note"


def test_finding_to_dict() -> None:
    """Test finding serialization to dictionary."""
    finding = Finding(
        id="LH-TEST-001",
        title="Test Finding",
        category=FindingCategory.DNSSEC,
        severity=Severity.HIGH,
        target="example.com",
        description="A test security issue.",
        recommendation="Fix the test issue.",
        evidence="Evidence string",
    )
    data = finding.to_dict()
    assert data["id"] == "LH-TEST-001"
    assert data["title"] == "Test Finding"
    assert data["category"] == "DNSSEC"
    assert data["severity"] == "HIGH"
    assert data["target"] == "example.com"
    assert data["description"] == "A test security issue."
    assert data["recommendation"] == "Fix the test issue."
    assert data["evidence"] == "Evidence string"


def test_audit_report_methods() -> None:
    """Test AuditReport summary and serialization."""
    report = AuditReport(
        target="example.com",
        target_type="domain",
        timestamp=datetime.now(timezone.utc),
        metadata={"scanner": "test"},
    )
    assert not report.has_critical_or_high
    assert report.summary_counts()["HIGH"] == 0

    f1 = Finding(
        id="LH-TEST-001",
        title="Critical issue",
        category=FindingCategory.SPF,
        severity=Severity.CRITICAL,
        target="example.com",
        description="Desc",
        recommendation="Rec",
    )
    f2 = Finding(
        id="LH-TEST-002",
        title="Info issue",
        category=FindingCategory.CAA,
        severity=Severity.INFO,
        target="example.com",
        description="Desc",
        recommendation="Rec",
    )
    report.add_finding(f1)
    report.add_finding(f2)

    assert report.has_critical_or_high
    summary = report.summary_counts()
    assert summary["CRITICAL"] == 1
    assert summary["INFO"] == 1
    assert summary["HIGH"] == 0

    report_dict = report.to_dict()
    assert report_dict["target"] == "example.com"
    assert report_dict["total_findings"] == 2
    assert len(report_dict["findings"]) == 2

