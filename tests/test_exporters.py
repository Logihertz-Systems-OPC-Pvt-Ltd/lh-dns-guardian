"""Unit tests for Table, JSON, and OASIS SARIF exporters."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from lh_dns_guardian.exporters.json_exporter import JsonExporter
from lh_dns_guardian.exporters.sarif import SarifExporter
from lh_dns_guardian.exporters.table import TableExporter
from lh_dns_guardian.models import AuditReport, Finding, FindingCategory, Severity


def create_sample_report() -> AuditReport:
    """Helper to create sample report with multiple findings."""
    report = AuditReport(
        target="example.com",
        target_type="domain",
        timestamp=datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc),
        metadata={"nameserver": "8.8.8.8"},
    )
    report.add_finding(
        Finding(
            id="LH-SEC-001",
            title="DNSSEC Not Enabled",
            category=FindingCategory.DNSSEC,
            severity=Severity.HIGH,
            target="example.com",
            description="DNSSEC is disabled.",
            recommendation="Enable DNSSEC.",
            evidence="No DNSKEY records.",
        )
    )
    report.add_finding(
        Finding(
            id="LH-SPF-003",
            title="Overly Permissive SPF Record (+all)",
            category=FindingCategory.SPF,
            severity=Severity.CRITICAL,
            target="example.com",
            description="SPF uses +all.",
            recommendation="Change to -all.",
            evidence="v=spf1 +all",
        )
    )
    report.add_finding(
        Finding(
            id="LH-CAA-002",
            title="CAA Configured",
            category=FindingCategory.CAA,
            severity=Severity.INFO,
            target="example.com",
            description="CAA valid.",
            recommendation="Maintain policy.",
            evidence='0 issue "letsencrypt.org"',
        )
    )
    return report


def test_table_exporter(tmp_path: Path) -> None:
    """Test TableExporter renders table and writes to file."""
    report = create_sample_report()
    exporter = TableExporter()

    # In-memory export
    table_str = exporter.export(report)
    assert "lh-dns-guardian Security Posture Report" in table_str
    assert "LH-SEC-001" in table_str
    assert "LH-SPF-003" in table_str
    assert "example.com" in table_str

    # File export
    out_file = tmp_path / "report.txt"
    exporter.export(report, output_file=str(out_file))
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Audit Findings" in content


def test_json_exporter(tmp_path: Path) -> None:
    """Test JsonExporter generates valid JSON and writes to file."""
    report = create_sample_report()
    exporter = JsonExporter()

    json_str = exporter.export(report)
    parsed = json.loads(json_str)
    assert parsed["target"] == "example.com"
    assert parsed["total_findings"] == 3
    assert parsed["summary"]["CRITICAL"] == 1
    assert parsed["summary"]["HIGH"] == 1
    assert parsed["summary"]["INFO"] == 1
    assert len(parsed["findings"]) == 3

    # File export
    out_file = tmp_path / "report.json"
    exporter.export(report, output_file=str(out_file))
    assert out_file.exists()
    assert json.loads(out_file.read_text(encoding="utf-8"))["target"] == "example.com"


def test_sarif_exporter(tmp_path: Path) -> None:
    """Test SarifExporter produces OASIS SARIF v2.1.0 compliant JSON."""
    report = create_sample_report()
    exporter = SarifExporter()

    sarif_str = exporter.export(report)
    sarif_data = json.loads(sarif_str)

    assert sarif_data["version"] == "2.1.0"
    assert "$schema" in sarif_data
    assert len(sarif_data["runs"]) == 1

    run = sarif_data["runs"][0]
    assert run["tool"]["driver"]["name"] == "lh-dns-guardian"
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 3

    # Verify severity mapping to SARIF level
    results_by_id = {r["ruleId"]: r for r in run["results"]}
    assert results_by_id["LH-SPF-003"]["level"] == "error"  # CRITICAL -> error
    assert results_by_id["LH-SEC-001"]["level"] == "error"  # HIGH -> error
    assert results_by_id["LH-CAA-002"]["level"] == "note"   # INFO -> note

    # File export
    out_file = tmp_path / "report.sarif"
    exporter.export(report, output_file=str(out_file))
    assert out_file.exists()

