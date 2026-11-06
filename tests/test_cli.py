"""Unit tests for lh-dns CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from lh_dns_guardian.cli import app
from lh_dns_guardian.models import AuditReport, Finding, FindingCategory, Severity

runner = CliRunner()


def test_cli_version() -> None:
    """Test lh-dns --version option."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "lh-dns-guardian version" in result.output


def test_cli_help() -> None:
    """Test lh-dns --help."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "audit-domain" in result.output
    assert "audit-zone" in result.output
    assert "check-takeover" in result.output


def test_cli_audit_domain_mocked(tmp_path: Path) -> None:
    """Test audit-domain command in table and json formats."""
    dummy_report = AuditReport(target="example.com", target_type="domain")
    dummy_report.add_finding(
        Finding(
            id="LH-SEC-001",
            title="DNSSEC Not Enabled",
            category=FindingCategory.DNSSEC,
            severity=Severity.HIGH,
            target="example.com",
            description="DNSSEC disabled.",
            recommendation="Enable DNSSEC.",
        )
    )

    with patch("lh_dns_guardian.cli.DomainAuditor.audit_domain", return_value=dummy_report):
        # Format table to stdout
        res_table = runner.invoke(app, ["audit-domain", "example.com", "--format", "table"])
        assert res_table.exit_code == 0
        assert "DNSSEC Not Enabled" in res_table.output

        # Format json to file
        out_json = tmp_path / "domain.json"
        res_json = runner.invoke(
            app,
            ["audit-domain", "example.com", "--format", "json", "--output", str(out_json)],
        )
        assert res_json.exit_code == 0
        assert out_json.exists()
        parsed = json.loads(out_json.read_text(encoding="utf-8"))
        assert parsed["target"] == "example.com"
        assert parsed["total_findings"] == 1


def test_cli_audit_zone(tmp_path: Path) -> None:
    """Test audit-zone command with valid and invalid files."""
    zone_content = """$ORIGIN example.com.
$TTL 300
@ IN SOA ns1.example.com. admin.example.com. ( 1 7200 3600 1209600 3600 )
@ IN NS ns1.example.com.
"""
    zone_file = tmp_path / "test.zone"
    zone_file.write_text(zone_content, encoding="utf-8")

    sarif_out = tmp_path / "zone.sarif"
    result = runner.invoke(
        app,
        ["audit-zone", str(zone_file), "--format", "sarif", "--output", str(sarif_out)],
    )
    assert result.exit_code == 0
    assert sarif_out.exists()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"


def test_cli_check_takeover(tmp_path: Path) -> None:
    """Test check-takeover command with subdomains file."""
    sub_file = tmp_path / "subs.txt"
    sub_file.write_text("docs.example.com\napi.example.com\n# ignore\n", encoding="utf-8")

    dummy_report = AuditReport(target="subs", target_type="subdomains")
    dummy_report.add_finding(
        Finding(
            id="LH-TKO-001",
            title="Dangling CNAME Takeover",
            category=FindingCategory.TAKEOVER,
            severity=Severity.CRITICAL,
            target="docs.example.com",
            description="Takeover detected.",
            recommendation="Remove CNAME.",
        )
    )

    with patch("lh_dns_guardian.cli.DomainAuditor.check_takeover", return_value=dummy_report):
        result = runner.invoke(app, ["check-takeover", str(sub_file), "--format", "table"])
        assert result.exit_code == 0
        assert "Dangling CNAME Takeover" in result.output


def test_cli_sarif_stdout_and_errors(tmp_path: Path) -> None:
    """Test printing SARIF to stdout and handling missing files."""
    dummy_report = AuditReport(target="example.com", target_type="domain")
    with patch("lh_dns_guardian.cli.DomainAuditor.audit_domain", return_value=dummy_report):
        res = runner.invoke(app, ["audit-domain", "example.com", "--format", "sarif"])
        assert res.exit_code == 0
        assert '"version": "2.1.0"' in res.output

    # Error reading invalid zone
    bad_zone = tmp_path / "bad.zone"
    bad_zone.write_text("invalid content without soa", encoding="utf-8")
    res_bad = runner.invoke(app, ["audit-zone", str(bad_zone)])
    assert res_bad.exit_code == 1
    assert "Error parsing zone file" in res_bad.output

    # Error reading nonexistent file in check-takeover
    res_nosub = runner.invoke(app, ["check-takeover", str(tmp_path / "missing.txt")])
    assert res_nosub.exit_code != 0
