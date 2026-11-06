"""Unit tests for DomainAuditor orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from lh_dns_guardian.auditor import DomainAuditor
from lh_dns_guardian.models import FindingCategory, Severity
from lh_dns_guardian.resolver import DNSQueryClient

SAMPLE_ZONE = """$ORIGIN vulnerable.org.
$TTL 3600
@   IN  SOA ns1.vulnerable.org. admin.vulnerable.org. ( 2026110101 7200 3600 1209600 3600 )
@   IN  NS  ns1.vulnerable.org.
@   IN  TXT "v=spf1 +all"
_dmarc IN TXT "v=DMARC1; p=none"
app IN  CNAME unclaimed.azurewebsites.net.
"""


def test_audit_domain_mocked() -> None:
    """Test auditing live domain with all external DNS queries mocked."""
    mock_client = MagicMock(spec=DNSQueryClient)
    mock_client.get_ns.return_value = ["ns1.example.com"]
    mock_client.check_axfr.return_value = False
    mock_client.get_dnskey.return_value = []
    mock_client.get_ds.return_value = []
    mock_client.get_rrsig.return_value = []
    mock_client.get_caa.return_value = []
    mock_client.get_txt.side_effect = lambda q: (
        ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
        if q.startswith("_dmarc")
        else ["v=spf1 -all"]
    )
    mock_client.get_cname.return_value = None

    auditor = DomainAuditor(resolver=mock_client)
    report = auditor.audit_domain("example.com")

    assert report.target == "example.com"
    assert report.target_type == "domain"

    # Should detect missing DNSSEC
    assert any(
        f.category == FindingCategory.DNSSEC and f.severity == Severity.HIGH
        for f in report.findings
    )
    # Should detect missing CAA
    assert any(
        f.category == FindingCategory.CAA and f.severity == Severity.MEDIUM for f in report.findings
    )
    # Should detect strict SPF
    assert any(
        f.category == FindingCategory.SPF and f.severity == Severity.INFO for f in report.findings
    )
    # Should detect enforced DMARC
    assert any(
        f.category == FindingCategory.DMARC and f.severity == Severity.INFO for f in report.findings
    )


def test_audit_zone_file(tmp_path: Path) -> None:
    """Test auditing BIND zone file with auditor."""
    zone_path = tmp_path / "vulnerable.org.zone"
    zone_path.write_text(SAMPLE_ZONE, encoding="utf-8")

    auditor = DomainAuditor()
    # Mock target_resolves to False for unresolvable takeover detection
    with patch.object(auditor.resolver, "target_resolves", return_value=False):
        report = auditor.audit_zone(zone_file=zone_path)

    assert report.target == "vulnerable.org"
    assert report.target_type == "zone"

    # Verify +all was detected
    assert any(f.id == "LH-SPF-003" and f.severity == Severity.CRITICAL for f in report.findings)
    # Verify p=none was detected
    assert any(f.id == "LH-DMC-002" and f.severity == Severity.MEDIUM for f in report.findings)
    # Verify CNAME takeover on unclaimed.azurewebsites.net
    assert any(f.id == "LH-TKO-001" and f.severity == Severity.CRITICAL for f in report.findings)


def test_check_takeover_subdomains_list() -> None:
    """Test scanning a list of subdomains for takeover risks."""
    mock_client = MagicMock(spec=DNSQueryClient)

    def mock_cname(sub: str) -> str | None:
        if sub == "docs.example.com":
            return "example.github.io"
        return None

    mock_client.get_cname.side_effect = mock_cname
    mock_client.get_ns.return_value = []
    mock_client.target_resolves.return_value = False

    auditor = DomainAuditor(resolver=mock_client)
    subdomains = ["docs.example.com", "api.example.com", "# comment line", ""]
    report = auditor.check_takeover(subdomains=subdomains)

    assert report.target_type == "subdomains"
    assert any(f.id == "LH-TKO-001" and "docs.example.com" in f.target for f in report.findings)


def test_audit_domain_root_cname_takeover() -> None:
    """Test audit_domain when root domain itself has a dangling CNAME."""
    mock_client = MagicMock(spec=DNSQueryClient)
    mock_client.get_ns.return_value = []
    mock_client.get_dnskey.return_value = []
    mock_client.get_ds.return_value = []
    mock_client.get_rrsig.return_value = []
    mock_client.get_caa.return_value = []
    mock_client.get_txt.return_value = []
    mock_client.get_cname.return_value = "myapp.herokuapp.com"
    mock_client.target_resolves.return_value = False

    auditor = DomainAuditor(resolver=mock_client)
    report = auditor.audit_domain("example.com")
    assert any(f.id == "LH-TKO-001" for f in report.findings)


def test_check_takeover_with_http_checker() -> None:
    """Test check_takeover calling http_checker."""
    mock_client = MagicMock(spec=DNSQueryClient)
    mock_client.get_cname.return_value = "myapp.herokuapp.com"
    mock_client.get_ns.return_value = ["ns-1.awsdns-01.com"]
    mock_client.target_resolves.return_value = True

    auditor = DomainAuditor(resolver=mock_client)

    def mock_http(url: str) -> str:
        return "404 No such app"

    report = auditor.check_takeover(["app.example.com"], http_checker=mock_http)
    assert any(f.id == "LH-TKO-001" and f.severity == Severity.CRITICAL for f in report.findings)
