"""Unit tests for BIND master zone file parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from lh_dns_guardian.zone_parser import parse_zone_file, parse_zone_text

SAMPLE_ZONE_TEXT = """$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. (
            2026110101 ; serial
            7200       ; refresh
            3600       ; retry
            1209600    ; expire
            3600       ; minimum
        )
@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.
@   IN  A   93.184.216.34
@   IN  TXT "v=spf1 include:_spf.google.com ~all"
_dmarc  IN  TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
@   IN  CAA 0 issue "letsencrypt.org"
docs    IN  CNAME example.github.io.
blog    IN  CNAME custom.azurewebsites.net.
sub     IN  NS    ns-1.awsdns-01.org.
"""


def test_parse_zone_text() -> None:
    """Test parsing BIND zone from text string."""
    zone = parse_zone_text(SAMPLE_ZONE_TEXT, origin="example.com")
    assert zone.origin == "example.com"

    # Verify NS records
    ns_records = zone.get_ns()
    assert "ns1.example.com" in ns_records
    assert "ns2.example.com" in ns_records

    # Verify TXT / SPF records
    txt_records = zone.get_txt()
    assert any("v=spf1" in txt for txt in txt_records)

    # Verify DMARC record
    dmarc_txt = zone.get_txt("compat" and "_dmarc.example.com")
    assert any("v=DMARC1" in txt for txt in dmarc_txt)

    # Verify CAA record
    caa_records = zone.get_caa()
    assert len(caa_records) == 1
    assert "letsencrypt.org" in caa_records[0]

    # Verify CNAME records
    cnames = zone.get_cnames()
    assert cnames["docs.example.com"] == "example.github.io"
    assert cnames["blog.example.com"] == "custom.azurewebsites.net"

    # Verify delegated NS
    sub_ns = zone.get_ns("sub.example.com")
    assert "ns-1.awsdns-01.org" in sub_ns


def test_parse_zone_file(tmp_path: Path) -> None:
    """Test parsing BIND zone from disk file."""
    zone_file = tmp_path / "example.com.zone"
    zone_file.write_text(SAMPLE_ZONE_TEXT, encoding="utf-8")

    parsed = parse_zone_file(zone_file)
    assert parsed.origin == "example.com"
    assert len(parsed.get_ns()) == 2


def test_parse_zone_file_not_found() -> None:
    """Test error handling when zone file does not exist."""
    with pytest.raises(FileNotFoundError):
        parse_zone_file("/nonexistent/zone.file")
