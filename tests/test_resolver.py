"""Unit tests for DNSQueryClient with mocked DNS responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from lh_dns_guardian.resolver import DNSQueryClient


def test_resolver_custom_nameserver() -> None:
    """Test initializing resolver with custom nameserver and timeout."""
    client = DNSQueryClient(nameserver="1.1.1.1", port=5353, timeout=2.0, lifetime=4.0)
    assert client.nameserver == "1.1.1.1"
    assert client.resolver.nameservers == ["1.1.1.1"]
    assert client.resolver.port == 5353
    assert client.resolver.timeout == 2.0
    assert client.resolver.lifetime == 4.0


def test_query_txt_records() -> None:
    """Test querying TXT records with concatenated multi-chunk strings."""
    client = DNSQueryClient()
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"v=spf1 include:_spf.google.com ", b"~all"]

    with patch.object(client.resolver, "resolve", return_value=[mock_rdata]):
        results = client.get_txt("example.com")
        assert len(results) == 1
        assert results[0] == "v=spf1 include:_spf.google.com ~all"


def test_query_caa_records() -> None:
    """Test querying CAA records."""
    client = DNSQueryClient()
    mock_rdata = MagicMock()
    mock_rdata.flags = 0
    mock_rdata.tag = b"issue"
    mock_rdata.value = b"letsencrypt.org"

    with patch.object(client.resolver, "resolve", return_value=[mock_rdata]):
        results = client.get_caa("example.com")
        assert len(results) == 1
        assert results[0] == '0 issue "letsencrypt.org"'


def test_query_cname_and_ns_records() -> None:
    """Test querying CNAME and NS records."""
    client = DNSQueryClient()
    mock_cname = MagicMock()
    mock_cname.target = "target.example.org."

    with patch.object(client.resolver, "resolve", return_value=[mock_cname]):
        assert client.get_cname("sub.example.com") == "target.example.org"

    mock_ns = MagicMock()
    mock_ns.target = "ns1.example.org."
    with patch.object(client.resolver, "resolve", return_value=[mock_ns]):
        assert client.get_ns("example.com") == ["ns1.example.org"]


def test_query_handles_dns_exceptions() -> None:
    """Test graceful handling of NXDOMAIN and Timeout."""
    client = DNSQueryClient()

    with patch.object(client.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
        assert client.query("nonexistent.invalid", "A") == []

    with patch.object(client.resolver, "resolve", side_effect=dns.exception.Timeout):
        assert client.query("timeout.invalid", "TXT") == []


def test_target_resolves() -> None:
    """Test target_resolves method."""
    client = DNSQueryClient()

    with patch.object(client, "query", side_effect=lambda q, t: ["192.0.2.1"] if t == "A" else []):
        assert client.target_resolves("active.example.com") is True

    with patch.object(client, "query", return_value=[]):
        assert client.target_resolves("dangling.example.com") is False


def test_check_axfr_mocked() -> None:
    """Test check_axfr against vulnerable and protected nameservers."""
    client = DNSQueryClient()

    with patch.object(client.resolver, "resolve", return_value=["198.51.100.1"]):
        # Mock successful zone transfer
        mock_zone = MagicMock()
        mock_zone.nodes = {"@": MagicMock(), "www": MagicMock()}
        with (
            patch("dns.query.xfr", return_value=iter([])),
            patch("dns.zone.from_xfr", return_value=mock_zone),
        ):
            assert client.check_axfr("example.com", "ns1.example.com") is True

        # Mock failed zone transfer
        with patch("dns.query.xfr", side_effect=Exception("Transfer failed")):
            assert client.check_axfr("example.com", "ns2.example.com") is False
