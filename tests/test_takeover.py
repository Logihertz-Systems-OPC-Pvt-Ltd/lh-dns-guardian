"""Unit tests for dangling subdomain takeover detection across cloud providers."""

from __future__ import annotations

from lh_dns_guardian.models import Severity
from lh_dns_guardian.rules.takeover import audit_cname_takeover, audit_ns_takeover


def test_takeover_github_pages_unresolvable() -> None:
    """Test GitHub Pages CNAME with unresolvable target."""
    finding = audit_cname_takeover(
        subdomain="docs.example.com",
        cname_target="org.github.io",
        target_resolves=False,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-001"
    assert finding.severity == Severity.CRITICAL
    assert "GitHub Pages" in finding.description


def test_takeover_github_pages_fingerprint_match() -> None:
    """Test GitHub Pages CNAME with HTTP body matching error fingerprint."""
    body = "<html><body>404 There isn't a GitHub Pages site here.</body></html>"
    finding = audit_cname_takeover(
        subdomain="docs.example.com",
        cname_target="org.github.io",
        target_resolves=True,
        http_body=body,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-001"
    assert finding.severity == Severity.CRITICAL
    assert "GitHub Pages" in finding.description


def test_takeover_aws_s3_fingerprint_match() -> None:
    """Test AWS S3 bucket missing error fingerprint."""
    body = (
        "<Error><Code>NoSuchBucket</Code>"
        "<Message>The specified bucket does not exist</Message></Error>"
    )
    finding = audit_cname_takeover(
        subdomain="assets.example.com",
        cname_target="mybucket.s3.amazonaws.com",
        target_resolves=True,
        http_body=body,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-001"
    assert finding.severity == Severity.CRITICAL
    assert "AWS S3" in finding.description


def test_takeover_azure_unresolvable() -> None:
    """Test Azure App Service unresolvable CNAME."""
    finding = audit_cname_takeover(
        subdomain="portal.example.com",
        cname_target="portalapp.azurewebsites.net",
        target_resolves=False,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-001"
    assert "Microsoft Azure" in finding.description


def test_takeover_vercel_fingerprint() -> None:
    """Test Vercel 404 deployment error fingerprint."""
    body = "404: NOT_FOUND The deployment could not be found"
    finding = audit_cname_takeover(
        subdomain="app.example.com",
        cname_target="cname.vercel-dns.com",
        target_resolves=True,
        http_body=body,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-001"
    assert "Vercel" in finding.description


def test_takeover_heroku_fingerprint() -> None:
    """Test Heroku No such app error fingerprint."""
    body = "<html><body>No such app</body></html>"
    finding = audit_cname_takeover(
        subdomain="api.example.com",
        cname_target="my-app.herokuapp.com",
        target_resolves=True,
        http_body=body,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-001"
    assert "Heroku" in finding.description


def test_takeover_active_safe() -> None:
    """Test active cloud asset returning valid content without error fingerprint."""
    body = "<html><body>Welcome to our live site</body></html>"
    finding = audit_cname_takeover(
        subdomain="docs.example.com",
        cname_target="org.github.io",
        target_resolves=True,
        http_body=body,
    )
    assert finding is not None
    assert finding.id == "LH-TKO-003"
    assert finding.severity == Severity.INFO


def test_takeover_unrelated_target() -> None:
    """Test CNAME pointing to unrelated domain."""
    finding = audit_cname_takeover(
        subdomain="mail.example.com",
        cname_target="mail.internal.net",
        target_resolves=True,
    )
    assert finding is None


def test_dangling_ns_delegation() -> None:
    """Test dangling NS delegation detection."""
    finding = audit_ns_takeover(
        subdomain="sub.example.com",
        ns_records=["ns-100.awsdns-01.com"],
        is_dangling=True,
        error_msg="REFUSED",
    )
    assert finding is not None
    assert finding.id == "LH-TKO-002"
    assert finding.severity == Severity.HIGH
    assert "AWS Route53" in finding.description
