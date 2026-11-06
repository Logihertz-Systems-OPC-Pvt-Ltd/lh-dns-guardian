# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.rules.takeover
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Subdomain takeover detection rules for CNAME and NS delegations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from lh_dns_guardian.models import Finding, FindingCategory, Severity
from lh_dns_guardian.rules.base import RuleDefinition

RULE_TAKEOVER_CNAME_DANGLING = RuleDefinition(
    id="LH-TKO-001",
    title="Dangling CNAME Subdomain Takeover Vulnerability",
    category=FindingCategory.TAKEOVER,
    severity=Severity.CRITICAL,
    description=(
        "Subdomain CNAME record points to an unclaimed or de-provisioned cloud service resource. "
        "An adversary can register the matching asset and seize full control of the subdomain."
    ),
    recommendation=(
        "Immediately remove the orphaned CNAME record from DNS or re-claim the corresponding "
        "cloud resource in your provider console."
    ),
)

RULE_TAKEOVER_NS_DANGLING = RuleDefinition(
    id="LH-TKO-002",
    title="Dangling NS Delegation Subdomain Takeover Risk",
    category=FindingCategory.TAKEOVER,
    severity=Severity.HIGH,
    description=(
        "Subdomain delegates DNS authority via NS records to a cloud DNS provider where "
        "the zone is inactive, refused, or unassigned."
    ),
    recommendation=(
        "Delete the orphaned NS delegation records or re-create the hosted zone at the provider."
    ),
)

RULE_TAKEOVER_SAFE = RuleDefinition(
    id="LH-TKO-003",
    title="Subdomain Target Active and Verified",
    category=FindingCategory.TAKEOVER,
    severity=Severity.INFO,
    description="Subdomain CNAME resolves to an active and operational cloud resource.",
    recommendation=(
        "Maintain periodic inventory audits to ensure retired assets have their DNS records purged."
    ),
)


@dataclass
class CloudProvider:
    """Represents a cloud hosting provider signature for subdomain takeover."""

    name: str
    cname_patterns: List[str]
    error_fingerprints: List[str]


CLOUD_PROVIDERS: List[CloudProvider] = [
    CloudProvider(
        name="GitHub Pages",
        cname_patterns=[
            r"\.github\.io\.?$",
            r"\.github\.map\.fastly\.net\.?$",
        ],
        error_fingerprints=[
            "There isn't a GitHub Pages site here",
            "404 There isn't a GitHub Pages site here.",
        ],
    ),
    CloudProvider(
        name="AWS S3",
        cname_patterns=[
            r"\.s3(-website)?[\.\-][a-z0-9\-]+\.amazonaws\.com\.?$",
            r"\.s3\.amazonaws\.com\.?$",
            r"\.s3-website-[a-z0-9\-]+\.amazonaws\.com\.?$",
        ],
        error_fingerprints=[
            "The specified bucket does not exist",
            "NoSuchBucket",
        ],
    ),
    CloudProvider(
        name="Microsoft Azure",
        cname_patterns=[
            r"\.azurewebsites\.net\.?$",
            r"\.cloudapp\.net\.?$",
            r"\.trafficmanager\.net\.?$",
            r"\.blob\.core\.windows\.net\.?$",
            r"\.azurestaticapps\.net\.?$",
        ],
        error_fingerprints=[
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ],
    ),
    CloudProvider(
        name="Vercel",
        cname_patterns=[
            r"cname\.vercel-dns\.com\.?$",
            r"\.vercel\.app\.?$",
        ],
        error_fingerprints=[
            "The deployment could not be found",
            "DEPLOYMENT_NOT_FOUND",
            "404: NOT_FOUND",
        ],
    ),
    CloudProvider(
        name="Heroku",
        cname_patterns=[
            r"\.herokuapp\.com\.?$",
            r"\.herokudns\.com\.?$",
        ],
        error_fingerprints=[
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
    ),
]

CLOUD_NS_PATTERNS = [
    (r"\.awsdns-[0-9]+\.(com|net|org|co\.uk)\.?$", "AWS Route53"),
    (r"\.azure-dns\.(com|net|org|info)\.?$", "Azure DNS"),
    (r"\.digitalocean\.com\.?$", "DigitalOcean"),
]


def match_cloud_provider(cname_target: str) -> Optional[CloudProvider]:
    """Check if a CNAME target matches any known cloud service provider patterns."""
    clean_target = cname_target.rstrip(".").lower()
    for provider in CLOUD_PROVIDERS:
        for pattern in provider.cname_patterns:
            if re.search(pattern, clean_target, re.IGNORECASE):
                return provider
    return None


def audit_cname_takeover(
    subdomain: str,
    cname_target: str,
    target_resolves: bool,
    http_body: Optional[str] = None,
) -> Optional[Finding]:
    """Audit a subdomain CNAME for dangling takeover risk.

    Args:
        subdomain: Subdomain name (e.g., 'docs.example.com').
        cname_target: Canonical name target (e.g., 'example.github.io').
        target_resolves: Boolean indicating whether target resolves via DNS.
        http_body: Optional raw HTTP response body from querying the subdomain.

    Returns:
        Finding if vulnerable or notable, or None.
    """
    provider = match_cloud_provider(cname_target)
    if not provider:
        return None

    # Case 1: CNAME points to cloud provider, but target does not resolve (NXDOMAIN)
    if not target_resolves:
        return RULE_TAKEOVER_CNAME_DANGLING.create_finding(
            target=subdomain,
            description_override=(
                f"Dangling CNAME on {subdomain} points to unresolvable {provider.name} "
                f"target '{cname_target}'. This resource can likely be registered by an attacker."
            ),
            evidence=f"CNAME: {cname_target} -> NXDOMAIN / Unresolved ({provider.name})",
        )

    # Case 2: Target resolves, but HTTP response matches the unclaimed asset fingerprint
    if http_body:
        for fingerprint in provider.error_fingerprints:
            if fingerprint.lower() in http_body.lower():
                return RULE_TAKEOVER_CNAME_DANGLING.create_finding(
                    target=subdomain,
                    description_override=(
                        f"Subdomain {subdomain} points to an unclaimed {provider.name} resource. "
                        f"Matched takeover fingerprint: '{fingerprint}'."
                    ),
                    evidence=(
                        f"CNAME: {cname_target} | Provider: {provider.name} | "
                        f"Match: '{fingerprint}'"
                    ),
                )

    # Case 3: Target resolves and no takeover fingerprint matched
    return RULE_TAKEOVER_SAFE.create_finding(
        target=subdomain,
        description_override=(
            f"Subdomain {subdomain} points to active {provider.name} asset '{cname_target}'."
        ),
        evidence=f"CNAME: {cname_target} ({provider.name})",
    )


def audit_ns_takeover(
    subdomain: str,
    ns_records: List[str],
    is_dangling: bool = False,
    error_msg: Optional[str] = None,
) -> Optional[Finding]:
    """Audit subdomain NS records for dangling delegation.

    Args:
        subdomain: Subdomain name.
        ns_records: List of NS nameserver hostnames.
        is_dangling: Whether the delegation was determined to be refused or orphaned.
        error_msg: Detail of the nameserver error (e.g. REFUSED, SERVFAIL).

    Returns:
        Finding if dangling delegation detected, else None.
    """
    for ns in ns_records:
        ns_clean = ns.rstrip(".").lower()
        for pattern, provider_name in CLOUD_NS_PATTERNS:
            if re.search(pattern, ns_clean, re.IGNORECASE):
                if is_dangling:
                    status_desc = error_msg or "Refused/Unclaimed"
                    evidence_str = f"NS: {ns} ({provider_name}) - {status_desc}"
                    return RULE_TAKEOVER_NS_DANGLING.create_finding(
                        target=subdomain,
                        description_override=(
                            f"Dangling NS delegation detected on {subdomain} to {provider_name} "
                            f"nameserver '{ns}'. The hosted zone appears unassigned or refused."
                        ),
                        evidence=evidence_str,
                    )
    return None
