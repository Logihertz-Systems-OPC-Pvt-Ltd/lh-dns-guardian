# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.rules.axfr
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Zone transfer (AXFR) misconfiguration evaluation rules."""

from __future__ import annotations

from typing import Callable, List

from lh_dns_guardian.models import Finding, FindingCategory, Severity
from lh_dns_guardian.rules.base import RuleDefinition

RULE_AXFR_OPEN = RuleDefinition(
    id="LH-AXFR-001",
    title="Open AXFR Zone Transfer Exposed",
    category=FindingCategory.ZONE_TRANSFER,
    severity=Severity.CRITICAL,
    description=(
        "An authoritative nameserver permits unauthenticated AXFR full zone transfers. "
        "Adversaries can download the entire DNS database, discovering hidden subdomains, "
        "internal IP architectures, and staging infrastructure."
    ),
    recommendation=(
        "Restrict AXFR queries on the authoritative nameserver to trusted secondary nameservers "
        "only (e.g., using 'allow-transfer { <secondary_ips>; };' in BIND or TSIG signatures)."
    ),
)

RULE_AXFR_PROTECTED = RuleDefinition(
    id="LH-AXFR-002",
    title="Zone Transfers Protected",
    category=FindingCategory.ZONE_TRANSFER,
    severity=Severity.INFO,
    description="All authoritative nameservers properly deny unauthenticated AXFR zone transfers.",
    recommendation=(
        "Maintain strict ACLs and TSIG keys for legitimate secondary nameserver replication."
    ),
)


def audit_axfr(
    domain: str,
    nameservers: List[str],
    check_fn: Callable[[str, str], bool],
) -> List[Finding]:
    """Test nameservers for open AXFR zone transfer misconfigurations.

    Args:
        domain: Domain or zone name to test.
        nameservers: List of authoritative nameserver hostnames or IPs.
        check_fn: Callable accepting (zone, nameserver) returning True if AXFR succeeded.

    Returns:
        List of Finding instances.
    """
    findings: List[Finding] = []
    vulnerable_servers: List[str] = []

    for ns in nameservers:
        is_open = check_fn(domain, ns)
        if is_open:
            vulnerable_servers.append(ns)
            findings.append(
                RULE_AXFR_OPEN.create_finding(
                    target=domain,
                    description_override=(
                        f"Authoritative nameserver '{ns}' allows unauthenticated "
                        f"AXFR zone transfers for {domain}."
                    ),
                    evidence=f"Vulnerable nameserver: {ns}",
                )
            )

    if not vulnerable_servers and nameservers:
        findings.append(
            RULE_AXFR_PROTECTED.create_finding(
                target=domain,
                evidence=f"Protected nameservers checked: {', '.join(nameservers)}",
            )
        )

    return findings
