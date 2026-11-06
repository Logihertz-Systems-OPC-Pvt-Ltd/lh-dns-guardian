# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.rules.caa
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Certificate Authority Authorization (CAA) policy evaluation rules."""

from __future__ import annotations

from typing import List

from lh_dns_guardian.models import Finding, FindingCategory, Severity
from lh_dns_guardian.rules.base import RuleDefinition

RULE_CAA_MISSING = RuleDefinition(
    id="LH-CAA-001",
    title="Missing CAA Records",
    category=FindingCategory.CAA,
    severity=Severity.MEDIUM,
    description=(
        "No Certificate Authority Authorization (CAA) record is published. "
        "Any publicly trusted Certificate Authority can issue TLS certificates for this domain."
    ),
    recommendation=(
        "Publish CAA records specifying authorized Certificate Authorities (e.g. Let's Encrypt) "
        "and configure 'iodef' incident reporting to monitor unauthorized issuance attempts."
    ),
)

RULE_CAA_CONFIGURED = RuleDefinition(
    id="LH-CAA-002",
    title="CAA Record Configured",
    category=FindingCategory.CAA,
    severity=Severity.INFO,
    description=(
        "CAA records are active and restrict unauthorized Certificate Authorities from "
        "issuing certificates."
    ),
    recommendation=(
        "Periodically review authorized CA entries and maintain valid iodef incident notification "
        "endpoints."
    ),
)


def audit_caa(domain: str, caa_records: List[str]) -> List[Finding]:
    """Audit CAA policy records for a domain.

    Args:
        domain: Domain name being audited.
        caa_records: List of CAA record strings (e.g., '0 issue "letsencrypt.org"').

    Returns:
        List of Finding instances.
    """
    findings: List[Finding] = []

    if not caa_records:
        findings.append(
            RULE_CAA_MISSING.create_finding(
                target=domain,
                evidence="CAA: None",
            )
        )
    else:
        evidence = "; ".join(caa_records)
        findings.append(
            RULE_CAA_CONFIGURED.create_finding(
                target=domain,
                evidence=evidence,
            )
        )

    return findings
