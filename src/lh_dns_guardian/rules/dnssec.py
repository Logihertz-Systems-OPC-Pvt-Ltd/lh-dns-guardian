# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.rules.dnssec
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""DNSSEC record validation and policy evaluation rules."""

from __future__ import annotations

from typing import List

from lh_dns_guardian.models import Finding, FindingCategory, Severity
from lh_dns_guardian.rules.base import RuleDefinition

RULE_DNSSEC_MISSING = RuleDefinition(
    id="LH-SEC-001",
    title="DNSSEC Not Enabled",
    category=FindingCategory.DNSSEC,
    severity=Severity.HIGH,
    description="The domain does not have DNSSEC enabled. Missing DNSKEY, DS, and RRSIG records.",
    recommendation=(
        "Enable DNSSEC by generating KSK/ZSK key pairs, signing the zone with RRSIG, "
        "and publishing the DS record at the parent registrar."
    ),
)

RULE_DNSSEC_INCOMPLETE = RuleDefinition(
    id="LH-SEC-002",
    title="DNSSEC Incomplete Configuration",
    category=FindingCategory.DNSSEC,
    severity=Severity.MEDIUM,
    description=(
        "DNSSEC configuration is incomplete. DNSKEY records exist but lack corresponding "
        "parent DS delegation records or RRSIG zone signatures."
    ),
    recommendation=(
        "Verify that your zone is fully signed with RRSIG records and that the corresponding "
        "DS record is uploaded and activated at your domain registrar."
    ),
)

RULE_DNSSEC_ACTIVE = RuleDefinition(
    id="LH-SEC-003",
    title="DNSSEC Configured and Active",
    category=FindingCategory.DNSSEC,
    severity=Severity.INFO,
    description="DNSSEC is properly configured with published DNSKEY, DS, and RRSIG records.",
    recommendation="Maintain automated key rollover and monitor DS record synchronization.",
)


def audit_dnssec(
    domain: str,
    dnskey_records: List[str],
    ds_records: List[str],
    rrsig_records: List[str],
) -> List[Finding]:
    """Audit DNSSEC posture for a domain or zone.

    Args:
        domain: Domain or zone name.
        dnskey_records: List of DNSKEY record strings.
        ds_records: List of DS record strings.
        rrsig_records: List of RRSIG record strings.

    Returns:
        List of Finding instances.
    """
    findings: List[Finding] = []
    has_dnskey = len(dnskey_records) > 0
    has_ds = len(ds_records) > 0
    has_rrsig = len(rrsig_records) > 0

    if not has_dnskey and not has_ds and not has_rrsig:
        findings.append(
            RULE_DNSSEC_MISSING.create_finding(
                target=domain,
                evidence="DNSKEY: None, DS: None, RRSIG: None",
            )
        )
    elif has_dnskey and (not has_ds or not has_rrsig):
        missing_parts: List[str] = []
        if not has_ds:
            missing_parts.append("parent DS delegation")
        if not has_rrsig:
            missing_parts.append("zone RRSIG signatures")

        evidence_str = (
            f"DNSKEY count: {len(dnskey_records)}, "
            f"DS count: {len(ds_records)}, "
            f"RRSIG count: {len(rrsig_records)}"
        )
        findings.append(
            RULE_DNSSEC_INCOMPLETE.create_finding(
                target=domain,
                description_override=(
                    f"DNSSEC keys are present on {domain}, but missing: {', '.join(missing_parts)}."
                ),
                evidence=evidence_str,
            )
        )
    else:
        evidence_str = (
            f"DNSKEY: {len(dnskey_records)}, DS: {len(ds_records)}, RRSIG: {len(rrsig_records)}"
        )
        findings.append(
            RULE_DNSSEC_ACTIVE.create_finding(
                target=domain,
                evidence=evidence_str,
            )
        )

    return findings
