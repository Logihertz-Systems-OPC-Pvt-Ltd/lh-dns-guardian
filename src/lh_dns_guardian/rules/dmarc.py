"""Domain-based Message Authentication, Reporting, and Conformance (DMARC) rules."""

from __future__ import annotations

import re
from typing import Dict, List

from lh_dns_guardian.models import Finding, FindingCategory, Severity
from lh_dns_guardian.rules.base import RuleDefinition

RULE_DMARC_MISSING = RuleDefinition(
    id="LH-DMC-001",
    title="Missing DMARC Record",
    category=FindingCategory.DMARC,
    severity=Severity.HIGH,
    description=(
        "No DMARC policy record is published at '_dmarc.<domain>'. "
        "Receivers cannot verify email authenticity."
    ),
    recommendation=(
        "Publish a DMARC policy TXT record at '_dmarc.<domain>' with "
        "'v=DMARC1; p=reject; rua=mailto:...'"
    ),
)

RULE_DMARC_POLICY_NONE = RuleDefinition(
    id="LH-DMC-002",
    title="Un-enforced DMARC Policy (p=none)",
    category=FindingCategory.DMARC,
    severity=Severity.MEDIUM,
    description=(
        "The DMARC policy is set to 'p=none' (monitoring only). Receiving mail servers do not "
        "reject or quarantine fraudulent emails claiming to be from your domain."
    ),
    recommendation=(
        "After monitoring aggregate feedback reports (rua), escalate policy from 'p=none' "
        "to 'p=quarantine' or 'p=reject'."
    ),
)

RULE_DMARC_SUBDOMAIN_NONE = RuleDefinition(
    id="LH-DMC-003",
    title="Un-enforced DMARC Subdomain Policy (sp=none)",
    category=FindingCategory.DMARC,
    severity=Severity.LOW,
    description=(
        "The primary DMARC policy enforces quarantine or reject, but the subdomain policy "
        "specifies 'sp=none'. Adversaries can spoof emails from arbitrary subdomains."
    ),
    recommendation=(
        "Align subdomain policy 'sp' with primary policy (e.g., 'sp=reject' or remove 'sp')."
    ),
)

RULE_DMARC_PCT_INCOMPLETE = RuleDefinition(
    id="LH-DMC-004",
    title="DMARC Enforcement Incomplete (pct < 100)",
    category=FindingCategory.DMARC,
    severity=Severity.LOW,
    description=(
        "The DMARC policy defines an enforcement percentage ('pct') of less than 100%. "
        "A portion of unauthenticated emails bypass policy enforcement."
    ),
    recommendation=(
        "Set 'pct=100' or omit the tag (defaults to 100) to ensure full policy coverage."
    ),
)

RULE_DMARC_RUA_MISSING = RuleDefinition(
    id="LH-DMC-005",
    title="Missing DMARC Aggregate Reporting URI (rua)",
    category=FindingCategory.DMARC,
    severity=Severity.LOW,
    description=(
        "The DMARC record lacks an aggregate reporting URI ('rua'). The domain owner receives "
        "no visibility into delivery trends, SPF/DKIM alignment failures, or phishing campaigns."
    ),
    recommendation=(
        "Add a 'rua=mailto:<reports@domain.com>' tag to receive standardized XML aggregate reports."
    ),
)

RULE_DMARC_ENFORCED = RuleDefinition(
    id="LH-DMC-006",
    title="DMARC Policy Enforced",
    category=FindingCategory.DMARC,
    severity=Severity.INFO,
    description="DMARC policy enforces active protection (quarantine or reject) against spoofing.",
    recommendation=(
        "Continuously monitor 'rua' feedback to ensure legitimate transactional senders remain "
        "aligned."
    ),
)

RULE_DMARC_MULTIPLE = RuleDefinition(
    id="LH-DMC-007",
    title="Multiple DMARC Records Found",
    category=FindingCategory.DMARC,
    severity=Severity.HIGH,
    description=(
        "Multiple DMARC records were discovered at '_dmarc.<domain>'. RFC 7489 Section 6.6.3 "
        "dictates that receivers must ignore all records if more than one is found."
    ),
    recommendation="Consolidate duplicate DMARC TXT records into a single authoritative record.",
)


def extract_dmarc_records(txt_records: List[str]) -> List[str]:
    """Extract records matching the DMARC tag prefix."""
    dmarc_list = []
    for txt in txt_records:
        cleaned = txt.strip()
        if cleaned.lower().startswith("v=dmarc1"):
            dmarc_list.append(cleaned)
    return dmarc_list


def parse_dmarc_tags(dmarc_record: str) -> Dict[str, str]:
    """Parse DMARC semi-colon delimited tags into a key-value dictionary."""
    tags: Dict[str, str] = {}
    parts = dmarc_record.split(";")
    for part in parts:
        part_clean = part.strip()
        if not part_clean:
            continue
        if "=" in part_clean:
            k, v = part_clean.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def audit_dmarc(domain: str, txt_records: List[str]) -> List[Finding]:
    """Audit DMARC records for compliance and policy enforcement.

    Args:
        domain: Domain name being audited.
        txt_records: List of TXT records queried from '_dmarc.<domain>'.

    Returns:
        List of Finding instances.
    """
    findings: List[Finding] = []
    dmarc_records = extract_dmarc_records(txt_records)

    if not dmarc_records:
        findings.append(
            RULE_DMARC_MISSING.create_finding(
                target=domain,
                evidence=f"No DMARC record at _dmarc.{domain}",
            )
        )
        return findings

    if len(dmarc_records) > 1:
        findings.append(
            RULE_DMARC_MULTIPLE.create_finding(
                target=domain,
                evidence=" | ".join(dmarc_records),
            )
        )

    # Inspect primary record
    primary_record = dmarc_records[0]
    tags = parse_dmarc_tags(primary_record)

    policy = tags.get("p", "").lower()
    sub_policy = tags.get("sp", "").lower()
    pct_val = tags.get("pct", "100")
    has_rua = "rua" in tags

    # Evaluate p policy
    if policy == "none":
        findings.append(
            RULE_DMARC_POLICY_NONE.create_finding(
                target=domain,
                evidence=primary_record,
            )
        )
    elif policy in ("quarantine", "reject"):
        findings.append(
            RULE_DMARC_ENFORCED.create_finding(
                target=domain,
                description_override=f"DMARC policy on {domain} is configured with 'p={policy}'.",
                evidence=primary_record,
            )
        )

    # Evaluate subdomain policy sp
    if policy in ("quarantine", "reject") and sub_policy == "none":
        findings.append(
            RULE_DMARC_SUBDOMAIN_NONE.create_finding(
                target=domain,
                evidence=primary_record,
            )
        )

    # Evaluate pct
    cleaned_digits = re.sub(r"[^\d]", "", pct_val)
    if cleaned_digits:
        pct_int = int(cleaned_digits)
        if pct_int < 100:
            findings.append(
                RULE_DMARC_PCT_INCOMPLETE.create_finding(
                    target=domain,
                    description_override=f"DMARC pct is configured to {pct_int}% (< 100%).",
                    evidence=primary_record,
                )
            )

    # Evaluate rua
    if not has_rua:
        findings.append(
            RULE_DMARC_RUA_MISSING.create_finding(
                target=domain,
                evidence=primary_record,
            )
        )

    return findings
