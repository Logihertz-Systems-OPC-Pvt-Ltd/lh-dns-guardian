"""Sender Policy Framework (SPF) validation rules and lookup chain counter."""

from __future__ import annotations

import logging
import re
from typing import Callable, List, Optional, Set

from lh_dns_guardian.models import Finding, FindingCategory, Severity
from lh_dns_guardian.rules.base import RuleDefinition

logger = logging.getLogger(__name__)

RULE_SPF_MISSING = RuleDefinition(
    id="LH-SPF-001",
    title="Missing SPF Record",
    category=FindingCategory.SPF,
    severity=Severity.HIGH,
    description=(
        "No SPF (Sender Policy Framework) record was found. Domain is vulnerable to email spoofing."
    ),
    recommendation=(
        "Publish a valid SPF record (e.g., 'v=spf1 include:_spf.example.com -all')."
    ),
)

RULE_SPF_MULTIPLE = RuleDefinition(
    id="LH-SPF-002",
    title="Multiple SPF Records Published",
    category=FindingCategory.SPF,
    severity=Severity.HIGH,
    description=(
        "Multiple SPF records were detected for the domain. RFC 7208 section 3.2 mandates "
        "exactly one record per domain; multiple records cause mail servers to return PermError."
    ),
    recommendation=(
        "Consolidate all authorized sending hosts and include mechanisms into a single SPF record."
    ),
)

RULE_SPF_PLUS_ALL = RuleDefinition(
    id="LH-SPF-003",
    title="Overly Permissive SPF Record (+all)",
    category=FindingCategory.SPF,
    severity=Severity.CRITICAL,
    description=(
        "The SPF record ends with '+all'. This authorizes any host on the Internet to send "
        "authenticated email appearing from your domain."
    ),
    recommendation="Change '+all' to strict fail '-all' or soft fail '~all'.",
)

RULE_SPF_QUESTION_ALL = RuleDefinition(
    id="LH-SPF-004",
    title="Permissive Neutral SPF Policy (?all)",
    category=FindingCategory.SPF,
    severity=Severity.MEDIUM,
    description=(
        "The SPF record specifies '?all' (Neutral). Receiving mail transfer agents treat "
        "spoofed emails as neutral rather than rejecting or quarantining them."
    ),
    recommendation="Transition from '?all' to '-all' to enforce strict sender authentication.",
)

RULE_SPF_EXCESSIVE_LOOKUPS = RuleDefinition(
    id="LH-SPF-005",
    title="Excessive SPF DNS Lookups (>10)",
    category=FindingCategory.SPF,
    severity=Severity.HIGH,
    description=(
        "The SPF record requires more than 10 DNS lookups to evaluate. RFC 7208 Section 4.6.4 "
        "limits DNS lookup mechanisms ('include', 'a', 'mx', 'ptr', 'exists', 'redirect') to 10. "
        "Exceeding this threshold causes recipient mail servers to terminate with PermError."
    ),
    recommendation=(
        "Flatten SPF records by consolidating IP ranges or removing unnecessary includes to keep "
        "total DNS lookups at or below 10."
    ),
)

RULE_SPF_DEPRECATED_PTR = RuleDefinition(
    id="LH-SPF-006",
    title="Deprecated 'ptr' Mechanism in SPF",
    category=FindingCategory.SPF,
    severity=Severity.MEDIUM,
    description=(
        "The SPF record utilizes the deprecated 'ptr' mechanism. RFC 7208 Section 5.5 "
        "discourages 'ptr' due to reliability and performance overhead on reverse DNS resolution."
    ),
    recommendation="Replace 'ptr' mechanisms with explicit 'ip4', 'ip6', or authorized 'include'.",
)

RULE_SPF_STRICT_PASS = RuleDefinition(
    id="LH-SPF-007",
    title="Strict SPF Policy Configured (-all)",
    category=FindingCategory.SPF,
    severity=Severity.INFO,
    description="The SPF record enforces a strict Fail policy (-all).",
    recommendation="Maintain sending IPs and include lists up to date as infrastructure evolves.",
)

RULE_SPF_SOFTFAIL = RuleDefinition(
    id="LH-SPF-008",
    title="SPF SoftFail Policy (~all)",
    category=FindingCategory.SPF,
    severity=Severity.LOW,
    description=(
        "The SPF record uses SoftFail (~all). Spoofed emails are marked rather than rejected."
    ),
    recommendation="When SPF alignment is verified across all senders, upgrade '~all' to '-all'.",
)


def extract_spf_records(txt_records: List[str]) -> List[str]:
    """Filter and normalize SPF records from a list of TXT records."""
    records = []
    for txt in txt_records:
        cleaned = txt.strip()
        if cleaned.lower().startswith("v=spf1"):
            records.append(cleaned)
    return records


def count_spf_lookups(
    spf_record: str,
    resolve_fn: Optional[Callable[[str], List[str]]] = None,
    visited: Optional[Set[str]] = None,
) -> int:
    """Calculate the total number of DNS-querying mechanisms per RFC 7208.

    Mechanisms counting toward the 10-lookup limit:
    - include:
    - a, a:
    - mx, mx:
    - ptr, ptr:
    - exists:
    - redirect=

    Args:
        spf_record: The SPF string.
        resolve_fn: Optional callable to recursively fetch included SPF TXT records.
        visited: Set of already traversed domain strings to prevent circular loops.

    Returns:
        Total lookup count.
    """
    if visited is None:
        visited = set()

    tokens = spf_record.split()
    lookup_count = 0

    for token in tokens[1:]:  # skip 'v=spf1'
        token_lower = token.lower()
        # Strip qualifier if present (+, -, ~, ?)
        if token_lower and token_lower[0] in "+-~?":
            term = token_lower[1:]
        else:
            term = token_lower

        if term.startswith("include:"):
            lookup_count += 1
            included_domain = term.split("include:", 1)[1].strip()
            if resolve_fn and included_domain not in visited:
                visited.add(included_domain)
                try:
                    inc_txts = resolve_fn(included_domain)
                    inc_spf = extract_spf_records(inc_txts)
                    if inc_spf:
                        lookup_count += count_spf_lookups(inc_spf[0], resolve_fn, visited)
                except Exception as exc:
                    logger.debug("Failed resolving SPF include %s: %s", included_domain, exc)
        elif term.startswith("redirect="):
            lookup_count += 1
            redirect_domain = term.split("redirect=", 1)[1].strip()
            if resolve_fn and redirect_domain not in visited:
                visited.add(redirect_domain)
                try:
                    red_txts = resolve_fn(redirect_domain)
                    red_spf = extract_spf_records(red_txts)
                    if red_spf:
                        lookup_count += count_spf_lookups(red_spf[0], resolve_fn, visited)
                except Exception as exc:
                    logger.debug("Failed resolving SPF redirect %s: %s", redirect_domain, exc)
        elif (
            term == "a"
            or term.startswith("a:")
            or term.startswith("a/")
            or term == "mx"
            or term.startswith("mx:")
            or term.startswith("mx/")
            or term == "ptr"
            or term.startswith("ptr:")
            or term.startswith("exists:")
        ):
            lookup_count += 1

    return lookup_count


def audit_spf(
    domain: str,
    txt_records: List[str],
    resolve_fn: Optional[Callable[[str], List[str]]] = None,
) -> List[Finding]:
    """Audit SPF records for security misconfigurations and RFC compliance.

    Args:
        domain: Domain name being audited.
        txt_records: List of raw TXT record strings for the domain.
        resolve_fn: Optional callable to resolve TXT records for recursive includes.

    Returns:
        List of Finding instances.
    """
    findings: List[Finding] = []
    spf_records = extract_spf_records(txt_records)

    if not spf_records:
        findings.append(
            RULE_SPF_MISSING.create_finding(
                target=domain,
                evidence="No TXT record starting with 'v=spf1'",
            )
        )
        return findings

    if len(spf_records) > 1:
        findings.append(
            RULE_SPF_MULTIPLE.create_finding(
                target=domain,
                description_override=(
                    f"Found {len(spf_records)} SPF records on {domain}. "
                    "Multiple records trigger PermError."
                ),
                evidence=" | ".join(spf_records),
            )
        )

    # Analyze primary record
    primary_spf = spf_records[0]
    tokens = primary_spf.split()
    mechanisms = [t.lower() for t in tokens[1:]]

    # Check for permissive mechanisms
    has_plus_all = False
    has_question_all = False
    has_minus_all = False
    has_tilde_all = False
    has_ptr = False

    for m in mechanisms:
        if m in ("+all", "all"):
            has_plus_all = True
        elif m == "?all":
            has_question_all = True
        elif m == "-all":
            has_minus_all = True
        elif m == "~all":
            has_tilde_all = True

        if m == "ptr" or m.startswith("ptr:") or re.match(r"^[\+\-\~\?]ptr(:.*)?$", m):
            has_ptr = True

    if not (has_plus_all or has_question_all or has_minus_all or has_tilde_all):
        for m in mechanisms:
            if m.startswith("redirect="):
                redirect_domain = m.split("redirect=", 1)[1].strip()
                if resolve_fn:
                    try:
                        red_txts = resolve_fn(redirect_domain)
                        red_spf = extract_spf_records(red_txts)
                        if red_spf:
                            for rm in [t.lower() for t in red_spf[0].split()[1:]]:
                                if rm in ("+all", "all"):
                                    has_plus_all = True
                                elif rm == "?all":
                                    has_question_all = True
                                elif rm == "-all":
                                    has_minus_all = True
                                elif rm == "~all":
                                    has_tilde_all = True
                    except Exception as exc:
                        logger.debug("Failed following redirect %s: %s", redirect_domain, exc)
                break

    if has_plus_all:
        findings.append(
            RULE_SPF_PLUS_ALL.create_finding(
                target=domain,
                evidence=primary_spf,
            )
        )
    elif has_question_all:
        findings.append(
            RULE_SPF_QUESTION_ALL.create_finding(
                target=domain,
                evidence=primary_spf,
            )
        )
    elif has_minus_all:
        findings.append(
            RULE_SPF_STRICT_PASS.create_finding(
                target=domain,
                evidence=primary_spf,
            )
        )
    elif has_tilde_all:
        findings.append(
            RULE_SPF_SOFTFAIL.create_finding(
                target=domain,
                evidence=primary_spf,
            )
        )

    if has_ptr:
        findings.append(
            RULE_SPF_DEPRECATED_PTR.create_finding(
                target=domain,
                evidence=primary_spf,
            )
        )

    # Check lookup count
    total_lookups = count_spf_lookups(primary_spf, resolve_fn=resolve_fn)
    if total_lookups > 10:
        findings.append(
            RULE_SPF_EXCESSIVE_LOOKUPS.create_finding(
                target=domain,
                description_override=(
                    f"SPF record for {domain} requires {total_lookups} DNS lookups "
                    "(RFC 7208 limit: 10)."
                ),
                evidence=f"Computed lookups: {total_lookups} > 10 in: {primary_spf}",
            )
        )

    return findings
