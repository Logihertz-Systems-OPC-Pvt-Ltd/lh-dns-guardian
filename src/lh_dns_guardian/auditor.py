# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.auditor
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""High-level audit orchestration for domains, zone files, and takeover detection."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, List, Optional, Union

from lh_dns_guardian.models import AuditReport
from lh_dns_guardian.resolver import DNSQueryClient
from lh_dns_guardian.rules.axfr import audit_axfr
from lh_dns_guardian.rules.caa import audit_caa
from lh_dns_guardian.rules.dmarc import audit_dmarc
from lh_dns_guardian.rules.dnssec import audit_dnssec
from lh_dns_guardian.rules.spf import audit_spf
from lh_dns_guardian.rules.takeover import audit_cname_takeover, audit_ns_takeover
from lh_dns_guardian.zone_parser import ParsedZone, parse_zone_file

logger = logging.getLogger(__name__)


class DomainAuditor:
    """Orchestrates comprehensive DNS security posture assessments."""

    def __init__(self, resolver: Optional[DNSQueryClient] = None) -> None:
        """Initialize auditor with optional resolver client."""
        self.resolver = resolver or DNSQueryClient()

    def audit_domain(
        self,
        domain: str,
        nameserver: Optional[str] = None,
    ) -> AuditReport:
        """Audit live DNS security posture for a target domain.

        Args:
            domain: The domain name to audit (e.g. 'example.com').
            nameserver: Optional custom nameserver IP.

        Returns:
            Populated AuditReport instance.
        """
        clean_domain = domain.rstrip(".").lower()
        client = DNSQueryClient(nameserver=nameserver) if nameserver else self.resolver

        report = AuditReport(
            target=clean_domain,
            target_type="domain",
            metadata={"nameserver": nameserver or "default system resolver"},
        )

        # 1. Authoritative Nameservers and AXFR Audit
        ns_records = client.get_ns(clean_domain)
        if ns_records:
            axfr_findings = audit_axfr(
                domain=clean_domain,
                nameservers=ns_records,
                check_fn=client.check_axfr,
            )
            for f in axfr_findings:
                report.add_finding(f)

        # 2. DNSSEC Audit
        dnskey_records = client.get_dnskey(clean_domain)
        ds_records = client.get_ds(clean_domain)
        rrsig_records = client.get_rrsig(clean_domain)
        dnssec_findings = audit_dnssec(
            domain=clean_domain,
            dnskey_records=dnskey_records,
            ds_records=ds_records,
            rrsig_records=rrsig_records,
        )
        for f in dnssec_findings:
            report.add_finding(f)

        # 3. CAA Audit
        caa_records = client.get_caa(clean_domain)
        caa_findings = audit_caa(domain=clean_domain, caa_records=caa_records)
        for f in caa_findings:
            report.add_finding(f)

        # 4. SPF Policy Audit
        txt_records = client.get_txt(clean_domain)
        spf_findings = audit_spf(
            domain=clean_domain,
            txt_records=txt_records,
            resolve_fn=client.get_txt,
        )
        for f in spf_findings:
            report.add_finding(f)

        # 5. DMARC Policy Audit
        dmarc_name = f"_dmarc.{clean_domain}"
        dmarc_txt_records = client.get_txt(dmarc_name)
        dmarc_findings = audit_dmarc(domain=clean_domain, txt_records=dmarc_txt_records)
        for f in dmarc_findings:
            report.add_finding(f)

        # 6. Check root/subdomain CNAME takeover
        cname_target = client.get_cname(clean_domain)
        if cname_target:
            target_resolves = client.target_resolves(cname_target)
            takeover_finding = audit_cname_takeover(
                subdomain=clean_domain,
                cname_target=cname_target,
                target_resolves=target_resolves,
            )
            if takeover_finding:
                report.add_finding(takeover_finding)

        return report

    def audit_zone(
        self,
        zone_file: Union[str, Path],
        origin: Optional[str] = None,
        check_live_takeover: bool = True,
    ) -> AuditReport:
        """Audit a BIND master zone file offline and cross-check dangling records.

        Args:
            zone_file: File path to the BIND zone file.
            origin: Optional explicit origin domain.
            check_live_takeover: Whether to test CNAME targets for DNS resolution.

        Returns:
            Populated AuditReport instance.
        """
        parsed_zone: ParsedZone = parse_zone_file(zone_file, origin=origin)
        origin_domain = parsed_zone.origin

        report = AuditReport(
            target=origin_domain,
            target_type="zone",
            metadata={"file": str(zone_file), "origin": origin_domain},
        )

        # 1. DNSSEC in zone
        dnskey_records = parsed_zone.get_dnskey()
        ds_records = parsed_zone.get_ds()
        rrsig_records = parsed_zone.get_rrsig()
        dnssec_findings = audit_dnssec(
            domain=origin_domain,
            dnskey_records=dnskey_records,
            ds_records=ds_records,
            rrsig_records=rrsig_records,
        )
        for f in dnssec_findings:
            report.add_finding(f)

        # 2. CAA in zone
        caa_records = parsed_zone.get_caa()
        caa_findings = audit_caa(domain=origin_domain, caa_records=caa_records)
        for f in caa_findings:
            report.add_finding(f)

        # 3. SPF in zone
        txt_records = parsed_zone.get_txt()
        spf_findings = audit_spf(
            domain=origin_domain,
            txt_records=txt_records,
            resolve_fn=parsed_zone.get_txt,
        )
        for f in spf_findings:
            report.add_finding(f)

        # 4. DMARC in zone
        dmarc_name = f"_dmarc.{origin_domain}"
        dmarc_txt = parsed_zone.get_txt(dmarc_name)
        dmarc_findings = audit_dmarc(domain=origin_domain, txt_records=dmarc_txt)
        for f in dmarc_findings:
            report.add_finding(f)

        # 5. CNAME Takeover analysis for all CNAMEs declared in zone
        cnames = parsed_zone.get_cnames()
        for sub_name, target in cnames.items():
            target_resolves = True
            if check_live_takeover:
                target_resolves = self.resolver.target_resolves(target)

            tko_finding = audit_cname_takeover(
                subdomain=sub_name,
                cname_target=target,
                target_resolves=target_resolves,
            )
            if tko_finding:
                report.add_finding(tko_finding)

        # 6. NS delegations declared in zone
        for name in parsed_zone.records:
            if name != origin_domain:
                ns_delegated = parsed_zone.get_ns(name)
                if ns_delegated:
                    # Check if delegated NS is dangling
                    ns_finding = audit_ns_takeover(
                        subdomain=name,
                        ns_records=ns_delegated,
                        is_dangling=False,
                    )
                    if ns_finding:
                        report.add_finding(ns_finding)

        return report

    def check_takeover(
        self,
        subdomains: List[str],
        nameserver: Optional[str] = None,
        http_checker: Optional[Callable[[str], Optional[str]]] = None,
    ) -> AuditReport:
        """Scan a list of subdomains for dangling CNAME and NS takeover vectors.

        Args:
            subdomains: List of subdomain strings to check.
            nameserver: Optional custom nameserver IP.
            http_checker: Optional callable accepting URL and returning response body string.

        Returns:
            Populated AuditReport instance.
        """
        client = DNSQueryClient(nameserver=nameserver) if nameserver else self.resolver
        report = AuditReport(
            target=f"{len(subdomains)} subdomains list",
            target_type="subdomains",
            metadata={"subdomains_scanned": len(subdomains)},
        )

        for sub in subdomains:
            clean_sub = sub.strip().rstrip(".").lower()
            if not clean_sub or clean_sub.startswith("#"):
                continue

            # Check CNAME
            cname = client.get_cname(clean_sub)
            if cname:
                target_resolves = client.target_resolves(cname)
                http_body: Optional[str] = None
                if target_resolves and http_checker:
                    try:
                        http_body = http_checker(f"http://{clean_sub}")
                    except Exception as exc:
                        logger.debug("HTTP checker failed for %s: %s", clean_sub, exc)

                finding = audit_cname_takeover(
                    subdomain=clean_sub,
                    cname_target=cname,
                    target_resolves=target_resolves,
                    http_body=http_body,
                )
                if finding:
                    report.add_finding(finding)

            # Check NS records for dangling delegation
            ns_records = client.get_ns(clean_sub)
            if ns_records:
                finding_ns = audit_ns_takeover(
                    subdomain=clean_sub,
                    ns_records=ns_records,
                    is_dangling=False,
                )
                if finding_ns:
                    report.add_finding(finding_ns)

        return report
