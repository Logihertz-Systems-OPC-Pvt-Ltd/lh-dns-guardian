"""DNS resolver and query abstraction client."""

from __future__ import annotations

import logging
from typing import List, Optional

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

logger = logging.getLogger(__name__)


class DNSQueryClient:
    """Performs DNS queries with configurable nameservers and timeouts."""

    def __init__(
        self,
        nameserver: Optional[str] = None,
        port: int = 53,
        timeout: float = 4.0,
        lifetime: float = 6.0,
    ) -> None:
        """Initialize the DNS resolver client.

        Args:
            nameserver: IP address of custom nameserver (e.g., "8.8.8.8").
            port: Port for DNS queries (default 53).
            timeout: Per-query timeout in seconds.
            lifetime: Total timeout for multi-step resolution in seconds.
        """
        self.resolver = dns.resolver.Resolver(configure=True)
        self.nameserver = nameserver
        if nameserver:
            self.resolver.nameservers = [nameserver]
        self.resolver.port = port
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    def query(self, qname: str, rdtype: str) -> List[str]:
        """Query DNS records for a given domain and record type.

        Args:
            qname: Domain name to query.
            rdtype: DNS record type (e.g., 'A', 'TXT', 'CAA', 'DNSKEY').

        Returns:
            List of string representations of record values.
        """
        try:
            rdata_type = dns.rdatatype.from_text(rdtype.upper())
            answer = self.resolver.resolve(qname, rdata_type)
            results: List[str] = []
            for rdata in answer:
                if rdtype.upper() == "TXT":
                    # TXT records may contain multiple byte strings that must be concatenated
                    if hasattr(rdata, "strings"):
                        txt_val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                        results.append(txt_val)
                    else:
                        results.append(str(rdata).strip('"'))
                elif rdtype.upper() == "CAA":
                    # Format: flags tag "value"
                    tag = (
                        rdata.tag.decode("utf-8")
                        if isinstance(rdata.tag, bytes)
                        else str(rdata.tag)
                    )
                    val = (
                        rdata.value.decode("utf-8")
                        if isinstance(rdata.value, bytes)
                        else str(rdata.value)
                    )
                    results.append(f'{rdata.flags} {tag} "{val}"')
                elif rdtype.upper() == "CNAME":
                    results.append(str(rdata.target).rstrip("."))
                elif rdtype.upper() == "NS":
                    results.append(str(rdata.target).rstrip("."))
                else:
                    results.append(str(rdata).rstrip("."))
            return results
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []
        except Exception as exc:
            logger.debug("DNS query error for %s (%s): %s", qname, rdtype, exc)
            return []

    def get_cname(self, qname: str) -> Optional[str]:
        """Retrieve CNAME record target if exists."""
        records = self.query(qname, "CNAME")
        return records[0] if records else None

    def get_ns(self, qname: str) -> List[str]:
        """Retrieve NS records for domain."""
        return self.query(qname, "NS")

    def get_txt(self, qname: str) -> List[str]:
        """Retrieve TXT records for domain."""
        return self.query(qname, "TXT")

    def get_caa(self, qname: str) -> List[str]:
        """Retrieve CAA records for domain."""
        return self.query(qname, "CAA")

    def get_dnskey(self, qname: str) -> List[str]:
        """Retrieve DNSKEY records for domain."""
        return self.query(qname, "DNSKEY")

    def get_ds(self, qname: str) -> List[str]:
        """Retrieve DS records for domain."""
        return self.query(qname, "DS")

    def get_rrsig(self, qname: str) -> List[str]:
        """Retrieve RRSIG records for domain."""
        return self.query(qname, "RRSIG")

    def check_axfr(self, zone: str, nameserver: str) -> bool:
        """Attempt an AXFR full zone transfer against a specific nameserver.

        Args:
            zone: Target zone or domain name.
            nameserver: Hostname or IP of the nameserver.

        Returns:
            True if zone transfer succeeded (vulnerable), False otherwise.
        """
        try:
            # Resolve nameserver to IP if needed
            ns_ips = [nameserver]
            try:
                ip_answers = self.resolver.resolve(nameserver, "A")
                ns_ips = [str(r) for r in ip_answers]
            except Exception as exc:
                logger.debug("Could not resolve IP for NS %s: %s", nameserver, exc)

            for ip in ns_ips:
                try:
                    xfr = dns.query.xfr(ip, zone, timeout=3.0, lifetime=5.0)
                    zone_obj = dns.zone.from_xfr(xfr)
                    if zone_obj and len(zone_obj.nodes) > 0:
                        return True
                except Exception as exc:
                    logger.debug("AXFR transfer failed from %s for %s: %s", ip, zone, exc)
            return False
        except Exception as exc:
            logger.debug("AXFR check aborted for %s on %s: %s", zone, nameserver, exc)
            return False

    def target_resolves(self, target: str) -> bool:
        """Check if target host resolves to an A, AAAA, or CNAME record."""
        try:
            target_clean = target.rstrip(".")
            a_records = self.query(target_clean, "A")
            if a_records:
                return True
            aaaa_records = self.query(target_clean, "AAAA")
            if aaaa_records:
                return True
            cname_records = self.query(target_clean, "CNAME")
            if cname_records:
                return True
            return False
        except Exception:
            return False
