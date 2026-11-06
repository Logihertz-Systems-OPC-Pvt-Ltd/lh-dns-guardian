"""Parser for BIND DNS master zone files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Union

import dns.name
import dns.rdatatype
import dns.zone


class ParsedZone:
    """Represents a parsed BIND zone file with structured lookup helpers."""

    def __init__(self, zone: dns.zone.Zone, origin: str) -> None:
        """Initialize with dnspython zone object and origin name.

        Args:
            zone: Parsed dnspython Zone instance.
            origin: Zone origin domain name.
        """
        self.zone = zone
        self.origin = origin.rstrip(".").lower()
        # Mapping: domain_name -> rdtype -> list of record values
        self.records: Dict[str, Dict[str, List[str]]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Index all node rdatasets into a convenient domain -> rdtype -> values map."""
        origin_name = dns.name.from_text(self.origin)
        for name, node in self.zone.nodes.items():
            # Derive full name
            if isinstance(name, dns.name.Name):
                full_name = name.derelativize(origin_name).to_text().rstrip(".").lower()
            else:
                full_name = str(name).rstrip(".").lower()

            if full_name not in self.records:
                self.records[full_name] = {}

            for rdataset in node.rdatasets:
                rdtype = dns.rdatatype.to_text(rdataset.rdtype).upper()
                if rdtype not in self.records[full_name]:
                    self.records[full_name][rdtype] = []

                for rdata in rdataset:
                    if rdtype == "TXT":
                        if hasattr(rdata, "strings"):
                            val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                            self.records[full_name][rdtype].append(val)
                        else:
                            self.records[full_name][rdtype].append(str(rdata).strip('"'))
                    elif rdtype == "CAA":
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
                        self.records[full_name][rdtype].append(f'{rdata.flags} {tag} "{val}"')
                    elif rdtype in ("CNAME", "NS", "PTR", "DNAME"):
                        self.records[full_name][rdtype].append(
                            str(rdata.target).rstrip(".").lower()
                        )
                    else:
                        self.records[full_name][rdtype].append(str(rdata).rstrip("."))

    def get_records(self, name: Optional[str] = None, rdtype: Optional[str] = None) -> List[str]:
        """Retrieve records by name and type.

        Args:
            name: Fully qualified domain name (defaults to zone origin).
            rdtype: DNS record type string (e.g. 'A', 'TXT', 'CAA').

        Returns:
            List of record string values.
        """
        target_name = (name.rstrip(".").lower()) if name else self.origin
        if target_name not in self.records:
            return []
        if rdtype is None:
            all_vals: List[str] = []
            for vals in self.records[target_name].values():
                all_vals.extend(vals)
            return all_vals
        return self.records[target_name].get(rdtype.upper(), [])

    def get_cnames(self) -> Dict[str, str]:
        """Return a mapping of domain name to CNAME target for all CNAMEs in the zone."""
        cnames: Dict[str, str] = {}
        for name, type_map in self.records.items():
            if "CNAME" in type_map and type_map["CNAME"]:
                cnames[name] = type_map["CNAME"][0]
        return cnames

    def get_txt(self, name: Optional[str] = None) -> List[str]:
        """Get TXT records for a specific name or the zone origin."""
        return self.get_records(name, "TXT")

    def get_caa(self, name: Optional[str] = None) -> List[str]:
        """Get CAA records for a specific name or the zone origin."""
        return self.get_records(name, "CAA")

    def get_dnskey(self, name: Optional[str] = None) -> List[str]:
        """Get DNSKEY records for a specific name or the zone origin."""
        return self.get_records(name, "DNSKEY")

    def get_ds(self, name: Optional[str] = None) -> List[str]:
        """Get DS records for a specific name or the zone origin."""
        return self.get_records(name, "DS")

    def get_rrsig(self, name: Optional[str] = None) -> List[str]:
        """Get RRSIG records for a specific name or the zone origin."""
        return self.get_records(name, "RRSIG")

    def get_ns(self, name: Optional[str] = None) -> List[str]:
        """Get NS records for a specific name or the zone origin."""
        return self.get_records(name, "NS")


def parse_zone_file(file_path: Union[str, Path], origin: Optional[str] = None) -> ParsedZone:
    """Parse a BIND zone file from disk.

    Args:
        file_path: Path to the zone file.
        origin: Domain origin (e.g., 'example.com.'). If omitted, inferred from file or basename.

    Returns:
        ParsedZone instance.

    Raises:
        FileNotFoundError: If zone file cannot be located.
        ValueError: If parsing fails or origin cannot be resolved.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Zone file not found: {file_path}")

    if origin:
        origin_str = origin.rstrip(".") + "."
        zone = dns.zone.from_file(str(path), origin=origin_str, relativize=False)
        resolved_origin = str(zone.origin).rstrip(".") if zone.origin else origin
        return ParsedZone(zone=zone, origin=resolved_origin)

    try:
        # First attempt: let dnspython detect $ORIGIN inside the file
        zone = dns.zone.from_file(str(path), relativize=False)
        resolved_origin = str(zone.origin).rstrip(".") if zone.origin else path.stem
        return ParsedZone(zone=zone, origin=resolved_origin)
    except (dns.zone.NoSOA, dns.zone.UnknownOrigin):
        # Fallback: infer origin from file basename
        basename = path.stem
        if basename.endswith((".zone", ".db", ".txt")):
            basename = os.path.splitext(basename)[0]
        fallback_origin = basename.rstrip(".") + "."
        zone = dns.zone.from_file(str(path), origin=fallback_origin, relativize=False)
        resolved_origin = str(zone.origin).rstrip(".") if zone.origin else basename
        return ParsedZone(zone=zone, origin=resolved_origin)


def parse_zone_text(zone_text: str, origin: str) -> ParsedZone:
    """Parse BIND zone content from a text string.

    Args:
        zone_text: Raw BIND zone string.
        origin: Domain origin (e.g., 'example.com').

    Returns:
        ParsedZone instance.
    """
    origin_str = origin.rstrip(".") + "."
    zone = dns.zone.from_text(zone_text, origin=origin_str, relativize=False)
    return ParsedZone(zone=zone, origin=origin)
