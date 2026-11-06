# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.exporters.sarif
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 finding exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from lh_dns_guardian.exporters.base import BaseExporter
from lh_dns_guardian.models import AuditReport

SARIF_SCHEMA_V2_1_0 = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class SarifExporter(BaseExporter):
    """Exports audit findings in standard OASIS SARIF v2.1.0 JSON format."""

    def __init__(self, indent: int = 2) -> None:
        """Initialize SARIF exporter."""
        self.indent = indent

    def export(self, report: AuditReport, output_file: Optional[str] = None) -> str:
        """Serialize audit report to OASIS SARIF v2.1.0 JSON."""
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for finding in report.findings:
            # Register rule if not already present
            if finding.id not in rules_map:
                rules_map[finding.id] = {
                    "id": finding.id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.recommendation},
                    "defaultConfiguration": {
                        "level": finding.severity.sarif_level,
                    },
                    "properties": {
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                    },
                }

            result_entry: Dict[str, Any] = {
                "ruleId": finding.id,
                "level": finding.severity.sarif_level,
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.target,
                            },
                        },
                    },
                ],
                "properties": {
                    "title": finding.title,
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "recommendation": finding.recommendation,
                },
            }
            if finding.evidence:
                result_entry["properties"]["evidence"] = finding.evidence

            results.append(result_entry)

        sarif_doc: Dict[str, Any] = {
            "$schema": SARIF_SCHEMA_V2_1_0,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "lh-dns-guardian",
                            "organization": "Logihertz Systems OPC Pvt Ltd",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-dns-guardian",
                            "rules": list(rules_map.values()),
                        },
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": report.timestamp.isoformat(),
                            "toolExecutionNotifications": [],
                        },
                    ],
                    "results": results,
                },
            ],
        }

        json_str = json.dumps(sarif_doc, indent=self.indent, ensure_ascii=False)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str
