# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.exporters.json_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""JSON finding exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from lh_dns_guardian.exporters.base import BaseExporter
from lh_dns_guardian.models import AuditReport


class JsonExporter(BaseExporter):
    """Exports audit report as structured JSON."""

    def __init__(self, indent: int = 2) -> None:
        """Initialize JSON exporter with indentation preference."""
        self.indent = indent

    def export(self, report: AuditReport, output_file: Optional[str] = None) -> str:
        """Serialize audit report to formatted JSON string."""
        data = report.to_dict()
        json_str = json.dumps(data, indent=self.indent, ensure_ascii=False)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str
