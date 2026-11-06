# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.exporters.base
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Base exporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from lh_dns_guardian.models import AuditReport


class BaseExporter(ABC):
    """Abstract base class for finding exporters."""

    @abstractmethod
    def export(self, report: AuditReport, output_file: Optional[str] = None) -> str:
        """Export report to formatted string and optionally save to file.

        Args:
            report: The completed audit report.
            output_file: Optional file path to write output.

        Returns:
            The exported report string.
        """
        pass
