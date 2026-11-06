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
