# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        src.lh_dns_guardian.rules.base
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Base interfaces and metadata definitions for DNS audit rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from lh_dns_guardian.models import Finding, FindingCategory, Severity


@dataclass
class RuleDefinition:
    """Metadata describing a DNS security check rule."""

    id: str
    title: str
    category: FindingCategory
    severity: Severity
    description: str
    recommendation: str

    def create_finding(
        self,
        target: str,
        description_override: Optional[str] = None,
        recommendation_override: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> Finding:
        """Create a Finding instance populated with this rule's metadata."""
        return Finding(
            id=self.id,
            title=self.title,
            category=self.category,
            severity=self.severity,
            target=target,
            description=description_override or self.description,
            recommendation=recommendation_override or self.recommendation,
            evidence=evidence,
        )
