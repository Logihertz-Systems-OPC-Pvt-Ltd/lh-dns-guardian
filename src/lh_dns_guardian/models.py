"""Data models and structures for DNS security audit findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Severity ratings for security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting severity (higher is more severe)."""
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)

    @property
    def sarif_level(self) -> str:
        """Map severity to OASIS SARIF v2.1.0 result level."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


class FindingCategory(str, Enum):
    """Categories of DNS security findings."""

    DNSSEC = "DNSSEC"
    CAA = "CAA"
    ZONE_TRANSFER = "ZONE_TRANSFER"
    SPF = "SPF"
    DMARC = "DMARC"
    TAKEOVER = "TAKEOVER"
    GENERAL = "GENERAL"


@dataclass
class Finding:
    """Represents a single security audit finding."""

    id: str
    title: str
    category: FindingCategory
    severity: Severity
    target: str
    description: str
    recommendation: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to a JSON-serializable dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class AuditReport:
    """Aggregated audit report containing all security findings."""

    target: str
    target_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self.findings.append(finding)

    def summary_counts(self) -> Dict[str, int]:
        """Generate count of findings grouped by severity."""
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def has_critical_or_high(self) -> bool:
        """Check if report contains any CRITICAL or HIGH severity findings."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire audit report to dictionary."""
        return {
            "target": self.target,
            "target_type": self.target_type,
            "timestamp": self.timestamp.isoformat(),
            "summary": self.summary_counts(),
            "total_findings": len(self.findings),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }
