# ==============================================================================
# Product:       lh-dns-guardian (lh-dns)
# Module:        tests.test_caa
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Certificate Authority Authorization (CAA) audit rules."""

from __future__ import annotations

from lh_dns_guardian.models import Severity
from lh_dns_guardian.rules.caa import audit_caa


def test_caa_missing() -> None:
    """Test flagging of missing CAA record."""
    findings = audit_caa("example.com", caa_records=[])
    assert len(findings) == 1
    assert findings[0].id == "LH-CAA-001"
    assert findings[0].severity == Severity.MEDIUM
    assert "Missing CAA" in findings[0].title


def test_caa_configured() -> None:
    """Test verification of published CAA policy."""
    records = ['0 issue "letsencrypt.org"', '0 iodef "mailto:security@example.com"']
    findings = audit_caa("example.com", caa_records=records)
    assert len(findings) == 1
    assert findings[0].id == "LH-CAA-002"
    assert findings[0].severity == Severity.INFO
    assert "letsencrypt.org" in (findings[0].evidence or "")
