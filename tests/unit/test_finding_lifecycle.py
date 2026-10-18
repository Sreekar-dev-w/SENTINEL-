from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.scanning.finding_lifecycle import FindingLifecycleError, transition_finding
from app.scanning.models import Finding, FindingSeverity, FindingStatus, VerificationStatus


def _finding() -> Finding:
    return Finding(
        code="fixture-finding",
        title="Fixture finding",
        description="A deterministic finding",
        severity=FindingSeverity.MEDIUM,
        target="https://fixture.example/",
    )


def test_verification_and_resolution_are_independent_and_audited():
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    confirmed = transition_finding(
        _finding(), verification=VerificationStatus.CONFIRMED,
        actor="operator", reason="reproduced", timestamp=timestamp,
    )
    resolved = transition_finding(
        confirmed, status=FindingStatus.RESOLVED,
        actor="operator", reason="remediation deployed", timestamp=timestamp,
    )

    assert confirmed.verification == VerificationStatus.CONFIRMED
    assert confirmed.status == FindingStatus.OPEN
    assert resolved.verification == VerificationStatus.CONFIRMED
    assert resolved.status == FindingStatus.RESOLVED
    assert [entry.action for entry in resolved.audit_trail] == [
        "verification_changed", "status_changed"
    ]
    assert resolved.audit_trail[-1].reason == "remediation deployed"


def test_invalid_transitions_are_rejected_without_mutating_the_original():
    finding = transition_finding(_finding(), status=FindingStatus.RESOLVED)
    with pytest.raises(FindingLifecycleError, match="status transition"):
        transition_finding(finding, status=FindingStatus.FALSE_POSITIVE)
    with pytest.raises(FindingLifecycleError, match="already has"):
        transition_finding(finding, verification=VerificationStatus.NOT_VERIFIED)
    with pytest.raises(FindingLifecycleError, match="already has"):
        transition_finding(finding, status=FindingStatus.RESOLVED)
    assert len(finding.audit_trail) == 1


def test_resolution_can_be_reopened_without_claiming_remediation_verification():
    resolved = transition_finding(_finding(), status=FindingStatus.RESOLVED)
    reopened = transition_finding(resolved, status=FindingStatus.OPEN)
    assert reopened.status == FindingStatus.OPEN
    assert reopened.verification == VerificationStatus.NOT_VERIFIED
    assert [entry.new_status for entry in reopened.audit_trail] == [
        FindingStatus.RESOLVED, FindingStatus.OPEN
    ]
