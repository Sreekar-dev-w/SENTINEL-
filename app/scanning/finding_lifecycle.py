"""Explicit, auditable finding verification and resolution transitions."""

from __future__ import annotations

from datetime import datetime

from app.scanning.models import (
    Finding,
    FindingAuditEntry,
    FindingStatus,
    VerificationStatus,
)


class FindingLifecycleError(ValueError):
    """Raised when a finding transition is not allowed."""


_VERIFICATION_TRANSITIONS: dict[VerificationStatus, frozenset[VerificationStatus]] = {
    VerificationStatus.NOT_VERIFIED: frozenset({
        VerificationStatus.POTENTIAL,
        VerificationStatus.CONFIRMED,
        VerificationStatus.INFORMATIONAL,
        VerificationStatus.NOT_APPLICABLE,
    }),
    VerificationStatus.POTENTIAL: frozenset({
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.CONFIRMED,
        VerificationStatus.INFORMATIONAL,
        VerificationStatus.NOT_APPLICABLE,
    }),
    VerificationStatus.CONFIRMED: frozenset({
        VerificationStatus.POTENTIAL,
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.NOT_APPLICABLE,
    }),
    VerificationStatus.INFORMATIONAL: frozenset({
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.POTENTIAL,
        VerificationStatus.CONFIRMED,
        VerificationStatus.NOT_APPLICABLE,
    }),
    VerificationStatus.NOT_APPLICABLE: frozenset({
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.POTENTIAL,
        VerificationStatus.CONFIRMED,
        VerificationStatus.INFORMATIONAL,
    }),
    VerificationStatus.OBSERVED: frozenset({
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.POTENTIAL,
        VerificationStatus.CONFIRMED,
    }),
    VerificationStatus.INFERRED: frozenset({
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.POTENTIAL,
        VerificationStatus.CONFIRMED,
    }),
    VerificationStatus.UNVERIFIED: frozenset({
        VerificationStatus.NOT_VERIFIED,
        VerificationStatus.POTENTIAL,
        VerificationStatus.CONFIRMED,
    }),
}

_STATUS_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset({
        FindingStatus.RESOLVED,
        FindingStatus.ACCEPTED,
        FindingStatus.FALSE_POSITIVE,
    }),
    FindingStatus.RESOLVED: frozenset({FindingStatus.OPEN}),
    FindingStatus.ACCEPTED: frozenset({FindingStatus.OPEN}),
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.OPEN}),
}


def transition_finding(
    finding: Finding,
    *,
    verification: VerificationStatus | None = None,
    status: FindingStatus | None = None,
    actor: str | None = None,
    reason: str | None = None,
    timestamp: datetime | None = None,
) -> Finding:
    """Return a new finding after one or both validated state transitions.

    Resolution and verification are intentionally independent: resolving a
    finding never implies that remediation was verified, and confirming a
    finding never closes it. The returned finding retains an append-only audit
    trail containing only bounded operator metadata.
    """

    if verification is None and status is None:
        raise FindingLifecycleError("a verification or status transition is required")
    if reason is not None and len(reason) > 512:
        raise FindingLifecycleError("finding transition reason is limited to 512 characters")
    if actor is not None and len(actor) > 512:
        raise FindingLifecycleError("finding transition actor is limited to 512 characters")

    updates = {}
    entries = list(finding.audit_trail)
    audit_time = {} if timestamp is None else {"timestamp": timestamp}
    if verification is not None:
        if verification == finding.verification:
            raise FindingLifecycleError("finding already has that verification state")
        if verification not in _VERIFICATION_TRANSITIONS.get(finding.verification, frozenset()):
            raise FindingLifecycleError(
                f"verification transition {finding.verification.value!r} -> {verification.value!r} is not allowed"
            )
        updates["verification"] = verification
        entries.append(FindingAuditEntry(
            action="verification_changed",
            actor=actor,
            reason=reason,
            previous_verification=finding.verification,
            new_verification=verification,
            **audit_time,
        ))

    if status is not None:
        if status == finding.status:
            raise FindingLifecycleError("finding already has that lifecycle status")
        if status not in _STATUS_TRANSITIONS.get(finding.status, frozenset()):
            raise FindingLifecycleError(
                f"status transition {finding.status.value!r} -> {status.value!r} is not allowed"
            )
        updates["status"] = status
        entries.append(FindingAuditEntry(
            action="status_changed",
            actor=actor,
            reason=reason,
            previous_status=finding.status,
            new_status=status,
            **audit_time,
        ))

    updates["audit_trail"] = entries
    return finding.model_copy(update=updates)


__all__ = ["FindingLifecycleError", "transition_finding"]
