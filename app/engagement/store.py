"""Race-safe in-memory engagement lifecycle store."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID

from app.engagement.models import Engagement, EngagementAuditEntry, EngagementStatus


class EngagementNotFound(LookupError):
    pass


class InvalidEngagementTransition(RuntimeError):
    pass


class EngagementStore:
    """Store only authorization metadata; it never accepts secrets or payloads."""

    def __init__(self) -> None:
        self._engagements: dict[UUID, Engagement] = {}
        self._lock = asyncio.Lock()

    async def create(self, engagement: Engagement) -> Engagement:
        async with self._lock:
            if engagement.id in self._engagements:
                raise ValueError(f"engagement {engagement.id} already exists")
            stored = engagement.model_copy(deep=True)
            if not stored.audit_metadata:
                stored.audit_metadata = (EngagementAuditEntry(
                    action="created", timestamp=stored.created_at
                ),)
            self._engagements[engagement.id] = stored
            return stored.model_copy(deep=True)

    async def get(self, engagement_id: UUID | str) -> Engagement | None:
        try:
            parsed = engagement_id if isinstance(engagement_id, UUID) else UUID(str(engagement_id))
        except (ValueError, TypeError):
            return None
        async with self._lock:
            engagement = self._engagements.get(parsed)
            if engagement is None:
                return None
            if engagement.effective_status() != engagement.status:
                engagement.status = engagement.effective_status()
                engagement.audit_metadata = (*engagement.audit_metadata, EngagementAuditEntry(
                    action="expired", timestamp=engagement.expires_at
                ))
            return engagement.model_copy(deep=True)

    async def require(self, engagement_id: UUID | str) -> Engagement:
        engagement = await self.get(engagement_id)
        if engagement is None:
            raise EngagementNotFound(str(engagement_id))
        return engagement

    async def cancel(
        self,
        engagement_id: UUID | str,
        *,
        actor: str | None = None,
        reason: str | None = None,
    ) -> Engagement:
        try:
            parsed = engagement_id if isinstance(engagement_id, UUID) else UUID(str(engagement_id))
        except (ValueError, TypeError) as exc:
            raise EngagementNotFound(str(engagement_id)) from exc
        async with self._lock:
            engagement = self._engagements.get(parsed)
            if engagement is None:
                raise EngagementNotFound(str(engagement_id))
            if engagement.effective_status() == EngagementStatus.EXPIRED:
                engagement.status = EngagementStatus.EXPIRED
                return engagement.model_copy(deep=True)
            if engagement.status == EngagementStatus.EXPIRED:
                return engagement.model_copy(deep=True)
            if engagement.status == EngagementStatus.CANCELLED:
                return engagement.model_copy(deep=True)
            now = datetime.now(timezone.utc)
            engagement.status = EngagementStatus.CANCELLED
            engagement.cancelled_at = now
            engagement.cancelled_by = actor
            engagement.cancellation_reason = reason
            engagement.audit_metadata = (*engagement.audit_metadata, EngagementAuditEntry(
                action="cancelled", actor=actor, reason=reason, timestamp=now
            ))
            return engagement.model_copy(deep=True)

    # Explicit names make the store convenient at API and integration seams.
    create_engagement = create
    get_engagement = get
    cancel_engagement = cancel
