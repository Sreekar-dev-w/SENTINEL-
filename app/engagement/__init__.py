"""First-class engagement authorization and scope primitives."""

from app.engagement.models import (
    Engagement,
    EngagementAuditEntry,
    EngagementBudgets,
    EngagementStatus,
)

EngagementBudget = EngagementBudgets
from app.engagement.policy import (
    EngagementPolicyError,
    EngagementScopePolicy,
    EngagementScopeViolation,
)
from app.engagement.store import (
    EngagementNotFound,
    EngagementStore,
    InvalidEngagementTransition,
)

__all__ = [
    "Engagement",
    "EngagementAuditEntry",
    "EngagementBudgets",
    "EngagementBudget",
    "EngagementStatus",
    "EngagementPolicyError",
    "EngagementScopePolicy",
    "EngagementScopeViolation",
    "EngagementNotFound",
    "EngagementStore",
    "InvalidEngagementTransition",
]
