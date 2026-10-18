"""Serializable, non-secret engagement authorization records."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_network
from typing import ClassVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import ScanLimits


def _now() -> datetime:
    return datetime.now(timezone.utc)


class EngagementStatus(str, Enum):
    ACTIVE = "active"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class EngagementAuditEntry(BaseModel):
    """Safe lifecycle metadata; it intentionally has no credentials or payloads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str
    actor: str | None = None
    reason: str | None = None
    timestamp: datetime = Field(default_factory=_now)

    @field_validator("action", "actor", "reason")
    @classmethod
    def bounded_text(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 512:
            raise ValueError("audit metadata text is limited to 512 characters")
        return value


class EngagementBudgets(BaseModel):
    """Optional per-engagement caps, always intersected with server defaults."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_requests_per_scan: int | None = Field(default=None, ge=0)
    maximum_requests_per_host: int | None = Field(default=None, ge=0)
    maximum_concurrency: int | None = Field(default=None, ge=1)
    scan_timeout_seconds: float | None = Field(default=None, gt=0)
    maximum_response_bytes: int | None = Field(default=None, ge=0)
    maximum_redirects: int | None = Field(default=None, ge=0)
    maximum_findings: int | None = Field(default=None, ge=0)

    @property
    def max_requests_per_scan(self) -> int | None:
        return self.maximum_requests_per_scan

    @property
    def max_requests_per_host(self) -> int | None:
        return self.maximum_requests_per_host

    def apply(self, limits: ScanLimits) -> ScanLimits:
        """Return limits narrowed by this engagement's declared budgets."""

        def cap(current, requested):
            return current if requested is None else min(current, requested)

        return ScanLimits(
            request_timeout_seconds=cap(limits.request_timeout_seconds, self.scan_timeout_seconds),
            scan_timeout_seconds=cap(limits.scan_timeout_seconds, self.scan_timeout_seconds),
            maximum_response_bytes=cap(limits.maximum_response_bytes, self.maximum_response_bytes),
            maximum_crawl_depth=limits.maximum_crawl_depth,
            maximum_pages=limits.maximum_pages,
            maximum_concurrency=cap(limits.maximum_concurrency, self.maximum_concurrency),
            maximum_requests_per_scan=cap(limits.maximum_requests_per_scan, self.maximum_requests_per_scan),
            maximum_findings=cap(limits.maximum_findings, self.maximum_findings),
            maximum_requests_per_host=cap(limits.maximum_requests_per_host, self.maximum_requests_per_host),
            maximum_redirects=cap(limits.maximum_redirects, self.maximum_redirects),
            allowed_ports=limits.allowed_ports,
        )


class Engagement(BaseModel):
    """An in-memory authorization record for one bounded assessment."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: UUID = Field(default_factory=uuid4)
    target_domains: tuple[str, ...] = Field(default_factory=tuple)
    target_ips: tuple[str, ...] = Field(default_factory=tuple)
    target_cidrs: tuple[str, ...] = Field(default_factory=tuple)
    excluded_hosts: tuple[str, ...] = Field(default_factory=tuple)
    excluded_addresses: tuple[str, ...] = Field(default_factory=tuple)
    excluded_routes: tuple[str, ...] = Field(default_factory=tuple)
    permitted_ports: tuple[int, ...] = (80, 443)
    permitted_service_types: tuple[str, ...] = ("http", "https")
    allowed_assessment_profiles: tuple[str, ...] = Field(default_factory=tuple)
    allowed_capabilities: tuple[str, ...] = Field(default_factory=tuple)
    authorization_reference: str
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime | None = None
    status: EngagementStatus = EngagementStatus.ACTIVE
    budgets: EngagementBudgets = Field(default_factory=EngagementBudgets)
    cancelled_at: datetime | None = None
    cancelled_by: str | None = None
    cancellation_reason: str | None = None
    audit_metadata: tuple[EngagementAuditEntry, ...] = Field(default_factory=tuple)

    _minimum_scope: ClassVar[str] = "at least one target domain, IP, or CIDR is required"

    @field_validator("target_domains", "excluded_hosts", "allowed_assessment_profiles", "allowed_capabilities")
    @classmethod
    def normalize_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("scope names must be non-empty strings")
            normalized.append(value.strip().casefold().rstrip("."))
        return tuple(dict.fromkeys(normalized))

    @field_validator("target_ips", "target_cidrs", "excluded_addresses")
    @classmethod
    def validate_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = []
        for value in values:
            try:
                normalized.append(str(ip_network(value, strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid IP or CIDR: {value!r}") from exc
        return tuple(dict.fromkeys(normalized))

    @field_validator("permitted_ports")
    @classmethod
    def validate_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if not values or any(not 1 <= port <= 65535 for port in values):
            raise ValueError("permitted_ports must contain valid ports")
        return tuple(dict.fromkeys(values))

    @field_validator("permitted_service_types")
    @classmethod
    def validate_services(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(dict.fromkeys(value.strip().casefold() for value in values if value.strip()))
        if not normalized:
            raise ValueError("permitted_service_types must not be empty")
        return normalized

    @field_validator("authorization_reference")
    @classmethod
    def validate_authorization_reference(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 512:
            raise ValueError("authorization_reference must be a non-empty reference")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime | None, info):
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        return value

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value

    def model_post_init(self, __context) -> None:
        if not self.target_domains and not self.target_ips and not self.target_cidrs:
            raise ValueError(self._minimum_scope)
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")

    def is_active(self, now: datetime | None = None) -> bool:
        now = now or _now()
        return self.status == EngagementStatus.ACTIVE and (
            self.expires_at is None or now < self.expires_at
        )

    def effective_status(self, now: datetime | None = None) -> EngagementStatus:
        if self.status == EngagementStatus.ACTIVE and self.expires_at is not None and (now or _now()) >= self.expires_at:
            return EngagementStatus.EXPIRED
        return self.status

    @property
    def target_networks(self) -> tuple[str, ...]:
        return (*self.target_ips, *self.target_cidrs)

    @property
    def allowed_profiles(self) -> tuple[str, ...]:
        return self.allowed_assessment_profiles
