"""Pydantic models for the v0.1 scan API.

The models deliberately describe the API boundary only.  They do not perform
DNS lookups, HTTP requests, or any other scan work.  A scan manager supplied by
the application owns those concerns.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.security.url_validation import URLValidationError, normalize_target_url
from app.engagement.models import Engagement, EngagementBudgets
from app.scanning.models import AssessmentCoverage, AssessmentResult, WebsiteProfile


class CreateScanRequest(BaseModel):
    """Validated input for creating an authorized scan."""

    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(..., description="HTTP(S) URL at which the scan starts")
    engagement_id: UUID | None = Field(
        default=None, description="Optional server-side engagement authorization"
    )
    assessment_profile: str | None = Field(
        default=None, description="Optional named assessment profile; defaults to passive"
    )
    active_testing_authorized: bool | None = Field(
        default=None, description="Explicit authorization for controlled active assessment"
    )
    authorization_confirmed: Literal[True] = Field(
        ..., description="The caller confirms they are authorized to scan the target"
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        """Validate URL syntax and return the canonical target URL.

        ``normalize_target_url`` is intentionally a pure validation boundary;
        no DNS or network operation occurs while validating a request.
        """

        try:
            return normalize_target_url(value).url
        except URLValidationError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("assessment_profile")
    @classmethod
    def validate_assessment_profile(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("assessment_profile must not be empty")
        return None if value is None else value.strip()


class CreateEngagementRequest(BaseModel):
    """Safe authorization metadata used to create an in-memory engagement."""

    model_config = ConfigDict(extra="forbid")

    target_domains: tuple[str, ...] = ()
    target_ips: tuple[str, ...] = ()
    target_cidrs: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    excluded_addresses: tuple[str, ...] = ()
    excluded_routes: tuple[str, ...] = ()
    permitted_ports: tuple[int, ...] = (80, 443)
    permitted_service_types: tuple[str, ...] = ("http", "https")
    allowed_assessment_profiles: tuple[str, ...] = ()
    allowed_capabilities: tuple[str, ...] = ()
    authorization_reference: str
    expires_at: datetime | None = None
    budgets: EngagementBudgets = Field(default_factory=EngagementBudgets)

    @model_validator(mode="after")
    def require_target_scope(self) -> "CreateEngagementRequest":
        if not self.target_domains and not self.target_ips and not self.target_cidrs:
            raise ValueError("at least one target domain, IP, or CIDR is required")
        return self

    def to_engagement(self) -> Engagement:
        return Engagement.model_validate(self.model_dump())


class EngagementResponse(Engagement):
    """Public engagement metadata; no credential-bearing fields exist."""

    model_config = ConfigDict(from_attributes=True)


class EvidenceResponse(BaseModel):
    """Safe response metadata attached to a check or finding."""

    model_config = ConfigDict(from_attributes=True)

    url: str
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class FindingResponse(BaseModel):
    """A single finding emitted by a check."""

    model_config = ConfigDict(from_attributes=True)

    code: str
    severity: str
    confidence: str = "high"
    target: str | None = None
    title: str
    description: str
    status: str = "open"
    evidence: EvidenceResponse | None = None
    remediation: str | None = None
    verification: str | None = "not_verified"
    module: str | None = None
    test_id: str | None = None
    test_version: str | None = None
    reference: str | None = None
    references: list[str] = Field(default_factory=list)
    owasp_category: str | None = None
    owasp_id: str | None = None
    timestamp: datetime | None = None


class CheckResponse(BaseModel):
    """The result of one named security check."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    status: str
    findings: list[FindingResponse] = Field(default_factory=list)
    evidence: EvidenceResponse | None = None
    observation: dict[str, str | bool] | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class SummaryResponse(BaseModel):
    """Aggregate counts for a scan."""

    model_config = ConfigDict(from_attributes=True)

    checks_total: int = Field(default=0, ge=0)
    checks_completed: int = Field(default=0, ge=0)
    findings_total: int = Field(default=0, ge=0)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)


class WebsiteProfileResponse(WebsiteProfile):
    """Optional v0.2 intelligence profile attached to a scan response."""

    model_config = ConfigDict(from_attributes=True)


class ScanStatusResponse(BaseModel):
    """Current status and available results for a scan."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID | str
    target_url: str
    engagement_id: UUID | None = None
    assessment_profile: str | None = None
    active_testing_authorized: bool | None = None
    status: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: SummaryResponse = Field(default_factory=SummaryResponse)
    checks: list[CheckResponse] = Field(default_factory=list)
    findings: list[FindingResponse] = Field(default_factory=list)
    intelligence: WebsiteProfileResponse | None = None
    assessment: AssessmentResult | None = None
    coverage: AssessmentCoverage | None = None
    error: str | None = None


# These aliases keep the model names easy to discover for callers that use the
# endpoint names as type names while retaining the explicit response suffixes.
CreateScan = CreateScanRequest
CreateScanResponse = ScanStatusResponse
ScanStatus = ScanStatusResponse
Summary = SummaryResponse
WebsiteProfileResult = WebsiteProfileResponse
Check = CheckResponse
Finding = FindingResponse
CreateEngagement = CreateEngagementRequest
