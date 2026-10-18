"""Small, serializable domain models for the scan core.

These models deliberately describe observations rather than retaining HTTP
payloads.  Evidence is restricted to the response metadata needed to explain
an initial check; cookies, authorization material, and response bodies are not
part of the model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar, TypeAlias
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class VerificationStatus(str, Enum):
    """How a result was established without implying exploitability."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFORMATIONAL = "informational"
    NOT_VERIFIED = "not_verified"
    NOT_APPLICABLE = "not_applicable"
    # Legacy aliases retained for clients that consumed the v0.3 preview.
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"


class ObservationMode(str, Enum):
    """Whether an intelligence value came directly from the target or was inferred."""

    OBSERVED = "observed"
    INFERRED = "inferred"


class ObservationStatus(str, Enum):
    """Lifecycle/result status for an intelligence observation."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    UNAVAILABLE = "unavailable"
    INCONCLUSIVE = "inconclusive"
    LIMITED = "limited"
    ERROR = "error"


WebsiteValue: TypeAlias = (
    str
    | int
    | bool
    | list[str]
    | dict[str, str | int | bool | list[str]]
)


class CheckType(str, Enum):
    HSTS = "hsts"
    CSP = "content_security_policy"
    X_CONTENT_TYPE_OPTIONS = "x_content_type_options"
    HTTPS_TRANSPORT = "https_transport"


class AssessmentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MinimalEvidence(BaseModel):
    """Safe response metadata for explaining a finding.

    Only headers used by the initial checks are accepted.  Rejecting sensitive
    names instead of silently storing them prevents accidental evidence leaks
    when a caller forwards a complete response-header mapping.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    status_code: int | None = Field(default=None, ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)

    _allowed_headers: ClassVar[frozenset[str]] = frozenset(
        {
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-expose-headers",
            "vary",
            "content-type",
            "location",
            "server",
            "x-powered-by",
            "via",
            "x-cache",
            "cf-ray",
        }
    )
    _forbidden_headers: ClassVar[frozenset[str]] = frozenset(
        {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        }
    )

    @field_validator("url")
    @classmethod
    def non_empty_url(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence URL must not be empty")
        return value

    @field_validator("headers")
    @classmethod
    def safe_headers(cls, values: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for name, value in values.items():
            key = name.strip().lower()
            if key in cls._forbidden_headers:
                raise ValueError(f"sensitive header is not valid evidence: {name}")
            if key not in cls._allowed_headers:
                raise ValueError(f"header is not valid minimal evidence: {name}")
            if len(value) > 4096:
                raise ValueError("evidence header values are limited to 4096 bytes")
            normalized[key] = value
        return normalized


class FindingAuditEntry(BaseModel):
    """Safe, append-only metadata for finding lifecycle changes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str
    actor: str | None = None
    reason: str | None = None
    previous_verification: VerificationStatus | None = None
    new_verification: VerificationStatus | None = None
    previous_status: FindingStatus | None = None
    new_status: FindingStatus | None = None
    timestamp: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.HIGH
    target: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    evidence: MinimalEvidence | None = None
    remediation: str | None = None
    # A finding always carries an explicit verification state.  ``not_verified``
    # is the compatibility-safe default for legacy checks that only report an
    # observed response condition.
    verification: VerificationStatus = VerificationStatus.NOT_VERIFIED
    audit_trail: list[FindingAuditEntry] = Field(default_factory=list)
    module: str | None = None
    test_id: str | None = None
    test_version: str | None = None
    reference: str | None = None
    references: list[str] = Field(default_factory=list)
    owasp_category: str | None = None
    owasp_id: str | None = None
    timestamp: datetime | None = None


class Check(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: CheckType
    status: CheckStatus = CheckStatus.PENDING
    findings: list[Finding] = Field(default_factory=list)
    evidence: MinimalEvidence | None = None
    observation: dict[str, str | bool] | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


class ScanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    checks_total: int = Field(default=0, ge=0)
    checks_completed: int = Field(default=0, ge=0)
    findings_total: int = Field(default=0, ge=0)
    findings_by_severity: dict[FindingSeverity, int] = Field(default_factory=dict)


class WebsiteObservation(BaseModel):
    """A small, safe fact collected while describing a website.

    Values are deliberately limited to JSON-shaped metadata.  The intelligence
    engine never puts response bodies, cookies, credentials, or complete header
    maps in this model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    value: WebsiteValue | None = None
    mode: ObservationMode
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    status: ObservationStatus
    evidence: MinimalEvidence | None = None
    module: str | None = None
    test_id: str | None = None
    test_version: str | None = None
    reference: str | None = None
    references: list[str] = Field(default_factory=list)
    owasp_category: str | None = None
    owasp_id: str | None = None
    timestamp: datetime | None = None


class WebsiteResource(BaseModel):
    """A discovered URL and the bounded action taken for it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    kind: str
    depth: int = Field(ge=0)
    mode: ObservationMode = ObservationMode.OBSERVED
    confidence: FindingConfidence = FindingConfidence.HIGH
    status: ObservationStatus
    method: str | None = None
    fields: list[str] = Field(default_factory=list)
    source_url: str | None = None
    evidence: MinimalEvidence | None = None


class WebsiteSummary(BaseModel):
    """Bounded counts for an optional website-intelligence profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pages_scanned: int = Field(default=0, ge=0)
    resources_discovered: int = Field(default=0, ge=0)
    resources_scanned: int = Field(default=0, ge=0)
    cross_origin_blocked: int = Field(default=0, ge=0)
    observations_total: int = Field(default=0, ge=0)
    partial: bool = False


class WebsiteProfile(BaseModel):
    """Optional, non-destructive website-intelligence result for one scan."""

    model_config = ConfigDict(extra="forbid")

    initial_url: str
    final_url: str | None = None
    mode: ObservationMode = ObservationMode.OBSERVED
    confidence: FindingConfidence = FindingConfidence.MEDIUM
    status: ObservationStatus = ObservationStatus.OBSERVED
    observations: list[WebsiteObservation] = Field(default_factory=list)
    resources: list[WebsiteResource] = Field(default_factory=list)
    summary: WebsiteSummary = Field(default_factory=WebsiteSummary)
    error: str | None = None


class AssessmentCoverage(BaseModel):
    """Bounded accounting of what the assessment attempted and could report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_modules: int = Field(default=0, ge=0)
    applicable_tests: int = Field(default=0, ge=0)
    completed_modules: int = Field(default=0, ge=0)
    passed_tests: int = Field(default=0, ge=0)
    skipped_modules: int = Field(default=0, ge=0)
    skipped_tests: int = Field(default=0, ge=0)
    not_run_tests: int = Field(default=0, ge=0)
    unavailable_modules: int = Field(default=0, ge=0)
    error_modules: int = Field(default=0, ge=0)
    execution_failures: int = Field(default=0, ge=0)
    confirmed_findings: int = Field(default=0, ge=0)
    potential_findings: int = Field(default=0, ge=0)
    informational_observations: int = Field(default=0, ge=0)
    findings_total: int = Field(default=0, ge=0)
    observations_total: int = Field(default=0, ge=0)
    partial: bool = False

    @property
    def modules_total(self) -> int:
        return self.total_modules

    @property
    def modules_completed(self) -> int:
        return self.completed_modules


class AssessmentModuleResult(BaseModel):
    """Result of one immutable, policy-bound passive assessment module."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    module: str
    test_id: str | None = None
    test_version: str | None = None
    status: AssessmentStatus
    progress: int | None = Field(default=None, ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    observations: list[WebsiteObservation] = Field(default_factory=list)
    reference: str | None = None
    references: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=_now)
    error: str | None = None
    skip_reason: str | None = None
    impact: str | None = None
    execution_mode: str | None = None


class AssessmentResult(BaseModel):
    """Assessment output kept separate from the legacy check summary."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    status: AssessmentStatus = AssessmentStatus.COMPLETED
    profile_id: str = "sentinel-v0.3-passive"
    profile_version: str = "0.3.0"
    enabled_modules: list[str] = Field(default_factory=list)
    progress: int | None = Field(default=None, ge=0, le=100)
    modules: list[AssessmentModuleResult] = Field(default_factory=list)
    coverage: AssessmentCoverage = Field(default_factory=AssessmentCoverage)
    findings: list[Finding] = Field(default_factory=list)
    observations: list[WebsiteObservation] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=_now)
    error: str | None = None

    @property
    def results(self) -> list[AssessmentModuleResult]:
        return self.modules


class Scan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    target_url: str
    engagement_id: UUID | None = None
    assessment_profile: str | None = None
    active_testing_authorized: bool | None = None
    status: ScanStatus = ScanStatus.QUEUED
    checks: list[Check] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    intelligence: WebsiteProfile | None = None
    assessment: AssessmentResult | None = None
    coverage: AssessmentCoverage | None = None
    created_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None

    @property
    def findings(self) -> list[Finding]:
        """Return findings in check order for API serialization."""

        entries = [
            (finding, check.name.value)
            for check in self.checks
            for finding in check.findings
        ]
        return deduplicate_findings(
            [finding for finding, _ in entries],
            sources=[source for _, source in entries],
        )

    @property
    def assessment_coverage(self) -> AssessmentCoverage | None:
        return self.coverage


class HTTPS_TransportObservation(BaseModel):
    """What the client can safely say about the requested transport.

    TLS version, cipher, certificate details, and verification outcome are
    intentionally absent: the scan core does not infer them from an HTTPS URL.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: str
    https: bool
    tls_details_available: bool = False
    message: str


# A source-compatible, conventional name without exposing TLS claims.
TransportObservation = HTTPS_TransportObservation

# Short aliases keep the public scan-core vocabulary approachable while the
# explicit names above remain useful in serialized schemas.
Evidence = MinimalEvidence
Summary = ScanSummary
CheckKind = CheckType
Severity = FindingSeverity
Confidence = FindingConfidence
ScanLifecycleStatus = ScanStatus
CheckLifecycleStatus = CheckStatus
FindingLifecycleStatus = FindingStatus
ScanState = ScanStatus
CheckState = CheckStatus
FindingState = FindingStatus
Verification = VerificationStatus
WebsiteProfileModel = WebsiteProfile
WebsiteObservationModel = WebsiteObservation


_VERIFICATION_PRIORITY: dict[VerificationStatus, int] = {
    VerificationStatus.NOT_APPLICABLE: 0,
    VerificationStatus.INFORMATIONAL: 1,
    VerificationStatus.NOT_VERIFIED: 1,
    VerificationStatus.UNVERIFIED: 1,
    VerificationStatus.OBSERVED: 1,
    VerificationStatus.INFERRED: 1,
    VerificationStatus.POTENTIAL: 2,
    VerificationStatus.CONFIRMED: 3,
}


def finding_dedup_key(
    finding: Finding,
    *,
    source: str | None = None,
) -> tuple[str, str | None, str | None, str | None, str, str, str, str]:
    """Return a stable identity that preserves distinct check results.

    A code and target are not enough to identify a finding: separate checks or
    materially different evidence can legitimately reuse a code. The optional
    ``source`` supplies a legacy check name that is not stored on ``Finding``.
    """

    return (
        finding.code,
        finding.target,
        source or finding.module,
        finding.test_id,
        finding.title,
        finding.description,
        finding.severity.value,
        finding.remediation or "",
    )


def deduplicate_findings(
    findings: list[Finding],
    *,
    sources: list[str | None] | None = None,
) -> list[Finding]:
    """Deduplicate findings in first-seen order, preferring stronger evidence.

    The returned order is stable for a stable input order.  If duplicate
    modules disagree about verification, the stronger state replaces the
    earlier value at that same position; equal-strength ties keep the first
    finding and its safe evidence.
    """

    if sources is not None and len(sources) != len(findings):
        raise ValueError("finding sources must align with findings")
    unique: list[Finding] = []
    positions: dict[tuple[str, str | None, str | None, str | None, str, str, str, str], int] = {}
    for index, finding in enumerate(findings):
        source = None if sources is None else sources[index]
        key = finding_dedup_key(finding, source=source)
        position = positions.get(key)
        if position is None:
            positions[key] = len(unique)
            unique.append(finding)
            continue
        current = unique[position]
        current_priority = _VERIFICATION_PRIORITY.get(current.verification, 0)
        new_priority = _VERIFICATION_PRIORITY.get(finding.verification, 0)
        if new_priority > current_priority:
            unique[position] = finding
    return unique


def new_check(name: CheckType) -> Check:
    """Create a check in its initial lifecycle state."""

    return Check(name=name)


def utc_now() -> datetime:
    """Return an aware UTC timestamp for lifecycle transitions."""

    return _now()
