"""Small, serializable domain models for the scan core.

These models deliberately describe observations rather than retaining HTTP
payloads.  Evidence is restricted to the response metadata needed to explain
an initial check; cookies, authorization material, and response bodies are not
part of the model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar
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


class CheckType(str, Enum):
    HSTS = "hsts"
    CSP = "content_security_policy"
    X_CONTENT_TYPE_OPTIONS = "x_content_type_options"
    HTTPS_TRANSPORT = "https_transport"


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
            "content-type",
            "location",
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


class Scan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    target_url: str
    status: ScanStatus = ScanStatus.QUEUED
    checks: list[Check] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    created_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None

    @property
    def findings(self) -> list[Finding]:
        """Return findings in check order for API serialization."""

        return [finding for check in self.checks for finding in check.findings]


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


def new_check(name: CheckType) -> Check:
    """Create a check in its initial lifecycle state."""

    return Check(name=name)


def utc_now() -> datetime:
    """Return an aware UTC timestamp for lifecycle transitions."""

    return _now()
