"""Application-owned contracts for bounded external security tools.

The adapter boundary intentionally contains no tool-specific payloads.  Tool
implementations return these small, JSON-serializable models so reports can
distinguish an unavailable tool from an empty result and from a partial run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, TypeAlias
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.engagement.policy import EngagementScopePolicy
from app.security.url_validation import NormalizedURL


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ToolCapability(str, Enum):
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"


class ToolAvailabilityStatus(str, Enum):
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class SanitizedDiagnostic(BaseModel):
    """Bounded diagnostics that never echo tool responses or credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    phase: str
    retryable: bool = False

    @field_validator("code", "message", "phase")
    @classmethod
    def bounded_diagnostic_text(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 256:
            raise ValueError("diagnostic text must be non-empty and at most 256 characters")
        return value


class ExecutionState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"


class ToolIdentity(BaseModel):
    """Stable adapter identity and observed tool/API versions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    vendor: str
    adapter_version: str
    tool_version: str | None = None
    api_version: str | None = None

    @field_validator("name", "vendor", "adapter_version", "tool_version", "api_version")
    @classmethod
    def bounded_identity_text(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or len(value) > 128):
            raise ValueError("tool identity values must be non-empty and at most 128 characters")
        return None if value is None else value.strip()


class ScopeRequirement(BaseModel):
    """What an adapter must have before it can cause tool-side network work."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requires_engagement: bool = True
    required_capabilities: tuple[str, ...] = ()
    active_testing: bool = False


class ToolAvailability(BaseModel):
    """A safe, serializable availability/version probe result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ToolAvailabilityStatus
    identity: ToolIdentity
    capabilities: tuple[ToolCapability, ...] = ()
    diagnostics: tuple["SanitizedDiagnostic", ...] = ()
    checked_at: datetime = Field(default_factory=_now)


class FindingProvenance(BaseModel):
    """Where a normalized finding came from, without retaining raw alerts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter: str
    tool: str
    tool_version: str | None = None
    api_version: str | None = None
    source_alert_id: str | None = None
    observed_at: datetime = Field(default_factory=_now)


class NormalizedFinding(BaseModel):
    """Tool-independent finding representation used by reports and APIs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    target: str
    remediation: str | None = None
    references: tuple[str, ...] = ()
    provenance: FindingProvenance

    @computed_field
    @property
    def rule(self) -> str:
        """Compatibility-friendly serialized name for report consumers."""

        return self.rule_id


class NormalizedObservation(BaseModel):
    """Tool-independent, non-vulnerability observation.

    Discovery and protocol inventory belongs here rather than in findings.  In
    particular, an open port or a successful TLS check is not by itself a
    vulnerability claim.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str
    kind: str
    key: str
    value: str
    target: str
    provenance: FindingProvenance


class AdapterExecutionRequest:
    """Execution controls supplied by the application, not by a tool."""

    __slots__ = (
        "target_url",
        "scope",
        "timeout_seconds",
        "max_output_bytes",
        "max_findings",
        "cancel_event",
        "active_scan",
        "active_testing_authorized",
        "infrastructure_authorized",
        "mode",
        "ports",
        "output_format",
    )

    def __init__(
        self,
        target_url: str,
        *,
        scope: "AdapterScope",
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 1_000_000,
        max_findings: int = 100,
        cancel_event: asyncio.Event | None = None,
        active_scan: bool = False,
        active_testing_authorized: bool = False,
        infrastructure_authorized: bool = False,
        mode: str = "discovery",
        ports: tuple[int, ...] | list[int] | None = None,
        output_format: str | None = None,
    ) -> None:
        if not isinstance(target_url, str) or not target_url.strip():
            raise ValueError("target_url must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if max_output_bytes < 0:
            raise ValueError("max_output_bytes must not be negative")
        if max_findings < 0:
            raise ValueError("max_findings must not be negative")
        normalized_mode = mode.strip().casefold() if isinstance(mode, str) else ""
        if not normalized_mode or len(normalized_mode) > 64:
            raise ValueError("mode must be a non-empty bounded string")
        normalized_ports = tuple(ports or ())
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in normalized_ports):
            raise ValueError("ports must contain valid TCP ports")
        normalized_format = output_format.strip().casefold() if isinstance(output_format, str) else ""
        if len(normalized_format) > 16:
            raise ValueError("output_format must be a bounded string")
        self.target_url = target_url
        self.scope = scope
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.max_findings = max_findings
        self.cancel_event = cancel_event
        self.active_scan = active_scan
        self.active_testing_authorized = active_testing_authorized
        self.infrastructure_authorized = infrastructure_authorized
        self.mode = normalized_mode
        self.ports = normalized_ports
        self.output_format = normalized_format


@dataclass(frozen=True, slots=True)
class AdapterScope:
    """Runtime scope handle backed by the existing engagement policy."""

    engagement_id: UUID | None
    engagement_policy: EngagementScopePolicy | None
    infrastructure_authorized: bool = False

    def validate_target(self, target_url: str) -> NormalizedURL:
        if self.engagement_policy is None:
            raise ValueError("an active engagement is required for external-tool execution")
        return self.engagement_policy.validate_url(target_url)

    def validate_capability(self, capability: str) -> None:
        if self.engagement_policy is None:
            raise ValueError("an active engagement is required for external-tool execution")
        # Active external-tool operations require an explicit allow-list entry;
        # the engagement policy's empty-list convention (unrestricted for
        # passive profiles) must not silently authorize active testing.
        if capability not in self.engagement_policy.engagement.allowed_capabilities:
            raise ValueError(f"capability {capability!r} is not explicitly allowed")
        self.engagement_policy.validate_capability(capability)


class AdapterExecutionResult(BaseModel):
    """Terminal state and bounded results from one adapter execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: ExecutionState
    tool: ToolIdentity
    observations: tuple[NormalizedObservation, ...] = ()
    findings: tuple[NormalizedFinding, ...] = ()
    diagnostics: tuple[SanitizedDiagnostic, ...] = ()
    partial: bool = False
    requests_made: int = Field(default=0, ge=0)
    started_at: datetime = Field(default_factory=_now)
    completed_at: datetime = Field(default_factory=_now)


class ExternalToolAdapter(Protocol):
    """Typed contract implemented by each application-approved tool adapter."""

    identity: ToolIdentity
    scope_requirements: ScopeRequirement

    async def check_availability(self, *, timeout_seconds: float = 5.0) -> ToolAvailability:
        ...

    async def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        ...

    async def run(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        ...


ToolResponseBody: TypeAlias = bytes | str | dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolHTTPResponse:
    """Minimal response shape shared by real and fake tool transports."""

    status_code: int
    body: ToolResponseBody
    headers: dict[str, str] | None = None


class ExternalToolTransport(Protocol):
    async def request(
        self,
        path: str,
        params: dict[str, str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ToolHTTPResponse:
        ...


__all__ = [
    "AdapterExecutionRequest",
    "AdapterExecutionResult",
    "AdapterScope",
    "ExternalToolAdapter",
    "ExternalToolTransport",
    "ExecutionState",
    "FindingProvenance",
    "NormalizedFinding",
    "NormalizedObservation",
    "SanitizedDiagnostic",
    "ScopeRequirement",
    "ToolAvailability",
    "ToolAvailabilityStatus",
    "ToolCapability",
    "ToolHTTPResponse",
    "ToolIdentity",
]

# Descriptive aliases keep the public contract discoverable for API/report
# callers that use the longer external-tool vocabulary.
ExternalToolIdentity = ToolIdentity
ExternalToolAvailability = ToolAvailability
ExternalToolFinding = NormalizedFinding
ExternalToolExecutionState = ExecutionState
