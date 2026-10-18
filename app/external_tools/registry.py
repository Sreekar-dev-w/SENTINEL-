"""Application-owned registry and bounded runner for external adapters.

The registry is deliberately separate from the adapters themselves.  It gives
the API a stable selection vocabulary, lets deployments inject only the tools
they have configured, and makes an omitted selection a strict native-only
scan.  The runner owns the engagement scope, scan budget, deadline, and
cancellation hand-off; adapters never receive raw application state.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from app.external_tools.contracts import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    AdapterScope,
    ExecutionState,
    ExternalToolAdapter,
    SanitizedDiagnostic,
    ScopeRequirement,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolCapability,
    ToolIdentity,
)
from app.scanning.budget import ScanBudget, ScanBudgetError


class ExternalToolSelectionError(ValueError):
    """A requested adapter name is unknown or not authorized for the scan."""


_KNOWN_IDENTITIES: dict[str, ToolIdentity] = {
    "owasp-zap": ToolIdentity(
        name="owasp-zap", vendor="OWASP", adapter_version="unknown"
    ),
    "nmap": ToolIdentity(name="nmap", vendor="Nmap Project", adapter_version="unknown"),
    "testssl.sh": ToolIdentity(
        name="testssl.sh", vendor="testssl.sh", adapter_version="unknown"
    ),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _diagnostic(code: str, phase: str, message: str, retryable: bool = False) -> SanitizedDiagnostic:
    return SanitizedDiagnostic(code=code, phase=phase, message=message, retryable=retryable)


_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(?:authorization|token|secret|password|cookie)\b\s*[:=]\s*[^\s,;]+"
)


def _safe_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()[:limit]
    parsed = urlsplit(text)
    if parsed.query:
        query = "&".join(
            f"{part.split('=', 1)[0]}=[redacted]"
            for part in parsed.query.split("&")
            if part
        )
        text = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))
    return _SENSITIVE_VALUE.sub("[redacted]", text)


def _sanitize_result(result: AdapterExecutionResult) -> AdapterExecutionResult:
    """Enforce the no-raw-output boundary before a result enters Scan state."""

    findings = tuple(
        finding.model_copy(
            update={
                "title": _safe_text(finding.title, 256) or "External-tool finding",
                "description": _safe_text(finding.description, 2_000) or "",
                "target": _safe_text(finding.target, 2_048),
                "remediation": _safe_text(finding.remediation, 2_000),
                "references": tuple(_safe_text(reference, 512) or "" for reference in finding.references),
                "provenance": finding.provenance.model_copy(
                    update={
                        "adapter": _safe_text(finding.provenance.adapter, 128) or "external",
                        "tool": _safe_text(finding.provenance.tool, 128) or "external",
                        "tool_version": _safe_text(finding.provenance.tool_version, 128),
                        "api_version": _safe_text(finding.provenance.api_version, 128),
                        "source_alert_id": _safe_text(finding.provenance.source_alert_id, 128),
                    }
                ),
            }
        )
        for finding in result.findings
    )
    observations = tuple(
        observation.model_copy(
            update={
                "key": _safe_text(observation.key, 128) or "unknown",
                "value": _safe_text(observation.value, 1_024) or "",
                "target": _safe_text(observation.target, 2_048) or "",
                "provenance": observation.provenance.model_copy(
                    update={
                        "adapter": _safe_text(observation.provenance.adapter, 128) or "external",
                        "tool": _safe_text(observation.provenance.tool, 128) or "external",
                        "tool_version": _safe_text(observation.provenance.tool_version, 128),
                        "api_version": _safe_text(observation.provenance.api_version, 128),
                        "source_alert_id": _safe_text(observation.provenance.source_alert_id, 128),
                    }
                ),
            }
        )
        for observation in result.observations
    )
    diagnostics = tuple(
        diagnostic.model_copy(
            update={"message": _safe_text(diagnostic.message, 256) or "External-tool diagnostic."}
        )
        for diagnostic in result.diagnostics
    )
    identity = result.tool.model_copy(
        update={
            "name": _safe_text(result.tool.name, 128) or "external",
            "vendor": _safe_text(result.tool.vendor, 128) or "external",
            "adapter_version": _safe_text(result.tool.adapter_version, 128) or "unknown",
            "tool_version": _safe_text(result.tool.tool_version, 128),
            "api_version": _safe_text(result.tool.api_version, 128),
        }
    )
    return result.model_copy(
        update={
            "tool": identity,
            "findings": findings,
            "observations": observations,
            "diagnostics": diagnostics,
        }
    )


class ExternalToolRegistry:
    """Resolve named, application-approved adapters without auto-running them."""

    def __init__(self, adapters: Mapping[str, ExternalToolAdapter] | None = None) -> None:
        self._adapters: dict[str, ExternalToolAdapter] = {}
        for name, adapter in (adapters or {}).items():
            normalized = self.normalize_name(name)
            if normalized in self._adapters:
                raise ValueError(f"duplicate external adapter name: {normalized}")
            self._adapters[normalized] = adapter

    @staticmethod
    def normalize_name(name: str) -> str:
        if not isinstance(name, str):
            raise ExternalToolSelectionError("external tool names must be strings")
        normalized = name.strip().casefold()
        if not normalized or len(normalized) > 128:
            raise ExternalToolSelectionError("external tool names must be non-empty and bounded")
        return normalized

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(set(_KNOWN_IDENTITIES) | set(self._adapters)))

    def identity(self, name: str) -> ToolIdentity:
        normalized = self.normalize_name(name)
        adapter = self._adapters.get(normalized)
        if adapter is not None:
            return adapter.identity
        return _KNOWN_IDENTITIES.get(
            normalized,
            ToolIdentity(name=normalized, vendor="application-configured", adapter_version="unknown"),
        )

    def adapter(self, name: str) -> ExternalToolAdapter | None:
        return self._adapters.get(self.normalize_name(name))

    def validate_selection(
        self,
        names: tuple[str, ...] | list[str],
        *,
        engagement_policy,
        active_testing_authorized: bool | None,
    ) -> tuple[str, ...]:
        selected: list[str] = []
        for raw_name in names:
            name = self.normalize_name(raw_name)
            if name not in self.names:
                raise ExternalToolSelectionError(f"external tool {name!r} is not configured")
            if name in selected:
                continue
            adapter = self._adapters.get(name)
            requirements = (
                adapter.scope_requirements
                if adapter is not None
                else ScopeRequirement(requires_engagement=True)
            )
            if requirements.requires_engagement and engagement_policy is None:
                raise ExternalToolSelectionError(
                    f"external tool {name!r} requires an active engagement"
                )
            if requirements.active_testing and active_testing_authorized is not True:
                raise ExternalToolSelectionError(
                    f"external tool {name!r} requires explicit active-testing authorization"
                )
            if engagement_policy is not None:
                for capability in requirements.required_capabilities:
                    try:
                        # External-tool capabilities are always explicit.  An
                        # empty engagement allow-list must not authorize them.
                        if capability not in engagement_policy.engagement.allowed_capabilities:
                            raise ValueError
                        engagement_policy.validate_capability(capability)
                    except Exception as exc:
                        raise ExternalToolSelectionError(
                            f"external tool {name!r} is not allowed by the engagement"
                        ) from exc
            selected.append(name)
        return tuple(selected)

    async def availability(self, *, timeout_seconds: float = 5.0) -> tuple[ToolAvailability, ...]:
        """Return safe availability records for configured and known tools."""

        records: list[ToolAvailability] = []
        for name in self.names:
            adapter = self._adapters.get(name)
            if adapter is None:
                records.append(
                    ToolAvailability(
                        status=ToolAvailabilityStatus.UNAVAILABLE,
                        identity=self.identity(name),
                        diagnostics=(
                            _diagnostic(
                                "adapter_not_configured",
                                "availability",
                                "The external tool adapter is not configured.",
                                True,
                            ),
                        ),
                    )
                )
                continue
            try:
                result = await adapter.check_availability(timeout_seconds=timeout_seconds)
                records.append(ToolAvailability.model_validate(result))
            except Exception:
                records.append(
                    ToolAvailability(
                        status=ToolAvailabilityStatus.ERROR,
                        identity=adapter.identity,
                        diagnostics=(
                            _diagnostic(
                                "availability_failure",
                                "availability",
                                "The external tool availability check failed.",
                                True,
                            ),
                        ),
                    )
                )
        return tuple(records)


class ExternalToolRunner:
    """Run selected adapters sequentially under one scan budget."""

    def __init__(self, registry: ExternalToolRegistry) -> None:
        self.registry = registry

    async def run(
        self,
        names: tuple[str, ...],
        *,
        target_url: str,
        scope: AdapterScope | None,
        budget: ScanBudget,
        cancel_event: asyncio.Event | None,
        timeout_seconds: float,
        max_output_bytes: int,
        max_findings: int,
        active_testing_authorized: bool,
        on_result=None,
    ) -> tuple[AdapterExecutionResult, ...]:
        results: list[AdapterExecutionResult] = []
        for name in names:
            if cancel_event is not None and cancel_event.is_set():
                result = self._cancelled(name)
                results.append(result)
                if on_result is not None:
                    await on_result(tuple(results))
                continue
            adapter = self.registry.adapter(name)
            if adapter is None:
                result = AdapterExecutionResult(
                    state=ExecutionState.UNAVAILABLE,
                    tool=self.registry.identity(name),
                    diagnostics=(
                        _diagnostic(
                            "adapter_not_configured",
                            "execution",
                            "The external tool adapter is not configured.",
                            True,
                        ),
                    ),
                )
                results.append(result)
                if on_result is not None:
                    await on_result(tuple(results))
                continue
            try:
                remaining = timeout_seconds
                if budget.deadline is not None:
                    remaining = min(remaining, budget.deadline - asyncio.get_running_loop().time())
                if remaining <= 0:
                    raise ScanBudgetError("scan-wide deadline expired")
                async with budget.attempt():
                    request = AdapterExecutionRequest(
                        target_url,
                        scope=scope,
                        timeout_seconds=remaining,
                        max_output_bytes=max_output_bytes,
                        max_findings=max_findings,
                        cancel_event=cancel_event,
                        active_scan=False,
                        active_testing_authorized=active_testing_authorized,
                    )
                    operation = getattr(adapter, "execute", None) or getattr(adapter, "run")
                    raw_result = await operation(request)
                result = _sanitize_result(AdapterExecutionResult.model_validate(raw_result))
            except asyncio.CancelledError:
                raise
            except ScanBudgetError:
                result = AdapterExecutionResult(
                    state=ExecutionState.FAILED,
                    tool=adapter.identity,
                    diagnostics=(
                        _diagnostic(
                            "scan_budget_exhausted",
                            "execution",
                            "The shared scan budget did not admit external-tool execution.",
                            True,
                        ),
                    ),
                )
            except Exception:
                # Never expose exception strings: adapters may have received
                # credentials or tool payloads before failing.
                result = AdapterExecutionResult(
                    state=ExecutionState.FAILED,
                    tool=adapter.identity,
                    diagnostics=(
                        _diagnostic(
                            "adapter_failure",
                            "execution",
                            "The external tool adapter failed without a usable normalized result.",
                        ),
                    ),
                )
            results.append(result)
            if on_result is not None:
                await on_result(tuple(results))
        return tuple(results)

    def _cancelled(self, name: str) -> AdapterExecutionResult:
        return AdapterExecutionResult(
            state=ExecutionState.CANCELLED,
            tool=self.registry.identity(name),
            diagnostics=(
                _diagnostic(
                    "cancelled",
                    "execution",
                    "External-tool execution was cancelled.",
                ),
            ),
        )


__all__ = [
    "ExternalToolRegistry",
    "ExternalToolRunner",
    "ExternalToolSelectionError",
]
