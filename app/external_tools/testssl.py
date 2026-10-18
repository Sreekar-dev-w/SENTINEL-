"""Optional testssl.sh adapter with JSON/CSV machine-output parsing."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from app.external_tools.contracts import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    ExecutionState,
    FindingProvenance,
    NormalizedFinding,
    NormalizedObservation,
    SanitizedDiagnostic,
    ScopeRequirement,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolCapability,
    ToolIdentity,
)
from app.external_tools.process import ProcessRunner, ProcessUnavailable, SubprocessRunner, run_process


TESTSSL_CAPABILITY = "testssl.tls_scan"
TESTSSL_ADAPTER_NAME = "testssl.sh"
TESTSSL_ADAPTER_VERSION = "1.0"
TESTSSL_FORMATS = frozenset({"json", "csv"})
_BAD_SEVERITIES = frozenset({"critical", "high", "medium", "low", "vulnerable", "warning", "warn", "fail", "insecure"})


class TestSSLAdapter:
    """Run testssl.sh only for an explicitly authorized HTTPS target."""

    __test__ = False  # pytest should not treat this production adapter as a test class

    scope_requirements = ScopeRequirement(
        requires_engagement=True,
        required_capabilities=(TESTSSL_CAPABILITY,),
        active_testing=True,
    )

    def __init__(
        self,
        runner: ProcessRunner | None = None,
        *,
        executable: str = "testssl.sh",
        adapter_version: str = TESTSSL_ADAPTER_VERSION,
        output_format: str = "json",
    ) -> None:
        output_format = output_format.strip().casefold()
        if output_format not in TESTSSL_FORMATS:
            raise ValueError("testssl output_format must be json or csv")
        self.runner = runner or SubprocessRunner()
        self.executable = executable
        self.output_format = output_format
        self.identity = ToolIdentity(name=TESTSSL_ADAPTER_NAME, vendor="testssl.sh", adapter_version=adapter_version)
        self._requests_made = 0

    async def check_availability(self, *, timeout_seconds: float = 5.0) -> ToolAvailability:
        diagnostics: list[SanitizedDiagnostic] = []
        try:
            result = await run_process(
                self.runner,
                (self.executable, "--version"),
                timeout_seconds=timeout_seconds,
                max_output_bytes=64_000,
                cancel_event=None,
            )
        except (ProcessUnavailable, FileNotFoundError, OSError):
            diagnostics.append(self._diagnostic("missing_executable", "availability", True))
            return ToolAvailability(status=ToolAvailabilityStatus.UNAVAILABLE, identity=self.identity, diagnostics=tuple(diagnostics))
        if result.timed_out:
            diagnostics.append(self._diagnostic("timeout", "availability", True))
            return ToolAvailability(status=ToolAvailabilityStatus.UNAVAILABLE, identity=self.identity, diagnostics=tuple(diagnostics))
        if result.output_limited or len(result.stdout) + len(result.stderr) > 64_000:
            diagnostics.append(self._diagnostic("output_limit", "availability", False))
            return ToolAvailability(status=ToolAvailabilityStatus.ERROR, identity=self.identity, diagnostics=tuple(diagnostics))
        if result.returncode != 0:
            diagnostics.append(self._diagnostic("nonzero_exit", "availability", True))
            return ToolAvailability(status=ToolAvailabilityStatus.ERROR, identity=self.identity, diagnostics=tuple(diagnostics))
        version = self._version(result.stdout + result.stderr)
        if version is None:
            diagnostics.append(self._diagnostic("malformed_version", "availability", False))
            return ToolAvailability(status=ToolAvailabilityStatus.ERROR, identity=self.identity, diagnostics=tuple(diagnostics))
        return ToolAvailability(
            status=ToolAvailabilityStatus.AVAILABLE,
            identity=self.identity.model_copy(update={"tool_version": version, "api_version": self.output_format}),
            capabilities=(ToolCapability.PASSIVE_SCAN, ToolCapability.ACTIVE_SCAN),
        )

    async def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        started = datetime.now(timezone.utc)
        self._requests_made = 0
        observations: list[NormalizedObservation] = []
        findings: list[NormalizedFinding] = []
        diagnostics: list[SanitizedDiagnostic] = []
        try:
            target = request.scope.validate_target(request.target_url)
            self._validate_request(request, target)
        except Exception:
            return self._result(ExecutionState.REJECTED, diagnostics=[self._diagnostic("out_of_scope", "scope", False)], started=started)
        if request.cancel_event is not None and request.cancel_event.is_set():
            return self._result(ExecutionState.CANCELLED, diagnostics=[self._diagnostic("cancelled", "execution", False)], started=started)
        output_format = request.output_format if request.output_format in TESTSSL_FORMATS else self.output_format
        argv = self._arguments(target.url, output_format)
        try:
            result = await run_process(
                self.runner,
                argv,
                timeout_seconds=request.timeout_seconds,
                max_output_bytes=request.max_output_bytes,
                cancel_event=request.cancel_event,
            )
            self._requests_made = 1
        except (ProcessUnavailable, FileNotFoundError, OSError):
            return self._result(ExecutionState.UNAVAILABLE, diagnostics=[self._diagnostic("missing_executable", "execution", True)], started=started)
        if result.cancelled:
            diagnostics.append(self._diagnostic("cancelled", "execution", False))
            return self._result(ExecutionState.CANCELLED, diagnostics=diagnostics, started=started)
        if result.timed_out:
            diagnostics.append(self._diagnostic("timeout", "execution", True))
            return self._result(ExecutionState.FAILED, diagnostics=diagnostics, started=started)
        if result.output_limited or len(result.stdout) + len(result.stderr) > request.max_output_bytes:
            diagnostics.append(self._diagnostic("output_limit", "execution", False))
            return self._result(ExecutionState.FAILED, diagnostics=diagnostics, partial=True, started=started)
        tool_identity = self.identity.model_copy(update={"tool_version": self._extract_tool_version(result.stdout), "api_version": output_format})
        if result.returncode != 0:
            diagnostics.append(self._diagnostic("nonzero_exit", "execution", False))
        try:
            records = self._parse_records(result.stdout, output_format)
            observations, findings = self._normalize_records(records, request, target.url, tool_identity)
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError, csv.Error):
            diagnostics.append(self._diagnostic("malformed_output", "parse", False))
            return self._result(ExecutionState.FAILED, diagnostics=diagnostics, started=started, identity=tool_identity)
        if result.returncode != 0:
            return self._result(
                ExecutionState.PARTIAL if observations or findings else ExecutionState.FAILED,
                observations=observations,
                findings=findings,
                diagnostics=diagnostics,
                partial=True,
                started=started,
                identity=tool_identity,
            )
        return self._result(ExecutionState.COMPLETED, observations=observations, findings=findings, started=started, identity=tool_identity)

    async def run(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        return await self.execute(request)

    availability = check_availability

    def _validate_request(self, request: AdapterExecutionRequest, target) -> None:
        if target.scheme != "https":
            raise ValueError("testssl requires an HTTPS target")
        if not (request.infrastructure_authorized or request.scope.infrastructure_authorized) or not request.active_testing_authorized:
            raise ValueError("explicit infrastructure and active-testing authorization are required")
        request.scope.validate_capability(TESTSSL_CAPABILITY)
        if request.mode not in {"discovery", "tls", "tls_assessment"}:
            raise ValueError("unsupported testssl mode")
        if request.ports:
            permitted = request.scope.engagement_policy.engagement.permitted_ports if request.scope.engagement_policy else ()
            if any(port not in permitted or port != target.port for port in request.ports):
                raise ValueError("requested TLS port is not permitted")

    def _arguments(self, target: str, output_format: str) -> tuple[str, ...]:
        option = "--jsonfile" if output_format == "json" else "--csvfile"
        return (self.executable, "--quiet", "--color", "0", option, "-", target)

    def _parse_records(self, payload: bytes, output_format: str) -> list[dict[str, Any]]:
        text = payload.decode("utf-8-sig").strip()
        if not text:
            raise ValueError("empty machine output")
        if output_format == "json":
            value = json.loads(text)
            if isinstance(value, list):
                records = value
            elif isinstance(value, dict):
                records = value.get("scanResult", value.get("results", value.get("findings", value)))
                if isinstance(records, dict):
                    records = [records]
            else:
                raise ValueError("unexpected JSON shape")
            if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
                raise ValueError("JSON records must be objects")
            return records
        sample = text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
        if not rows or not rows[0]:
            raise ValueError("CSV records are missing headers")
        return [{str(key).strip().casefold(): value for key, value in row.items() if key is not None} for row in rows]

    def _normalize_records(self, records, request, target, identity):
        observations: list[NormalizedObservation] = []
        findings: list[NormalizedFinding] = []
        for record in records[: request.max_findings]:
            normalized = {str(key).strip().casefold(): value for key, value in record.items()}
            check_id = self._text(normalized, "id", "check", "finding", default="unknown")
            severity = self._text(normalized, "severity", "rating", default="info").casefold()
            finding_text = self._text(normalized, "finding", "result", "description", default="")
            port = self._port(normalized)
            if port is not None and request.ports and port != (urlsplit(target).port or 443):
                # The command was scoped to one target port; reject records for
                # another port rather than turning them into false findings.
                continue
            display_value = f"{severity}: {finding_text}".strip(": ")[:1_024]
            observations.append(
                NormalizedObservation(
                    source=TESTSSL_ADAPTER_NAME,
                    kind="tls_check",
                    key=check_id[:128],
                    value=display_value,
                    target=target,
                    provenance=FindingProvenance(adapter=TESTSSL_ADAPTER_NAME, tool="testssl.sh", tool_version=identity.tool_version, api_version=identity.api_version),
                )
            )
            if severity in _BAD_SEVERITIES:
                findings.append(
                    NormalizedFinding(
                        source=TESTSSL_ADAPTER_NAME,
                        rule_id=check_id[:128],
                        title=self._text(normalized, "title", "finding", "id", default=check_id)[:256],
                        description=finding_text[:2_000],
                        severity={"vulnerable": "high", "fail": "high", "insecure": "high", "warn": "medium", "warning": "medium"}.get(severity, severity),
                        confidence="high" if severity in {"critical", "high", "vulnerable", "fail"} else "medium",
                        target=target,
                        remediation=self._text(normalized, "remediation", "solution", default="")[:2_000] or None,
                        provenance=FindingProvenance(adapter=TESTSSL_ADAPTER_NAME, tool="testssl.sh", tool_version=identity.tool_version, api_version=identity.api_version, source_alert_id=check_id[:128]),
                    )
                )
        return observations[: request.max_findings], findings[: request.max_findings]

    @staticmethod
    def _text(record, *keys, default="") -> str:
        for key in keys:
            value = record.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
        return default

    @staticmethod
    def _port(record) -> int | None:
        value = record.get("port")
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _version(payload: bytes) -> str | None:
        match = re.search(rb"(?:testssl\.sh|testssl)\s*(?:version)?\s*([0-9][^\s,;]*)", payload, re.I)
        return match.group(1).decode("ascii", "ignore")[:128] if match else None

    def _extract_tool_version(self, payload: bytes) -> str | None:
        match = re.search(rb'["\']version["\']\s*:\s*["\']([^"\']+)', payload, re.I)
        if match:
            return match.group(1).decode("utf-8", "ignore")[:128]
        return self._version(payload)

    def _result(self, state, *, observations=(), findings=(), diagnostics=(), partial=False, started, identity=None):
        return AdapterExecutionResult(
            state=state,
            tool=identity or self.identity,
            observations=tuple(observations),
            findings=tuple(findings),
            diagnostics=tuple(diagnostics),
            partial=partial,
            requests_made=self._requests_made,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _diagnostic(code: str, phase: str, retryable: bool) -> SanitizedDiagnostic:
        messages = {
            "out_of_scope": "The HTTPS target, infrastructure authorization, mode, or port is outside the authorized engagement scope.",
            "missing_executable": "The optional testssl.sh executable is unavailable.",
            "timeout": "The external tool exceeded the bounded execution deadline.",
            "cancelled": "External-tool execution was cancelled and safely terminated.",
            "output_limit": "The external tool exceeded the bounded output limit.",
            "nonzero_exit": "The external tool exited unsuccessfully; parsed output is marked partial.",
            "malformed_output": "The external tool returned malformed JSON/CSV machine output.",
            "malformed_version": "The external tool version could not be verified.",
        }
        return SanitizedDiagnostic(code=code, message=messages.get(code, "The external tool operation did not complete."), phase=phase, retryable=retryable)


TestsslAdapter = TestSSLAdapter
TestSSLExternalToolAdapter = TestSSLAdapter

__all__ = ["TESTSSL_CAPABILITY", "TestSSLAdapter", "TestsslAdapter", "TestSSLExternalToolAdapter"]
