"""Optional Nmap adapter using XML output and a bounded process runner."""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Sequence

from app.external_tools.contracts import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    AdapterScope,
    ExecutionState,
    FindingProvenance,
    NormalizedObservation,
    SanitizedDiagnostic,
    ScopeRequirement,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolCapability,
    ToolIdentity,
)
from app.external_tools.process import ProcessResult, ProcessRunner, ProcessUnavailable, SubprocessRunner, run_process


NMAP_DISCOVERY_CAPABILITY = "nmap.discovery"
NMAP_SERVICE_CAPABILITY = "nmap.service_detection"
NMAP_ADAPTER_NAME = "nmap"
NMAP_ADAPTER_VERSION = "1.0"
NMAP_MODES = frozenset({"discovery", "host_discovery", "service_detection"})


class NmapAdapter:
    """Run only explicitly selected, engagement-scoped Nmap modes."""

    scope_requirements = ScopeRequirement(
        requires_engagement=True,
        required_capabilities=(NMAP_DISCOVERY_CAPABILITY,),
        active_testing=True,
    )

    def __init__(
        self,
        runner: ProcessRunner | None = None,
        *,
        executable: str = "nmap",
        adapter_version: str = NMAP_ADAPTER_VERSION,
    ) -> None:
        self.runner = runner or SubprocessRunner()
        self.executable = executable
        self.identity = ToolIdentity(name=NMAP_ADAPTER_NAME, vendor="Nmap Project", adapter_version=adapter_version)
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
            identity=self.identity.model_copy(update={"tool_version": version, "api_version": "xml"}),
            capabilities=(ToolCapability.PASSIVE_SCAN, ToolCapability.ACTIVE_SCAN),
        )

    async def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        started = datetime.now(timezone.utc)
        self._requests_made = 0
        observations: list[NormalizedObservation] = []
        diagnostics: list[SanitizedDiagnostic] = []
        try:
            target = request.scope.validate_target(request.target_url)
            self._validate_request(request, target)
        except Exception:
            return self._result(ExecutionState.REJECTED, diagnostics=[self._diagnostic("out_of_scope", "scope", False)], started=started)
        if request.cancel_event is not None and request.cancel_event.is_set():
            return self._result(ExecutionState.CANCELLED, diagnostics=[self._diagnostic("cancelled", "execution", False)], started=started)
        argv = self._arguments(request, target.hostname)
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
        tool_identity = self.identity.model_copy(update={"tool_version": self._xml_version(result.stdout), "api_version": "xml"})
        if result.returncode != 0:
            diagnostics.append(self._diagnostic("nonzero_exit", "execution", False))
        try:
            observations = self._parse(result.stdout, request, target.url, tool_identity)
        except (ET.ParseError, ValueError, TypeError):
            diagnostics.append(self._diagnostic("malformed_output", "parse", False))
            return self._result(ExecutionState.FAILED, diagnostics=diagnostics, started=started, identity=tool_identity)
        if result.returncode != 0:
            return self._result(
                ExecutionState.PARTIAL if observations else ExecutionState.FAILED,
                observations=observations,
                diagnostics=diagnostics,
                partial=True,
                started=started,
                identity=tool_identity,
            )
        return self._result(ExecutionState.COMPLETED, observations=observations, started=started, identity=tool_identity)

    async def run(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        return await self.execute(request)

    availability = check_availability

    def _validate_request(self, request: AdapterExecutionRequest, target) -> None:
        if not (request.infrastructure_authorized or request.scope.infrastructure_authorized):
            raise ValueError("explicit infrastructure authorization is required")
        if not request.active_testing_authorized:
            raise ValueError("Nmap execution requires explicit active-testing authorization")
        request.scope.validate_capability(NMAP_DISCOVERY_CAPABILITY)
        if request.mode not in NMAP_MODES:
            raise ValueError("unsupported Nmap mode")
        if request.mode == "service_detection":
            if not request.active_testing_authorized:
                raise ValueError("service detection requires explicit active authorization")
            request.scope.validate_capability(NMAP_SERVICE_CAPABILITY)
            if not request.ports:
                raise ValueError("service detection requires explicit ports")
        elif request.ports:
            raise ValueError("ports are only accepted for service detection")
        permitted = request.scope.engagement_policy.engagement.permitted_ports if request.scope.engagement_policy else ()
        if any(port not in permitted for port in request.ports):
            raise ValueError("requested port is not permitted")

    def _arguments(self, request: AdapterExecutionRequest, hostname: str) -> tuple[str, ...]:
        if request.mode == "service_detection":
            return (
                self.executable,
                "-n",
                "-Pn",
                "-sV",
                "--version-light",
                "-p",
                ",".join(str(port) for port in request.ports),
                "-oX",
                "-",
                hostname,
            )
        return (self.executable, "-n", "-sn", "-oX", "-", hostname)

    def _parse(self, payload: bytes, request: AdapterExecutionRequest, target: str, identity: ToolIdentity) -> list[NormalizedObservation]:
        root = ET.fromstring(payload)
        if root.tag != "nmaprun":
            raise ValueError("unexpected XML root")
        hosts = root.findall("host")
        if not hosts:
            # A valid discovery can contain no host records; keep it as an
            # empty observation result rather than inventing a vulnerability.
            return []
        observations: list[NormalizedObservation] = []
        host_limit = request.max_findings
        for host in hosts[:host_limit]:
            status = host.find("status")
            if status is not None and status.get("state"):
                observations.append(self._observation("host", "status", status.get("state", ""), target, identity))
            for port in host.findall("./ports/port"):
                number = port.get("portid", "")
                try:
                    port_number = int(number)
                except ValueError:
                    continue
                if request.mode == "service_detection" and port_number not in request.ports:
                    continue
                state = port.find("state")
                value = state.get("state", "unknown") if state is not None else "unknown"
                service = port.find("service")
                service_name = service.get("name", "") if service is not None else ""
                if service_name:
                    value = f"{value}; service={service_name}"
                observations.append(self._observation("port", str(port_number), value, target, identity))
        if not observations:
            # An empty authorized discovery result is valid and remains an
            # observation-free completed run; it still cannot become a finding.
            return []
        return observations[: request.max_findings]

    def _xml_version(self, payload: bytes) -> str | None:
        try:
            root = ET.fromstring(payload)
        except ET.ParseError:
            return None
        return self._bounded(root.get("version"))

    @staticmethod
    def _version(payload: bytes) -> str | None:
        match = re.search(rb"Nmap version\s+([^\s]+)", payload)
        return match.group(1).decode("ascii", "ignore")[:128] if match else None

    def _observation(self, kind: str, key: str, value: str, target: str, identity: ToolIdentity) -> NormalizedObservation:
        return NormalizedObservation(
            source=NMAP_ADAPTER_NAME,
            kind=kind,
            key=key[:128],
            value=value[:512],
            target=target,
            provenance=FindingProvenance(adapter=NMAP_ADAPTER_NAME, tool="Nmap", tool_version=identity.tool_version, api_version="xml"),
        )

    def _result(self, state, *, observations=(), diagnostics=(), partial=False, started, identity=None):
        return AdapterExecutionResult(
            state=state,
            tool=identity or self.identity,
            observations=tuple(observations),
            diagnostics=tuple(diagnostics),
            partial=partial,
            requests_made=self._requests_made,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _bounded(value: str | None) -> str | None:
        value = value.strip() if value else None
        return value[:128] if value else None

    @staticmethod
    def _diagnostic(code: str, phase: str, retryable: bool) -> SanitizedDiagnostic:
        messages = {
            "out_of_scope": "The target, infrastructure authorization, mode, or port is outside the authorized engagement scope.",
            "missing_executable": "The optional Nmap executable is unavailable.",
            "timeout": "The external tool exceeded the bounded execution deadline.",
            "cancelled": "External-tool execution was cancelled and safely terminated.",
            "output_limit": "The external tool exceeded the bounded output limit.",
            "nonzero_exit": "The external tool exited unsuccessfully; parsed output is marked partial.",
            "malformed_output": "The external tool returned malformed Nmap XML.",
            "malformed_version": "The external tool version could not be verified.",
        }
        return SanitizedDiagnostic(code=code, message=messages.get(code, "The external tool operation did not complete."), phase=phase, retryable=retryable)


NmapExternalToolAdapter = NmapAdapter

__all__ = ["NMAP_DISCOVERY_CAPABILITY", "NMAP_SERVICE_CAPABILITY", "NmapAdapter", "NmapExternalToolAdapter"]
