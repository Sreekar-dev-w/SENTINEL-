"""OWASP ZAP HTTP API adapter with passive-by-default execution.

Only documented ZAP API endpoints are used.  The adapter never launches a ZAP
process and cannot execute a target request without an active engagement scope.
The transport is injected so unit and integration tests do not need a running
scanner; :class:`ZAPHTTPTransport` is the real-service implementation.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

from app.external_tools.contracts import (
    AdapterExecutionRequest,
    AdapterExecutionResult,
    ExternalToolTransport,
    ExecutionState,
    FindingProvenance,
    NormalizedFinding,
    SanitizedDiagnostic,
    ScopeRequirement,
    ToolAvailability,
    ToolAvailabilityStatus,
    ToolCapability,
    ToolHTTPResponse,
    ToolIdentity,
)


ZAP_ACTIVE_SCAN_CAPABILITY = "zap.active_scan"
ZAP_ADAPTER_NAME = "owasp-zap"
ZAP_ADAPTER_VERSION = "1.0"


class ZAPTransportError(RuntimeError):
    """Transport failures are deliberately not exposed in diagnostics."""


class ZAPTransportTimeout(ZAPTransportError):
    """The real HTTP client hit its per-request timeout."""


class ZAPTransportOutputLimit(ZAPTransportError):
    """The real HTTP client received more bytes than the adapter allows."""


class ZAPHTTPTransport:
    """Real HTTP transport for an already-running, locally configured ZAP API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        *,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("ZAP base_url must be an HTTP(S) URL")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = client or httpx.AsyncClient(trust_env=False, follow_redirects=False)
        self._owns_client = client is None

    async def request(
        self,
        path: str,
        params: dict[str, str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ToolHTTPResponse:
        query = dict(params)
        if self.api_key:
            query["apikey"] = self.api_key
        try:
            response = await self._client.get(
                f"{self.base_url}/{path.lstrip('/')}",
                params=query,
                timeout=timeout_seconds,
            )
            body = await response.aread()
        except (httpx.TimeoutException, TimeoutError) as exc:
            raise ZAPTransportTimeout(type(exc).__name__) from exc
        except httpx.HTTPError as exc:
            raise ZAPTransportError(type(exc).__name__) from exc
        if len(body) > max_output_bytes:
            raise ZAPTransportOutputLimit("response output exceeded configured limit")
        return ToolHTTPResponse(
            status_code=response.status_code,
            body=body,
            headers=dict(response.headers),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class _ZAPTimeout(Exception):
    pass


class _ZAPCancelled(Exception):
    pass


class _ZAPOutputLimit(Exception):
    pass


class _ZAPAPIError(Exception):
    pass


class _ZAPVersionError(Exception):
    pass


class ZAPAdapter:
    """Run ZAP passive scanning through the application adapter contract."""

    scope_requirements = ScopeRequirement(requires_engagement=True)

    def __init__(
        self,
        transport: ExternalToolTransport,
        *,
        adapter_version: str = ZAP_ADAPTER_VERSION,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if poll_interval_seconds < 0:
            raise ValueError("poll_interval_seconds must not be negative")
        self.transport = transport
        self.identity = ToolIdentity(
            name=ZAP_ADAPTER_NAME,
            vendor="OWASP",
            adapter_version=adapter_version,
        )
        self.poll_interval_seconds = poll_interval_seconds
        self._requests_made = 0
        self._active_scan_id: str | None = None

    async def check_availability(self, *, timeout_seconds: float = 5.0) -> ToolAvailability:
        diagnostics: list[SanitizedDiagnostic] = []
        try:
            response = await self._request(
                "JSON/core/view/version/",
                {},
                deadline=asyncio.get_running_loop().time() + timeout_seconds,
                max_output_bytes=64_000,
                cancel_event=None,
            )
            payload = self._json(response)
            version = self._version(payload)
        except _ZAPTimeout:
            diagnostics.append(self._diagnostic("timeout", "availability", True))
            return ToolAvailability(
                status=ToolAvailabilityStatus.UNAVAILABLE,
                identity=self.identity,
                capabilities=(ToolCapability.PASSIVE_SCAN, ToolCapability.ACTIVE_SCAN),
                diagnostics=tuple(diagnostics),
            )
        except (ZAPTransportError, ConnectionError):
            diagnostics.append(self._diagnostic("service_unavailable", "availability", True))
            return ToolAvailability(
                status=ToolAvailabilityStatus.UNAVAILABLE,
                identity=self.identity,
                capabilities=(ToolCapability.PASSIVE_SCAN, ToolCapability.ACTIVE_SCAN),
                diagnostics=tuple(diagnostics),
            )
        except (_ZAPAPIError, _ZAPVersionError, ValueError, TypeError):
            diagnostics.append(self._diagnostic("version_failure", "availability", False))
            return ToolAvailability(
                status=ToolAvailabilityStatus.ERROR,
                identity=self.identity,
                capabilities=(),
                diagnostics=tuple(diagnostics),
            )
        identity = self.identity.model_copy(update={"tool_version": version, "api_version": "json"})
        return ToolAvailability(
            status=ToolAvailabilityStatus.AVAILABLE,
            identity=identity,
            capabilities=(ToolCapability.PASSIVE_SCAN, ToolCapability.ACTIVE_SCAN),
        )

    async def execute(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        started = datetime.now(timezone.utc)
        self._requests_made = 0
        self._active_scan_id = None
        findings: list[NormalizedFinding] = []
        diagnostics: list[SanitizedDiagnostic] = []
        partial = False
        try:
            target = request.scope.validate_target(request.target_url)
        except Exception:
            return self._result(
                ExecutionState.REJECTED,
                diagnostics=[self._diagnostic("out_of_scope", "scope", False)],
                started=started,
            )
        if request.active_scan:
            if not request.active_testing_authorized:
                return self._result(
                    ExecutionState.REJECTED,
                    diagnostics=[self._diagnostic("active_testing_not_authorized", "scope", False)],
                    started=started,
                )
            try:
                request.scope.validate_capability(ZAP_ACTIVE_SCAN_CAPABILITY)
            except Exception:
                return self._result(
                    ExecutionState.REJECTED,
                    diagnostics=[self._diagnostic("active_capability_not_allowed", "scope", False)],
                    started=started,
                )

        deadline = asyncio.get_running_loop().time() + request.timeout_seconds
        tool_identity = self.identity
        try:
            try:
                version_response = await self._request(
                    "JSON/core/view/version/",
                    {},
                    deadline=deadline,
                    max_output_bytes=request.max_output_bytes,
                    cancel_event=request.cancel_event,
                )
            except _ZAPAPIError as exc:
                raise _ZAPVersionError() from exc
            try:
                version_payload = self._json(version_response)
                tool_version = self._version(version_payload)
            except (_ZAPAPIError, _ZAPVersionError) as exc:
                raise _ZAPVersionError() from exc
            tool_identity = self.identity.model_copy(
                update={"tool_version": tool_version, "api_version": "json"}
            )
            if request.active_scan:
                await self._active_scan(target.url, request, deadline)
                await self._wait_for_active_scan(request, deadline)
            else:
                await self._passive_access(target.url, request, deadline)
                await self._wait_for_passive_scan(request, deadline)
            alerts_response = await self._request(
                "JSON/core/view/alerts/",
                {"baseurl": target.origin, "start": "0", "count": str(request.max_findings)},
                deadline=deadline,
                max_output_bytes=request.max_output_bytes,
                cancel_event=request.cancel_event,
            )
            alerts = self._alerts(self._json(alerts_response))
            for index, alert in enumerate(alerts):
                try:
                    finding = self._normalize_alert(
                        alert,
                        request=request,
                        target_origin=target.origin,
                        tool_identity=tool_identity,
                    )
                except _ZAPAPIError as exc:
                    code = str(exc)
                    diagnostics.append(self._diagnostic(code, "alerts", False))
                    partial = True
                    continue
                if finding is not None:
                    findings.append(finding)
                if len(findings) >= request.max_findings:
                    if len(alerts) > request.max_findings:
                        diagnostics.append(self._diagnostic("output_truncated", "alerts", False))
                        partial = True
                    break
        except _ZAPCancelled:
            if request.active_scan and self._active_scan_id is not None:
                await self._stop_active_scan(request, deadline)
            diagnostics.append(self._diagnostic("cancelled", "execution", False))
            return self._result(
                ExecutionState.CANCELLED,
                findings=findings,
                diagnostics=diagnostics,
                partial=bool(findings),
                started=started,
                identity=tool_identity,
            )
        except _ZAPTimeout:
            diagnostics.append(self._diagnostic("timeout", "execution", True))
            return self._result(
                ExecutionState.PARTIAL if findings else ExecutionState.FAILED,
                findings=findings,
                diagnostics=diagnostics,
                partial=bool(findings),
                started=started,
                identity=tool_identity,
            )
        except _ZAPOutputLimit:
            diagnostics.append(self._diagnostic("output_limit", "execution", False))
            return self._result(
                ExecutionState.PARTIAL if findings else ExecutionState.FAILED,
                findings=findings,
                diagnostics=diagnostics,
                partial=True,
                started=started,
                identity=tool_identity,
            )
        except ZAPTransportTimeout:
            diagnostics.append(self._diagnostic("timeout", "execution", True))
            return self._result(
                ExecutionState.PARTIAL if findings else ExecutionState.FAILED,
                findings=findings,
                diagnostics=diagnostics,
                partial=bool(findings),
                started=started,
                identity=tool_identity,
            )
        except ZAPTransportOutputLimit:
            diagnostics.append(self._diagnostic("output_limit", "execution", False))
            return self._result(
                ExecutionState.PARTIAL if findings else ExecutionState.FAILED,
                findings=findings,
                diagnostics=diagnostics,
                partial=True,
                started=started,
                identity=tool_identity,
            )
        except (ZAPTransportError, ConnectionError):
            diagnostics.append(
                self._diagnostic(
                    "service_unavailable" if not findings else "api_failure",
                    "execution",
                    True,
                )
            )
            return self._result(
                ExecutionState.UNAVAILABLE if not findings else ExecutionState.PARTIAL,
                findings=findings,
                diagnostics=diagnostics,
                partial=bool(findings),
                started=started,
                identity=tool_identity,
            )
        except _ZAPVersionError:
            diagnostics.append(self._diagnostic("version_failure", "version", False))
            return self._result(
                ExecutionState.FAILED,
                diagnostics=diagnostics,
                started=started,
                identity=tool_identity,
            )
        except _ZAPAPIError:
            diagnostics.append(self._diagnostic("api_failure", "execution", False))
            return self._result(
                ExecutionState.PARTIAL if findings else ExecutionState.FAILED,
                findings=findings,
                diagnostics=diagnostics,
                partial=bool(findings),
                started=started,
                identity=tool_identity,
            )
        state = ExecutionState.PARTIAL if partial else ExecutionState.COMPLETED
        return self._result(
            state,
            findings=findings,
            diagnostics=diagnostics,
            partial=partial,
            started=started,
            identity=tool_identity,
        )

    async def run(self, request: AdapterExecutionRequest) -> AdapterExecutionResult:
        """Contract-friendly alias for callers that use ``run`` terminology."""

        return await self.execute(request)

    availability = check_availability

    async def _passive_access(self, target_url: str, request: AdapterExecutionRequest, deadline: float) -> None:
        response = await self._request(
            "JSON/core/action/accessUrl/",
            {"url": target_url, "followRedirects": "false"},
            deadline=deadline,
            max_output_bytes=request.max_output_bytes,
            cancel_event=request.cancel_event,
        )
        payload = self._json(response)
        if not isinstance(payload, Mapping):
            raise _ZAPAPIError("access_failure")

    async def _wait_for_passive_scan(self, request: AdapterExecutionRequest, deadline: float) -> None:
        for _ in range(10_000):
            response = await self._request(
                "JSON/pscan/view/recordsToScan/",
                {},
                deadline=deadline,
                max_output_bytes=request.max_output_bytes,
                cancel_event=request.cancel_event,
            )
            payload = self._json(response)
            value = payload.get("recordsToScan") if isinstance(payload, Mapping) else None
            try:
                remaining = int(value)
            except (TypeError, ValueError) as exc:
                raise _ZAPAPIError("api_failure") from exc
            if remaining <= 0:
                return
            await self._sleep_or_cancel(request.cancel_event, deadline)
        raise _ZAPTimeout()

    async def _active_scan(self, target_url: str, request: AdapterExecutionRequest, deadline: float) -> None:
        response = await self._request(
            "JSON/ascan/action/scan/",
            {"url": target_url, "recurse": "false", "inScopeOnly": "true"},
            deadline=deadline,
            max_output_bytes=request.max_output_bytes,
            cancel_event=request.cancel_event,
        )
        payload = self._json(response)
        if not isinstance(payload, Mapping) or not str(payload.get("scanId", "")).strip():
            raise _ZAPAPIError("api_failure")
        self._active_scan_id = str(payload["scanId"])

    async def _stop_active_scan(self, request: AdapterExecutionRequest, deadline: float) -> None:
        """Best-effort bounded cleanup when an opted-in active scan is cancelled."""

        try:
            await self._request(
                "JSON/ascan/action/stop/",
                {"scanId": self._active_scan_id or ""},
                deadline=min(
                    deadline,
                    asyncio.get_running_loop().time() + min(1.0, request.timeout_seconds),
                ),
                max_output_bytes=request.max_output_bytes,
                cancel_event=None,
            )
        except Exception:
            # Cancellation remains authoritative even if the remote cleanup API
            # is unavailable; the diagnostic must not include tool payloads.
            return

    async def _wait_for_active_scan(self, request: AdapterExecutionRequest, deadline: float) -> None:
        for _ in range(10_000):
            response = await self._request(
                "JSON/ascan/view/status/",
                {"scanId": self._active_scan_id},
                deadline=deadline,
                max_output_bytes=request.max_output_bytes,
                cancel_event=request.cancel_event,
            )
            payload = self._json(response)
            value = payload.get("status") if isinstance(payload, Mapping) else None
            try:
                if int(value) >= 100:
                    return
            except (TypeError, ValueError) as exc:
                raise _ZAPAPIError("api_failure") from exc
            await self._sleep_or_cancel(request.cancel_event, deadline)
        raise _ZAPTimeout()

    async def _sleep_or_cancel(self, cancel_event: asyncio.Event | None, deadline: float) -> None:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise _ZAPTimeout()
        if cancel_event is None:
            await asyncio.sleep(min(self.poll_interval_seconds, remaining))
            return
        if cancel_event.is_set():
            raise _ZAPCancelled()
        try:
            await asyncio.wait_for(cancel_event.wait(), timeout=min(self.poll_interval_seconds, remaining))
        except asyncio.TimeoutError:
            return
        raise _ZAPCancelled()

    async def _request(
        self,
        path: str,
        params: dict[str, str],
        *,
        deadline: float,
        max_output_bytes: int,
        cancel_event: asyncio.Event | None,
    ) -> ToolHTTPResponse:
        if cancel_event is not None and cancel_event.is_set():
            raise _ZAPCancelled()
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise _ZAPTimeout()
        request_task = asyncio.create_task(
            self.transport.request(
                path,
                params,
                timeout_seconds=remaining,
                max_output_bytes=max_output_bytes,
            )
        )
        cancel_task = None if cancel_event is None else asyncio.create_task(cancel_event.wait())
        try:
            tasks = {request_task} | ({cancel_task} if cancel_task is not None else set())
            done, _ = await asyncio.wait(tasks, timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
            if not done:
                request_task.cancel()
                await asyncio.gather(request_task, return_exceptions=True)
                raise _ZAPTimeout()
            if cancel_task is not None and cancel_task in done and cancel_task.result():
                request_task.cancel()
                await asyncio.gather(request_task, return_exceptions=True)
                raise _ZAPCancelled()
            try:
                response = await request_task
            except (ZAPTransportError, ConnectionError):
                raise
            except Exception as exc:
                raise ZAPTransportError(type(exc).__name__) from exc
            if isinstance(response, Mapping):
                response = ToolHTTPResponse(status_code=200, body=dict(response))
            if not isinstance(response, ToolHTTPResponse):
                raise ZAPTransportError("invalid transport response")
            self._requests_made += 1
            if response.status_code < 200 or response.status_code >= 300:
                raise _ZAPAPIError("api_failure")
            if isinstance(response.body, bytes) and len(response.body) > max_output_bytes:
                raise _ZAPOutputLimit()
            if isinstance(response.body, (str, Mapping)):
                try:
                    encoded = json.dumps(response.body, separators=(",", ":")).encode("utf-8")
                except (TypeError, ValueError) as exc:
                    raise _ZAPAPIError("api_failure") from exc
                if len(encoded) > max_output_bytes:
                    raise _ZAPOutputLimit()
            return response
        except asyncio.TimeoutError as exc:
            raise _ZAPTimeout() from exc
        finally:
            if cancel_task is not None:
                cancel_task.cancel()
                await asyncio.gather(cancel_task, return_exceptions=True)

    @staticmethod
    def _json(response: ToolHTTPResponse) -> Mapping[str, Any]:
        body = response.body
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _ZAPAPIError("api_failure") from exc
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError as exc:
                raise _ZAPAPIError("api_failure") from exc
        if not isinstance(body, Mapping):
            raise _ZAPAPIError("api_failure")
        return body

    @staticmethod
    def _version(payload: Mapping[str, Any]) -> str:
        value = payload.get("version")
        if not isinstance(value, str) or not value.strip() or len(value) > 128:
            raise _ZAPVersionError()
        return value.strip()

    @staticmethod
    def _alerts(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        alerts = payload.get("alerts")
        if not isinstance(alerts, list):
            raise _ZAPAPIError("api_failure")
        return [alert for alert in alerts if isinstance(alert, Mapping)] + [
            {} for alert in alerts if not isinstance(alert, Mapping)
        ]

    def _normalize_alert(
        self,
        alert: Mapping[str, Any],
        *,
        request: AdapterExecutionRequest,
        target_origin: str,
        tool_identity: ToolIdentity,
    ) -> NormalizedFinding | None:
        required = ("pluginId", "name", "risk", "confidence", "url")
        if any(key not in alert for key in required):
            raise _ZAPAPIError("malformed_alert")
        try:
            if any(alert[key] is None for key in required):
                raise ValueError
            rule_id = str(alert["pluginId"]).strip()
            title = str(alert["name"]).strip()
            alert_url = str(alert["url"]).strip()
            if not rule_id or not title or not alert_url:
                raise ValueError
            try:
                normalized_alert = request.scope.validate_target(alert_url)
            except Exception as exc:
                raise _ZAPAPIError("out_of_scope") from exc
            # Core alerts are requested by origin; retain only alerts from the
            # authorized target origin to avoid cross-origin session leakage.
            if normalized_alert.origin != target_origin:
                raise _ZAPAPIError("out_of_scope")
            severity = self._severity(alert["risk"])
            confidence = self._confidence(alert["confidence"])
        except _ZAPAPIError:
            raise
        except Exception as exc:
            raise _ZAPAPIError("malformed_alert") from exc
        return NormalizedFinding(
            source=ZAP_ADAPTER_NAME,
            rule_id=rule_id,
            title=title[:256],
            description=str(alert.get("description", "")).strip()[:2_000],
            severity=severity,
            confidence=confidence,
            target=normalized_alert.url,
            remediation=str(alert.get("solution", "")).strip()[:2_000] or None,
            references=self._references(alert.get("reference")),
            provenance=FindingProvenance(
                adapter=ZAP_ADAPTER_NAME,
                tool="OWASP ZAP",
                tool_version=tool_identity.tool_version,
                api_version=tool_identity.api_version,
                source_alert_id=str(alert.get("id")).strip() if alert.get("id") is not None else None,
            ),
        )

    @staticmethod
    def _severity(value: Any) -> str:
        mapping = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
        normalized = str(value).strip().casefold()
        if normalized in mapping:
            return mapping[normalized]
        if normalized in {"informational", "info", "low", "medium", "high", "critical"}:
            return normalized
        raise ValueError

    @staticmethod
    def _confidence(value: Any) -> str:
        mapping = {"0": "false_positive", "1": "low", "2": "medium", "3": "high"}
        normalized = str(value).strip().casefold()
        if normalized in mapping:
            return mapping[normalized]
        if normalized in {"low", "medium", "high"}:
            return normalized
        raise ValueError

    @staticmethod
    def _references(value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, str):
            return ()
        return tuple(item.strip()[:512] for item in value.splitlines() if item.strip())[:10]

    def _result(
        self,
        state: ExecutionState,
        *,
        findings: list[NormalizedFinding] | None = None,
        diagnostics: list[SanitizedDiagnostic] | None = None,
        partial: bool = False,
        started: datetime,
        identity: ToolIdentity | None = None,
    ) -> AdapterExecutionResult:
        return AdapterExecutionResult(
            state=state,
            tool=identity or self.identity,
            findings=tuple(findings or ()),
            diagnostics=tuple(diagnostics or ()),
            partial=partial,
            requests_made=self._requests_made,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _diagnostic(code: str, phase: str, retryable: bool) -> SanitizedDiagnostic:
        messages = {
            "timeout": "The external tool exceeded the bounded execution deadline.",
            "service_unavailable": "The external tool service is unavailable.",
            "version_failure": "The external tool version/API response could not be verified.",
            "api_failure": "The external tool API returned an unusable response.",
            "malformed_alert": "An external-tool alert was malformed and was omitted.",
            "out_of_scope": "The target or alert is outside the authorized engagement scope.",
            "active_testing_not_authorized": "Active testing requires explicit authorization.",
            "active_capability_not_allowed": "The engagement does not allow active tool testing.",
            "output_limit": "The external tool response exceeded the bounded output limit.",
            "output_truncated": "The external tool returned more findings than the configured limit.",
            "cancelled": "External-tool execution was cancelled.",
        }
        return SanitizedDiagnostic(
            code=code,
            message=messages.get(code, "The external tool operation did not complete."),
            phase=phase,
            retryable=retryable,
        )


__all__ = [
    "ZAP_ACTIVE_SCAN_CAPABILITY",
    "ZAPAdapter",
    "ZAPHTTPTransport",
    "ZAPTransportError",
]
