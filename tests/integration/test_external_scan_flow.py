"""Manager/report integration for explicitly selected external adapters.

All adapter and native HTTP work in this module is injected and deterministic;
no public target or real external scanner is contacted.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from app.engagement import Engagement, EngagementPolicyError, EngagementScopePolicy
from app.external_tools import (
    AdapterExecutionResult,
    AdapterExecutionRequest,
    AdapterScope,
    ExecutionState,
    FindingProvenance,
    NormalizedFinding,
    SanitizedDiagnostic,
    ScopeRequirement,
    ToolHTTPResponse,
    ToolIdentity,
    ZAPAdapter,
)
from app.api.models import CreateScanRequest
from app.config import ScanLimits
from app.reporting import ReportExporter
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.runner import ScanManager


TARGET = "https://authorized.example/"


class SafeResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


def native_factory(limits: ScanLimits):
    return BoundedHTTPClient.for_testing(
        limits=limits,
        resolver=SafeResolver(),
        transport_factory=lambda: httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-type": "text/html"}, request=request)
        ),
    )


async def wait_terminal(manager: ScanManager, scan_id: str):
    for _ in range(100):
        scan = await manager.get_scan(scan_id)
        if scan is not None and scan.status.value in {"completed", "failed", "cancelled"}:
            return scan
        await asyncio.sleep(0)
    raise AssertionError("scan did not reach a terminal state")


async def add_engagement(manager: ScanManager, *, capabilities=()):
    return await manager.engagement_store.create(
        Engagement(
            target_domains=("authorized.example",),
            allowed_capabilities=capabilities,
            authorization_reference="fake-fixture",
        )
    )


class CompletedFixtureAdapter:
    def __init__(self, name: str, *, active: bool = False, capabilities=()):
        self.identity = ToolIdentity(name=name, vendor="fixture", adapter_version="1")
        self.scope_requirements = ScopeRequirement(
            requires_engagement=True,
            required_capabilities=tuple(capabilities),
            active_testing=active,
        )

    async def check_availability(self, *, timeout_seconds=5.0):
        raise AssertionError("availability is not probed during scan execution")

    async def execute(self, request: AdapterExecutionRequest):
        return AdapterExecutionResult(state=ExecutionState.COMPLETED, tool=self.identity)

    async def run(self, request: AdapterExecutionRequest):
        return await self.execute(request)


def test_native_only_request_remains_ordinary_and_has_no_external_results():
    async def exercise():
        manager = ScanManager(
            ScanLimits(maximum_requests_per_scan=2),
            client_factory=native_factory,
            enable_intelligence=False,
        )
        created = await manager.create_scan(
            CreateScanRequest(target_url=TARGET, authorization_confirmed=True)
        )
        return await wait_terminal(manager, str(created.id))

    scan = asyncio.run(exercise())
    assert scan.status.value == "completed"
    assert scan.external_tool_names == ()
    assert scan.external_tools == []


def test_external_selection_requires_active_engagement_and_explicit_active_auth():
    async def exercise():
        manager = ScanManager(client_factory=native_factory, enable_intelligence=False)
        with pytest.raises(EngagementPolicyError):
            await manager.create_scan(
                CreateScanRequest(
                    target_url=TARGET,
                    external_tools=("nmap",),
                    authorization_confirmed=True,
                )
            )

    asyncio.run(exercise())


def test_unknown_external_tool_id_is_rejected_by_the_application_allowlist():
    async def exercise():
        manager = ScanManager(client_factory=native_factory, enable_intelligence=False)
        engagement = await add_engagement(manager)
        with pytest.raises(EngagementPolicyError, match="not configured"):
            await manager.create_scan(
                CreateScanRequest(
                    target_url=TARGET,
                    engagement_id=engagement.id,
                    external_tools=("unknown-tool",),
                    authorization_confirmed=True,
                )
            )

    asyncio.run(exercise())


def test_multiple_selected_external_tools_complete_in_order_and_preserve_native_checks():
    async def exercise():
        manager = ScanManager(
            ScanLimits(maximum_requests_per_scan=4),
            client_factory=native_factory,
            enable_intelligence=False,
            external_adapters={
                "owasp-zap": CompletedFixtureAdapter("owasp-zap"),
                "nmap": CompletedFixtureAdapter("nmap", active=True, capabilities=("nmap.discovery",)),
            },
        )
        engagement = await add_engagement(manager, capabilities=("nmap.discovery",))
        created = await manager.create_scan(
            CreateScanRequest(
                target_url=TARGET,
                engagement_id=engagement.id,
                external_tools=("owasp-zap", "nmap"),
                active_testing_authorized=True,
                authorization_confirmed=True,
            )
        )
        return await wait_terminal(manager, str(created.id))

    scan = asyncio.run(exercise())
    assert scan.status.value == "completed"
    assert scan.summary.checks_total == 4
    assert scan.external_tool_names == ("owasp-zap", "nmap")
    assert [result.state for result in scan.external_tools] == [ExecutionState.COMPLETED, ExecutionState.COMPLETED]


def test_known_but_unconfigured_adapter_is_reported_without_stopping_native_checks():
    async def exercise():
        manager = ScanManager(
            ScanLimits(maximum_requests_per_scan=3),
            client_factory=native_factory,
            enable_intelligence=False,
        )
        engagement = await add_engagement(manager)
        created = await manager.create_scan(
            CreateScanRequest(
                target_url=TARGET,
                engagement_id=engagement.id,
                external_tools=("owasp-zap",),
                authorization_confirmed=True,
            )
        )
        return await wait_terminal(manager, str(created.id))

    scan = asyncio.run(exercise())
    assert scan.status.value == "completed"
    assert scan.summary.checks_total == 4
    assert scan.external_tools[0].state == ExecutionState.UNAVAILABLE
    assert scan.external_tools[0].diagnostics[0].code == "adapter_not_configured"
    report = ReportExporter().export(scan, format="json")
    assert '"external_tools"' in report
    assert "adapter_not_configured" in report


class FakeZAPTransport:
    def __init__(self):
        self.calls: list[str] = []

    async def request(self, path, params, *, timeout_seconds, max_output_bytes):
        self.calls.append(path)
        payloads = {
            "JSON/core/view/version/": {"version": "2.14.0"},
            "JSON/core/action/accessUrl/": {"accessUrl": TARGET},
            "JSON/pscan/view/recordsToScan/": {"recordsToScan": "0"},
            "JSON/core/view/alerts/": {
                "alerts": [
                    {
                        "id": "9",
                        "pluginId": "10021",
                        "name": "Missing header",
                        "risk": "2",
                        "confidence": "3",
                        "url": "https://authorized.example/account",
                        "description": "bounded normalized description",
                        "solution": "Set the header",
                        "reference": "https://example.invalid/rule",
                    }
                ]
            },
        }
        return ToolHTTPResponse(200, payloads[path])


def test_fake_zap_runs_through_manager_and_v06_reports_provenance():
    async def exercise():
        transport = FakeZAPTransport()
        manager = ScanManager(
            ScanLimits(maximum_requests_per_scan=5),
            client_factory=native_factory,
            enable_intelligence=False,
            external_adapters={"owasp-zap": ZAPAdapter(transport)},
        )
        engagement = await add_engagement(manager)
        created = await manager.create_scan(
            CreateScanRequest(
                target_url=TARGET,
                engagement_id=engagement.id,
                external_tools=("owasp-zap",),
                authorization_confirmed=True,
            )
        )
        scan = await wait_terminal(manager, str(created.id))
        report = ReportExporter().export(scan, format="json")
        return scan, report, transport.calls

    scan, report, calls = asyncio.run(exercise())
    assert scan.external_tools[0].state == ExecutionState.COMPLETED
    assert scan.external_tools[0].findings[0].provenance.tool_version == "2.14.0"
    assert '"report_version":"0.6"' in report
    assert '"external_findings"' in report
    assert "owasp-zap" in report
    assert calls[-1] == "JSON/core/view/alerts/"


class PartialAdapter:
    identity = ToolIdentity(name="fake-partial", vendor="fixture", adapter_version="1")
    scope_requirements = ScopeRequirement(requires_engagement=True)

    async def check_availability(self, *, timeout_seconds=5.0):
        raise AssertionError("availability is not probed during scan execution")

    async def execute(self, request: AdapterExecutionRequest):
        return AdapterExecutionResult(
            state=ExecutionState.CANCELLED,
            tool=self.identity,
            partial=True,
            findings=(
                NormalizedFinding(
                    source="fake-partial",
                    rule_id="fixture-1",
                    title="Fixture result",
                    description="password=fixture-secret should be redacted",
                    severity="low",
                    confidence="medium",
                    target=TARGET,
                    provenance=FindingProvenance(
                        adapter="fake-partial", tool="fixture", source_alert_id="raw-id"
                    ),
                ),
            ),
            diagnostics=(
                SanitizedDiagnostic(
                    code="cancelled", message="cancelled token=fixture-secret", phase="execution"
                ),
            ),
        )


class BlockingCancelledAdapter(PartialAdapter):
    def __init__(self):
        self.entered = asyncio.Event()

    async def execute(self, request: AdapterExecutionRequest):
        self.entered.set()
        assert request.cancel_event is not None
        await request.cancel_event.wait()
        return await super().execute(request)


def test_manager_cancellation_preserves_adapter_cancelled_partial_result():
    async def exercise():
        adapter = BlockingCancelledAdapter()
        manager = ScanManager(
            ScanLimits(maximum_requests_per_scan=3),
            client_factory=native_factory,
            enable_intelligence=False,
            external_adapters={"fake-partial": adapter},
        )
        engagement = await add_engagement(manager)
        created = await manager.create_scan(
            CreateScanRequest(
                target_url=TARGET,
                engagement_id=engagement.id,
                external_tools=("fake-partial",),
                authorization_confirmed=True,
            )
        )
        await adapter.entered.wait()
        cancelled = await manager.cancel_scan(str(created.id))
        assert cancelled is not None and cancelled.status.value == "cancelled"
        for _ in range(100):
            scan = await manager.get_scan(str(created.id))
            if scan is not None and scan.external_tools:
                return scan
            await asyncio.sleep(0)
        raise AssertionError("cancelled adapter result was not persisted")

    scan = asyncio.run(exercise())
    assert scan.status.value == "cancelled"
    assert scan.external_tools[0].state == ExecutionState.CANCELLED
    assert scan.external_tools[0].partial is True


def test_cancelled_partial_adapter_is_stored_and_redacted_in_report():
    async def exercise():
        manager = ScanManager(
            ScanLimits(maximum_requests_per_scan=3),
            client_factory=native_factory,
            enable_intelligence=False,
            external_adapters={"fake-partial": PartialAdapter()},
        )
        engagement = await add_engagement(manager)
        created = await manager.create_scan(
            CreateScanRequest(
                target_url=TARGET,
                engagement_id=engagement.id,
                external_tools=("fake-partial",),
                authorization_confirmed=True,
            )
        )
        scan = await wait_terminal(manager, str(created.id))
        return scan, ReportExporter().export(scan, format="markdown")

    scan, report = asyncio.run(exercise())
    assert scan.external_tools[0].state == ExecutionState.CANCELLED
    assert scan.external_tools[0].partial is True
    assert "fixture-secret" not in report
    assert "password=fixture-secret" not in scan.model_dump_json()
    assert "External tools" in report
