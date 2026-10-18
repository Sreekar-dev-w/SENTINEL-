"""Unit tests for application-owned external-tool contracts and ZAP gates.

These tests use a fake API transport. They never launch ZAP or connect to a
real scanner service.
"""

from __future__ import annotations

import asyncio

from app.engagement import Engagement, EngagementScopePolicy
from app.external_tools import (
    AdapterExecutionRequest,
    AdapterScope,
    ExecutionState,
    ToolAvailabilityStatus,
    ToolHTTPResponse,
    ZAP_ACTIVE_SCAN_CAPABILITY,
    ZAPAdapter,
)


def _scope(*, capabilities: tuple[str, ...] = ()) -> AdapterScope:
    engagement = Engagement(
        target_domains=("authorized.example",),
        excluded_routes=("/excluded",),
        allowed_capabilities=capabilities,
        authorization_reference="unit-test-engagement",
    )
    return AdapterScope(engagement.id, EngagementScopePolicy(engagement))


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def request(self, path, params, *, timeout_seconds, max_output_bytes):
        self.calls.append((path, dict(params)))
        response = self.responses[path]
        if callable(response):
            response = response()
        return response


def test_contracts_serialize_safe_identity_availability_and_provenance():
    async def exercise():
        transport = FakeTransport({"JSON/core/view/version/": ToolHTTPResponse(200, {"version": "2.14.0"})})
        availability = await ZAPAdapter(transport).check_availability()
        return availability.model_dump(mode="json")

    serialized = asyncio.run(exercise())
    assert serialized["status"] == ToolAvailabilityStatus.AVAILABLE.value
    assert serialized["identity"]["tool_version"] == "2.14.0"
    assert serialized["capabilities"] == ["passive_scan", "active_scan"]
    assert "api_key" not in str(serialized)


def test_active_scan_is_rejected_without_explicit_authorization_or_capability():
    async def exercise():
        transport = FakeTransport({})
        adapter = ZAPAdapter(transport)
        no_authorization = await adapter.execute(
            AdapterExecutionRequest(
                "https://authorized.example/",
                scope=_scope(capabilities=(ZAP_ACTIVE_SCAN_CAPABILITY,)),
                active_scan=True,
            )
        )
        no_capability = await adapter.execute(
            AdapterExecutionRequest(
                "https://authorized.example/",
                scope=_scope(),
                active_scan=True,
                active_testing_authorized=True,
            )
        )
        return no_authorization, no_capability, transport.calls

    no_authorization, no_capability, calls = asyncio.run(exercise())
    assert no_authorization.state == ExecutionState.REJECTED
    assert no_authorization.diagnostics[0].code == "active_testing_not_authorized"
    assert no_capability.state == ExecutionState.REJECTED
    assert no_capability.diagnostics[0].code == "active_capability_not_allowed"
    assert calls == []


def test_scope_rejection_happens_before_tool_availability_probe():
    async def exercise():
        transport = FakeTransport({})
        result = await ZAPAdapter(transport).execute(
            AdapterExecutionRequest("https://authorized.example/excluded/item", scope=_scope())
        )
        return result, transport.calls

    result, calls = asyncio.run(exercise())
    assert result.state == ExecutionState.REJECTED
    assert result.diagnostics[0].code == "out_of_scope"
    assert calls == []


def test_timeout_and_cancellation_are_bounded_and_sanitized():
    async def exercise():
        class SlowTransport:
            async def request(self, path, params, *, timeout_seconds, max_output_bytes):
                await asyncio.sleep(10)
                return ToolHTTPResponse(200, {"version": "2.14.0"})

        timeout_result = await ZAPAdapter(SlowTransport()).execute(
            AdapterExecutionRequest("https://authorized.example/", scope=_scope(), timeout_seconds=0.01)
        )
        cancelled = asyncio.Event()
        adapter = ZAPAdapter(SlowTransport())
        task = asyncio.create_task(
            adapter.execute(
                AdapterExecutionRequest(
                    "https://authorized.example/", scope=_scope(), cancel_event=cancelled
                )
            )
        )
        await asyncio.sleep(0.01)
        cancelled.set()
        cancelled_result = await task
        return timeout_result, cancelled_result

    timeout_result, cancelled_result = asyncio.run(exercise())
    assert timeout_result.state == ExecutionState.FAILED
    assert timeout_result.diagnostics[0].code == "timeout"
    assert cancelled_result.state == ExecutionState.CANCELLED
    assert cancelled_result.diagnostics[0].code == "cancelled"
