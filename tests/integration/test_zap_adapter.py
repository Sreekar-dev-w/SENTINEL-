"""Deterministic ZAP adapter integration tests using a fake API transport.

The fake transport models supported ZAP JSON API responses. No ZAP executable,
container, public target, or real external service is used by this module.
"""

from __future__ import annotations

import asyncio

from app.engagement import Engagement, EngagementScopePolicy
from app.external_tools import (
    AdapterExecutionRequest,
    AdapterScope,
    ExecutionState,
    ToolHTTPResponse,
    ZAP_ACTIVE_SCAN_CAPABILITY,
    ZAPAdapter,
)


TARGET = "https://authorized.example/"


def scope(*, excluded_hosts=(), capabilities=()):
    engagement = Engagement(
        target_domains=("authorized.example",),
        excluded_hosts=excluded_hosts,
        allowed_capabilities=capabilities,
        authorization_reference="zap-fake-fixture",
    )
    return AdapterScope(engagement.id, EngagementScopePolicy(engagement))


class FixtureZAPTransport:
    """Small supported-API fixture, intentionally separate from real transport."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def request(self, path, params, *, timeout_seconds, max_output_bytes):
        self.calls.append((path, dict(params)))
        response = self.responses[path]
        if callable(response):
            response = response()
        return response


def _success_transport(alerts):
    return FixtureZAPTransport(
        {
            "JSON/core/view/version/": ToolHTTPResponse(200, {"version": "2.14.0"}),
            "JSON/core/action/accessUrl/": ToolHTTPResponse(200, {"accessUrl": TARGET}),
            "JSON/pscan/view/recordsToScan/": ToolHTTPResponse(200, {"recordsToScan": "0"}),
            "JSON/core/view/alerts/": ToolHTTPResponse(200, {"alerts": alerts}),
        }
    )


def test_passive_scan_normalizes_alerts_and_keeps_provenance():
    async def exercise():
        transport = _success_transport(
            [
                {
                    "id": "7",
                    "pluginId": "10021",
                    "name": "Missing Anti-clickjacking Header",
                    "risk": "2",
                    "confidence": "3",
                    "url": "https://authorized.example/account",
                    "description": "A bounded description.",
                    "solution": "Set a suitable header.",
                    "reference": "https://example.invalid/rule",
                }
            ]
        )
        result = await ZAPAdapter(transport).execute(
            AdapterExecutionRequest(TARGET, scope=scope())
        )
        return result, transport.calls

    result, calls = asyncio.run(exercise())
    assert result.state == ExecutionState.COMPLETED
    assert result.partial is False
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source == "owasp-zap"
    assert finding.rule_id == "10021"
    assert finding.severity == "medium"
    assert finding.provenance.tool_version == "2.14.0"
    assert [path for path, _ in calls] == [
        "JSON/core/view/version/",
        "JSON/core/action/accessUrl/",
        "JSON/pscan/view/recordsToScan/",
        "JSON/core/view/alerts/",
    ]


def test_malformed_and_out_of_scope_alerts_produce_partial_sanitized_result():
    async def exercise():
        transport = _success_transport(
            [
                {"pluginId": "missing-required-fields"},
                {
                    "pluginId": "2",
                    "name": "Cross-origin alert",
                    "risk": "1",
                    "confidence": "2",
                    "url": "https://other.example/",
                },
            ]
        )
        return await ZAPAdapter(transport).execute(
            AdapterExecutionRequest(TARGET, scope=scope())
        )

    result = asyncio.run(exercise())
    assert result.state == ExecutionState.PARTIAL
    assert result.findings == ()
    assert {diagnostic.code for diagnostic in result.diagnostics} == {
        "malformed_alert",
        "out_of_scope",
    }
    assert all("other.example" not in diagnostic.message for diagnostic in result.diagnostics)


def test_active_scan_requires_opt_in_but_uses_the_gated_supported_api_path():
    async def exercise():
        transport = FixtureZAPTransport(
            {
                "JSON/core/view/version/": ToolHTTPResponse(200, {"version": "2.14.0"}),
                "JSON/ascan/action/scan/": ToolHTTPResponse(200, {"scanId": "4"}),
                "JSON/ascan/view/status/": ToolHTTPResponse(200, {"status": "100"}),
                "JSON/core/view/alerts/": ToolHTTPResponse(200, {"alerts": []}),
            }
        )
        result = await ZAPAdapter(transport).run(
            AdapterExecutionRequest(
                TARGET,
                scope=scope(capabilities=(ZAP_ACTIVE_SCAN_CAPABILITY,)),
                active_scan=True,
                active_testing_authorized=True,
            )
        )
        return result, transport.calls

    result, calls = asyncio.run(exercise())
    assert result.state == ExecutionState.COMPLETED
    assert [path for path, _ in calls] == [
        "JSON/core/view/version/",
        "JSON/ascan/action/scan/",
        "JSON/ascan/view/status/",
        "JSON/core/view/alerts/",
    ]


def test_unavailable_and_malformed_version_are_distinct_failures():
    async def exercise():
        unavailable = FixtureZAPTransport({"JSON/core/view/version/": ConnectionError("secret=token")})
        # Raise a transport-level failure without exposing its message.
        async def unavailable_request(path, params, *, timeout_seconds, max_output_bytes):
            raise unavailable.responses[path]
        unavailable.request = unavailable_request
        unavailable_result = await ZAPAdapter(unavailable).execute(
            AdapterExecutionRequest(TARGET, scope=scope())
        )
        malformed = FixtureZAPTransport(
            {"JSON/core/view/version/": ToolHTTPResponse(200, {"unexpected": "shape"})}
        )
        malformed_result = await ZAPAdapter(malformed).execute(
            AdapterExecutionRequest(TARGET, scope=scope())
        )
        return unavailable_result, malformed_result

    unavailable_result, malformed_result = asyncio.run(exercise())
    assert unavailable_result.state == ExecutionState.UNAVAILABLE
    assert unavailable_result.diagnostics[0].code == "service_unavailable"
    assert "secret" not in unavailable_result.diagnostics[0].message
    assert malformed_result.state == ExecutionState.FAILED
    assert malformed_result.diagnostics[0].code == "version_failure"
