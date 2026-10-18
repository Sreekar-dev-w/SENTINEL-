from __future__ import annotations

import asyncio

import httpx
import pytest

from app.assessment.context import AssessmentContext, ResponseSnapshot
from app.assessment.modules import MODULE_FUNCTIONS
from app.assessment.registry import (
    API_TOP10,
    ASVS,
    DEFAULT_REGISTRY,
    TOP10,
    WSTG,
    AssessmentModuleDefinition,
    AssessmentRegistry,
)
from app.assessment.runner import run_assessment
from app.api.models import ScanStatusResponse
from app.config import ScanLimits
from app.scanning.budget import ScanBudget
from app.scanning.http_client import BoundedHTTPClient, PortNotAllowed
from app.scanning.models import (
    AssessmentStatus,
    Check,
    CheckType,
    Finding,
    FindingSeverity,
    ObservationStatus,
    Scan,
    VerificationStatus,
)


def _context(headers: dict[str, str]) -> AssessmentContext:
    request = httpx.Request("GET", "https://fixture.example/")
    response = httpx.Response(200, headers=headers, request=request)
    limits = ScanLimits(maximum_requests_per_scan=2)
    client = BoundedHTTPClient.for_testing(
        limits=limits,
        transport_factory=lambda: httpx.MockTransport(lambda req: httpx.Response(200, request=req)),
    )
    return AssessmentContext(
        target_url="https://fixture.example/",
        response=response,
        budget=ScanBudget(limits),
        _client=client,
    )


def test_registry_is_immutable_and_uses_only_official_versions():
    assert tuple(DEFAULT_REGISTRY.modules) == DEFAULT_REGISTRY.modules
    with pytest.raises((AttributeError, TypeError)):
        DEFAULT_REGISTRY.modules += ()
    assert {WSTG.version, TOP10.version, ASVS.version, API_TOP10.version} == {"4.2", "2025", "5.0.0", "2023"}
    with pytest.raises(ValueError):
        AssessmentRegistry((AssessmentModuleDefinition("x", "x", "x", (WSTG,)), AssessmentModuleDefinition("x", "x", "x", (WSTG,))))


def test_registry_exposes_exact_versioned_identifiers():
    security = next(item for item in DEFAULT_REGISTRY if item.name == "security-headers")
    references = {reference.key for reference in security.references}
    assert "WSTG:4.2:WSTG-CONF-07" in references
    assert "ASVS:5.0.0:v5.0.0-3.4.3" in references
    assert "OWASP Top 10:2025:A02:2025" in references


def test_context_strips_response_body_and_cookie_values_before_module_access():
    request = httpx.Request("GET", "https://fixture.example/")
    raw = httpx.Response(
        200,
        headers={"set-cookie": "session=super-secret; Secure; HttpOnly", "server": "fixture/1.0"},
        content=b"body-super-secret",
        request=request,
    )
    context = AssessmentContext(
        target_url="https://fixture.example/",
        response=raw,
        budget=ScanBudget(ScanLimits()),
    )
    assert isinstance(context.response, ResponseSnapshot)
    assert context.response.cookies[0].secure is True
    assert "super-secret" not in repr(context.response)
    assert not hasattr(context.response, "content")


def test_production_client_enforces_explicit_port_scope():
    async def exercise():
        async with BoundedHTTPClient(limits=ScanLimits(allowed_ports=(443,))) as client:
            with pytest.raises(PortNotAllowed):
                await client.get("http://fixture.example/")

    asyncio.run(exercise())


def test_positive_headers_and_cookie_attributes_have_no_security_findings():
    async def exercise():
        result = await run_assessment(_context({
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "set-cookie": "sid=redacted; Secure; HttpOnly; SameSite=Lax",
        }))
        assert result.coverage.total_modules == 9
        assert result.coverage.findings_total == 0
        assert result.status == AssessmentStatus.PARTIAL
        assert result.modules[-1].progress == 100
    asyncio.run(exercise())


def test_missing_capability_is_unavailable_without_running_a_module():
    async def exercise():
        registry = AssessmentRegistry((AssessmentModuleDefinition(
            "requires-tls", "TLS", "controlled capability", (WSTG,),
            capabilities=frozenset({"tls-metadata"}), function_key="unavailable",
        ),))
        result = await run_assessment(_context({}), registry)
        assert result.modules[0].status == AssessmentStatus.UNAVAILABLE
        assert result.modules[0].error == "missing capability: tls-metadata"

    asyncio.run(exercise())


def test_negative_cors_and_inconclusive_cookie_observations_are_explicit():
    async def exercise():
        result = await run_assessment(_context({
            "set-cookie": "not-a-cookie",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }))
        assert "cors-wildcard-with-credentials" in {finding.code for finding in result.findings}
        cookies = next(item for item in result.modules if item.module == "cookies")
        assert cookies.observations[0].status == ObservationStatus.INCONCLUSIVE
        assert {item.status for item in result.modules} >= {AssessmentStatus.UNAVAILABLE, AssessmentStatus.SKIPPED}
    asyncio.run(exercise())


def test_aggregate_findings_are_deduplicated_stably_and_keep_strongest_verification(monkeypatch):
    def emitter(verification: VerificationStatus, code: str):
        def run(context, definition):
            return [Finding(
                code=code,
                title=code,
                description="controlled finding",
                severity=FindingSeverity.LOW,
                target=context.response.url,
                verification=verification,
                module="shared-module",
                test_id="shared-test",
            )], []

        return run

    monkeypatch.setitem(MODULE_FUNCTIONS, "duplicate-potential", emitter(VerificationStatus.POTENTIAL, "same-code"))
    monkeypatch.setitem(MODULE_FUNCTIONS, "duplicate-confirmed", emitter(VerificationStatus.CONFIRMED, "same-code"))
    monkeypatch.setitem(MODULE_FUNCTIONS, "unique-unverified", emitter(VerificationStatus.NOT_VERIFIED, "other-code"))
    registry = AssessmentRegistry((
        AssessmentModuleDefinition("duplicate-potential", "first", "", (WSTG,), function_key="duplicate-potential"),
        AssessmentModuleDefinition("duplicate-confirmed", "second", "", (WSTG,), function_key="duplicate-confirmed"),
        AssessmentModuleDefinition("unique-unverified", "third", "", (WSTG,), function_key="unique-unverified"),
    ))

    async def exercise():
        result = await run_assessment(_context({}), registry)
        assert [finding.code for finding in result.findings] == ["same-code", "other-code"]
        assert [finding.verification for finding in result.findings] == [
            VerificationStatus.CONFIRMED,
            VerificationStatus.NOT_VERIFIED,
        ]
        assert result.coverage.findings_total == 2
        assert result.coverage.confirmed_findings == 1
        assert [finding.code for finding in result.modules[0].findings] == ["same-code"]
        assert [finding.code for finding in result.modules[1].findings] == ["same-code"]

    asyncio.run(exercise())


def test_scan_deduplication_keeps_same_code_from_distinct_checks():
    first = Finding(
        code="shared-code", title="Header issue", description="HSTS evidence",
        severity=FindingSeverity.LOW, target="https://fixture.example/",
        module=None, remediation="Fix HSTS",
    )
    second = Finding(
        code="shared-code", title="Header issue", description="CSP evidence",
        severity=FindingSeverity.LOW, target="https://fixture.example/",
        module=None, remediation="Fix CSP",
    )
    scan = Scan(
        target_url="https://fixture.example/",
        checks=[
            Check(name=CheckType.HSTS, findings=[first]),
            Check(name=CheckType.CSP, findings=[second]),
        ],
    )
    assert [finding.description for finding in scan.findings] == [
        "HSTS evidence", "CSP evidence"
    ]


def test_module_failure_is_isolated_and_coverage_counts_it():
    async def exercise():
        original = MODULE_FUNCTIONS["redirects"]
        MODULE_FUNCTIONS["redirects"] = lambda context, definition: (_ for _ in ()).throw(RuntimeError("controlled"))
        try:
            result = await run_assessment(_context({}))
        finally:
            MODULE_FUNCTIONS["redirects"] = original
        redirect = next(item for item in result.modules if item.module == "redirects")
        assert redirect.status == AssessmentStatus.ERROR
        assert result.coverage.error_modules == 1
        assert any(item.module == "cookies" for item in result.modules)
    asyncio.run(exercise())


def test_old_api_response_without_v03_fields_remains_valid():
    response = ScanStatusResponse.model_validate({
        "id": "legacy", "target_url": "https://fixture.example/", "status": "completed",
        "created_at": "2025-01-01T00:00:00Z",
    })
    assert response.assessment is None
    assert response.coverage is None
