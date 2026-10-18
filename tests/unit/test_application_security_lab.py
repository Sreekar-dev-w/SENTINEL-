from __future__ import annotations

import asyncio

import httpx
import pytest

from app.assessment.context import AssessmentContext
from app.assessment.lab import (
    LAB_AUTHENTICATION,
    LAB_AUTHORIZATION,
    LAB_INPUT_VALIDATION,
    LAB_SESSION_COOKIE_METADATA,
    AuthorizationMetadata,
    InProcessAssessmentLab,
    InputValidationMetadata,
    LabScope,
    ProtectedRouteMetadata,
    SessionCookieMetadata,
    SyntheticResource,
    SyntheticUser,
    LabConfigurationError,
    build_secure_application_security_lab,
)
from app.assessment.registry import CONTROLLED_APPLICATION_SECURITY_REGISTRY
from app.assessment.runner import run_assessment
from app.scanning.budget import ScanBudget
from app.scanning.models import AssessmentStatus
from app.config import ScanLimits


TARGET = "https://lab.example/"
ALL_CAPABILITIES = frozenset({
    LAB_AUTHENTICATION,
    LAB_SESSION_COOKIE_METADATA,
    LAB_AUTHORIZATION,
    LAB_INPUT_VALIDATION,
})
ALL_PREREQUISITES = frozenset({
    "protected-route-expectation",
    "authenticated-session",
    "session-cookie-metadata",
    "authorization-expectations",
    "malformed-input-probe",
})


def _context(*, lab: InProcessAssessmentLab | None, target: str = TARGET, prerequisites=ALL_PREREQUISITES) -> AssessmentContext:
    request = httpx.Request("GET", target)
    response = httpx.Response(200, headers={
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
    }, request=request)
    return AssessmentContext(
        target_url=target,
        response=response,
        budget=ScanBudget(ScanLimits(maximum_requests_per_scan=2)),
        lab=lab,
        capabilities=ALL_CAPABILITIES if lab else frozenset(),
        prerequisites=prerequisites,
    )


def _lab(*, flawed: bool = False, target: str = TARGET) -> InProcessAssessmentLab:
    users = (SyntheticUser("user-a", "member"), SyntheticUser("user-b", "member"))
    resources = (SyntheticResource("resource-a", "user-a"),)
    return InProcessAssessmentLab(
        scope=LabScope(target, approved=True, operations=frozenset({
            "authentication", "session-cookie-metadata", "authorization", "input-validation",
        })),
        capabilities=ALL_CAPABILITIES,
        users=users,
        resources=resources,
        protected_route=ProtectedRouteMetadata("account", True, False, True),
        session_cookie=SessionCookieMetadata(True, True, True, "Lax"),
        authorization_cases=(
            AuthorizationMetadata("user-a", "resource-a", "read", True, True, True, "owner"),
            AuthorizationMetadata("user-b", "resource-a", "read", False, flawed, False, "owner-only"),
        ),
        input_validation=(InputValidationMetadata("search", True, "application/json", True, True, False, False),),
    )


def _module(result, name: str):
    return next(item for item in result.modules if item.module == name)


def test_lab_requires_explicit_approval_and_declared_capabilities():
    with pytest.raises(LabConfigurationError):
        LabScope(TARGET, approved=False, operations=frozenset({"authorization"}))
    with pytest.raises(LabConfigurationError):
        InProcessAssessmentLab(
            scope=LabScope(TARGET, approved=True, operations=frozenset({"authorization"})),
            capabilities=frozenset(),
        )


def test_controlled_modules_are_unavailable_without_a_lab():
    async def exercise():
        result = await run_assessment(_context(lab=None), CONTROLLED_APPLICATION_SECURITY_REGISTRY)
        assert {item.status for item in result.modules} == {AssessmentStatus.UNAVAILABLE}
        assert all(item.error.startswith("missing capability:") for item in result.modules)
    asyncio.run(exercise())


def test_secure_controls_have_no_false_positive_findings_and_stable_metadata():
    async def exercise():
        result = await run_assessment(_context(lab=_lab()), CONTROLLED_APPLICATION_SECURITY_REGISTRY)
        assert result.profile_version == "0.4.0"
        assert result.findings == []
        assert _module(result, "authentication-protected-route").test_id == "authentication-protected-route"
        assert _module(result, "authentication-protected-route").test_version == "0.4.0"
        assert _module(result, "authorization-object-access").status == AssessmentStatus.COMPLETED
        assert _module(result, "input-validation-safety").observations[0].value["injection_inferred_from_validation"] is False
    asyncio.run(exercise())


def test_controlled_registry_uses_stable_v04_ids_and_exact_references():
    assert [item.test_id for item in CONTROLLED_APPLICATION_SECURITY_REGISTRY] == [
        "authentication-protected-route",
        "session-cookie-metadata",
        "authorization-object-access",
        "input-validation-safety",
    ]
    assert all(item.test_version == "0.4.0" for item in CONTROLLED_APPLICATION_SECURITY_REGISTRY)
    authorization = next(item for item in CONTROLLED_APPLICATION_SECURITY_REGISTRY if item.name == "authorization-object-access")
    assert {reference.key for reference in authorization.references} == {
        "OWASP Top 10:2025:A01:2025",
        "ASVS:5.0.0:v5.0.0-8.2.2",
        "API Security Top 10:2023:API1:2023",
    }


def test_deliberate_cross_user_access_flaw_is_detected_without_status_codes():
    async def exercise():
        result = await run_assessment(_context(lab=_lab(flawed=True)), CONTROLLED_APPLICATION_SECURITY_REGISTRY)
        authorization = _module(result, "authorization-object-access")
        assert authorization.status == AssessmentStatus.COMPLETED
        assert [finding.code for finding in authorization.findings] == ["cross-user-object-access"]
        assert authorization.observations[0].value["status_code_used"] is False
    asyncio.run(exercise())


def test_session_cookie_prerequisite_is_skipped_without_authenticated_session():
    async def exercise():
        result = await run_assessment(
            _context(lab=_lab(), prerequisites=frozenset(ALL_PREREQUISITES - {"authenticated-session"})),
            CONTROLLED_APPLICATION_SECURITY_REGISTRY,
        )
        cookie = _module(result, "session-cookie-metadata")
        assert cookie.status == AssessmentStatus.SKIPPED
        assert cookie.skip_reason == "missing prerequisite: authenticated-session"
    asyncio.run(exercise())


def test_unsupported_scope_is_skipped_before_lab_metadata_is_used():
    async def exercise():
        result = await run_assessment(_context(lab=_lab(), target="https://other.example/"), CONTROLLED_APPLICATION_SECURITY_REGISTRY)
        assert _module(result, "authorization-object-access").status == AssessmentStatus.SKIPPED
        assert _module(result, "authorization-object-access").skip_reason == "unsupported lab scope"
    asyncio.run(exercise())


def test_lab_metadata_cannot_contain_cookie_values_or_raw_input_markers():
    lab = _lab()
    assert "password" not in repr(lab).lower()
    assert "super-secret" not in repr(lab)
    assert "marker" not in repr(lab).lower()
    assert lab.session_cookie_metadata(TARGET).secure is True


def test_default_secure_lab_builder_is_deterministic_and_metadata_only():
    first = build_secure_application_security_lab(TARGET)
    second = build_secure_application_security_lab(TARGET)
    assert first.scope.target_url == "https://lab.example"
    assert first.capabilities == second.capabilities
    assert first.protected_route_metadata(TARGET) == second.protected_route_metadata(TARGET)
    assert first.session_cookie_metadata(TARGET) == second.session_cookie_metadata(TARGET)
    assert first.authorization_metadata(TARGET) == second.authorization_metadata(TARGET)
    assert first.input_validation_metadata(TARGET) == second.input_validation_metadata(TARGET)
    assert first.authorization_metadata(TARGET)[1].actual_allowed is False
    assert first.input_validation_metadata(TARGET)[0].injection_observed is False
    rendered = repr(first).lower()
    assert all(secret not in rendered for secret in ("password", "token", "cookie=", "request body", "payload"))


def test_two_scans_have_isolated_lab_outcomes():
    async def exercise():
        secure, flawed = await asyncio.gather(
            run_assessment(_context(lab=_lab()), CONTROLLED_APPLICATION_SECURITY_REGISTRY),
            run_assessment(_context(lab=_lab(flawed=True)), CONTROLLED_APPLICATION_SECURITY_REGISTRY),
        )
        assert secure.findings == []
        assert [item.code for item in flawed.findings] == ["cross-user-object-access"]
    asyncio.run(exercise())
