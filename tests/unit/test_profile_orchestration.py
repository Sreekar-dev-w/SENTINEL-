"""Deterministic v0.5 profile orchestration coverage."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.api.app import create_app
from app.api.models import CreateScanRequest
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
)
from app.assessment.orchestration import CONTROLLED_LAB, LEGACY_PASSIVE
from app.config import ScanLimits
from app.engagement.models import Engagement
from app.engagement.policy import EngagementPolicyError
from app.engagement.store import EngagementStore
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.models import ScanStatus
from app.scanning.runner import ScanManager


TARGET = "https://lab.example/"
CAPABILITIES = frozenset({
    LAB_AUTHENTICATION,
    LAB_SESSION_COOKIE_METADATA,
    LAB_AUTHORIZATION,
    LAB_INPUT_VALIDATION,
})


def _lab(target: str = TARGET, *, flawed: bool = False) -> InProcessAssessmentLab:
    return InProcessAssessmentLab(
        scope=LabScope(
            target, approved=True,
            operations=frozenset({"authentication", "session-cookie-metadata", "authorization", "input-validation"}),
        ),
        capabilities=CAPABILITIES,
        users=(SyntheticUser("a", "member"), SyntheticUser("b", "member")),
        resources=(SyntheticResource("resource", "a"),),
        protected_route=ProtectedRouteMetadata("account", True, False, True),
        session_cookie=SessionCookieMetadata(True, True, True, "Lax"),
        authorization_cases=(
            AuthorizationMetadata("a", "resource", "read", True, True, True, "owner"),
            AuthorizationMetadata("b", "resource", "read", False, flawed, False, "owner-only"),
        ),
        input_validation=(InputValidationMetadata("search", True, "application/json", True, True, False, False),),
    )


def _manager(*, store: EngagementStore | None = None, lab=None, maximum_requests: int = 1) -> ScanManager:
    def factory(limits: ScanLimits) -> BoundedHTTPClient:
        resolver = type("Resolver", (), {"resolve": lambda self, hostname: asyncio.sleep(0, result=("93.184.216.34",))})()
        return BoundedHTTPClient.for_testing(
            limits=limits,
            resolver=resolver,
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(200, headers={"content-type": "text/html"}, request=request)
            ),
        )

    return ScanManager(
        ScanLimits(scan_timeout_seconds=1, maximum_requests_per_scan=maximum_requests),
        client_factory=factory,
        enable_intelligence=False,
        engagement_store=store,
        assessment_lab_factory=lab,
    )


async def _terminal(manager: ScanManager, scan_id: str):
    for _ in range(200):
        scan = await manager.get_scan(scan_id)
        if scan is not None and scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            return scan
        await asyncio.sleep(0)
    raise AssertionError("scan did not reach a terminal state")


def test_legacy_request_keeps_omitted_profile_fields_and_old_assessment_metadata():
    async def exercise():
        manager = _manager()
        scan = await manager.create_scan(CreateScanRequest(target_url=TARGET, authorization_confirmed=True))
        result = await _terminal(manager, str(scan.id))
        assert result.assessment_profile is None
        assert result.active_testing_authorized is None
        assert result.assessment.profile_id == LEGACY_PASSIVE.profile_id
        assert result.assessment.profile_version == LEGACY_PASSIVE.version

    asyncio.run(exercise())


def test_controlled_profile_requires_engagement_and_explicit_authorization():
    async def exercise():
        manager = _manager()
        with pytest.raises(EngagementPolicyError, match="engagement_id"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                assessment_profile="controlled-lab",
                active_testing_authorized=True,
                authorization_confirmed=True,
            ))
        store = EngagementStore()
        engagement = await store.create(Engagement(
            target_domains=("lab.example",),
            allowed_assessment_profiles=(CONTROLLED_LAB.name,),
            allowed_capabilities=tuple(CAPABILITIES),
            authorization_reference="fixture-approval",
        ))
        manager = _manager(store=store, lab=lambda target: _lab(target))
        with pytest.raises(EngagementPolicyError, match="active_testing_authorized"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                engagement_id=engagement.id,
                assessment_profile=CONTROLLED_LAB.name,
                authorization_confirmed=True,
            ))

    asyncio.run(exercise())


def test_controlled_profile_runs_only_when_policy_and_synthetic_lab_are_present():
    async def exercise():
        store = EngagementStore()
        engagement = await store.create(Engagement(
            target_domains=("lab.example",),
            allowed_assessment_profiles=(CONTROLLED_LAB.name,),
            allowed_capabilities=tuple(CAPABILITIES),
            authorization_reference="fixture-approval",
        ))
        manager = _manager(store=store, lab=lambda target: _lab(target))
        scan = await manager.create_scan(CreateScanRequest(
            target_url=TARGET,
            engagement_id=engagement.id,
            assessment_profile=CONTROLLED_LAB.name,
            active_testing_authorized=True,
            authorization_confirmed=True,
        ))
        result = await _terminal(manager, str(scan.id))
        assert result.status == ScanStatus.COMPLETED
        assert result.assessment.profile_id == CONTROLLED_LAB.profile_id
        assert result.assessment.profile_version == CONTROLLED_LAB.version
        assert all(item.status.value == "completed" for item in result.assessment.modules)

    asyncio.run(exercise())


def test_controlled_profile_denial_is_translated_by_the_api():
    async def exercise():
        manager = _manager()
        app = create_app(manager)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api.test") as client:
            response = await client.post("/scans", json={
                "target_url": TARGET,
                "assessment_profile": "controlled-lab",
                "active_testing_authorized": True,
                "authorization_confirmed": True,
            })
        assert response.status_code == 403
        assert "engagement_id" in response.json()["detail"]

    asyncio.run(exercise())


def test_controlled_profile_requires_engagement_profile_and_capabilities():
    async def exercise():
        all_profiles = EngagementStore()
        profile_restricted = await all_profiles.create(Engagement(
            target_domains=("lab.example",),
            allowed_assessment_profiles=(LEGACY_PASSIVE.name,),
            allowed_capabilities=tuple(CAPABILITIES),
            authorization_reference="fixture-approval",
        ))
        manager = _manager(store=all_profiles, lab=lambda target: _lab(target))
        with pytest.raises(EngagementPolicyError, match="assessment profile"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                engagement_id=profile_restricted.id,
                assessment_profile=CONTROLLED_LAB.name,
                active_testing_authorized=True,
                authorization_confirmed=True,
            ))

        capability_restricted = await all_profiles.create(Engagement(
            target_domains=("lab.example",),
            allowed_assessment_profiles=(CONTROLLED_LAB.name,),
            allowed_capabilities=tuple(sorted(CAPABILITIES - {LAB_INPUT_VALIDATION})),
            authorization_reference="fixture-approval",
        ))
        with pytest.raises(EngagementPolicyError, match="capability"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                engagement_id=capability_restricted.id,
                assessment_profile=CONTROLLED_LAB.name,
                active_testing_authorized=True,
                authorization_confirmed=True,
            ))

    asyncio.run(exercise())


def test_controlled_profile_rechecks_scope_expiry_and_cancellation_at_admission():
    async def exercise():
        store = EngagementStore()
        expired = await store.create(Engagement(
            target_domains=("lab.example",),
            allowed_assessment_profiles=(CONTROLLED_LAB.name,),
            allowed_capabilities=tuple(CAPABILITIES),
            authorization_reference="fixture-approval",
            created_at=datetime.now(timezone.utc) - timedelta(seconds=2),
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        ))
        manager = _manager(store=store, lab=lambda target: _lab(target))
        with pytest.raises(EngagementPolicyError, match="expired"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                engagement_id=expired.id,
                assessment_profile=CONTROLLED_LAB.name,
                active_testing_authorized=True,
                authorization_confirmed=True,
            ))

        cancelled = await store.create(Engagement(
            target_domains=("lab.example",),
            allowed_assessment_profiles=(CONTROLLED_LAB.name,),
            allowed_capabilities=tuple(CAPABILITIES),
            authorization_reference="fixture-approval",
        ))
        await store.cancel(cancelled.id, actor="test", reason="finished")
        with pytest.raises(EngagementPolicyError, match="cancelled"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                engagement_id=cancelled.id,
                assessment_profile=CONTROLLED_LAB.name,
                active_testing_authorized=True,
                authorization_confirmed=True,
            ))

        out_of_scope = await store.create(Engagement(
            target_domains=("other.example",),
            allowed_assessment_profiles=(CONTROLLED_LAB.name,),
            allowed_capabilities=tuple(CAPABILITIES),
            authorization_reference="fixture-approval",
        ))
        with pytest.raises(EngagementPolicyError, match="outside engagement domains"):
            await manager.create_scan(CreateScanRequest(
                target_url=TARGET,
                engagement_id=out_of_scope.id,
                assessment_profile=CONTROLLED_LAB.name,
                active_testing_authorized=True,
                authorization_confirmed=True,
            ))

    asyncio.run(exercise())


def test_default_app_controlled_workflow_uses_secure_lab_and_only_initial_get():
    async def exercise():
        requests: list[httpx.Request] = []

        def factory(limits: ScanLimits) -> BoundedHTTPClient:
            resolver = type("Resolver", (), {"resolve": lambda self, hostname: asyncio.sleep(0, result=("93.184.216.34",))})()

            def handler(request: httpx.Request) -> httpx.Response:
                requests.append(request)
                return httpx.Response(200, headers={"content-type": "text/html"}, request=request)

            return BoundedHTTPClient.for_testing(
                limits=limits,
                resolver=resolver,
                transport_factory=lambda: httpx.MockTransport(handler),
            )

        app = create_app()
        manager = app.state.scan_manager
        manager._client_factory = factory
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as client:
            engagement_response = await client.post("/engagements", json={
                "target_domains": ["lab.example"],
                "allowed_assessment_profiles": [CONTROLLED_LAB.name],
                "allowed_capabilities": list(CAPABILITIES),
                "authorization_reference": "fixture-approval",
            })
            assert engagement_response.status_code == 201
            created_response = await client.post("/scans", json={
                "target_url": TARGET,
                "engagement_id": engagement_response.json()["id"],
                "assessment_profile": CONTROLLED_LAB.name,
                "active_testing_authorized": True,
                "authorization_confirmed": True,
            })
        assert created_response.status_code == 202
        result = await _terminal(manager, created_response.json()["id"])
        assert result.status == ScanStatus.COMPLETED
        assert len(requests) == 1
        assert result.assessment is not None
        assert [module.status.value for module in result.assessment.modules] == [
            "completed", "completed", "completed", "completed"
        ]
        assert result.assessment.findings == []

    asyncio.run(exercise())
