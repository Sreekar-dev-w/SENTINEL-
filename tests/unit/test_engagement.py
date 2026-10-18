from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from pydantic import ValidationError

from app.api.app import create_app
from app.engagement import (
    Engagement,
    EngagementBudgets,
    EngagementScopePolicy,
    EngagementScopeViolation,
    EngagementStatus,
    EngagementStore,
)
from app.scanning.http_client import BoundedHTTPClient
from app.config import ScanLimits
from app.scanning.runner import ScanManager
from fastapi.testclient import TestClient


def engagement(**overrides) -> Engagement:
    values = {"target_domains": ("example.com",), "authorization_reference": "ticket-123"}
    values.update(overrides)
    return Engagement(**values)


def test_scope_allows_target_and_rejects_hosts_routes_addresses_and_private_ips():
    policy = EngagementScopePolicy(
        engagement(
            target_cidrs=("93.184.216.0/24",),
            excluded_hosts=("blocked.example.com",),
            excluded_addresses=("93.184.216.99",),
            excluded_routes=("/admin",),
        )
    )

    assert policy.validate_url("https://www.example.com/public").hostname == "www.example.com"
    with pytest.raises(EngagementScopeViolation):
        policy.validate_url("https://blocked.example.com/")
    with pytest.raises(EngagementScopeViolation):
        policy.validate_url("https://example.com/admin/users")
    with pytest.raises(EngagementScopeViolation):
        policy.validate_destination("93.184.216.99", hostname="example.com", port=443, service_type="https")
    with pytest.raises(EngagementScopeViolation):
        policy.validate_destination("10.0.0.1", hostname="example.com", port=443, service_type="https")


def test_scope_enforces_ports_and_service_types():
    policy = EngagementScopePolicy(
        engagement(
            permitted_ports=(443,), permitted_service_types=("https",), target_cidrs=("93.184.216.0/24",)
        )
    )
    with pytest.raises(EngagementScopeViolation):
        policy.validate_url("http://example.com/")
    with pytest.raises(EngagementScopeViolation):
        policy.validate_connection(
            hostname="example.com", address="93.184.216.34", port=80, service_type="http"
        )


def test_expiry_and_cancellation_are_enforced_and_audited():
    async def exercise() -> None:
        store = EngagementStore()
        expiring = engagement(
            created_at=datetime.now(timezone.utc) - timedelta(seconds=2),
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        await store.create(expiring)
        expired = await store.get(expiring.id)
        assert expired is not None and expired.status == EngagementStatus.EXPIRED
        with pytest.raises(EngagementScopeViolation):
            EngagementScopePolicy(expired).validate_url("https://example.com/")

        active = engagement()
        await store.create(active)
        cancelled = await store.cancel(active.id, actor="operator", reason="finished")
        assert cancelled.status == EngagementStatus.CANCELLED
        assert cancelled.cancelled_by == "operator"
        assert cancelled.audit_metadata[-1].action == "cancelled"
        with pytest.raises(EngagementScopeViolation):
            EngagementScopePolicy(cancelled).validate_url("https://example.com/")

    asyncio.run(exercise())


def test_budgets_are_narrowed_without_expanding_server_limits():
    narrowed = EngagementBudgets(
        maximum_requests_per_scan=2, maximum_requests_per_host=1, maximum_concurrency=1, scan_timeout_seconds=3
    ).apply(ScanLimits(maximum_requests_per_scan=10, maximum_requests_per_host=5, scan_timeout_seconds=30))
    assert narrowed.maximum_requests_per_scan == 2
    assert narrowed.maximum_requests_per_host == 1
    assert narrowed.maximum_concurrency == 1
    assert narrowed.scan_timeout_seconds == 3


def test_rebinding_and_redirects_are_checked_by_the_bounded_client():
    class Resolver:
        def __init__(self):
            self.calls = 0

        async def resolve(self, hostname):
            self.calls += 1
            return ("93.184.216.34",) if self.calls == 1 else ("8.8.8.8",)

    policy = EngagementScopePolicy(
        engagement(target_cidrs=("93.184.216.0/24",))
    )

    async def exercise() -> None:
        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_redirects=2),
            resolver=Resolver(),
            engagement_policy=policy,
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(302, headers={"location": "/next"})
            ),
        ) as client:
            with pytest.raises(EngagementScopeViolation):
                await client.get("https://example.com/")

    asyncio.run(exercise())


def test_engagements_are_isolated_and_no_secret_fields_are_stored():
    first = EngagementScopePolicy(engagement(target_domains=("one.example",)))
    second = EngagementScopePolicy(engagement(target_domains=("two.example",)))
    assert first.allows_profile("profile-a")
    with pytest.raises(EngagementScopeViolation):
        second.validate_url("https://one.example/")
    with pytest.raises(ValidationError):
        Engagement(target_domains=("example.com",), authorization_reference="x", api_key="secret")


def test_engagement_api_and_scan_engagement_id_are_compatible():
    manager = ScanManager(enable_intelligence=False)
    client = TestClient(create_app(manager))
    created = client.post(
        "/engagements",
        json={"target_domains": ["example.com"], "authorization_reference": "ticket-1"},
    )
    assert created.status_code == 201
    engagement_id = created.json()["id"]
    fetched = client.get(f"/engagements/{engagement_id}")
    assert fetched.status_code == 200
    scan = client.post(
        "/scans",
        json={
            "target_url": "https://example.com/",
            "authorization_confirmed": True,
            "engagement_id": engagement_id,
        },
    )
    assert scan.status_code == 202
    assert scan.json()["engagement_id"] == engagement_id
    cancelled = client.post(f"/engagements/{engagement_id}/cancel")
    assert cancelled.status_code == 200
    rejected = client.post(
        "/scans",
        json={
            "target_url": "https://example.com/",
            "authorization_confirmed": True,
            "engagement_id": engagement_id,
        },
    )
    assert rejected.status_code == 403
