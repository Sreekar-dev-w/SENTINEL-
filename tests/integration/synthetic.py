"""Reusable deterministic fixtures for end-to-end scan validation.

These helpers deliberately use only the production scan manager, an injected
DNS resolver, and HTTPX's explicit MockTransport test seam.  They never open a
socket or consult the host resolver.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeAlias

import httpx

from app.api.app import create_app
from app.config import ScanLimits
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.models import Scan, ScanStatus
from app.scanning.runner import ScanManager


Handler: TypeAlias = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]


class SyntheticDNS:
    """A deterministic A/AAAA source that records logical host lookups."""

    def __init__(self, addresses: dict[str, tuple[str, ...]] | None = None) -> None:
        self.addresses = addresses or {}
        self.calls: list[str] = []

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        return self.addresses.get(hostname, ("93.184.216.34",))


def make_manager(
    handler: Handler,
    *,
    limits: ScanLimits | None = None,
    resolver: SyntheticDNS | None = None,
    enable_intelligence: bool = True,
) -> tuple[ScanManager, SyntheticDNS]:
    """Build a real manager with a fresh explicit MockTransport per request."""

    dns = resolver or SyntheticDNS()
    configured_limits = limits or ScanLimits(scan_timeout_seconds=1)

    def client_factory(scan_limits: ScanLimits) -> BoundedHTTPClient:
        return BoundedHTTPClient.for_testing(
            limits=scan_limits,
            resolver=dns,
            transport_factory=lambda: httpx.MockTransport(handler),
        )

    return (
        ScanManager(
            configured_limits,
            client_factory=client_factory,
            enable_intelligence=enable_intelligence,
        ),
        dns,
    )


async def wait_for_terminal(manager: ScanManager, scan_id: str) -> Scan:
    """Yield to the manager task until its scan reaches a terminal state."""

    for _ in range(200):
        scan = await manager.get_scan(scan_id)
        if scan is not None and scan.status in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }:
            return scan
        await asyncio.sleep(0)
    raise AssertionError("synthetic scan did not reach a terminal state")


async def api_scan(manager: ScanManager, target_url: str) -> tuple[dict, ScanManager]:
    """Create and retrieve one scan through the actual FastAPI response path."""

    app = create_app(manager)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        created = await client.post(
            "/scans",
            json={"target_url": target_url, "authorization_confirmed": True},
        )
        assert created.status_code == 202
        scan_id = created.json()["id"]
        for _ in range(200):
            response = await client.get(f"/scans/{scan_id}")
            assert response.status_code == 200
            payload = response.json()
            if payload["status"] in {"completed", "failed", "cancelled"}:
                return payload, manager
            await asyncio.sleep(0)
    raise AssertionError("synthetic API scan did not reach a terminal state")
