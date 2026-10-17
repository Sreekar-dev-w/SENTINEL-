from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.models import CreateScanRequest, ScanStatusResponse
from app.scanning.models import Scan


def _scan(scan_id: str = "scan-1") -> ScanStatusResponse:
    return ScanStatusResponse(
        id=scan_id,
        target_url="https://example.com/",
        status="queued",
        created_at=datetime.now(timezone.utc),
    )


class FakeScanManager:
    def __init__(self) -> None:
        self.created: list[CreateScanRequest] = []
        self.cancelled: list[str] = []
        self.scan = _scan()

    async def create_scan(self, request: CreateScanRequest) -> ScanStatusResponse:
        self.created.append(request)
        return self.scan

    async def get_scan(self, scan_id: str) -> ScanStatusResponse | None:
        return self.scan if scan_id == self.scan.id else None

    async def cancel_scan(self, scan_id: str) -> ScanStatusResponse | None:
        if scan_id != self.scan.id:
            return None
        self.cancelled.append(scan_id)
        self.scan.status = "cancelled"
        return self.scan


def test_create_scan_rejects_unconfirmed_authorization_before_manager_call() -> None:
    manager = FakeScanManager()
    client = TestClient(create_app(manager))

    response = client.post(
        "/scans",
        json={"target_url": "https://example.com", "authorization_confirmed": False},
    )

    assert response.status_code == 422
    assert manager.created == []


def test_create_scan_rejects_invalid_target_before_manager_call() -> None:
    manager = FakeScanManager()
    client = TestClient(create_app(manager))

    response = client.post(
        "/scans",
        json={"target_url": "not-a-url", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert manager.created == []


def test_scan_routes_delegate_to_injected_manager() -> None:
    manager = FakeScanManager()
    client = TestClient(create_app(manager))

    created = client.post(
        "/scans",
        json={"target_url": "HTTPS://Example.COM", "authorization_confirmed": True},
    )
    fetched = client.get("/scans/scan-1")
    cancelled = client.post("/scans/scan-1/cancel")

    assert created.status_code == 202
    assert created.json()["id"] == "scan-1"
    assert manager.created[0].target_url == "https://example.com/"
    assert fetched.status_code == 200
    assert cancelled.status_code == 202
    assert manager.cancelled == ["scan-1"]


def test_scan_routes_return_not_found_for_unknown_scan() -> None:
    client = TestClient(create_app(FakeScanManager()))

    assert client.get("/scans/missing").status_code == 404
    assert client.post("/scans/missing/cancel").status_code == 404


def test_api_serializes_the_domain_scan_with_flattened_findings() -> None:
    class DomainScanManager(FakeScanManager):
        async def create_scan(self, request: CreateScanRequest) -> Scan:
            return Scan(target_url=request.target_url)

    response = TestClient(create_app(DomainScanManager())).post(
        "/scans",
        json={"target_url": "https://example.com", "authorization_confirmed": True},
    )

    assert response.status_code == 202
    assert response.json()["findings"] == []
