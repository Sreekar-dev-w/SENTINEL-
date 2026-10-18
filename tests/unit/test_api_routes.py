from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app.api.app import create_app
from app.api.models import CreateScanRequest, ScanStatusResponse
from app.external_tools import ToolAvailability, ToolAvailabilityStatus, ToolIdentity
from app.scanning.models import Scan
from app.scanning.runner import ScanManager
from app.auth import JWTConfig


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
        self.availability = [ToolAvailability(status=ToolAvailabilityStatus.UNAVAILABLE, identity=ToolIdentity(name="nmap", vendor="Nmap Project", adapter_version="1"))]

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

    async def external_tool_availability(self):
        return self.availability


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


def test_create_scan_preserves_selected_external_tool_names_at_api_boundary() -> None:
    manager = FakeScanManager()
    client = TestClient(create_app(manager))

    response = client.post(
        "/scans",
        json={
            "target_url": "https://example.com",
            "authorization_confirmed": True,
            "engagement_id": "00000000-0000-0000-0000-000000000001",
            "external_tools": ["OWASP-ZAP", "nmap", "nmap"],
        },
    )

    assert response.status_code == 202
    assert manager.created[0].external_tools == ("owasp-zap", "nmap")


def test_create_scan_rejects_unknown_extra_fields_before_manager_call() -> None:
    manager = FakeScanManager()
    client = TestClient(create_app(manager))

    response = client.post(
        "/scans",
        json={"target_url": "https://example.com", "authorization_confirmed": True, "external_tool": "nmap"},
    )

    assert response.status_code == 422
    assert manager.created == []


def test_external_tool_availability_route_uses_manager_seam() -> None:
    manager = FakeScanManager()
    response = TestClient(create_app(manager)).get("/external-tools")

    assert response.status_code == 200
    assert response.json()[0]["identity"]["name"] == "nmap"


def _token(subject: str, tenant: str = "tenant-a") -> str:
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()
    header = part({"alg": "HS256", "typ": "JWT"})
    claims = part({"sub": subject, "tenant": tenant, "exp": datetime.now(timezone.utc).timestamp() + 300})
    signature = hmac.new(b"test-secret", f"{header}.{claims}".encode(), hashlib.sha256).digest()
    return f"{header}.{claims}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


def test_configured_jwt_is_required_and_bound_to_scan_request_owner() -> None:
    manager = FakeScanManager()
    app = create_app(manager)
    app.state.jwt_config = JWTConfig(secret="test-secret", issuer=None, audience=None, required=True)
    client = TestClient(app)

    missing = client.post("/scans", json={"target_url": "https://example.com", "authorization_confirmed": True})
    assert missing.status_code == 401

    accepted = client.post(
        "/scans",
        headers={"Authorization": f"Bearer {_token('operator-1')}"},
        json={"target_url": "https://example.com", "authorization_confirmed": True, "infrastructure_authorized": True},
    )
    assert accepted.status_code == 202
    assert manager.created[0].owner_id == "operator-1"
    assert manager.created[0].tenant_id == "tenant-a"
    assert manager.created[0].infrastructure_authorized is False


def test_engagement_reads_and_cancellation_are_owner_scoped() -> None:
    app = create_app(ScanManager(enable_intelligence=False))
    app.state.jwt_config = JWTConfig(secret="test-secret", required=True)
    client = TestClient(app)
    owner_headers = {"Authorization": f"Bearer {_token('owner-1')}"}
    other_headers = {"Authorization": f"Bearer {_token('other-1')}"}
    created = client.post(
        "/engagements",
        headers=owner_headers,
        json={"target_domains": ["example.com"], "authorization_reference": "OWNER-1"},
    )
    assert created.status_code == 201
    engagement_id = created.json()["id"]
    assert client.get(f"/engagements/{engagement_id}", headers=owner_headers).status_code == 200
    assert client.get(f"/engagements/{engagement_id}", headers=other_headers).status_code == 404
    assert client.post(f"/engagements/{engagement_id}/cancel", headers=other_headers).status_code == 404
