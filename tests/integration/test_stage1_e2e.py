"""Stage 1 deterministic end-to-end validation through the public API."""

from __future__ import annotations

import asyncio

import httpx

from app.api.app import create_app
from app.api.models import CreateScanRequest
from app.config import ScanLimits
from app.scanning.models import ScanStatus
from tests.integration.synthetic import (
    SyntheticDNS,
    api_scan,
    make_manager,
    wait_for_terminal,
)


def _response(
    request: httpx.Request,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"<html><title>controlled fixture</title></html>",
    status_code: int = 200,
) -> httpx.Response:
    return httpx.Response(status_code, headers=headers or {}, content=body, request=request)


def test_secure_headers_are_complete_and_safe_in_api_response():
    async def exercise() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _response(
                request,
                headers={
                    "content-type": "text/html",
                    "strict-transport-security": "max-age=31536000",
                    "content-security-policy": "default-src 'self'",
                    "x-content-type-options": "nosniff",
                    "set-cookie": "session=secure-cookie-secret; Secure; HttpOnly; SameSite=Lax",
                },
                body=b"<html><title>secure fixture</title>body-secret</html>",
            )

        manager, dns = make_manager(
            handler, limits=ScanLimits(maximum_requests_per_scan=1)
        )
        payload, _ = await api_scan(manager, "https://secure.example/")

        assert payload["status"] == "completed"
        assert payload["target_url"] == "https://secure.example/"
        assert payload["summary"]["findings_total"] == 0
        assert payload["findings"] == []
        assert {check["status"] for check in payload["checks"]} == {"passed"}
        assert payload["intelligence"]["status"] == "observed"
        assert payload["assessment"]["status"] == "partial"
        assert payload["coverage"] == payload["assessment"]["coverage"]
        assert payload["coverage"]["total_modules"] == 9
        assert payload["coverage"]["findings_total"] == 0
        assert dns.calls == ["secure.example", "secure.example"]
        serialized = str(payload)
        assert "body-secret" not in serialized
        assert "secure-cookie-secret" not in serialized

    asyncio.run(exercise())


def test_missing_headers_preserve_exact_finding_evidence_and_legacy_fields():
    async def exercise() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _response(
                request,
                headers={
                    "content-type": "text/plain",
                },
                body=b"missing-header-body-secret",
            )

        manager, _ = make_manager(
            handler, limits=ScanLimits(maximum_requests_per_scan=1)
        )
        payload, _ = await api_scan(manager, "https://missing.example/")

        assert payload["status"] == "completed"
        assert payload["summary"]["findings_total"] == 3
        expected = {
            "hsts-missing-or-invalid": "hsts",
            "csp-missing": "content_security_policy",
            "x-content-type-options-nosniff-missing": "x_content_type_options",
        }
        findings = {finding["code"]: finding for finding in payload["findings"]}
        assert set(findings) == set(expected)
        for code, check_name in expected.items():
            check = next(item for item in payload["checks"] if item["name"] == check_name)
            finding = findings[code]
            assert check["status"] == "failed"
            assert finding["verification"] == "not_verified"
            assert finding["evidence"] == {
                "url": "https://missing.example/",
                "status_code": 200,
                "headers": {},
            }
            assert check["evidence"] == {
                "url": "https://missing.example/",
                "status_code": 200,
                "headers": {},
            }
        assessment_findings = payload["assessment"]["findings"]
        assert {finding["code"] for finding in assessment_findings} == set(expected)
        assert all(
            finding["evidence"]["url"] == "https://missing.example/"
            and finding["evidence"]["headers"] == {}
            for finding in assessment_findings
        )
        assert {finding["verification"] for finding in assessment_findings} == {"confirmed"}
        assert payload["coverage"]["findings_total"] == 3
        assert "missing-header-body-secret" not in str(payload)
        assert "set-cookie" not in str(payload)

    asyncio.run(exercise())


def test_controlled_child_failure_is_partial_and_does_not_escape_scope():
    async def exercise() -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            if request.url.path == "/broken":
                raise httpx.ConnectError("controlled child failure", request=request)
            return _response(
                request,
                headers={"content-type": "text/html"},
                body=b'<a href="/broken?token=child-secret">broken</a>',
            )

        manager, _ = make_manager(
            handler, limits=ScanLimits(maximum_requests_per_scan=2)
        )
        payload, _ = await api_scan(manager, "https://partial.example/")

        assert payload["status"] == "completed"
        profile = payload["intelligence"]
        assert profile["status"] == "inconclusive"
        assert profile["summary"]["partial"] is True
        assert profile["resources"] == [
            {
                "url": "https://partial.example/broken?token=[redacted]",
                "kind": "link",
                "depth": 1,
                "mode": "observed",
                "confidence": "high",
                "status": "error",
                "method": None,
                "fields": [],
                "source_url": None,
                "evidence": {"url": "https://partial.example/broken?token=[redacted]", "status_code": None, "headers": {}},
            }
        ]
        assert payload["assessment"]["status"] == "partial"
        assert payload["coverage"]["partial"] is True
        assert requests == ["https://93.184.216.34/", "https://93.184.216.34/broken"]
        serialized = str(payload)
        assert "child-secret" not in serialized
        assert "controlled child failure" not in serialized

    asyncio.run(exercise())


def test_redirect_scope_rejection_is_terminal_without_follow_up_or_secret_leak():
    async def exercise() -> None:
        requests: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(str(request.url))
            return _response(
                request,
                status_code=302,
                headers={"location": "https://outside.example/next?token=redirect-secret"},
                body=b"redirect-body-secret",
            )

        manager, _ = make_manager(
            handler, limits=ScanLimits(maximum_requests_per_scan=2)
        )
        payload, _ = await api_scan(manager, "https://redirect.example/")

        assert payload["status"] == "failed"
        assert payload["checks"] == []
        assert payload["findings"] == []
        assert payload["intelligence"] is None
        assert payload["assessment"] is None
        assert payload["coverage"] is None
        assert "CrossOriginRedirect" in payload["error"]
        assert requests == ["https://93.184.216.34/"]
        serialized = str(payload)
        assert "redirect-secret" not in serialized
        assert "redirect-body-secret" not in serialized

    asyncio.run(exercise())


def test_two_targets_are_isolated_when_scanned_concurrently():
    async def exercise() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            host = request.headers["host"]
            marker = "alpha" if host == "alpha.example" else "beta"
            return _response(
                request,
                headers={
                    "content-type": "text/html",
                    "server": f"{marker}-server",
                    "set-cookie": f"sid={marker}-cookie-secret",
                },
                body=f"<html><title>{marker} page</title>{marker}-body-secret</html>".encode(),
            )

        manager, _ = make_manager(
            handler,
            limits=ScanLimits(maximum_requests_per_scan=1),
            resolver=SyntheticDNS({
                "alpha.example": ("93.184.216.34",),
                "beta.example": ("93.184.216.35",),
            }),
        )
        alpha, beta = await asyncio.gather(
            api_scan(manager, "https://alpha.example/"),
            api_scan(manager, "https://beta.example/"),
        )
        alpha_payload, beta_payload = alpha[0], beta[0]

        assert alpha_payload["status"] == beta_payload["status"] == "completed"
        assert alpha_payload["target_url"] == "https://alpha.example/"
        assert beta_payload["target_url"] == "https://beta.example/"
        assert "alpha-server" in str(alpha_payload)
        assert "beta-server" not in str(alpha_payload)
        assert "beta-server" in str(beta_payload)
        assert "alpha-server" not in str(beta_payload)
        assert "alpha-cookie-secret" not in str(alpha_payload)
        assert "beta-cookie-secret" not in str(beta_payload)
        assert "alpha-body-secret" not in str(alpha_payload)
        assert "beta-body-secret" not in str(beta_payload)

    asyncio.run(exercise())


def test_budget_and_cancellation_are_visible_through_api_lifecycle():
    async def exercise() -> None:
        def budget_handler(request: httpx.Request) -> httpx.Response:
            return _response(
                request,
                headers={"content-type": "text/html"},
                body=b'<a href="/not-requested">child</a>',
            )

        budget_manager, _ = make_manager(
            budget_handler,
            limits=ScanLimits(maximum_requests_per_scan=1),
        )
        budget_payload, _ = await api_scan(budget_manager, "https://budget.example/")
        resource = budget_payload["intelligence"]["resources"][0]
        assert budget_payload["status"] == "completed"
        assert resource["status"] == "limited"
        assert budget_payload["intelligence"]["summary"]["resources_scanned"] == 0
        assert budget_payload["assessment"]["status"] == "partial"

        started = asyncio.Event()
        finished = asyncio.Event()

        async def cancellation_handler(request: httpx.Request) -> httpx.Response:
            started.set()
            try:
                await asyncio.sleep(60)
            finally:
                finished.set()
            return _response(request)

        cancellation_manager, _ = make_manager(cancellation_handler)
        created = await cancellation_manager.create_scan(
            CreateScanRequest(
                target_url="https://cancel.example/", authorization_confirmed=True
            )
        )
        await started.wait()
        cancelled = await cancellation_manager.cancel_scan(str(created.id))
        assert cancelled is not None
        assert cancelled.status == ScanStatus.CANCELLED
        await finished.wait()
        final = await wait_for_terminal(cancellation_manager, str(created.id))
        assert final.status == ScanStatus.CANCELLED
        assert final.checks == []
        assert final.assessment is None

    asyncio.run(exercise())


def test_api_accepts_legacy_status_payload_without_stage1_optional_fields():
    class LegacyManager:
        async def get_scan(self, scan_id: str) -> dict:
            return {
                "id": scan_id,
                "target_url": "https://legacy.example/",
                "status": "completed",
                "created_at": "2025-01-01T00:00:00Z",
            }

        async def create_scan(self, request):
            raise AssertionError("not used")

        async def cancel_scan(self, scan_id: str):
            raise AssertionError("not used")

    async def exercise() -> None:
        app = create_app(LegacyManager())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as client:
            response = await client.get("/scans/legacy")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "completed"
        assert body["checks"] == []
        assert body["findings"] == []
        assert body["intelligence"] is None
        assert body["assessment"] is None
        assert body["coverage"] is None

    asyncio.run(exercise())
