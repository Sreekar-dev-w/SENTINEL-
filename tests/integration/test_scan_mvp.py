import asyncio

import httpx

from app.api.models import CreateScanRequest
from app.config import ScanLimits
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.models import ScanStatus
from app.scanning.runner import ScanManager


class SafeResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


async def wait_for_terminal(manager: ScanManager, scan_id: str):
    for _ in range(100):
        scan = await manager.get_scan(scan_id)
        if scan is not None and scan.status in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        }:
            return scan
        await asyncio.sleep(0)
    raise AssertionError("scan did not reach a terminal state")


def test_scan_manager_runs_checks_and_stores_minimal_evidence():
    async def exercise() -> None:
        resolver = SafeResolver()
        requests: list[httpx.Request] = []

        def factory(limits: ScanLimits) -> BoundedHTTPClient:
            def handler(request: httpx.Request) -> httpx.Response:
                requests.append(request)
                return httpx.Response(
                    200,
                    headers={
                        "Content-Type": "text/html",
                        "Set-Cookie": "session=must-not-be-stored",
                    },
                    content=b"not retained",
                )

            return BoundedHTTPClient.for_testing(
                limits=limits,
                resolver=resolver,
                transport_factory=lambda: httpx.MockTransport(handler),
            )

        manager = ScanManager(
            ScanLimits(
                request_timeout_seconds=1,
                scan_timeout_seconds=1,
                maximum_requests_per_scan=1,
            ),
            client_factory=factory,
        )
        created = await manager.create_scan(
            CreateScanRequest(
                target_url="https://fixture.example/",
                authorization_confirmed=True,
            )
        )
        assert created.status == ScanStatus.QUEUED

        completed = await wait_for_terminal(manager, str(created.id))
        assert completed.status == ScanStatus.COMPLETED
        assert len(requests) == 1
        assert completed.summary.findings_total == 3
        assert {finding.code for check in completed.checks for finding in check.findings} == {
            "hsts-missing-or-invalid",
            "csp-missing",
            "x-content-type-options-nosniff-missing",
        }
        evidence_headers = {
            name
            for check in completed.checks
            if check.evidence is not None
            for name in check.evidence.headers
        }
        assert "set-cookie" not in evidence_headers

    asyncio.run(exercise())


def test_scan_failure_is_terminal_and_does_not_report_findings():
    async def exercise() -> None:
        def factory(limits: ScanLimits) -> BoundedHTTPClient:
            return BoundedHTTPClient.for_testing(
                limits=limits,
                resolver=SafeResolver(),
                transport_factory=lambda: httpx.MockTransport(
                    lambda request: (_ for _ in ()).throw(
                        httpx.ConnectError("controlled failure", request=request)
                    )
                ),
            )

        manager = ScanManager(
            ScanLimits(scan_timeout_seconds=1),
            client_factory=factory,
        )
        created = await manager.create_scan(
            CreateScanRequest(
                target_url="https://fixture.example/",
                authorization_confirmed=True,
            )
        )
        failed = await wait_for_terminal(manager, str(created.id))
        assert failed.status == ScanStatus.FAILED
        assert failed.checks == []
        assert failed.error is not None

    asyncio.run(exercise())


def test_scan_cancellation_is_race_safe_and_closes_the_transport():
    async def exercise() -> None:
        started = asyncio.Event()
        transports: list[httpx.AsyncBaseTransport] = []

        class BlockingTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.closed = False

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                started.set()
                await asyncio.sleep(60)
                return httpx.Response(200, content=b"never", request=request)

            async def aclose(self) -> None:
                self.closed = True

        def factory(limits: ScanLimits) -> BoundedHTTPClient:
            def transport_factory() -> BlockingTransport:
                transport = BlockingTransport()
                transports.append(transport)
                return transport

            return BoundedHTTPClient.for_testing(
                limits=limits,
                resolver=SafeResolver(),
                transport_factory=transport_factory,
            )

        manager = ScanManager(
            ScanLimits(scan_timeout_seconds=10),
            client_factory=factory,
        )
        created = await manager.create_scan(
            CreateScanRequest(
                target_url="https://fixture.example/",
                authorization_confirmed=True,
            )
        )
        await started.wait()
        cancelled = await manager.cancel_scan(str(created.id))
        assert cancelled is not None
        assert cancelled.status == ScanStatus.CANCELLED
        await asyncio.sleep(0)
        assert transports[0].closed is True
        final = await manager.get_scan(str(created.id))
        assert final is not None
        assert final.status == ScanStatus.CANCELLED

    asyncio.run(exercise())
