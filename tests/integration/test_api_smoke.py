import asyncio

import httpx

from app.api.app import create_app
from app.config import ScanLimits
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.runner import ScanManager


class SafeResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


def test_api_smoke_starts_and_retrieves_a_controlled_scan():
    async def exercise() -> None:
        def factory(limits: ScanLimits) -> BoundedHTTPClient:
            return BoundedHTTPClient.for_testing(
                limits=limits,
                resolver=SafeResolver(),
                transport_factory=lambda: httpx.MockTransport(
                    lambda request: httpx.Response(
                        200,
                        headers={"Content-Type": "text/plain"},
                        content=b"controlled fixture",
                    )
                ),
            )

        manager = ScanManager(
            ScanLimits(scan_timeout_seconds=1),
            client_factory=factory,
        )
        app = create_app(manager)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            created = await client.post(
                "/scans",
                json={
                    "target_url": "https://controlled.fixture/",
                    "authorization_confirmed": True,
                },
            )
            assert created.status_code == 202
            scan_id = created.json()["id"]

            for _ in range(100):
                result = await client.get(f"/scans/{scan_id}")
                assert result.status_code == 200
                if result.json()["status"] == "completed":
                    assert result.json()["summary"]["findings_total"] == 3
                    assert result.json()["intelligence"]["status"] in {
                        "observed",
                        "inconclusive",
                    }
                    assert result.json()["assessment"]["status"] == "partial"
                    assert result.json()["assessment"]["coverage"]["total_modules"] == 9
                    return
                await asyncio.sleep(0)

        raise AssertionError("controlled API scan did not complete")

    asyncio.run(exercise())
