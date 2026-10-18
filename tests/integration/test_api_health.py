import asyncio

import httpx

from app.api.app import create_app
from app.scanning.runner import ScanManager


def test_health_and_readiness_endpoints_report_service_state():
    async def exercise() -> None:
        app = create_app(ScanManager())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            assert health.json() == {"status": "ok"}

            ready = await client.get("/readyz")
            assert ready.status_code == 200
            assert ready.json() == {"status": "ready"}

            app.state.scan_manager = None
            not_ready = await client.get("/readyz")
            assert not_ready.status_code == 503
            assert not_ready.json() == {"detail": "Application services are not ready"}

    asyncio.run(exercise())
