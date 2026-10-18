from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
from app.api.models import CreateScanRequest

from app.config import ScanLimits
from app.engagement import Engagement
from app.persistence import SnapshotDatabase
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.runner import ScanManager


class Resolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


def client_factory(limits: ScanLimits):
    return BoundedHTTPClient.for_testing(
        limits=limits,
        resolver=Resolver(),
        transport_factory=lambda: httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-type": "text/html"}, request=request)
        ),
    )


def test_terminal_scan_and_engagement_survive_manager_recreation(tmp_path: Path):
    async def exercise():
        database_path = tmp_path / "sentinel.sqlite3"
        with SnapshotDatabase(database_path) as database:
            first = ScanManager(
                ScanLimits(maximum_requests_per_scan=2),
                client_factory=client_factory,
                enable_intelligence=False,
                state_database=database,
            )
            engagement = await first.engagement_store.create(
                Engagement(target_domains=("authorized.example",), authorization_reference="PERSIST-1")
            )
            created = await first.create_scan(CreateScanRequest(
                target_url="https://authorized.example/",
                engagement_id=engagement.id,
                authorization_confirmed=True,
            ))
            for _ in range(100):
                scan = await first.get_scan(str(created.id))
                if scan is not None and scan.status.value in {"completed", "failed", "cancelled"}:
                    break
                await asyncio.sleep(0)
            assert scan is not None and scan.status.value == "completed"

        with SnapshotDatabase(database_path) as database:
            second = ScanManager(state_database=database, enable_intelligence=False)
            restored_scan = await second.get_scan(str(created.id))
            restored_engagement = await second.engagement_store.get(engagement.id)
            assert restored_scan is not None
            assert restored_scan.status.value == "completed"
            assert restored_scan.summary.checks_completed == 4
            assert restored_engagement is not None
            assert restored_engagement.authorization_reference == "PERSIST-1"

    asyncio.run(exercise())


def test_interrupted_running_snapshot_is_marked_failed_on_restart(tmp_path: Path):
    async def exercise():
        path = tmp_path / "sentinel.sqlite3"
        with SnapshotDatabase(path) as database:
            manager = ScanManager(state_database=database, enable_intelligence=False)
            scan = await manager.store.create("https://authorized.example/")
            from app.scanning.models import ScanStatus
            await manager.store.transition(scan.id, ScanStatus.RUNNING)
        with SnapshotDatabase(path) as database:
            restored = ScanManager(state_database=database, enable_intelligence=False)
            scan = await restored.get_scan(str(scan.id))
            assert scan is not None
            assert scan.status.value == "failed"
            assert "application restart" in (scan.error or "")

    asyncio.run(exercise())
