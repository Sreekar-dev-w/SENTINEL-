"""Run a controlled, local demonstration of the SENTINEL v0.1 API.

The scan target is never resolved by the operating system and no socket is
opened.  The injected resolver and HTTPX mock transport make the result
repeatable for a judge or a developer running from a clean checkout.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from app.api.app import create_app
from app.config import ScanLimits
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.runner import ScanManager


class ControlledResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        """Return a fixed safe address without performing DNS."""

        return ("93.184.216.34",)


def _client_factory(request_count: list[int]):
    def factory(limits: ScanLimits) -> BoundedHTTPClient:
        def handler(request: httpx.Request) -> httpx.Response:
            request_count[0] += 1
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Set-Cookie": "demo-only=not-retained",
                },
                content=b"controlled fixture body; not retained",
            )

        return BoundedHTTPClient.for_testing(
            limits=limits,
            resolver=ControlledResolver(),
            transport_factory=lambda: httpx.MockTransport(handler),
        )

    return factory


def _print_json(label: str, payload: object) -> None:
    print(label)
    print(json.dumps(payload, indent=2, sort_keys=True))


async def main() -> None:
    request_count = [0]
    manager = ScanManager(
        ScanLimits(scan_timeout_seconds=1),
        client_factory=_client_factory(request_count),
    )
    app = create_app(manager)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://demo.local",
    ) as client:
        print("SENTINEL v0.1 controlled API demonstration")
        print("No public target, DNS lookup, or network socket is used.\n")

        create = await client.post(
            "/scans",
            json={
                "target_url": "https://controlled.fixture/",
                "authorization_confirmed": True,
            },
        )
        assert create.status_code == 202, create.text
        created = create.json()
        scan_id = created["id"]
        _print_json(
            "1) Submit an authorized scan (POST /scans) -> HTTP 202",
            {"id": scan_id, "status": created["status"]},
        )

        observed_states = [created["status"]]
        result: dict[str, object] | None = None
        for _ in range(100):
            response = await client.get(f"/scans/{scan_id}")
            assert response.status_code == 200, response.text
            result = response.json()
            if result["status"] not in observed_states:
                observed_states.append(result["status"])
            if result["status"] == "completed":
                break
            await asyncio.sleep(0)
        else:
            raise AssertionError("controlled scan did not complete")

        assert result is not None
        print("2) Retrieve the completed result (GET /scans/{scan_id}) -> HTTP 200")
        print(f"   lifecycle: {' -> '.join(observed_states)}")
        print(f"   checks: {result['summary']['checks_completed']}/{result['summary']['checks_total']}")
        print(f"   findings: {result['summary']['findings_total']}")
        for finding in result["findings"]:
            print(f"   - {finding['code']}: {finding['title']}")
            print(f"     remediation: {finding['remediation']}")
        print(f"   controlled HTTP requests: {request_count[0]}")
        print("   response body and Set-Cookie were not stored in the result\n")

        invalid = await client.post(
            "/scans",
            json={
                "target_url": "not-a-url",
                "authorization_confirmed": True,
            },
        )
        assert invalid.status_code == 422, invalid.text
        _print_json(
            "3) Reject an invalid target before scanning (POST /scans) -> HTTP 422",
            {"detail": invalid.json()["detail"]},
        )


if __name__ == "__main__":
    asyncio.run(main())
