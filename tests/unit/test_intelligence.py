import asyncio
from urllib.parse import urlsplit

import httpx
import pytest

from app.config import ScanLimits
from app.scanning.budget import ScanBudget
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.intelligence import WebsiteIntelligenceEngine
from app.scanning.models import ObservationStatus


class FixtureResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


async def run_profile(
    body: bytes,
    *,
    limits: ScanLimits | None = None,
    handler=None,
    cancel_event: asyncio.Event | None = None,
):
    requests: list[str] = []

    def default_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, content=body)

    transport_handler = handler or default_handler

    def observed_handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return transport_handler(request)

    def factory():
        return BoundedHTTPClient.for_testing(
            limits=limits or ScanLimits(maximum_requests_per_scan=5),
            resolver=FixtureResolver(),
            transport_factory=lambda: httpx.MockTransport(observed_handler),
        )

    configured_limits = limits or ScanLimits(maximum_requests_per_scan=5)
    client = factory()
    budget = ScanBudget(configured_limits, deadline_seconds=2)
    async with client:
        async with budget.attempt():
            initial = await client.get("https://fixture.example/?seed=secret")
        try:
            profile = await WebsiteIntelligenceEngine().scan(
                "https://fixture.example/?seed=secret",
                initial,
                client,
                budget,
                cancel_event=cancel_event,
            )
        finally:
            initial.close()
    return profile, requests, budget


def test_profiles_are_independent_and_do_not_share_discovered_urls():
    async def exercise() -> None:
        first, first_requests, _ = await run_profile(b'<a href="/one">one</a>')
        second, second_requests, _ = await run_profile(b'<a href="/two">two</a>')

        assert [resource.url for resource in first.resources] == ["https://fixture.example/one"]
        assert [resource.url for resource in second.resources] == ["https://fixture.example/two"]
        assert [urlsplit(url).path for url in first_requests] == ["/", "/one"]
        assert [urlsplit(url).path for url in second_requests] == ["/", "/two"]

    asyncio.run(exercise())


def test_discovery_is_same_origin_read_only_and_redacts_query_values():
    async def exercise() -> None:
        body = b"""
            <a href='/page?token=top-secret'>page</a>
            <script src='/app.js?key=another-secret'></script>
            <link rel='stylesheet' href='/site.css?css=secret'>
            <form method='post' action='/submit?password=secret'></form>
            <a href='https://outside.example/exfil?value=secret'>outside</a>
        """

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, headers={"content-type": "text/html"}, content=body)
            return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"child")

        profile, requests, _ = await run_profile(body, handler=handler)
        urls = [resource.url for resource in profile.resources]
        assert "https://outside.example/exfil?value=[redacted]" in urls
        assert all("secret" not in url for url in urls)
        assert all("outside.example" not in request for request in requests)
        assert {urlsplit(request).path for request in requests} == {
            "/",
            "/page",
            "/app.js",
            "/site.css",
        }
        form_resources = [resource for resource in profile.resources if resource.kind == "form"]
        assert len(form_resources) == 1
        assert form_resources[0].status == ObservationStatus.LIMITED
        assert profile.summary.cross_origin_blocked == 1

    asyncio.run(exercise())


def test_limits_and_cancellation_are_scan_wide():
    async def exercise() -> None:
        limits = ScanLimits(maximum_requests_per_scan=2, maximum_pages=2)
        body = b'<a href="/one">one</a><a href="/two">two</a>'
        profile, requests, budget = await run_profile(body, limits=limits)
        assert len(requests) == 2
        assert budget.reserved_requests == 2
        assert profile.summary.pages_scanned == 2
        assert any(resource.status == ObservationStatus.LIMITED for resource in profile.resources)

        cancelled = asyncio.Event()
        cancelled.set()
        with pytest.raises(asyncio.CancelledError):
            await run_profile(body, cancel_event=cancelled)

    asyncio.run(exercise())


def test_malformed_hostile_html_and_partial_child_failure_are_safe():
    async def exercise() -> None:
        secret_body = b"<html><a href='/ok?token=secret'>ok<script src='javascript:alert(1)'>"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/ok":
                raise httpx.ConnectError("controlled optional failure", request=request)
            return httpx.Response(200, headers={"content-type": "text/html"}, content=secret_body)

        profile, _, _ = await run_profile(secret_body, handler=handler)
        serialized = profile.model_dump_json()
        assert "token=secret" not in serialized
        assert "controlled optional failure" not in serialized
        assert "secret" not in serialized
        assert any(resource.status == ObservationStatus.ERROR for resource in profile.resources)
        assert any(observation.kind == "dns.mx" and observation.status == ObservationStatus.UNAVAILABLE
                   for observation in profile.observations)

    asyncio.run(exercise())


def test_child_cross_origin_redirect_is_rejected_without_leaving_scope():
    async def exercise() -> None:
        body = b'<a href="/redirect">redirect</a>'

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, headers={"content-type": "text/html"}, content=body)
            return httpx.Response(
                302,
                headers={"location": "https://outside.example/next?secret=value"},
                request=request,
            )

        profile, requests, _ = await run_profile(body, handler=handler)
        redirect_resources = [resource for resource in profile.resources if resource.kind == "link"]
        assert len(redirect_resources) == 1
        assert redirect_resources[0].status == ObservationStatus.ERROR
        assert all("outside.example" not in request for request in requests)
        assert profile.status == ObservationStatus.INCONCLUSIVE

    asyncio.run(exercise())
