import asyncio

import httpx
import pytest

from app.config import ScanLimits
from app.scanning.http_client import (
    BoundedHTTPClient,
    HostRequestLimitExceeded,
)
from app.security.dns import DNSLookupError


SAFE_IP = "93.184.216.34"


class SafeResolver:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        return (SAFE_IP,)


class FailingResolver(SafeResolver):
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        raise DNSLookupError("controlled DNS failure")


class CountingTransport(httpx.AsyncBaseTransport):
    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.requests = 0
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        return httpx.Response(200, content=b"ok", request=request)

    async def aclose(self) -> None:
        self.closed = True


class FailingTransport(CountingTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        raise httpx.ConnectError("controlled transport failure", request=request)


class RedirectTransport(CountingTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        return httpx.Response(
            302,
            headers={"location": "/next"},
            content=b"",
            request=request,
        )


class BlockingTransport(CountingTransport):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        self.started.set()
        await asyncio.sleep(60)
        return httpx.Response(200, content=b"never", request=request)


def test_concurrent_requests_never_exceed_limit_one():
    async def exercise() -> None:
        resolver = SafeResolver()
        transports: list[CountingTransport] = []

        def factory() -> CountingTransport:
            transport = CountingTransport(delay=0.02)
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=1),
            resolver=resolver,
            transport_factory=factory,
        ) as client:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *(client.get("https://example.com/") for _ in range(20)),
                    return_exceptions=True,
                ),
                timeout=1,
            )

        assert sum(isinstance(result, httpx.Response) for result in results) == 1
        assert sum(isinstance(result, HostRequestLimitExceeded) for result in results) == 19
        assert sum(transport.requests for transport in transports) == 1

    asyncio.run(exercise())


def test_concurrent_requests_admit_only_configured_larger_limit():
    async def exercise() -> None:
        transports: list[CountingTransport] = []

        def factory() -> CountingTransport:
            transport = CountingTransport(delay=0.02)
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=3),
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *(client.get("https://example.com/") for _ in range(10)),
                    return_exceptions=True,
                ),
                timeout=1,
            )

        assert sum(isinstance(result, httpx.Response) for result in results) == 3
        assert sum(isinstance(result, HostRequestLimitExceeded) for result in results) == 7
        assert sum(transport.requests for transport in transports) == 3

    asyncio.run(exercise())


def test_redirect_follow_up_requires_a_new_budget_reservation():
    async def exercise() -> None:
        transports: list[RedirectTransport] = []

        def factory() -> RedirectTransport:
            transport = RedirectTransport()
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=1),
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            with pytest.raises(HostRequestLimitExceeded):
                await client.get("https://example.com/")

        assert transports[0].requests == 1

    asyncio.run(exercise())


def test_dns_failure_consumes_budget_before_resolution_retry():
    async def exercise() -> None:
        resolver = FailingResolver()
        transports: list[CountingTransport] = []

        def factory() -> CountingTransport:
            transport = CountingTransport()
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=1),
            resolver=resolver,
            transport_factory=factory,
        ) as client:
            with pytest.raises(DNSLookupError):
                await client.get("https://example.com/")
            with pytest.raises(HostRequestLimitExceeded):
                await client.get("https://example.com/")

        assert resolver.calls == ["example.com"]
        assert len(transports) == 2
        assert all(transport.requests == 0 for transport in transports)

    asyncio.run(exercise())


def test_transport_failure_consumes_budget_before_retry():
    async def exercise() -> None:
        transports: list[FailingTransport] = []

        def factory() -> FailingTransport:
            transport = FailingTransport()
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=1),
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            with pytest.raises(httpx.ConnectError):
                await client.get("https://example.com/")
            with pytest.raises(HostRequestLimitExceeded):
                await client.get("https://example.com/")

        assert len(transports) == 2
        assert sum(transport.requests for transport in transports) == 1
        assert transports[0].requests == 1

    asyncio.run(exercise())


def test_cancellation_after_reservation_consumes_budget():
    async def exercise() -> None:
        transports: list[BlockingTransport] = []

        def factory() -> BlockingTransport:
            transport = BlockingTransport()
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=1),
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            task = asyncio.create_task(client.get("https://example.com/"))
            while not transports:
                await asyncio.sleep(0)
            await transports[0].started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(HostRequestLimitExceeded):
                await client.get("https://example.com/")

        assert transports[0].closed is True

    asyncio.run(exercise())


def test_request_budgets_are_isolated_by_logical_hostname():
    async def exercise() -> None:
        resolver = SafeResolver()
        transports: list[CountingTransport] = []

        def factory() -> CountingTransport:
            transport = CountingTransport()
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_host=1),
            resolver=resolver,
            transport_factory=factory,
        ) as client:
            results = await asyncio.gather(
                client.get("https://alpha.example/"),
                client.get("https://beta.example/"),
                return_exceptions=True,
            )

        assert all(isinstance(result, httpx.Response) for result in results)
        assert sorted(resolver.calls) == ["alpha.example", "beta.example"]
        assert sum(transport.requests for transport in transports) == 2

    asyncio.run(exercise())
