import asyncio

import httpx
import pytest

from app.config import ScanLimits
from app.scanning.http_client import BoundedHTTPClient, RequestDeadlineExceeded


SAFE_IP = "93.184.216.34"


class SlowResolver:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        self.started.set()
        await asyncio.sleep(60)
        return (SAFE_IP,)


class SafeResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return (SAFE_IP,)


class SlowStream(httpx.AsyncByteStream):
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.started = asyncio.Event()
        self.closed = False

    async def __aiter__(self):
        self.started.set()
        yield b"first"
        await asyncio.sleep(self.delay)
        yield b"second"

    async def aclose(self) -> None:
        self.closed = True


class StreamingTransport(httpx.AsyncBaseTransport):
    def __init__(self, stream: SlowStream) -> None:
        self.stream = stream
        self.requests = 0
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        return httpx.Response(200, stream=self.stream, request=request)

    async def aclose(self) -> None:
        self.closed = True


class RedirectThenStreamTransport(StreamingTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.requests == 1:
            return httpx.Response(
                302,
                headers={"location": "/next"},
                content=b"",
                request=request,
            )
        return httpx.Response(200, stream=self.stream, request=request)


def test_slow_dns_is_bounded_without_contacting_transport():
    async def exercise() -> None:
        resolver = SlowResolver()
        transport_calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            transport_calls.append(request)
            return httpx.Response(200, content=b"unexpected")

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(request_timeout_seconds=0.03),
            resolver=resolver,
            transport_factory=lambda: httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(RequestDeadlineExceeded):
                await client.get("https://example.com/")

        assert resolver.started.is_set()
        assert transport_calls == []

    asyncio.run(exercise())


def test_total_deadline_covers_response_stream_and_closes_resources():
    async def exercise() -> None:
        stream = SlowStream(delay=60)
        transports: list[StreamingTransport] = []

        def factory() -> StreamingTransport:
            transport = StreamingTransport(stream)
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(request_timeout_seconds=0.03),
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            with pytest.raises(RequestDeadlineExceeded):
                await client.get("https://example.com/")

        assert stream.closed is True
        assert transports[0].closed is True
        assert transports[0].requests == 1

    asyncio.run(exercise())


def test_total_deadline_is_not_reset_by_redirects():
    async def exercise() -> None:
        stream = SlowStream(delay=60)
        transports: list[RedirectThenStreamTransport] = []

        def factory() -> RedirectThenStreamTransport:
            transport = RedirectThenStreamTransport(stream)
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(request_timeout_seconds=0.03),
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            with pytest.raises(RequestDeadlineExceeded):
                await client.get("https://example.com/")

        assert stream.closed is True
        assert transports[0].closed is True
        assert transports[0].requests == 2

    asyncio.run(exercise())


def test_cancellation_preserves_cancelled_error_and_closes_resources():
    async def exercise() -> None:
        stream = SlowStream(delay=60)
        transports: list[StreamingTransport] = []

        def factory() -> StreamingTransport:
            transport = StreamingTransport(stream)
            transports.append(transport)
            return transport

        async with BoundedHTTPClient.for_testing(
            resolver=SafeResolver(),
            transport_factory=factory,
        ) as client:
            task = asyncio.create_task(client.get("https://example.com/"))
            await stream.started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert stream.closed is True
        assert transports[0].closed is True

    asyncio.run(exercise())
