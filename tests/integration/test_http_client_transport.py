import asyncio
import http.server
import ipaddress
import socket
import threading
import time

import httpx
import pytest
from anyio._backends import _asyncio as anyio_asyncio_backend

from app.config import ScanLimits
from app.scanning.http_client import (
    BoundedHTTPClient,
    CrossOriginRedirect,
    RequestDeadlineExceeded,
    ResponseTooLarge,
)


class LoopbackResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("127.0.0.1",)


class TrackingAsyncTransport(httpx.AsyncBaseTransport):
    """Test wrapper proving the real HTTPX transport was closed."""

    def __init__(self) -> None:
        self.inner = httpx.AsyncHTTPTransport(trust_env=False)
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        self.closed = True
        await self.inner.aclose()


def _start_server(handler: type[http.server.BaseHTTPRequestHandler]):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop_server(server: http.server.ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _allow_loopback_only_for_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    # Production destination policy remains unchanged. This replacement exists
    # only so the real socket can be exercised against a local fixture.
    monkeypatch.setattr(
        "app.security.dns.ip_policy.validate_ip_addresses",
        lambda values: tuple(values),
    )


def _client_factory(transports: list[TrackingAsyncTransport]):
    def factory() -> TrackingAsyncTransport:
        transport = TrackingAsyncTransport()
        transports.append(transport)
        return transport

    return factory


def test_real_transport_connects_to_validated_ip_without_logical_dns(
    monkeypatch: pytest.MonkeyPatch,
):
    logical_hostname = "pinning-fixture.example"
    expected_ip = ipaddress.ip_address("127.0.0.1")
    seen_lookups: list[str | None] = []
    peer_addresses: list[str] = []
    host_headers: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            peer_addresses.append(self.client_address[0])
            host_headers.append(self.headers["Host"])
            body = b"real-transport"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server, thread = _start_server(Handler)
    original_getaddrinfo = socket.getaddrinfo

    def guarded_getaddrinfo(host, *args, **kwargs):
        normalized = host.decode("ascii") if isinstance(host, bytes) else host
        seen_lookups.append(normalized)
        if isinstance(normalized, str):
            try:
                address = ipaddress.ip_address(normalized.rstrip("."))
            except ValueError:
                if normalized.rstrip(".").casefold() == logical_hostname:
                    raise AssertionError("transport attempted logical-host DNS resolution")
            else:
                if address == expected_ip:
                    return original_getaddrinfo(host, *args, **kwargs)
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)

    original_backend_getaddrinfo = anyio_asyncio_backend.AsyncIOBackend.getaddrinfo

    async def guarded_backend_getaddrinfo(cls, host, port, **kwargs):
        normalized = host.decode("ascii") if isinstance(host, bytes) else host
        seen_lookups.append(normalized)
        if isinstance(normalized, str):
            candidate = normalized.strip("[]").rstrip(".")
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                if candidate.casefold() == logical_hostname:
                    raise AssertionError("transport attempted logical-host DNS resolution")
            else:
                if address == expected_ip:
                    return await original_backend_getaddrinfo(host, port, **kwargs)
        return await original_backend_getaddrinfo(host, port, **kwargs)

    monkeypatch.setattr(
        anyio_asyncio_backend.AsyncIOBackend,
        "getaddrinfo",
        classmethod(guarded_backend_getaddrinfo),
    )
    _allow_loopback_only_for_fixture(monkeypatch)
    transports: list[TrackingAsyncTransport] = []

    async def exercise() -> None:
        async with BoundedHTTPClient.for_testing(
            resolver=LoopbackResolver(),
            transport_factory=_client_factory(transports),
        ) as client:
            response = await client.get(
                f"http://{logical_hostname}:{server.server_port}/"
            )
            assert response.text == "real-transport"

    try:
        asyncio.run(exercise())
    finally:
        _stop_server(server, thread)

    # Numeric IP literals may bypass getaddrinfo entirely on this asyncio
    # backend; the server-side peer address is the authoritative socket proof.
    assert logical_hostname not in {
        value.rstrip(".").casefold()
        for value in seen_lookups
        if isinstance(value, str)
    }
    assert peer_addresses == [str(expected_ip)]
    assert host_headers == [f"{logical_hostname}:{server.server_port}"]
    assert transports[0].closed is True


def test_real_streaming_limit_closes_transport_and_server_stream(
    monkeypatch: pytest.MonkeyPatch,
):
    total_bytes = 4 * 1024 * 1024
    chunk = b"x" * (64 * 1024)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.server.started.set()
            self.send_response(200)
            self.send_header("Content-Length", str(total_bytes))
            self.end_headers()
            sent = 0
            try:
                while sent < total_bytes:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    sent += len(chunk)
                    self.server.bytes_sent = sent
                    time.sleep(0.002)
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.server.stopped_early = True
            finally:
                self.server.finished.set()

        def log_message(self, *_args) -> None:
            pass

    server, thread = _start_server(Handler)
    server.started = threading.Event()
    server.finished = threading.Event()
    server.bytes_sent = 0
    server.stopped_early = False
    _allow_loopback_only_for_fixture(monkeypatch)
    transports: list[TrackingAsyncTransport] = []

    async def exercise() -> None:
        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_response_bytes=1024),
            resolver=LoopbackResolver(),
            transport_factory=_client_factory(transports),
        ) as client:
            with pytest.raises(ResponseTooLarge):
                await client.get(f"http://fixture.example:{server.server_port}/")

    try:
        asyncio.run(exercise())
        assert server.finished.wait(2)
    finally:
        _stop_server(server, thread)

    assert transports[0].closed is True
    assert server.stopped_early is True
    assert server.bytes_sent < total_bytes


def test_real_socket_deadline_closes_transport_after_slow_headers(
    monkeypatch: pytest.MonkeyPatch,
):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.server.started.set()
            time.sleep(1)
            try:
                self.send_response(200)
                self.end_headers()
            except OSError:
                pass
            finally:
                self.server.finished.set()

        def log_message(self, *_args) -> None:
            pass

    server, thread = _start_server(Handler)
    server.started = threading.Event()
    server.finished = threading.Event()
    _allow_loopback_only_for_fixture(monkeypatch)
    transports: list[TrackingAsyncTransport] = []

    async def exercise() -> None:
        async with BoundedHTTPClient.for_testing(
            limits=ScanLimits(request_timeout_seconds=0.1),
            resolver=LoopbackResolver(),
            transport_factory=_client_factory(transports),
        ) as client:
            with pytest.raises((RequestDeadlineExceeded, httpx.ReadTimeout)):
                await client.get(f"http://fixture.example:{server.server_port}/")

    try:
        asyncio.run(exercise())
        assert server.started.wait(1)
        assert server.finished.wait(2)
    finally:
        _stop_server(server, thread)

    assert transports[0].closed is True


def test_real_socket_cancellation_closes_transport_and_server_stream(
    monkeypatch: pytest.MonkeyPatch,
):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.server.started.set()
            body_chunk = b"y" * 4096
            self.send_response(200)
            self.send_header("Content-Length", str(4 * 1024 * 1024))
            self.end_headers()
            try:
                while True:
                    self.wfile.write(body_chunk)
                    self.wfile.flush()
                    time.sleep(0.01)
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.server.finished.set()

        def log_message(self, *_args) -> None:
            pass

    server, thread = _start_server(Handler)
    server.started = threading.Event()
    server.finished = threading.Event()
    _allow_loopback_only_for_fixture(monkeypatch)
    transports: list[TrackingAsyncTransport] = []

    async def exercise() -> None:
        async with BoundedHTTPClient.for_testing(
            resolver=LoopbackResolver(),
            transport_factory=_client_factory(transports),
        ) as client:
            task = asyncio.create_task(
                client.get(f"http://fixture.example:{server.server_port}/")
            )
            await asyncio.to_thread(server.started.wait, 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    try:
        asyncio.run(exercise())
        assert server.finished.wait(2)
    finally:
        _stop_server(server, thread)

    assert transports[0].closed is True


def test_real_cross_origin_redirect_does_not_make_follow_up_request(
    monkeypatch: pytest.MonkeyPatch,
):
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://other-fixture.example/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args) -> None:
            pass

    server, thread = _start_server(Handler)
    _allow_loopback_only_for_fixture(monkeypatch)
    transports: list[TrackingAsyncTransport] = []

    async def exercise() -> None:
        async with BoundedHTTPClient.for_testing(
            resolver=LoopbackResolver(),
            transport_factory=_client_factory(transports),
        ) as client:
            with pytest.raises(CrossOriginRedirect):
                await client.get(f"http://fixture.example:{server.server_port}/")

    try:
        asyncio.run(exercise())
    finally:
        _stop_server(server, thread)

    assert requests == ["/"]
    assert transports[0].closed is True
