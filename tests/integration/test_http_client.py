import asyncio

import httpx
import pytest

from app.config import ScanLimits
from app.scanning.http_client import (
    BoundedHTTPClient,
    CrossOriginRedirect,
    HostRequestLimitExceeded,
    RedirectLimitExceeded,
    RedirectLoop,
    ResponseTooLarge,
)
from app.security.ip_policy import UnsafeIPAddress
from app.security.dns import UnsafeDNSResult


SAFE_IP = "93.184.216.34"
SECOND_SAFE_IP = "93.184.216.35"


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    async def resolve(self, hostname):
        self.calls.append(hostname)
        if callable(self.answers):
            return self.answers(len(self.calls))
        return self.answers


def client_for(handler, *, resolver=None, limits=None):
    return BoundedHTTPClient.for_testing(
        limits=limits or ScanLimits(maximum_redirects=4),
        resolver=resolver or FakeResolver((SAFE_IP,)),
        transport_factory=lambda: httpx.MockTransport(handler),
    )


def run(coroutine):
    return asyncio.run(coroutine)


def test_production_constructor_rejects_transport_injection():
    with pytest.raises(TypeError, match="transport"):
        BoundedHTTPClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))

    unsafe_transport = httpx.HTTPTransport(verify=False)
    try:
        with pytest.raises(TypeError, match="transport"):
            BoundedHTTPClient(transport=unsafe_transport)
    finally:
        unsafe_transport.close()


def test_explicit_testing_seam_accepts_mock_transport():
    async def exercise():
        async with BoundedHTTPClient.for_testing(
            resolver=FakeResolver((SAFE_IP,)),
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"test seam")
            ),
        ) as client:
            return await client.get("https://example.com/")

    response = run(exercise())
    assert response.text == "test seam"


def test_revalidates_all_dns_answers_before_connecting():
    resolver = FakeResolver((SAFE_IP, "127.0.0.1"))
    called = []

    def handler(request):
        called.append(request)
        return httpx.Response(200, content=b"should not connect")

    async def exercise():
        async with client_for(handler, resolver=resolver) as client:
            with pytest.raises(UnsafeDNSResult, match="loopback"):
                await client.get("https://example.com/")

    run(exercise())
    assert called == []


def test_revalidates_dns_when_redirect_answer_changes_to_private():
    resolver = FakeResolver(
        lambda call: (SAFE_IP,) if call == 1 else ("169.254.169.254",)
    )
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "/next"})

    async def exercise():
        async with client_for(handler, resolver=resolver) as client:
            with pytest.raises(UnsafeDNSResult, match="cloud metadata"):
                await client.get("https://example.com/")

    run(exercise())
    assert len(requests) == 1
    assert len(resolver.calls) == 2


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest",
    ],
)
def test_rejects_private_and_metadata_ip_literals(url):
    async def exercise():
        async with client_for(lambda request: httpx.Response(200)) as client:
            with pytest.raises(UnsafeIPAddress):
                await client.get(url)

    run(exercise())


def test_rejects_cross_origin_redirect_before_resolving_redirect_host():
    resolver = FakeResolver((SAFE_IP,))

    def handler(request):
        return httpx.Response(302, headers={"location": "https://other.example/"})

    async def exercise():
        async with client_for(handler, resolver=resolver) as client:
            with pytest.raises(CrossOriginRedirect):
                await client.get("https://example.com/")

    run(exercise())
    assert resolver.calls == ["example.com"]


def test_rejects_redirect_loops():
    def handler(request):
        return httpx.Response(302, headers={"location": "/same"})

    async def exercise():
        async with client_for(handler) as client:
            with pytest.raises(RedirectLoop):
                await client.get("https://example.com/same")

    run(exercise())


def test_enforces_redirect_limit():
    def handler(request):
        return httpx.Response(302, headers={"location": "/next"})

    limits = ScanLimits(maximum_redirects=0)
    async def exercise():
        async with client_for(handler, limits=limits) as client:
            with pytest.raises(RedirectLimitExceeded):
                await client.get("https://example.com/")

    run(exercise())


def test_propagates_transport_timeout_with_bounded_timeout():
    def handler(request):
        assert 0 < request.extensions["timeout"]["connect"] <= 0.25
        assert 0 < request.extensions["timeout"]["read"] <= 0.25
        raise httpx.ReadTimeout("controlled timeout", request=request)

    limits = ScanLimits(request_timeout_seconds=0.25)
    async def exercise():
        async with client_for(handler, limits=limits) as client:
            with pytest.raises(httpx.ReadTimeout):
                await client.get("https://example.com/")

    run(exercise())


def test_enforces_response_byte_limit():
    def handler(request):
        return httpx.Response(200, content=b"0123456789")

    limits = ScanLimits(maximum_response_bytes=5)
    async def exercise():
        async with client_for(handler, limits=limits) as client:
            with pytest.raises(ResponseTooLarge):
                await client.get("https://example.com/")

    run(exercise())


def test_enforces_request_limit_per_host_across_redirects():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "/next"})

    limits = ScanLimits(maximum_redirects=2, maximum_requests_per_host=1)
    async def exercise():
        async with client_for(handler, limits=limits) as client:
            with pytest.raises(HostRequestLimitExceeded):
                await client.get("https://example.com/")

    run(exercise())
    assert len(requests) == 1


def test_uses_validated_ip_but_preserves_host_and_https_sni():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    async def exercise():
        async with client_for(handler, resolver=FakeResolver((SECOND_SAFE_IP,))) as client:
            return await client.get("https://Example.com:443/health")

    response = run(exercise())
    assert response.text == "ok"
    assert str(seen[0].url) == "https://93.184.216.35/health"
    assert seen[0].headers["host"] == "example.com"
    assert seen[0].extensions["sni_hostname"] == "example.com"


def test_overrides_caller_host_and_preserves_non_default_origin_port():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    async def exercise():
        async with client_for(handler, resolver=FakeResolver((SECOND_SAFE_IP,))) as client:
            return await client.get(
                "http://Example.com:8080/health",
                headers={"Host": "attacker.example"},
            )

    response = run(exercise())
    assert response.text == "ok"
    assert str(seen[0].url) == "http://93.184.216.35:8080/health"
    assert seen[0].headers["host"] == "example.com:8080"
