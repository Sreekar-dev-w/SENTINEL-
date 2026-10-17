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


SAFE_IP = "93.184.216.34"
SECOND_SAFE_IP = "93.184.216.35"


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def resolve(self, hostname):
        self.calls.append(hostname)
        if callable(self.answers):
            return self.answers(len(self.calls))
        return self.answers


def client_for(handler, *, resolver=None, limits=None):
    return BoundedHTTPClient(
        limits=limits or ScanLimits(maximum_redirects=4),
        resolver=resolver or FakeResolver((SAFE_IP,)),
        transport=httpx.MockTransport(handler),
    )


def test_revalidates_all_dns_answers_before_connecting():
    resolver = FakeResolver((SAFE_IP, "127.0.0.1"))
    called = False

    def handler(request):
        nonlocal called
        called = True
        return httpx.Response(200, content=b"should not connect")

    with client_for(handler, resolver=resolver) as client:
        with pytest.raises(UnsafeIPAddress, match="loopback"):
            client.get("https://example.com/")

    assert called is False


def test_revalidates_dns_when_redirect_answer_changes_to_private():
    resolver = FakeResolver(
        lambda call: (SAFE_IP,) if call == 1 else ("169.254.169.254",)
    )
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "/next"})

    with client_for(handler, resolver=resolver) as client:
        with pytest.raises(UnsafeIPAddress, match="cloud metadata"):
            client.get("https://example.com/")

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
    with client_for(lambda request: httpx.Response(200)) as client:
        with pytest.raises(UnsafeIPAddress):
            client.get(url)


def test_rejects_cross_origin_redirect_before_resolving_redirect_host():
    resolver = FakeResolver((SAFE_IP,))

    def handler(request):
        return httpx.Response(302, headers={"location": "https://other.example/"})

    with client_for(handler, resolver=resolver) as client:
        with pytest.raises(CrossOriginRedirect):
            client.get("https://example.com/")

    assert resolver.calls == ["example.com"]


def test_rejects_redirect_loops():
    def handler(request):
        return httpx.Response(302, headers={"location": "/same"})

    with client_for(handler) as client:
        with pytest.raises(RedirectLoop):
            client.get("https://example.com/same")


def test_enforces_redirect_limit():
    def handler(request):
        return httpx.Response(302, headers={"location": "/next"})

    limits = ScanLimits(maximum_redirects=0)
    with client_for(handler, limits=limits) as client:
        with pytest.raises(RedirectLimitExceeded):
            client.get("https://example.com/")


def test_propagates_transport_timeout_with_bounded_timeout():
    def handler(request):
        assert request.extensions["timeout"]["connect"] == 0.25
        assert request.extensions["timeout"]["read"] == 0.25
        raise httpx.ReadTimeout("controlled timeout", request=request)

    limits = ScanLimits(request_timeout_seconds=0.25)
    with client_for(handler, limits=limits) as client:
        with pytest.raises(httpx.ReadTimeout):
            client.get("https://example.com/")


def test_enforces_response_byte_limit():
    def handler(request):
        return httpx.Response(200, content=b"0123456789")

    limits = ScanLimits(maximum_response_bytes=5)
    with client_for(handler, limits=limits) as client:
        with pytest.raises(ResponseTooLarge):
            client.get("https://example.com/")


def test_enforces_request_limit_per_host_across_redirects():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "/next"})

    limits = ScanLimits(maximum_redirects=2, maximum_requests_per_host=1)
    with client_for(handler, limits=limits) as client:
        with pytest.raises(HostRequestLimitExceeded):
            client.get("https://example.com/")

    assert len(requests) == 1


def test_uses_validated_ip_but_preserves_host_and_https_sni():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    with client_for(handler, resolver=FakeResolver((SECOND_SAFE_IP,))) as client:
        response = client.get("https://Example.com:443/health")

    assert response.text == "ok"
    assert str(seen[0].url) == "https://93.184.216.35/health"
    assert seen[0].headers["host"] == "example.com"
    assert seen[0].extensions["sni_hostname"] == "example.com"


def test_overrides_caller_host_and_preserves_non_default_origin_port():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    with client_for(handler, resolver=FakeResolver((SECOND_SAFE_IP,))) as client:
        response = client.get(
            "http://Example.com:8080/health",
            headers={"Host": "attacker.example"},
        )

    assert response.text == "ok"
    assert str(seen[0].url) == "http://93.184.216.35:8080/health"
    assert seen[0].headers["host"] == "example.com:8080"
