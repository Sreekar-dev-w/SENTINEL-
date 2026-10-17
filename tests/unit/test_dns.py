import pytest
import asyncio

from app.security.dns import (
    AsyncResolver,
    DNSLookupError,
    EmptyDNSResult,
    InvalidDNSResult,
    SystemResolver,
    UnsafeDNSResult,
    ValidatedDestination,
    resolve_destination,
)


class FakeResolver:
    def __init__(self, *answers: list[str]) -> None:
        self.answers = iter(answers)

    async def resolve(self, hostname: str) -> list[str]:
        return next(self.answers)


def test_fake_resolver_is_a_deterministic_async_resolver():
    resolver = FakeResolver(["8.8.8.8"], ["2001:4860:4860::8888"])

    assert isinstance(resolver, AsyncResolver)

    async def exercise() -> None:
        first = await resolve_destination("example.test", resolver)
        second = await resolve_destination("example.test", resolver)
        assert first == ValidatedDestination("example.test", ("8.8.8.8",))
        assert second == ValidatedDestination("example.test", ("2001:4860:4860::8888",))

    asyncio.run(exercise())


def test_accepts_safe_ipv4_and_ipv6_and_deduplicates_canonically():
    result = asyncio.run(
        resolve_destination(
            "example.test",
            FakeResolver(["8.8.8.8", "2001:4860:4860::8888", "8.8.8.8"]),
        )
    )

    assert result.addresses == ("8.8.8.8", "2001:4860:4860::8888")
    assert result.ips == result.addresses


def test_deduplicates_equivalent_ipv6_spellings_after_policy_canonicalization():
    result = asyncio.run(
        resolve_destination(
            "example.test",
            FakeResolver(["2001:4860:4860::8888", "2001:4860:4860:0:0:0:0:8888"]),
        )
    )

    assert result.addresses == ("2001:4860:4860::8888",)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "192.168.1.20",
        "169.254.169.254",
        "fd00:ec2::254",
        "::1",
    ],
)
def test_rejects_private_link_local_metadata_and_loopback_results(address):
    with pytest.raises(UnsafeDNSResult):
        asyncio.run(resolve_destination("example.test", FakeResolver([address])))


def test_rejects_empty_results():
    with pytest.raises(EmptyDNSResult):
        asyncio.run(resolve_destination("example.test", FakeResolver([])))


def test_rejects_invalid_results():
    with pytest.raises(InvalidDNSResult):
        asyncio.run(resolve_destination("example.test", FakeResolver(["not-an-ip"])))


def test_system_resolver_requests_ipv4_and_ipv6_with_getaddrinfo(monkeypatch):
    calls = []

    def fake_getaddrinfo(hostname, service, family, type):
        calls.append((hostname, service, family, type))
        return [
            (2, 1, 6, "", ("8.8.8.8", 0)),
            (10, 1, 6, "", ("2001:4860:4860::8888", 0, 0, 0)),
        ]

    monkeypatch.setattr("app.security.dns.socket.getaddrinfo", fake_getaddrinfo)
    addresses = asyncio.run(SystemResolver().resolve("example.test"))

    assert addresses == ("8.8.8.8", "2001:4860:4860::8888")
    assert calls == [("example.test", None, 0, 1)]


def test_system_resolver_reports_lookup_failures_explicitly(monkeypatch):
    def fake_getaddrinfo(*args):
        raise OSError("resolver unavailable")

    monkeypatch.setattr("app.security.dns.socket.getaddrinfo", fake_getaddrinfo)

    with pytest.raises(DNSLookupError, match="resolver unavailable"):
        asyncio.run(resolve_destination("example.test"))
