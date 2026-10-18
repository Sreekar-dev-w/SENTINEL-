import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from app.config import ScanLimits
from app.scanning.budget import ScanBudget
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.intelligence import WebsiteIntelligenceEngine
from app.scanning.intelligence_providers import (
    DNSIntelligence,
    HostingIntelligence,
    ProviderState,
)
from app.scanning.models import ObservationStatus
from app.security.network_policy import (
    DestinationNotApproved,
    NetworkAssessmentPolicy,
    NetworkLimitExceeded,
    PortNotPermitted,
    ProhibitedDestination,
)
from app.security.tls import (
    TLSProbeRequest,
    TLSProbeResult,
    TLSProbeStatus,
    collect_tls_metadata,
)


class PublicFixtureResolver:
    async def resolve(self, hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


class ResultProbe:
    def __init__(self, result: TLSProbeResult) -> None:
        self.result = result
        self.requests: list[TLSProbeRequest] = []

    async def probe(self, request: TLSProbeRequest) -> TLSProbeResult:
        self.requests.append(request)
        return self.result


def test_tls_probe_states_are_explicit_and_receive_only_validated_metadata():
    async def exercise() -> None:
        for status in (
            TLSProbeStatus.VALID,
            TLSProbeStatus.INVALID,
            TLSProbeStatus.HANDSHAKE_FAILURE,
            TLSProbeStatus.HOSTNAME_MISMATCH,
        ):
            probe = ResultProbe(
                TLSProbeResult(
                    status=status,
                    verified=status is TLSProbeStatus.VALID,
                    hostname_verified=status is TLSProbeStatus.VALID,
                    handshake_succeeded=status in {TLSProbeStatus.VALID, TLSProbeStatus.HOSTNAME_MISMATCH},
                    subject="CN=fixture.example" if status is TLSProbeStatus.VALID else None,
                    issuer="CN=Fixture CA" if status is TLSProbeStatus.VALID else None,
                    valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc) if status is TLSProbeStatus.VALID else None,
                    expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc) if status is TLSProbeStatus.VALID else None,
                    chain_validated=status is TLSProbeStatus.VALID,
                    protocol="TLSv1.3" if status is TLSProbeStatus.VALID else None,
                )
            )
            result = await collect_tls_metadata(
                "https://fixture.example/",
                resolver=PublicFixtureResolver(),
                probe=probe,
            )
            assert result.status is status
            assert probe.requests[0].hostname == "fixture.example"
            assert probe.requests[0].address == "93.184.216.34"
            assert not hasattr(probe.requests[0], "certificate")
            assert not hasattr(probe.requests[0], "private_key")
            if status is TLSProbeStatus.VALID:
                assert result.subject == "CN=fixture.example"
                assert result.chain_validated is True

        unavailable = await collect_tls_metadata(
            "https://fixture.example/", resolver=PublicFixtureResolver()
        )
        assert unavailable.status is TLSProbeStatus.UNAVAILABLE

    asyncio.run(exercise())


def test_tls_probe_uses_network_policy_for_port_and_destination_at_connection_time():
    async def exercise() -> None:
        probe = ResultProbe(TLSProbeResult(status=TLSProbeStatus.VALID, verified=True))
        policy = NetworkAssessmentPolicy(
            approved_cidrs=("93.184.216.0/24",),
            permitted_ports=(443,),
        )
        result = await collect_tls_metadata(
            "https://fixture.example/",
            resolver=PublicFixtureResolver(),
            probe=probe,
            network_policy=policy,
        )
        assert result.status is TLSProbeStatus.VALID
        assert len(policy.audit_metadata) == 1

        rejected = NetworkAssessmentPolicy(approved_cidrs=("1.1.1.0/24",))
        result = await collect_tls_metadata(
            "https://fixture.example/",
            resolver=PublicFixtureResolver(),
            probe=probe,
            network_policy=rejected,
        )
        assert result.status is TLSProbeStatus.UNAVAILABLE
        assert result.error_code == "policy_rejected"

    asyncio.run(exercise())


def test_network_policy_rejects_private_out_of_scope_prohibited_and_ports():
    policy = NetworkAssessmentPolicy(
        approved_cidrs=("93.184.216.0/24",),
        permitted_ports=(443,),
        prohibited_destinations=("93.184.216.20", "blocked.example"),
    )
    with pytest.raises(DestinationNotApproved):
        policy.validate_destination("10.0.0.5")
    with pytest.raises(DestinationNotApproved):
        policy.validate_destination("1.1.1.1")
    with pytest.raises(ProhibitedDestination):
        policy.validate_destination("93.184.216.20")
    with pytest.raises(ProhibitedDestination):
        policy.validate_destination("93.184.216.21", hostname="blocked.example")
    with pytest.raises(PortNotPermitted):
        policy.validate_connection(
            hostname="fixture.example",
            address="93.184.216.34",
            port=80,
            service_type="http",
        )


def test_network_policy_limits_cancellation_cleanup_and_audit():
    async def exercise() -> None:
        policy = NetworkAssessmentPolicy(
            approved_cidrs=("93.184.216.0/24",),
            max_connections=1,
            max_requests=2,
            per_host_concurrency=1,
        )
        first = await policy.acquire(
            hostname="fixture.example", address="93.184.216.34", port=443, service_type="https"
        )
        cancelled = asyncio.Event()
        waiting = asyncio.create_task(
            policy.acquire(
                hostname="fixture.example",
                address="93.184.216.34",
                port=443,
                service_type="https",
                cancel_event=cancelled,
            )
        )
        await asyncio.sleep(0)
        cancelled.set()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        await first.release()
        with pytest.raises(NetworkLimitExceeded):
            await policy.acquire(
                hostname="fixture.example", address="93.184.216.34", port=443, service_type="https"
            )
        assert len(policy.audit_metadata) == 1
        assert policy.audit_metadata[0].outcome == "completed"

    asyncio.run(exercise())


def test_optional_provider_observations_preserve_dns_and_degrade_explicitly():
    class FakeDNS:
        async def lookup_dns(self, hostname: str) -> DNSIntelligence:
            return DNSIntelligence(
                state=ProviderState.AVAILABLE,
                cname=("edge.example",),
                mx=("mail.example",),
                ns=("ns1.example",),
                txt=("v=spf1 -all",),
                dnssec=True,
                confidence="high",
            )

    class FakeHosting:
        async def lookup_hosting(self, hostname: str, addresses: tuple[str, ...]) -> HostingIntelligence:
            assert addresses == ("93.184.216.34",)
            return HostingIntelligence(
                state=ProviderState.AVAILABLE,
                asn="AS64500",
                network="93.184.216.0/24",
                provider="Example Network",
                cdn="Example CDN",
                reverse_proxy=True,
                waf="Example WAF",
                confidence="medium",
            )

    async def exercise() -> None:
        client = BoundedHTTPClient.for_testing(
            limits=ScanLimits(maximum_requests_per_scan=1),
            resolver=PublicFixtureResolver(),
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok")
            ),
        )
        budget = ScanBudget(ScanLimits(maximum_requests_per_scan=1), deadline_seconds=2)
        async with client:
            async with budget.attempt():
                initial = await client.get("https://fixture.example/")
            try:
                profile = await WebsiteIntelligenceEngine(
                    dns_provider=FakeDNS(), hosting_provider=FakeHosting()
                ).scan("https://fixture.example/", initial, client, budget)
            finally:
                initial.close()
        kinds = {observation.kind for observation in profile.observations}
        assert {"dns.cname", "dns.mx", "dns.ns", "dns.txt", "dns.dnssec"} <= kinds
        assert {"asn.provider", "hosting.network", "hosting.cdn", "hosting.waf"} <= kinds
        assert all(observation.timestamp is not None for observation in profile.observations if observation.kind.startswith("dns.") and observation.kind != "dns.a_aaaa")

        class FailingDNS:
            async def lookup_dns(self, hostname: str) -> DNSIntelligence:
                return DNSIntelligence(state=ProviderState.FAILURE, confidence="low", error_code="timeout")

        client = BoundedHTTPClient.for_testing(
            resolver=PublicFixtureResolver(),
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok")
            ),
        )
        budget = ScanBudget(deadline_seconds=2)
        async with client:
            async with budget.attempt():
                initial = await client.get("https://fixture.example/")
            try:
                degraded = await WebsiteIntelligenceEngine(dns_provider=FailingDNS()).scan(
                    "https://fixture.example/", initial, client, budget
                )
            finally:
                initial.close()
        assert any(observation.kind == "dns.a_aaaa" and observation.status is ObservationStatus.OBSERVED for observation in degraded.observations)
        assert any(observation.kind == "dns.mx" and observation.status is ObservationStatus.ERROR for observation in degraded.observations)
        assert "timeout" in degraded.model_dump_json()
        assert "Authorization" not in degraded.model_dump_json()

    asyncio.run(exercise())
