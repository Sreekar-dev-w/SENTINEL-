"""Deterministic process-runner tests for optional Nmap/testssl adapters."""

from __future__ import annotations

import asyncio

from app.engagement import Engagement, EngagementScopePolicy
from app.external_tools import (
    AdapterExecutionRequest,
    AdapterScope,
    ExecutionState,
    NMAP_DISCOVERY_CAPABILITY,
    NMAP_SERVICE_CAPABILITY,
    NmapAdapter,
    ProcessResult,
    TESTSSL_CAPABILITY,
    TestSSLAdapter,
)


TARGET = "https://authorized.example/"


def _scope(*capabilities: str, ports=(443,)) -> AdapterScope:
    engagement = Engagement(
        target_domains=("authorized.example",),
        permitted_ports=ports,
        permitted_service_types=("https",),
        allowed_capabilities=capabilities,
        authorization_reference="fake-process-test",
    )
    return AdapterScope(engagement.id, EngagementScopePolicy(engagement))


class FakeRunner:
    def __init__(self, result: ProcessResult):
        self.result = result
        self.argv = None

    async def run(self, argv, **kwargs):
        self.argv = tuple(argv)
        return self.result


def _request(scope, **kwargs):
    return AdapterExecutionRequest(
        TARGET,
        scope=scope,
        infrastructure_authorized=True,
        active_testing_authorized=True,
        **kwargs,
    )


def test_nmap_scope_denial_and_argument_array_are_explicit():
    async def exercise():
        denied_runner = FakeRunner(ProcessResult(0, b""))
        denied = await NmapAdapter(denied_runner).execute(
            _request(_scope(), mode="service_detection", ports=(443,))
        )
        runner = FakeRunner(
            ProcessResult(
                0,
                b'<nmaprun version="7.95"><host><status state="up"/></host></nmaprun>',
            )
        )
        result = await NmapAdapter(runner).execute(
            _request(_scope(NMAP_DISCOVERY_CAPABILITY, NMAP_SERVICE_CAPABILITY), mode="service_detection", ports=(443,))
        )
        return denied, runner, result

    denied, runner, result = asyncio.run(exercise())
    assert denied.state == ExecutionState.REJECTED
    assert runner.argv == ("nmap", "-n", "-Pn", "-sV", "--version-light", "-p", "443", "-oX", "-", "authorized.example")
    assert result.state == ExecutionState.COMPLETED
    assert result.findings == ()
    assert result.tool.tool_version == "7.95"


def test_nmap_xml_becomes_observations_not_vulnerability_findings():
    payload = b"""<nmaprun version="7.94"><host><status state="up"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>"""
    runner = FakeRunner(ProcessResult(0, payload))
    result = asyncio.run(
        NmapAdapter(runner).execute(_request(_scope(NMAP_DISCOVERY_CAPABILITY), mode="discovery"))
    )
    assert result.state == ExecutionState.COMPLETED
    assert {observation.kind for observation in result.observations} == {"host", "port"}
    assert result.findings == ()
    assert result.observations[1].provenance.tool_version == "7.94"


def test_testssl_json_normalizes_findings_and_ok_checks_separately():
    payload = b'''[{"id":"tls1_3","severity":"OK","finding":"offered"},{"id":"heartbleed","severity":"HIGH","finding":"vulnerable","solution":"upgrade"}]'''
    runner = FakeRunner(ProcessResult(0, payload))
    result = asyncio.run(
        TestSSLAdapter(runner).execute(
            _request(_scope(TESTSSL_CAPABILITY), mode="tls", output_format="json")
        )
    )
    assert result.state == ExecutionState.COMPLETED
    assert len(result.observations) == 2
    assert [finding.rule_id for finding in result.findings] == ["heartbleed"]
    assert result.findings[0].provenance.api_version == "json"
    assert runner.argv[-2:] == ("-", TARGET)


def test_testssl_csv_machine_output_and_scope_port_gate():
    runner = FakeRunner(ProcessResult(0, b"id,severity,finding\nprotocols,OK,TLS enabled\n"))
    result = asyncio.run(
        TestSSLAdapter(runner, output_format="csv").execute(
            _request(_scope(TESTSSL_CAPABILITY), mode="tls", output_format="csv")
        )
    )
    assert result.state == ExecutionState.COMPLETED
    assert result.observations[0].key == "protocols"
    assert runner.argv[4:6] == ("--csvfile", "-")


def test_testssl_ansi_version_banner_is_detected():
    banner = b"\x1b[1mtestssl.sh\x1b[0m version \x1b[1m3.2.4\x1b[0m"
    assert TestSSLAdapter._version(banner) == "3.2.4"


def test_missing_nonzero_malformed_oversized_timeout_and_cancel_states():
    async def exercise():
        missing = FakeRunner(ProcessResult(127, b""))
        # Raising FileNotFoundError models an unavailable executable; a nonzero
        # ProcessResult remains a distinct tool failure.
        async def unavailable(*args, **kwargs):
            raise FileNotFoundError("nmap")
        missing.run = unavailable
        missing_result = await NmapAdapter(missing).execute(_request(_scope(NMAP_DISCOVERY_CAPABILITY)))
        nonzero = await NmapAdapter(FakeRunner(ProcessResult(2, b'<nmaprun version="7.95"><host><status state="up"/></host></nmaprun>'))).execute(
            _request(_scope(NMAP_DISCOVERY_CAPABILITY))
        )
        malformed = await TestSSLAdapter(FakeRunner(ProcessResult(0, b"not-json"))).execute(
            _request(_scope(TESTSSL_CAPABILITY))
        )
        oversized = await TestSSLAdapter(FakeRunner(ProcessResult(0, b"x", output_limited=True))).execute(
            _request(_scope(TESTSSL_CAPABILITY))
        )
        timeout = await NmapAdapter(FakeRunner(ProcessResult(None, timed_out=True))).execute(
            _request(_scope(NMAP_DISCOVERY_CAPABILITY))
        )
        cancelled = await TestSSLAdapter(FakeRunner(ProcessResult(None, cancelled=True))).execute(
            _request(_scope(TESTSSL_CAPABILITY))
        )
        return missing_result, nonzero, malformed, oversized, timeout, cancelled

    results = asyncio.run(exercise())
    assert results[0].state == ExecutionState.UNAVAILABLE
    assert results[1].state == ExecutionState.PARTIAL
    assert results[1].diagnostics[0].code == "nonzero_exit"
    assert results[2].diagnostics[0].code == "malformed_output"
    assert results[3].diagnostics[0].code == "output_limit"
    assert results[4].diagnostics[0].code == "timeout"
    assert results[5].state == ExecutionState.CANCELLED
