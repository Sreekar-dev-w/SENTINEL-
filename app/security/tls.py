"""Narrow TLS metadata seam for controlled, metadata-only assessments.

The production default is explicitly unavailable.  A caller may inject a
probe, usually a deterministic test double or a separately reviewed adapter.
The probe receives only a validated destination and connection metadata; it
never receives response content, credentials, certificate bytes, or private
keys.  HTTPS by itself is never treated as proof of TLS validity.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.security.dns import ValidatedDestination, resolve_destination
from app.security.ip_policy import validate_ip
from app.security.network_policy import NetworkAssessmentPolicy, NetworkPolicyError
from app.security.url_validation import NormalizedURL, normalize_target_url


class TLSProbeStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    HANDSHAKE_FAILURE = "handshake_failure"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class TLSProbeRequest(BaseModel):
    """Safe input to an injected probe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    address: str
    port: int = Field(ge=1, le=65535)
    scheme: str = "https"


class TLSProbeResult(BaseModel):
    """Safe TLS metadata; raw certificates and keys cannot be represented."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: TLSProbeStatus
    verified: bool | None = None
    hostname_verified: bool | None = None
    handshake_succeeded: bool | None = None
    subject: str | None = Field(default=None, max_length=512)
    issuer: str | None = Field(default=None, max_length=512)
    valid_from: datetime | None = None
    expires_at: datetime | None = None
    chain_validated: bool | None = None
    protocol: str | None = Field(default=None, max_length=64)
    cipher: str | None = Field(default=None, max_length=128)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: str = "high"
    error_code: str | None = Field(default=None, max_length=128)


@runtime_checkable
class TLSMetadataProbe(Protocol):
    async def probe(self, request: TLSProbeRequest) -> TLSProbeResult:
        """Return metadata from one already-authorized TLS connection."""


class UnavailableTLSProbe:
    """Default no-network probe used when no TLS source is configured."""

    async def probe(self, request: TLSProbeRequest) -> TLSProbeResult:
        return TLSProbeResult(status=TLSProbeStatus.UNAVAILABLE, confidence="low")


def _request_for(target: NormalizedURL, address: str) -> TLSProbeRequest:
    return TLSProbeRequest(
        hostname=target.hostname,
        address=address,
        port=target.port,
        scheme=target.scheme,
    )


async def collect_tls_metadata(
    target_url: str,
    *,
    resolver=None,
    probe: TLSMetadataProbe | None = None,
    network_policy: NetworkAssessmentPolicy | None = None,
    cancel_event: asyncio.Event | None = None,
) -> TLSProbeResult:
    """Resolve, authorize, and invoke one injected TLS metadata probe.

    Destination validation occurs immediately before the probe call.  With no
    explicit ``network_policy``, the existing HTTP port scope (80/443) is used
    by the caller; this helper itself only permits HTTPS and port 443 by
    default, so it cannot broaden the normal HTTP profile.
    """

    target = normalize_target_url(target_url)
    if target.scheme != "https":
        return TLSProbeResult(status=TLSProbeStatus.UNAVAILABLE, confidence="low", error_code="https_required")
    if probe is None:
        return await UnavailableTLSProbe().probe(_request_for(target, target.hostname))
    if cancel_event is not None and cancel_event.is_set():
        raise asyncio.CancelledError
    if target.port != 443 and network_policy is None:
        return TLSProbeResult(status=TLSProbeStatus.UNAVAILABLE, confidence="low", error_code="port_not_permitted")

    try:
        try:
            literal = validate_ip(target.hostname)
            destination = ValidatedDestination(target.hostname, (literal,))
        except ValueError:
            destination = await resolve_destination(target.hostname, resolver)
    except Exception:
        return TLSProbeResult(status=TLSProbeStatus.UNAVAILABLE, confidence="low", error_code="dns_unavailable")

    address = destination.selected_address
    try:
        if network_policy is not None:
            lease = await network_policy.acquire(
                hostname=target.hostname,
                address=address,
                port=target.port,
                service_type="tls",
                cancel_event=cancel_event,
            )
            try:
                result = await _probe_with_deadline(network_policy, probe, _request_for(target, address))
            finally:
                await lease.release()
        else:
            if target.port != 443:
                return TLSProbeResult(status=TLSProbeStatus.UNAVAILABLE, confidence="low", error_code="port_not_permitted")
            result = await probe.probe(_request_for(target, address))
    except asyncio.CancelledError:
        raise
    except NetworkPolicyError:
        return TLSProbeResult(status=TLSProbeStatus.UNAVAILABLE, confidence="low", error_code="policy_rejected")
    except Exception:
        return TLSProbeResult(status=TLSProbeStatus.ERROR, confidence="low", error_code="probe_failure")
    return result


async def _probe_with_deadline(
    policy: NetworkAssessmentPolicy,
    probe: TLSMetadataProbe,
    request: TLSProbeRequest,
) -> TLSProbeResult:
    """Keep an injected TLS operation inside the separate network deadline."""

    remaining = policy.remaining_seconds
    if remaining is None:
        return await probe.probe(request)
    try:
        async with asyncio.timeout(remaining):
            return await probe.probe(request)
    except TimeoutError as exc:
        raise NetworkPolicyError("TLS probe deadline expired") from exc


# Friendly aliases for embedding callers.
TLSProbe = TLSMetadataProbe
TLSMetadataProvider = TLSMetadataProbe
TLSMetadata = TLSProbeResult
TLSMetadataResult = TLSProbeResult
TLSProbeOutcome = TLSProbeStatus
