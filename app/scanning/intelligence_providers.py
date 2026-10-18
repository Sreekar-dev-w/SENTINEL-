"""Optional, metadata-only DNS and hosting attribution provider interfaces.

Providers are dependency-free protocols.  The engine passes a hostname and
validated address metadata only; it never sends page content, request bodies,
cookies, authorization material, or credentials to a provider.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol, Sequence, runtime_checkable


class ProviderState(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class DNSIntelligence:
    state: ProviderState = ProviderState.UNAVAILABLE
    cname: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    ns: tuple[str, ...] = ()
    txt: tuple[str, ...] = ()
    dnssec: bool | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: str = "medium"
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class HostingIntelligence:
    state: ProviderState = ProviderState.UNAVAILABLE
    asn: str | None = None
    network: str | None = None
    provider: str | None = None
    cdn: str | None = None
    reverse_proxy: bool | None = None
    waf: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: str = "medium"
    error_code: str | None = None


@runtime_checkable
class DNSIntelligenceProvider(Protocol):
    async def lookup_dns(self, hostname: str) -> DNSIntelligence:
        """Return bounded DNS metadata for ``hostname`` only."""


@runtime_checkable
class HostingIntelligenceProvider(Protocol):
    async def lookup_hosting(self, hostname: str, addresses: Sequence[str]) -> HostingIntelligence:
        """Return attribution metadata for a hostname and validated addresses."""


@runtime_checkable
class DNSHostingIntelligenceProvider(Protocol):
    async def lookup_dns(self, hostname: str) -> DNSIntelligence:
        """Return DNS metadata without receiving application content."""

    async def lookup_hosting(self, hostname: str, addresses: Sequence[str]) -> HostingIntelligence:
        """Return hosting metadata for validated addresses only."""


@dataclass(frozen=True, slots=True)
class UnavailableDNSProvider:
    async def lookup_dns(self, hostname: str) -> DNSIntelligence:
        return DNSIntelligence()


@dataclass(frozen=True, slots=True)
class UnavailableHostingProvider:
    async def lookup_hosting(self, hostname: str, addresses: Sequence[str]) -> HostingIntelligence:
        return HostingIntelligence()


# Compatibility names for callers that call this capability "enrichment".
DNSProvider = DNSIntelligenceProvider
HostingProvider = HostingIntelligenceProvider
DNSRecordEnrichment = DNSIntelligence
HostingAttribution = HostingIntelligence
DNSHostingProvider = DNSHostingIntelligenceProvider
DNSProviderResult = DNSIntelligence
HostingProviderResult = HostingIntelligence
