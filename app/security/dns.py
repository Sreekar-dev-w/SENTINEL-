"""Async DNS resolution with destination-policy enforcement.

This module deliberately stops at validated IP addresses.  It does not open
connections or implement an HTTP client.  Callers should resolve a hostname
through :func:`resolve_destination` immediately before any future connection
and treat the returned addresses as the complete, currently-authorized set.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

from app.security import ip_policy


class DNSResolutionError(RuntimeError):
    """Base error for lookup, result-shape, and destination-policy failures."""


class DNSLookupError(DNSResolutionError):
    """The system resolver could not obtain a DNS answer."""


class InvalidDNSResult(DNSResolutionError):
    """A resolver returned an empty, malformed, or otherwise invalid result."""


class UnsafeDNSResult(DNSResolutionError):
    """At least one resolved address failed the destination safety policy."""


class EmptyDNSResult(InvalidDNSResult):
    """A resolver returned no addresses."""


@dataclass(frozen=True, slots=True)
class ValidatedDestination:
    """The complete canonical address set authorized for one hostname."""

    hostname: str
    addresses: tuple[str, ...]

    @property
    def ips(self) -> tuple[str, ...]:
        """Compatibility-friendly name for the canonical address set."""

        return self.addresses

    @property
    def selected_address(self) -> str:
        """Return the first stable address for callers that need one choice."""

        return self.addresses[0]


# This name reads naturally at call sites and keeps the result type explicit.
ResolvedDestination = ValidatedDestination


@runtime_checkable
class AsyncResolver(Protocol):
    """Injectable async source of raw A/AAAA address strings."""

    async def resolve(self, hostname: str) -> Sequence[str]:
        """Return every address currently reported for ``hostname``."""


class SystemResolver:
    """Resolve A and AAAA records through the host's ``getaddrinfo``."""

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        """Return raw IPv4/IPv6 address strings from the system resolver."""

        try:
            records = await asyncio.to_thread(
                socket.getaddrinfo,
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise DNSLookupError(f"DNS lookup failed for {hostname!r}: {exc}") from exc
        except OSError as exc:
            raise DNSLookupError(f"DNS lookup failed for {hostname!r}: {exc}") from exc

        addresses: list[str] = []
        for record in records:
            try:
                sockaddr = record[4]
                address = sockaddr[0]
            except (IndexError, KeyError, TypeError) as exc:
                raise InvalidDNSResult(
                    f"system resolver returned a malformed record for {hostname!r}"
                ) from exc
            addresses.append(address)
        return tuple(addresses)


# A descriptive alias for callers that prefer the implementation's full name.
SystemDNSResolver = SystemResolver
DNSResolver = AsyncResolver


def _validate_hostname(hostname: str) -> None:
    if not isinstance(hostname, str) or not hostname:
        raise InvalidDNSResult("hostname must be a non-empty string")
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in hostname):
        raise InvalidDNSResult("hostname must not contain whitespace or control characters")


async def resolve_destination(
    hostname: str,
    resolver: AsyncResolver | None = None,
) -> ValidatedDestination:
    """Resolve and validate all current addresses for ``hostname``.

    ``resolver`` is injectable so tests and callers with a controlled DNS
    source can deterministically supply changing answers.  Every returned
    value goes through :func:`validate_ip_addresses`; only after validation are
    canonical duplicates removed.  A single unsafe or invalid answer rejects
    the complete resolution set.
    """

    _validate_hostname(hostname)
    source = resolver if resolver is not None else SystemResolver()

    try:
        raw_addresses = await source.resolve(hostname)
    except DNSResolutionError:
        raise
    except Exception as exc:
        raise DNSLookupError(f"resolver failed for {hostname!r}: {exc}") from exc

    if raw_addresses is None or isinstance(raw_addresses, (str, bytes)):
        raise InvalidDNSResult("resolver must return an iterable of IP addresses")
    try:
        values = tuple(raw_addresses)
    except (TypeError, ValueError) as exc:
        raise InvalidDNSResult("resolver must return an iterable of IP addresses") from exc
    if not values:
        raise EmptyDNSResult(f"resolver returned no addresses for {hostname!r}")

    try:
        canonical = ip_policy.validate_ip_addresses(values)
    except ip_policy.UnsafeIPAddress as exc:
        raise UnsafeDNSResult(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise InvalidDNSResult(str(exc)) from exc

    # Preserve resolver order while removing equivalent textual forms.
    unique_addresses = tuple(dict.fromkeys(canonical))
    if not unique_addresses:
        # Defensive guard in case the policy implementation changes.
        raise EmptyDNSResult(f"resolver returned no addresses for {hostname!r}")
    return ValidatedDestination(hostname=hostname, addresses=unique_addresses)


async def resolve_hostname(
    hostname: str,
    resolver: AsyncResolver | None = None,
) -> ValidatedDestination:
    """Alias for :func:`resolve_destination` for hostname-oriented call sites."""

    return await resolve_destination(hostname, resolver)


async def resolve_validated_destination(
    hostname: str,
    resolver: AsyncResolver | None = None,
) -> ValidatedDestination:
    """Compatibility alias for :func:`resolve_destination`."""

    return await resolve_destination(hostname, resolver)


class ValidatingResolver:
    """Adapter that exposes validated destinations over an injected resolver."""

    def __init__(self, resolver: AsyncResolver | None = None) -> None:
        self._resolver = resolver if resolver is not None else SystemResolver()

    async def resolve(self, hostname: str) -> ValidatedDestination:
        return await resolve_destination(hostname, self._resolver)
