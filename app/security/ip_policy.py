"""IPv4/IPv6 destination safety policy for SENTINEL.

The policy is intentionally deny-by-default for non-global destinations. DNS
resolution and redirect handling will call this policy again in later phases.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Iterable


CLOUD_METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",  # Common cloud instance metadata endpoint.
        "169.254.170.2",  # ECS task metadata endpoint.
        "fd00:ec2::254",  # AWS IPv6 instance metadata endpoint.
    }
)


class UnsafeIPAddress(ValueError):
    """Raised when an address is not safe for an authorized scan."""

    def __init__(self, address: str, reason: str) -> None:
        self.address = address
        self.reason = reason
        super().__init__(f"unsafe destination {address!r}: {reason}")


@dataclass(frozen=True, slots=True)
class IPAssessment:
    address: str
    safe: bool
    reason: str | None = None


def _parse_ip(value: str) -> IPv4Address | IPv6Address:
    if not isinstance(value, str) or not value:
        raise ValueError("IP address must be a non-empty string")
    if any(character.isspace() for character in value) or "%" in value:
        raise ValueError("IP address contains whitespace or a zone identifier")
    try:
        return ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def unsafe_reason(value: str) -> str | None:
    """Return a stable rejection reason, or ``None`` for a global address."""

    address = _parse_ip(value)
    canonical = str(address).lower()

    if canonical in CLOUD_METADATA_ADDRESSES:
        return "cloud metadata address"

    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        mapped_reason = unsafe_reason(str(address.ipv4_mapped))
        if mapped_reason is not None:
            return f"IPv4-mapped IPv6 address: {mapped_reason}"

    if address.is_unspecified:
        return "unspecified address"
    if address.is_loopback:
        return "loopback address"
    if address.is_private:
        return "private address"
    if address.is_link_local:
        return "link-local address"
    if address.is_multicast:
        return "multicast address"
    if address.is_reserved:
        return "reserved address"
    if not address.is_global:
        return "non-global address"
    return None


def assess_ip(value: str) -> IPAssessment:
    """Assess a single address without raising for policy rejection."""

    try:
        reason = unsafe_reason(value)
    except ValueError as exc:
        return IPAssessment(address=value, safe=False, reason=str(exc))
    return IPAssessment(address=value, safe=reason is None, reason=reason)


def validate_ip(value: str) -> str:
    """Return the canonical IP string or raise ``UnsafeIPAddress``."""

    address = _parse_ip(value)
    reason = unsafe_reason(str(address))
    if reason is not None:
        raise UnsafeIPAddress(str(address), reason)
    return str(address)


def validate_ip_addresses(values: Iterable[str]) -> tuple[str, ...]:
    """Validate all resolved addresses and return canonical values.

    An empty resolution result is rejected because a caller must never treat a
    failed or empty DNS response as authorization to connect elsewhere.
    """

    canonical = tuple(validate_ip(value) for value in values)
    if not canonical:
        raise ValueError("at least one resolved IP address is required")
    return canonical
