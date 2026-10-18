"""Server-side intersection policy for engagement target scope."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

from app.engagement.models import Engagement
from app.security.ip_policy import UnsafeIPAddress, validate_ip
from app.security.url_validation import NormalizedURL, URLValidationError, normalize_target_url


class EngagementPolicyError(ValueError):
    """Base class for a rejected engagement-scoped operation."""


class EngagementScopeViolation(EngagementPolicyError):
    """The host, route, destination, port, or capability is outside scope."""


def _host_matches(hostname: str, entries: tuple[str, ...]) -> bool:
    host = hostname.casefold().rstrip(".")
    for entry in entries:
        candidate = entry.casefold().rstrip(".")
        if candidate.startswith("*."):
            candidate = candidate[2:]
            if host.endswith("." + candidate):
                return True
        elif host == candidate or host.endswith("." + candidate):
            return True
    return False


class EngagementScopePolicy:
    """Apply one engagement's scope to URLs, DNS answers, and connections."""

    def __init__(self, engagement: Engagement) -> None:
        self.engagement = engagement
        self._target_networks = tuple(
            ip_network(value, strict=False)
            for value in (*engagement.target_ips, *engagement.target_cidrs)
        )
        self._excluded_networks = tuple(
            ip_network(value, strict=False) for value in engagement.excluded_addresses
        )

    def _require_active(self) -> None:
        if not self.engagement.is_active():
            raise EngagementScopeViolation(
                f"engagement {self.engagement.id} is {self.engagement.effective_status().value}"
            )

    def _route_excluded(self, target: NormalizedURL) -> bool:
        for route in self.engagement.excluded_routes:
            candidate = route.strip()
            if "://" in candidate:
                try:
                    excluded = normalize_target_url(candidate)
                except URLValidationError:
                    continue
                if excluded.origin != target.origin:
                    continue
                candidate = excluded.path
            else:
                candidate = urlsplit(candidate).path or candidate
            candidate = candidate.rstrip("/") or "/"
            path = target.path.rstrip("/") or "/"
            if path == candidate or path.startswith(candidate + "/"):
                return True
        return False

    def validate_url(self, url: str | NormalizedURL) -> NormalizedURL:
        self._require_active()
        try:
            target = url if isinstance(url, NormalizedURL) else normalize_target_url(url)
        except (TypeError, ValueError, URLValidationError) as exc:
            raise EngagementScopeViolation("target URL is invalid") from exc
        if target.hostname in self.engagement.excluded_hosts or _host_matches(target.hostname, self.engagement.excluded_hosts):
            raise EngagementScopeViolation(f"hostname {target.hostname!r} is excluded")
        if target.port not in self.engagement.permitted_ports:
            raise EngagementScopeViolation(f"port {target.port} is not permitted by engagement")
        if target.scheme.casefold() not in self.engagement.permitted_service_types:
            raise EngagementScopeViolation(f"service type {target.scheme!r} is not permitted by engagement")
        if self._route_excluded(target):
            raise EngagementScopeViolation(f"route {target.path!r} is excluded")

        if target.is_ip_literal:
            if not self._target_networks:
                raise EngagementScopeViolation("IP literal is not in an engagement IP/CIDR scope")
            self.validate_destination(target.hostname, hostname=target.hostname, port=target.port, service_type=target.scheme)
        elif self.engagement.target_domains and not _host_matches(target.hostname, self.engagement.target_domains):
            raise EngagementScopeViolation(f"hostname {target.hostname!r} is outside engagement domains")
        return target

    def validate_destination(
        self,
        address: str,
        *,
        hostname: str,
        port: int | None = None,
        service_type: str | None = None,
    ) -> str:
        self._require_active()
        try:
            canonical = validate_ip(address)
            parsed = ip_address(canonical)
        except (UnsafeIPAddress, ValueError) as exc:
            raise EngagementScopeViolation(str(exc)) from exc
        if _host_matches(hostname, self.engagement.excluded_hosts):
            raise EngagementScopeViolation(f"hostname {hostname!r} is excluded")
        if any(parsed in network for network in self._excluded_networks):
            raise EngagementScopeViolation(f"destination {canonical!r} is excluded")
        if self._target_networks and not any(parsed in network for network in self._target_networks):
            raise EngagementScopeViolation(f"destination {canonical!r} is outside engagement networks")
        if port is not None:
            self._validate_port_service(port, service_type)
        return canonical

    def _validate_port_service(self, port: int, service_type: str | None) -> None:
        if port not in self.engagement.permitted_ports:
            raise EngagementScopeViolation(f"port {port} is not permitted by engagement")
        if service_type is not None and service_type.casefold() not in self.engagement.permitted_service_types:
            raise EngagementScopeViolation(f"service type {service_type!r} is not permitted by engagement")

    def validate_connection(self, *, hostname: str, address: str, port: int, service_type: str) -> str:
        self._require_active()
        if _host_matches(hostname, self.engagement.excluded_hosts):
            raise EngagementScopeViolation(f"hostname {hostname!r} is excluded")
        try:
            host_is_ip = bool(ip_address(hostname))
        except ValueError:
            host_is_ip = False
        if not host_is_ip and self.engagement.target_domains and not _host_matches(
            hostname, self.engagement.target_domains
        ):
            raise EngagementScopeViolation(f"hostname {hostname!r} is outside engagement domains")
        return self.validate_destination(
            address, hostname=hostname, port=port, service_type=service_type
        )

    authorize_url = validate_url
    authorize_connection = validate_connection
    validate_target_url = validate_url
    validate_dns_destination = validate_destination
    allows_url = validate_url

    def allows_profile(self, profile: str) -> bool:
        self._require_active()
        return not self.engagement.allowed_assessment_profiles or profile in self.engagement.allowed_assessment_profiles

    def allows_capability(self, capability: str) -> bool:
        self._require_active()
        return not self.engagement.allowed_capabilities or capability in self.engagement.allowed_capabilities

    def validate_profile(self, profile: str) -> str:
        if not self.allows_profile(profile):
            raise EngagementScopeViolation(f"assessment profile {profile!r} is not permitted")
        return profile

    def validate_capability(self, capability: str) -> str:
        if not self.allows_capability(capability):
            raise EngagementScopeViolation(f"capability {capability!r} is not permitted")
        return capability

    def effective_limits(self, limits):
        return self.engagement.budgets.apply(limits)
