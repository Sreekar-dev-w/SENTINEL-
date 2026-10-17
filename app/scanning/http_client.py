"""Bounded, same-origin HTTP requests for authorized scanning.

The client owns redirect handling so every hop goes through URL, origin, DNS,
IP-policy, timeout, response-size, and request-budget checks. It never gives
httpx a hostname to resolve: the transport URL always contains the selected
validated IP literal while the logical Host header and HTTPS SNI remain the
target hostname.
"""

from __future__ import annotations

import asyncio
import inspect
from collections import Counter
from ipaddress import ip_address
from typing import Callable, Mapping
from urllib.parse import urljoin, urlunsplit

import httpx

from app.config import ScanLimits
from app.security.dns import (
    DNSResolver,
    SystemDNSResolver,
    ValidatedDestination,
    resolve_validated_destination,
)
from app.security.ip_policy import validate_ip, validate_ip_addresses
from app.security.url_validation import NormalizedURL, URLValidationError, normalize_target_url


class BoundedHTTPError(RuntimeError):
    """Base class for policy failures raised by :class:`BoundedHTTPClient`."""


class CrossOriginRedirect(BoundedHTTPError):
    """A redirect target is outside the initial normalized origin."""


class RedirectLoop(BoundedHTTPError):
    """A redirect would revisit a URL already requested."""


class RedirectLimitExceeded(BoundedHTTPError):
    """The configured maximum number of redirects would be exceeded."""


class ResponseTooLarge(BoundedHTTPError):
    """The response body exceeded ``ScanLimits.maximum_response_bytes``."""


class HostRequestLimitExceeded(BoundedHTTPError):
    """The per-host request budget has been exhausted."""


def _connection_url(target: NormalizedURL, address: str) -> str:
    """Build a URL addressed to an approved IP at the target's port."""

    display_address = f"[{address}]" if ":" in address else address
    authority = display_address
    default_port = 443 if target.scheme == "https" else 80
    if target.port != default_port:
        authority = f"{authority}:{target.port}"
    return urlunsplit((target.scheme, authority, target.path, target.query, ""))


def _host_header(target: NormalizedURL) -> str:
    """Return the logical authority that must reach the origin server."""

    hostname = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    default_port = 443 if target.scheme == "https" else 80
    if target.port == default_port:
        return hostname
    return f"{hostname}:{target.port}"


class BoundedHTTPClient:
    """A synchronous GET-only client with strict network safety bounds.

    ``transport`` and ``resolver`` are injectable for deterministic tests and
    for callers that provide an approved network boundary. The default
    transport is httpx's normal transport with certificate verification left
    enabled.
    """

    def __init__(
        self,
        limits: ScanLimits | None = None,
        *,
        resolver: DNSResolver | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.limits = limits or ScanLimits()
        if self.limits.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be greater than zero")
        if self.limits.maximum_response_bytes < 0:
            raise ValueError("maximum_response_bytes must not be negative")
        if self.limits.maximum_redirects < 0:
            raise ValueError("maximum_redirects must not be negative")
        if self.limits.maximum_requests_per_host < 0:
            raise ValueError("maximum_requests_per_host must not be negative")

        self.resolver = resolver or SystemDNSResolver()
        self._headers = dict(headers or {})
        self._requests_per_host: Counter[str] = Counter()
        self._test_transport_factory: Callable[[], httpx.BaseTransport] | None = None
        self._closed = False

    @classmethod
    def for_testing(
        cls,
        *,
        transport_factory: Callable[[], httpx.BaseTransport],
        limits: ScanLimits | None = None,
        resolver: DNSResolver | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> "BoundedHTTPClient":
        """Create a client with an explicit test-only transport seam.

        Production callers must use the normal constructor, which never accepts
        an HTTPX transport. The factory returns a fresh transport for each
        top-level request so tests cannot accidentally share a pool across
        logical origins.
        """

        if not callable(transport_factory):
            raise TypeError("transport_factory must be callable")
        instance = cls(limits=limits, resolver=resolver, headers=headers)
        instance._test_transport_factory = transport_factory
        return instance

    def __enter__(self) -> "BoundedHTTPClient":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def _new_client(self) -> httpx.Client:
        """Create a pool scoped to one top-level logical request."""

        client_kwargs: dict[str, object] = {
            "follow_redirects": False,
            "timeout": httpx.Timeout(self.limits.request_timeout_seconds),
            "trust_env": False,
            "verify": True,
        }
        if self._test_transport_factory is not None:
            client_kwargs["transport"] = self._test_transport_factory()
        return httpx.Client(**client_kwargs)

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> httpx.Response:
        """Perform a bounded GET, manually following safe redirects."""

        if self._closed:
            raise RuntimeError("BoundedHTTPClient is closed")

        current = normalize_target_url(url)
        initial_origin = current.origin
        visited: set[str] = set()
        history: list[httpx.Response] = []

        merged_headers = dict(self._headers)
        if headers:
            merged_headers.update(headers)

        redirects = 0
        with self._new_client() as client:
            while True:
                if current.url in visited:
                    raise RedirectLoop(f"redirect loop detected at {current.url}")
                visited.add(current.url)

                response = self._request_once(client, current, merged_headers)
                response.history = list(history)
                if not response.is_redirect:
                    return response

                location = response.headers.get("location")
                if location is None:
                    return response
                if redirects >= self.limits.maximum_redirects:
                    response.close()
                    raise RedirectLimitExceeded(
                        f"redirect limit exceeded after {redirects} redirects"
                    )

                try:
                    redirect_url = urljoin(current.url, location)
                    next_target = normalize_target_url(redirect_url)
                except (TypeError, ValueError, URLValidationError) as exc:
                    response.close()
                    raise BoundedHTTPError(
                        f"invalid redirect location: {location!r}"
                    ) from exc

                if next_target.origin != initial_origin:
                    response.close()
                    raise CrossOriginRedirect(
                        f"redirect from {initial_origin} to {next_target.origin} is not allowed"
                    )
                if next_target.url in visited:
                    response.close()
                    raise RedirectLoop(f"redirect loop detected at {next_target.url}")

                history.append(response)
                current = next_target
                redirects += 1

    def _request_once(
        self,
        client: httpx.Client,
        target: NormalizedURL,
        headers: Mapping[str, str],
    ) -> httpx.Response:
        destination = self._resolve_destination(target.hostname)
        host_key = target.hostname
        if self._requests_per_host[host_key] >= self.limits.maximum_requests_per_host:
            raise HostRequestLimitExceeded(
                f"request limit exceeded for host {host_key!r}"
            )
        self._requests_per_host[host_key] += 1

        # Never accept a caller-supplied Host header. The logical authority is
        # part of the same-origin policy and must remain the normalized target,
        # while the connection URL below contains only the validated address.
        safe_headers = {key: value for key, value in headers.items() if key.lower() != "host"}
        safe_headers["Host"] = _host_header(target)
        logical_request = httpx.Request("GET", target.url, headers=safe_headers)
        extensions = dict(logical_request.extensions)
        if target.scheme == "https":
            extensions["sni_hostname"] = target.hostname
        connection_request = httpx.Request(
            "GET",
            _connection_url(target, destination.selected_address),
            headers=logical_request.headers,
            extensions=extensions,
        )

        response = client.send(
            connection_request,
            stream=True,
            follow_redirects=False,
        )
        try:
            body = self._read_bounded_body(response)
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                content=body,
                request=logical_request,
                extensions=response.extensions,
            )
        finally:
            response.close()

    def _read_bounded_body(self, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self.limits.maximum_response_bytes:
                raise ResponseTooLarge(
                    "response body exceeds "
                    f"{self.limits.maximum_response_bytes} bytes"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    def _resolve_destination(self, hostname: str) -> ValidatedDestination:
        """Resolve through the planned async DNS boundary or a sync fixture."""

        try:
            literal = ip_address(hostname)
        except ValueError:
            resolver_method = getattr(self.resolver, "resolve")
            if inspect.iscoroutinefunction(resolver_method):
                # The public client is synchronous; keep the async DNS
                # interface deterministic by completing it before transport.
                return asyncio.run(
                    resolve_validated_destination(hostname, self.resolver)
                )

            raw_addresses = resolver_method(hostname)
            addresses = validate_ip_addresses(raw_addresses)
            return ValidatedDestination(hostname=hostname, addresses=addresses)

        return ValidatedDestination(hostname=hostname, addresses=(validate_ip(str(literal)),))


# Names that make the policy boundary discoverable to callers using either
# "bounded" or "safe" terminology.
SafeHTTPClient = BoundedHTTPClient
HTTPClient = BoundedHTTPClient
