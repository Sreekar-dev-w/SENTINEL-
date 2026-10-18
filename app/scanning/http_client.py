"""Bounded, same-origin HTTP requests for authorized scanning.

The client owns redirect handling so every hop goes through URL, origin, DNS,
IP-policy, timeout, response-size, and request-budget checks. It never gives
httpx a hostname to resolve: the transport URL always contains the selected
validated IP literal while the logical Host header and HTTPS SNI remain the
target hostname.
"""

from __future__ import annotations

import asyncio
import threading
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
from app.security.ip_policy import validate_ip
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


class PortNotAllowed(BoundedHTTPError):
    """The target port is outside the explicit scan scope."""


class RequestDeadlineExceeded(BoundedHTTPError):
    """The complete top-level request exceeded its monotonic deadline."""


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
    """An asynchronous GET-only client with strict network safety bounds.

    The resolver is injectable for deterministic tests. The default transport is
    HTTPX's normal transport with certificate verification left enabled; custom
    transports are available only through the explicit test seam.
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
        if not self.limits.allowed_ports or any(not 1 <= port <= 65535 for port in self.limits.allowed_ports):
            raise ValueError("allowed_ports must contain valid ports")

        self.resolver = resolver or SystemDNSResolver()
        self._headers = dict(headers or {})
        self._requests_per_host: Counter[str] = Counter()
        self._request_budget_lock = threading.Lock()
        self._test_transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None
        self._closed = False

    @classmethod
    def for_testing(
        cls,
        *,
        transport_factory: Callable[[], httpx.AsyncBaseTransport],
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

    async def __aenter__(self) -> "BoundedHTTPClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def _new_client(self) -> httpx.AsyncClient:
        """Create a pool scoped to one top-level logical request."""

        client_kwargs: dict[str, object] = {
            "follow_redirects": False,
            "timeout": httpx.Timeout(self.limits.request_timeout_seconds),
            "trust_env": False,
            "verify": True,
        }
        if self._test_transport_factory is not None:
            client_kwargs["transport"] = self._test_transport_factory()
        return httpx.AsyncClient(**client_kwargs)

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Perform a bounded GET, manually following safe redirects."""

        if self._closed:
            raise RuntimeError("BoundedHTTPClient is closed")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.limits.request_timeout_seconds
        try:
            async with asyncio.timeout_at(deadline):
                return await self._get_until_deadline(url, headers, deadline)
        except TimeoutError as exc:
            raise RequestDeadlineExceeded(
                f"request exceeded {self.limits.request_timeout_seconds} seconds"
            ) from exc

    async def _get_until_deadline(
        self,
        url: str,
        headers: Mapping[str, str] | None,
        deadline: float,
    ) -> httpx.Response:
        current = normalize_target_url(url)
        self._ensure_allowed_port(current.port)
        initial_origin = current.origin
        visited: set[str] = set()
        history: list[httpx.Response] = []

        merged_headers = dict(self._headers)
        if headers:
            merged_headers.update(headers)

        redirects = 0
        async with self._new_client() as client:
            while True:
                self._raise_if_expired(deadline)
                if current.url in visited:
                    raise RedirectLoop(f"redirect loop detected at {current.url}")
                visited.add(current.url)

                response = await self._request_once(
                    client, current, merged_headers, deadline
                )
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
                self._ensure_allowed_port(next_target.port)
                if next_target.url in visited:
                    response.close()
                    raise RedirectLoop(f"redirect loop detected at {next_target.url}")

                history.append(response)
                current = next_target
                redirects += 1

    @staticmethod
    def _raise_if_expired(deadline: float) -> None:
        if asyncio.get_running_loop().time() >= deadline:
            raise RequestDeadlineExceeded("request deadline expired")

    async def _request_once(
        self,
        client: httpx.AsyncClient,
        target: NormalizedURL,
        headers: Mapping[str, str],
        deadline: float,
    ) -> httpx.Response:
        # Reserve before DNS so failures, cancellation, and retries cannot
        # evade the per-host request budget. The lock covers only this
        # check-and-increment; no await or I/O occurs while it is held.
        self._reserve_request(target.hostname)
        destination = await self._resolve_destination(target.hostname, deadline)

        # Never accept a caller-supplied Host header. The logical authority is
        # part of the same-origin policy and must remain the normalized target,
        # while the connection URL below contains only the validated address.
        safe_headers = {key: value for key, value in headers.items() if key.lower() != "host"}
        safe_headers["Host"] = _host_header(target)
        logical_request = httpx.Request("GET", target.url, headers=safe_headers)
        extensions = dict(logical_request.extensions)
        remaining = self._remaining(deadline)
        extensions["timeout"] = httpx.Timeout(remaining).as_dict()
        if target.scheme == "https":
            extensions["sni_hostname"] = target.hostname
        connection_request = httpx.Request(
            "GET",
            _connection_url(target, destination.selected_address),
            headers=logical_request.headers,
            extensions=extensions,
        )

        response = await client.send(
            connection_request,
            stream=True,
            follow_redirects=False,
        )
        try:
            body = await self._read_bounded_body(response, deadline)
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                content=body,
                request=logical_request,
                extensions=response.extensions,
            )
        finally:
            await response.aclose()

    def _reserve_request(self, hostname: str) -> None:
        with self._request_budget_lock:
            if self._requests_per_host[hostname] >= self.limits.maximum_requests_per_host:
                raise HostRequestLimitExceeded(
                    f"request limit exceeded for host {hostname!r}"
                )
            self._requests_per_host[hostname] += 1

    def _ensure_allowed_port(self, port: int) -> None:
        # The explicit mock/loopback transport seam is used by deterministic
        # tests that bind ephemeral ports. Production clients remain limited to
        # the configured scope.
        if self._test_transport_factory is not None:
            return
        if port not in self.limits.allowed_ports:
            raise PortNotAllowed(f"port {port} is outside the configured scan scope")

    async def _read_bounded_body(
        self,
        response: httpx.Response,
        deadline: float,
    ) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            self._raise_if_expired(deadline)
            total += len(chunk)
            if total > self.limits.maximum_response_bytes:
                raise ResponseTooLarge(
                    "response body exceeds "
                    f"{self.limits.maximum_response_bytes} bytes"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    async def _resolve_destination(
        self,
        hostname: str,
        deadline: float,
    ) -> ValidatedDestination:
        """Resolve through the async DNS boundary before connection."""

        try:
            literal = ip_address(hostname)
        except ValueError:
            remaining = self._remaining(deadline)
            try:
                return await asyncio.wait_for(
                    resolve_validated_destination(hostname, self.resolver),
                    timeout=remaining,
                )
            except asyncio.TimeoutError as exc:
                raise RequestDeadlineExceeded("DNS resolution exceeded the request deadline") from exc

        return ValidatedDestination(hostname=hostname, addresses=(validate_ip(str(literal)),))

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise RequestDeadlineExceeded("request deadline expired")
        return remaining


# Names that make the policy boundary discoverable to callers using either
# "bounded" or "safe" terminology.
SafeHTTPClient = BoundedHTTPClient
HTTPClient = BoundedHTTPClient
