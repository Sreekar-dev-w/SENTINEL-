"""Explicit policy and accounting for controlled network assessments.

This module is deliberately a policy boundary, not a scanner.  It authorizes a
single already-resolved connection, applies bounded accounting, and returns a
lease that callers must close.  It never creates sockets, enumerates ports, or
accepts application payloads.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from threading import Lock
from typing import AsyncIterator, Iterable

from app.security.ip_policy import UnsafeIPAddress, validate_ip


class NetworkPolicyError(RuntimeError):
    """Base class for controlled network policy failures."""


class DestinationNotApproved(NetworkPolicyError):
    """A validated destination is outside the explicitly approved CIDRs."""


class ProhibitedDestination(NetworkPolicyError):
    """A destination or hostname is explicitly prohibited."""


class PortNotPermitted(NetworkPolicyError):
    """The requested port is outside the permitted service scope."""


class ServiceTypeNotPermitted(NetworkPolicyError):
    """The requested service type is outside the permitted scope."""


class NetworkLimitExceeded(NetworkPolicyError):
    """A request, connection, concurrency, rate, or deadline limit was hit."""


@dataclass(frozen=True, slots=True)
class NetworkAuditMetadata:
    """Safe metadata for one policy decision; no payload or credentials."""

    operation: str
    hostname: str
    address: str
    port: int
    service_type: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    outcome: str = "authorized"
    reason: str | None = None


@dataclass(slots=True)
class NetworkLease:
    """A held bounded connection slot."""

    policy: "NetworkAssessmentPolicy"
    metadata: NetworkAuditMetadata
    _host_key: str
    _released: bool = False

    async def __aenter__(self) -> "NetworkLease":
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.release(outcome="cancelled" if exc_type is asyncio.CancelledError else "error" if exc_type else "completed")

    async def release(self, *, outcome: str = "completed", reason: str | None = None) -> None:
        if self._released:
            return
        self._released = True
        self.policy._release(self, outcome=outcome, reason=reason)


class NetworkAssessmentPolicy:
    """Allow only explicitly bounded, already-resolved network connections.

    ``approved_cidrs`` is optional for compatibility with the existing global
    destination policy.  When supplied, an address must pass both the existing
    ``validate_ip`` policy and one of these CIDRs.  This object does not perform
    DNS, open sockets, scan ports, or send data.
    """

    def __init__(
        self,
        *,
        approved_cidrs: Iterable[str | IPv4Network | IPv6Network] = (),
        permitted_ports: Iterable[int] = (80, 443),
        permitted_service_types: Iterable[str] = ("http", "https", "tls"),
        prohibited_destinations: Iterable[str | IPv4Network | IPv6Network] = (),
        max_connections: int = 4,
        max_requests: int = 50,
        deadline_seconds: float | None = 30.0,
        per_host_concurrency: int = 4,
        rate_limit_per_host: float | None = None,
        operation: str = "network-assessment",
        approved_ips: Iterable[str | IPv4Network | IPv6Network] | None = None,
        allowed_ports: Iterable[int] | None = None,
        service_types: Iterable[str] | None = None,
        request_limit: int | None = None,
        connection_limit: int | None = None,
        per_host_rate_limit: float | None = None,
    ) -> None:
        if connection_limit is not None:
            max_connections = connection_limit
        if request_limit is not None:
            max_requests = request_limit
        if per_host_rate_limit is not None:
            rate_limit_per_host = per_host_rate_limit
        if approved_ips is not None:
            approved_cidrs = approved_ips
        if allowed_ports is not None:
            permitted_ports = allowed_ports
        if service_types is not None:
            permitted_service_types = service_types
        if max_connections <= 0 or per_host_concurrency <= 0:
            raise ValueError("connection limits must be greater than zero")
        if max_requests < 0:
            raise ValueError("max_requests must not be negative")
        if deadline_seconds is not None and deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be greater than zero")
        if rate_limit_per_host is not None and rate_limit_per_host <= 0:
            raise ValueError("rate_limit_per_host must be greater than zero")
        ports = tuple(permitted_ports)
        if not ports or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("permitted_ports must contain valid ports")
        services = tuple(str(value).lower() for value in permitted_service_types)
        if not services:
            raise ValueError("permitted_service_types must not be empty")

        self.approved_cidrs = tuple(self._network(value) for value in approved_cidrs)
        if not self.approved_cidrs:
            raise ValueError("approved_cidrs must contain at least one explicit range")
        self.permitted_ports = frozenset(ports)
        self.permitted_service_types = frozenset(services)
        self.prohibited_destinations = tuple(self._destination(value) for value in prohibited_destinations)
        self.max_connections = max_connections
        self.max_requests = max_requests
        self.deadline_seconds = deadline_seconds
        self.per_host_concurrency = per_host_concurrency
        self.rate_limit_per_host = rate_limit_per_host
        self.operation = operation
        self._requests = 0
        self._request_lock = Lock()
        self._connections = asyncio.Semaphore(max_connections)
        self._host_semaphores: dict[str, asyncio.Semaphore] = {}
        self._host_lock = Lock()
        self._last_host_request: dict[str, float] = {}
        self._audit: list[NetworkAuditMetadata] = []
        self._audit_lock = Lock()
        self._closed = False
        self._deadline = time.monotonic() + deadline_seconds if deadline_seconds is not None else None

    @staticmethod
    def _network(value: str | IPv4Network | IPv6Network) -> IPv4Network | IPv6Network:
        try:
            return ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid approved CIDR: {value!r}") from exc

    @staticmethod
    def _destination(value: str | IPv4Network | IPv6Network):
        if isinstance(value, (IPv4Network, IPv6Network)):
            return value
        try:
            return ip_network(value, strict=False)
        except ValueError:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("prohibited destination must be an IP, CIDR, or hostname")
            return value.casefold().rstrip(".")

    @property
    def requests_used(self) -> int:
        with self._request_lock:
            return self._requests

    @property
    def remaining_seconds(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    @property
    def approved_networks(self):
        return self.approved_cidrs

    @property
    def allowed_ports(self):
        return self.permitted_ports

    @property
    def audit_metadata(self) -> tuple[NetworkAuditMetadata, ...]:
        with self._audit_lock:
            return tuple(self._audit)

    def _check_deadline(self) -> None:
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise NetworkLimitExceeded("network assessment deadline expired")

    def validate_destination(self, address: str, *, hostname: str | None = None) -> str:
        try:
            canonical = validate_ip(address)
        except (UnsafeIPAddress, ValueError) as exc:
            raise DestinationNotApproved(str(exc)) from exc
        if hostname and hostname.casefold().rstrip(".") in {
            item for item in self.prohibited_destinations if isinstance(item, str)
        }:
            raise ProhibitedDestination(f"hostname {hostname!r} is prohibited")
        parsed = ip_address(canonical)
        for item in self.prohibited_destinations:
            if not isinstance(item, str) and parsed in item:
                raise ProhibitedDestination(f"destination {canonical!r} is prohibited")
        if self.approved_cidrs and not any(parsed in network for network in self.approved_cidrs):
            raise DestinationNotApproved(f"destination {canonical!r} is outside approved CIDRs")
        return canonical

    def validate_connection(
        self,
        *,
        hostname: str,
        address: str,
        port: int,
        service_type: str,
    ) -> str:
        self._check_deadline()
        if port not in self.permitted_ports:
            raise PortNotPermitted(f"port {port} is not permitted")
        normalized_service = service_type.casefold()
        if normalized_service not in self.permitted_service_types:
            raise ServiceTypeNotPermitted(f"service type {service_type!r} is not permitted")
        return self.validate_destination(address, hostname=hostname)

    check_destination = validate_destination
    authorize_connection = validate_connection

    def _reserve_request(self) -> None:
        self._check_deadline()
        with self._request_lock:
            if self._requests >= self.max_requests:
                raise NetworkLimitExceeded(f"network request limit exhausted at {self.max_requests}")
            self._requests += 1

    async def _wait_rate(self, host_key: str) -> None:
        if self.rate_limit_per_host is None:
            return
        interval = 1.0 / self.rate_limit_per_host
        with self._host_lock:
            previous = self._last_host_request.get(host_key)
            now = time.monotonic()
            wait_for = 0.0 if previous is None else max(0.0, interval - (now - previous))
            self._last_host_request[host_key] = now + wait_for
        if wait_for:
            try:
                await asyncio.sleep(wait_for)
            except asyncio.CancelledError:
                raise

    async def acquire(
        self,
        *,
        hostname: str,
        address: str,
        port: int,
        service_type: str,
        cancel_event: asyncio.Event | None = None,
    ) -> NetworkLease:
        if self._closed:
            raise NetworkLimitExceeded("network assessment policy is closed")
        canonical = self.validate_connection(
            hostname=hostname, address=address, port=port, service_type=service_type
        )
        if cancel_event is not None and cancel_event.is_set():
            raise asyncio.CancelledError
        self._reserve_request()
        host_key = hostname.casefold().rstrip(".")
        host_sem = self._host_semaphores.setdefault(host_key, asyncio.Semaphore(self.per_host_concurrency))
        acquired_global = acquired_host = False
        try:
            self._check_deadline()
            await self._wait_rate(host_key)
            await self._acquire(self._connections, cancel_event)
            acquired_global = True
            await self._acquire(host_sem, cancel_event)
            acquired_host = True
            metadata = NetworkAuditMetadata(
                operation=self.operation,
                hostname=host_key,
                address=canonical,
                port=port,
                service_type=service_type.casefold(),
            )
            return NetworkLease(self, metadata, host_key)
        except BaseException:
            if acquired_host:
                host_sem.release()
            if acquired_global:
                self._connections.release()
            raise

    async def _acquire(self, semaphore: asyncio.Semaphore, cancel_event: asyncio.Event | None) -> None:
        self._check_deadline()
        remaining = None if self._deadline is None else max(0.0, self._deadline - time.monotonic())
        if cancel_event is None:
            try:
                if remaining is None:
                    await semaphore.acquire()
                else:
                    await asyncio.wait_for(semaphore.acquire(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise NetworkLimitExceeded("network assessment deadline expired") from exc
            return
        waiter = asyncio.create_task(semaphore.acquire())
        cancellation = asyncio.create_task(cancel_event.wait())
        deadline_task = (
            asyncio.create_task(asyncio.sleep(remaining)) if remaining is not None else None
        )
        tasks = {waiter, cancellation}
        if deadline_task is not None:
            tasks.add(deadline_task)
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        if waiter in done and waiter.result():
            return
        if cancellation in done and cancellation.result():
            waiter.cancel()
            raise asyncio.CancelledError
        if deadline_task is not None and deadline_task in done:
            waiter.cancel()
            raise NetworkLimitExceeded("network assessment deadline expired")

    def _release(self, lease: NetworkLease, *, outcome: str, reason: str | None) -> None:
        self._connections.release()
        host_sem = self._host_semaphores.get(lease._host_key)
        if host_sem is not None:
            host_sem.release()
        completed = datetime.now(timezone.utc)
        with self._audit_lock:
            self._audit.append(
                NetworkAuditMetadata(
                    operation=lease.metadata.operation,
                    hostname=lease.metadata.hostname,
                    address=lease.metadata.address,
                    port=lease.metadata.port,
                    service_type=lease.metadata.service_type,
                    started_at=lease.metadata.started_at,
                    completed_at=completed,
                    outcome=outcome,
                    reason=reason,
                )
            )

    @asynccontextmanager
    async def connection(self, **kwargs) -> AsyncIterator[NetworkLease]:
        lease = await self.acquire(**kwargs)
        try:
            yield lease
        except asyncio.CancelledError:
            await lease.release(outcome="cancelled")
            raise
        except Exception as exc:
            await lease.release(outcome="error", reason=type(exc).__name__)
            raise
        else:
            await lease.release()

    request = connection

    def close(self) -> None:
        self._closed = True


# Discoverable aliases for callers using shorter terminology.
NetworkPolicy = NetworkAssessmentPolicy
NetworkAudit = NetworkAuditMetadata
PortNotAllowed = PortNotPermitted
NetworkPolicyRejected = NetworkPolicyError
