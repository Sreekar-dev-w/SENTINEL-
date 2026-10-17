"""Authoritative scan-wide request and concurrency budget.

``ScanBudget.attempt()`` is the boundary a runner should wrap around one
network attempt.  It waits for a concurrency slot, atomically reserves one
request, and only then yields to the caller.  The reservation is never
returned, including when the yielded operation fails or is cancelled.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from threading import Lock
from typing import AsyncIterator

from app.config import ScanLimits


class ScanBudgetError(RuntimeError):
    """Base class for scan budget failures."""


class RequestBudgetExhausted(ScanBudgetError):
    """The scan has reserved its maximum number of request attempts."""


class ScanDeadlineExceeded(ScanBudgetError):
    """The scan-wide monotonic deadline has elapsed."""


class ScanBudget:
    """Coordinate one scan's total request count and active I/O slots.

    ``deadline`` is an absolute monotonic timestamp, suitable for passing from
    ``asyncio.get_running_loop().time()``.  ``deadline_seconds`` is a
    convenience for a relative scan deadline.  Only the short reservation
    check/increment uses a lock; no lock is held while waiting or doing I/O.
    """

    def __init__(
        self,
        limits: ScanLimits | None = None,
        *,
        maximum_requests: int | None = None,
        maximum_concurrency: int | None = None,
        deadline: float | None = None,
        deadline_seconds: float | None = None,
    ) -> None:
        configured = limits or ScanLimits()
        self.maximum_requests = (
            configured.maximum_requests_per_scan
            if maximum_requests is None
            else maximum_requests
        )
        self.maximum_concurrency = (
            configured.maximum_concurrency
            if maximum_concurrency is None
            else maximum_concurrency
        )
        if self.maximum_requests < 0:
            raise ValueError("maximum_requests must not be negative")
        if self.maximum_concurrency <= 0:
            raise ValueError("maximum_concurrency must be greater than zero")
        if deadline is not None and deadline_seconds is not None:
            raise ValueError("provide deadline or deadline_seconds, not both")
        if deadline_seconds is not None and deadline_seconds < 0:
            raise ValueError("deadline_seconds must not be negative")

        self.deadline = (
            deadline
            if deadline is not None
            else (
                time.monotonic() + deadline_seconds
                if deadline_seconds is not None
                else None
            )
        )
        self._reserved = 0
        self._reservation_lock = Lock()
        self._semaphore = asyncio.Semaphore(self.maximum_concurrency)

    @property
    def reserved_requests(self) -> int:
        """Return the number of consumed request reservations."""

        with self._reservation_lock:
            return self._reserved

    @property
    def remaining_requests(self) -> int:
        return max(0, self.maximum_requests - self.reserved_requests)

    @property
    def active_requests(self) -> int:
        # Semaphore._value is intentionally not used as a public count: this
        # value is only an observability aid and is never a correctness check.
        return self.maximum_concurrency - self._semaphore._value

    def _check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise ScanDeadlineExceeded("scan-wide deadline expired")

    def reserve(self) -> int:
        """Atomically consume one request reservation and return its ordinal.

        This synchronous method is useful when a caller has already acquired
        its own I/O slot.  Prefer :meth:`attempt` for normal network calls.
        """

        self._check_deadline()
        with self._reservation_lock:
            # Re-check after acquiring the lock so an attempt that races the
            # deadline cannot be admitted based on an earlier observation.
            self._check_deadline()
            if self._reserved >= self.maximum_requests:
                raise RequestBudgetExhausted(
                    f"scan request budget exhausted at {self.maximum_requests} attempts"
                )
            self._reserved += 1
            return self._reserved

    reserve_request = reserve

    async def _acquire_slot(self) -> None:
        self._check_deadline()
        if self.deadline is None:
            await self._semaphore.acquire()
            return
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ScanDeadlineExceeded("scan-wide deadline expired")
        try:
            await asyncio.wait_for(self._semaphore.acquire(), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise ScanDeadlineExceeded("scan-wide deadline expired while waiting for concurrency") from exc

    @asynccontextmanager
    async def attempt(self) -> AsyncIterator[int]:
        """Yield a reservation ordinal while one network attempt is active."""

        await self._acquire_slot()
        try:
            # There is no await between acquiring the slot and reservation, so
            # cancellation cannot create an unaccounted network attempt.
            ordinal = self.reserve()
        except BaseException:
            self._semaphore.release()
            raise
        try:
            yield ordinal
        finally:
            # Releasing concurrency is safe after success, error, or
            # cancellation.  The request reservation above is never rolled back.
            self._semaphore.release()

    request = attempt
    network_attempt = attempt
