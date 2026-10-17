import asyncio

import pytest

from app.scanning.budget import (
    RequestBudgetExhausted,
    ScanBudget,
    ScanDeadlineExceeded,
)
from app.config import ScanLimits


def test_budget_reserves_total_requests_and_limits_active_concurrency():
    async def exercise() -> None:
        budget = ScanBudget(
            ScanLimits(maximum_requests_per_scan=5, maximum_concurrency=2)
        )
        entered = 0
        peak = 0
        lock = asyncio.Lock()

        async def operation() -> int:
            nonlocal entered, peak
            async with budget.attempt() as ordinal:
                async with lock:
                    entered += 1
                    peak = max(peak, entered)
                await asyncio.sleep(0.01)
                async with lock:
                    entered -= 1
                return ordinal

        ordinals = await asyncio.gather(*(operation() for _ in range(5)))
        assert sorted(ordinals) == [1, 2, 3, 4, 5]
        assert peak == 2
        assert budget.reserved_requests == 5

        with pytest.raises(RequestBudgetExhausted):
            async with budget.attempt():
                pass

    asyncio.run(exercise())


def test_failures_and_cancellation_after_entry_do_not_roll_back_reservation():
    async def exercise() -> None:
        budget = ScanBudget(maximum_requests=1, maximum_concurrency=1)
        with pytest.raises(RuntimeError):
            async with budget.attempt():
                raise RuntimeError("controlled failure")
        assert budget.reserved_requests == 1

        with pytest.raises(RequestBudgetExhausted):
            async with budget.attempt():
                pass

        cancelled_budget = ScanBudget(maximum_requests=1, maximum_concurrency=1)
        entered = asyncio.Event()

        async def blocked() -> None:
            async with cancelled_budget.attempt():
                entered.set()
                await asyncio.sleep(60)

        task = asyncio.create_task(blocked())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled_budget.reserved_requests == 1
        with pytest.raises(RequestBudgetExhausted):
            async with cancelled_budget.attempt():
                pass

    asyncio.run(exercise())


def test_cancellation_while_waiting_for_slot_does_not_consume_request():
    async def exercise() -> None:
        budget = ScanBudget(maximum_requests=2, maximum_concurrency=1)
        entered = asyncio.Event()
        release = asyncio.Event()

        async def first() -> None:
            async with budget.attempt():
                entered.set()
                await release.wait()

        first_task = asyncio.create_task(first())
        await entered.wait()
        async def waiting_operation() -> None:
            async with budget.attempt():
                pass

        waiting = asyncio.create_task(waiting_operation())
        await asyncio.sleep(0)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert budget.reserved_requests == 1
        release.set()
        await first_task

    asyncio.run(exercise())


def test_scan_deadline_applies_while_waiting_for_concurrency():
    async def exercise() -> None:
        budget = ScanBudget(maximum_requests=2, maximum_concurrency=1, deadline_seconds=0.02)
        entered = asyncio.Event()
        release = asyncio.Event()

        async def first() -> None:
            async with budget.attempt():
                entered.set()
                await release.wait()

        first_task = asyncio.create_task(first())
        await entered.wait()
        with pytest.raises(ScanDeadlineExceeded):
            async with budget.attempt():
                pass
        release.set()
        await first_task
        assert budget.reserved_requests == 1

    asyncio.run(exercise())
