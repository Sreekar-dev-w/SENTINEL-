"""Bounded, cancellable process execution for approved external tools.

The runner accepts an argument vector only.  It never invokes a shell and it
owns process cleanup on timeout, cancellation, and output overflow.  Adapters
can inject a fake runner implementing the same small protocol in tests.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Awaitable, Callable, Protocol, Sequence


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    cancelled: bool = False
    output_limited: bool = False


class ProcessRunner(Protocol):
    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancel_event: asyncio.Event | None = None,
    ) -> ProcessResult:
        ...


class ProcessUnavailable(FileNotFoundError):
    """The configured executable is not installed or cannot be started."""


class SubprocessRunner:
    """Run one process with bounded stdout/stderr and safe termination."""

    async def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
        cancel_event: asyncio.Event | None = None,
    ) -> ProcessResult:
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("argv must contain non-empty strings")
        if timeout_seconds <= 0 or max_output_bytes < 0:
            raise ValueError("invalid process bounds")
        try:
            process = await asyncio.create_subprocess_exec(
                *tuple(argv),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ProcessUnavailable(argv[0]) from exc
        except OSError as exc:
            raise ProcessUnavailable(argv[0]) from exc

        stdout_task = asyncio.create_task(self._read_limited(process.stdout, max_output_bytes))
        stderr_task = asyncio.create_task(self._read_limited(process.stderr, max_output_bytes))
        wait_task = asyncio.create_task(process.wait())
        cancel_task = None if cancel_event is None else asyncio.create_task(cancel_event.wait())
        timed_out = False
        cancelled = False
        output_limited = False
        try:
            deadline = asyncio.get_running_loop().time() + timeout_seconds
            control_tasks = {wait_task}
            if cancel_task is not None:
                control_tasks.add(cancel_task)
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    timed_out = True
                    break
                done, _ = await asyncio.wait(
                    control_tasks | {stdout_task, stderr_task},
                    timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if cancel_task is not None and cancel_task in done and cancel_task.result():
                    cancelled = True
                    break
                for stream_task in (stdout_task, stderr_task):
                    if stream_task in done and stream_task.result()[1]:
                        output_limited = True
                        break
                if output_limited:
                    break
                if wait_task in done:
                    break
            if timed_out or cancelled or output_limited:
                await self._terminate(process)
            await asyncio.gather(wait_task, return_exceptions=True)
            stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
            output_limited = output_limited or stdout[1] or stderr[1]
            return ProcessResult(
                returncode=process.returncode,
                stdout=stdout[0],
                stderr=stderr[0],
                timed_out=timed_out,
                cancelled=cancelled,
                output_limited=output_limited,
            )
        finally:
            if cancel_task is not None:
                cancel_task.cancel()
                await asyncio.gather(cancel_task, return_exceptions=True)

    @staticmethod
    async def _read_limited(stream, limit: int) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        # Keep one extra byte solely to detect an overflow, then stop reading;
        # termination in the caller prevents an unbounded producer.
        chunks: list[bytes] = []
        remaining = limit
        while True:
            chunk = await stream.read(min(65_536, remaining + 1))
            if not chunk:
                return b"".join(chunks), False
            if len(chunk) > remaining:
                if remaining:
                    chunks.append(chunk[:remaining])
                return b"".join(chunks), True
            chunks.append(chunk)
            remaining -= len(chunk)
            if remaining == 0:
                marker = await stream.read(1)
                return b"".join(chunks), bool(marker)

    @staticmethod
    async def _terminate(process) -> None:
        if process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=0.5)
        except (asyncio.TimeoutError, ProcessLookupError):
            if process.returncode is None:
                process.kill()
                await asyncio.gather(process.wait(), return_exceptions=True)


async def run_process(
    runner: ProcessRunner | Callable[..., Awaitable[ProcessResult]],
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    cancel_event: asyncio.Event | None,
) -> ProcessResult:
    """Call a protocol runner or an async callable for convenient test fakes."""

    operation = runner.run if hasattr(runner, "run") else runner
    result = operation(
        tuple(argv),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        cancel_event=cancel_event,
    )
    if inspect.isawaitable(result):
        result = await result
    if not isinstance(result, ProcessResult):
        raise TypeError("process runner must return ProcessResult")
    return result


__all__ = ["ProcessResult", "ProcessRunner", "ProcessUnavailable", "SubprocessRunner", "run_process"]
