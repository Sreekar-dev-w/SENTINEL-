"""In-memory scan lifecycle and the first SENTINEL vertical slice."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime
from typing import Callable
from uuid import UUID

import httpx

from app.config import ScanLimits
from app.engagement import EngagementNotFound, EngagementScopePolicy, EngagementStore
from app.assessment.context import AssessmentContext
from app.assessment.lab import InProcessAssessmentLab
from app.assessment.orchestration import (
    AssessmentOrchestrator,
    prerequisites_for_lab,
)
from app.scanning.budget import ScanBudget
from app.scanning.findings import (
    check_csp,
    check_x_content_type_options,
    hsts_applicable,
    observe_https_transport,
    validate_hsts,
)
from app.scanning.http_client import BoundedHTTPClient
from app.scanning.intelligence import WebsiteIntelligenceEngine, redact_url
from app.scanning.models import (
    Check,
    CheckStatus,
    CheckType,
    Finding,
    FindingSeverity,
    MinimalEvidence,
    Scan,
    ScanStatus,
    ScanSummary,
    AssessmentResult,
    AssessmentStatus,
    WebsiteProfile,
    ObservationStatus,
    utc_now,
)


class ScanNotFound(LookupError):
    """Raised when a scan ID does not exist in the in-memory store."""


class InvalidScanTransition(RuntimeError):
    """Raised when a non-terminal scan transition is invalid."""


class ScanStore:
    """Race-safe in-memory store for scan records and terminal transitions."""

    _terminal = frozenset(
        {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
    )

    def __init__(self) -> None:
        self._scans: dict[UUID, Scan] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        target_url: str,
        *,
        engagement_id: UUID | None = None,
        assessment_profile: str | None = None,
        active_testing_authorized: bool | None = None,
    ) -> Scan:
        scan = Scan(
            target_url=target_url,
            engagement_id=engagement_id,
            assessment_profile=assessment_profile,
            active_testing_authorized=active_testing_authorized,
            status=ScanStatus.QUEUED,
        )
        async with self._lock:
            self._scans[scan.id] = scan
            return scan.model_copy(deep=True)

    async def get(self, scan_id: UUID) -> Scan | None:
        async with self._lock:
            scan = self._scans.get(scan_id)
            return None if scan is None else scan.model_copy(deep=True)

    async def transition(
        self,
        scan_id: UUID,
        new_status: ScanStatus,
        *,
        expected: frozenset[ScanStatus] | None = None,
        error: str | None = None,
    ) -> Scan:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                raise ScanNotFound(str(scan_id))
            if scan.status in self._terminal:
                return scan.model_copy(deep=True)
            if expected is not None and scan.status not in expected:
                raise InvalidScanTransition(
                    f"cannot transition {scan.status.value} to {new_status.value}"
                )
            allowed = {
                ScanStatus.QUEUED: {ScanStatus.RUNNING, ScanStatus.CANCELLED},
                ScanStatus.RUNNING: {
                    ScanStatus.COMPLETED,
                    ScanStatus.FAILED,
                    ScanStatus.CANCELLED,
                },
            }
            if new_status not in allowed.get(scan.status, set()):
                raise InvalidScanTransition(
                    f"cannot transition {scan.status.value} to {new_status.value}"
                )
            scan.status = new_status
            now = utc_now()
            if new_status == ScanStatus.RUNNING:
                scan.started_at = now
            if new_status in self._terminal:
                scan.completed_at = now
            if error is not None:
                scan.error = error
            return scan.model_copy(deep=True)

    async def complete(
        self,
        scan_id: UUID,
        checks: list[Check],
        summary: ScanSummary,
        intelligence: WebsiteProfile | None = None,
        assessment: AssessmentResult | None = None,
    ) -> Scan:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                raise ScanNotFound(str(scan_id))
            if scan.status in self._terminal:
                return scan.model_copy(deep=True)
            if scan.status != ScanStatus.RUNNING:
                raise InvalidScanTransition("only running scans can complete")
            scan.checks = checks
            scan.summary = summary
            scan.intelligence = intelligence
            scan.assessment = assessment
            scan.coverage = None if assessment is None else assessment.coverage
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = utc_now()
            return scan.model_copy(deep=True)

    async def cancel(self, scan_id: UUID) -> Scan:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                raise ScanNotFound(str(scan_id))
            if scan.status in self._terminal:
                return scan.model_copy(deep=True)
            scan.status = ScanStatus.CANCELLED
            scan.completed_at = utc_now()
            return scan.model_copy(deep=True)


class ScanManager:
    """Own scan tasks, one shared budget, and one hardened client per scan."""

    def __init__(
        self,
        limits: ScanLimits | None = None,
        *,
        client_factory: Callable[[ScanLimits], BoundedHTTPClient] | None = None,
        intelligence_engine: WebsiteIntelligenceEngine | None = None,
        enable_intelligence: bool = True,
        engagement_store: EngagementStore | None = None,
        assessment_lab_factory: Callable[[str], InProcessAssessmentLab | None] | None = None,
        lab_factory: Callable[[str], InProcessAssessmentLab | None] | None = None,
    ) -> None:
        self.limits = limits or ScanLimits()
        if self.limits.scan_timeout_seconds <= 0:
            raise ValueError("scan_timeout_seconds must be greater than zero")
        if self.limits.maximum_findings < 0:
            raise ValueError("maximum_findings must not be negative")
        self.store = ScanStore()
        self.engagement_store = engagement_store or EngagementStore()
        self._client_factory = client_factory or (
            lambda scan_limits: BoundedHTTPClient(limits=scan_limits)
        )
        self._intelligence_engine = intelligence_engine or WebsiteIntelligenceEngine()
        self._enable_intelligence = enable_intelligence
        if assessment_lab_factory is not None and lab_factory is not None:
            raise ValueError("provide only one assessment lab factory")
        self._assessment_lab_factory = assessment_lab_factory or lab_factory
        self._orchestrator = AssessmentOrchestrator()
        self._tasks: dict[UUID, asyncio.Task[None]] = {}
        self._cancel_events: dict[UUID, asyncio.Event] = {}

    async def create_scan(self, request) -> Scan:
        engagement_id = getattr(request, "engagement_id", None)
        requested_profile = getattr(request, "assessment_profile", None)
        profile = self._orchestrator.resolve(requested_profile)
        active_testing_authorized = getattr(request, "active_testing_authorized", None)
        engagement_policy = None
        if engagement_id is not None:
            engagement = await self.engagement_store.require(engagement_id)
            # Validate at admission and again immediately before network work;
            # cancellation/expiry can race a queued task.
            engagement_policy = EngagementScopePolicy(engagement)
            engagement_policy.validate_url(request.target_url)
        self._orchestrator.validate_admission(
            profile,
            engagement_id=engagement_id,
            active_testing_authorized=active_testing_authorized,
            engagement_policy=engagement_policy,
        )
        scan = await self.store.create(
            request.target_url,
            engagement_id=engagement_id,
            # Keep omitted legacy fields omitted in the response. The worker
            # resolves the default profile from None.
            assessment_profile=None if requested_profile is None else profile.name,
            active_testing_authorized=active_testing_authorized,
        )
        self._cancel_events[scan.id] = asyncio.Event()
        task = asyncio.create_task(self._run(scan.id))
        self._tasks[scan.id] = task
        task.add_done_callback(lambda completed: self._discard_task(scan.id, completed))
        return scan

    async def get_scan(self, scan_id: str) -> Scan | None:
        try:
            return await self.store.get(UUID(scan_id))
        except ValueError:
            return None

    async def cancel_scan(self, scan_id: str) -> Scan | None:
        try:
            parsed = UUID(scan_id)
        except ValueError:
            return None
        try:
            scan = await self.store.cancel(parsed)
        except ScanNotFound:
            return None
        event = self._cancel_events.get(parsed)
        if event is not None:
            event.set()
        task = self._tasks.get(parsed)
        if task is not None and not task.done():
            task.cancel()
        return scan

    def _discard_task(self, scan_id: UUID, task: asyncio.Task[None]) -> None:
        self._tasks.pop(scan_id, None)
        self._cancel_events.pop(scan_id, None)
        try:
            task.exception()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _run(self, scan_id: UUID) -> None:
        try:
            running = await self.store.transition(
                scan_id,
                ScanStatus.RUNNING,
                expected=frozenset({ScanStatus.QUEUED}),
            )
            effective_limits = self.limits
            engagement_policy = None
            if running.engagement_id is not None:
                engagement = await self.engagement_store.require(running.engagement_id)
                engagement_policy = EngagementScopePolicy(engagement)
                engagement_policy.validate_url(running.target_url)
                effective_limits = engagement_policy.effective_limits(self.limits)
            profile = self._orchestrator.resolve(running.assessment_profile)
            self._orchestrator.validate_admission(
                profile,
                engagement_id=running.engagement_id,
                active_testing_authorized=running.active_testing_authorized,
                engagement_policy=engagement_policy,
            )
            budget = ScanBudget(
                effective_limits,
                deadline_seconds=effective_limits.scan_timeout_seconds,
            )
            if budget.deadline is None:
                raise RuntimeError("scan budget did not receive a deadline")
            async with asyncio.timeout_at(budget.deadline):
                async with self._client_factory(effective_limits) as client:
                    if engagement_policy is not None:
                        # Keep the existing factory seam and add the engagement
                        # gate to the client instance without weakening its
                        # global NetworkAssessmentPolicy.
                        client.engagement_policy = engagement_policy
                    async with budget.attempt():
                        response = await client.get(running.target_url)
                    try:
                        checks = self._run_checks(running.target_url, response)
                        intelligence = None
                        if self._enable_intelligence:
                            try:
                                intelligence = await self._intelligence_engine.scan(
                                    running.target_url,
                                    response,
                                    client,
                                    budget,
                                )
                            except asyncio.CancelledError:
                                raise
                            except Exception as exc:
                                # Intelligence is optional: an isolated parser or
                                # observation failure must not discard v0.1 checks.
                                intelligence = WebsiteProfile(
                                    initial_url=redact_url(running.target_url),
                                    status=ObservationStatus.ERROR,
                                    error=type(exc).__name__,
                                )
                        assessment = None
                        try:
                            lab = None
                            if profile.active_testing and self._assessment_lab_factory is not None:
                                lab = self._assessment_lab_factory(running.target_url)
                                if lab is not None and not isinstance(lab, InProcessAssessmentLab):
                                    raise TypeError("assessment lab factory returned an invalid lab")
                            context = AssessmentContext(
                                target_url=running.target_url,
                                response=response,
                                intelligence=intelligence,
                                budget=budget,
                                cancel_event=self._cancel_events.get(scan_id),
                                capabilities=frozenset() if lab is None else lab.capabilities,
                                prerequisites=prerequisites_for_lab(running.target_url, lab),
                                lab=lab,
                                _client=client,
                            )
                            assessment = await self._orchestrator.run(context, profile)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            # Assessment is additive to the v0.1/v0.2 flow. A
                            # module or registry failure must be represented as
                            # an assessment error, not erase legacy checks.
                            assessment = AssessmentResult(
                                status=AssessmentStatus.ERROR,
                                error=type(exc).__name__,
                            )
                    finally:
                        response.close()
                self._limit_findings(checks, effective_limits)
                summary = self._summary(checks)
                await self.store.complete(scan_id, checks, summary, intelligence, assessment)
        except asyncio.CancelledError:
            try:
                await self.store.transition(
                    scan_id,
                    ScanStatus.CANCELLED,
                    expected=frozenset({ScanStatus.QUEUED, ScanStatus.RUNNING}),
                )
            finally:
                raise
        except Exception as exc:
            await self.store.transition(
                scan_id,
                ScanStatus.FAILED,
                expected=frozenset({ScanStatus.QUEUED, ScanStatus.RUNNING}),
                error=f"{type(exc).__name__}: {exc}",
            )

    def _run_checks(self, target_url: str, response: httpx.Response) -> list[Check]:
        url = str(response.url)
        status_code = response.status_code
        headers = response.headers
        evidence = MinimalEvidence(
            url=url,
            status_code=status_code,
            headers={
                name: headers[name]
                for name in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                )
                if name in headers
            },
        )

        hsts = validate_hsts(target_url, response, url=url)
        csp = check_csp(response, url=url)
        nosniff = check_x_content_type_options(response, url=url)
        transport = observe_https_transport(target_url)

        checks = [
            Check(
                name=CheckType.HSTS,
                status=(
                    CheckStatus.SKIPPED
                    if not hsts_applicable(target_url)
                    else CheckStatus.FAILED
                    if hsts is not None
                    else CheckStatus.PASSED
                ),
                findings=[] if hsts is None else [hsts],
                evidence=evidence,
            ),
            Check(
                name=CheckType.CSP,
                status=CheckStatus.FAILED if csp is not None else CheckStatus.PASSED,
                findings=[] if csp is None else [csp],
                evidence=evidence,
            ),
            Check(
                name=CheckType.X_CONTENT_TYPE_OPTIONS,
                status=CheckStatus.FAILED
                if nosniff is not None
                else CheckStatus.PASSED,
                findings=[] if nosniff is None else [nosniff],
                evidence=evidence,
            ),
            Check(
                name=CheckType.HTTPS_TRANSPORT,
                status=CheckStatus.PASSED
                if transport.https
                else CheckStatus.SKIPPED,
                observation=transport.model_dump(),
            ),
        ]
        return checks

    def _limit_findings(self, checks: list[Check], limits: ScanLimits | None = None) -> None:
        """Apply the scan-wide finding cap to stored check results."""

        remaining = (limits or self.limits).maximum_findings
        for check in checks:
            if remaining <= 0:
                check.findings = []
                continue
            check.findings = check.findings[:remaining]
            remaining -= len(check.findings)

    def _summary(self, checks: list[Check]) -> ScanSummary:
        findings = [finding for check in checks for finding in check.findings]
        by_severity = Counter(finding.severity for finding in findings)
        return ScanSummary(
            checks_total=len(checks),
            checks_completed=sum(
                check.status
                in {CheckStatus.PASSED, CheckStatus.FAILED, CheckStatus.SKIPPED}
                for check in checks
            ),
            findings_total=len(findings),
            findings_by_severity=dict(by_severity),
        )
