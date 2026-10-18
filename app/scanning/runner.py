"""In-memory scan lifecycle and the first SENTINEL vertical slice."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime
from typing import Callable, Mapping
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
    deduplicate_findings,
    utc_now,
)
from app.external_tools import (
    AdapterScope,
    AdapterExecutionResult,
    ExternalToolAdapter,
    ExternalToolRegistry,
    ExternalToolRunner,
    ExternalToolSelectionError,
)
from app.persistence import SnapshotDatabase


class ScanNotFound(LookupError):
    """Raised when a scan ID does not exist in the in-memory store."""


class InvalidScanTransition(RuntimeError):
    """Raised when a non-terminal scan transition is invalid."""


class ScanStore:
    """Race-safe in-memory store for scan records and terminal transitions."""

    _terminal = frozenset(
        {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
    )

    def __init__(self, database: SnapshotDatabase | None = None) -> None:
        self._scans: dict[UUID, Scan] = {}
        self._lock = asyncio.Lock()
        self._database = database
        if database is not None:
            for record_id, payload in database.load("scan"):
                try:
                    scan = Scan.model_validate_json(payload)
                except (ValueError, TypeError):
                    continue
                if scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING}:
                    scan.status = ScanStatus.FAILED
                    scan.error = "Scan interrupted by an application restart; work was not resumed."
                    scan.completed_at = utc_now()
                self._scans[UUID(record_id)] = scan
                if scan.status == ScanStatus.FAILED and scan.error == "Scan interrupted by an application restart; work was not resumed.":
                    database.save("scan", str(scan.id), scan.model_dump_json())

    def _persist(self, scan: Scan) -> None:
        if self._database is not None:
            self._database.save("scan", str(scan.id), scan.model_dump_json())

    async def create(
        self,
        target_url: str,
        *,
        engagement_id: UUID | None = None,
        assessment_profile: str | None = None,
        active_testing_authorized: bool | None = None,
        infrastructure_authorized: bool = False,
        external_tool_names: tuple[str, ...] = (),
        owner_id: str = "local-development",
        tenant_id: str = "local",
    ) -> Scan:
        scan = Scan(
            target_url=target_url,
            owner_id=owner_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            assessment_profile=assessment_profile,
            active_testing_authorized=active_testing_authorized,
            infrastructure_authorized=infrastructure_authorized,
            external_tool_names=external_tool_names,
            status=ScanStatus.QUEUED,
        )
        async with self._lock:
            self._scans[scan.id] = scan
            self._persist(scan)
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
            self._persist(scan)
            return scan.model_copy(deep=True)

    async def complete(
        self,
        scan_id: UUID,
        checks: list[Check],
        summary: ScanSummary,
        intelligence: WebsiteProfile | None = None,
        assessment: AssessmentResult | None = None,
        external_tools: tuple[AdapterExecutionResult, ...] = (),
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
            scan.external_tools = list(external_tools)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = utc_now()
            self._persist(scan)
            return scan.model_copy(deep=True)

    async def set_external_tools(
        self,
        scan_id: UUID,
        external_tools: tuple[AdapterExecutionResult, ...],
    ) -> Scan | None:
        """Persist safe adapter snapshots, including during cancellation."""

        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return None
            scan.external_tools = list(external_tools)
            self._persist(scan)
            return scan.model_copy(deep=True)

    async def update_assessment_progress(
        self,
        scan_id: UUID,
        assessment: AssessmentResult,
    ) -> Scan | None:
        """Store a metadata-only assessment snapshot while a scan is running."""

        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None or scan.status in self._terminal:
                return None if scan is None else scan.model_copy(deep=True)
            if scan.status != ScanStatus.RUNNING:
                return scan.model_copy(deep=True)
            scan.assessment = assessment.model_copy(deep=True)
            self._persist(scan)
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
            self._persist(scan)
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
        publish_assessment_progress: bool = True,
        external_adapters: Mapping[str, ExternalToolAdapter] | None = None,
        state_db_path: str | None = None,
        state_database: SnapshotDatabase | None = None,
    ) -> None:
        self.limits = limits or ScanLimits()
        if self.limits.scan_timeout_seconds <= 0:
            raise ValueError("scan_timeout_seconds must be greater than zero")
        if self.limits.maximum_findings < 0:
            raise ValueError("maximum_findings must not be negative")
        database = state_database
        if database is None and state_db_path:
            database = SnapshotDatabase(state_db_path)
        self.state_database = database
        self.store = ScanStore(database)
        self.engagement_store = engagement_store or EngagementStore(database)
        self._client_factory = client_factory or (
            lambda scan_limits: BoundedHTTPClient(limits=scan_limits)
        )
        self._intelligence_engine = intelligence_engine or WebsiteIntelligenceEngine()
        self._enable_intelligence = enable_intelligence
        if assessment_lab_factory is not None and lab_factory is not None:
            raise ValueError("provide only one assessment lab factory")
        self._assessment_lab_factory = assessment_lab_factory or lab_factory
        self._publish_assessment_progress = publish_assessment_progress
        self._orchestrator = AssessmentOrchestrator()
        self.external_tool_registry = ExternalToolRegistry(external_adapters)
        self._external_tool_runner = ExternalToolRunner(self.external_tool_registry)
        self._tasks: dict[UUID, asyncio.Task[None]] = {}
        self._cancel_events: dict[UUID, asyncio.Event] = {}
        self._external_running: set[UUID] = set()

    async def create_scan(self, request) -> Scan:
        engagement_id = getattr(request, "engagement_id", None)
        requested_profile = getattr(request, "assessment_profile", None)
        profile = self._orchestrator.resolve(requested_profile)
        active_testing_authorized = getattr(request, "active_testing_authorized", None)
        requested_external_tools = tuple(
            getattr(request, "external_tools", None)
            or getattr(request, "external_tool_names", ())
            or ()
        )
        engagement_policy = None
        if engagement_id is not None:
            engagement = await self.engagement_store.require(engagement_id)
            if (
                engagement.owner_id != (getattr(request, "owner_id", None) or "local-development")
                or engagement.tenant_id != (getattr(request, "tenant_id", None) or "local")
            ):
                from app.engagement import EngagementPolicyError
                raise EngagementPolicyError("engagement is not accessible to this principal")
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
        try:
            selected_external_tools = self.external_tool_registry.validate_selection(
                requested_external_tools,
                engagement_policy=engagement_policy,
                active_testing_authorized=active_testing_authorized,
            )
        except ExternalToolSelectionError as exc:
            # Preserve the API's existing policy error boundary without
            # exposing adapter internals or tool output.
            from app.engagement import EngagementPolicyError

            raise EngagementPolicyError(str(exc)) from exc
        scan = await self.store.create(
            request.target_url,
            engagement_id=engagement_id,
            # Keep omitted legacy fields omitted in the response. The worker
            # resolves the default profile from None.
            assessment_profile=None if requested_profile is None else profile.name,
            active_testing_authorized=active_testing_authorized,
            infrastructure_authorized=bool(getattr(request, "infrastructure_authorized", False)),
            external_tool_names=selected_external_tools,
            owner_id=getattr(request, "owner_id", None) or "local-development",
            tenant_id=getattr(request, "tenant_id", None) or "local",
        )
        self._cancel_events[scan.id] = asyncio.Event()
        task = asyncio.create_task(self._run(scan.id))
        self._tasks[scan.id] = task
        task.add_done_callback(lambda completed: self._discard_task(scan.id, completed))
        return scan

    async def get_scan(self, scan_id: str, principal=None) -> Scan | None:
        try:
            scan = await self.store.get(UUID(scan_id))
            if scan is None or (principal is not None and (scan.owner_id != principal.subject or scan.tenant_id != principal.tenant)):
                return None
            return scan
        except ValueError:
            return None

    async def external_tool_availability(self):
        """Return safe availability records without executing a scan."""

        return await self.external_tool_registry.availability()

    async def cancel_scan(self, scan_id: str, principal=None) -> Scan | None:
        try:
            parsed = UUID(scan_id)
        except ValueError:
            return None
        try:
            existing = await self.store.get(parsed)
            if existing is None or (principal is not None and (existing.owner_id != principal.subject or existing.tenant_id != principal.tenant)):
                return None
            scan = await self.store.cancel(parsed)
        except ScanNotFound:
            return None
        event = self._cancel_events.get(parsed)
        if event is not None:
            event.set()
        task = self._tasks.get(parsed)
        # Let an in-flight adapter observe the shared cancellation event and
        # return a bounded CANCELLED/PARTIAL result. Native work still uses the
        # immediate task cancellation path, preserving its existing behavior.
        if task is not None and not task.done() and parsed not in self._external_running:
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
            external_tools: tuple[AdapterExecutionResult, ...] = ()
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
                        # Controlled profile work is satisfied by the in-process
                        # lab. Keep it to the existing bounded initial GET and
                        # do not turn the opt-in workflow into a crawler.
                        if self._enable_intelligence and not profile.active_testing:
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
                            progress_callback = None
                            if self._publish_assessment_progress:
                                async def progress_callback(update: AssessmentResult) -> None:
                                    await self.store.update_assessment_progress(scan_id, update)

                            assessment = await self._orchestrator.run(
                                context,
                                profile,
                                progress_callback=progress_callback,
                            )
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
                if running.external_tool_names:
                    if engagement_policy is None:
                        # This is defensive: admission rejects this state, and
                        # it must never become a silent external execution.
                        external_tools = tuple(
                            AdapterExecutionResult(
                                state="rejected",
                                tool=self.external_tool_registry.identity(name),
                                diagnostics=(),
                            )
                            for name in running.external_tool_names
                        )
                    else:
                        self._external_running.add(scan_id)
                        try:
                            external_tools = await self._external_tool_runner.run(
                                running.external_tool_names,
                                target_url=running.target_url,
                                scope=AdapterScope(
                                    running.engagement_id,
                                    engagement_policy,
                                    infrastructure_authorized=running.infrastructure_authorized,
                                ),
                                budget=budget,
                                cancel_event=self._cancel_events.get(scan_id),
                                timeout_seconds=effective_limits.scan_timeout_seconds,
                                max_output_bytes=effective_limits.maximum_response_bytes,
                                max_findings=effective_limits.maximum_findings,
                                active_testing_authorized=bool(running.active_testing_authorized),
                                on_result=lambda snapshot: self.store.set_external_tools(scan_id, snapshot),
                            )
                        finally:
                            self._external_running.discard(scan_id)
                self._limit_findings(checks, effective_limits)
                summary = self._summary(checks)
                await self.store.complete(
                    scan_id,
                    checks,
                    summary,
                    intelligence,
                    assessment,
                    external_tools,
                )
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
        entries = [
            (finding, check.name.value)
            for check in checks
            for finding in check.findings
        ]
        findings = deduplicate_findings(
            [finding for finding, _ in entries],
            sources=[source for _, source in entries],
        )
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
