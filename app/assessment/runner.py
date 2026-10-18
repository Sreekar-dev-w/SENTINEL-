"""Isolated execution of the immutable passive assessment registry."""

from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timezone
from typing import Awaitable, Callable

from app.assessment.context import AssessmentContext
from app.assessment.modules import MODULE_FUNCTIONS
from app.assessment.registry import AssessmentModuleDefinition, AssessmentRegistry, DEFAULT_REGISTRY
from app.scanning.budget import RequestBudgetExhausted, ScanDeadlineExceeded
from app.scanning.models import (
    AssessmentCoverage,
    AssessmentModuleResult,
    AssessmentResult,
    AssessmentStatus,
    VerificationStatus,
    ObservationMode,
    ObservationStatus,
    WebsiteObservation,
    deduplicate_findings,
)
from app.security.url_validation import URLValidationError, normalize_target_url


ProgressCallback = Callable[[AssessmentResult], Awaitable[None] | None]


def _now():
    return datetime.now(timezone.utc)


def _unavailable(context: AssessmentContext, definition: AssessmentModuleDefinition, status: AssessmentStatus, message: str) -> AssessmentModuleResult:
    observation = WebsiteObservation(
        kind=f"assessment.{definition.name}", value={"reason": message}, mode=ObservationMode.INFERRED,
        confidence="low", status=ObservationStatus.UNAVAILABLE if status == AssessmentStatus.UNAVAILABLE else ObservationStatus.LIMITED,
        module=definition.name, test_id=definition.test_id, test_version=definition.test_version,
        reference=definition.references[0].key,
        references=[reference.key for reference in definition.references],
        owasp_category=definition.owasp_category, owasp_id=definition.owasp_id,
    )
    return AssessmentModuleResult(
        module=definition.name, test_id=definition.test_id, test_version=definition.test_version,
        status=status, observations=[observation], reference=definition.references[0].key,
        references=[reference.key for reference in definition.references], error=message,
        skip_reason=message if status == AssessmentStatus.SKIPPED else None,
        impact=definition.impact, execution_mode=definition.execution_mode,
    )


async def run_assessment(
    context: AssessmentContext,
    registry: AssessmentRegistry = DEFAULT_REGISTRY,
    *,
    profile_id: str | None = None,
    profile_version: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> AssessmentResult:
    """Run each module with cancellation and exception isolation."""

    results: list[AssessmentModuleResult] = []
    completed_modules: set[str] = set()
    definitions = tuple(registry)

    async def publish_progress(
        *,
        current_index: int | None = None,
        current_status: AssessmentStatus | None = None,
    ) -> None:
        if progress_callback is None:
            return
        metadata: list[AssessmentModuleResult] = []
        result_by_name = {result.module: result for result in results}
        for index, definition in enumerate(definitions):
            result = result_by_name.get(definition.name)
            if result is not None:
                metadata.append(result.model_copy(
                    update={
                        "progress": round((index + 1) / len(definitions) * 100),
                        "findings": [],
                        "observations": [],
                        "reference": None,
                        "references": [],
                        "error": None,
                        "skip_reason": None,
                        "impact": None,
                        "execution_mode": None,
                    }
                ))
                continue
            status = AssessmentStatus.PENDING
            progress = 0
            if current_index == index:
                status = current_status or AssessmentStatus.RUNNING
            metadata.append(AssessmentModuleResult(
                module=definition.name,
                test_id=definition.test_id,
                test_version=definition.test_version,
                status=status,
                progress=progress,
            ))
        completed = sum(item.status == AssessmentStatus.COMPLETED for item in metadata)
        interim_progress = 0 if current_index is None else round(
            (current_index + (0 if current_status == AssessmentStatus.RUNNING else 1))
            / len(definitions) * 100
        )
        snapshot = AssessmentResult(
            status=AssessmentStatus.PARTIAL,
            profile_id=profile_id or "sentinel-v0.3-passive",
            profile_version=profile_version or "0.3.0",
            enabled_modules=[definition.name for definition in definitions],
            progress=min(99, interim_progress),
            modules=metadata,
            coverage=AssessmentCoverage(
                total_modules=len(definitions),
                completed_modules=completed,
                not_run_tests=sum(item.status in {
                    AssessmentStatus.PENDING,
                    AssessmentStatus.RUNNING,
                } for item in metadata),
                partial=True,
            ),
            findings=[],
            observations=[],
        )
        update = progress_callback(snapshot)
        if inspect.isawaitable(update):
            await update

    await publish_progress()
    for index, definition in enumerate(definitions):
        if context.cancel_event is not None and context.cancel_event.is_set():
            raise asyncio.CancelledError
        await publish_progress(current_index=index, current_status=AssessmentStatus.RUNNING)
        missing_permissions = sorted(set(definition.permissions) - set(context.permissions))
        if missing_permissions:
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, f"missing permission: {missing_permissions[0]}"))
            await publish_progress(current_index=index, current_status=AssessmentStatus.SKIPPED)
            continue
        if definition.scope is not None and context.lab is not None:
            try:
                supported_scope = context.lab.scope.target_url == normalize_target_url(context.target_url).origin
            except (TypeError, ValueError, URLValidationError):
                supported_scope = False
            if not supported_scope:
                results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, "unsupported lab scope"))
                await publish_progress(current_index=index, current_status=AssessmentStatus.SKIPPED)
                continue
        declared_capabilities = set(context.capabilities)
        if context.lab is not None:
            declared_capabilities &= set(context.lab.capabilities)
        missing_capabilities = sorted(set(definition.capabilities) - declared_capabilities)
        if missing_capabilities:
            results.append(_unavailable(context, definition, AssessmentStatus.UNAVAILABLE, f"missing capability: {missing_capabilities[0]}"))
            await publish_progress(current_index=index, current_status=AssessmentStatus.UNAVAILABLE)
            continue
        if definition.scope is not None and context.lab is not None and any(
            not context.lab.supports_capability(context.target_url, capability)
            for capability in definition.capabilities
        ):
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, "unsupported lab scope"))
            await publish_progress(current_index=index, current_status=AssessmentStatus.SKIPPED)
            continue
        missing = sorted(set(definition.prerequisites) - set(context.prerequisites))
        if missing:
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, f"missing prerequisite: {missing[0]}"))
            await publish_progress(current_index=index, current_status=AssessmentStatus.SKIPPED)
            continue
        if definition.availability != "available":
            results.append(_unavailable(context, definition, AssessmentStatus.UNAVAILABLE, "capability is not configured"))
            await publish_progress(current_index=index, current_status=AssessmentStatus.UNAVAILABLE)
            continue
        missing_dependencies = sorted(
            dependency for dependency in definition.dependencies
            if dependency not in completed_modules
        )
        if missing_dependencies:
            results.append(_unavailable(
                context,
                definition,
                AssessmentStatus.SKIPPED,
                f"dependency not completed: {missing_dependencies[0]}",
            ))
            await publish_progress(current_index=index, current_status=AssessmentStatus.SKIPPED)
            continue
        try:
            function_key = definition.function_key or definition.name
            function = MODULE_FUNCTIONS[function_key]
            outcome = function(context, definition)
            if inspect.isawaitable(outcome):
                outcome = await outcome
            findings, observations = outcome
            results.append(AssessmentModuleResult(
                module=definition.name, test_id=definition.test_id, test_version=definition.test_version,
                status=AssessmentStatus.COMPLETED, findings=findings, observations=observations,
                reference=definition.references[0].key, references=[reference.key for reference in definition.references],
                impact=definition.impact, execution_mode=definition.execution_mode,
            ))
            completed_modules.add(definition.name)
            await publish_progress(current_index=index, current_status=AssessmentStatus.COMPLETED)
        except (RequestBudgetExhausted, ScanDeadlineExceeded) as exc:
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, type(exc).__name__))
            await publish_progress(current_index=index, current_status=AssessmentStatus.SKIPPED)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            results.append(AssessmentModuleResult(
                module=definition.name, test_id=definition.test_id, test_version=definition.test_version,
                status=AssessmentStatus.ERROR, reference=definition.references[0].key,
                references=[reference.key for reference in definition.references], error=type(exc).__name__,
                impact=definition.impact, execution_mode=definition.execution_mode,
            ))
            await publish_progress(current_index=index, current_status=AssessmentStatus.ERROR)

    if results:
        results = [
            result.model_copy(update={"progress": round(index / len(registry) * 100)})
            for index, result in enumerate(results, start=1)
        ]
    # Keep each module's raw findings for module-level traceability, while the
    # aggregate result exposes one deterministic finding per target/code.
    findings = deduplicate_findings(
        [finding for result in results for finding in result.findings]
    )
    observations = [observation for result in results for observation in result.observations]
    coverage = AssessmentCoverage(
        total_modules=len(results),
        applicable_tests=sum(result.status in {AssessmentStatus.COMPLETED, AssessmentStatus.ERROR} for result in results),
        completed_modules=sum(result.status == AssessmentStatus.COMPLETED for result in results),
        passed_tests=sum(result.status == AssessmentStatus.COMPLETED and not result.findings for result in results),
        skipped_modules=sum(result.status == AssessmentStatus.SKIPPED for result in results),
        skipped_tests=sum(result.status == AssessmentStatus.SKIPPED for result in results),
        not_run_tests=0,
        unavailable_modules=sum(result.status == AssessmentStatus.UNAVAILABLE for result in results),
        error_modules=sum(result.status == AssessmentStatus.ERROR for result in results),
        execution_failures=sum(result.status == AssessmentStatus.ERROR for result in results),
        confirmed_findings=sum(finding.verification == VerificationStatus.CONFIRMED for finding in findings),
        potential_findings=sum(finding.verification == VerificationStatus.POTENTIAL for finding in findings),
        informational_observations=sum(
            observation.status in {ObservationStatus.OBSERVED, ObservationStatus.INFERRED}
            for observation in observations
        ),
        findings_total=len(findings), observations_total=len(observations),
        partial=any(result.status != AssessmentStatus.COMPLETED for result in results),
    )
    status = AssessmentStatus.PARTIAL if coverage.partial else AssessmentStatus.COMPLETED
    controlled = any(definition.scope is not None for definition in registry)
    return AssessmentResult(
        status=status,
        profile_id=profile_id or (
            "sentinel-v0.4-controlled-application-security" if controlled
            else "sentinel-v0.3-passive"
        ),
        profile_version=profile_version or ("0.4.0" if controlled else "0.3.0"),
        enabled_modules=[definition.name for definition in registry],
        progress=100,
        modules=results,
        coverage=coverage,
        findings=findings,
        observations=observations,
        timestamp=_now(),
    )
