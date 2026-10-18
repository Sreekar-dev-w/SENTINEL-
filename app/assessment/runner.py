"""Isolated execution of the immutable passive assessment registry."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

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
)


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


async def run_assessment(context: AssessmentContext, registry: AssessmentRegistry = DEFAULT_REGISTRY) -> AssessmentResult:
    """Run each module with cancellation and exception isolation."""

    results: list[AssessmentModuleResult] = []
    for definition in registry:
        if context.cancel_event is not None and context.cancel_event.is_set():
            raise asyncio.CancelledError
        missing_permissions = sorted(set(definition.permissions) - set(context.permissions))
        if missing_permissions:
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, f"missing permission: {missing_permissions[0]}"))
            continue
        missing_capabilities = sorted(set(definition.capabilities) - set(context.capabilities))
        if missing_capabilities:
            results.append(_unavailable(context, definition, AssessmentStatus.UNAVAILABLE, f"missing capability: {missing_capabilities[0]}"))
            continue
        missing = sorted(set(definition.prerequisites) - set(context.prerequisites))
        if missing:
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, f"missing prerequisite: {missing[0]}"))
            continue
        if definition.availability != "available":
            results.append(_unavailable(context, definition, AssessmentStatus.UNAVAILABLE, "capability is not configured"))
            continue
        try:
            function_key = definition.function_key or definition.name
            function = MODULE_FUNCTIONS[function_key]
            findings, observations = function(context, definition)
            results.append(AssessmentModuleResult(
                module=definition.name, test_id=definition.test_id, test_version=definition.test_version,
                status=AssessmentStatus.COMPLETED, findings=findings, observations=observations,
                reference=definition.references[0].key, references=[reference.key for reference in definition.references],
                impact=definition.impact, execution_mode=definition.execution_mode,
            ))
        except (RequestBudgetExhausted, ScanDeadlineExceeded) as exc:
            results.append(_unavailable(context, definition, AssessmentStatus.SKIPPED, type(exc).__name__))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            results.append(AssessmentModuleResult(
                module=definition.name, test_id=definition.test_id, test_version=definition.test_version,
                status=AssessmentStatus.ERROR, reference=definition.references[0].key,
                references=[reference.key for reference in definition.references], error=type(exc).__name__,
                impact=definition.impact, execution_mode=definition.execution_mode,
            ))

    if results:
        results = [
            result.model_copy(update={"progress": round(index / len(results) * 100)})
            for index, result in enumerate(results, start=1)
        ]
    findings = [finding for result in results for finding in result.findings]
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
    return AssessmentResult(
        status=status,
        enabled_modules=[definition.name for definition in registry],
        progress=100,
        modules=results,
        coverage=coverage,
        findings=findings,
        observations=observations,
        timestamp=_now(),
    )
