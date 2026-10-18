"""Deterministic, metadata-only report exports for completed scans.

The report boundary deliberately consumes the existing API/domain models and
does not know how scans are executed or persisted.  Evidence is copied through
the same small header allowlist as :class:`MinimalEvidence`; response bodies,
cookies, and credential-bearing headers cannot enter either output format.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from app.api.models import (
    CheckResponse,
    EvidenceResponse,
    FindingResponse,
    ScanStatusResponse,
)
from app.engagement.models import Engagement
from app.scanning.intelligence import redact_url
from app.scanning.models import MinimalEvidence

ReportFormat = Literal["json", "markdown"]


class ReportNotReadyError(ValueError):
    """Raised when a scan exists but has no completed report result."""

    def __init__(self, scan_status: str) -> None:
        self.scan_status = scan_status
        super().__init__(
            f"scan report is available only for completed scans; current status is {scan_status}"
        )


def _status(value: Any) -> str:
    return getattr(value, "value", value)


def _display_url(value: str | None) -> str | None:
    if value is None:
        return None
    return redact_url(value)


def _safe_observation(value: dict[str, str | bool] | None) -> dict[str, str | bool] | None:
    """Keep observation metadata while dropping payload-like keys defensively."""

    if value is None:
        return None
    blocked = ("body", "cookie", "authorization", "token", "secret", "password")
    return {
        str(key): item
        for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))
        if not any(marker in str(key).casefold() for marker in blocked)
    }


def _safe_evidence(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    evidence = EvidenceResponse.model_validate(value)
    allowed = MinimalEvidence._allowed_headers
    forbidden = MinimalEvidence._forbidden_headers
    headers: dict[str, str] = {}
    for name, header_value in evidence.headers.items():
        normalized = name.strip().casefold()
        if normalized in forbidden or normalized not in allowed:
            continue
        safe_value = str(header_value)
        if normalized == "location":
            safe_value = redact_url(safe_value)
        headers[normalized] = safe_value
    return {
        "url": redact_url(evidence.url),
        "status_code": evidence.status_code,
        "headers": dict(sorted(headers.items())),
    }


def _finding(value: Any) -> dict[str, Any]:
    finding = FindingResponse.model_validate(value)
    result = finding.model_dump(mode="json", exclude_none=False)
    result["severity"] = _status(finding.severity)
    result["confidence"] = _status(finding.confidence)
    result["status"] = _status(finding.status)
    result["verification"] = _status(finding.verification)
    result["target"] = _display_url(finding.target)
    result["evidence"] = _safe_evidence(finding.evidence)
    result["references"] = sorted(finding.references)
    return result


def _finding_key(value: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    return (
        str(value.get("code") or ""),
        str(value.get("target") or ""),
        str(value.get("module") or ""),
        str(value.get("test_id") or ""),
        str(value.get("severity") or ""),
        str(value.get("title") or ""),
    )


def _check(value: Any) -> dict[str, Any]:
    check = CheckResponse.model_validate(value)
    return {
        "name": _status(check.name),
        "status": _status(check.status),
        "findings": sorted((_finding(item) for item in check.findings), key=_finding_key),
        "evidence": _safe_evidence(check.evidence),
        "observation": _safe_observation(check.observation),
        "started_at": check.started_at.isoformat() if check.started_at else None,
        "completed_at": check.completed_at.isoformat() if check.completed_at else None,
        # Errors are application metadata, not captured HTTP content.  The
        # model's bounded lifecycle error is retained for failed checks.
        "error": check.error,
    }


def _module(value: Any) -> dict[str, Any]:
    data = value.model_dump(mode="json", exclude_none=False)
    data["status"] = _status(value.status)
    data["findings"] = sorted((_finding(item) for item in value.findings), key=_finding_key)
    observations = []
    for observation in value.observations:
        observation_data = observation.model_dump(mode="json", exclude_none=False)
        observation_data["mode"] = _status(observation.mode)
        observation_data["confidence"] = _status(observation.confidence)
        observation_data["status"] = _status(observation.status)
        observation_data["evidence"] = _safe_evidence(observation.evidence)
        observation_data["references"] = sorted(observation.references)
        observations.append(observation_data)
    data["observations"] = sorted(
        observations,
        key=lambda item: (str(item.get("kind") or ""), str(item.get("value") or "")),
    )
    data["references"] = sorted(value.references)
    return data


def _engagement(value: Engagement | None) -> dict[str, Any] | None:
    if value is None:
        return None
    # Engagement is already a non-secret Pydantic boundary.  Sorting is done
    # by the canonical JSON renderer, while lists are normalized here because
    # their order is not meaningful authorization metadata.
    data = value.model_dump(mode="json", exclude_none=False)
    for field in (
        "target_domains",
        "target_ips",
        "target_cidrs",
        "excluded_hosts",
        "excluded_addresses",
        "excluded_routes",
        "permitted_ports",
        "permitted_service_types",
        "allowed_assessment_profiles",
        "allowed_capabilities",
    ):
        data[field] = sorted(data[field])
    return data


def build_report(scan: Any, engagement: Engagement | None = None) -> dict[str, Any]:
    """Build a JSON-shaped report for one completed scan.

    This function is pure: it performs model validation and formatting only;
    callers own fetching the scan and optional engagement metadata.
    """

    result = ScanStatusResponse.model_validate(scan)
    scan_status = _status(result.status)
    if scan_status != "completed":
        raise ReportNotReadyError(scan_status)

    checks = sorted((_check(item) for item in result.checks), key=lambda item: str(item["name"]))
    findings = sorted((_finding(item) for item in result.findings), key=_finding_key)
    assessment = result.assessment
    modules = [] if assessment is None else sorted(
        (_module(item) for item in assessment.modules),
        key=lambda item: (str(item.get("module") or ""), str(item.get("test_id") or "")),
    )
    coverage = result.coverage or (None if assessment is None else assessment.coverage)
    coverage_data = None if coverage is None else coverage.model_dump(mode="json")

    profile = {
        "requested": result.assessment_profile,
        "id": None if assessment is None else assessment.profile_id,
        "version": None if assessment is None else assessment.profile_version,
        "enabled_modules": [] if assessment is None else sorted(assessment.enabled_modules),
    }
    assessment_data = None
    if assessment is not None:
        assessment_data = {
            "status": _status(assessment.status),
            "profile_id": assessment.profile_id,
            "profile_version": assessment.profile_version,
            "enabled_modules": sorted(assessment.enabled_modules),
            "progress": assessment.progress,
            "coverage": coverage_data,
            "modules": modules,
            "findings": sorted((_finding(item) for item in assessment.findings), key=_finding_key),
            "observations": sorted(
                (
                    {
                        **observation.model_dump(mode="json", exclude_none=False),
                        "mode": _status(observation.mode),
                        "confidence": _status(observation.confidence),
                        "status": _status(observation.status),
                        "evidence": _safe_evidence(observation.evidence),
                        "references": sorted(observation.references),
                    }
                    for observation in assessment.observations
                ),
                key=lambda item: (str(item.get("kind") or ""), str(item.get("value") or "")),
            ),
            "timestamp": assessment.timestamp.isoformat(),
            "error": assessment.error,
        }

    engagement_data = _engagement(engagement)
    if engagement_data is None and result.engagement_id is not None:
        engagement_data = {"id": str(result.engagement_id), "metadata_available": False}
    elif engagement_data is not None:
        engagement_data.setdefault("metadata_available", True)

    return {
        "report_version": "0.5",
        "status": scan_status,
        "scan": {
            "id": str(result.id),
            "target_url": redact_url(result.target_url),
            "engagement_id": None if result.engagement_id is None else str(result.engagement_id),
            "assessment_profile": result.assessment_profile,
            "active_testing_authorized": result.active_testing_authorized,
            "status": scan_status,
            "created_at": result.created_at.isoformat(),
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "error": result.error,
        },
        "engagement": engagement_data,
        "profile": profile,
        "summary": result.summary.model_dump(mode="json"),
        "coverage": coverage_data,
        "assessment": assessment_data,
        "checks": checks,
        "findings": findings,
    }


def render_json(report: dict[str, Any]) -> str:
    """Render canonical JSON with stable keys, separators, and Unicode."""

    return json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def _markdown_value(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _markdown_evidence(lines: list[str], evidence: dict[str, Any] | None) -> None:
    if evidence is None:
        return
    lines.append(
        f"- Evidence: `{_markdown_value(evidence['url'])}` (HTTP {_markdown_value(evidence['status_code'])})"
    )
    lines.append(
        f"- Evidence headers: `{_markdown_value(json.dumps(evidence['headers'], sort_keys=True))}`"
    )


def render_markdown(report: dict[str, Any]) -> str:
    """Render the report as deterministic, human-readable Markdown."""

    scan = report["scan"]
    summary = report["summary"]
    lines = [
        "# SENTINEL Scan Report",
        "",
        f"- Report version: `{_markdown_value(report['report_version'])}`",
        f"- Status: `{_markdown_value(report['status'])}`",
        f"- Scan ID: `{_markdown_value(scan['id'])}`",
        f"- Target: `{_markdown_value(scan['target_url'])}`",
        "",
        "## Profile",
        "",
        f"- Requested: `{_markdown_value(report['profile']['requested'])}`",
        f"- ID: `{_markdown_value(report['profile']['id'])}`",
        f"- Version: `{_markdown_value(report['profile']['version'])}`",
        f"- Enabled modules: `{_markdown_value(', '.join(report['profile']['enabled_modules']))}`",
        "",
        "## Engagement",
        "",
    ]
    engagement = report["engagement"]
    if engagement is None:
        lines.append("No engagement metadata attached.")
    else:
        lines.extend(
            [
                f"- ID: `{_markdown_value(engagement.get('id'))}`",
                f"- Status: `{_markdown_value(engagement.get('status'))}`",
                f"- Authorization reference: `{_markdown_value(engagement.get('authorization_reference'))}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Checks: {summary['checks_completed']}/{summary['checks_total']} completed",
            f"- Findings: {summary['findings_total']}",
            f"- Findings by severity: `{_markdown_value(json.dumps(summary['findings_by_severity'], sort_keys=True))}`",
            "",
            "## Assessment coverage",
            "",
        ]
    )
    coverage = report["coverage"]
    if coverage is None:
        lines.append("No assessment coverage recorded.")
    else:
        for key in sorted(coverage):
            lines.append(f"- {key}: `{_markdown_value(coverage[key])}`")
    lines.extend(["", "## Checks", ""])
    for check in report["checks"]:
        lines.append(f"### {_markdown_value(check['name'])} — `{_markdown_value(check['status'])}`")
        _markdown_evidence(lines, check["evidence"])
        if check["observation"]:
            lines.append(f"- Observation: `{_markdown_value(json.dumps(check['observation'], sort_keys=True))}`")
        for finding in check["findings"]:
            lines.append(f"- Finding `{_markdown_value(finding['code'])}`: {_markdown_value(finding['title'])}")
            _markdown_evidence(lines, finding["evidence"])
    lines.extend(["", "## Assessment modules", ""])
    assessment = report["assessment"]
    if assessment is None or not assessment["modules"]:
        lines.append("No assessment modules recorded.")
    else:
        for module in assessment["modules"]:
            lines.append(f"### {_markdown_value(module['module'])} — `{_markdown_value(module['status'])}`")
            for finding in module["findings"]:
                lines.append(f"- Finding `{_markdown_value(finding['code'])}`: {_markdown_value(finding['title'])}")
                _markdown_evidence(lines, finding["evidence"])
            for observation in module["observations"]:
                lines.append(f"- Observation `{_markdown_value(observation['kind'])}`: {_markdown_value(observation.get('value'))}")
                _markdown_evidence(lines, observation["evidence"])
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings recorded.")
    else:
        lines.append("| Code | Severity | Confidence | Target | Title |")
        lines.append("| --- | --- | --- | --- | --- |")
        for finding in report["findings"]:
            lines.append(
                "| " + " | ".join(
                    _markdown_value(finding[field])
                    for field in ("code", "severity", "confidence", "target", "title")
                ) + " |"
            )
    return "\n".join(lines) + "\n"


class ReportExporter:
    """Application-owned pure report renderer, suitable for dependency injection."""

    def export(
        self,
        scan: Any,
        *,
        engagement: Engagement | None = None,
        format: ReportFormat = "json",
    ) -> str:
        report = build_report(scan, engagement)
        if format == "json":
            return render_json(report)
        if format == "markdown":
            return render_markdown(report)
        raise ValueError(f"unsupported report format: {format}")
