"""Deterministic, metadata-only report exports for completed scans.

The report boundary deliberately consumes the existing API/domain models and
does not know how scans are executed or persisted.  Evidence is copied through
the same small header allowlist as :class:`MinimalEvidence`; response bodies,
cookies, and credential-bearing headers cannot enter either output format.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from app.api.models import (
    CheckResponse,
    EvidenceResponse,
    FindingResponse,
    ScanStatusResponse,
)
from app.engagement.models import Engagement
from app.external_tools import AdapterExecutionResult
from app.scanning.intelligence import redact_url
from app.scanning.models import MinimalEvidence

ReportFormat = Literal["json", "markdown"]

_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(?:authorization|token|secret|password|cookie)\b\s*[:=]\s*[^\s,;]+"
)

_SEVERITY_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_VERIFICATION_PRIORITY = {"confirmed": 3, "potential": 2, "not_verified": 1}


class ReportNotReadyError(ValueError):
    """Raised when a scan exists but has no terminal report result."""

    def __init__(self, scan_status: str) -> None:
        self.scan_status = scan_status
        super().__init__(
            f"scan report is available only for terminal scans; current status is {scan_status}"
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


def _safe_payload(value: Any) -> Any:
    """Copy JSON-shaped metadata while dropping payload-like fields."""

    blocked = ("body", "cookie", "authorization", "token", "secret", "password")
    if isinstance(value, dict):
        return {
            str(key): _safe_payload(item)
            for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))
            if not any(marker in str(key).casefold() for marker in blocked)
        }
    if isinstance(value, list):
        return [_safe_payload(item) for item in value]
    if isinstance(value, str) and "://" in value:
        return redact_url(value)
    return value


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


def _finding_priority_key(value: dict[str, Any]) -> tuple[int, int, str, str, str, str]:
    """Sort findings by actionable priority while keeping ties deterministic."""

    return (
        -_SEVERITY_PRIORITY.get(str(value.get("severity") or "").casefold(), 0),
        -_VERIFICATION_PRIORITY.get(str(value.get("verification") or "").casefold(), 0),
        str(value.get("code") or ""),
        str(value.get("target") or ""),
        str(value.get("module") or ""),
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
        observation_data = _safe_payload(
            observation.model_dump(mode="json", exclude_none=False)
        )
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


def _safe_external_string(value: Any, *, limit: int = 2_048) -> str:
    """Keep normalized adapter text bounded and redact URL-bearing values."""

    text = str(value or "").strip()[:limit]
    text = _SENSITIVE_VALUE.sub("[redacted]", text)
    if "://" in text:
        text = redact_url(text)
    return text


def _external_finding(value: Any) -> dict[str, Any]:
    finding = value if isinstance(value, dict) else value.model_dump(mode="json")
    result = {
        "source": _safe_external_string(finding.get("source"), limit=128),
        "rule_id": _safe_external_string(finding.get("rule_id"), limit=128),
        "title": _safe_external_string(finding.get("title")),
        "description": _safe_external_string(finding.get("description")),
        "severity": _safe_external_string(finding.get("severity"), limit=32),
        "confidence": _safe_external_string(finding.get("confidence"), limit=32),
        "target": _display_url(finding.get("target")),
        "remediation": (
            None
            if finding.get("remediation") is None
            else _safe_external_string(finding.get("remediation"))
        ),
        "references": sorted(
            redact_url(_safe_external_string(reference, limit=512))
            for reference in finding.get("references", ())
        ),
    }
    provenance = finding.get("provenance") or {}
    result["provenance"] = {
        "adapter": _safe_external_string(provenance.get("adapter"), limit=128),
        "tool": _safe_external_string(provenance.get("tool"), limit=128),
        "tool_version": (
            None
            if provenance.get("tool_version") is None
            else _safe_external_string(provenance.get("tool_version"), limit=128)
        ),
        "api_version": (
            None
            if provenance.get("api_version") is None
            else _safe_external_string(provenance.get("api_version"), limit=128)
        ),
        "source_alert_id": (
            None
            if provenance.get("source_alert_id") is None
            else _safe_external_string(provenance.get("source_alert_id"), limit=128)
        ),
        "observed_at": provenance.get("observed_at"),
    }
    return result


def _external_observation(value: Any) -> dict[str, Any]:
    observation = value if isinstance(value, dict) else value.model_dump(mode="json")
    provenance = observation.get("provenance") or {}
    return {
        "source": _safe_external_string(observation.get("source"), limit=128),
        "kind": _safe_external_string(observation.get("kind"), limit=128),
        "key": _safe_external_string(observation.get("key"), limit=128),
        "value": _safe_external_string(observation.get("value")),
        "target": _display_url(observation.get("target")),
        "provenance": {
            "adapter": _safe_external_string(provenance.get("adapter"), limit=128),
            "tool": _safe_external_string(provenance.get("tool"), limit=128),
            "tool_version": provenance.get("tool_version"),
            "api_version": provenance.get("api_version"),
            "source_alert_id": provenance.get("source_alert_id"),
            "observed_at": provenance.get("observed_at"),
        },
    }


def _external_result(value: Any) -> dict[str, Any]:
    result = AdapterExecutionResult.model_validate(value)
    data = {
        "tool": result.tool.model_dump(mode="json"),
        "state": _status(result.state),
        "partial": result.partial,
        "requests_made": result.requests_made,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat(),
        "diagnostics": sorted(
            (diagnostic.model_dump(mode="json") for diagnostic in result.diagnostics),
            key=lambda item: (str(item.get("phase")), str(item.get("code"))),
        ),
        "findings": sorted(
            (_external_finding(item) for item in result.findings),
            key=lambda item: (
                item["source"],
                item["rule_id"],
                item["target"] or "",
                item["title"],
            ),
        ),
        "observations": sorted(
            (_external_observation(item) for item in result.observations),
            key=lambda item: (
                item["source"],
                item["kind"],
                item["key"],
                item["target"] or "",
            ),
        ),
    }
    data["tool"] = _safe_payload(data["tool"])
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
    """Build a JSON-shaped report for one terminal scan.

    This function is pure: it performs model validation and formatting only;
    callers own fetching the scan and optional engagement metadata.
    """

    result = ScanStatusResponse.model_validate(scan)
    scan_status = _status(result.status)
    if scan_status not in {"completed", "failed", "cancelled"}:
        raise ReportNotReadyError(scan_status)

    checks = sorted((_check(item) for item in result.checks), key=lambda item: str(item["name"]))
    assessment = result.assessment
    modules = [] if assessment is None else sorted(
        (_module(item) for item in assessment.modules),
        key=lambda item: (str(item.get("module") or ""), str(item.get("test_id") or "")),
    )
    coverage = result.coverage or (None if assessment is None else assessment.coverage)
    coverage_data = None if coverage is None else coverage.model_dump(mode="json")
    skipped_checks = [
        {
            "name": check["name"],
            "status": check["status"],
            "error": check["error"],
        }
        for check in checks
        if check["status"] in {"skipped", "error"}
    ]
    unmet_prerequisites = [
        {
            "module": module.get("module"),
            "status": module.get("status"),
            "reason": module.get("skip_reason") or module.get("error"),
        }
        for module in modules
        if module.get("status") in {"skipped", "unavailable", "error"}
    ]

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
        "findings": sorted((_finding(item) for item in assessment.findings), key=_finding_priority_key),
            "observations": sorted(
                (
                    {
                        **_safe_payload(observation.model_dump(mode="json", exclude_none=False)),
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

    findings = [_finding(item) for item in result.findings]
    if assessment is not None:
        findings.extend(_finding(item) for item in assessment.findings)
    findings = sorted(findings, key=_finding_priority_key)
    limitations = [
        "This report covers only configured and applicable SENTINEL modules; it does not claim comprehensive OWASP coverage.",
    ]
    if scan_status in {"failed", "cancelled"}:
        limitations.append(f"The assessment ended with terminal status: {scan_status}.")
    if assessment is None:
        limitations.append("No assessment result was recorded for this scan.")
    elif assessment.coverage.partial:
        limitations.append("Assessment coverage is partial because one or more modules were skipped, unavailable, or failed.")
    if skipped_checks:
        limitations.append("One or more legacy checks were skipped or errored; see the Checks section.")
    external_tools = sorted(
        (_external_result(item) for item in result.external_tools),
        key=lambda item: (str(item["tool"].get("name") or ""), str(item["state"])),
    )
    external_findings = sorted(
        [finding for tool in external_tools for finding in tool["findings"]],
        key=lambda item: (
            -_SEVERITY_PRIORITY.get(str(item.get("severity") or "").casefold(), 0),
            item["source"],
            item["rule_id"],
            item["target"] or "",
            item["title"],
        ),
    )
    external_observations = sorted(
        [observation for tool in external_tools for observation in tool["observations"]],
        key=lambda item: (
            item["source"],
            item["kind"],
            item["key"],
            item["target"] or "",
        ),
    )
    external_states = {str(tool["state"]) for tool in external_tools}
    if external_tools:
        limitations.append(
            "External-tool results are limited to explicitly selected adapters and normalized output."
        )
    if any(state in {"unavailable", "failed", "partial", "cancelled", "rejected"} for state in external_states):
        limitations.append(
            "One or more selected external tools were unavailable, partial, cancelled, or rejected; see External tools."
        )
    high_priority = sum(
        str(finding.get("severity") or "").casefold() in {"critical", "high"}
        for finding in (*findings, *external_findings)
    )
    executive_summary = {
        "status": scan_status,
        "findings_total": len(findings) + len(external_findings),
        "high_priority_findings": high_priority,
        "confirmed_findings": sum(
            finding.get("verification") == "confirmed" for finding in findings
        ),
        "potential_findings": sum(
            finding.get("verification") == "potential" for finding in findings
        ),
        "coverage_partial": bool(coverage_data and coverage_data.get("partial")),
        "limitations_count": len(limitations),
    }

    return {
        "report_version": "0.6",
        "status": scan_status,
        "executive_summary": executive_summary,
        "limitations": limitations,
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
        "skipped_checks": skipped_checks,
        "unmet_prerequisites": unmet_prerequisites,
        "assessment": assessment_data,
        "checks": checks,
        "findings": findings,
        "external_tools": external_tools,
        "external_findings": external_findings,
        "external_observations": external_observations,
    }


def render_json(report: dict[str, Any]) -> str:
    """Render canonical JSON with stable keys, separators, and Unicode."""

    return json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def _markdown_value(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("`", "\\`").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


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
        "## Executive summary",
        "",
        f"- Findings: {_markdown_value(report['executive_summary']['findings_total'])}",
        f"- High-priority findings: {_markdown_value(report['executive_summary']['high_priority_findings'])}",
        f"- Confirmed findings: {_markdown_value(report['executive_summary']['confirmed_findings'])}",
        f"- Potential findings: {_markdown_value(report['executive_summary']['potential_findings'])}",
        f"- Coverage partial: `{_markdown_value(report['executive_summary']['coverage_partial'])}`",
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
    lines.extend(["", "## Limitations", ""])
    for limitation in report["limitations"]:
        lines.append(f"- {_markdown_value(limitation)}")
    lines.extend(["", "## Skipped checks and unmet prerequisites", ""])
    skipped_items = [
        *[
            f"check {item['name']}: {item['status']}"
            + (f" ({item['error']})" if item.get("error") else "")
            for item in report["skipped_checks"]
        ],
        *[
            f"module {item['module']}: {item['status']}"
            + (f" ({item['reason']})" if item.get("reason") else "")
            for item in report["unmet_prerequisites"]
        ],
    ]
    if not skipped_items:
        lines.append("No skipped checks or unmet prerequisites were recorded.")
    else:
        lines.extend(f"- {_markdown_value(item)}" for item in skipped_items)
    lines.extend(["", "## Checks", ""])
    for check in report["checks"]:
        lines.append(f"### {_markdown_value(check['name'])} — `{_markdown_value(check['status'])}`")
        _markdown_evidence(lines, check["evidence"])
        if check["observation"]:
            lines.append(f"- Observation: `{_markdown_value(json.dumps(check['observation'], sort_keys=True))}`")
        for finding in check["findings"]:
            lines.append(
                f"- Finding `{_markdown_value(finding['code'])}`: {_markdown_value(finding['title'])}"
                f" — {_markdown_value(finding['verification'])}, {_markdown_value(finding['status'])}"
            )
            if finding.get("remediation"):
                lines.append(f"  - Remediation: {_markdown_value(finding['remediation'])}")
            _markdown_evidence(lines, finding["evidence"])
    lines.extend(["", "## Assessment modules", ""])
    assessment = report["assessment"]
    if assessment is None or not assessment["modules"]:
        lines.append("No assessment modules recorded.")
    else:
        for module in assessment["modules"]:
            lines.append(f"### {_markdown_value(module['module'])} — `{_markdown_value(module['status'])}`")
            if module.get("skip_reason"):
                lines.append(f"- Skip reason: {_markdown_value(module['skip_reason'])}")
            if module.get("error"):
                lines.append(f"- Error: {_markdown_value(module['error'])}")
            for finding in module["findings"]:
                lines.append(
                    f"- Finding `{_markdown_value(finding['code'])}`: {_markdown_value(finding['title'])}"
                    f" — {_markdown_value(finding['verification'])}, {_markdown_value(finding['status'])}"
                )
                if finding.get("remediation"):
                    lines.append(f"  - Remediation: {_markdown_value(finding['remediation'])}")
                _markdown_evidence(lines, finding["evidence"])
            for observation in module["observations"]:
                lines.append(f"- Observation `{_markdown_value(observation['kind'])}`: {_markdown_value(observation.get('value'))}")
                _markdown_evidence(lines, observation["evidence"])
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("No findings recorded.")
    else:
        lines.append("| Code | Severity | Verification | Status | Target | Title |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for finding in report["findings"]:
            lines.append(
                "| " + " | ".join(
                    _markdown_value(finding[field])
                    for field in ("code", "severity", "verification", "status", "target", "title")
                ) + " |"
            )
    lines.extend(["", "## External tools", ""])
    external_tools = report.get("external_tools", [])
    if not external_tools:
        lines.append("No external tools were selected.")
    else:
        for tool in external_tools:
            identity = tool["tool"]
            lines.append(
                f"### {_markdown_value(identity.get('name'))} — `{_markdown_value(tool['state'])}`"
            )
            lines.append(
                f"- Vendor: `{_markdown_value(identity.get('vendor'))}`; adapter: `{_markdown_value(identity.get('adapter_version'))}`"
            )
            if identity.get("tool_version"):
                lines.append(f"- Tool version: `{_markdown_value(identity['tool_version'])}`")
            if tool.get("partial"):
                lines.append("- Partial result: `true`")
            for diagnostic in tool.get("diagnostics", []):
                lines.append(
                    f"- Diagnostic `{_markdown_value(diagnostic.get('code'))}`: {_markdown_value(diagnostic.get('message'))}"
                )
            for finding in tool.get("findings", []):
                provenance = finding.get("provenance", {})
                lines.append(
                    f"- Finding `{_markdown_value(finding['rule_id'])}`: {_markdown_value(finding['title'])}"
                    f" — {_markdown_value(finding['severity'])}, {_markdown_value(finding['confidence'])}"
                    f" (source: `{_markdown_value(provenance.get('adapter'))}`)"
                )
                if finding.get("target"):
                    lines.append(f"  - Target: `{_markdown_value(finding['target'])}`")
                if finding.get("remediation"):
                    lines.append(f"  - Remediation: {_markdown_value(finding['remediation'])}")
            for observation in tool.get("observations", []):
                provenance = observation.get("provenance", {})
                lines.append(
                    f"- Observation `{_markdown_value(observation['kind'])}`: {_markdown_value(observation.get('value'))}"
                    f" (source: `{_markdown_value(provenance.get('adapter'))}`)"
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
