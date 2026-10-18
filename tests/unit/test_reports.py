from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient
import pytest

from app.api.app import create_app
from app.api.models import (
    CheckResponse,
    EvidenceResponse,
    FindingResponse,
    ScanStatusResponse,
    SummaryResponse,
)
from app.reporting.reports import build_report, render_json, render_markdown
from app.scanning.models import (
    AssessmentCoverage,
    AssessmentModuleResult,
    AssessmentResult,
    AssessmentStatus,
    Finding,
    FindingSeverity,
    MinimalEvidence,
)

_CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
_SCAN_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_ENGAGEMENT_ID = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


def _finding(code: str, *, target: str = "https://example.test/path?token=secret") -> FindingResponse:
    return FindingResponse(
        code=code,
        severity="high",
        confidence="high",
        target=target,
        title=f"Title {code}",
        description="A safe metadata-only finding",
        evidence=EvidenceResponse(
            url=target,
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "session=secret-cookie",
                "X-Private": "should-not-export",
            },
        ),
    )


def _completed_scan(*, reverse: bool = False) -> ScanStatusResponse:
    first = _finding("z-last")
    second = _finding("a-first", target="https://example.test/?password=secret")
    checks = [
        CheckResponse(name="z-check", status="failed", findings=[first], evidence=first.evidence),
        CheckResponse(
            name="a-check",
            status="passed",
            findings=[second],
            evidence=second.evidence,
            observation={"scheme": "https", "response_body": "secret-body"},
        ),
    ]
    if reverse:
        checks.reverse()
    assessment = AssessmentResult(
        status=AssessmentStatus.COMPLETED,
        profile_id="sentinel-test-profile",
        profile_version="0.5.0",
        enabled_modules=["module-z", "module-a"],
        coverage=AssessmentCoverage(total_modules=2, completed_modules=2, findings_total=2),
        timestamp=_CREATED,
        modules=[
            AssessmentModuleResult(
                module="module-z",
                status=AssessmentStatus.COMPLETED,
                findings=[
                    Finding(
                        code="module-finding",
                        title="Module finding",
                        description="Safe module metadata",
                        severity=FindingSeverity.LOW,
                        evidence=MinimalEvidence(
                            url="https://example.test/module?value=secret",
                            headers={"Content-Type": "text/plain"},
                        ),
                    )
                ],
                timestamp=_CREATED,
            ),
        ],
    )
    return ScanStatusResponse(
        id=_SCAN_ID,
        target_url="https://example.test/start?secret=do-not-export",
        engagement_id=_ENGAGEMENT_ID,
        assessment_profile="passive",
        status="completed",
        created_at=_CREATED,
        started_at=_CREATED,
        completed_at=_CREATED,
        summary=SummaryResponse(
            checks_total=2,
            checks_completed=2,
            findings_total=2,
            findings_by_severity={"high": 2},
        ),
        checks=checks,
        findings=[first, second] if not reverse else [second, first],
        assessment=assessment,
        coverage=assessment.coverage,
    )


def test_json_and_markdown_exports_are_deterministic_and_include_safe_sections() -> None:
    first = build_report(_completed_scan())
    second = build_report(_completed_scan(reverse=True))

    assert render_json(first) == render_json(second)
    markdown = render_markdown(first)
    assert "## Summary" in markdown
    assert "## Executive summary" in markdown
    assert "## Limitations" in markdown
    assert first["report_version"] == "0.6"
    assert first["executive_summary"]["findings_total"] == 2
    assert first["skipped_checks"] == []
    assert first["unmet_prerequisites"] == []
    assert "## Assessment coverage" in markdown
    assert "## Assessment modules" in markdown
    assert "## Findings" in markdown
    assert "Verification" in markdown
    assert "module-finding" in markdown
    assert "do-not-export" not in render_json(first)
    assert "password=secret" not in render_json(first)
    assert "session=secret-cookie" not in markdown
    assert "secret-body" not in render_json(first)
    assert "x-private" not in render_json(first)
    assert first["checks"][0]["name"] == "a-check"
    assert first["assessment"]["modules"][0]["module"] == "module-z"


@pytest.mark.parametrize("status", ["failed", "cancelled"])
def test_terminal_failure_and_cancellation_reports_preserve_lifecycle(status: str) -> None:
    scan = _completed_scan()
    scan.status = status
    report = build_report(scan)
    assert report["status"] == status
    assert report["scan"]["status"] == status
    assert f"- Status: `{status}`" in render_markdown(report)


class ReportManager:
    def __init__(self, scan: ScanStatusResponse | None) -> None:
        self.scan = scan

    async def get_scan(self, scan_id: str):
        if self.scan is not None and scan_id == str(self.scan.id):
            return self.scan
        return None


def test_report_route_handles_unknown_and_non_terminal_scans() -> None:
    queued = _completed_scan()
    queued.status = "running"
    client = TestClient(create_app(ReportManager(queued)))

    unknown = client.get("/scans/missing/report")
    not_ready = client.get(f"/scans/{queued.id}/report")

    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "Scan not found"
    assert not_ready.status_code == 409
    assert "terminal" in not_ready.json()["detail"]


def test_report_route_returns_json_and_markdown_without_side_effects() -> None:
    client = TestClient(create_app(ReportManager(_completed_scan())))

    json_response = client.get(f"/scans/{_SCAN_ID}/report?format=json")
    markdown_response = client.get(f"/scans/{_SCAN_ID}/report?format=markdown")

    assert json_response.status_code == 200
    assert json_response.headers["content-type"] == "application/json"
    assert json_response.json()["status"] == "completed"
    assert json_response.json()["engagement"]["id"] == str(_ENGAGEMENT_ID)
    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"] == "text/markdown; charset=utf-8"
    assert markdown_response.text.startswith("# SENTINEL Scan Report\n")
