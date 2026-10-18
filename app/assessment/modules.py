"""Pure passive/low-impact assessment module implementations."""

from __future__ import annotations

from app.assessment.context import AssessmentContext
from app.assessment.registry import AssessmentModuleDefinition
from app.scanning.findings import check_csp, check_x_content_type_options, validate_hsts
from app.scanning.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    MinimalEvidence,
    ObservationMode,
    ObservationStatus,
    VerificationStatus,
    WebsiteObservation,
    utc_now,
)


def _reference(definition: AssessmentModuleDefinition) -> str:
    return ",".join(reference.key for reference in definition.references)


def _evidence(context: AssessmentContext, headers: tuple[str, ...] = ()) -> MinimalEvidence:
    response = context.response
    selected = {
        name.lower(): value
        for name in headers
        if (value := response.header(name)) is not None
    }
    return MinimalEvidence(url=response.url, status_code=response.status_code, headers=selected)


def _observation(context: AssessmentContext, definition: AssessmentModuleDefinition, kind: str, value=None, *, status=ObservationStatus.OBSERVED, mode=ObservationMode.OBSERVED) -> WebsiteObservation:
    return WebsiteObservation(
        kind=kind, value=value, mode=mode, confidence=FindingConfidence.HIGH if status == ObservationStatus.OBSERVED else FindingConfidence.LOW,
        status=status, evidence=_evidence(context), module=definition.name,
        test_id=definition.test_id, test_version=definition.test_version,
        reference=_reference(definition), references=[reference.key for reference in definition.references],
        owasp_category=definition.owasp_category, owasp_id=definition.owasp_id,
        timestamp=utc_now()
    )


def _finding(context: AssessmentContext, definition: AssessmentModuleDefinition, *, code: str, title: str, description: str, remediation: str, severity=FindingSeverity.LOW, verification: VerificationStatus = VerificationStatus.POTENTIAL, evidence_headers: tuple[str, ...] = ()) -> Finding:
    references = [reference.key for reference in definition.references]
    return Finding(
        code=code, title=title, description=description, severity=severity, confidence=FindingConfidence.HIGH,
        target=context.response.url, evidence=_evidence(context, evidence_headers), remediation=remediation,
        verification=verification, module=definition.name, test_id=definition.test_id,
        test_version=definition.test_version, reference=_reference(definition), references=references,
        owasp_category=definition.owasp_category, owasp_id=definition.owasp_id,
        timestamp=utc_now()
    )


def security_headers(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    response = context.response
    headers = dict(response.headers)
    findings = [finding for finding in (
        validate_hsts(context.target_url, headers, url=response.url),
        check_csp(headers, url=response.url),
        check_x_content_type_options(headers, url=response.url),
    ) if finding is not None]
    findings = [finding.model_copy(update={
        "module": definition.name,
        "test_id": definition.test_id,
        "test_version": definition.test_version,
        "reference": _reference(definition),
        "references": [reference.key for reference in definition.references],
        "verification": VerificationStatus.CONFIRMED,
        "owasp_category": definition.owasp_category,
        "owasp_id": definition.owasp_id,
        "timestamp": utc_now(),
    }) for finding in findings]
    observation = _observation(context, definition, "security.headers", {
        "hsts": response.has_header("strict-transport-security"),
        "csp": response.has_header("content-security-policy"),
        "nosniff": response.has_header("x-content-type-options"),
    })
    return findings, [observation]


def cookies(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    findings: list[Finding] = []
    total = len(context.response.cookies) + context.response.malformed_cookies
    malformed = context.response.malformed_cookies
    missing = {"secure": 0, "httponly": 0, "samesite": 0}
    for cookie in context.response.cookies:
        if not cookie.secure:
            missing["secure"] += 1
        if not cookie.httponly:
            missing["httponly"] += 1
        if not cookie.samesite:
            missing["samesite"] += 1
    for attribute, count in missing.items():
        if count:
            findings.append(_finding(context, definition, code=f"cookie-{attribute}-missing", title=f"Cookie {attribute.title()} attribute is missing", description=f"{count} observed cookie(s) did not advertise the {attribute} attribute.", remediation=f"Set the {attribute.title()} attribute on cookies where it is appropriate."))
    observation = _observation(
        context, definition, "http.cookies",
        {"count": total, "malformed": malformed, "missing_attributes": [key for key, value in missing.items() if value]},
        status=ObservationStatus.INCONCLUSIVE if malformed else ObservationStatus.OBSERVED,
    )
    return findings, [observation]


def cors(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    response = context.response
    allow_origin = response.header("access-control-allow-origin")
    allow_credentials = (response.header("access-control-allow-credentials") or "").strip().lower() == "true"
    findings: list[Finding] = []
    if allow_origin == "*" and allow_credentials:
        findings.append(_finding(context, definition, code="cors-wildcard-with-credentials", title="CORS wildcard is combined with credentials", description="The response advertises a wildcard origin and credentialed CORS, which is an invalid and unsafe policy combination.", remediation="Use an explicit trusted origin and review credentialed cross-origin access.", severity=FindingSeverity.MEDIUM))
    observation = _observation(context, definition, "http.cors", {
        "allow_origin_present": allow_origin is not None,
        "allow_origin_wildcard": allow_origin == "*",
        "allow_credentials": allow_credentials,
        "vary_origin": "origin" in (response.header("vary") or "").lower(),
    }, status=ObservationStatus.OBSERVED)
    return findings, [observation]


def redirects(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    observations: list[WebsiteObservation] = []
    for previous in context.response.history:
        observations.append(_observation(context, definition, "http.redirect", {
            "from": previous.url, "to": previous.location,
            "status_code": previous.status_code, "followed": True,
        }))
    if not observations:
        observations.append(_observation(context, definition, "http.redirect", {"count": 0}))
    return [], observations


def information_exposure(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    response = context.response
    server = response.header("server")
    powered_by = response.header("x-powered-by")
    findings: list[Finding] = []
    if powered_by:
        findings.append(_finding(
            context, definition, code="technology-header-disclosure",
            title="Response discloses implementation metadata",
            description="The X-Powered-By response header discloses implementation metadata. Presence alone does not prove a vulnerability.",
            remediation="Remove unnecessary implementation-identifying response headers or document the disclosure decision.",
            verification=VerificationStatus.POTENTIAL,
            evidence_headers=("x-powered-by",),
        ))
    values = [value for value in (server, powered_by) if value]
    if context.intelligence is not None:
        values.extend(
            resource.url for resource in context.intelligence.resources
            if resource.kind in {"robots", "sitemap"}
        )
    status = ObservationStatus.OBSERVED if values else ObservationStatus.INCONCLUSIVE
    observation = _observation(
        context, definition, "information.metadata",
        {"indicators": values[:32], "profile_available": context.intelligence is not None},
        status=status,
    )
    return findings, [observation]


def api_inventory(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    if context.intelligence is None:
        return [], [_observation(context, definition, "api.inventory", {"available": False}, status=ObservationStatus.INCONCLUSIVE)]
    candidates = [
        resource.url for resource in context.intelligence.resources
        if any(marker in resource.url.lower() for marker in ("/api", "openapi", "swagger", "graphql"))
    ][:32]
    observation = _observation(
        context, definition, "api.inventory",
        {"discovered_routes": candidates, "authentication_tested": False},
        status=ObservationStatus.OBSERVED,
    )
    return [], [observation]


def unavailable(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    return [], [_observation(context, definition, f"assessment.{definition.name}", status=ObservationStatus.UNAVAILABLE, mode=ObservationMode.INFERRED)]


def _lab_unconfigured(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    """Controlled modules never silently fall back to the network context."""

    return [], [_observation(
        context, definition, f"assessment.{definition.name}",
        {"available": False, "reason": "controlled lab metadata is not configured"},
        status=ObservationStatus.UNAVAILABLE, mode=ObservationMode.INFERRED,
    )]


def authentication_protected_route(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    lab = context.lab
    if lab is None:
        return _lab_unconfigured(context, definition)
    metadata = lab.protected_route_metadata(context.target_url)
    if metadata is None:
        return [], [_observation(context, definition, "lab.authentication", {"available": False, "reason": "unsupported lab scope"}, status=ObservationStatus.INCONCLUSIVE, mode=ObservationMode.INFERRED)]
    findings: list[Finding] = []
    if not metadata.protected or metadata.anonymous_access:
        findings.append(_finding(
            context, definition, code="protected-route-allows-anonymous",
            title="Protected route is accessible anonymously",
            description="The declared protected-route expectation is not met by the synthetic route metadata.",
            remediation=definition.remediation, severity=FindingSeverity.HIGH,
            verification=VerificationStatus.CONFIRMED,
        ))
    observation = _observation(context, definition, "lab.authentication", {
        "route_declared_protected": metadata.protected,
        "anonymous_access": metadata.anonymous_access,
        "authenticated_access": metadata.authenticated_access,
    })
    return findings, [observation]


def session_cookie_metadata(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    lab = context.lab
    if lab is None:
        return _lab_unconfigured(context, definition)
    metadata = lab.session_cookie_metadata(context.target_url)
    if metadata is None or not metadata.present:
        return [], [_observation(context, definition, "lab.session-cookie", {"available": False, "reason": "session-cookie metadata not supplied"}, status=ObservationStatus.INCONCLUSIVE, mode=ObservationMode.INFERRED)]
    findings: list[Finding] = []
    missing = [name for name, value in (("secure", metadata.secure), ("httponly", metadata.httponly), ("samesite", bool(metadata.samesite))) if not value]
    for attribute in missing:
        findings.append(_finding(
            context, definition, code=f"session-cookie-{attribute}-missing",
            title=f"Session cookie {attribute.title()} attribute is missing",
            description=f"Synthetic session-cookie metadata does not advertise the {attribute} attribute.",
            remediation=definition.remediation,
            verification=VerificationStatus.CONFIRMED,
        ))
    return findings, [_observation(context, definition, "lab.session-cookie", {
        "present": True, "secure": bool(metadata.secure), "httponly": bool(metadata.httponly),
        "samesite_present": bool(metadata.samesite),
    })]


def authorization_object_access(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    lab = context.lab
    if lab is None:
        return _lab_unconfigured(context, definition)
    cases = lab.authorization_metadata(context.target_url)
    if not cases:
        return [], [_observation(context, definition, "lab.authorization", {"available": False, "reason": "authorization expectations not supplied"}, status=ObservationStatus.INCONCLUSIVE, mode=ObservationMode.INFERRED)]
    findings: list[Finding] = []
    mismatches = []
    for case in cases:
        mismatch = case.actual_allowed != case.expected_allowed
        if mismatch:
            mismatches.append(case.requester_id)
            findings.append(_finding(
                context, definition, code="cross-user-object-access",
                title="Synthetic user can access another user's resource",
                description="The bounded policy decision allows access that the explicit synthetic expectation denies; this comparison uses ownership and policy metadata rather than an HTTP status code.",
                remediation=definition.remediation, severity=FindingSeverity.HIGH,
                verification=VerificationStatus.CONFIRMED,
            ))
    observation = _observation(context, definition, "lab.authorization", {
        "cases_tested": len(cases), "mismatches": len(mismatches),
        "cross_user_mismatch": bool(mismatches),
        "status_code_used": False,
    })
    return findings, [observation]


def input_validation_safety(context: AssessmentContext, definition: AssessmentModuleDefinition) -> tuple[list[Finding], list[WebsiteObservation]]:
    lab = context.lab
    if lab is None:
        return _lab_unconfigured(context, definition)
    probes = lab.input_validation_metadata(context.target_url)
    if not probes:
        return [], [_observation(context, definition, "lab.input-validation", {"available": False, "reason": "input probe metadata not supplied"}, status=ObservationStatus.INCONCLUSIVE, mode=ObservationMode.INFERRED)]
    findings: list[Finding] = []
    validation_failures = 0
    validation_weaknesses = 0
    injection_observations = 0
    for probe in probes:
        if not probe.validation_failed:
            validation_weaknesses += 1
            findings.append(_finding(
                context, definition, code="malformed-input-not-rejected",
                title="Malformed input was not rejected",
                description="The bounded malformed-marker/content-type probe was accepted. This is a validation weakness and does not establish injection.",
                remediation=definition.remediation,
                verification=VerificationStatus.CONFIRMED,
            ))
        else:
            validation_failures += 1
        if probe.error_disclosed or not probe.safe_error_handling:
            findings.append(_finding(
                context, definition, code="input-error-disclosure",
                title="Input handling discloses unsafe error metadata",
                description="The bounded malformed-input result reports unsafe error handling or disclosure metadata.",
                remediation=definition.remediation,
                severity=FindingSeverity.MEDIUM, verification=VerificationStatus.CONFIRMED,
            ))
        if probe.injection_observed:
            injection_observations += 1
            findings.append(_finding(
                context, definition, code="injection-observed-in-lab",
                title="Injection behavior observed in controlled lab",
                description="The lab explicitly reports injection behavior. It is not inferred from malformed input handling.",
                remediation=definition.remediation,
                severity=FindingSeverity.HIGH, verification=VerificationStatus.CONFIRMED,
            ))
    observation = _observation(context, definition, "lab.input-validation", {
        "probes_tested": len(probes), "malformed_input_tested": all(item.malformed_input_tested for item in probes),
        "content_types": sorted({item.content_type for item in probes}),
        "validation_failures": validation_failures,
        "validation_weaknesses": validation_weaknesses,
        "injection_observed": injection_observations > 0,
        "injection_inferred_from_validation": False,
    })
    return findings, [observation]


MODULE_FUNCTIONS = {
    "security-headers": security_headers,
    "cookies": cookies,
    "cors": cors,
    "redirects": redirects,
    "information-exposure": information_exposure,
    "api-inventory": api_inventory,
    "tls-metadata": unavailable,
    "authenticated-authorization": unavailable,
    "external-vulnerability-intelligence": unavailable,
    "authentication-protected-route": authentication_protected_route,
    "session-cookie-metadata": session_cookie_metadata,
    "authorization-object-access": authorization_object_access,
    "input-validation-safety": input_validation_safety,
}

run_security_headers = security_headers
run_cookie_attributes = cookies
run_cors = cors
observe_redirects = redirects
