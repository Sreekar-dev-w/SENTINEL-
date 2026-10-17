"""Pure initial response checks.

The functions in this module inspect only a URL and response metadata supplied
by the caller.  They perform no network access and never inspect or retain a
response body.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from app.scanning.models import (
    Finding,
    FindingConfidence,
    FindingSeverity,
    MinimalEvidence,
    TransportObservation,
)


def _scheme(value: str) -> str:
    """Return a normalized scheme from either a URL or a scheme string."""

    candidate = value.strip().lower()
    if "://" in candidate:
        return urlsplit(candidate).scheme
    return candidate.removesuffix(":")


def hsts_applicable(url_or_scheme: str) -> bool:
    """Return whether HSTS is meaningful for the requested transport."""

    return _scheme(url_or_scheme) == "https"


def _response_metadata(
    response_or_headers: Any,
    *,
    url: str | None = None,
) -> tuple[str, int | None, Mapping[str, str]]:
    """Extract only URL/status/headers from a response-like value."""

    if isinstance(response_or_headers, Mapping):
        return url or "unknown://response", None, response_or_headers
    response_url = str(getattr(response_or_headers, "url", url or "unknown://response"))
    status_code = getattr(response_or_headers, "status_code", None)
    response_headers = getattr(response_or_headers, "headers", {})
    if not isinstance(response_headers, Mapping):
        raise TypeError("response headers must be a mapping")
    return url or response_url, status_code, response_headers


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return str(value)
    return None


def _evidence(
    url: str,
    status_code: int | None,
    headers: Mapping[str, str],
    names: tuple[str, ...],
) -> MinimalEvidence:
    selected = {
        name: value
        for name in names
        if (value := _header(headers, name)) is not None
    }
    return MinimalEvidence(url=url, status_code=status_code, headers=selected)


def validate_hsts(
    url_or_scheme: str,
    response_or_headers: Any,
    *,
    url: str | None = None,
) -> Finding | None:
    """Return an HSTS finding when HTTPS lacks a valid ``max-age`` directive.

    HTTP responses are not reported as HSTS failures because HSTS is only
    applicable to HTTPS.  A positive integer ``max-age`` is the required
    directive; optional directives are not needed to establish presence.
    """

    evidence_url, status_code, headers = _response_metadata(response_or_headers, url=url)
    if not hsts_applicable(url_or_scheme):
        return None
    value = _header(headers, "strict-transport-security")
    valid = False
    if value:
        for directive in value.split(";"):
            name, separator, argument = directive.strip().partition("=")
            if name.lower() == "max-age" and separator:
                try:
                    valid = int(argument.strip()) > 0
                except ValueError:
                    valid = False
                break
    if valid:
        return None
    return Finding(
        code="hsts-missing-or-invalid",
        title="Strict-Transport-Security is missing or invalid",
        description="HTTPS should return Strict-Transport-Security with a positive max-age.",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        target=evidence_url,
        evidence=_evidence(evidence_url, status_code, headers, ("strict-transport-security",)),
        remediation="Return a Strict-Transport-Security header with a positive max-age over HTTPS.",
    )


def check_hsts(
    url_or_scheme: str,
    response_or_headers: Any,
    *,
    url: str | None = None,
) -> Finding | None:
    """Alias for :func:`validate_hsts` used by check orchestration."""

    return validate_hsts(url_or_scheme, response_or_headers, url=url)


def check_csp(
    response_or_headers: Any,
    *,
    url: str | None = None,
) -> Finding | None:
    """Return a finding when Content-Security-Policy is absent or empty."""

    evidence_url, status_code, headers = _response_metadata(response_or_headers, url=url)
    if (_header(headers, "content-security-policy") or "").strip():
        return None
    return Finding(
        code="csp-missing",
        title="Content-Security-Policy is missing",
        description="The response does not advertise a Content-Security-Policy.",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        target=evidence_url,
        evidence=_evidence(evidence_url, status_code, headers, ("content-security-policy",)),
        remediation="Define a restrictive Content-Security-Policy appropriate for the application.",
    )


def check_x_content_type_options(
    response_or_headers: Any,
    *,
    url: str | None = None,
) -> Finding | None:
    """Return a finding unless X-Content-Type-Options contains ``nosniff``."""

    evidence_url, status_code, headers = _response_metadata(response_or_headers, url=url)
    value = _header(headers, "x-content-type-options") or ""
    if any(token.strip().lower() == "nosniff" for token in value.split(",")):
        return None
    return Finding(
        code="x-content-type-options-nosniff-missing",
        title="X-Content-Type-Options nosniff is missing",
        description="The response does not set X-Content-Type-Options to nosniff.",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        target=evidence_url,
        evidence=_evidence(evidence_url, status_code, headers, ("x-content-type-options",)),
        remediation="Return X-Content-Type-Options: nosniff.",
    )


def observe_https_transport(url_or_scheme: str) -> TransportObservation:
    """Describe scheme-level transport without inventing TLS details."""

    is_https = hsts_applicable(url_or_scheme)
    if is_https:
        message = (
            "HTTPS transport was requested/observed; TLS version, cipher, "
            "certificate, and verification details are unavailable here."
        )
    else:
        message = "HTTP transport was requested/observed; HTTPS is not in use."
    return TransportObservation(
        scheme=_scheme(url_or_scheme),
        https=is_https,
        tls_details_available=False,
        message=message,
    )


# Friendly names for callers that use the check-oriented vocabulary.
check_https_transport = observe_https_transport
check_content_security_policy = check_csp
check_nosniff = check_x_content_type_options
is_hsts_applicable = hsts_applicable
observe_https = observe_https_transport
