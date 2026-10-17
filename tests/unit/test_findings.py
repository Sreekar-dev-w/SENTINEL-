import pytest
from pydantic import ValidationError

from app.scanning.findings import (
    check_csp,
    check_x_content_type_options,
    hsts_applicable,
    observe_https_transport,
    validate_hsts,
)
from app.scanning.models import MinimalEvidence


def test_hsts_only_applies_to_https_and_requires_positive_max_age():
    assert hsts_applicable("http://example.test/") is False
    assert validate_hsts("http://example.test/", {}) is None

    missing = validate_hsts("https://example.test/", {})
    assert missing is not None
    assert missing.code == "hsts-missing-or-invalid"

    assert validate_hsts(
        "https://example.test/",
        {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
    ) is None
    assert validate_hsts("https", {"strict-transport-security": "max-age=0"})


def test_csp_and_nosniff_checks_are_case_insensitive_and_header_only():
    csp = check_csp({"Content-Security-Policy": "default-src 'self'"})
    assert csp is None
    assert check_csp({}) is not None

    assert check_x_content_type_options({"X-Content-Type-Options": "NoSniff"}) is None
    finding = check_x_content_type_options({})
    assert finding is not None
    assert finding.code == "x-content-type-options-nosniff-missing"


def test_evidence_contains_only_small_safe_metadata():
    finding = check_csp(
        {
            "Content-Security-Policy": "",
            "Set-Cookie": "session=secret",
        },
        url="https://example.test/",
    )
    assert finding is not None
    assert finding.evidence is not None
    assert "set-cookie" not in finding.evidence.headers

    with pytest.raises(ValidationError):
        # Sensitive request/response material cannot become evidence.
        MinimalEvidence(
            url="https://example.test/",
            headers={"Authorization": "secret"},
        )


def test_https_observation_does_not_claim_unavailable_tls_details():
    observation = observe_https_transport("https://example.test/")
    assert observation.https is True
    assert observation.tls_details_available is False
    assert "TLS version" in observation.message
    assert not hasattr(observation, "certificate")
