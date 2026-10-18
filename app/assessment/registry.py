"""Immutable v0.3 assessment registry and versioned OWASP references."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.assessment.lab import (
    LAB_AUTHENTICATION,
    LAB_AUTHORIZATION,
    LAB_INPUT_VALIDATION,
    LAB_SCOPE,
    LAB_SESSION_COOKIE_METADATA,
)


@dataclass(frozen=True, slots=True)
class StandardReference:
    """One exact, version-qualified standard mapping."""

    standard: str
    version: str
    identifier: str
    title: str
    url: str

    @property
    def key(self) -> str:
        return f"{self.standard}:{self.version}:{self.identifier}"


# The umbrella constants remain exported for callers that only need the
# verified standard/version. Modules use the exact references below.
WSTG: Final = StandardReference(
    "WSTG", "4.2", "WSTG", "OWASP Web Security Testing Guide",
    "https://owasp.org/www-project-web-security-testing-guide/",
)
TOP10: Final = StandardReference(
    "OWASP Top 10", "2025", "Top10", "OWASP Top 10",
    "https://owasp.org/Top10/2025/",
)
ASVS: Final = StandardReference(
    "ASVS", "5.0.0", "ASVS", "OWASP Application Security Verification Standard",
    "https://owasp.org/www-project-application-security-verification-standard/",
)
API_TOP10: Final = StandardReference(
    "API Security Top 10", "2023", "API10", "OWASP API Security Top 10",
    "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
)


def _wstg(identifier: str, title: str, path: str) -> StandardReference:
    return StandardReference(
        "WSTG", "4.2", identifier, title,
        f"https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/{path}",
    )


def _top10(identifier: str, title: str, path: str) -> StandardReference:
    return StandardReference(
        "OWASP Top 10", "2025", identifier, title,
        f"https://owasp.org/Top10/2025/{path}/",
    )


def _asvs(identifier: str, title: str, chapter: str) -> StandardReference:
    return StandardReference(
        "ASVS", "5.0.0", identifier, title,
        f"https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/{chapter}",
    )


def _api(identifier: str, title: str, path: str) -> StandardReference:
    return StandardReference(
        "API Security Top 10", "2023", identifier, title,
        f"https://owasp.org/API-Security/editions/2023/en/{path}/",
    )


WSTG_CONF_07 = _wstg("WSTG-CONF-07", "Test HTTP Strict Transport Security", "02-Configuration_and_Deployment_Management/07-HTTP_Strict_Transport_Security.md")
WSTG_CONF_12 = _wstg("WSTG-CONF-12", "Test Content Security Policy", "02-Configuration_and_Deployment_Management/12-Content_Security_Policy.md")
WSTG_CONF_14 = _wstg("WSTG-CONF-14", "Test Other HTTP Security Header Misconfigurations", "02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations.md")
WSTG_SESS_02 = _wstg("WSTG-SESS-02", "Test Cookies Attributes", "06-Session_Management/02-Cookies_Attributes.md")
WSTG_CLNT_07 = _wstg("WSTG-CLNT-07", "Test Cross Origin Resource Sharing", "11-Client-side/07-Cross_Origin_Resource_Sharing.md")
WSTG_INFO_02 = _wstg("WSTG-INFO-02", "Fingerprint Web Server", "01-Information_Gathering/02-Fingerprint_Web_Server.md")
WSTG_APIT_01 = _wstg("WSTG-APIT-01", "API Reconnaissance", "12-API_Testing/01-API_Reconnaissance.md")

TOP10_A02 = _top10("A02:2025", "Security Misconfiguration", "A02_2025-Security_Misconfiguration")
TOP10_A03 = _top10("A03:2025", "Software Supply Chain Failures", "A03_2025-Software_Supply_Chain_Failures")
TOP10_A04 = _top10("A04:2025", "Cryptographic Failures", "A04_2025-Cryptographic_Failures")
TOP10_A07 = _top10("A07:2025", "Authentication Failures", "A07_2025-Authentication_Failures")
TOP10_A01 = _top10("A01:2025", "Broken Access Control", "A01_2025-Broken_Access_Control")
TOP10_A05 = _top10("A05:2025", "Injection", "A05_2025-Injection")

ASVS_V3_3_1 = _asvs("v5.0.0-3.3.1", "Secure cookie Secure attribute", "0x12-V3-Web-Frontend-Security.md")
ASVS_V3_3_2 = _asvs("v5.0.0-3.3.2", "Cookie SameSite attribute", "0x12-V3-Web-Frontend-Security.md")
ASVS_V3_3_4 = _asvs("v5.0.0-3.3.4", "Cookie HttpOnly attribute", "0x12-V3-Web-Frontend-Security.md")
ASVS_V3_4_2 = _asvs("v5.0.0-3.4.2", "CORS origin policy", "0x12-V3-Web-Frontend-Security.md")
ASVS_V3_4_3 = _asvs("v5.0.0-3.4.3", "Content Security Policy", "0x12-V3-Web-Frontend-Security.md")
ASVS_V3_4_4 = _asvs("v5.0.0-3.4.4", "X-Content-Type-Options", "0x12-V3-Web-Frontend-Security.md")
ASVS_V12_2_1 = _asvs("v5.0.0-12.2.1", "TLS for external-facing services", "0x21-V12-Secure-Communication.md")
ASVS_V12_2_2 = _asvs("v5.0.0-12.2.2", "Publicly trusted TLS certificates", "0x21-V12-Secure-Communication.md")
ASVS_V8_1_1 = _asvs("v5.0.0-8.1.1", "Authorization documentation", "0x17-V8-Authorization.md")
ASVS_V8_2_2 = _asvs("v5.0.0-8.2.2", "Data-specific authorization", "0x17-V8-Authorization.md")
ASVS_V6_3_3 = _asvs("v5.0.0-6.3.3", "Authentication required for application access", "0x15-V6-Authentication.md")
ASVS_V2_2_1 = _asvs("v5.0.0-2.2.1", "Input validation", "0x11-V2-Validation-and-Business-Logic.md")

API8 = _api("API8:2023", "Security Misconfiguration", "0xa8-security-misconfiguration")
API9 = _api("API9:2023", "Improper Inventory Management", "0xa9-improper-inventory-management")
API2 = _api("API2:2023", "Broken Authentication", "0xa2-broken-authentication")
API1 = _api("API1:2023", "Broken Object Level Authorization", "0xa1-broken-object-level-authorization")
API3 = _api("API3:2023", "Broken Object Property Level Authorization", "0xa3-broken-object-property-level-authorization")

SUPPORTED_REFERENCES: Final = frozenset({
    WSTG, TOP10, ASVS, API_TOP10, WSTG_CONF_07, WSTG_CONF_12, WSTG_CONF_14,
    WSTG_SESS_02, WSTG_CLNT_07, WSTG_INFO_02, WSTG_APIT_01, TOP10_A02,
    TOP10_A03, TOP10_A04, TOP10_A07, TOP10_A01, TOP10_A05, ASVS_V3_3_1, ASVS_V3_3_2, ASVS_V3_3_4,
    ASVS_V3_4_2, ASVS_V3_4_3, ASVS_V3_4_4, ASVS_V12_2_1, ASVS_V12_2_2,
    ASVS_V8_1_1, ASVS_V8_2_2, ASVS_V6_3_3, ASVS_V2_2_1, API8, API9, API2, API1, API3,
})


@dataclass(frozen=True, slots=True)
class AssessmentModuleDefinition:
    """Complete metadata and execution contract for one independent test."""

    name: str
    title: str
    description: str
    references: tuple[StandardReference, ...]
    test_version: str = "0.3.0"
    target_types: frozenset[str] = frozenset({"web"})
    capabilities: frozenset[str] = frozenset()
    permissions: frozenset[str] = frozenset({"authorized-target"})
    prerequisites: frozenset[str] = frozenset()
    impact: str = "passive"
    execution_mode: str = "passive"
    expected_evidence: tuple[str, ...] = ()
    result_rules: tuple[str, ...] = ()
    remediation: str = "Review the evidence and apply the documented control appropriate to the application."
    availability: str = "available"
    owasp_category: str | None = None
    owasp_id: str | None = None
    function_key: str | None = None
    # Controlled v0.4 modules additionally require an approved lab scope.
    scope: str | None = None

    @property
    def test_id(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True, init=False)
class AssessmentRegistry:
    """Validated immutable sequence of module definitions."""

    _modules: tuple[AssessmentModuleDefinition, ...]

    def __init__(self, modules: tuple[AssessmentModuleDefinition, ...]):
        if not modules:
            raise ValueError("assessment registry must contain a module")
        names = [module.name for module in modules]
        if len(names) != len(set(names)) or any(not name.strip() for name in names):
            raise ValueError("assessment module names must be unique and non-empty")
        for module in modules:
            if not module.references or any(reference not in SUPPORTED_REFERENCES for reference in module.references):
                raise ValueError(f"module {module.name!r} has an unsupported reference")
            if module.impact not in {"passive", "low-impact", "controlled"}:
                raise ValueError(f"module {module.name!r} has an invalid impact")
            if module.execution_mode not in {"passive", "low-impact-active", "controlled-active"}:
                raise ValueError(f"module {module.name!r} has an invalid execution mode")
        object.__setattr__(self, "_modules", tuple(modules))

    @property
    def modules(self) -> tuple[AssessmentModuleDefinition, ...]:
        return self._modules

    def __iter__(self):
        return iter(self._modules)

    def __len__(self) -> int:
        return len(self._modules)


AssessmentTestDefinition = AssessmentModuleDefinition
TestDefinition = AssessmentModuleDefinition


DEFAULT_REGISTRY: Final = AssessmentRegistry((
    AssessmentModuleDefinition(
        "security-headers", "Security headers", "Reuse the existing passive header checks.",
        (WSTG_CONF_07, WSTG_CONF_12, WSTG_CONF_14, TOP10_A02, ASVS_V3_4_3, ASVS_V3_4_4),
        expected_evidence=("response headers",), result_rules=("missing header is a confirmed configuration observation",),
        remediation="Return HSTS, CSP, and X-Content-Type-Options appropriate for the application.",
        owasp_category="Security Misconfiguration", owasp_id="A02:2025", function_key="security-headers",
    ),
    AssessmentModuleDefinition(
        "cookies", "Cookie attributes", "Observe cookie attribute flags without retaining values.",
        (WSTG_SESS_02, TOP10_A02, ASVS_V3_3_1, ASVS_V3_3_2, ASVS_V3_3_4),
        expected_evidence=("Set-Cookie attribute names",), result_rules=("missing flags are potential findings until cookie purpose is confirmed",),
        remediation="Set Secure, HttpOnly, and SameSite attributes where appropriate.",
        owasp_category="Security Misconfiguration", owasp_id="A02:2025", function_key="cookies",
    ),
    AssessmentModuleDefinition(
        "cors", "CORS response policy", "Observe safe CORS response headers without issuing an Origin probe.",
        (WSTG_CLNT_07, TOP10_A02, ASVS_V3_4_2, API8),
        expected_evidence=("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"), result_rules=("wildcard plus credentials is a potential misconfiguration; sensitive-data exposure is not proven",),
        remediation="Use explicit trusted origins and review credentialed cross-origin access.",
        owasp_category="Security Misconfiguration", owasp_id="A02:2025", function_key="cors",
    ),
    AssessmentModuleDefinition(
        "redirects", "Redirect and configuration observations", "Record the bounded redirect chain and safe response metadata.",
        (WSTG_CONF_14, TOP10_A02, ASVS_V12_2_1),
        expected_evidence=("validated redirect history",), result_rules=("redirect evidence is informational unless a policy violation is established",),
        owasp_category="Security Misconfiguration", owasp_id="A02:2025", function_key="redirects",
    ),
    AssessmentModuleDefinition(
        "information-exposure", "Information exposure indicators", "Inspect only observed metadata and Stage 1 asset classifications for disclosure indicators.",
        (WSTG_INFO_02, WSTG_CONF_14, TOP10_A02),
        expected_evidence=("safe response metadata", "Stage 1 resource classifications"),
        result_rules=("an implementation header is a potential disclosure, not proof of exploitability",),
        remediation="Remove unnecessary implementation-identifying headers and review public metadata decisions.",
        owasp_category="Security Misconfiguration", owasp_id="A02:2025", function_key="information-exposure",
    ),
    AssessmentModuleDefinition(
        "api-inventory", "API inventory observations", "Identify API routes or API documentation only from the Stage 1 asset map.",
        (WSTG_APIT_01, API9, TOP10_A02),
        expected_evidence=("already discovered same-origin resources",),
        result_rules=("route discovery does not test authentication or authorization",),
        remediation="Review the discovered API inventory and remove undocumented or stale public routes where appropriate.",
        owasp_category="Improper Inventory Management", owasp_id="API9:2023", function_key="api-inventory",
    ),
    AssessmentModuleDefinition(
        "tls-metadata", "TLS metadata", "Certificate and negotiated TLS metadata are not available to the scan core.",
        (TOP10_A04, ASVS_V12_2_1, ASVS_V12_2_2), availability="unavailable", capabilities=frozenset({"tls-metadata"}),
        result_rules=("never infer certificate validity from an HTTPS URL",), remediation="Provide a configured, safe TLS metadata capability before enabling this test.",
        owasp_category="Cryptographic Failures", owasp_id="A04:2025", function_key="unavailable",
    ),
    AssessmentModuleDefinition(
        "authenticated-authorization", "Authenticated authorization", "No authenticated session or authorization test context is supplied.",
        (WSTG_APIT_01, TOP10_A07, ASVS_V8_1_1, API2), prerequisites=frozenset({"authenticated-session"}), availability="unavailable",
        impact="controlled", execution_mode="controlled-active", result_rules=("never claim authorization correctness from 401/403 alone",),
        remediation="Supply owner-provided test accounts and an explicit controlled authorization scope.",
        owasp_category="Broken Access Control", owasp_id="A01:2025", function_key="unavailable",
    ),
    AssessmentModuleDefinition(
        "external-vulnerability-intelligence", "External vulnerability intelligence", "No external vulnerability intelligence source is configured.",
        (WSTG_INFO_02, TOP10_A03, API9), prerequisites=frozenset({"vulnerability-intelligence-source"}), availability="unavailable",
        capabilities=frozenset({"external-vulnerability-intelligence"}), result_rules=("a potentially affected version is not a verified exploitable vulnerability",),
        remediation="Configure a documented, privacy-reviewed vulnerability source before enabling this test.",
        owasp_category="Software Supply Chain Failures", owasp_id="A03:2025", function_key="unavailable",
    ),
))


# v0.4 is intentionally a separate opt-in registry.  This keeps existing
# default scans stable while making the controlled application-security suite
# available to callers that explicitly provide an approved lab and its scope.
CONTROLLED_APPLICATION_SECURITY_REGISTRY: Final = AssessmentRegistry(
    (
        AssessmentModuleDefinition(
            "authentication-protected-route",
            "Protected-route authentication expectation",
            "Verify the synthetic application marks the declared route as protected without handling credentials.",
            (TOP10_A07, ASVS_V6_3_3, API2),
            test_version="0.4.0",
            prerequisites=frozenset({"protected-route-expectation"}),
            capabilities=frozenset({LAB_AUTHENTICATION}),
            scope=LAB_SCOPE,
            impact="controlled", execution_mode="controlled-active",
            expected_evidence=("protected-route metadata",),
            result_rules=("route protection is evaluated from the declared expectation and metadata, not a status code alone",),
            remediation="Require authentication for the protected route and verify the route policy in the application.",
            owasp_category="Authentication Failures", owasp_id="A07:2025",
            function_key="authentication-protected-route",
        ),
        AssessmentModuleDefinition(
            "session-cookie-metadata",
            "Session-cookie metadata",
            "Check only synthetic session-cookie flags after an authenticated session prerequisite is declared.",
            (WSTG_SESS_02, TOP10_A07, ASVS_V3_3_1, ASVS_V3_3_2, ASVS_V3_3_4),
            test_version="0.4.0",
            prerequisites=frozenset({"authenticated-session", "session-cookie-metadata"}),
            capabilities=frozenset({LAB_SESSION_COOKIE_METADATA}),
            scope=LAB_SCOPE,
            impact="controlled", execution_mode="controlled-active",
            expected_evidence=("session-cookie flag metadata",),
            result_rules=("missing session-cookie metadata is skipped; flags are assessed without a cookie name or value",),
            remediation="Set Secure, HttpOnly, and an appropriate SameSite policy on session cookies.",
            owasp_category="Authentication Failures", owasp_id="A07:2025",
            function_key="session-cookie-metadata",
        ),
        AssessmentModuleDefinition(
            "authorization-object-access",
            "Synthetic object authorization",
            "Compare explicit expected access for two synthetic users with the lab policy decision and ownership metadata.",
            (TOP10_A01, ASVS_V8_2_2, API1),
            test_version="0.4.0",
            prerequisites=frozenset({"authorization-expectations"}),
            capabilities=frozenset({LAB_AUTHORIZATION}),
            scope=LAB_SCOPE,
            impact="controlled", execution_mode="controlled-active",
            expected_evidence=("synthetic access decision metadata",),
            result_rules=("a cross-user decision is a finding only when actual and expected access differ; HTTP status codes are not used",),
            remediation="Enforce object-level authorization for every request and deny a user access to another user's resource.",
            owasp_category="Broken Access Control", owasp_id="A01:2025",
            function_key="authorization-object-access",
        ),
        AssessmentModuleDefinition(
            "input-validation-safety",
            "Bounded malformed-input handling",
            "Evaluate one bounded malformed-marker/content-type probe from safe result metadata and separate validation from injection evidence.",
            (TOP10_A05, ASVS_V2_2_1, API8),
            test_version="0.4.0",
            prerequisites=frozenset({"malformed-input-probe"}),
            capabilities=frozenset({LAB_INPUT_VALIDATION}),
            scope=LAB_SCOPE,
            impact="controlled", execution_mode="controlled-active",
            expected_evidence=("malformed input outcome metadata", "safe error-disclosure metadata"),
            result_rules=("validation failure is distinct from injection; injection is never inferred from a malformed marker",),
            remediation="Reject malformed input with a safe, generic error and keep parser or stack details out of responses.",
            owasp_category="Injection", owasp_id="A05:2025",
            function_key="input-validation-safety",
        ),
    )
)

# Public aliases make the opt-in nature explicit for embedding applications.
V04_REGISTRY: Final = CONTROLLED_APPLICATION_SECURITY_REGISTRY
APPLICATION_SECURITY_REGISTRY: Final = CONTROLLED_APPLICATION_SECURITY_REGISTRY
