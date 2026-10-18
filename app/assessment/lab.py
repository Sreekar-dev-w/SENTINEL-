"""Deterministic, metadata-only application-security assessment lab.

The lab is deliberately in-process.  It is a small policy boundary for
controlled assessment modules, rather than an HTTP client or an application
fixture that returns payloads.  Every value exposed to a module is synthetic
metadata; credentials, request data, response bodies, and cookie values are
not representable by these models.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit


LAB_SCOPE = "application-security-lab"
LAB_AUTHENTICATION = "lab.authentication"
LAB_SESSION_COOKIE_METADATA = "lab.session-cookie-metadata"
LAB_AUTHORIZATION = "lab.authorization"
LAB_INPUT_VALIDATION = "lab.input-validation"
LAB_CAPABILITIES = frozenset(
    {
        LAB_AUTHENTICATION,
        LAB_SESSION_COOKIE_METADATA,
        LAB_AUTHORIZATION,
        LAB_INPUT_VALIDATION,
    }
)


class LabConfigurationError(ValueError):
    """Raised when a lab is not explicitly approved and bounded."""


class LabOperation(StrEnum):
    AUTHENTICATION = "authentication"
    SESSION_COOKIE_METADATA = "session-cookie-metadata"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input-validation"


_CAPABILITY_OPERATIONS = {
    LAB_AUTHENTICATION: LabOperation.AUTHENTICATION,
    LAB_SESSION_COOKIE_METADATA: LabOperation.SESSION_COOKIE_METADATA,
    LAB_AUTHORIZATION: LabOperation.AUTHORIZATION,
    LAB_INPUT_VALIDATION: LabOperation.INPUT_VALIDATION,
}


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LabConfigurationError("lab scope requires an HTTP(S) target origin")
    host = parsed.hostname.lower()
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    default = 443 if parsed.scheme == "https" else 80
    authority = host if port == default else f"{host}:{port}"
    return f"{parsed.scheme}://{authority}"


@dataclass(frozen=True, slots=True)
class LabScope:
    """An explicit owner-approved origin and operation allowlist."""

    target_url: str
    approved: bool = False
    operations: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_url", _origin(self.target_url))
        if not self.approved:
            raise LabConfigurationError("lab scope requires explicit approval")
        allowed = {item.value for item in LabOperation}
        if not set(self.operations) <= allowed:
            raise LabConfigurationError("lab scope contains an unsupported operation")
        if not self.operations:
            raise LabConfigurationError("lab scope must declare at least one operation")

    def supports(self, target_url: str, operation: str) -> bool:
        try:
            return _origin(target_url) == self.target_url and operation in self.operations
        except (TypeError, ValueError, LabConfigurationError):
            return False


@dataclass(frozen=True, slots=True)
class SyntheticUser:
    """A synthetic principal; no password, token, or other credential exists."""

    user_id: str
    role: str

    def __post_init__(self) -> None:
        if not self.user_id or not self.role:
            raise LabConfigurationError("synthetic users require an id and role")


@dataclass(frozen=True, slots=True)
class SyntheticResource:
    resource_id: str
    owner_user_id: str
    allowed_roles: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.resource_id or not self.owner_user_id:
            raise LabConfigurationError("synthetic resources require an id and owner")


@dataclass(frozen=True, slots=True)
class ProtectedRouteMetadata:
    route_id: str
    protected: bool
    anonymous_access: bool
    authenticated_access: bool


@dataclass(frozen=True, slots=True)
class SessionCookieMetadata:
    """Cookie flags only; the cookie name and value are intentionally absent."""

    present: bool
    secure: bool | None = None
    httponly: bool | None = None
    samesite: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationMetadata:
    requester_id: str
    resource_id: str
    action: str
    expected_allowed: bool
    actual_allowed: bool
    ownership_matches: bool
    policy_rule: str


@dataclass(frozen=True, slots=True)
class InputValidationMetadata:
    route_id: str
    malformed_input_tested: bool
    content_type: str
    validation_failed: bool
    safe_error_handling: bool
    error_disclosed: bool
    injection_observed: bool


class InProcessAssessmentLab:
    """A bounded synthetic application model used by controlled modules.

    ``authorization_actual`` and ``input_validation`` are explicit fixture
    outcomes.  They make secure and intentionally flawed controls deterministic
    without sending requests or exposing an application response.
    """

    def __init__(
        self,
        *,
        scope: LabScope,
        capabilities: frozenset[str],
        users: tuple[SyntheticUser, ...] = (),
        resources: tuple[SyntheticResource, ...] = (),
        protected_route: ProtectedRouteMetadata | None = None,
        session_cookie: SessionCookieMetadata | None = None,
        authorization_cases: tuple[AuthorizationMetadata, ...] = (),
        input_validation: tuple[InputValidationMetadata, ...] = (),
    ) -> None:
        if not isinstance(scope, LabScope):
            raise LabConfigurationError("lab scope must be an approved LabScope")
        if not capabilities:
            raise LabConfigurationError("lab capabilities must be explicitly declared")
        if not set(capabilities) <= LAB_CAPABILITIES:
            raise LabConfigurationError("lab contains an unsupported capability")
        user_ids = {user.user_id for user in users}
        if len(user_ids) != len(users):
            raise LabConfigurationError("synthetic user ids must be unique")
        resource_ids = {resource.resource_id for resource in resources}
        if len(resource_ids) != len(resources):
            raise LabConfigurationError("synthetic resource ids must be unique")
        if not {resource.owner_user_id for resource in resources} <= user_ids:
            raise LabConfigurationError("resource owners must be synthetic users")
        if len(authorization_cases) > 0 and len(users) != 2:
            raise LabConfigurationError("authorization lab requires exactly two synthetic users")
        if not {case.requester_id for case in authorization_cases} <= user_ids:
            raise LabConfigurationError("authorization requesters must be synthetic users")
        if not {case.resource_id for case in authorization_cases} <= resource_ids:
            raise LabConfigurationError("authorization resources must be synthetic resources")
        self._scope = scope
        self._capabilities = frozenset(capabilities)
        self._users = tuple(users)
        self._resources = tuple(resources)
        self._protected_route = protected_route
        self._session_cookie = session_cookie
        self._authorization_cases = tuple(authorization_cases)
        self._input_validation = tuple(input_validation)

    @property
    def scope(self) -> LabScope:
        return self._scope

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    def supports(self, target_url: str, operation: LabOperation | str) -> bool:
        operation_name = operation.value if isinstance(operation, LabOperation) else operation
        return self._scope.supports(target_url, operation_name)

    def supports_capability(self, target_url: str, capability: str) -> bool:
        operation = _CAPABILITY_OPERATIONS.get(capability)
        return operation is not None and self.supports(target_url, operation)

    def protected_route_metadata(self, target_url: str) -> ProtectedRouteMetadata | None:
        if not self.supports(target_url, LabOperation.AUTHENTICATION):
            return None
        return self._protected_route

    def session_cookie_metadata(self, target_url: str) -> SessionCookieMetadata | None:
        if not self.supports(target_url, LabOperation.SESSION_COOKIE_METADATA):
            return None
        return self._session_cookie

    def authorization_metadata(self, target_url: str) -> tuple[AuthorizationMetadata, ...]:
        if not self.supports(target_url, LabOperation.AUTHORIZATION):
            return ()
        return self._authorization_cases

    def input_validation_metadata(self, target_url: str) -> tuple[InputValidationMetadata, ...]:
        if not self.supports(target_url, LabOperation.INPUT_VALIDATION):
            return ()
        return self._input_validation


# Friendly names for embedders and deterministic tests.
ControlledAssessmentLab = InProcessAssessmentLab
ApplicationSecurityLab = InProcessAssessmentLab


__all__ = [
    "ApplicationSecurityLab",
    "AuthorizationMetadata",
    "ControlledAssessmentLab",
    "InputValidationMetadata",
    "InProcessAssessmentLab",
    "LAB_AUTHENTICATION",
    "LAB_AUTHORIZATION",
    "LAB_CAPABILITIES",
    "LAB_INPUT_VALIDATION",
    "LAB_SCOPE",
    "LAB_SESSION_COOKIE_METADATA",
    "LabConfigurationError",
    "LabOperation",
    "LabScope",
    "ProtectedRouteMetadata",
    "SessionCookieMetadata",
    "SyntheticResource",
    "SyntheticUser",
]
