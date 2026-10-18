"""Profile selection and policy-bound assessment orchestration.

The orchestration layer deliberately does not implement a new scanner.  It
selects one of the existing immutable registries, validates the admission
contract, and passes the existing bounded context through to ``run_assessment``.
This keeps the ordinary passive flow source-compatible while making controlled
application-security work an explicit opt-in.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from uuid import UUID

from app.assessment.context import AssessmentContext
from app.assessment.lab import (
    LAB_AUTHENTICATION,
    LAB_AUTHORIZATION,
    LAB_INPUT_VALIDATION,
    LAB_SESSION_COOKIE_METADATA,
    InProcessAssessmentLab,
)
from app.assessment.registry import (
    CONTROLLED_APPLICATION_SECURITY_REGISTRY,
    DEFAULT_REGISTRY,
    AssessmentRegistry,
)
from app.assessment.runner import run_assessment
from app.engagement.policy import EngagementPolicyError, EngagementScopePolicy
from app.scanning.models import AssessmentResult


class AssessmentProfileError(ValueError):
    """Raised when a requested profile cannot be admitted or resolved."""


LEGACY_PASSIVE_PROFILE: Final = "legacy-passive"
CONTROLLED_LAB_PROFILE: Final = "controlled-lab"
LEGACY_PASSIVE_PROFILE_ID: Final = "sentinel-v0.3-passive"
LEGACY_PASSIVE_PROFILE_VERSION: Final = "0.3.0"
CONTROLLED_LAB_PROFILE_ID: Final = "sentinel-v0.4-controlled-application-security"
CONTROLLED_LAB_PROFILE_VERSION: Final = "0.4.0"


@dataclass(frozen=True, slots=True)
class AssessmentProfile:
    """Stable metadata and execution contract for one named profile."""

    name: str
    profile_id: str
    version: str
    registry: AssessmentRegistry
    active_testing: bool = False
    required_capabilities: frozenset[str] = frozenset()

    @property
    def id(self) -> str:
        """Stable serialized profile identifier."""

        return self.profile_id

    @property
    def profile_version(self) -> str:
        return self.version

    @property
    def enabled_modules(self) -> tuple[str, ...]:
        return tuple(module.name for module in self.registry)


LEGACY_PASSIVE: Final = AssessmentProfile(
    name=LEGACY_PASSIVE_PROFILE,
    profile_id=LEGACY_PASSIVE_PROFILE_ID,
    version=LEGACY_PASSIVE_PROFILE_VERSION,
    registry=DEFAULT_REGISTRY,
)

CONTROLLED_LAB: Final = AssessmentProfile(
    name=CONTROLLED_LAB_PROFILE,
    profile_id=CONTROLLED_LAB_PROFILE_ID,
    version=CONTROLLED_LAB_PROFILE_VERSION,
    registry=CONTROLLED_APPLICATION_SECURITY_REGISTRY,
    active_testing=True,
    required_capabilities=frozenset({
        LAB_AUTHENTICATION,
        LAB_SESSION_COOKIE_METADATA,
        LAB_AUTHORIZATION,
        LAB_INPUT_VALIDATION,
    }),
)

PROFILES: Final = {
    LEGACY_PASSIVE_PROFILE: LEGACY_PASSIVE,
    CONTROLLED_LAB_PROFILE: CONTROLLED_LAB,
    # Stable IDs and descriptive aliases are accepted at the API seam so a
    # caller can persist either a human-friendly key or returned metadata.
    "passive": LEGACY_PASSIVE,
    "legacy": LEGACY_PASSIVE,
    LEGACY_PASSIVE.profile_id: LEGACY_PASSIVE,
    "controlled": CONTROLLED_LAB,
    "controlled-application-security": CONTROLLED_LAB,
    "controlled_lab": CONTROLLED_LAB,
    "controlled-application-security-lab": CONTROLLED_LAB,
    "application-security-lab": CONTROLLED_LAB,
    CONTROLLED_LAB.profile_id: CONTROLLED_LAB,
}


def resolve_profile(name: str | None) -> AssessmentProfile:
    """Resolve a request value, defaulting to the legacy passive profile."""

    if name is None:
        return LEGACY_PASSIVE
    try:
        return PROFILES[name.strip().casefold()]
    except (AttributeError, KeyError) as exc:
        raise AssessmentProfileError(f"unknown assessment profile: {name!r}") from exc


def prerequisites_for_lab(
    target_url: str, lab: InProcessAssessmentLab | None
) -> frozenset[str]:
    """Translate supplied synthetic metadata into module prerequisites.

    The lab remains metadata-only.  This helper merely declares which bounded
    fixtures are present; it never creates a client, sends a request, or reads
    credentials.
    """

    if lab is None:
        return frozenset()
    prerequisites: set[str] = set()
    if lab.protected_route_metadata(target_url) is not None:
        prerequisites.add("protected-route-expectation")
    if lab.session_cookie_metadata(target_url) is not None:
        prerequisites.update({"authenticated-session", "session-cookie-metadata"})
    if lab.authorization_metadata(target_url):
        prerequisites.update({"authenticated-session", "authorization-expectations"})
    if lab.input_validation_metadata(target_url):
        prerequisites.add("malformed-input-probe")
    return frozenset(prerequisites)


class AssessmentOrchestrator:
    """Select and execute a profile using one shared assessment context."""

    profiles = PROFILES

    def resolve(self, name: str | None) -> AssessmentProfile:
        return resolve_profile(name)

    def validate_admission(
        self,
        profile: AssessmentProfile | str | None,
        *,
        engagement_id: UUID | None,
        active_testing_authorized: bool | None,
        engagement_policy: EngagementScopePolicy | None,
    ) -> None:
        if not isinstance(profile, AssessmentProfile):
            profile = self.resolve(profile)
        if profile.active_testing and engagement_id is None:
            raise EngagementPolicyError(
                "controlled assessment profile requires an engagement_id"
            )
        if profile.active_testing and active_testing_authorized is not True:
            raise EngagementPolicyError(
                "controlled assessment profile requires explicit active_testing_authorized=true"
            )
        if engagement_policy is None:
            if not profile.active_testing:
                return
            raise EngagementPolicyError(
                "controlled assessment profile requires an active engagement policy"
            )
        try:
            try:
                engagement_policy.validate_profile(profile.profile_id)
            except EngagementPolicyError:
                # Engagements created with the request-facing profile key are
                # equivalent to those using the stable returned profile ID.
                engagement_policy.validate_profile(profile.name)
            for capability in profile.required_capabilities:
                engagement_policy.validate_capability(capability)
        except EngagementPolicyError:
            raise
        except Exception as exc:  # defensive boundary for embedding policies
            raise EngagementPolicyError("assessment profile policy validation failed") from exc

    async def run(
        self,
        context: AssessmentContext,
        profile: AssessmentProfile | str | None = None,
    ) -> AssessmentResult:
        selected = self.resolve(profile) if not isinstance(profile, AssessmentProfile) else profile
        return await run_assessment(
            context,
            selected.registry,
            profile_id=selected.profile_id,
            profile_version=selected.version,
        )


# Friendly aliases for embedding applications.
AssessmentProfileOrchestrator = AssessmentOrchestrator


__all__ = [
    "AssessmentOrchestrator",
    "AssessmentProfile",
    "AssessmentProfileError",
    "AssessmentProfileOrchestrator",
    "CONTROLLED_LAB",
    "CONTROLLED_LAB_PROFILE",
    "CONTROLLED_LAB_PROFILE_ID",
    "CONTROLLED_LAB_PROFILE_VERSION",
    "LEGACY_PASSIVE",
    "LEGACY_PASSIVE_PROFILE",
    "LEGACY_PASSIVE_PROFILE_ID",
    "LEGACY_PASSIVE_PROFILE_VERSION",
    "PROFILES",
    "prerequisites_for_lab",
    "resolve_profile",
]
