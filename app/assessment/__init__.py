"""Policy-bound assessment modules for SENTINEL v0.3 and v0.4 lab scans."""

from app.assessment.context import AssessmentContext, AssessmentExecutionContext
from app.assessment.registry import (
    APPLICATION_SECURITY_REGISTRY,
    CONTROLLED_APPLICATION_SECURITY_REGISTRY,
    DEFAULT_REGISTRY,
    AssessmentModuleDefinition,
    AssessmentRegistry,
    AssessmentTestDefinition,
    V04_REGISTRY,
)
from app.assessment.lab import (
    ApplicationSecurityLab,
    ControlledAssessmentLab,
    InProcessAssessmentLab,
    LabScope,
    SyntheticResource,
    SyntheticUser,
)
from app.assessment.runner import run_assessment

__all__ = [
    "AssessmentModuleDefinition",
    "AssessmentTestDefinition",
    "AssessmentRegistry",
    "AssessmentContext",
    "AssessmentExecutionContext",
    "DEFAULT_REGISTRY",
    "CONTROLLED_APPLICATION_SECURITY_REGISTRY",
    "APPLICATION_SECURITY_REGISTRY",
    "V04_REGISTRY",
    "InProcessAssessmentLab",
    "ControlledAssessmentLab",
    "ApplicationSecurityLab",
    "LabScope",
    "SyntheticUser",
    "SyntheticResource",
    "run_assessment",
]
