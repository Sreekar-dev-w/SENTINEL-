"""Compatibility names for the v0.3 assessment executor."""

from app.assessment.runner import run_assessment

AssessmentRunner = run_assessment

__all__ = ["AssessmentRunner", "run_assessment"]
