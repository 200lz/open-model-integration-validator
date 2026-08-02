"""Generic deterministic Phase 5G deployment/runtime snapshot verification."""

from omiv.runtime.continuity import evaluate_continuity, verify_continuity_evaluation
from omiv.runtime.models import ContinuityEvaluation, ContinuityPolicy, ContinuityVerdict
from omiv.runtime.policy import build_continuity_policy

__all__ = [
    "ContinuityEvaluation",
    "ContinuityPolicy",
    "ContinuityVerdict",
    "build_continuity_policy",
    "evaluate_continuity",
    "verify_continuity_evaluation",
]
