"""Deterministic structural comparison of verified model artifacts."""

from omiv.comparison.engine import build_structural_comparison
from omiv.comparison.reporting import (
    verify_comparison_inventory,
    verify_comparison_report,
)

__all__ = [
    "build_structural_comparison",
    "verify_comparison_inventory",
    "verify_comparison_report",
]
