"""Conservative projection of canonical evidence into concise Phase 6F verdicts."""

from __future__ import annotations

from typing import Any

from omiv.assurance.models import VerdictStatus

_POSITIVE_EXACT = {
    "PASS",
    "VERIFIED",
    "VALID",
    "APPROVED",
    "EXACT_MATCH_FOR_EXPECTATION_SCOPE",
    "CONFORMS_FOR_DECLARED_SCOPE",
    "PARITY_ESTABLISHED_FOR_DECLARED_SCOPE",
    "SATISFACTORY_FOR_DECLARED_SCOPE",
    "COMPLETE_FOR_DECLARED_LOCAL_SCOPE",
    "MATCHES_COMPLETE_EXPECTATION",
    "VERIFIED_WITH_LIMITATIONS",
}


def project_semantic_status(value: dict[str, Any]) -> tuple[VerdictStatus, str]:
    """Project only explicit status fields; never infer truth from schema validity."""
    selected_name = ""
    selected = ""
    for name in ("overall_status", "status", "outcome", "verdict", "decision_outcome"):
        candidate = value.get(name)
        if isinstance(candidate, str):
            selected_name, selected = name, candidate.upper()
            break
    if not selected:
        return VerdictStatus.UNKNOWN, "No supported semantic verdict field was present."
    if selected in _POSITIVE_EXACT:
        return VerdictStatus.PASS, f"{selected_name}={selected}"
    if any(
        token in selected
        for token in ("MISMATCH", "FAILED", "FAILURE", "INVALID", "REJECTED", "DENIED")
    ):
        return VerdictStatus.FAIL, f"{selected_name}={selected}"
    if any(token in selected for token in ("PARTIAL", "WARNING", "WARN", "LIMITATION")):
        return VerdictStatus.WARN, f"{selected_name}={selected}"
    if any(
        token in selected
        for token in (
            "UNKNOWN",
            "UNAVAILABLE",
            "NOT_EVALUATED",
            "NOT_OBSERVED",
            "NOT_VERIFIED",
            "INSUFFICIENT",
            "INCOMPLETE",
            "INDETERMINATE",
        )
    ):
        return VerdictStatus.UNKNOWN, f"{selected_name}={selected}"
    return VerdictStatus.UNKNOWN, f"Unsupported semantic value {selected_name}={selected}."
