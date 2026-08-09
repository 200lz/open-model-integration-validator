"""Deterministic JSON and Markdown reporting for Phase 6C."""

from __future__ import annotations

import json

from pydantic import BaseModel

from omiv.quantization.models import QuantizationFidelityReport


def pretty_json(value: BaseModel) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_markdown(report: QuantizationFidelityReport) -> str:
    return "\n".join(
        [
            "# OMIV Quantization Representation and Numerical Fidelity Report",
            "",
            f"- Overall status: **{report.overall_status.value}**",
            f"- Structural status: **{report.structural_status.value}**",
            f"- Numerical status: **{report.numerical_status.value}**",
            f"- Evaluated scope: **{report.expectation_scope.value}**",
            "- Findings included: "
            f"**{report.included_finding_count}/{report.total_finding_count}**",
            f"- Report truncation: **{report.truncation_status}**",
            "- Model correctness: **NOT_ESTABLISHED**",
            "- Behavioral parity: **NOT_EVALUATED**",
            "- Security and safety: **NOT_EVALUATED**",
            "- Runtime identity: **NOT_OBSERVED**",
            "",
            "Numerical reconstruction evidence applies only to the exact declared identity and "
            "evaluated coverage. Sampling, metadata agreement, or a valid signature does not "
            "establish complete-model fidelity, behavioral equivalence, authority, or safety.",
            "",
        ]
    )
