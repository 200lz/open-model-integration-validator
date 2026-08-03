"""Deterministic Phase 6B JSON and Markdown reporting."""

from __future__ import annotations

import json

from pydantic import BaseModel

from omiv.reconciliation.models import RemoteLocalReconciliationReport


def pretty_json(value: BaseModel) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )


def render_markdown(report: RemoteLocalReconciliationReport) -> str:
    evidence = report.evidence
    comparison = report.comparison
    return "\n".join(
        [
            "# OMIV Remote-to-Local Reconciliation Report",
            "",
            f"- Subject: `{evidence.subject.subject_id}`",
            f"- Resolved comparison: **{comparison.status.value}**",
            f"- Evidence outcome: **{evidence.outcome.value}**",
            f"- Policy satisfied: **{str(evidence.policy_satisfied).upper()}**",
            f"- Topology: **{report.topology_status.value}**",
            f"- Shard completeness: **{report.completeness_status.value}**",
            f"- Publisher authority: **{report.publisher_authority.value}**",
            f"- Network use: **{report.network_use.value}**",
            f"- Payload download: **{report.payload_download.value}**",
            "- Model authenticity: **NOT_ESTABLISHED**",
            "- Model semantic correctness: **NOT_EVALUATED**",
            "- Model safety: **NOT_VERIFIED**",
            "- Runtime identity: **NOT_OBSERVED**",
            "",
            "Exact reconciliation is limited to the declared scope and comparable payload-digest "
            "semantics. It does not prove authenticity, tensor completeness, safety, loadability, "
            "quantization fidelity, tokenizer parity, or runtime identity.",
            "",
        ]
    )
