"""Deterministic Phase 6A serialization and reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.payload_integrity.building import build_report
from omiv.payload_integrity.models import (
    PayloadIntegrityEvidence,
    PayloadIntegrityReport,
    PayloadManifestComparison,
)

T = TypeVar("T", bound=BaseModel)


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


def load_payload(path: Path, model: type[T]) -> T:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("payload-integrity input must be a regular non-symlink file")
    raw, _ = load_bounded_json(path, max_bytes=64 * 1024 * 1024)
    try:
        return model.model_validate(raw)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid payload-integrity record: {exc}") from exc


def verify_report(
    report: PayloadIntegrityReport,
    evidence: PayloadIntegrityEvidence,
    comparison: PayloadManifestComparison | None,
) -> PayloadIntegrityReport:
    if report != build_report(evidence, comparison):
        raise OmivInputError("payload report does not match deterministic reconstruction")
    return report


def render_markdown(report: PayloadIntegrityReport) -> str:
    evidence = report.evidence
    comparison = report.comparison
    comparison_status = comparison.status.value if comparison else "NOT_PERFORMED"
    expectation_scope = evidence.expectation_scope.value if evidence.expectation_scope else "NONE"
    files_hashed = f"{evidence.coverage.hashed_files}/{evidence.coverage.discovered_regular_files}"
    bytes_hashed = f"{evidence.coverage.hashed_bytes}/{evidence.coverage.discovered_bytes}"
    return "\n".join(
        [
            "# OMIV Local Payload Integrity Report",
            "",
            f"- Subject: `{evidence.subject_id}`",
            f"- Logical root: `{evidence.logical_root}`",
            f"- Root mode: **{evidence.root_mode.value}**",
            f"- Artifact-set payload digest: `{evidence.artifact_set_payload_digest}`",
            f"- Evidence outcome: **{evidence.outcome.value}**",
            f"- Comparison status: **{comparison_status}**",
            f"- Expectation scope: **{expectation_scope}**",
            f"- Publisher authority: **{evidence.publisher_authority_status}**",
            f"- Files hashed: **{files_hashed}**",
            f"- Bytes hashed: **{bytes_hashed}**",
            "- Model semantic correctness: **NOT_EVALUATED**",
            "- Remote repository completeness: **NOT_EVALUATED**",
            "- Runtime safety: **NOT_VERIFIED**",
            "- Continuous verification: **NOT_ESTABLISHED**",
            "",
            "Payload digest match does not establish authenticity, semantic correctness, safety, "
            "approval, deployment, or runtime identity.",
            "",
        ]
    )
