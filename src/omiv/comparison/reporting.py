"""Serialization, rendering, and fail-closed verification for comparisons."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256, load_json_value
from omiv.comparison.engine import build_structural_comparison
from omiv.comparison.models import (
    COMPARISON_REPORT_SCHEMA,
    ComparisonProfileOutcome,
    StructuralComparisonInventory,
    StructuralComparisonReport,
    StructuralComparisonReportEnvelope,
)
from omiv.comparison.policy import (
    comparison_profile_policy,
    evaluate_comparison_profiles,
    structural_comparison_policy,
)
from omiv.errors import OmivInputError
from omiv.safe_write import atomic_write_text

MAX_COMPARISON_BYTES = 64 * 1024 * 1024


def pretty_json(value: Any) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _load(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_COMPARISON_BYTES:
            raise OmivInputError("comparison artifact exceeds the size limit")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot load comparison artifact: {exc}") from exc


def _internal_verify(inventory: StructuralComparisonInventory) -> None:
    data = inventory.model_dump(mode="json")
    stored = data.pop("comparison_digest")
    if stored != canonical_sha256(data):
        raise OmivInputError("comparison inventory digest mismatch")
    if inventory.policy != structural_comparison_policy():
        raise OmivInputError("comparison policy is not canonical")
    profiles = comparison_profile_policy()
    if inventory.profile_policy != profiles:
        raise OmivInputError("comparison profile policy is not canonical")
    checked = {
        "cross_quantization_structural_comparison"
        if inventory.cross_quantization_structural_comparison.value == "checked"
        else ""
    }
    expected_profiles = evaluate_comparison_profiles(inventory.controls, checked, profiles)
    if expected_profiles != inventory.profile_results:
        raise OmivInputError("comparison profile reconstruction mismatch")
    index = [item.model_dump(mode="json") for item in inventory.artifact_index]
    if inventory.artifact_index_digest != canonical_sha256(index):
        raise OmivInputError("comparison artifact-index digest mismatch")


def load_comparison_inventory(path: Path) -> StructuralComparisonInventory:
    try:
        inventory = StructuralComparisonInventory.model_validate(_load(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid comparison inventory: {exc}") from exc
    _internal_verify(inventory)
    return inventory


def _entry_path(inventory: StructuralComparisonInventory, root: Path, role: str) -> Path:
    entries = [item for item in inventory.artifact_index if item.role == role]
    if len(entries) != 1:
        raise OmivInputError(f"comparison artifact index lacks unique role {role!r}")
    path = root / entries[0].relative_path
    if not path.is_file():
        raise OmivInputError(f"comparison dependency is missing: {entries[0].relative_path}")
    if path.stat().st_size != entries[0].size_bytes:
        raise OmivInputError(f"comparison dependency size mismatch: {entries[0].relative_path}")
    return path


def rebuild_comparison_inventory(
    inventory: StructuralComparisonInventory, root: Path
) -> StructuralComparisonInventory:
    root = root.resolve()
    return build_structural_comparison(
        root=root,
        baseline_validation_path=_entry_path(inventory, root, "baseline_validation"),
        candidate_validation_path=_entry_path(inventory, root, "candidate_validation"),
        baseline_split_path=_entry_path(inventory, root, "baseline_split"),
        candidate_split_path=_entry_path(inventory, root, "candidate_split"),
        baseline_ontology_path=_entry_path(inventory, root, "baseline_ontology"),
        candidate_ontology_path=_entry_path(inventory, root, "candidate_ontology"),
        baseline_mapping_path=_entry_path(inventory, root, "baseline_mapping"),
        candidate_mapping_path=_entry_path(inventory, root, "candidate_mapping"),
        selected_profile=inventory.selected_profile,
    )


def verify_comparison_inventory(path: Path, root: Path) -> StructuralComparisonInventory:
    inventory = load_comparison_inventory(path)
    rebuilt = rebuild_comparison_inventory(inventory, root)
    if rebuilt != inventory:
        raise OmivInputError("comparison inventory does not reconstruct from verified dependencies")
    return inventory


def build_comparison_report(
    inventory: StructuralComparisonInventory,
) -> StructuralComparisonReportEnvelope:
    _internal_verify(inventory)
    executive = {
        "result": inventory.overall_result.value,
        "baseline": inventory.baseline.variant,
        "candidate": inventory.candidate.variant,
        "conclusion": (
            "The verified artifact variants preserve the recorded target identities, "
            "normalized tensor structures, ontology, and semantic-mapping relations "
            "when all structural controls pass."
        ),
        "limitation": (
            "This comparison does not establish payload equality, numerical "
            "quantization fidelity, tokenizer equivalence, runtime equivalence, "
            "or comparative model quality."
        ),
    }
    repository = inventory.repository_comparison.model_dump(mode="json")
    metadata = inventory.metadata_comparison.model_dump(mode="json")
    tensor = {
        "identities": inventory.tensor_identity_comparison.model_dump(mode="json"),
        "shapes": inventory.shape_comparison.model_dump(mode="json"),
        "encoded_spans": inventory.encoded_span_comparison.model_dump(mode="json"),
    }
    transition_matrix = [
        item.model_dump(mode="json")
        for item in inventory.type_transition_comparison.family_transitions
    ]
    profile_matrix = [item.model_dump(mode="json") for item in inventory.profile_results]
    data: dict[str, Any] = {
        "inventory": inventory,
        "executive_summary": executive,
        "repository_summary": repository,
        "metadata_summary": metadata,
        "tensor_summary": tensor,
        "type_transition_matrix": transition_matrix,
        "acceptance_profile_matrix": profile_matrix,
        "report_digest": "0" * 64,
    }
    draft = StructuralComparisonReport.model_validate(data)
    digest_data = draft.model_dump(mode="json")
    digest_data.pop("report_digest")
    data["report_digest"] = canonical_sha256(digest_data)
    report = StructuralComparisonReport.model_validate(data)
    return StructuralComparisonReportEnvelope(
        report=report,
        integrity={
            "canonicalization": CANONICALIZATION_ID,
            "sha256": canonical_sha256(report.model_dump(mode="json")),
        },
    )


def load_comparison_report(path: Path) -> StructuralComparisonReportEnvelope:
    try:
        envelope = StructuralComparisonReportEnvelope.model_validate(_load(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid comparison report: {exc}") from exc
    if envelope.report.report_schema != COMPARISON_REPORT_SCHEMA:
        raise OmivInputError("comparison report schema mismatch")
    if envelope.integrity.get("canonicalization") != CANONICALIZATION_ID:
        raise OmivInputError("comparison report canonicalization mismatch")
    if envelope.integrity.get("sha256") != canonical_sha256(
        envelope.report.model_dump(mode="json")
    ):
        raise OmivInputError("comparison report envelope digest mismatch")
    data = envelope.report.model_dump(mode="json")
    stored = data.pop("report_digest")
    if stored != canonical_sha256(data):
        raise OmivInputError("comparison report digest mismatch")
    expected = build_comparison_report(envelope.report.inventory)
    if expected != envelope:
        raise OmivInputError("comparison report summary reconstruction mismatch")
    return envelope


def verify_comparison_report(path: Path, root: Path) -> StructuralComparisonReportEnvelope:
    envelope = load_comparison_report(path)
    rebuilt = rebuild_comparison_inventory(envelope.report.inventory, root)
    expected = build_comparison_report(rebuilt)
    if expected != envelope:
        raise OmivInputError("comparison report does not reconstruct from dependencies")
    return envelope


def write_comparison_bundle(
    inventory: StructuralComparisonInventory,
    output: Path,
    report_output: Path,
    markdown_output: Path,
) -> StructuralComparisonReportEnvelope:
    report = build_comparison_report(inventory)
    outputs = (output, report_output, markdown_output)
    if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
        raise OmivInputError("comparison outputs must be distinct")
    forbidden = tuple(Path(item.relative_path) for item in inventory.artifact_index)
    atomic_write_text(output, pretty_json(inventory), forbidden_inputs=forbidden)
    atomic_write_text(
        report_output,
        pretty_json(report),
        forbidden_inputs=(*forbidden, output, markdown_output),
    )
    atomic_write_text(
        markdown_output,
        render_comparison_markdown(report),
        forbidden_inputs=(*forbidden, output, report_output),
    )
    return report


def _safe(value: Any) -> str:
    text = html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=True)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return text


def render_comparison_markdown(
    envelope: StructuralComparisonReportEnvelope,
) -> str:
    report = envelope.report
    inv = report.inventory
    lines = [
        "# Model Artifact Structural Comparison",
        "",
        "## Executive Summary",
        "",
        f"**{_safe(inv.overall_result.value)}**",
        "",
        str(report.executive_summary["conclusion"]),
        "",
        str(report.executive_summary["limitation"]),
        "",
        "## Baseline and Candidate",
        "",
        f"- Baseline: `{_safe(inv.baseline.repository)}` / `{_safe(inv.baseline.variant)}`",
        f"- Candidate: `{_safe(inv.candidate.repository)}` / `{_safe(inv.candidate.variant)}`",
        f"- Baseline revision: `{inv.baseline.resolved_revision}`",
        f"- Candidate revision: `{inv.candidate.resolved_revision}`",
        f"- Comparison digest: `{inv.comparison_digest}`",
        f"- Comparison-policy digest: `{inv.policy.policy_digest}`",
        f"- Profile-policy digest: `{inv.profile_policy.policy_digest}`",
        "",
        "## Repository Layout",
        "",
        f"- Same immutable revision: {inv.repository_comparison.same_immutable_revision}",
        f"- Shards: {inv.repository_comparison.baseline_shards} / "
        f"{inv.repository_comparison.candidate_shards}",
        f"- Repository bytes: {inv.repository_comparison.baseline_total_bytes} / "
        f"{inv.repository_comparison.candidate_total_bytes}",
        f"- Repository file-byte ratio (candidate / baseline): "
        f"{inv.repository_comparison.ratio_numerator_reduced} / "
        f"{inv.repository_comparison.ratio_denominator_reduced} "
        f"({inv.repository_comparison.deterministic_decimal})",
        f"- Header bytes accepted: {inv.repository_comparison.baseline_header_bytes} / "
        f"{inv.repository_comparison.candidate_header_bytes}",
        f"- Range requests: {inv.repository_comparison.baseline_range_requests} / "
        f"{inv.repository_comparison.candidate_range_requests}",
        f"- Tensor payload bytes accepted: "
        f"{inv.repository_comparison.baseline_payload_bytes_accepted} / "
        f"{inv.repository_comparison.candidate_payload_bytes_accepted}",
        "",
        "## Metadata",
        "",
        f"- Equal: {inv.metadata_comparison.equal_count}",
        f"- Different and allowed: {inv.metadata_comparison.different_allowed_count}",
        f"- Different and unexpected: "
        f"{inv.metadata_comparison.different_unexpected_count}",
        f"- Missing baseline / candidate: "
        f"{inv.metadata_comparison.missing_baseline_count} / "
        f"{inv.metadata_comparison.missing_candidate_count}",
        "",
        "## Tensor Identity and Shapes",
        "",
        f"- Matched identities: {inv.tensor_identity_comparison.matched_count}",
        f"- Baseline-only / candidate-only: "
        f"{inv.tensor_identity_comparison.baseline_only_count} / "
        f"{inv.tensor_identity_comparison.candidate_only_count}",
        f"- Normalized shape matches: {inv.shape_comparison.normalized_shape_equal_count}",
        f"- Physical-only differences: "
        f"{inv.shape_comparison.physical_different_logically_equal_count}",
        f"- Incompatible shapes: {inv.shape_comparison.incompatible_count}",
        f"- Encoded tensor bytes: "
        f"{inv.encoded_span_comparison.baseline_total_encoded_bytes} / "
        f"{inv.encoded_span_comparison.candidate_total_encoded_bytes}",
        f"- Encoded-span ratio (candidate / baseline): "
        f"{inv.encoded_span_comparison.ratio_numerator} / "
        f"{inv.encoded_span_comparison.ratio_denominator}",
        f"- Bounded spans: {inv.encoded_span_comparison.baseline_bounded_count} / "
        f"{inv.encoded_span_comparison.candidate_bounded_count}",
        f"- Overlaps: {inv.encoded_span_comparison.baseline_overlap_count} / "
        f"{inv.encoded_span_comparison.candidate_overlap_count}",
        "",
        "## GGML Type Transitions",
        "",
        "| Family | Baseline type | Candidate type | State | Allowed | Count |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for item in inv.type_transition_comparison.family_transitions:
        lines.append(
            f"| {_safe(item.family_id)} | {_safe(item.baseline_type)} | "
            f"{_safe(item.candidate_type)} | {_safe(item.state.value)} | "
            f"{item.allowed} | {item.count} |"
        )
    lines.extend(
        [
            "",
            "## Acceptance Profiles",
            "",
            "| Profile | Result | Warnings | Failed controls |",
            "| --- | --- | --- | --- |",
        ]
    )
    for profile in inv.profile_results:
        lines.append(
            f"| {_safe(profile.profile_name)} | **{_safe(profile.outcome.value)}** | "
            f"{_safe(', '.join(profile.warning_controls) or '—')} | "
            f"{_safe(', '.join(profile.failed_controls) or '—')} |"
        )
    lines.extend(["", "## Evidence Boundaries", ""])
    lines.extend(
        [
            "- Cross-quantization structural comparison: checked",
            "- Payload equality: not checked",
            "- Quantization numerical fidelity: not checked",
            "- Tokenizer parity: not checked",
            "- Runtime parity: not checked",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {_safe(item)}" for item in inv.limitations)
    lines.extend(["", "## Artifact Index", ""])
    lines.extend(
        f"- `{_safe(item.relative_path)}` — {_safe(item.role)}, "
        f"`{item.digest}`, {item.size_bytes} bytes"
        for item in inv.artifact_index
    )
    lines.extend(["", "## Findings", ""])
    lines.extend(
        f"- **{_safe(item.status)}** {_safe(item.finding_id)}: {_safe(item.summary)}"
        for item in inv.findings
    )
    return "\n".join(lines) + "\n"


def selected_profile_exit_code(inventory: StructuralComparisonInventory) -> int:
    selected = next(
        item
        for item in inventory.profile_results
        if item.profile_name == inventory.selected_profile
    )
    return (
        0
        if selected.outcome
        in {
            ComparisonProfileOutcome.SATISFIED,
            ComparisonProfileOutcome.SATISFIED_WITH_WARNINGS,
        }
        else 1
    )
