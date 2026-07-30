"""Deterministic serialization, rendering, and verification for validation bundles."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256, load_json_value
from omiv.errors import OmivInputError
from omiv.safe_write import atomic_write_text
from omiv.validation.builder import build_independent_validation
from omiv.validation.models import (
    EvidenceStatus,
    ValidationInventory,
    ValidationReport,
    ValidationReportEnvelope,
)
from omiv.validation.profiles import evaluate_profiles, profile_policy

MAX_VALIDATION_BYTES = 64 * 1024 * 1024


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


def _load_json(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_VALIDATION_BYTES:
            raise OmivInputError(f"validation artifact exceeds {MAX_VALIDATION_BYTES} bytes")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot load validation artifact: {exc}") from exc


def _inventory_digest(inventory: ValidationInventory) -> str:
    data = inventory.model_dump(mode="json")
    data.pop("inventory_digest")
    return canonical_sha256(data)


def _graph_digest(inventory: ValidationInventory) -> str:
    return canonical_sha256(
        {
            "nodes": [node.model_dump(mode="json") for node in inventory.evidence_nodes],
            "edges": [edge.model_dump(mode="json") for edge in inventory.evidence_edges],
            "model_pack_digest": inventory.model_pack_identity.digest,
            "policy_digests": sorted(
                [
                    inventory.model_pack_identity.ontology_policy_digest,
                    inventory.model_pack_identity.mapping_policy_digest,
                ]
            ),
            "stages": [stage.model_dump(mode="json") for stage in inventory.evidence_stages],
        }
    )


def _verify_internal(inventory: ValidationInventory) -> None:
    if _inventory_digest(inventory) != inventory.inventory_digest:
        raise OmivInputError("validation inventory digest mismatch")
    if _graph_digest(inventory) != inventory.evidence_graph_digest:
        raise OmivInputError("evidence graph digest mismatch")
    trusted_policy = profile_policy()
    if inventory.profile_policy != trusted_policy:
        raise OmivInputError("validation acceptance-profile policy mismatch")
    if evaluate_profiles(inventory.evidence_stages, trusted_policy) != inventory.profile_results:
        raise OmivInputError("acceptance-profile result reconstruction mismatch")
    if any(edge.linkage_status != EvidenceStatus.PASS for edge in inventory.evidence_edges):
        raise OmivInputError("validation evidence graph contains a failed linkage")
    if inventory.artifact_index.index_digest != canonical_sha256(
        {"entries": [entry.model_dump(mode="json") for entry in inventory.artifact_index.entries]}
    ):
        raise OmivInputError("artifact-index digest mismatch")


def load_validation_inventory(path: Path) -> ValidationInventory:
    try:
        inventory = ValidationInventory.model_validate(_load_json(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid validation inventory: {exc}") from exc
    _verify_internal(inventory)
    return inventory


def _entry_path(inventory: ValidationInventory, root: Path, role: str) -> Path:
    matches = [entry for entry in inventory.artifact_index.entries if entry.role == role]
    if len(matches) != 1:
        raise OmivInputError(f"artifact index must contain exactly one {role!r}")
    return root / matches[0].relative_path


def verify_validation_inventory(path: Path, root: Path) -> ValidationInventory:
    """Rebuild an inventory from verified dependencies and compare it byte-for-byte."""
    inventory = load_validation_inventory(path)
    root = root.resolve()
    for entry in inventory.artifact_index.entries:
        artifact = root / entry.relative_path
        if not artifact.is_file():
            raise OmivInputError(f"artifact-index file is missing: {entry.relative_path}")
        if artifact.stat().st_size != entry.size_bytes:
            raise OmivInputError(f"artifact-index size mismatch: {entry.relative_path}")
    rebuilt = build_independent_validation(
        root=root,
        subject=inventory.subject.model_family,
        variant=inventory.subject.artifact_variant,
        snapshot_path=_entry_path(inventory, root, "repository_snapshot"),
        split_path=_entry_path(inventory, root, "split_inventory"),
        ontology_path=_entry_path(inventory, root, "target_ontology_inventory"),
        mapping_path=_entry_path(inventory, root, "semantic_mapping_inventory"),
        selected_profile=inventory.selected_profile,
    )
    if rebuilt != inventory:
        raise OmivInputError(
            "validation inventory does not reconstruct from canonical dependencies"
        )
    return inventory


def _stage_matrix(inventory: ValidationInventory) -> list[dict[str, Any]]:
    return [
        {
            "stage": stage.stage.value,
            "status": stage.status.value,
            "evidence": stage.evidence_node_ids,
            "scope": stage.scope,
            "limitations": stage.limitations,
            "next_required_evidence": stage.next_required_evidence,
        }
        for stage in inventory.evidence_stages
    ]


def _profile_matrix(inventory: ValidationInventory) -> list[dict[str, Any]]:
    return [
        {
            "profile": result.profile_name,
            "outcome": result.outcome.value,
            "satisfied": result.satisfied,
            "warning_count": result.warning_count,
            "failed_requirement_count": result.failed_requirement_count,
        }
        for result in inventory.profile_results
    ]


COMMERCIAL_CONTROLS = (
    ("Artifact identity", "repository_identity"),
    ("Immutable revision", "repository_identity"),
    ("Repository completeness", "repository_layout"),
    ("Remote byte-range safety", "range_semantics"),
    ("GGUF header completeness", "complete_header"),
    ("Split consistency", "split_container"),
    ("Tensor descriptor completeness", "split_container"),
    ("Payload-span bounds", "payload_span_bounds"),
    ("Target architecture ontology", "target_ontology"),
    ("Structural semantic mapping", "structural_semantic_mapping"),
    ("Converter rule evidence", "converter_rule_support"),
    ("Artifact-specific provenance", "artifact_specific_provenance"),
    ("Payload integrity", "payload_integrity"),
    ("Quantization fidelity", "quantization_fidelity"),
    ("Tokenizer parity", "tokenizer_parity"),
    ("Runtime parity", "runtime_parity"),
)


def _commercial_matrix(inventory: ValidationInventory) -> list[dict[str, Any]]:
    stages = {stage.stage.value: stage for stage in inventory.evidence_stages}
    rows = []
    for control, stage_name in COMMERCIAL_CONTROLS:
        stage = stages[stage_name]
        interpretation = (
            "Structural control accepted within its recorded scope."
            if stage.status == EvidenceStatus.PASS
            else "Supporting converter rules are pinned; artifact production is not proven."
            if stage.status == EvidenceStatus.AVAILABLE
            else "This control cannot support an equivalence or deployment claim."
        )
        rows.append(
            {
                "control": control,
                "status": stage.status.value,
                "evidence": stage.evidence_node_ids,
                "commercial_interpretation": interpretation,
                "required_next_step": stage.next_required_evidence,
            }
        )
    return rows


def build_validation_report(inventory: ValidationInventory) -> ValidationReportEnvelope:
    _verify_internal(inventory)
    executive = {
        "result": inventory.structural_validation_result.value,
        "subject": "Kimi K3 UD-IQ1_M",
        "repository": inventory.repository_identity.repository,
        "resolved_revision": inventory.repository_identity.resolved_revision,
        "conclusion": (
            "The pinned UD-IQ1_M split GGUF set is structurally validated under "
            "the recorded repository, HTTP Range, GGUF header, split-container, "
            "Kimi K3 ontology, and semantic-mapping policies."
        ),
        "limitation": (
            "This result is not evidence of tensor payload integrity, numerical "
            "quantization fidelity, tokenizer parity, runtime equivalence, or "
            "artifact-specific conversion provenance."
        ),
        "structural_integration_acceptance": True,
        "numerical_or_runtime_equivalence": False,
    }
    engineering = {
        "repository": inventory.repository_summary,
        "architecture": inventory.architecture_summary,
        "source_accounting": inventory.source_accounting,
        "target_accounting": inventory.target_accounting,
        "mapping_domains": inventory.mapping_domain_summary,
        "model_pack": inventory.model_pack_identity.model_dump(mode="json"),
        "evidence_graph_digest": inventory.evidence_graph_digest,
        "artifact_index_digest": inventory.artifact_index.index_digest,
        "verified_scope": inventory.verified_scope,
        "not_verified_scope": inventory.not_verified_scope,
        "limitations": inventory.limitations,
    }
    report_data: dict[str, Any] = {
        "inventory": inventory,
        "executive_summary": executive,
        "engineering_summary": engineering,
        "commercial_acceptance_matrix": _commercial_matrix(inventory),
        "validation_stage_matrix": _stage_matrix(inventory),
        "acceptance_profile_matrix": _profile_matrix(inventory),
        "report_digest": "0" * 64,
    }
    draft = ValidationReport.model_validate(report_data)
    digest_data = draft.model_dump(mode="json")
    digest_data.pop("report_digest")
    report_data["report_digest"] = canonical_sha256(digest_data)
    report = ValidationReport.model_validate(report_data)
    return ValidationReportEnvelope(
        report=report,
        integrity={
            "canonicalization": CANONICALIZATION_ID,
            "sha256": canonical_sha256(report.model_dump(mode="json")),
        },
    )


def load_validation_report(path: Path) -> ValidationReportEnvelope:
    try:
        envelope = ValidationReportEnvelope.model_validate(_load_json(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid independent validation report: {exc}") from exc
    if envelope.integrity.get("canonicalization") != CANONICALIZATION_ID:
        raise OmivInputError("validation report canonicalization mismatch")
    if envelope.integrity.get("sha256") != canonical_sha256(
        envelope.report.model_dump(mode="json")
    ):
        raise OmivInputError("validation report envelope integrity mismatch")
    report_data = envelope.report.model_dump(mode="json")
    stored = report_data.pop("report_digest")
    if stored != canonical_sha256(report_data):
        raise OmivInputError("validation report digest mismatch")
    _verify_internal(envelope.report.inventory)
    expected = build_validation_report(envelope.report.inventory)
    if expected != envelope:
        raise OmivInputError("validation report derived summary reconstruction mismatch")
    return envelope


def verify_validation_report(path: Path, root: Path) -> ValidationReportEnvelope:
    envelope = load_validation_report(path)
    inventory = envelope.report.inventory
    rebuilt = verify_inventory_model(inventory, root)
    expected = build_validation_report(rebuilt)
    if expected != envelope:
        raise OmivInputError("validation report does not reconstruct from dependencies")
    return envelope


def verify_inventory_model(inventory: ValidationInventory, root: Path) -> ValidationInventory:
    """Verify an embedded inventory without requiring a separate inventory file."""
    root = root.resolve()
    rebuilt = build_independent_validation(
        root=root,
        subject=inventory.subject.model_family,
        variant=inventory.subject.artifact_variant,
        snapshot_path=_entry_path(inventory, root, "repository_snapshot"),
        split_path=_entry_path(inventory, root, "split_inventory"),
        ontology_path=_entry_path(inventory, root, "target_ontology_inventory"),
        mapping_path=_entry_path(inventory, root, "semantic_mapping_inventory"),
        selected_profile=inventory.selected_profile,
    )
    if rebuilt != inventory:
        raise OmivInputError("embedded validation inventory reconstruction mismatch")
    return inventory


def write_validation_bundle(
    inventory: ValidationInventory,
    output: Path,
    report_output: Path,
    markdown_output: Path,
    *,
    forbidden_inputs: tuple[Path, ...] = (),
) -> ValidationReportEnvelope:
    report = build_validation_report(inventory)
    outputs = [output, report_output, markdown_output]
    if len({path.resolve(strict=False) for path in outputs}) != len(outputs):
        raise OmivInputError("validation bundle outputs must use distinct paths")
    atomic_write_text(
        output,
        pretty_json(inventory),
        forbidden_inputs=[*forbidden_inputs, report_output, markdown_output],
    )
    atomic_write_text(
        report_output,
        pretty_json(report),
        forbidden_inputs=[*forbidden_inputs, output, markdown_output],
    )
    atomic_write_text(
        markdown_output,
        render_validation_markdown(report),
        forbidden_inputs=[*forbidden_inputs, output, report_output],
    )
    return report


def _safe(value: Any) -> str:
    text = html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=True)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return text


def render_validation_markdown(envelope: ValidationReportEnvelope) -> str:
    report = envelope.report
    inventory = report.inventory
    executive = report.executive_summary
    lines = [
        "# Independent Model Validation — Kimi K3 UD\\-IQ1\\_M",
        "",
        "## Executive Summary",
        "",
        f"**{_safe(executive['result'])}**",
        "",
        str(executive["conclusion"]),
        "",
        str(executive["limitation"]),
        "",
        "## Subject Identity",
        "",
        f"- Repository: `{_safe(inventory.repository_identity.repository)}`",
        f"- Requested revision: `{_safe(inventory.repository_identity.requested_revision)}`",
        f"- Resolved revision: `{_safe(inventory.repository_identity.resolved_revision)}`",
        f"- Selection: `{_safe(inventory.repository_identity.selection)}`",
        f"- Model pack: `kimi-k3` v{inventory.model_pack_identity.version}",
        f"- Model-pack digest: `{inventory.model_pack_identity.digest}`",
        f"- Evidence-graph digest: `{inventory.evidence_graph_digest}`",
        f"- Profile-policy digest: `{inventory.profile_policy.policy_digest}`",
        f"- Artifact-index digest: `{inventory.artifact_index.index_digest}`",
        f"- Validation inventory digest: `{inventory.inventory_digest}`",
        f"- Validation report digest: `{report.report_digest}`",
        "",
        "## Validation Stages",
        "",
        "| Stage | Status | Scope | Limitation / next evidence |",
        "| --- | --- | --- | --- |",
    ]
    for stage in inventory.evidence_stages:
        boundary = "; ".join([*stage.limitations, *stage.next_required_evidence]) or "—"
        lines.append(
            f"| {_safe(stage.stage.value)} | **{_safe(stage.status.value)}** | "
            f"{_safe('; '.join(stage.scope) or '—')} | {_safe(boundary)} |"
        )
    lines.extend(
        [
            "",
            "## Acceptance Profiles",
            "",
            "| Profile | Result | Warnings | Failed requirements |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    for profile in inventory.profile_results:
        lines.append(
            f"| {_safe(profile.profile_name)} | **{_safe(profile.outcome.value)}** | "
            f"{profile.warning_count} | {profile.failed_requirement_count} |"
        )
    repository = inventory.repository_summary
    lines.extend(
        [
            "",
            "## Engineering Summary",
            "",
            f"- Selected shards: {repository['selected_shard_count']}",
            f"- Repository bytes: {repository['total_repository_bytes']}",
            f"- Accepted header bytes: {repository['header_bytes_accepted']}",
            f"- Range requests: {repository['range_request_count']}",
            f"- Tensor payload bytes accepted: {repository['tensor_payload_bytes_accepted']}",
            (
                f"- Global/aggregated tensors: "
                f"{repository['global_declared_tensor_count']}/"
                f"{repository['aggregated_tensor_count']}"
            ),
            (
                f"- Duplicate/conflicting names: {repository['duplicate_count']}/"
                f"{repository['conflict_count']}"
            ),
            (
                f"- Computable/bounded spans: "
                f"{repository['payload_span_computable_count']}/"
                f"{repository['payload_span_bounded_count']}"
            ),
            f"- Span overlaps: {repository['payload_span_overlap_count']}",
            "",
            "### Architecture",
            "",
        ]
    )
    architecture = inventory.architecture_summary
    for label, key in (
        ("Architecture", "architecture"),
        ("Layers", "layers"),
        ("KDA / MLA", "kda_layers"),
        ("Target tensors", "target_tensors"),
        ("Routed experts", "routed_experts"),
        ("Experts used", "experts_used"),
        ("Shared experts", "shared_experts"),
        ("Attention Residual block size", "attention_residual_block_size"),
    ):
        value = (
            f"{architecture['kda_layers']} / {architecture['mla_layers']}"
            if label == "KDA / MLA"
            else architecture[key]
        )
        lines.append(f"- {_safe(label)}: {_safe(value)}")
    lines.extend(
        [
            "",
            "### Source and Target Accounting",
            "",
            f"- Source records: {inventory.source_accounting['physical_records']} "
            f"(unresolved {inventory.source_accounting['unresolved_records']})",
            f"- Historical 450: {inventory.source_accounting['newly_classified_text_records']} "
            "newly classified text + "
            f"{inventory.source_accounting['source_only_auxiliary_records']} "
            "source-only vision/mm-projector auxiliary",
            f"- Target descriptors: {inventory.target_accounting['physical_records']} "
            f"(unresolved {inventory.target_accounting['unresolved_records']})",
            "",
            "| Accounting side | State | Count |",
            "| --- | --- | ---: |",
        ]
    )
    for side, accounting in (
        ("source", inventory.source_accounting),
        ("target", inventory.target_accounting),
    ):
        states = cast(dict[str, int], accounting["states"])
        for state, count in sorted(states.items()):
            lines.append(f"| {side} | {_safe(state)} | {count} |")
    lines.extend(
        [
            "",
            "### Semantic Mapping Domains",
            "",
            "| Domain | Source | Target | Relation | Evidence | Payload |",
            "| --- | ---: | ---: | --- | --- | --- |",
        ]
    )
    for domain in inventory.mapping_domain_summary:
        lines.append(
            f"| {_safe(domain['domain'])} | {domain['source_numerator']}/"
            f"{domain['source_denominator']} | "
            f"{domain['target_numerator']}/{domain['target_denominator']} | "
            f"{_safe(domain['relation'])} | {_safe(domain['evidence_level'])} | "
            f"**{_safe(domain['payload_status'])}** |"
        )
    lines.extend(
        [
            "",
            "## Commercial Acceptance Controls",
            "",
            "| Control | Status | Commercial interpretation | Required next step |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in report.commercial_acceptance_matrix:
        required_next_step = cast(list[str], row["required_next_step"])
        lines.append(
            f"| {_safe(row['control'])} | **{_safe(row['status'])}** | "
            f"{_safe(row['commercial_interpretation'])} | "
            f"{_safe('; '.join(required_next_step) or '—')} |"
        )
    lines.extend(["", "## Verified", ""])
    lines.extend(f"- {_safe(item)}" for item in inventory.verified_scope)
    lines.extend(["", "## Not Verified", ""])
    lines.extend(f"- {_safe(item)}" for item in inventory.not_verified_scope)
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_safe(item)}" for item in inventory.limitations)
    lines.extend(["", "## Unavailable Evidence", ""])
    lines.extend(
        f"- {_safe(stage.stage.value)}: {_safe('; '.join(stage.limitations))}"
        for stage in inventory.evidence_stages
        if stage.status == EvidenceStatus.UNAVAILABLE
    )
    lines.extend(["", "## Not-Checked Evidence", ""])
    lines.extend(
        f"- {_safe(stage.stage.value)}: {_safe('; '.join(stage.limitations))}"
        for stage in inventory.evidence_stages
        if stage.status == EvidenceStatus.NOT_CHECKED
    )
    lines.extend(
        [
            "",
            "## Reproducibility",
            "",
            (
                "Offline verification requires only the repository-relative artifacts "
                "in the embedded index."
            ),
            "",
        ]
    )
    lines.extend(
        f"- `{_safe(command.command)}` — {_safe(command.purpose)}"
        for command in inventory.reproduction.offline_verification_commands
    )
    lines.extend(["", "## Artifact Index", ""])
    lines.extend(
        f"- `{_safe(entry.relative_path)}` — {_safe(entry.role)}, "
        f"`{entry.canonical_digest}`, {entry.size_bytes} bytes"
        for entry in inventory.artifact_index.entries
    )
    lines.extend(["", "## Findings", ""])
    lines.extend(
        f"- **{_safe(finding.status.value)}** {_safe(finding.finding_id)}: {_safe(finding.summary)}"
        for finding in inventory.findings
    )
    return "\n".join(lines) + "\n"
