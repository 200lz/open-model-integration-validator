"""Integrity, verification, and Markdown for Kimi K3 GGUF ontology evidence."""

from __future__ import annotations

import html
import json
from pathlib import Path

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.model_packs.kimi_k3.gguf_models import (
    KimiK3GGUFOntologyInventory,
    KimiK3GGUFOntologyInventoryEnvelope,
    KimiK3GGUFOntologyReport,
    KimiK3GGUFOntologyReportEnvelope,
    build_ontology_findings,
)
from omiv.model_packs.registry import get_model_pack
from omiv.remote.models import Integrity, RemoteResult, ReportExecution
from omiv.remote.reporting import safe_markdown_text
from omiv.remote.split_models import SplitInventoryEnvelope
from omiv.remote.split_reporting import (
    split_inventory_integrity_matches,
)

MAX_ONTOLOGY_ARTIFACT_BYTES = 128 * 1024 * 1024


def build_ontology_inventory_envelope(
    inventory: KimiK3GGUFOntologyInventory,
) -> KimiK3GGUFOntologyInventoryEnvelope:
    return KimiK3GGUFOntologyInventoryEnvelope(
        inventory=inventory,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(inventory.model_dump(mode="json")),
        ),
    )


def ontology_inventory_integrity_matches(
    envelope: KimiK3GGUFOntologyInventoryEnvelope,
) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(envelope.inventory.model_dump(mode="json"))


def ontology_inventory_links_split(
    envelope: KimiK3GGUFOntologyInventoryEnvelope,
    split: SplitInventoryEnvelope,
) -> bool:
    inventory = envelope.inventory
    source = split.inventory
    return (
        split_inventory_integrity_matches(split)
        and inventory.source_split_inventory_sha256 == split.integrity.sha256
        and inventory.source_split_schema == source.inventory_schema
        and inventory.repository == source.repository
        and inventory.snapshot_sha256 == source.snapshot_sha256
        and inventory.split_shard_count == source.shard_count
        and inventory.split_tensor_count == source.aggregated_tensor_count
    )


def _validate_model_pack_linkage(
    inventory: KimiK3GGUFOntologyInventory,
) -> None:
    pack = get_model_pack(inventory.model_pack)
    if pack.metadata.digest != inventory.model_pack_digest:
        raise OmivInputError("ontology model-pack digest mismatch")
    if inventory.ontology_policy_digest != inventory.ontology_policy.digest:
        raise OmivInputError("ontology policy digest mismatch")


def load_ontology_inventory(
    path: Path,
) -> KimiK3GGUFOntologyInventoryEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_ONTOLOGY_ARTIFACT_BYTES)
        envelope = KimiK3GGUFOntologyInventoryEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid Kimi K3 GGUF ontology inventory: {exc}") from exc
    if not ontology_inventory_integrity_matches(envelope):
        raise OmivInputError("Kimi K3 GGUF ontology inventory integrity mismatch")
    _validate_model_pack_linkage(envelope.inventory)
    return envelope


def build_ontology_report(
    envelope: KimiK3GGUFOntologyInventoryEnvelope,
) -> KimiK3GGUFOntologyReportEnvelope:
    if not ontology_inventory_integrity_matches(envelope):
        raise OmivInputError("cannot report an invalid ontology inventory")
    _validate_model_pack_linkage(envelope.inventory)
    findings = build_ontology_findings(envelope.inventory)
    result = (
        RemoteResult.FAIL
        if any(item.status == RemoteResult.FAIL for item in findings)
        else RemoteResult.WARN
        if any(item.status == RemoteResult.WARN for item in findings)
        else RemoteResult.PASS
    )
    report = KimiK3GGUFOntologyReport(
        execution=ReportExecution(
            result=result,
            exit_code=1 if result == RemoteResult.FAIL else 0,
        ),
        inventory_sha256=envelope.integrity.sha256,
        inventory=envelope.inventory,
        findings=findings,
        limitations=[
            "The ontology classifies target-side physical GGUF descriptors only.",
            "Packed expert PASS does not prove source expert ordering or source-to-target mapping.",
            "Shape PASS does not prove tensor values or conversion transforms.",
            "GGML type placement PASS does not prove quantization fidelity.",
            "No tensor payload byte, tokenizer parity, logit parity, or runtime "
            "output was checked.",
        ],
    )
    return KimiK3GGUFOntologyReportEnvelope(
        report=report,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(report.model_dump(mode="json")),
        ),
    )


def ontology_report_integrity_matches(
    envelope: KimiK3GGUFOntologyReportEnvelope,
) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(envelope.report.model_dump(mode="json"))


def load_ontology_report(
    path: Path,
) -> KimiK3GGUFOntologyReportEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_ONTOLOGY_ARTIFACT_BYTES)
        envelope = KimiK3GGUFOntologyReportEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid Kimi K3 GGUF ontology report: {exc}") from exc
    _validate_model_pack_linkage(envelope.report.inventory)
    return envelope


def pretty_ontology_json(
    value: KimiK3GGUFOntologyInventoryEnvelope | KimiK3GGUFOntologyReportEnvelope,
) -> str:
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


def render_ontology_markdown(
    envelope: KimiK3GGUFOntologyReportEnvelope,
) -> str:
    report = envelope.report
    inventory = report.inventory
    census = inventory.census
    classification = inventory.classification
    lines = [
        "# Kimi K3 Target GGUF Ontology Report",
        "",
        "## Result",
        "",
        report.execution.result.value.upper(),
        "",
        "## Pinned Target",
        "",
        f"- Repository: {safe_markdown_text(inventory.repository.repo_id)}",
        f"- Resolved revision: {inventory.repository.resolved_revision}",
        f"- Split inventory SHA-256: {inventory.source_split_inventory_sha256}",
        f"- Snapshot SHA-256: {inventory.snapshot_sha256}",
        f"- Shards: {inventory.split_shard_count}",
        f"- Tensor descriptors: {inventory.split_tensor_count}",
        "",
        "## Architecture Metadata",
        "",
        f"- Architecture: "
        f"{safe_markdown_text(inventory.architecture_metadata.architecture_identifier)}",
        f"- Model name: {safe_markdown_text(inventory.architecture_metadata.model_name)}",
        f"- Direct metadata items: {inventory.architecture_metadata.direct_item_count}",
        f"- Derived items: {inventory.architecture_metadata.derived_item_count}",
        f"- Required failures: {len(inventory.architecture_metadata.required_failures)}",
        "",
        "## Tensor-Name Census",
        "",
        f"- Unique names: {census.unique_tensor_count}",
        f"- Layer-indexed names: {census.layer_indexed_count}",
        f"- Non-layer names: {len(census.non_layer_names)}",
        f"- Suffix vocabulary size: {len(census.suffix_vocabulary)}",
        f"- Observed layer range: {census.observed_layer_ids[0]}–{census.observed_layer_ids[-1]}",
        f"- GGML types: {safe_markdown_text(census.tensor_count_by_ggml_type)}",
        "",
        "## Schedules",
        "",
        f"- KDA layers ({len(inventory.schedule.kda_layer_ids)}): "
        f"{safe_markdown_text(inventory.schedule.kda_layer_ids)}",
        f"- MLA layers ({len(inventory.schedule.mla_layer_ids)}): "
        f"{safe_markdown_text(inventory.schedule.mla_layer_ids)}",
        f"- Dense layers: {safe_markdown_text(inventory.schedule.dense_layer_ids)}",
        f"- MoE layers: {len(inventory.schedule.moe_layer_ids)}",
        "",
        "## Structural Families",
        "",
        f"- Packed routed-expert families: "
        f"{safe_markdown_text(inventory.packed_experts.family_ids)}",
        f"- Structurally encoded expert count: "
        f"{safe_markdown_text(inventory.packed_experts.structurally_encoded_expert_counts)}",
        f"- Shared-expert families: {safe_markdown_text(inventory.shared_experts.family_ids)}",
        f"- g_proj physical families: {safe_markdown_text(inventory.g_proj.physical_family_ids)}",
        f"- Attention Residual block size: "
        f"{safe_markdown_text(inventory.attention_residual.metadata_block_size)}",
        "",
        "## Classification Accounting",
        "",
        f"- Classified: {classification.classified_count}",
        f"- Intentionally unclassified: {classification.intentionally_unclassified_count}",
        f"- Invalid: {classification.invalid_count}",
        f"- Duplicate classification: {classification.duplicate_classification_count}",
        "",
        "## Family Census",
        "",
        "| Family | Count | Scope | Physical shapes | GGML types | Coverage |",
        "| --- | ---: | --- | --- | --- | --- |",
    ]
    for family in inventory.family_summaries:
        shapes = [item.physical_dimensions for item in family.shape_summaries]
        valid = family.coverage_valid and family.shape_valid and family.type_valid
        lines.append(
            f"| {safe_markdown_text(family.family_id)} | {family.observed_count} | "
            f"{safe_markdown_text(family.scope)} | {safe_markdown_text(shapes)} | "
            f"{safe_markdown_text(family.ggml_type_counts)} | "
            f"{'PASS' if valid else 'FAIL'} |"
        )
    lines.extend(["", "## Findings"])
    for finding in report.findings:
        evidence = json.dumps(
            finding.evidence,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        lines.extend(
            [
                "",
                f"### {safe_markdown_text(finding.rule_id)}",
                "",
                f"- Status: {finding.status.value.upper()}",
                f"- Message: {safe_markdown_text(finding.message)}",
                "- Evidence:",
                "",
                "    " + html.escape(evidence, quote=False),
            ]
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {safe_markdown_text(item)}" for item in report.limitations)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Inventory SHA-256: {report.inventory_sha256}",
            f"- Model-pack SHA-256: {inventory.model_pack_digest}",
            f"- Ontology policy SHA-256: {inventory.ontology_policy_digest}",
            f"- Classification SHA-256: {inventory.census.classified_assignment_sha256}",
            f"- Report SHA-256: {envelope.integrity.sha256}",
            "",
        ]
    )
    return "\n".join(lines)
