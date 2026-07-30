"""Strict schemas for Kimi K3 target-side GGUF ontology evidence."""

from __future__ import annotations

from typing import Final, Literal, cast

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.model_packs.kimi_k3.gguf_ontology import KimiK3GGUFOntologyPolicy
from omiv.models import StrictModel
from omiv.remote.models import (
    SHA256_PATTERN,
    Integrity,
    RemoteFinding,
    RemoteResult,
    ReportExecution,
    RepositoryIdentity,
)

ONTOLOGY_INVENTORY_SCHEMA: Final = "omiv.kimi-k3-gguf-ontology-inventory.v1"
ONTOLOGY_REPORT_SCHEMA: Final = "omiv.kimi-k3-gguf-ontology-report.v1"


class CensusOrderingObservation(StrictModel):
    descriptor_order_matches_name_order: bool
    payload_offset_order_matches_descriptor_order_by_shard: bool
    payload_gap_count: int = Field(ge=0)
    trailing_byte_count: int = Field(ge=0)


class TensorNameCensus(StrictModel):
    total_tensor_count: int = Field(ge=0)
    unique_tensor_count: int = Field(ge=0)
    top_level_prefix_counts: dict[str, int]
    suffix_vocabulary: list[str]
    layer_indexed_count: int = Field(ge=0)
    non_layer_names: list[str]
    observed_layer_ids: list[int]
    tensor_count_by_layer: dict[str, int]
    tensor_count_by_shard: dict[str, int]
    tensor_count_by_ggml_type: dict[str, int]
    tensor_count_by_family: dict[str, int]
    shape_signatures_by_family: dict[str, dict[str, int]]
    ggml_types_by_family: dict[str, dict[str, int]]
    malformed_names: list[str]
    packed_tensor_names: list[str]
    shared_expert_tensor_names: list[str]
    attention_residual_tensor_names: list[str]
    g_proj_tensor_names: list[str]
    ordering: CensusOrderingObservation
    classified_assignment_sha256: str = Field(pattern=SHA256_PATTERN)


class ArchitectureMetadataItem(StrictModel):
    key: str
    policy_class: Literal[
        "required", "optional", "derived", "informational", "unsupported", "unknown"
    ]
    evidence: Literal["direct", "derived", "unavailable"]
    value_type: str | None = None
    summary_value: JsonValue = None
    encoded_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    valid: bool
    note: str | None = None


class ArchitectureMetadataSummary(StrictModel):
    metadata_inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    metadata_shard_path: str
    architecture_identifier: str | None
    model_name: str | None
    items: list[ArchitectureMetadataItem]
    required_failures: list[str]
    direct_item_count: int = Field(ge=0)
    derived_item_count: int = Field(ge=0)
    unavailable_item_count: int = Field(ge=0)


class FamilyShapeSummary(StrictModel):
    physical_dimensions: list[int]
    normalized_dimensions: list[int]
    shape_relation: str
    dimension_roles: list[str]
    observation_count: int = Field(ge=1)


class TensorFamilySummary(StrictModel):
    family_id: str
    suffix: str
    scope: str
    physical_kind: str
    module: str
    observed_count: int = Field(ge=0)
    expected_count: int = Field(ge=0)
    observed_layer_ids: list[int]
    expected_layer_ids: list[int]
    missing_layer_ids: list[int]
    unexpected_layer_ids: list[int]
    duplicate_layer_ids: list[int]
    shape_summaries: list[FamilyShapeSummary]
    ggml_type_counts: dict[str, int]
    allowed_ggml_types: list[str]
    shape_valid: bool
    type_valid: bool
    coverage_valid: bool


class LayerOntologySummary(StrictModel):
    layer_id: int = Field(ge=0)
    attention_kind: Literal["kda", "mla", "unknown", "conflict"]
    ffn_kind: Literal["dense", "moe", "unknown", "conflict"]
    tensor_count: int = Field(ge=0)
    classified_tensor_count: int = Field(ge=0)
    unclassified_tensor_count: int = Field(ge=0)
    family_ids: list[str]
    missing_family_ids: list[str]
    unexpected_family_ids: list[str]


class ScheduleSummary(StrictModel):
    expected_layer_ids: list[int]
    observed_layer_ids: list[int]
    missing_layer_ids: list[int]
    unexpected_layer_ids: list[int]
    kda_layer_ids: list[int]
    mla_layer_ids: list[int]
    dense_layer_ids: list[int]
    moe_layer_ids: list[int]
    missing_kda_layer_ids: list[int]
    unexpected_kda_layer_ids: list[int]
    missing_mla_layer_ids: list[int]
    unexpected_mla_layer_ids: list[int]
    attention_overlap_layer_ids: list[int]


class PackedExpertSummary(StrictModel):
    family_ids: list[str]
    layer_ids: list[int]
    missing_layer_ids: list[int]
    duplicate_components: list[str]
    structurally_encoded_expert_counts: list[int]
    metadata_expert_count: int | None
    shape_valid: bool
    type_valid: bool


class SharedExpertSummary(StrictModel):
    family_ids: list[str]
    layer_ids: list[int]
    missing_layer_ids: list[int]
    unexpected_layer_ids: list[int]
    duplicate_components: list[str]
    shape_valid: bool
    type_valid: bool


class GProjSummary(StrictModel):
    physical_family_ids: list[str]
    kda_layer_ids: list[int]
    mla_layer_ids: list[int]
    combined_layer_ids: list[int]
    missing_layer_ids: list[int]
    duplicate_layer_ids: list[int]
    shape_valid: bool
    type_valid: bool


class AttentionResidualSummary(StrictModel):
    layer_family_ids: list[str]
    model_family_ids: list[str]
    attention_score_layer_ids: list[int]
    ffn_score_layer_ids: list[int]
    model_output_score_present: bool
    metadata_block_size: int | None
    expected_block_size: int
    derived_checkpoint_layer_ids: list[int]
    missing_components: list[str]
    shape_valid: bool
    type_valid: bool


class ClassificationDetail(StrictModel):
    name: str
    shard_path: str
    dimensions: list[int]
    ggml_type_name: str
    reason: str
    suggested_category: str | None = None


class ClassificationAccounting(StrictModel):
    total_tensor_count: int = Field(ge=0)
    classified_count: int = Field(ge=0)
    intentionally_unclassified_count: int = Field(ge=0)
    invalid_count: int = Field(ge=0)
    duplicate_classification_count: int = Field(ge=0)
    unclassified_details: list[ClassificationDetail]
    invalid_details: list[ClassificationDetail]
    unclassified_detail_digest: str = Field(pattern=SHA256_PATTERN)
    invalid_detail_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def consistent(self) -> ClassificationAccounting:
        if (
            self.classified_count + self.intentionally_unclassified_count + self.invalid_count
            != self.total_tensor_count
        ):
            raise ValueError("classification accounting does not equal tensor total")
        return self


class KimiK3GGUFOntologyInventory(StrictModel):
    inventory_schema: Literal["omiv.kimi-k3-gguf-ontology-inventory.v1"] = ONTOLOGY_INVENTORY_SCHEMA
    model_pack: Literal["kimi-k3"]
    model_pack_digest: str = Field(pattern=SHA256_PATTERN)
    ontology_policy: KimiK3GGUFOntologyPolicy
    ontology_policy_digest: str = Field(pattern=SHA256_PATTERN)
    source_split_inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    source_split_schema: Literal["omiv.remote-split-gguf-inventory.v1"]
    repository: RepositoryIdentity
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    split_shard_count: int = Field(ge=1)
    split_tensor_count: int = Field(ge=0)
    architecture_metadata: ArchitectureMetadataSummary
    census: TensorNameCensus
    schedule: ScheduleSummary
    family_summaries: list[TensorFamilySummary]
    layer_summaries: list[LayerOntologySummary]
    packed_experts: PackedExpertSummary
    shared_experts: SharedExpertSummary
    g_proj: GProjSummary
    attention_residual: AttentionResidualSummary
    classification: ClassificationAccounting
    findings: list[RemoteFinding]

    @model_validator(mode="after")
    def consistent(self) -> KimiK3GGUFOntologyInventory:
        if self.ontology_policy_digest != self.ontology_policy.digest:
            raise ValueError("ontology policy digest mismatch")
        if self.split_tensor_count != self.census.total_tensor_count:
            raise ValueError("census total does not match split tensor count")
        if self.classification.total_tensor_count != self.split_tensor_count:
            raise ValueError("classification total does not match split tensor count")
        if self.census.unique_tensor_count != self.split_tensor_count:
            raise ValueError("source split tensor names are not unique")
        family_ids = [item.family_id for item in self.family_summaries]
        if family_ids != sorted(family_ids) or len(family_ids) != len(set(family_ids)):
            raise ValueError("family summaries must be unique and sorted")
        layer_ids = [item.layer_id for item in self.layer_summaries]
        if layer_ids != sorted(layer_ids) or len(layer_ids) != len(set(layer_ids)):
            raise ValueError("layer summaries must be unique and sorted")
        if self.findings != build_ontology_findings(self):
            raise ValueError("ontology findings do not reconstruct from inventory")
        return self


class KimiK3GGUFOntologyInventoryEnvelope(StrictModel):
    inventory: KimiK3GGUFOntologyInventory
    integrity: Integrity


class KimiK3GGUFOntologyReport(StrictModel):
    report_schema: Literal["omiv.kimi-k3-gguf-ontology-report.v1"] = ONTOLOGY_REPORT_SCHEMA
    execution: ReportExecution
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    inventory: KimiK3GGUFOntologyInventory
    findings: list[RemoteFinding]
    limitations: list[str]

    @model_validator(mode="after")
    def consistent(self) -> KimiK3GGUFOntologyReport:
        if self.inventory_sha256 != canonical_sha256(self.inventory.model_dump(mode="json")):
            raise ValueError("ontology report inventory digest mismatch")
        if self.findings != build_ontology_findings(self.inventory):
            raise ValueError("ontology report findings do not reconstruct")
        expected_result = (
            RemoteResult.FAIL
            if any(item.status == RemoteResult.FAIL for item in self.findings)
            else RemoteResult.WARN
            if any(item.status == RemoteResult.WARN for item in self.findings)
            else RemoteResult.PASS
        )
        expected_execution = ReportExecution(
            result=expected_result,
            exit_code=1 if expected_result == RemoteResult.FAIL else 0,
        )
        if self.execution != expected_execution:
            raise ValueError("ontology report execution does not reconstruct")
        return self


class KimiK3GGUFOntologyReportEnvelope(StrictModel):
    report: KimiK3GGUFOntologyReport
    integrity: Integrity


def _finding(
    rule_id: str,
    status: RemoteResult,
    message: str,
    evidence: dict[str, object],
) -> RemoteFinding:
    from omiv.remote.models import RemoteSeverity

    severity = {
        RemoteResult.PASS: RemoteSeverity.INFO,
        RemoteResult.WARN: RemoteSeverity.WARNING,
        RemoteResult.FAIL: RemoteSeverity.ERROR,
    }[status]
    return RemoteFinding(
        rule_id=rule_id,
        severity=severity,
        status=status,
        message=message,
        evidence=cast(dict[str, JsonValue], evidence),
    )


def build_ontology_findings(
    inventory: KimiK3GGUFOntologyInventory,
) -> list[RemoteFinding]:
    families = {item.family_id: item for item in inventory.family_summaries}
    attention_families = [
        item
        for item in inventory.family_summaries
        if item.module in {"attention", "kda_attention", "mla_attention", "g_proj"}
    ]
    packed = inventory.packed_experts
    shared = inventory.shared_experts
    schedule = inventory.schedule
    architecture_ok = (
        inventory.architecture_metadata.architecture_identifier
        == inventory.ontology_policy.expected_architecture
        and not inventory.architecture_metadata.required_failures
    )
    layer_ok = not schedule.missing_layer_ids and not schedule.unexpected_layer_ids
    attention_schedule_ok = (
        not schedule.missing_kda_layer_ids
        and not schedule.unexpected_kda_layer_ids
        and not schedule.missing_mla_layer_ids
        and not schedule.unexpected_mla_layer_ids
        and not schedule.attention_overlap_layer_ids
    )
    dense_moe_ok = all(
        item.ffn_kind
        == (
            "dense"
            if item.layer_id in inventory.ontology_policy.expected_dense_layer_ids
            else "moe"
        )
        and not item.missing_family_ids
        and not item.unexpected_family_ids
        for item in inventory.layer_summaries
    )
    attention_ok = all(
        item.coverage_valid and item.shape_valid and item.type_valid for item in attention_families
    )
    packed_ok = (
        not packed.missing_layer_ids
        and not packed.duplicate_components
        and packed.shape_valid
        and packed.type_valid
    )
    expert_count_ok = (
        packed.structurally_encoded_expert_counts
        == [inventory.ontology_policy.expected_expert_count]
        and packed.metadata_expert_count == inventory.ontology_policy.expected_expert_count
    )
    shared_ok = (
        not shared.missing_layer_ids
        and not shared.unexpected_layer_ids
        and not shared.duplicate_components
        and shared.shape_valid
        and shared.type_valid
    )
    g_proj_ok = (
        not inventory.g_proj.missing_layer_ids
        and not inventory.g_proj.duplicate_layer_ids
        and inventory.g_proj.shape_valid
        and inventory.g_proj.type_valid
    )
    residual_ok = (
        not inventory.attention_residual.missing_components
        and inventory.attention_residual.metadata_block_size
        == inventory.attention_residual.expected_block_size
        and inventory.attention_residual.shape_valid
        and inventory.attention_residual.type_valid
    )
    shapes_ok = all(item.shape_valid for item in inventory.family_summaries)
    types_ok = all(item.type_valid for item in inventory.family_summaries)
    accounting_ok = (
        inventory.classification.classified_count == inventory.split_tensor_count
        and inventory.classification.intentionally_unclassified_count == 0
        and inventory.classification.invalid_count == 0
        and inventory.classification.duplicate_classification_count == 0
    )
    linkage_ok = (
        inventory.split_tensor_count == inventory.census.total_tensor_count
        and inventory.split_shard_count == len(inventory.census.tensor_count_by_shard)
        and len(inventory.repository.resolved_revision) == 40
    )
    deterministic_ok = (
        inventory.ontology_policy_digest == inventory.ontology_policy.digest
        and sorted(families) == list(families)
    )

    rows: list[tuple[str, bool, str, dict[str, object]]] = [
        (
            "KIMIGGUF-001",
            architecture_ok,
            "Architecture identifier and required metadata are valid.",
            {
                "architecture": inventory.architecture_metadata.architecture_identifier,
                "required_failures": inventory.architecture_metadata.required_failures,
            },
        ),
        (
            "KIMIGGUF-002",
            layer_ok,
            "The target layer set is complete.",
            {
                "observed": schedule.observed_layer_ids,
                "missing": schedule.missing_layer_ids,
                "unexpected": schedule.unexpected_layer_ids,
            },
        ),
        (
            "KIMIGGUF-003",
            attention_schedule_ok,
            "The KDA and MLA schedules are exact.",
            {
                "kda_count": len(schedule.kda_layer_ids),
                "mla_count": len(schedule.mla_layer_ids),
                "missing_kda": schedule.missing_kda_layer_ids,
                "missing_mla": schedule.missing_mla_layer_ids,
            },
        ),
        (
            "KIMIGGUF-004",
            dense_moe_ok,
            "The dense and MoE schedules are structurally complete.",
            {
                "dense_layers": schedule.dense_layer_ids,
                "moe_layer_count": len(schedule.moe_layer_ids),
            },
        ),
        (
            "KIMIGGUF-005",
            attention_ok,
            "Required target attention families are complete.",
            {"family_count": len(attention_families)},
        ),
        (
            "KIMIGGUF-006",
            packed_ok,
            "Packed routed-expert families are complete and consistent.",
            {"families": packed.family_ids, "missing_layers": packed.missing_layer_ids},
        ),
        (
            "KIMIGGUF-007",
            expert_count_ok,
            "Packed shapes and metadata encode the expected expert count.",
            {
                "shape_counts": packed.structurally_encoded_expert_counts,
                "metadata_count": packed.metadata_expert_count,
            },
        ),
        (
            "KIMIGGUF-008",
            shared_ok,
            "Shared-expert families are complete and consistent.",
            {"families": shared.family_ids, "missing_layers": shared.missing_layer_ids},
        ),
        (
            "KIMIGGUF-009",
            g_proj_ok,
            "The physical KDA/MLA g_proj representations cover all layers.",
            {
                "physical_families": inventory.g_proj.physical_family_ids,
                "missing_layers": inventory.g_proj.missing_layer_ids,
            },
        ),
        (
            "KIMIGGUF-010",
            residual_ok,
            "Fused Attention Residual score tensors are complete.",
            {
                "block_size": inventory.attention_residual.metadata_block_size,
                "missing_components": inventory.attention_residual.missing_components,
            },
        ),
        (
            "KIMIGGUF-011",
            shapes_ok,
            "Descriptor shapes satisfy target-side family rules.",
            {
                "invalid_families": [
                    item.family_id for item in inventory.family_summaries if not item.shape_valid
                ]
            },
        ),
        (
            "KIMIGGUF-012",
            types_ok,
            "GGML type placement satisfies the recorded family policy.",
            {
                "invalid_families": [
                    item.family_id for item in inventory.family_summaries if not item.type_valid
                ]
            },
        ),
        (
            "KIMIGGUF-013",
            accounting_ok,
            "Every target descriptor has exactly one accounting category.",
            {
                "classified": inventory.classification.classified_count,
                "unclassified": inventory.classification.intentionally_unclassified_count,
                "invalid": inventory.classification.invalid_count,
                "duplicate_classification": inventory.classification.duplicate_classification_count,
            },
        ),
        (
            "KIMIGGUF-014",
            linkage_ok,
            "The verified split inventory linkage is internally consistent.",
            {
                "source_split_inventory_sha256": inventory.source_split_inventory_sha256,
                "snapshot_sha256": inventory.snapshot_sha256,
                "resolved_revision": inventory.repository.resolved_revision,
            },
        ),
        (
            "KIMIGGUF-015",
            deterministic_ok,
            "The ontology inventory uses canonical ordering and policies.",
            {
                "ontology_policy_digest": inventory.ontology_policy_digest,
                "classification_digest": inventory.census.classified_assignment_sha256,
            },
        ),
    ]
    return [
        _finding(rule_id, RemoteResult.PASS if passed else RemoteResult.FAIL, message, evidence)
        for rule_id, passed, message, evidence in rows
    ]
