"""Typed canonical inventory and validation result models."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class AttentionKind(StrEnum):
    KDA = "kda"
    MLA = "mla"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class FfnKind(StrEnum):
    DENSE = "dense"
    MOE = "moe"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class FindingStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceSummary(StrictModel):
    format: str
    record_count: int = Field(ge=0)
    source_sha256: str
    shard_count: int = Field(ge=0)
    shards: list[str]
    dtype_counts: dict[str, int]


class AttentionInventory(StrictModel):
    kind: AttentionKind
    observed_markers: list[str]
    g_proj_present: bool
    g_proj_observation_count: int = Field(ge=0)


class ExpertCoverage(StrictModel):
    complete_expert_count: int = Field(ge=0)
    incomplete_experts: dict[str, list[str]]


class FfnInventory(StrictModel):
    kind: FfnKind
    dense_components: list[str]
    routed_expert_ids: list[int]
    expert_component_coverage: ExpertCoverage
    shared_expert_components: list[str]


class LayerInventory(StrictModel):
    id: int = Field(ge=0)
    attention: AttentionInventory
    ffn: FfnInventory
    attention_residual_components: list[str]


class Diagnostic(StrictModel):
    code: str
    severity: Severity
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class LayerExpertPair(StrictModel):
    layer_id: int = Field(ge=0)
    expert_id: int = Field(ge=0)


class DescriptorGroup(StrictModel):
    dtype: str
    shape: list[int]
    observation_count: int = Field(ge=1)
    layer_ids: list[int] = Field(default_factory=list)
    layer_expert_pair_examples: list[LayerExpertPair] = Field(default_factory=list)


class DescriptorSummary(StrictModel):
    observation_count: int = Field(ge=0)
    descriptor_groups: list[DescriptorGroup]


class SemanticDescriptorInventory(StrictModel):
    g_proj: DescriptorSummary
    shared_expert_components: dict[str, DescriptorSummary]
    attention_residual_components: dict[str, DescriptorSummary]
    routed_expert_components: dict[str, DescriptorSummary]
    model_attention_residual_components: dict[str, DescriptorSummary]


class UnclassifiedGroup(StrictModel):
    key: str
    record_count: int = Field(ge=1)
    examples: list[str]


class CompactUnclassifiedGroups(StrictModel):
    record_count: int = Field(ge=0)
    group_count: int = Field(ge=0)
    emitted_group_count: int = Field(ge=0)
    omitted_group_count: int = Field(ge=0)
    groups: list[UnclassifiedGroup]


class TensorClassificationSummary(StrictModel):
    total_tensor_records: int = Field(ge=0)
    semantically_classified_records: int = Field(ge=0)
    unclassified_records: int = Field(ge=0)
    duplicate_exact_tensor_names: int = Field(ge=0)
    duplicate_examples: list[str]
    group_cap: int = Field(ge=1)
    examples_per_group_cap: int = Field(ge=1)
    unknown_layer_local: CompactUnclassifiedGroups
    unknown_model_namespaces: CompactUnclassifiedGroups


class ModelInventory(StrictModel):
    schema_version: int
    source: SourceSummary
    observed_layer_ids: list[int]
    layers: list[LayerInventory]
    model_attention_residual_components: list[str]
    semantic_descriptors: SemanticDescriptorInventory
    tensor_classification: TensorClassificationSummary
    diagnostics: list[Diagnostic]


class ValidationFinding(StrictModel):
    rule_id: str
    severity: Severity
    status: FindingStatus
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class ValidationReport(StrictModel):
    findings: list[ValidationFinding]

    @property
    def passed(self) -> bool:
        return not any(finding.status == FindingStatus.FAIL for finding in self.findings)


def json_compatible(value: Any) -> JsonValue:
    """Narrow an already JSON-compatible value for static type checkers."""
    return value  # type: ignore[no-any-return]
