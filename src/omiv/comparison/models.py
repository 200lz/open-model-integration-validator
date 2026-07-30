"""Strict schemas for cross-artifact structural comparison evidence."""

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from omiv.models import StrictModel

COMPARISON_SCHEMA = "omiv.model-artifact-structural-comparison.v1"
COMPARISON_REPORT_SCHEMA = "omiv.model-artifact-structural-comparison-report.v1"
COMPARISON_POLICY_SCHEMA = "omiv.structural-comparison-policy.v1"
COMPARISON_PROFILE_POLICY_SCHEMA = "omiv.structural-comparison-profile-policy.v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ComparisonValueStatus(StrEnum):
    EQUAL = "equal"
    DIFFERENT_ALLOWED = "different_allowed"
    DIFFERENT_UNEXPECTED = "different_unexpected"
    MISSING_BASELINE = "missing_baseline"
    MISSING_CANDIDATE = "missing_candidate"
    INFORMATIONAL = "informational"
    UNAVAILABLE = "unavailable"


class EvidenceBoundaryStatus(StrEnum):
    CHECKED = "checked"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    NOT_CHECKED = "not_checked"


class TypeTransitionState(StrEnum):
    UNCHANGED = "unchanged"
    PRECISION_INCREASED = "precision_increased"
    PRECISION_DECREASED = "precision_decreased"
    QUANTIZATION_FAMILY_CHANGED = "quantization_family_changed"
    KEPT_UNQUANTIZED = "kept_unquantized"
    UNEXPECTED_UNQUANTIZED = "unexpected_unquantized"
    UNSUPPORTED = "unsupported"
    INCOMPARABLE = "incomparable"


class OverallComparisonResult(StrEnum):
    STRUCTURALLY_EQUIVALENT_WITH_QUANTIZATION_DIFFERENCES = (
        "STRUCTURALLY_EQUIVALENT_WITH_QUANTIZATION_DIFFERENCES"
    )
    STRUCTURAL_EQUIVALENCE_WITH_LIMITATIONS = "STRUCTURAL_EQUIVALENCE_WITH_LIMITATIONS"
    STRUCTURALLY_DIFFERENT = "STRUCTURALLY_DIFFERENT"
    INCOMPARABLE = "INCOMPARABLE"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"


class ComparisonProfileOutcome(StrEnum):
    SATISFIED = "SATISFIED"
    SATISFIED_WITH_WARNINGS = "SATISFIED_WITH_WARNINGS"
    NOT_SATISFIED = "NOT_SATISFIED"


class IdentityPolicyClass(StrEnum):
    REQUIRED_EQUAL = "required_equal"
    ALLOWED_DIFFERENT = "allowed_different"
    INFORMATIONAL = "informational"
    INCOMPARABLE = "incomparable"


class ComparisonSubject(StrictModel):
    role: Literal["baseline", "candidate"]
    model_family: str
    variant: str
    provider: str
    repository: str
    requested_revision: str
    resolved_revision: str
    validation_inventory_digest: str = Field(pattern=SHA256_PATTERN)
    split_inventory_digest: str = Field(pattern=SHA256_PATTERN)
    ontology_inventory_digest: str = Field(pattern=SHA256_PATTERN)
    mapping_inventory_digest: str = Field(pattern=SHA256_PATTERN)


class IdentityFieldResult(StrictModel):
    field: str
    policy_class: IdentityPolicyClass
    baseline_value: JsonValue
    candidate_value: JsonValue
    status: ComparisonValueStatus


class StructuralComparisonPolicy(StrictModel):
    schema_id: Literal["omiv.structural-comparison-policy.v1"] = (
        "omiv.structural-comparison-policy.v1"
    )
    policy_id: str
    policy_version: int = Field(ge=1)
    identity_classes: dict[str, IdentityPolicyClass]
    required_normalized_shape_equality: bool
    require_sensitive_f32_unchanged: bool
    allow_quantized_matrix_type_change: bool
    allowed_quantized_target_types: list[str]
    family_allowed_target_types: dict[str, list[str]]
    allow_shard_layout_change: bool
    maximum_difference_examples: int = Field(ge=1)
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class ComparisonProfile(StrictModel):
    name: str
    required_controls: list[str]
    warning_controls: list[str]
    required_evidence_checked: list[str]


class ComparisonProfilePolicy(StrictModel):
    schema_id: Literal["omiv.structural-comparison-profile-policy.v1"] = (
        "omiv.structural-comparison-profile-policy.v1"
    )
    profiles: list[ComparisonProfile]
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class ComparisonProfileResult(StrictModel):
    profile_name: str
    outcome: ComparisonProfileOutcome
    satisfied: bool
    warning_controls: list[str]
    failed_controls: list[str]


class RepositoryComparison(StrictModel):
    same_provider: bool
    same_repository: bool
    same_immutable_revision: bool
    revision_status: ComparisonValueStatus
    baseline_shards: int = Field(ge=1)
    candidate_shards: int = Field(ge=1)
    shard_layout_status: ComparisonValueStatus
    baseline_total_bytes: int = Field(ge=0)
    candidate_total_bytes: int = Field(ge=0)
    ratio_numerator_reduced: int = Field(ge=0)
    ratio_denominator_reduced: int = Field(ge=1)
    deterministic_decimal: str
    baseline_header_bytes: int = Field(ge=0)
    candidate_header_bytes: int = Field(ge=0)
    baseline_range_requests: int = Field(ge=0)
    candidate_range_requests: int = Field(ge=0)
    baseline_metadata_only_shards: int = Field(ge=0)
    candidate_metadata_only_shards: int = Field(ge=0)
    baseline_tensor_bearing_shards: int = Field(ge=0)
    candidate_tensor_bearing_shards: int = Field(ge=0)
    baseline_payload_bytes_accepted: int = Field(ge=0)
    candidate_payload_bytes_accepted: int = Field(ge=0)


class MetadataDifference(StrictModel):
    key: str
    category: str
    status: ComparisonValueStatus
    baseline_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    candidate_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)


class MetadataComparison(StrictModel):
    compared_key_count: int = Field(ge=0)
    equal_count: int = Field(ge=0)
    different_allowed_count: int = Field(ge=0)
    different_unexpected_count: int = Field(ge=0)
    missing_baseline_count: int = Field(ge=0)
    missing_candidate_count: int = Field(ge=0)
    difference_digest: str = Field(pattern=SHA256_PATTERN)
    differences: list[MetadataDifference]


class TensorIdentityComparison(StrictModel):
    baseline_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    matched_count: int = Field(ge=0)
    baseline_only_count: int = Field(ge=0)
    candidate_only_count: int = Field(ge=0)
    duplicate_baseline_count: int = Field(ge=0)
    duplicate_candidate_count: int = Field(ge=0)
    baseline_only_digest: str = Field(pattern=SHA256_PATTERN)
    candidate_only_digest: str = Field(pattern=SHA256_PATTERN)
    baseline_only_examples: list[str]
    candidate_only_examples: list[str]
    family_counts_equal: bool
    layer_coverage_equal: bool
    component_coverage_equal: bool


class ShapeComparison(StrictModel):
    matched_count: int = Field(ge=0)
    normalized_shape_equal_count: int = Field(ge=0)
    physical_shape_equal_count: int = Field(ge=0)
    physical_different_logically_equal_count: int = Field(ge=0)
    incompatible_count: int = Field(ge=0)
    unavailable_count: int = Field(ge=0)
    difference_digest: str = Field(pattern=SHA256_PATTERN)
    incompatible_examples: list[str]


class FamilyTypeTransition(StrictModel):
    family_id: str
    baseline_type: str
    candidate_type: str
    state: TypeTransitionState
    allowed: bool
    count: int = Field(ge=1)
    policy_rule: str
    evidence_limitation: str


class TypeTransitionComparison(StrictModel):
    matched_count: int = Field(ge=0)
    state_counts: dict[TypeTransitionState, int]
    allowed_count: int = Field(ge=0)
    disallowed_count: int = Field(ge=0)
    transition_digest: str = Field(pattern=SHA256_PATTERN)
    family_transitions: list[FamilyTypeTransition]


class EncodedSpanComparison(StrictModel):
    baseline_total_encoded_bytes: int = Field(ge=0)
    candidate_total_encoded_bytes: int = Field(ge=0)
    ratio_numerator: int = Field(ge=0)
    ratio_denominator: int = Field(ge=1)
    baseline_bounded_count: int = Field(ge=0)
    candidate_bounded_count: int = Field(ge=0)
    baseline_overlap_count: int = Field(ge=0)
    candidate_overlap_count: int = Field(ge=0)
    family_totals_digest: str = Field(pattern=SHA256_PATTERN)
    family_totals: list[dict[str, JsonValue]]


class OntologyComparison(StrictModel):
    architecture_equal: bool
    layer_schedule_equal: bool
    family_set_equal: bool
    family_coverage_equal: bool
    classification_accounting_equal: bool
    normalized_shape_signatures_equal: bool
    baseline_type_valid: bool
    candidate_type_valid_under_native_policy: bool
    structure_equivalent: bool
    difference_digest: str = Field(pattern=SHA256_PATTERN)


class MappingComparison(StrictModel):
    same_source_inventory: bool
    source_accounting_equal: bool
    target_accounting_structure_equal: bool
    mapping_rule_identities_equal: bool
    routed_cardinality_equal: bool
    shared_mapping_equal: bool
    direct_mapping_equal: bool
    fused_mapping_equal: bool
    logical_realization_equal: bool
    converter_revision_equal: bool
    duplicate_and_ambiguity_counts_equal: bool
    structure_equivalent: bool
    difference_digest: str = Field(pattern=SHA256_PATTERN)


class ValidationComparison(StrictModel):
    evidence_stage_statuses_equal: bool
    acceptance_profile_outcomes_equal: bool
    unavailable_stages_equal: bool
    not_checked_stages_equal: bool
    model_pack_identity_equal: bool
    evidence_graphs_independently_valid: bool
    baseline_artifact_count: int = Field(ge=0)
    candidate_artifact_count: int = Field(ge=0)


class ComparisonFinding(StrictModel):
    finding_id: str
    status: Literal["PASS", "WARN", "FAIL", "AVAILABLE", "UNAVAILABLE", "NOT_CHECKED"]
    summary: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class ComparisonArtifact(StrictModel):
    role: str
    schema_id: str
    relative_path: str
    digest: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)
    required: bool
    verification_command: str

    @model_validator(mode="after")
    def safe_relative_path(self) -> "ComparisonArtifact":
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
            raise ValueError("comparison artifact path must be repository-relative POSIX")
        return self


class StructuralComparisonInventory(StrictModel):
    schema_id: Literal["omiv.model-artifact-structural-comparison.v1"] = (
        "omiv.model-artifact-structural-comparison.v1"
    )
    baseline: ComparisonSubject
    candidate: ComparisonSubject
    comparison_direction: Literal["baseline_to_candidate"] = "baseline_to_candidate"
    policy: StructuralComparisonPolicy
    profile_policy: ComparisonProfilePolicy
    identity_comparison: list[IdentityFieldResult]
    repository_comparison: RepositoryComparison
    metadata_comparison: MetadataComparison
    tensor_identity_comparison: TensorIdentityComparison
    shape_comparison: ShapeComparison
    type_transition_comparison: TypeTransitionComparison
    encoded_span_comparison: EncodedSpanComparison
    ontology_comparison: OntologyComparison
    mapping_comparison: MappingComparison
    validation_comparison: ValidationComparison
    controls: dict[str, bool]
    profile_results: list[ComparisonProfileResult]
    selected_profile: str
    overall_result: OverallComparisonResult
    cross_quantization_structural_comparison: EvidenceBoundaryStatus
    payload_equality: EvidenceBoundaryStatus
    quantization_numerical_fidelity: EvidenceBoundaryStatus
    tokenizer_parity: EvidenceBoundaryStatus
    runtime_parity: EvidenceBoundaryStatus
    limitations: list[str]
    findings: list[ComparisonFinding]
    artifact_index: list[ComparisonArtifact]
    artifact_index_digest: str = Field(pattern=SHA256_PATTERN)
    comparison_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def unique_and_ordered(self) -> "StructuralComparisonInventory":
        finding_ids = [item.finding_id for item in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("duplicate comparison finding")
        roles = [item.role for item in self.artifact_index]
        if len(roles) != len(set(roles)):
            raise ValueError("duplicate comparison artifact role")
        if self.payload_equality != EvidenceBoundaryStatus.NOT_CHECKED:
            raise ValueError("Phase 4F-7 payload equality must remain not_checked")
        if self.quantization_numerical_fidelity != EvidenceBoundaryStatus.NOT_CHECKED:
            raise ValueError("Phase 4F-7 quantization fidelity must remain not_checked")
        if self.runtime_parity != EvidenceBoundaryStatus.NOT_CHECKED:
            raise ValueError("Phase 4F-7 runtime parity must remain not_checked")
        return self


class StructuralComparisonReport(StrictModel):
    report_schema: Literal["omiv.model-artifact-structural-comparison-report.v1"] = (
        "omiv.model-artifact-structural-comparison-report.v1"
    )
    inventory: StructuralComparisonInventory
    executive_summary: dict[str, JsonValue]
    repository_summary: dict[str, JsonValue]
    metadata_summary: dict[str, JsonValue]
    tensor_summary: dict[str, JsonValue]
    type_transition_matrix: list[dict[str, JsonValue]]
    acceptance_profile_matrix: list[dict[str, JsonValue]]
    report_digest: str = Field(pattern=SHA256_PATTERN)


class StructuralComparisonReportEnvelope(StrictModel):
    report: StructuralComparisonReport
    integrity: dict[str, str]
