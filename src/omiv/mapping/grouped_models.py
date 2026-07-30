"""Strict, compact models for grouped semantic mappings (Phase 4F-5)."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256


class GroupRelation(StrEnum):
    ONE_TO_ONE = "one_to_one"
    MANY_TO_ONE_PACKED = "many_to_one_packed"
    ONE_TO_MANY_SPLIT = "one_to_many_split"
    MANY_TO_MANY_TRANSFORM = "many_to_many_transform"
    FUSED_TARGET = "fused_target"
    LOGICAL_REALIZATION = "logical_realization"
    BACKEND_FALLBACK = "backend_fallback"
    FORMAT_ALIAS = "format_alias"
    SYNTHESIZED = "synthesized"
    INTENTIONALLY_EXCLUDED = "intentionally_excluded"
    UNSUPPORTED = "unsupported"


class EvidenceLevel(StrEnum):
    IDENTITY_ONLY = "identity_only"
    DESCRIPTOR_STRUCTURAL = "descriptor_structural"
    CONVERTER_CODE_SUPPORTED = "converter_code_supported"
    PROVENANCE_LINKED = "provenance_linked"
    PAYLOAD_SAMPLED = "payload_sampled"
    PAYLOAD_COMPLETE = "payload_complete"
    RUNTIME_VERIFIED = "runtime_verified"


class PayloadStatus(StrEnum):
    NOT_CHECKED = "not_checked"


class ProvenanceStatus(StrEnum):
    UNAVAILABLE = "unavailable"


class TransitionStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class SourceAccountingState(StrEnum):
    DIRECTLY_MAPPED = "directly_mapped"
    PACKED_GROUP_MEMBER = "packed_group_member"
    FUSED_MAPPING_MEMBER = "fused_mapping_member"
    LOGICAL_REALIZATION_SOURCE = "logical_realization_source"
    SOURCE_ONLY_AUXILIARY = "source_only_auxiliary"
    INTENTIONALLY_EXCLUDED = "intentionally_excluded"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"
    UNCLASSIFIED = "unclassified"


class TargetAccountingState(StrEnum):
    DIRECTLY_REALIZED = "directly_realized"
    PACKED_GROUP_TARGET = "packed_group_target"
    FUSED_TARGET = "fused_target"
    LOGICAL_REALIZATION_TARGET = "logical_realization_target"
    TARGET_ONLY_AUXILIARY = "target_only_auxiliary"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"
    UNCLASSIFIED = "unclassified"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class MappingRule(StrictModel):
    rule_id: str
    source_family: str
    target_family: str
    relation: GroupRelation
    grouping_key: list[str] = Field(default_factory=list)
    layer_scope: str
    source_name_pattern: str
    target_name_patterns: list[str]
    member_ordering: str = "canonical"
    source_cardinality: int | None = None
    target_cardinality: int | None = None
    shape_relation: str = "family_policy"
    axis_relation: str = "family_policy"
    source_dtype: str
    allowed_target_types: list[str]
    converter_operation: str
    evidence_source: str
    evidence_level: EvidenceLevel = EvidenceLevel.CONVERTER_CODE_SUPPORTED
    payload_status: PayloadStatus = PayloadStatus.NOT_CHECKED
    authorized_target_count: int = 1


class MappingResult(StrictModel):
    rule_id: str
    relation: GroupRelation
    source_group_key: list[Any] = Field(default_factory=list)
    source_member_count: int
    source_physical_count: int
    target_count: int
    target_names: list[str] = Field(default_factory=list)
    source_name_examples: list[str] = Field(default_factory=list)
    member_set_digest: str
    source_shape_signature: list[list[int]] = Field(default_factory=list)
    target_shape: list[int] | None = None
    target_shapes: list[list[int]] = Field(default_factory=list)
    axis_relation: str
    shape_relation: str
    source_dtypes: list[str]
    target_ggml_types: list[str]
    allowed_target_types: list[str]
    type_transition_status: TransitionStatus
    converter_operation: str
    evidence_level: EvidenceLevel
    payload_status: PayloadStatus = PayloadStatus.NOT_CHECKED
    status: Literal["PASS", "WARN", "FAIL", "NOT_CHECKED"] = "PASS"
    detail: str | None = None


class MappingFinding(StrictModel):
    code: str
    status: Literal["PASS", "WARN", "FAIL", "NOT_CHECKED", "UNAVAILABLE"]
    message: str


class MappingPolicy(StrictModel):
    policy_schema: Literal["omiv.kimi-k3-semantic-mapping-policy.v1"] = (
        "omiv.kimi-k3-semantic-mapping-policy.v1"
    )
    source_model_pack: str
    target_model_pack: str
    converter_revision: str
    converter_evidence_role: str
    rules: list[MappingRule]
    exclusion_rules: list[MappingRule] = Field(default_factory=list)
    artifact_specific_provenance: ProvenanceStatus = ProvenanceStatus.UNAVAILABLE
    payload_status: PayloadStatus = PayloadStatus.NOT_CHECKED
    unresolved_policy: str = "explicit_accounting"

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    @model_validator(mode="after")
    def non_overlapping(self) -> MappingPolicy:
        rule_ids = [rule.rule_id for rule in [*self.rules, *self.exclusion_rules]]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("mapping policy rule IDs must be unique")
        seen_targets: dict[str, str] = {}
        seen_sources: dict[tuple[str, str], str] = {}
        for rule in self.rules:
            for target in rule.target_name_patterns:
                previous = seen_targets.setdefault(target, rule.rule_id)
                if previous != rule.rule_id:
                    raise ValueError(
                        f"mapping policy target pattern {target!r} overlaps "
                        f"{previous!r} and {rule.rule_id!r}"
                    )
            source_key = (rule.source_name_pattern, rule.layer_scope)
            previous_source = seen_sources.setdefault(source_key, rule.rule_id)
            if previous_source != rule.rule_id:
                raise ValueError(
                    f"mapping policy source pattern/scope overlaps "
                    f"{previous_source!r} and {rule.rule_id!r}"
                )
        return self


class MappingInventory(StrictModel):
    inventory_schema: Literal["omiv.semantic-mapping-inventory.v3"] = Field(
        "omiv.semantic-mapping-inventory.v3", alias="schema"
    )
    source: dict[str, Any]
    target: dict[str, Any]
    model_pack: dict[str, Any]
    mapping_policy_digest: str
    converter_evidence_revision: str
    source_accounting: dict[str, Any]
    target_accounting: dict[str, Any]
    mapping_results: list[MappingResult]
    coverage: dict[str, Any]
    kimi_summary: dict[str, Any]
    findings: list[MappingFinding]
    inventory_digest: str | None = None

    @model_validator(mode="after")
    def accounting_is_complete(self) -> MappingInventory:
        source_states = self.source_accounting.get("states", {})
        target_states = self.target_accounting.get("states", {})
        if sum(source_states.values()) != self.source_accounting.get("physical_records"):
            raise ValueError("source accounting states do not reconstruct physical total")
        if sum(target_states.values()) != self.target_accounting.get("physical_records"):
            raise ValueError("target accounting states do not reconstruct physical total")
        if self.source_accounting.get("accounted") != self.source_accounting.get(
            "physical_records"
        ):
            raise ValueError("source accounting is incomplete")
        if self.target_accounting.get("accounted") != self.target_accounting.get(
            "physical_records"
        ):
            raise ValueError("target accounting is incomplete")
        capabilities = self.model_pack.get("capabilities", [])
        if "semantic_mapping" not in capabilities:
            raise ValueError("model pack lacks canonical semantic_mapping capability")
        duplicates = self.coverage.get("duplicates", {})
        if any(item.get("count") for item in duplicates.values()):
            raise ValueError("mapping inventory contains duplicate assignments")
        if self.coverage.get("ambiguities", {}).get("count"):
            raise ValueError("mapping inventory contains ambiguous assignments")
        result_identities: set[tuple[str, str, tuple[str, ...]]] = set()
        source_groups: set[tuple[str, str]] = set()
        target_names: set[str] = set()
        reconstructed_source: Counter[str] = Counter()
        reconstructed_target: Counter[str] = Counter()
        source_state_by_relation = {
            GroupRelation.ONE_TO_ONE: SourceAccountingState.DIRECTLY_MAPPED,
            GroupRelation.MANY_TO_ONE_PACKED: SourceAccountingState.PACKED_GROUP_MEMBER,
            GroupRelation.FUSED_TARGET: SourceAccountingState.FUSED_MAPPING_MEMBER,
            GroupRelation.LOGICAL_REALIZATION: SourceAccountingState.LOGICAL_REALIZATION_SOURCE,
            GroupRelation.ONE_TO_MANY_SPLIT: SourceAccountingState.LOGICAL_REALIZATION_SOURCE,
        }
        target_state_by_relation = {
            GroupRelation.ONE_TO_ONE: TargetAccountingState.DIRECTLY_REALIZED,
            GroupRelation.MANY_TO_ONE_PACKED: TargetAccountingState.PACKED_GROUP_TARGET,
            GroupRelation.FUSED_TARGET: TargetAccountingState.FUSED_TARGET,
            GroupRelation.LOGICAL_REALIZATION: TargetAccountingState.LOGICAL_REALIZATION_TARGET,
            GroupRelation.ONE_TO_MANY_SPLIT: TargetAccountingState.LOGICAL_REALIZATION_TARGET,
        }
        for result in self.mapping_results:
            group_key = canonical_sha256(result.source_group_key)
            result_identity = (result.rule_id, group_key, tuple(result.target_names))
            if result_identity in result_identities:
                raise ValueError("mapping results contain duplicate result identity")
            result_identities.add(result_identity)
            group_identity = (result.rule_id, group_key)
            if group_identity in source_groups:
                raise ValueError("mapping results contain duplicate source group")
            source_groups.add(group_identity)
            if len(result.target_names) != result.target_count:
                raise ValueError("mapping result target count does not match target names")
            if len(result.target_shapes) != result.target_count:
                raise ValueError("mapping result target count does not match target shapes")
            for target_name in result.target_names:
                if target_name in target_names:
                    raise ValueError("mapping results contain duplicate target assignment")
                target_names.add(target_name)
            if result.type_transition_status != TransitionStatus.PASS:
                raise ValueError("mapping result contains failed type transition")
            if not set(result.target_ggml_types) <= set(result.allowed_target_types):
                raise ValueError("mapping result target type is outside policy")
            source_accounting_state = source_state_by_relation.get(result.relation)
            target_accounting_state = target_state_by_relation.get(result.relation)
            if source_accounting_state is None or target_accounting_state is None:
                raise ValueError(f"mapping result relation is not operational: {result.relation}")
            reconstructed_source[source_accounting_state.value] += result.source_physical_count
            reconstructed_target[target_accounting_state.value] += result.target_count
        reconstructed_source[SourceAccountingState.SOURCE_ONLY_AUXILIARY.value] = int(
            self.source_accounting.get("source_only_auxiliary_records", 0)
        )
        for source_state in SourceAccountingState:
            if reconstructed_source[source_state.value] != source_states.get(source_state.value, 0):
                raise ValueError(
                    f"source accounting state {source_state.value!r} "
                    "is not backed by mapping results"
                )
        for target_state in TargetAccountingState:
            if reconstructed_target[target_state.value] != target_states.get(target_state.value, 0):
                raise ValueError(
                    f"target accounting state {target_state.value!r} "
                    "is not backed by mapping results"
                )
        return self


class MappingReport(StrictModel):
    report_schema: Literal["omiv.semantic-mapping-report.v3"] = "omiv.semantic-mapping-report.v3"
    inventory_digest: str
    source: dict[str, Any]
    target: dict[str, Any]
    model_pack: dict[str, Any]
    mapping_policy_digest: str
    converter_evidence_revision: str
    artifact_specific_provenance: ProvenanceStatus
    payload_status: PayloadStatus
    summary: dict[str, Any]
    findings: list[MappingFinding]

    @model_validator(mode="after")
    def linked_summary(self) -> MappingReport:
        if self.summary.get("source", {}).get("physical_records") != self.source.get(
            "physical_count"
        ):
            raise ValueError("report source linkage does not reconstruct")
        if self.summary.get("target", {}).get("physical_records") != self.target.get(
            "physical_count"
        ):
            raise ValueError("report target linkage does not reconstruct")
        if self.payload_status != PayloadStatus.NOT_CHECKED:
            raise ValueError("Phase 4F-5 payload status must remain not_checked")
        return self


class MappingEnvelope(StrictModel):
    report: MappingReport
    integrity: dict[str, str]
