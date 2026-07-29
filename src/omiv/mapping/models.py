"""Strict typed models for semantic mapping manifests and reports."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ShapeRelation(StrEnum):
    IDENTICAL = "identical"
    REVERSE_DIMENSIONS = "reverse_dimensions"


class PayloadTransform(StrEnum):
    IDENTITY = "identity"


class MappingCardinality(StrEnum):
    ONE_TO_ONE = "one_to_one"


class SourceKind(StrEnum):
    PHYSICAL = "physical"
    LOGICAL = "logical"


class MaterializationPolicy(StrEnum):
    REQUIRED = "required"
    FORBIDDEN = "forbidden"


class MappingStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class MappingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class MappingResult(StrEnum):
    PASS = "pass"
    PASS_WITH_WARNINGS = "pass_with_warnings"
    FAIL = "fail"


class MappingSelector(StrictModel):
    canonical_identity: str = Field(min_length=1, max_length=256)
    tensor_name: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("canonical_identity", "tensor_name")
    @classmethod
    def safe_pattern(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(character in value for character in ("\\", "/", "\0", "*", "?", "[", "]")):
            raise ValueError("selector contains path or glob syntax")
        scrubbed = value.replace("{layer}", "")
        if "{" in scrubbed or "}" in scrubbed:
            raise ValueError("selector contains an invalid placeholder")
        return value


class LayerBinding(StrictModel):
    variable: Literal["layer"]
    range: tuple[int, int]

    @model_validator(mode="after")
    def valid_range(self) -> LayerBinding:
        start, end = self.range
        if start < 0 or end < start:
            raise ValueError("layer binding range must be nonnegative and ordered")
        if end - start + 1 > 1024:
            raise ValueError("layer binding exceeds maximum binding count 1024")
        return self


class IgnoredSource(StrictModel):
    selector: MappingSelector
    justification: str = Field(min_length=1, max_length=1000)


class MappingRule(StrictModel):
    rule_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    source: MappingSelector
    target: MappingSelector
    source_kind: SourceKind
    cardinality: MappingCardinality
    layer_binding: LayerBinding | None = None
    shape_relation: ShapeRelation
    payload_transform: PayloadTransform
    parameter: Literal["weight", "bias"]
    target_materialization: MaterializationPolicy | None = None
    physical_source: str | None = Field(default=None, min_length=1, max_length=256)
    payload_origin: Literal["unverified"] | None = None
    evidence_reference: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def coherent_rule(self) -> MappingRule:
        source_layer = "{layer}" in self.source.canonical_identity
        target_layer = "{layer}" in self.target.canonical_identity
        target_name_layer = (
            self.target.tensor_name is not None
            and "{layer}" in self.target.tensor_name
        )
        has_placeholder = source_layer or target_layer or target_name_layer
        if has_placeholder and self.layer_binding is None:
            raise ValueError("rule with {layer} requires layer_binding")
        if self.layer_binding is not None and (not source_layer or not target_layer):
            raise ValueError(
                "layer-bound rule requires {layer} in both canonical selectors"
            )
        if self.source_kind == SourceKind.LOGICAL:
            if self.target_materialization is None:
                raise ValueError("logical rule requires target_materialization")
            if self.physical_source is None:
                raise ValueError("logical rule requires physical_source")
            if self.payload_origin is None:
                raise ValueError("logical rule requires payload_origin")
        elif any(
            value is not None
            for value in (
                self.target_materialization,
                self.physical_source,
                self.payload_origin,
            )
        ):
            raise ValueError(
                "materialization, physical_source, and payload_origin are logical-only"
            )
        return self


class MappingManifest(StrictModel):
    mapping_schema: Literal["omiv.semantic-mapping.v1"]
    mapping_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$"
    )
    model_family: str = Field(min_length=1, max_length=64)
    source_format: Literal["huggingface-safetensors"]
    target_format: Literal["gguf"]
    description: str | None = Field(default=None, max_length=2000)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    source_assumptions: list[str] = Field(default_factory=list, max_length=100)
    target_assumptions: list[str] = Field(default_factory=list, max_length=100)
    require_complete_source_coverage: bool = True
    require_complete_target_coverage: bool = True
    ignored_sources: list[IgnoredSource] = Field(default_factory=list, max_length=100)
    rules: list[MappingRule] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_rule_ids(self) -> MappingManifest:
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("duplicate rule IDs")
        return self


class SemanticTensorDescriptor(StrictModel):
    exact_name: str
    canonical_identity: str | None
    classification: Literal["classified", "unclassified"]
    scope: Literal["model", "layer"] | None
    layer_id: int | None = Field(default=None, ge=0)
    module: str | None
    component: str | None
    parameter: Literal["weight", "bias"] | None
    source_kind: SourceKind
    materialized: bool
    shape: list[int]
    shape_order: Literal[
        "huggingface_safetensors", "gguf_on_disk_reader_tensor_shape", "logical"
    ]
    data_type: str | None
    physical_source_identity: str | None = None


class MappingResolution(StrictModel):
    rule_id: str
    layer_id: int | None
    source: SemanticTensorDescriptor
    target: SemanticTensorDescriptor
    shape_relation: ShapeRelation
    payload_transform: PayloadTransform
    parameter: Literal["weight", "bias"]


class MappingFinding(StrictModel):
    rule_id: str
    severity: MappingSeverity
    status: MappingStatus
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class MappingCoverage(StrictModel):
    physical_source_mapped: int = Field(ge=0)
    physical_source_total: int = Field(ge=0)
    logical_source_mapped: int = Field(ge=0)
    logical_source_total: int = Field(ge=0)
    target_explained: int = Field(ge=0)
    target_total: int = Field(ge=0)
    duplicate_source_count: int = Field(ge=0)
    duplicate_target_count: int = Field(ge=0)
    unmapped_source_count: int = Field(ge=0)
    unmapped_target_count: int = Field(ge=0)


class MappingValidationReport(StrictModel):
    findings: list[MappingFinding]
    resolutions: list[MappingResolution]
    coverage: MappingCoverage
    unverified_payload_relation_count: int = Field(ge=0)

    @property
    def passed(self) -> bool:
        return not any(finding.status == MappingStatus.FAIL for finding in self.findings)


class MappingReportTool(StrictModel):
    name: Literal["open-model-integration-validator"]
    version: str


class MappingReportExecution(StrictModel):
    result: MappingResult
    exit_code: Literal[0, 1]


class SourceReportProvenance(StrictModel):
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository: str | None
    revision: str | None
    physical_tensor_count: int = Field(ge=0)
    logical_tie_count: int = Field(ge=0)
    model_family: str


class TargetReportProvenance(StrictModel):
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    architecture: str
    model_name: str
    tensor_count: int = Field(ge=0)


class ManifestReportProvenance(StrictModel):
    mapping_id: str
    mapping_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mapping_schema: Literal["omiv.semantic-mapping.v1"]


class MappingReportSummary(StrictModel):
    pass_count: int = Field(ge=0)
    warn_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)
    physical_source_mapped: int = Field(ge=0)
    physical_source_total: int = Field(ge=0)
    logical_source_mapped: int = Field(ge=0)
    logical_source_total: int = Field(ge=0)
    target_explained: int = Field(ge=0)
    target_total: int = Field(ge=0)
    resolved_mapping_count: int = Field(ge=0)
    duplicate_source_count: int = Field(ge=0)
    duplicate_target_count: int = Field(ge=0)
    unmapped_source_count: int = Field(ge=0)
    unmapped_target_count: int = Field(ge=0)
    unverified_payload_relation_count: int = Field(ge=0)


class MappingReportPayload(StrictModel):
    report_schema: Literal["omiv.semantic-mapping-report.v1"]
    tool: MappingReportTool
    execution: MappingReportExecution
    source: SourceReportProvenance
    target: TargetReportProvenance
    mapping: ManifestReportProvenance
    summary: MappingReportSummary
    findings: list[MappingFinding]


class MappingReportIntegrity(StrictModel):
    canonicalization: Literal["omiv-json-v1"]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MappingReportEnvelope(StrictModel):
    report: MappingReportPayload
    integrity: MappingReportIntegrity
