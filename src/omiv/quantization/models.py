"""Strict canonical models for Phase 6C quantization fidelity evidence."""

from __future__ import annotations

import re
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    InvalidOperation,
    localcontext,
)
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.runtime.models import ProductSubject, ScopeContext

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
DECIMAL_PATTERN = r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:E-?[0-9]+)?$"
INPUT_DECIMAL_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
DECIMAL_PRECISION = 50
MAX_DECIMAL_INPUT_LENGTH = 768
MAX_DECIMAL_SIGNIFICANT_DIGITS = 100
MAX_DECIMAL_INPUT_ADJUSTED_EXPONENT = 308
MAX_DECIMAL_SCALE_ADJUSTED_EXPONENT = 128
MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT = 640
MAX_DECIMAL_OUTPUT_LENGTH = 768
MAX_TEXT = 1024
MAX_TENSORS = 100_000
MAX_LOGICAL_ELEMENTS_PER_TENSOR = 100_000_000
MAX_TOTAL_LOGICAL_ELEMENTS = 1_000_000_000
MAX_FINDINGS = 200_000
MAX_INDEX_ENTRIES = 140
ExplicitTime = Annotated[
    str,
    StringConstraints(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    ),
]


class QuantizationModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def canonical_decimal_strings(self) -> QuantizationModel:
        decimal_fields = {
            "scale",
            "value",
            "worst_metric_value",
            "minimum_tensor_coverage",
            "minimum_element_coverage",
            "minimum_byte_coverage",
            "minimum_parameter_coverage",
            "maximum_sampling_gap",
            "maximum_absolute_error",
            "maximum_mean_absolute_error",
            "maximum_rmse",
            "maximum_relative_l2_error",
            "minimum_cosine_similarity",
            "maximum_bias",
            "maximum_quantization_bound_rate",
        }

        def walk(value: Any, field_name: str | None = None) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    walk(child, key)
            elif isinstance(value, list):
                for child in value:
                    walk(child, field_name)
            elif (
                field_name in decimal_fields
                and isinstance(value, str)
                and value
                != _canonical_decimal_text(
                    value,
                    maximum_adjusted_exponent=(
                        MAX_DECIMAL_SCALE_ADJUSTED_EXPONENT
                        if field_name == "scale"
                        else MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT
                    ),
                )
            ):
                raise ValueError(f"{field_name} is not a canonical decimal string")

        walk(self.model_dump(mode="json", by_alias=True))
        return self


class ArtifactRole(StrEnum):
    SOURCE = "SOURCE"
    CANDIDATE = "CANDIDATE"


class ArtifactAvailability(StrEnum):
    EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE = "EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE"
    REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE = "REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE"
    REMOTE_NON_PAYLOAD_IDENTITY_ONLY = "REMOTE_NON_PAYLOAD_IDENTITY_ONLY"
    METADATA_IDENTITY_ONLY = "METADATA_IDENTITY_ONLY"
    DIGEST_REFERENCE_ONLY = "DIGEST_REFERENCE_ONLY"
    ARTIFACT_NOT_SUPPLIED = "ARTIFACT_NOT_SUPPLIED"
    IDENTITY_UNAVAILABLE = "IDENTITY_UNAVAILABLE"
    IDENTITY_INVALID = "IDENTITY_INVALID"


class RelationshipMode(StrEnum):
    SOURCE_TO_QUANTIZED_CANDIDATE = "SOURCE_TO_QUANTIZED_CANDIDATE"
    SOURCE_TO_REPACKED_CANDIDATE = "SOURCE_TO_REPACKED_CANDIDATE"
    SOURCE_TO_MIXED_PRECISION_CANDIDATE = "SOURCE_TO_MIXED_PRECISION_CANDIDATE"
    CANDIDATE_ONLY_WITH_DECLARED_SOURCE_REFERENCE = "CANDIDATE_ONLY_WITH_DECLARED_SOURCE_REFERENCE"
    RELATIONSHIP_UNAVAILABLE = "RELATIONSHIP_UNAVAILABLE"


class DeclarationProvenance(StrEnum):
    CALLER_DECLARED = "CALLER_DECLARED"
    SIGNED_TRANSFORMATION_ATTESTATION = "SIGNED_TRANSFORMATION_ATTESTATION"
    IMPORTED_PROVIDER_METADATA = "IMPORTED_PROVIDER_METADATA"
    OBSERVER_INFERRED_WITH_LIMITATIONS = "OBSERVER_INFERRED_WITH_LIMITATIONS"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class SchemeFamily(StrEnum):
    UNQUANTIZED = "UNQUANTIZED"
    UNIFORM_AFFINE_INTEGER = "UNIFORM_AFFINE_INTEGER"
    SYMMETRIC_INTEGER = "SYMMETRIC_INTEGER"
    ASYMMETRIC_INTEGER = "ASYMMETRIC_INTEGER"
    CODEBOOK = "CODEBOOK"
    BLOCKWISE_FLOAT = "BLOCKWISE_FLOAT"
    MIXED_PRECISION = "MIXED_PRECISION"
    OPAQUE_PROVIDER_FORMAT = "OPAQUE_PROVIDER_FORMAT"
    UNKNOWN = "UNKNOWN"


class NumericalCodec(StrEnum):
    UNQUANTIZED_IDENTITY = "UNQUANTIZED_IDENTITY"
    UNIFORM_AFFINE_INTEGER = "UNIFORM_AFFINE_INTEGER"
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"


class ObservationLevel(StrEnum):
    METADATA_ONLY = "METADATA_ONLY"
    FULL_TENSOR_VALUES = "FULL_TENSOR_VALUES"
    DETERMINISTIC_SAMPLE = "DETERMINISTIC_SAMPLE"
    EXTERNALLY_SUPPLIED_MEASUREMENT = "EXTERNALLY_SUPPLIED_MEASUREMENT"
    OPAQUE_FORMAT = "OPAQUE_FORMAT"
    NOT_OBSERVED = "NOT_OBSERVED"


class ParameterProvenance(StrEnum):
    OBSERVED_FROM_PAYLOAD = "OBSERVED_FROM_PAYLOAD"
    OBSERVED_FROM_FORMAT_METADATA = "OBSERVED_FROM_FORMAT_METADATA"
    IMPORTED_SIGNED_RECORD = "IMPORTED_SIGNED_RECORD"
    IMPORTED_UNSIGNED_RECORD = "IMPORTED_UNSIGNED_RECORD"
    CALLER_DECLARED = "CALLER_DECLARED"
    INFERRED_NON_AUTHORITATIVELY = "INFERRED_NON_AUTHORITATIVELY"
    UNAVAILABLE = "UNAVAILABLE"


class TensorRole(StrEnum):
    ABSENT_ROLE = "ABSENT_ROLE"
    OTHER_DECLARED = "OTHER_DECLARED"
    PRIMARY_WEIGHT = "PRIMARY_WEIGHT"
    MANDATORY_COMPANION = "MANDATORY_COMPANION"
    OPTIONAL_COMPANION = "OPTIONAL_COMPANION"
    QUANTIZATION_PARAMETER = "QUANTIZATION_PARAMETER"
    AUXILIARY_METADATA = "AUXILIARY_METADATA"


class CorrespondenceCardinality(StrEnum):
    ONE_TO_ONE = "ONE_TO_ONE"
    ONE_TO_MANY_DECLARED = "ONE_TO_MANY_DECLARED"
    MANY_TO_ONE_DECLARED = "MANY_TO_ONE_DECLARED"
    MANY_TO_MANY_DECLARED = "MANY_TO_MANY_DECLARED"
    UNMAPPED_SOURCE = "UNMAPPED_SOURCE"
    UNMAPPED_CANDIDATE = "UNMAPPED_CANDIDATE"
    AMBIGUOUS = "AMBIGUOUS"
    UNSUPPORTED = "UNSUPPORTED"


class MappingNumericalStatus(StrEnum):
    NUMERICALLY_EVALUABLE = "NUMERICALLY_EVALUABLE"
    MAPPING_STRUCTURALLY_AVAILABLE_NUMERICALLY_UNAVAILABLE = (
        "MAPPING_STRUCTURALLY_AVAILABLE_NUMERICALLY_UNAVAILABLE"
    )
    AMBIGUOUS = "AMBIGUOUS"
    NOT_MAPPED = "NOT_MAPPED"


class ExpectationScope(StrEnum):
    COMPLETE_DECLARED_ARTIFACT_SET = "COMPLETE_DECLARED_ARTIFACT_SET"
    COMPLETE_DECLARED_TENSOR_SET = "COMPLETE_DECLARED_TENSOR_SET"
    SELECTED_REQUIRED_TENSORS = "SELECTED_REQUIRED_TENSORS"
    SELECTED_REQUIRED_ROLES = "SELECTED_REQUIRED_ROLES"
    PARTIAL_REFERENCE_SET = "PARTIAL_REFERENCE_SET"
    DETERMINISTIC_SAMPLE_SCOPE = "DETERMINISTIC_SAMPLE_SCOPE"


class MetricState(StrEnum):
    AVAILABLE = "AVAILABLE"
    EXACT = "EXACT"
    UNDEFINED_ZERO_REFERENCE_NORM = "UNDEFINED_ZERO_REFERENCE_NORM"
    UNDEFINED_ZERO_VECTOR = "UNDEFINED_ZERO_VECTOR"
    NON_FINITE_INPUT = "NON_FINITE_INPUT"
    NOT_COMPUTED = "NOT_COMPUTED"
    INSUFFICIENT_COVERAGE = "INSUFFICIENT_COVERAGE"
    FORMAT_NOT_SUPPORTED = "FORMAT_NOT_SUPPORTED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID = "INVALID"


class StructuralStatus(StrEnum):
    STRUCTURALLY_CONSISTENT_FOR_SCOPE = "STRUCTURALLY_CONSISTENT_FOR_SCOPE"
    STRUCTURAL_MISMATCH = "STRUCTURAL_MISMATCH"
    STRUCTURAL_INFORMATION_INCOMPLETE = "STRUCTURAL_INFORMATION_INCOMPLETE"
    TENSOR_MAPPING_AMBIGUOUS = "TENSOR_MAPPING_AMBIGUOUS"
    QUANTIZATION_PARAMETERS_INCOMPLETE = "QUANTIZATION_PARAMETERS_INCOMPLETE"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class NumericalStatus(StrEnum):
    NUMERICALLY_EVALUATED_FOR_SCOPE = "NUMERICALLY_EVALUATED_FOR_SCOPE"
    SAMPLED_NUMERICALLY_EVALUATED = "SAMPLED_NUMERICALLY_EVALUATED"
    EXACT_FOR_EVALUATED_SCOPE = "EXACT_FOR_EVALUATED_SCOPE"
    WITHIN_POLICY_FOR_EVALUATED_SCOPE = "WITHIN_POLICY_FOR_EVALUATED_SCOPE"
    OUTSIDE_POLICY_FOR_EVALUATED_SCOPE = "OUTSIDE_POLICY_FOR_EVALUATED_SCOPE"
    SAMPLED_WITHIN_POLICY = "SAMPLED_WITHIN_POLICY"
    SAMPLED_OUTSIDE_POLICY = "SAMPLED_OUTSIDE_POLICY"
    INSUFFICIENT_NUMERICAL_COVERAGE = "INSUFFICIENT_NUMERICAL_COVERAGE"
    FORMAT_NOT_NUMERICALLY_SUPPORTED = "FORMAT_NOT_NUMERICALLY_SUPPORTED"
    PAYLOAD_VALUES_UNAVAILABLE = "PAYLOAD_VALUES_UNAVAILABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class OverallEvidenceStatus(StrEnum):
    CONFORMS_FOR_DECLARED_SCOPE = "CONFORMS_FOR_DECLARED_SCOPE"
    DOES_NOT_CONFORM_FOR_DECLARED_SCOPE = "DOES_NOT_CONFORM_FOR_DECLARED_SCOPE"
    INDETERMINATE = "INDETERMINATE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class RequirementStatus(StrEnum):
    POLICY_REQUIREMENT_SATISFIED = "POLICY_REQUIREMENT_SATISFIED"
    POLICY_REQUIREMENT_FAILED = "POLICY_REQUIREMENT_FAILED"
    POLICY_REQUIREMENT_NOT_EVALUATED = "POLICY_REQUIREMENT_NOT_EVALUATED"
    POLICY_REQUIREMENT_NOT_APPLICABLE = "POLICY_REQUIREMENT_NOT_APPLICABLE"
    POLICY_REQUIREMENT_INVALID = "POLICY_REQUIREMENT_INVALID"


class AuthorityStatus(StrEnum):
    ESTABLISHED = "ESTABLISHED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    NOT_EVALUATED = "NOT_EVALUATED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    INVALID = "INVALID"


class FindingKind(StrEnum):
    SHAPE_MATCH = "SHAPE_MATCH"
    SHAPE_MISMATCH = "SHAPE_MISMATCH"
    STORAGE_DTYPE_MATCH = "STORAGE_DTYPE_MATCH"
    STORAGE_DTYPE_MISMATCH = "STORAGE_DTYPE_MISMATCH"
    LOGICAL_DTYPE_MISMATCH = "LOGICAL_DTYPE_MISMATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    CONTENT_DIGEST_MISMATCH = "CONTENT_DIGEST_MISMATCH"
    QUANTIZATION_PARAMETER_MISMATCH = "QUANTIZATION_PARAMETER_MISMATCH"
    QUANTIZATION_PARAMETERS_MISSING = "QUANTIZATION_PARAMETERS_MISSING"
    NUMERICAL_THRESHOLD_EXCEEDED = "NUMERICAL_THRESHOLD_EXCEEDED"
    NUMERICAL_DIFFERENCE_OBSERVED = "NUMERICAL_DIFFERENCE_OBSERVED"
    MANDATORY_TENSOR_MISSING = "MANDATORY_TENSOR_MISSING"
    MAPPING_AMBIGUOUS = "MAPPING_AMBIGUOUS"
    MAPPING_RECIPE_UNAVAILABLE = "MAPPING_RECIPE_UNAVAILABLE"
    FORMAT_NOT_NUMERICALLY_SUPPORTED = "FORMAT_NOT_NUMERICALLY_SUPPORTED"
    PAYLOAD_VALUES_UNAVAILABLE = "PAYLOAD_VALUES_UNAVAILABLE"
    PHASE6A_IDENTITY_MISMATCH = "PHASE6A_IDENTITY_MISMATCH"
    PHASE6B_DIGEST_NOT_COMPARABLE = "PHASE6B_DIGEST_NOT_COMPARABLE"
    PATH_REBOUND_DURING_OBSERVATION = "PATH_REBOUND_DURING_OBSERVATION"
    OPENED_FILE_CHANGED_DURING_READ = "OPENED_FILE_CHANGED_DURING_READ"
    ROOT_CHANGED_DURING_OBSERVATION = "ROOT_CHANGED_DURING_OBSERVATION"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    NON_FINITE_INPUT = "NON_FINITE_INPUT"


class ObjectReference(QuantizationModel):
    schema_id: str = Field(pattern=r"^omiv\.[a-z0-9.-]+\.v[0-9]+$")
    object_id: str = Field(min_length=3, max_length=160)
    object_digest: str = Field(pattern=SHA256_PATTERN)


class ArtifactIdentity(QuantizationModel):
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    role: ArtifactRole
    provider: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=256)
    artifact_name: str = Field(min_length=1, max_length=256)
    requested_revision: str | None = Field(default=None, max_length=512)
    resolved_revision: str | None = Field(default=None, max_length=512)
    local_payload_manifest: ObjectReference | None = None
    remote_snapshot: ObjectReference | None = None
    artifact_set_identity: str | None = Field(default=None, pattern=SHA256_PATTERN)
    coverage: str = Field(pattern=ID_PATTERN)
    identity_semantics: str = Field(pattern=ID_PATTERN)
    availability: ArtifactAvailability
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def availability_binding(self) -> ArtifactIdentity:
        if self.availability == ArtifactAvailability.EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE and (
            self.local_payload_manifest is None or self.artifact_set_identity is None
        ):
            raise ValueError("exact local identity requires Phase 6A manifest and artifact set")
        if (
            self.availability == ArtifactAvailability.REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE
            and (self.remote_snapshot is None or self.artifact_set_identity is None)
        ):
            raise ValueError("remote payload identity requires snapshot and artifact set")
        if self.availability == ArtifactAvailability.DIGEST_REFERENCE_ONLY and any(
            (self.local_payload_manifest, self.remote_snapshot)
        ):
            raise ValueError("digest-only identity cannot contain a supplied canonical object")
        return self


class TransformationAttestationReference(QuantizationModel):
    attestation: ObjectReference
    execution_record: ObjectReference
    claimed_transformation_kind: str = Field(pattern=ID_PATTERN)
    signer_trust_report: ObjectReference | None = None
    provenance_strength: str = Field(pattern=ID_PATTERN)
    authority_status: AuthorityStatus
    evaluation_context: ScopeContext
    proves_numerical_fidelity: Literal[False] = False


class QuantizationRelationshipDeclaration(QuantizationModel):
    schema_id: Literal["omiv.quantization-relationship-declaration.v1"] = Field(
        default="omiv.quantization-relationship-declaration.v1", alias="schema"
    )
    declaration_id: str = Field(pattern=r"^quantization_declaration_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    relationship_mode: RelationshipMode
    provenance: DeclarationProvenance
    source_artifact: ArtifactIdentity
    candidate_artifact: ArtifactIdentity
    transformation_attestation: TransformationAttestationReference | None = None
    authority_status: AuthorityStatus
    declared_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)
    declaration_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationRelationshipDeclaration:
        if self.source_artifact.subject_id != self.subject.subject_id:
            raise ValueError("source artifact subject differs from declaration subject")
        if self.candidate_artifact.subject_id != self.subject.subject_id:
            raise ValueError("candidate artifact subject differs from declaration subject")
        if self.source_artifact.role != ArtifactRole.SOURCE:
            raise ValueError("source artifact must have SOURCE role")
        if self.candidate_artifact.role != ArtifactRole.CANDIDATE:
            raise ValueError("candidate artifact must have CANDIDATE role")
        if self.provenance == DeclarationProvenance.SIGNED_TRANSFORMATION_ATTESTATION:
            if self.transformation_attestation is None:
                raise ValueError("signed transformation provenance requires exact attestation")
        elif self.transformation_attestation is not None:
            raise ValueError("attestation reference conflicts with declaration provenance")
        _identity(self, "declaration_id", "quantization_declaration_", "declaration_digest")
        return self


class QuantizationLimits(QuantizationModel):
    maximum_artifact_members: int = Field(default=100_000, ge=1, le=100_000)
    maximum_tensor_records: int = Field(default=100_000, ge=1, le=100_000)
    maximum_tensor_rank: int = Field(default=16, ge=0, le=64)
    maximum_dimensions_per_tensor: int = Field(default=16, ge=0, le=64)
    maximum_logical_elements_per_tensor: int = Field(default=100_000_000, ge=1)
    maximum_total_logical_elements: int = Field(default=1_000_000_000, ge=1)
    maximum_correspondence_records: int = Field(default=100_000, ge=1, le=100_000)
    maximum_mapping_fan_in: int = Field(default=64, ge=1, le=1024)
    maximum_mapping_fan_out: int = Field(default=64, ge=1, le=1024)
    maximum_quantization_parameter_records: int = Field(default=100_000, ge=1, le=100_000)
    maximum_sample_elements_per_tensor: int = Field(default=100_000, ge=0, le=1_000_000)
    maximum_total_sampled_elements: int = Field(default=1_000_000, ge=0, le=10_000_000)
    maximum_fully_compared_elements: int = Field(default=10_000_000, ge=1)
    maximum_payload_bytes_per_file: int = Field(default=256 * 1024 * 1024, ge=0)
    maximum_total_payload_bytes: int = Field(default=1024 * 1024 * 1024, ge=0)
    maximum_streaming_chunk_size: int = Field(default=4 * 1024 * 1024, ge=4096)
    maximum_json_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    maximum_json_nesting: int = Field(default=64, ge=1, le=128)
    maximum_canonical_string_length: int = Field(default=MAX_TEXT, ge=64, le=8192)
    maximum_findings: int = Field(default=MAX_FINDINGS, ge=1, le=MAX_FINDINGS)
    maximum_report_reconstruction_nodes: int = Field(default=200_000, ge=1)
    maximum_dependency_graph_nodes: int = Field(default=200_000, ge=1)
    maximum_dependency_graph_edges: int = Field(default=1_000_000, ge=1)
    maximum_traversal_depth: int = Field(default=128, ge=1, le=1024)
    maximum_generated_artifact_count: int = Field(default=140, ge=1, le=140)
    maximum_generated_metadata_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)


class QuantizationObservationPlan(QuantizationModel):
    schema_id: Literal["omiv.quantization-observation-plan.v1"] = Field(
        default="omiv.quantization-observation-plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=r"^quantization_plan_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    declaration: ObjectReference
    source_phase6a: ObjectReference | None = None
    candidate_phase6a: ObjectReference | None = None
    remote_phase6b: tuple[ObjectReference, ...] = Field(default=(), max_length=16)
    requested_observation_level: ObservationLevel
    expectation_scope: ExpectationScope
    deterministic_sample: ObjectReference | None = None
    limits: QuantizationLimits = QuantizationLimits()
    requested_at: ExplicitTime
    network_use: Literal["NONE"] = "NONE"
    model_execution: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    limitations: tuple[str, ...] = Field(max_length=64)
    plan_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationObservationPlan:
        _require_reference_schema(self.declaration, "omiv.quantization-relationship-declaration.v1")
        if self.source_phase6a is not None:
            _require_reference_schema(self.source_phase6a, "omiv.observed-payload-manifest.v1")
        if self.candidate_phase6a is not None:
            _require_reference_schema(self.candidate_phase6a, "omiv.observed-payload-manifest.v1")
        for reference in self.remote_phase6b:
            _require_reference_schema(reference, "omiv.remote-snapshot-manifest.v1")
        if self.requested_observation_level == ObservationLevel.DETERMINISTIC_SAMPLE:
            if self.deterministic_sample is None:
                raise ValueError("sample observation requires a finalized sample definition")
        elif self.deterministic_sample is not None:
            raise ValueError("sample definition is only valid for deterministic sampling")
        _identity(self, "plan_id", "quantization_plan_", "plan_digest")
        return self


class QuantizationExecutionRecord(QuantizationModel):
    schema_id: Literal["omiv.quantization-execution-record.v1"] = Field(
        default="omiv.quantization-execution-record.v1", alias="schema"
    )
    execution_id: str = Field(pattern=r"^quantization_execution_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    plan: ObjectReference
    supplied_inputs: tuple[ObjectReference, ...] = Field(max_length=32)
    tool_id: str = Field(pattern=ID_PATTERN)
    tool_version: str = Field(pattern=ID_PATTERN)
    effective_limits: QuantizationLimits
    completion_state: Literal["COMPLETE", "INCOMPLETE", "LIMIT_EXCEEDED", "FAILED"]
    tensor_records_processed: int = Field(ge=0)
    values_processed: int = Field(ge=0)
    payload_bytes_read: int = Field(ge=0)
    network_use: Literal["NONE"] = "NONE"
    model_execution: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    failure_class: Literal[
        "NONE",
        "INVALID_INPUT",
        "LIMIT_EXCEEDED",
        "UNSUPPORTED_FORMAT",
        "FILESYSTEM_RACE",
        "INTERNAL_ERROR",
    ]
    result_reference_status: Literal["LINKED_DOWNSTREAM_BY_OBSERVATIONS"] = (
        "LINKED_DOWNSTREAM_BY_OBSERVATIONS"
    )
    limitations: tuple[str, ...] = Field(max_length=64)
    execution_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationExecutionRecord:
        _require_reference_schema(self.plan, "omiv.quantization-observation-plan.v1")
        if self.payload_bytes_read > self.effective_limits.maximum_total_payload_bytes:
            raise ValueError("LIMIT_EXCEEDED:TOTAL_PAYLOAD_BYTES")
        _identity(self, "execution_id", "quantization_execution_", "execution_digest")
        return self


class QuantizationDescriptor(QuantizationModel):
    scheme_family: SchemeFamily
    numerical_codec: NumericalCodec
    storage_dtype: str | None = Field(default=None, max_length=128)
    logical_reconstructed_dtype: str | None = Field(default=None, max_length=128)
    bit_width: int | None = Field(default=None, ge=1, le=64)
    signed: bool | None = None
    byte_order: Literal["LITTLE", "BIG", "NOT_APPLICABLE", "UNKNOWN"]
    packing_order: str | None = Field(default=None, max_length=128)
    scale_representation: str | None = Field(default=None, max_length=128)
    zero_point_representation: str | None = Field(default=None, max_length=128)
    quantization_axis: int | None = None
    group_size: int | None = Field(default=None, ge=1)
    block_size: int | None = Field(default=None, ge=1)
    codebook_identity: str | None = Field(default=None, pattern=SHA256_PATTERN)
    rounding_mode: str | None = Field(default=None, max_length=128)
    clipping_behavior: str | None = Field(default=None, max_length=128)
    exceptional_value_handling: str | None = Field(default=None, max_length=128)
    format_identifier: str | None = Field(default=None, max_length=256)
    format_version: str | None = Field(default=None, max_length=128)
    parameter_provenance: ParameterProvenance
    observation_level: ObservationLevel

    @model_validator(mode="after")
    def supported_semantics(self) -> QuantizationDescriptor:
        if (
            self.numerical_codec == NumericalCodec.UNQUANTIZED_IDENTITY
            and self.scheme_family != SchemeFamily.UNQUANTIZED
        ):
            raise ValueError("identity codec requires unquantized scheme")
        if self.numerical_codec == NumericalCodec.UNIFORM_AFFINE_INTEGER:
            if self.scheme_family != SchemeFamily.UNIFORM_AFFINE_INTEGER:
                raise ValueError("affine codec requires affine scheme")
            if self.bit_width is None or self.signed is None:
                raise ValueError("affine codec requires explicit width and signedness")
            if self.packing_order is None:
                raise ValueError("affine codec requires explicit normalized or packed layout")
        return self


class TensorRepresentationRecord(QuantizationModel):
    schema_id: Literal["omiv.tensor-representation-record.v1"] = Field(
        default="omiv.tensor-representation-record.v1", alias="schema"
    )
    tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    artifact_identity: str = Field(pattern=SHA256_PATTERN)
    logical_name: str = Field(min_length=1, max_length=1024)
    role: TensorRole
    role_detail: str | None = Field(default=None, pattern=ID_PATTERN)
    shape: tuple[int, ...] = Field(max_length=64)
    rank: int = Field(ge=0, le=64)
    logical_element_count: int = Field(ge=0)
    storage_dtype: str = Field(min_length=1, max_length=128)
    logical_dtype: str = Field(min_length=1, max_length=128)
    byte_offset: int | None = Field(default=None, ge=0)
    byte_length: int | None = Field(default=None, ge=0)
    member_identity: str | None = Field(default=None, max_length=1024)
    content_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    quantization: QuantizationDescriptor
    observation_level: ObservationLevel
    observed_element_count: int = Field(ge=0)
    provenance: ParameterProvenance
    limitations: tuple[str, ...] = Field(max_length=64)
    tensor_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> TensorRepresentationRecord:
        validate_portable_path(self.logical_name)
        if self.rank != len(self.shape):
            raise ValueError("tensor rank does not match shape")
        product = 1
        for dimension in self.shape:
            if dimension < 0:
                raise ValueError("tensor dimensions cannot be negative")
            if dimension > MAX_LOGICAL_ELEMENTS_PER_TENSOR:
                raise ValueError("LIMIT_EXCEEDED:TENSOR_DIMENSION")
            product *= dimension
            if product > MAX_LOGICAL_ELEMENTS_PER_TENSOR:
                raise ValueError("LIMIT_EXCEEDED:LOGICAL_ELEMENTS_PER_TENSOR")
        if product != self.logical_element_count:
            raise ValueError("logical element count does not match shape")
        if self.observed_element_count > self.logical_element_count:
            raise ValueError("observed elements exceed logical population")
        if (self.byte_offset is None) != (self.byte_length is None):
            raise ValueError("byte range must be fully specified or unavailable")
        if (self.role == TensorRole.OTHER_DECLARED) != (self.role_detail is not None):
            raise ValueError("OTHER_DECLARED alone requires role detail")
        _identity(self, "tensor_id", "quantization_tensor_", "tensor_digest")
        return self


class CoverageDimension(QuantizationModel):
    dimension: Literal[
        "SOURCE_ARTIFACT",
        "CANDIDATE_ARTIFACT",
        "SOURCE_TENSOR",
        "CANDIDATE_TENSOR",
        "MAPPED_TENSOR",
        "MANDATORY_ROLE",
        "NUMERICAL_TENSOR",
        "NUMERICAL_ELEMENT",
        "BYTE",
        "QUANTIZATION_PARAMETER",
        "SAMPLING",
    ]
    numerator: int = Field(ge=0)
    denominator: int | None = Field(default=None, ge=0)
    status: Literal["COMPLETE", "PARTIAL", "UNAVAILABLE", "NOT_APPLICABLE"]
    incomplete_reason: str | None = Field(default=None, max_length=MAX_TEXT)

    @model_validator(mode="after")
    def valid_coverage(self) -> CoverageDimension:
        if self.denominator is not None and self.numerator > self.denominator:
            raise ValueError("coverage numerator exceeds denominator")
        if self.status == "COMPLETE" and (
            self.denominator is None or self.numerator != self.denominator
        ):
            raise ValueError("complete coverage requires equal known counts")
        if self.status in {"PARTIAL", "UNAVAILABLE"} and self.incomplete_reason is None:
            raise ValueError("incomplete coverage requires a reason")
        return self


class RepresentationObservation(QuantizationModel):
    schema_id: Literal["omiv.representation-observation.v1"] = Field(
        default="omiv.representation-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^representation_observation_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    execution: ObjectReference
    representation_role: ArtifactRole
    artifact: ArtifactIdentity
    format_descriptor: QuantizationDescriptor
    tensors: tuple[TensorRepresentationRecord, ...] = Field(max_length=MAX_TENSORS)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    available_at: ExplicitTime
    observed_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)
    observation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RepresentationObservation:
        _require_reference_schema(self.execution, "omiv.quantization-execution-record.v1")
        if self.artifact.role != self.representation_role:
            raise ValueError("observation and artifact roles differ")
        names = tuple(t.logical_name for t in self.tensors)
        if names:
            validate_path_set(names)
        if self.tensors != tuple(sorted(self.tensors, key=lambda t: t.logical_name.encode())):
            raise ValueError("tensor records must be canonically ordered")
        if len({t.tensor_id for t in self.tensors}) != len(self.tensors):
            raise ValueError("duplicate tensor identity")
        represented = 0
        for tensor in self.tensors:
            represented += tensor.logical_element_count
            if represented > MAX_TOTAL_LOGICAL_ELEMENTS:
                raise ValueError("LIMIT_EXCEEDED:TOTAL_LOGICAL_ELEMENTS")
        _identity(self, "observation_id", "representation_observation_", "observation_digest")
        return self


class TensorMapping(QuantizationModel):
    mapping_id: str = Field(pattern=r"^tensor_mapping_[0-9a-f]{32}$")
    source_tensor_ids: tuple[str, ...] = Field(max_length=64)
    candidate_tensor_ids: tuple[str, ...] = Field(max_length=64)
    cardinality: CorrespondenceCardinality
    numerical_status: MappingNumericalStatus
    reconstruction_recipe: ObjectReference | None = None
    limitations: tuple[str, ...] = Field(max_length=32)
    mapping_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> TensorMapping:
        if len(set(self.source_tensor_ids)) != len(self.source_tensor_ids):
            raise ValueError("duplicate source tensor mapping")
        if len(set(self.candidate_tensor_ids)) != len(self.candidate_tensor_ids):
            raise ValueError("duplicate candidate tensor mapping")
        if self.cardinality == CorrespondenceCardinality.ONE_TO_ONE and (
            len(self.source_tensor_ids) != 1 or len(self.candidate_tensor_ids) != 1
        ):
            raise ValueError("ONE_TO_ONE requires one source and one candidate")
        if (
            self.numerical_status == MappingNumericalStatus.NUMERICALLY_EVALUABLE
            and self.cardinality != CorrespondenceCardinality.ONE_TO_ONE
            and self.reconstruction_recipe is None
        ):
            raise ValueError("non-one-to-one numerical mapping requires recipe")
        _identity(self, "mapping_id", "tensor_mapping_", "mapping_digest")
        return self


class TensorCorrespondence(QuantizationModel):
    schema_id: Literal["omiv.tensor-correspondence.v1"] = Field(
        default="omiv.tensor-correspondence.v1", alias="schema"
    )
    correspondence_id: str = Field(pattern=r"^tensor_correspondence_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    source_observation: ObjectReference
    candidate_observation: ObjectReference
    mappings: tuple[TensorMapping, ...] = Field(max_length=MAX_TENSORS)
    mapping_semantics: Literal["EXPLICIT_ONLY"] = "EXPLICIT_ONLY"
    limitations: tuple[str, ...] = Field(max_length=64)
    correspondence_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> TensorCorrespondence:
        _require_reference_schema(self.source_observation, "omiv.representation-observation.v1")
        _require_reference_schema(self.candidate_observation, "omiv.representation-observation.v1")
        if self.mappings != tuple(sorted(self.mappings, key=lambda m: m.mapping_id)):
            raise ValueError("mappings must be canonically ordered")
        source_ids = [x for m in self.mappings for x in m.source_tensor_ids]
        candidate_ids = [x for m in self.mappings for x in m.candidate_tensor_ids]
        if len(source_ids) != len(set(source_ids)) or len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("tensor appears in multiple correspondence records")
        _identity(self, "correspondence_id", "tensor_correspondence_", "correspondence_digest")
        return self


class QuantizationParameterObservation(QuantizationModel):
    schema_id: Literal["omiv.quantization-parameter-observation.v1"] = Field(
        default="omiv.quantization-parameter-observation.v1", alias="schema"
    )
    parameter_observation_id: str = Field(pattern=r"^quantization_parameters_[0-9a-f]{32}$")
    candidate_observation: ObjectReference
    tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    scheme_family: SchemeFamily
    numerical_codec: NumericalCodec
    scale: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    zero_point: int | None = None
    quantization_axis: int | None = None
    group_size: int | None = Field(default=None, ge=1)
    block_size: int | None = Field(default=None, ge=1)
    storage_bit_width: int | None = Field(default=None, ge=1, le=64)
    storage_signed: bool | None = None
    provenance: ParameterProvenance
    observation_level: ObservationLevel
    complete_for_supported_codec: bool
    limitations: tuple[str, ...] = Field(max_length=64)
    parameter_observation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationParameterObservation:
        _require_reference_schema(self.candidate_observation, "omiv.representation-observation.v1")
        if self.numerical_codec == NumericalCodec.UNIFORM_AFFINE_INTEGER:
            required = (
                self.scale,
                self.zero_point,
                self.storage_bit_width,
                self.storage_signed,
            )
            if self.complete_for_supported_codec and any(x is None for x in required):
                raise ValueError(
                    "complete affine parameters require scale, zero point, width, sign"
                )
        elif self.complete_for_supported_codec and self.numerical_codec not in {
            NumericalCodec.UNQUANTIZED_IDENTITY,
        }:
            raise ValueError("unsupported codec cannot have complete numerical parameters")
        _identity(
            self,
            "parameter_observation_id",
            "quantization_parameters_",
            "parameter_observation_digest",
        )
        return self


class DeterministicSampleDefinition(QuantizationModel):
    schema_id: Literal["omiv.deterministic-sample-definition.v1"] = Field(
        default="omiv.deterministic-sample-definition.v1", alias="schema"
    )
    sample_id: str = Field(pattern=r"^quantization_sample_[0-9a-f]{32}$")
    algorithm: Literal["SHA256_REJECTION_V1"] = "SHA256_REJECTION_V1"
    domain_separated_seed: str = Field(min_length=1, max_length=256)
    source_tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    candidate_tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    population_element_count: int = Field(ge=0)
    requested_sample_count: int = Field(ge=0)
    actual_sample_count: int = Field(ge=0)
    selected_indices: tuple[int, ...] = Field(max_length=1_000_000)
    ordering: Literal["ASCENDING_INDEX"] = "ASCENDING_INDEX"
    inclusion_rules: tuple[str, ...] = Field(max_length=32)
    exclusion_rules: tuple[str, ...] = Field(max_length=32)
    maximum_sample_count: int = Field(ge=0, le=1_000_000)
    maximum_population_count: int = Field(ge=1)
    maximum_population_traversal_count: int = Field(ge=0)
    maximum_hash_attempts: int = Field(ge=0)
    hash_attempt_count: int = Field(ge=0)
    maximum_stored_candidates: int = Field(ge=0)
    status: Literal["AVAILABLE", "EMPTY", "LIMIT_EXCEEDED"]
    limitations: tuple[str, ...] = Field(max_length=32)
    sample_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> DeterministicSampleDefinition:
        if self.selected_indices != tuple(sorted(set(self.selected_indices))):
            raise ValueError("sample indices must be unique and ascending")
        if self.actual_sample_count != len(self.selected_indices):
            raise ValueError("actual sample count mismatch")
        if any(x >= self.population_element_count for x in self.selected_indices):
            raise ValueError("sample index outside population")
        if self.hash_attempt_count > self.maximum_hash_attempts:
            raise ValueError("sample hashing exceeds recorded bound")
        if self.actual_sample_count > self.maximum_stored_candidates:
            raise ValueError("sample storage exceeds recorded bound")
        if (
            self.population_element_count > self.maximum_population_count
            and self.status != "LIMIT_EXCEEDED"
        ):
            raise ValueError("oversized population must be LIMIT_EXCEEDED")
        if self.status != "LIMIT_EXCEEDED" and self.actual_sample_count != min(
            self.requested_sample_count, self.population_element_count
        ):
            raise ValueError("sample count does not cover bounded request")
        _identity(self, "sample_id", "quantization_sample_", "sample_digest")
        return self


class MetricValue(QuantizationModel):
    state: MetricState
    value: str | None = Field(default=None, pattern=DECIMAL_PATTERN)

    @model_validator(mode="after")
    def valid_state(self) -> MetricValue:
        if (self.state in {MetricState.AVAILABLE, MetricState.EXACT}) != (self.value is not None):
            raise ValueError("available metric states require a value and others prohibit one")
        return self


class TensorMetricSet(QuantizationModel):
    source_tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    candidate_tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    compared_element_count: int = Field(ge=0)
    non_finite_source_count: int = Field(ge=0)
    non_finite_reconstructed_count: int = Field(ge=0)
    exact_equality_count: int = Field(ge=0)
    maximum_absolute_error: MetricValue
    mean_absolute_error: MetricValue
    mean_squared_error: MetricValue
    root_mean_squared_error: MetricValue
    source_l2_norm: MetricValue
    error_l2_norm: MetricValue
    relative_l2_error: MetricValue
    dot_product: MetricValue
    cosine_similarity: MetricValue
    signed_mean_error: MetricValue
    at_quantization_bound_count: int | None = Field(default=None, ge=0)
    clipping_status: Literal[
        "CLIPPING_OBSERVED", "CLIPPING_NOT_OBSERVED", "CLIPPING_NOT_EVALUATED"
    ] = "CLIPPING_NOT_EVALUATED"
    findings: tuple[FindingKind, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def boundary_count(self) -> TensorMetricSet:
        if (
            self.at_quantization_bound_count is not None
            and self.at_quantization_bound_count > self.compared_element_count
        ):
            raise ValueError("quantization-bound count exceeds compared elements")
        return self


class NumericalFidelityMeasurement(QuantizationModel):
    schema_id: Literal["omiv.numerical-fidelity-measurement.v1"] = Field(
        default="omiv.numerical-fidelity-measurement.v1", alias="schema"
    )
    measurement_id: str = Field(pattern=r"^quantization_measurement_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    source_observation: ObjectReference
    candidate_observation: ObjectReference
    correspondence: ObjectReference
    parameter_observations: tuple[ObjectReference, ...] = Field(max_length=MAX_TENSORS)
    sample_definition: ObjectReference | None = None
    observation_level: ObservationLevel
    decimal_precision: int = Field(default=50, ge=18, le=100)
    decimal_rounding: Literal["ROUND_HALF_EVEN"] = "ROUND_HALF_EVEN"
    metrics: tuple[TensorMetricSet, ...] = Field(max_length=MAX_TENSORS)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    worst_metric_name: str | None = Field(default=None, max_length=128)
    worst_metric_value: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    failed_tensor_ids: tuple[str, ...] = Field(max_length=MAX_TENSORS)
    weighted_aggregate_semantics: str = Field(max_length=512)
    unweighted_aggregate_semantics: str = Field(max_length=512)
    total_evaluated_elements: int = Field(ge=0)
    status: NumericalStatus
    limitations: tuple[str, ...] = Field(max_length=64)
    measurement_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> NumericalFidelityMeasurement:
        _require_reference_schema(self.source_observation, "omiv.representation-observation.v1")
        _require_reference_schema(self.candidate_observation, "omiv.representation-observation.v1")
        _require_reference_schema(self.correspondence, "omiv.tensor-correspondence.v1")
        for reference in self.parameter_observations:
            _require_reference_schema(reference, "omiv.quantization-parameter-observation.v1")
        if self.sample_definition is not None:
            _require_reference_schema(
                self.sample_definition, "omiv.deterministic-sample-definition.v1"
            )
        if self.observation_level == ObservationLevel.DETERMINISTIC_SAMPLE:
            if self.sample_definition is None:
                raise ValueError("sampled measurement requires sample definition")
            if self.status in {
                NumericalStatus.EXACT_FOR_EVALUATED_SCOPE,
                NumericalStatus.WITHIN_POLICY_FOR_EVALUATED_SCOPE,
            }:
                raise ValueError("sampled measurement cannot claim full evaluated-scope status")
        elif self.sample_definition is not None:
            raise ValueError("non-sampled measurement cannot bind a sample definition")
        if self.total_evaluated_elements != sum(
            metric.compared_element_count for metric in self.metrics
        ):
            raise ValueError("measurement evaluated-element count mismatch")
        evaluable = {
            NumericalStatus.EXACT_FOR_EVALUATED_SCOPE,
            NumericalStatus.NUMERICALLY_EVALUATED_FOR_SCOPE,
            NumericalStatus.SAMPLED_NUMERICALLY_EVALUATED,
        }
        if self.status in evaluable and (not self.metrics or self.total_evaluated_elements == 0):
            raise ValueError("empty measurement cannot claim numerical evaluation")
        _identity(self, "measurement_id", "quantization_measurement_", "measurement_digest")
        return self


class QuantizationFinding(QuantizationModel):
    kind: FindingKind
    status: Literal["PASS", "FAIL", "OBSERVED", "INCOMPLETE", "NOT_EVALUATED"]
    tensor_ids: tuple[str, ...] = Field(max_length=64)
    detail: str = Field(min_length=1, max_length=MAX_TEXT)


class QuantizationFidelityComparison(QuantizationModel):
    schema_id: Literal["omiv.quantization-fidelity-comparison.v1"] = Field(
        default="omiv.quantization-fidelity-comparison.v1", alias="schema"
    )
    comparison_id: str = Field(pattern=r"^quantization_comparison_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    declaration: ObjectReference
    source_observation: ObjectReference
    candidate_observation: ObjectReference
    correspondence: ObjectReference
    parameter_observations: tuple[ObjectReference, ...] = Field(max_length=MAX_TENSORS)
    measurements: tuple[ObjectReference, ...] = Field(max_length=MAX_TENSORS)
    expectation_scope: ExpectationScope
    structural_status: StructuralStatus
    numerical_status: NumericalStatus
    findings: tuple[QuantizationFinding, ...] = Field(max_length=MAX_FINDINGS)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    complete_model_equivalence_claimed: Literal[False] = False
    behavioral_equivalence_claimed: Literal[False] = False
    limitations: tuple[str, ...] = Field(max_length=64)
    comparison_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationFidelityComparison:
        _require_reference_schema(self.declaration, "omiv.quantization-relationship-declaration.v1")
        _require_reference_schema(self.source_observation, "omiv.representation-observation.v1")
        _require_reference_schema(self.candidate_observation, "omiv.representation-observation.v1")
        _require_reference_schema(self.correspondence, "omiv.tensor-correspondence.v1")
        for reference in self.parameter_observations:
            _require_reference_schema(reference, "omiv.quantization-parameter-observation.v1")
        for reference in self.measurements:
            _require_reference_schema(reference, "omiv.numerical-fidelity-measurement.v1")
        _identity(self, "comparison_id", "quantization_comparison_", "comparison_digest")
        return self


class FidelityThresholds(QuantizationModel):
    maximum_absolute_error: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    maximum_mean_absolute_error: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    maximum_rmse: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    maximum_relative_l2_error: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    minimum_cosine_similarity: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    maximum_bias: str | None = Field(default=None, pattern=DECIMAL_PATTERN)
    maximum_quantization_bound_rate: str | None = Field(default=None, pattern=DECIMAL_PATTERN)

    @model_validator(mode="after")
    def threshold_ranges(self) -> FidelityThresholds:
        nonnegative = (
            self.maximum_absolute_error,
            self.maximum_mean_absolute_error,
            self.maximum_rmse,
            self.maximum_relative_l2_error,
            self.maximum_bias,
            self.maximum_quantization_bound_rate,
        )
        if any(value is not None and parse_bounded_decimal(value) < 0 for value in nonnegative):
            raise ValueError("maximum fidelity thresholds must be non-negative")
        if self.minimum_cosine_similarity is not None:
            cosine = parse_bounded_decimal(self.minimum_cosine_similarity)
            if cosine < -1 or cosine > 1:
                raise ValueError("cosine threshold must be between -1 and 1")
        if self.maximum_quantization_bound_rate is not None:
            rate = parse_bounded_decimal(self.maximum_quantization_bound_rate)
            if rate > 1:
                raise ValueError("quantization-bound rate must be between 0 and 1")
        return self


class RoleThreshold(QuantizationModel):
    role: TensorRole
    thresholds: FidelityThresholds


class TensorThreshold(QuantizationModel):
    tensor_id: str = Field(pattern=r"^quantization_tensor_[0-9a-f]{32}$")
    thresholds: FidelityThresholds


class QuantizationFidelityPolicy(QuantizationModel):
    schema_id: Literal["omiv.quantization-fidelity-policy.v1"] = Field(
        default="omiv.quantization-fidelity-policy.v1", alias="schema"
    )
    policy_id: str = Field(pattern=r"^quantization_policy_[0-9a-f]{32}$")
    policy_name: str = Field(pattern=ID_PATTERN)
    evaluation_context: ScopeContext
    allowed_scheme_families: tuple[SchemeFamily, ...] = Field(min_length=1)
    allowed_storage_dtypes: tuple[str, ...] = Field(min_length=1)
    allowed_logical_dtypes: tuple[str, ...] = Field(min_length=1)
    required_artifact_availability: ArtifactAvailability
    required_tensor_roles: tuple[TensorRole, ...]
    minimum_tensor_coverage: str = Field(pattern=DECIMAL_PATTERN)
    minimum_element_coverage: str = Field(pattern=DECIMAL_PATTERN)
    minimum_byte_coverage: str = Field(pattern=DECIMAL_PATTERN)
    minimum_parameter_coverage: str = Field(pattern=DECIMAL_PATTERN)
    deterministic_sampling_permitted: bool
    maximum_sampling_gap: str = Field(pattern=DECIMAL_PATTERN)
    default_thresholds: FidelityThresholds
    per_role_thresholds: tuple[RoleThreshold, ...] = Field(max_length=32)
    per_tensor_overrides: tuple[TensorThreshold, ...] = Field(max_length=MAX_TENSORS)
    non_finite_value_policy: Literal["FAIL", "NOT_EVALUATED"]
    unsupported_format_behavior: Literal["FAIL", "INDETERMINATE"]
    missing_source_behavior: Literal["FAIL", "INDETERMINATE"]
    missing_candidate_behavior: Literal["FAIL", "INDETERMINATE"]
    source_publisher_authority_required: bool
    candidate_publisher_authority_required: bool
    transformation_authority_required: bool
    limitations: tuple[str, ...] = Field(max_length=64)
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationFidelityPolicy:
        for values in (
            self.allowed_scheme_families,
            self.allowed_storage_dtypes,
            self.allowed_logical_dtypes,
            self.required_tensor_roles,
        ):
            if len(set(values)) != len(values):
                raise ValueError("policy collections must be unique")
        if len({value.role for value in self.per_role_thresholds}) != len(self.per_role_thresholds):
            raise ValueError("policy role thresholds must be unique")
        if len({value.tensor_id for value in self.per_tensor_overrides}) != len(
            self.per_tensor_overrides
        ):
            raise ValueError("policy tensor overrides must be unique")
        for value in (
            self.minimum_tensor_coverage,
            self.minimum_element_coverage,
            self.minimum_byte_coverage,
            self.minimum_parameter_coverage,
            self.maximum_sampling_gap,
        ):
            parsed = parse_bounded_decimal(value)
            if parsed < 0 or parsed > 1:
                raise ValueError("coverage and sampling policy values must be between 0 and 1")
        _identity(self, "policy_id", "quantization_policy_", "policy_digest")
        return self


class PolicyRequirementResult(QuantizationModel):
    requirement: str = Field(pattern=ID_PATTERN)
    status: RequirementStatus
    observed_value: str | None = Field(default=None, max_length=MAX_TEXT)
    required_value: str | None = Field(default=None, max_length=MAX_TEXT)
    tensor_ids: tuple[str, ...] = Field(max_length=64)
    detail: str = Field(min_length=1, max_length=MAX_TEXT)


class QuantizationPolicyEvaluation(QuantizationModel):
    schema_id: Literal["omiv.quantization-policy-evaluation.v1"] = Field(
        default="omiv.quantization-policy-evaluation.v1", alias="schema"
    )
    evaluation_id: str = Field(pattern=r"^quantization_policy_evaluation_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    policy: ObjectReference
    comparison: ObjectReference
    authority_evaluation: ObjectReference | None = None
    requirements: tuple[PolicyRequirementResult, ...] = Field(max_length=MAX_FINDINGS)
    policy_satisfied_for_declared_scope: bool
    overall_status: OverallEvidenceStatus
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)
    evaluation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationPolicyEvaluation:
        _require_reference_schema(self.policy, "omiv.quantization-fidelity-policy.v1")
        _require_reference_schema(self.comparison, "omiv.quantization-fidelity-comparison.v1")
        if self.authority_evaluation is not None:
            _require_reference_schema(
                self.authority_evaluation, "omiv.quantization-authority-evaluation.v1"
            )
        failed = any(
            x.status == RequirementStatus.POLICY_REQUIREMENT_FAILED for x in self.requirements
        )
        pending = any(
            x.status
            in {
                RequirementStatus.POLICY_REQUIREMENT_NOT_EVALUATED,
                RequirementStatus.POLICY_REQUIREMENT_INVALID,
            }
            for x in self.requirements
        )
        if self.policy_satisfied_for_declared_scope and (failed or pending):
            raise ValueError("policy cannot pass with failed or unevaluated requirements")
        _identity(
            self,
            "evaluation_id",
            "quantization_policy_evaluation_",
            "evaluation_digest",
        )
        return self


class QuantizationAuthorityEvaluation(QuantizationModel):
    schema_id: Literal["omiv.quantization-authority-evaluation.v1"] = Field(
        default="omiv.quantization-authority-evaluation.v1", alias="schema"
    )
    authority_evaluation_id: str = Field(pattern=r"^quantization_authority_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    declaration: ObjectReference
    source_publisher_authority: AuthorityStatus
    candidate_publisher_authority: AuthorityStatus
    transformation_authority: AuthorityStatus
    expectation_publisher_authority: AuthorityStatus
    measurement_signature_status: Literal[
        "SIGNATURE_VALID", "SIGNATURE_INVALID", "SIGNATURE_NOT_SUPPLIED", "NOT_EVALUATED"
    ]
    measurement_signer_trust: Literal["SIGNER_TRUSTED", "SIGNER_NOT_TRUSTED", "NOT_EVALUATED"]
    measurement_signer_authorized: Literal[
        "SIGNER_AUTHORIZED_FOR_PURPOSE", "SIGNER_NOT_AUTHORIZED_FOR_PURPOSE", "NOT_EVALUATED"
    ]
    policy_authority: AuthorityStatus
    subject_scope_authorized: bool
    namespace_creates_authority: Literal[False] = False
    signature_creates_publisher_authority: Literal[False] = False
    limitations: tuple[str, ...] = Field(max_length=64)
    authority_evaluation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationAuthorityEvaluation:
        _require_reference_schema(self.declaration, "omiv.quantization-relationship-declaration.v1")
        _identity(
            self,
            "authority_evaluation_id",
            "quantization_authority_",
            "authority_evaluation_digest",
        )
        return self


class QuantizationFidelityEvidence(QuantizationModel):
    schema_id: Literal["omiv.quantization-fidelity-evidence.v1"] = Field(
        default="omiv.quantization-fidelity-evidence.v1", alias="schema"
    )
    evidence_id: str = Field(pattern=r"^quantization_evidence_[0-9a-f]{32}$")
    subject: ProductSubject
    scope: ScopeContext
    comparison: ObjectReference
    policy_evaluation: ObjectReference
    authority_evaluation: ObjectReference
    overall_status: OverallEvidenceStatus
    structural_status: StructuralStatus
    numerical_status: NumericalStatus
    expectation_scope: ExpectationScope
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    policy_satisfied_for_declared_scope: bool
    authority_established: bool
    model_correctness: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    behavioral_parity: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    security_safety: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    runtime_identity: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)
    evidence_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationFidelityEvidence:
        _require_reference_schema(self.comparison, "omiv.quantization-fidelity-comparison.v1")
        _require_reference_schema(self.policy_evaluation, "omiv.quantization-policy-evaluation.v1")
        _require_reference_schema(
            self.authority_evaluation, "omiv.quantization-authority-evaluation.v1"
        )
        if self.overall_status == OverallEvidenceStatus.CONFORMS_FOR_DECLARED_SCOPE:
            if not self.policy_satisfied_for_declared_scope:
                raise ValueError("conforming evidence requires scope-qualified policy success")
            if self.numerical_status in {
                NumericalStatus.NUMERICALLY_EVALUATED_FOR_SCOPE,
                NumericalStatus.SAMPLED_NUMERICALLY_EVALUATED,
                NumericalStatus.NOT_EVALUATED,
                NumericalStatus.PAYLOAD_VALUES_UNAVAILABLE,
                NumericalStatus.FORMAT_NOT_NUMERICALLY_SUPPORTED,
                NumericalStatus.INSUFFICIENT_NUMERICAL_COVERAGE,
            }:
                raise ValueError("metadata or unavailable numerical evidence cannot conform")
        if (
            self.numerical_status
            in {
                NumericalStatus.SAMPLED_WITHIN_POLICY,
                NumericalStatus.SAMPLED_OUTSIDE_POLICY,
            }
            and self.expectation_scope != ExpectationScope.DETERMINISTIC_SAMPLE_SCOPE
        ):
            raise ValueError("sampled evidence requires deterministic sample scope")
        _identity(self, "evidence_id", "quantization_evidence_", "evidence_digest")
        return self


class QuantizationIntegrationSummary(QuantizationModel):
    schema_id: Literal["omiv.quantization-integration-summary.v1"] = Field(
        default="omiv.quantization-integration-summary.v1", alias="schema"
    )
    integration_id: str = Field(pattern=r"^quantization_integration_[0-9a-f]{32}$")
    integration_type: Literal[
        "PASSPORT",
        "CUSTODY",
        "ATTESTATION",
        "GOVERNANCE",
        "SECURITY",
        "RUNTIME",
        "HISTORICAL",
        "PAYLOAD_INTEGRITY",
        "RECONCILIATION",
    ]
    evidence: ObjectReference
    source_object: ObjectReference | None = None
    subject_identity_match: bool | None = None
    payload_identity_match: bool | None = None
    derived_status: str = Field(min_length=1, max_length=MAX_TEXT)
    creates_governance_approval: Literal[False] = False
    creates_security_pass: Literal[False] = False
    creates_observed_runtime_identity: Literal[False] = False
    mutates_prior_artifact: Literal[False] = False
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)
    integration_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationIntegrationSummary:
        if (
            self.integration_type in {"SECURITY", "RUNTIME", "GOVERNANCE"}
            and self.source_object is not None
            and (self.subject_identity_match is not True or self.payload_identity_match is not True)
        ):
            raise ValueError("cross-phase evidence identity mismatch")
        _identity(self, "integration_id", "quantization_integration_", "integration_digest")
        return self


class QuantizationFidelityReport(QuantizationModel):
    schema_id: Literal["omiv.quantization-fidelity-report.v1"] = Field(
        default="omiv.quantization-fidelity-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^quantization_report_[0-9a-f]{32}$")
    evidence: ObjectReference
    comparison: ObjectReference
    policy_evaluation: ObjectReference
    authority_evaluation: ObjectReference
    overall_status: OverallEvidenceStatus
    structural_status: StructuralStatus
    numerical_status: NumericalStatus
    expectation_scope: ExpectationScope
    total_finding_count: int = Field(ge=0)
    included_finding_count: int = Field(ge=0)
    omitted_finding_count: int = Field(ge=0)
    finding_selection_rule: Literal["CANONICAL_ORDER_PREFIX"] = "CANONICAL_ORDER_PREFIX"
    truncation_status: Literal["NOT_TRUNCATED", "TRUNCATED"]
    limitations: tuple[str, ...] = Field(max_length=64)
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationFidelityReport:
        if self.included_finding_count + self.omitted_finding_count != self.total_finding_count:
            raise ValueError("report finding accounting mismatch")
        if (self.omitted_finding_count > 0) != (self.truncation_status == "TRUNCATED"):
            raise ValueError("report truncation status mismatch")
        _identity(self, "report_id", "quantization_report_", "report_digest")
        return self


class QuantizationExampleCase(QuantizationModel):
    case_id: str = Field(pattern=ID_PATTERN)
    description: str = Field(min_length=1, max_length=MAX_TEXT)
    expected_structural_status: StructuralStatus
    expected_numerical_status: NumericalStatus
    representative_object: ObjectReference
    limitations: tuple[str, ...] = Field(max_length=16)


class QuantizationExampleResult(QuantizationModel):
    schema_id: Literal["omiv.quantization-example-result.v1"] = Field(
        default="omiv.quantization-example-result.v1", alias="schema"
    )
    result_id: str = Field(pattern=r"^quantization_example_result_[0-9a-f]{32}$")
    case_id: str = Field(pattern=ID_PATTERN)
    outcome: Literal["PASS", "FAIL", "INDETERMINATE", "NOT_EVALUATED", "LIMIT_EXCEEDED"]
    structural_status: StructuralStatus
    numerical_status: NumericalStatus
    upstream_objects: tuple[ObjectReference, ...] = Field(min_length=1, max_length=16)
    exercised_invariant: str = Field(min_length=1, max_length=MAX_TEXT)
    observed_findings: tuple[str, ...] = Field(min_length=1, max_length=32)
    limitations: tuple[str, ...] = Field(max_length=16)
    result_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationExampleResult:
        if len({(value.object_id, value.object_digest) for value in self.upstream_objects}) != len(
            self.upstream_objects
        ):
            raise ValueError("example result upstream objects must be unique")
        _identity(self, "result_id", "quantization_example_result_", "result_digest")
        return self


class QuantizationExampleCatalog(QuantizationModel):
    schema_id: Literal["omiv.quantization-example-catalog.v1"] = Field(
        default="omiv.quantization-example-catalog.v1", alias="schema"
    )
    catalog_id: str = Field(pattern=r"^quantization_catalog_[0-9a-f]{32}$")
    cases: tuple[QuantizationExampleCase, ...] = Field(min_length=22, max_length=64)
    limitations: tuple[str, ...] = Field(max_length=32)
    catalog_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationExampleCatalog:
        if self.cases != tuple(sorted(self.cases, key=lambda x: x.case_id)):
            raise ValueError("example cases must be canonically ordered")
        if len({x.case_id for x in self.cases}) != len(self.cases):
            raise ValueError("duplicate example case")
        _identity(self, "catalog_id", "quantization_catalog_", "catalog_digest")
        return self


class QuantizationArtifactIndexEntry(QuantizationModel):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str
    canonical_id: str


class QuantizationArtifactIndex(QuantizationModel):
    schema_id: Literal["omiv.quantization-artifact-index.v1"] = Field(
        default="omiv.quantization-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^quantization_index_[0-9a-f]{32}$")
    entries: tuple[QuantizationArtifactIndexEntry, ...] = Field(max_length=MAX_INDEX_ENTRIES)
    total_size: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(max_length=32)
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> QuantizationArtifactIndex:
        paths = tuple(x.path for x in self.entries)
        validate_path_set(paths)
        if self.entries != tuple(sorted(self.entries, key=lambda x: x.path.encode())):
            raise ValueError("artifact index entries must be canonically ordered")
        if len({x.canonical_id for x in self.entries}) != len(self.entries):
            raise ValueError("artifact index contains duplicate canonical identities")
        _identity(self, "index_id", "quantization_index_", "index_digest")
        return self


def object_reference(value: BaseModel) -> ObjectReference:
    body = value.model_dump(mode="json", by_alias=True)
    schema = str(body["schema"])
    known = {
        "omiv.observed-payload-manifest.v1": ("manifest_id", "manifest_digest"),
        "omiv.payload-hash-execution-record.v1": ("execution_id", "execution_digest"),
        "omiv.remote-snapshot-manifest.v1": ("manifest_id", "manifest_digest"),
        "omiv.quantization-relationship-declaration.v1": (
            "declaration_id",
            "declaration_digest",
        ),
        "omiv.quantization-observation-plan.v1": ("plan_id", "plan_digest"),
        "omiv.quantization-execution-record.v1": ("execution_id", "execution_digest"),
        "omiv.tensor-representation-record.v1": ("tensor_id", "tensor_digest"),
        "omiv.representation-observation.v1": ("observation_id", "observation_digest"),
        "omiv.tensor-correspondence.v1": ("correspondence_id", "correspondence_digest"),
        "omiv.quantization-parameter-observation.v1": (
            "parameter_observation_id",
            "parameter_observation_digest",
        ),
        "omiv.deterministic-sample-definition.v1": ("sample_id", "sample_digest"),
        "omiv.numerical-fidelity-measurement.v1": ("measurement_id", "measurement_digest"),
        "omiv.quantization-fidelity-comparison.v1": ("comparison_id", "comparison_digest"),
        "omiv.quantization-fidelity-policy.v1": ("policy_id", "policy_digest"),
        "omiv.quantization-policy-evaluation.v1": ("evaluation_id", "evaluation_digest"),
        "omiv.quantization-authority-evaluation.v1": (
            "authority_evaluation_id",
            "authority_evaluation_digest",
        ),
        "omiv.quantization-fidelity-evidence.v1": ("evidence_id", "evidence_digest"),
        "omiv.quantization-integration-summary.v1": ("integration_id", "integration_digest"),
        "omiv.quantization-fidelity-report.v1": ("report_id", "report_digest"),
        "omiv.quantization-example-catalog.v1": ("catalog_id", "catalog_digest"),
        "omiv.quantization-example-result.v1": ("result_id", "result_digest"),
    }
    fields = known.get(schema)
    if fields is None:
        pairs = tuple((k, v) for k, v in body.items() if k.endswith("_id"))
        digests = tuple((k, v) for k, v in body.items() if k.endswith("_digest"))
        if len(pairs) != 1 or len(digests) != 1:
            raise ValueError("canonical object does not expose exactly one identity pair")
        fields = pairs[0][0], digests[0][0]
    return ObjectReference(
        schema_id=schema,
        object_id=str(body[fields[0]]),
        object_digest=str(body[fields[1]]),
    )


def _require_reference_schema(reference: ObjectReference, expected: str) -> None:
    if reference.schema_id != expected:
        raise ValueError(f"canonical reference requires {expected}")


def _identity(value: QuantizationModel, id_field: str, prefix: str, digest_field: str) -> None:
    body: dict[str, Any] = value.model_dump(mode="json", by_alias=True)
    digest = str(body.pop(digest_field))
    identity = str(body.pop(id_field))
    expected_id = prefix + canonical_sha256(body)[:32]
    if identity != expected_id or digest != canonical_sha256({**body, id_field: expected_id}):
        raise ValueError("canonical identity or digest mismatch")


def finalize_identity(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    """Add the canonical ID and stored digest used by Phase 5/6 records."""
    value = _json_compatible(body)
    if not isinstance(value, dict):
        raise TypeError("canonical identity body must be an object")
    object_id = prefix + canonical_sha256(value)[:32]
    value[id_field] = object_id
    value[digest_field] = canonical_sha256(value)
    return value


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return {str(key): _json_compatible(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_json_compatible(child) for child in value]
    if isinstance(value, list):
        return [_json_compatible(child) for child in value]
    return value


def decimal_context() -> Context:
    """Return a fresh context independent of mutable process-global Decimal state."""
    context = Context(
        prec=DECIMAL_PRECISION,
        rounding=ROUND_HALF_EVEN,
        Emin=-MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT,
        Emax=MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT,
        capitals=1,
        clamp=0,
    )
    context.clear_flags()
    return context


def parse_bounded_decimal(
    value: str,
    *,
    maximum_adjusted_exponent: int = MAX_DECIMAL_INPUT_ADJUSTED_EXPONENT,
) -> Decimal:
    if not isinstance(value, str):
        raise ValueError("canonical numerical inputs must be strings")
    if len(value) > MAX_DECIMAL_INPUT_LENGTH:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_INPUT_LENGTH")
    if INPUT_DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid canonical numerical input")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("invalid canonical decimal") from exc
    if not parsed.is_finite():
        raise ValueError("non-finite canonical decimal")
    if len(parsed.as_tuple().digits) > MAX_DECIMAL_SIGNIFICANT_DIGITS:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_SIGNIFICANT_DIGITS")
    if parsed != 0 and abs(parsed.adjusted()) > maximum_adjusted_exponent:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_ADJUSTED_EXPONENT")
    return parsed


def _canonical_decimal_text(
    value: str,
    *,
    maximum_adjusted_exponent: int = MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT,
) -> str:
    parsed = parse_bounded_decimal(value, maximum_adjusted_exponent=maximum_adjusted_exponent)
    try:
        with localcontext(decimal_context()):
            parsed = +parsed
    except DecimalException as exc:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_INTERMEDIATE_MAGNITUDE") from exc
    if parsed == 0:
        return "0"
    rendered = format(parsed, "f")
    rendered = rendered.rstrip("0").rstrip(".") if "." in rendered else rendered
    if len(rendered) > MAX_DECIMAL_OUTPUT_LENGTH:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_OUTPUT_MAGNITUDE")
    return rendered
