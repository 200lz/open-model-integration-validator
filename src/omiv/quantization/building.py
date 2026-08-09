"""Canonical builders and evaluations for provider-neutral Phase 6C objects."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from decimal import Decimal, localcontext
from typing import Any, TypeVar, cast

from pydantic import BaseModel

from omiv.quantization.models import (
    MAX_LOGICAL_ELEMENTS_PER_TENSOR,
    ArtifactAvailability,
    ArtifactIdentity,
    AuthorityStatus,
    CoverageDimension,
    DeclarationProvenance,
    DeterministicSampleDefinition,
    ExpectationScope,
    FidelityThresholds,
    FindingKind,
    MappingNumericalStatus,
    NumericalFidelityMeasurement,
    NumericalStatus,
    ObjectReference,
    ObservationLevel,
    OverallEvidenceStatus,
    ParameterProvenance,
    PolicyRequirementResult,
    QuantizationAuthorityEvaluation,
    QuantizationExecutionRecord,
    QuantizationFidelityComparison,
    QuantizationFidelityEvidence,
    QuantizationFidelityPolicy,
    QuantizationFidelityReport,
    QuantizationFinding,
    QuantizationIntegrationSummary,
    QuantizationLimits,
    QuantizationObservationPlan,
    QuantizationParameterObservation,
    QuantizationPolicyEvaluation,
    QuantizationRelationshipDeclaration,
    RelationshipMode,
    RepresentationObservation,
    RequirementStatus,
    SchemeFamily,
    StructuralStatus,
    TensorCorrespondence,
    TensorMapping,
    TensorMetricSet,
    TensorRepresentationRecord,
    TensorRole,
    decimal_context,
    finalize_identity,
    object_reference,
    parse_bounded_decimal,
)
from omiv.runtime.models import ProductSubject, ScopeContext

ModelT = TypeVar("ModelT", bound=BaseModel)


def _build(
    model: type[ModelT], body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> ModelT:
    return model.model_validate(finalize_identity(body, id_field, prefix, digest_field))


def build_declaration(
    subject: ProductSubject,
    source: ArtifactIdentity,
    candidate: ArtifactIdentity,
    *,
    mode: RelationshipMode,
    provenance: DeclarationProvenance,
    authority: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    transformation_attestation: BaseModel | None = None,
    declared_at: str = "NOT_RECORDED",
    limitations: tuple[str, ...] = (),
) -> QuantizationRelationshipDeclaration:
    body = {
        "schema": "omiv.quantization-relationship-declaration.v1",
        "subject": subject,
        "scope": subject.scope,
        "relationship_mode": mode,
        "provenance": provenance,
        "source_artifact": source,
        "candidate_artifact": candidate,
        "transformation_attestation": transformation_attestation,
        "authority_status": authority,
        "declared_at": declared_at,
        "limitations": limitations,
    }
    return _build(
        QuantizationRelationshipDeclaration,
        body,
        "declaration_id",
        "quantization_declaration_",
        "declaration_digest",
    )


def build_plan(
    declaration: QuantizationRelationshipDeclaration,
    *,
    observation_level: ObservationLevel,
    expectation_scope: ExpectationScope,
    source_phase6a: ObjectReference | None = None,
    candidate_phase6a: ObjectReference | None = None,
    remote_phase6b: tuple[ObjectReference, ...] = (),
    deterministic_sample: DeterministicSampleDefinition | None = None,
    limits: QuantizationLimits | None = None,
    requested_at: str = "NOT_RECORDED",
    limitations: tuple[str, ...] = (),
) -> QuantizationObservationPlan:
    body = {
        "schema": "omiv.quantization-observation-plan.v1",
        "subject": declaration.subject,
        "scope": declaration.scope,
        "declaration": object_reference(declaration),
        "source_phase6a": source_phase6a,
        "candidate_phase6a": candidate_phase6a,
        "remote_phase6b": remote_phase6b,
        "requested_observation_level": observation_level,
        "expectation_scope": expectation_scope,
        "deterministic_sample": object_reference(deterministic_sample)
        if deterministic_sample
        else None,
        "limits": limits or QuantizationLimits(),
        "requested_at": requested_at,
        "network_use": "NONE",
        "model_execution": "NOT_PERFORMED",
        "limitations": limitations,
    }
    return _build(
        QuantizationObservationPlan,
        body,
        "plan_id",
        "quantization_plan_",
        "plan_digest",
    )


def build_execution(
    plan: QuantizationObservationPlan,
    *,
    supplied_inputs: tuple[ObjectReference, ...] = (),
    completion_state: str = "COMPLETE",
    tensors: int = 0,
    values: int = 0,
    payload_bytes: int = 0,
    failure_class: str = "NONE",
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    evaluated_at: str = "NOT_RECORDED",
    limitations: tuple[str, ...] = (),
) -> QuantizationExecutionRecord:
    body = {
        "schema": "omiv.quantization-execution-record.v1",
        "subject": plan.subject,
        "scope": plan.scope,
        "plan": object_reference(plan),
        "supplied_inputs": supplied_inputs,
        "tool_id": "omiv.quantization.offline-v1",
        "tool_version": "phase-6c-v1",
        "effective_limits": plan.limits,
        "completion_state": completion_state,
        "tensor_records_processed": tensors,
        "values_processed": values,
        "payload_bytes_read": payload_bytes,
        "network_use": "NONE",
        "model_execution": "NOT_PERFORMED",
        "available_at": available_at,
        "observed_at": observed_at,
        "evaluated_at": evaluated_at,
        "failure_class": failure_class,
        "result_reference_status": "LINKED_DOWNSTREAM_BY_OBSERVATIONS",
        "limitations": limitations,
    }
    return _build(
        QuantizationExecutionRecord,
        body,
        "execution_id",
        "quantization_execution_",
        "execution_digest",
    )


def build_tensor(
    *,
    artifact_identity: str,
    logical_name: str,
    role: TensorRole,
    shape: tuple[int, ...],
    storage_dtype: str,
    logical_dtype: str,
    quantization: BaseModel,
    observation_level: ObservationLevel,
    observed_element_count: int,
    provenance: ParameterProvenance,
    role_detail: str | None = None,
    byte_offset: int | None = None,
    byte_length: int | None = None,
    member_identity: str | None = None,
    content_digest: str | None = None,
    limitations: tuple[str, ...] = (),
) -> TensorRepresentationRecord:
    if len(shape) > 64:
        raise ValueError("LIMIT_EXCEEDED:TENSOR_RANK")
    elements = 1
    for dimension in shape:
        if dimension < 0:
            raise ValueError("tensor dimensions cannot be negative")
        if dimension > MAX_LOGICAL_ELEMENTS_PER_TENSOR:
            raise ValueError("LIMIT_EXCEEDED:TENSOR_DIMENSION")
        elements *= dimension
        if elements > MAX_LOGICAL_ELEMENTS_PER_TENSOR:
            raise ValueError("LIMIT_EXCEEDED:LOGICAL_ELEMENTS_PER_TENSOR")
    body = {
        "schema": "omiv.tensor-representation-record.v1",
        "artifact_identity": artifact_identity,
        "logical_name": logical_name,
        "role": role,
        "role_detail": role_detail,
        "shape": shape,
        "rank": len(shape),
        "logical_element_count": elements,
        "storage_dtype": storage_dtype,
        "logical_dtype": logical_dtype,
        "byte_offset": byte_offset,
        "byte_length": byte_length,
        "member_identity": member_identity,
        "content_digest": content_digest,
        "quantization": quantization,
        "observation_level": observation_level,
        "observed_element_count": observed_element_count,
        "provenance": provenance,
        "limitations": limitations,
    }
    return _build(
        TensorRepresentationRecord,
        body,
        "tensor_id",
        "quantization_tensor_",
        "tensor_digest",
    )


def build_observation(
    execution: QuantizationExecutionRecord,
    artifact: ArtifactIdentity,
    format_descriptor: BaseModel,
    tensors: Iterable[TensorRepresentationRecord],
    coverage: tuple[CoverageDimension, ...],
    *,
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    limitations: tuple[str, ...] = (),
) -> RepresentationObservation:
    ordered = tuple(sorted(tensors, key=lambda value: value.logical_name.encode()))
    body = {
        "schema": "omiv.representation-observation.v1",
        "subject": execution.subject,
        "scope": execution.scope,
        "execution": object_reference(execution),
        "representation_role": artifact.role,
        "artifact": artifact,
        "format_descriptor": format_descriptor,
        "tensors": ordered,
        "coverage": coverage,
        "available_at": available_at,
        "observed_at": observed_at,
        "limitations": limitations,
    }
    return _build(
        RepresentationObservation,
        body,
        "observation_id",
        "representation_observation_",
        "observation_digest",
    )


def build_mapping(
    source_tensor_ids: tuple[str, ...],
    candidate_tensor_ids: tuple[str, ...],
    *,
    cardinality: str,
    numerical_status: MappingNumericalStatus,
    reconstruction_recipe: ObjectReference | None = None,
    limitations: tuple[str, ...] = (),
) -> TensorMapping:
    body = {
        "source_tensor_ids": source_tensor_ids,
        "candidate_tensor_ids": candidate_tensor_ids,
        "cardinality": cardinality,
        "numerical_status": numerical_status,
        "reconstruction_recipe": reconstruction_recipe,
        "limitations": limitations,
    }
    return _build(TensorMapping, body, "mapping_id", "tensor_mapping_", "mapping_digest")


def build_correspondence(
    source: RepresentationObservation,
    candidate: RepresentationObservation,
    mappings: Iterable[TensorMapping],
    *,
    limitations: tuple[str, ...] = (),
) -> TensorCorrespondence:
    ordered = tuple(sorted(mappings, key=lambda value: value.mapping_id))
    body = {
        "schema": "omiv.tensor-correspondence.v1",
        "subject": source.subject,
        "scope": source.scope,
        "source_observation": object_reference(source),
        "candidate_observation": object_reference(candidate),
        "mappings": ordered,
        "mapping_semantics": "EXPLICIT_ONLY",
        "limitations": limitations,
    }
    return _build(
        TensorCorrespondence,
        body,
        "correspondence_id",
        "tensor_correspondence_",
        "correspondence_digest",
    )


def build_parameters(
    candidate: RepresentationObservation,
    tensor: TensorRepresentationRecord,
    *,
    scale: str | None,
    zero_point: int | None,
    provenance: ParameterProvenance,
    complete: bool,
    quantization_axis: int | None = None,
    group_size: int | None = None,
    block_size: int | None = None,
    limitations: tuple[str, ...] = (),
) -> QuantizationParameterObservation:
    descriptor = tensor.quantization
    body = {
        "schema": "omiv.quantization-parameter-observation.v1",
        "candidate_observation": object_reference(candidate),
        "tensor_id": tensor.tensor_id,
        "scheme_family": descriptor.scheme_family,
        "numerical_codec": descriptor.numerical_codec,
        "scale": scale,
        "zero_point": zero_point,
        "quantization_axis": quantization_axis,
        "group_size": group_size,
        "block_size": block_size,
        "storage_bit_width": descriptor.bit_width,
        "storage_signed": descriptor.signed,
        "provenance": provenance,
        "observation_level": descriptor.observation_level,
        "complete_for_supported_codec": complete,
        "limitations": limitations,
    }
    return _build(
        QuantizationParameterObservation,
        body,
        "parameter_observation_id",
        "quantization_parameters_",
        "parameter_observation_digest",
    )


def build_policy(
    scope: ScopeContext,
    *,
    name: str = "quantization.synthetic-fidelity-policy",
    allowed_schemes: tuple[SchemeFamily, ...] = (
        SchemeFamily.UNQUANTIZED,
        SchemeFamily.UNIFORM_AFFINE_INTEGER,
    ),
    allowed_storage_dtypes: tuple[str, ...] = ("float32", "int8", "uint8"),
    allowed_logical_dtypes: tuple[str, ...] = ("float32",),
    required_availability: str = "EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE",
    required_roles: tuple[TensorRole, ...] = (TensorRole.PRIMARY_WEIGHT,),
    minimum_tensor_coverage: str = "1",
    minimum_element_coverage: str = "1",
    minimum_byte_coverage: str = "0",
    minimum_parameter_coverage: str = "1",
    sampling_permitted: bool = True,
    maximum_sampling_gap: str = "0.99",
    thresholds: FidelityThresholds | None = None,
    source_authority_required: bool = False,
    candidate_authority_required: bool = False,
    transformation_authority_required: bool = False,
) -> QuantizationFidelityPolicy:
    body = {
        "schema": "omiv.quantization-fidelity-policy.v1",
        "policy_name": name,
        "evaluation_context": scope,
        "allowed_scheme_families": allowed_schemes,
        "allowed_storage_dtypes": allowed_storage_dtypes,
        "allowed_logical_dtypes": allowed_logical_dtypes,
        "required_artifact_availability": required_availability,
        "required_tensor_roles": required_roles,
        "minimum_tensor_coverage": minimum_tensor_coverage,
        "minimum_element_coverage": minimum_element_coverage,
        "minimum_byte_coverage": minimum_byte_coverage,
        "minimum_parameter_coverage": minimum_parameter_coverage,
        "deterministic_sampling_permitted": sampling_permitted,
        "maximum_sampling_gap": maximum_sampling_gap,
        "default_thresholds": thresholds
        or FidelityThresholds(
            maximum_absolute_error="0.25",
            maximum_mean_absolute_error="0.1",
            maximum_rmse="0.15",
            maximum_relative_l2_error="0.1",
            minimum_cosine_similarity="0.99",
            maximum_bias="0.1",
            maximum_quantization_bound_rate=None,
        ),
        "per_role_thresholds": (),
        "per_tensor_overrides": (),
        "non_finite_value_policy": "FAIL",
        "unsupported_format_behavior": "INDETERMINATE",
        "missing_source_behavior": "INDETERMINATE",
        "missing_candidate_behavior": "INDETERMINATE",
        "source_publisher_authority_required": source_authority_required,
        "candidate_publisher_authority_required": candidate_authority_required,
        "transformation_authority_required": transformation_authority_required,
        "limitations": (
            "Policy success is limited to the declared exact-identity and numerical scope.",
        ),
    }
    return _build(
        QuantizationFidelityPolicy,
        body,
        "policy_id",
        "quantization_policy_",
        "policy_digest",
    )


def build_measurement(
    source: RepresentationObservation,
    candidate: RepresentationObservation,
    correspondence: TensorCorrespondence,
    parameters: Iterable[QuantizationParameterObservation],
    metrics: Iterable[TensorMetricSet],
    coverage: tuple[CoverageDimension, ...],
    *,
    observation_level: ObservationLevel,
    sample: DeterministicSampleDefinition | None = None,
    failed_tensor_ids: tuple[str, ...] = (),
    limitations: tuple[str, ...] = (),
) -> NumericalFidelityMeasurement:
    metric_values = tuple(
        sorted(metrics, key=lambda value: (value.source_tensor_id, value.candidate_tensor_id))
    )
    if source.subject != candidate.subject or source.scope != candidate.scope:
        raise ValueError("measurement observations have different subject or scope")
    if correspondence.source_observation != object_reference(source):
        raise ValueError("measurement source observation reference mismatch")
    if correspondence.candidate_observation != object_reference(candidate):
        raise ValueError("measurement candidate observation reference mismatch")
    parameter_values = tuple(sorted(parameters, key=lambda value: value.parameter_observation_id))
    if any(
        value.candidate_observation != object_reference(candidate) for value in parameter_values
    ):
        raise ValueError("measurement parameter candidate reference mismatch")
    mapped_source = {
        item for mapping in correspondence.mappings for item in mapping.source_tensor_ids
    }
    mapped_candidate = {
        item for mapping in correspondence.mappings for item in mapping.candidate_tensor_ids
    }
    mapped_pairs = {
        (mapping.source_tensor_ids[0], mapping.candidate_tensor_ids[0])
        for mapping in correspondence.mappings
        if len(mapping.source_tensor_ids) == len(mapping.candidate_tensor_ids) == 1
        and mapping.numerical_status == MappingNumericalStatus.NUMERICALLY_EVALUABLE
    }
    if any(
        metric.source_tensor_id not in mapped_source
        or metric.candidate_tensor_id not in mapped_candidate
        or (metric.source_tensor_id, metric.candidate_tensor_id) not in mapped_pairs
        for metric in metric_values
    ):
        raise ValueError("measurement metric pair is absent from evaluable correspondence")
    candidate_tensor_ids = {value.tensor_id for value in candidate.tensors}
    if any(value.tensor_id not in candidate_tensor_ids for value in parameter_values):
        raise ValueError("measurement parameter tensor is absent from candidate observation")
    if sample is not None and (
        len(metric_values) != 1
        or metric_values[0].source_tensor_id != sample.source_tensor_id
        or metric_values[0].candidate_tensor_id != sample.candidate_tensor_id
    ):
        raise ValueError("sample definition does not bind the measured tensor pair")
    worst = [
        (Decimal(x.maximum_absolute_error.value), x.maximum_absolute_error.value)
        for x in metric_values
        if x.maximum_absolute_error.value is not None
    ]
    worst_value = max(worst, default=None)
    total_evaluated = sum(x.compared_element_count for x in metric_values)
    exact = bool(metric_values) and all(
        value.exact_equality_count == value.compared_element_count for value in metric_values
    )
    if not metric_values or total_evaluated == 0:
        status = NumericalStatus.INSUFFICIENT_NUMERICAL_COVERAGE
    elif observation_level == ObservationLevel.DETERMINISTIC_SAMPLE:
        status = NumericalStatus.SAMPLED_NUMERICALLY_EVALUATED
    elif exact:
        status = NumericalStatus.EXACT_FOR_EVALUATED_SCOPE
    else:
        status = NumericalStatus.NUMERICALLY_EVALUATED_FOR_SCOPE
    body = {
        "schema": "omiv.numerical-fidelity-measurement.v1",
        "subject": source.subject,
        "scope": source.scope,
        "source_observation": object_reference(source),
        "candidate_observation": object_reference(candidate),
        "correspondence": object_reference(correspondence),
        "parameter_observations": tuple(object_reference(x) for x in parameter_values),
        "sample_definition": object_reference(sample) if sample else None,
        "observation_level": observation_level,
        "decimal_precision": 50,
        "decimal_rounding": "ROUND_HALF_EVEN",
        "metrics": metric_values,
        "coverage": coverage,
        "worst_metric_name": "maximum_absolute_error" if worst_value else None,
        "worst_metric_value": worst_value[1] if worst_value else None,
        "failed_tensor_ids": tuple(sorted(failed_tensor_ids)),
        "weighted_aggregate_semantics": "Element-count weighting; per-tensor failures retained.",
        "unweighted_aggregate_semantics": "No aggregate average suppresses a tensor finding.",
        "total_evaluated_elements": total_evaluated,
        "status": status,
        "limitations": limitations,
    }
    return _build(
        NumericalFidelityMeasurement,
        body,
        "measurement_id",
        "quantization_measurement_",
        "measurement_digest",
    )


def compare_representations(
    declaration: QuantizationRelationshipDeclaration,
    source: RepresentationObservation,
    candidate: RepresentationObservation,
    correspondence: TensorCorrespondence,
    parameters: tuple[QuantizationParameterObservation, ...],
    measurements: tuple[NumericalFidelityMeasurement, ...],
    *,
    expectation_scope: ExpectationScope,
    coverage: tuple[CoverageDimension, ...],
    limitations: tuple[str, ...] = (),
) -> QuantizationFidelityComparison:
    if any(
        observation.subject != declaration.subject or observation.scope != declaration.scope
        for observation in (source, candidate)
    ):
        raise ValueError("comparison observation subject or scope differs from declaration")
    if declaration.source_artifact != source.artifact:
        raise ValueError("comparison source artifact differs from declaration")
    if declaration.candidate_artifact != candidate.artifact:
        raise ValueError("comparison candidate artifact differs from declaration")
    if correspondence.source_observation != object_reference(source):
        raise ValueError("comparison source observation reference mismatch")
    if correspondence.candidate_observation != object_reference(candidate):
        raise ValueError("comparison candidate observation reference mismatch")
    if any(value.candidate_observation != object_reference(candidate) for value in parameters):
        raise ValueError("comparison parameter candidate reference mismatch")
    parameter_values = tuple(sorted(parameters, key=lambda value: value.parameter_observation_id))
    measurement_values = tuple(sorted(measurements, key=lambda value: value.measurement_id))
    parameter_refs = tuple(object_reference(value) for value in parameter_values)
    for measurement in measurement_values:
        if (
            measurement.source_observation != object_reference(source)
            or measurement.candidate_observation != object_reference(candidate)
            or measurement.correspondence != object_reference(correspondence)
            or measurement.parameter_observations != parameter_refs
        ):
            raise ValueError("comparison measurement upstream reference mismatch")
    source_tensors = {x.tensor_id: x for x in source.tensors}
    candidate_tensors = {x.tensor_id: x for x in candidate.tensors}
    findings: list[QuantizationFinding] = []
    structural = StructuralStatus.STRUCTURALLY_CONSISTENT_FOR_SCOPE
    for mapping in correspondence.mappings:
        if mapping.cardinality.value == "AMBIGUOUS":
            structural = StructuralStatus.TENSOR_MAPPING_AMBIGUOUS
            findings.append(
                QuantizationFinding(
                    kind=FindingKind.MAPPING_AMBIGUOUS,
                    status="FAIL",
                    tensor_ids=(*mapping.source_tensor_ids, *mapping.candidate_tensor_ids),
                    detail="Explicit correspondence is ambiguous.",
                )
            )
        elif mapping.numerical_status != MappingNumericalStatus.NUMERICALLY_EVALUABLE:
            if structural == StructuralStatus.STRUCTURALLY_CONSISTENT_FOR_SCOPE:
                structural = StructuralStatus.STRUCTURAL_INFORMATION_INCOMPLETE
            findings.append(
                QuantizationFinding(
                    kind=FindingKind.MAPPING_RECIPE_UNAVAILABLE,
                    status="INCOMPLETE",
                    tensor_ids=(*mapping.source_tensor_ids, *mapping.candidate_tensor_ids),
                    detail="Structural mapping has no supported numerical reconstruction recipe.",
                )
            )
        if len(mapping.source_tensor_ids) == len(mapping.candidate_tensor_ids) == 1:
            left = source_tensors.get(mapping.source_tensor_ids[0])
            right = candidate_tensors.get(mapping.candidate_tensor_ids[0])
            if left and right:
                if left.shape != right.shape:
                    structural = StructuralStatus.STRUCTURAL_MISMATCH
                    findings.append(
                        QuantizationFinding(
                            kind=FindingKind.SHAPE_MISMATCH,
                            status="FAIL",
                            tensor_ids=(left.tensor_id, right.tensor_id),
                            detail=(
                                f"Source shape {left.shape} differs from candidate {right.shape}."
                            ),
                        )
                    )
                if left.logical_dtype != right.logical_dtype:
                    structural = StructuralStatus.STRUCTURAL_MISMATCH
                    findings.append(
                        QuantizationFinding(
                            kind=FindingKind.LOGICAL_DTYPE_MISMATCH,
                            status="FAIL",
                            tensor_ids=(left.tensor_id, right.tensor_id),
                            detail="Logical reconstructed dtypes differ.",
                        )
                    )
    if any(not x.complete_for_supported_codec for x in parameter_values):
        if structural == StructuralStatus.STRUCTURALLY_CONSISTENT_FOR_SCOPE:
            structural = StructuralStatus.QUANTIZATION_PARAMETERS_INCOMPLETE
        findings.append(
            QuantizationFinding(
                kind=FindingKind.QUANTIZATION_PARAMETERS_MISSING,
                status="INCOMPLETE",
                tensor_ids=tuple(
                    x.tensor_id for x in parameter_values if not x.complete_for_supported_codec
                ),
                detail="One or more supported-codec parameter records are incomplete.",
            )
        )
    if measurement_values:
        statuses = {value.status for value in measurement_values}
        if NumericalStatus.INVALID in statuses:
            numerical = NumericalStatus.INVALID
        elif NumericalStatus.INSUFFICIENT_NUMERICAL_COVERAGE in statuses:
            numerical = NumericalStatus.INSUFFICIENT_NUMERICAL_COVERAGE
        elif NumericalStatus.FORMAT_NOT_NUMERICALLY_SUPPORTED in statuses:
            numerical = NumericalStatus.FORMAT_NOT_NUMERICALLY_SUPPORTED
        elif expectation_scope == ExpectationScope.DETERMINISTIC_SAMPLE_SCOPE:
            numerical = NumericalStatus.SAMPLED_NUMERICALLY_EVALUATED
        elif statuses == {NumericalStatus.EXACT_FOR_EVALUATED_SCOPE}:
            numerical = NumericalStatus.EXACT_FOR_EVALUATED_SCOPE
        else:
            numerical = NumericalStatus.NUMERICALLY_EVALUATED_FOR_SCOPE
        for measurement in measurement_values:
            for metric in measurement.metrics:
                if metric.exact_equality_count != metric.compared_element_count:
                    findings.append(
                        QuantizationFinding(
                            kind=FindingKind.NUMERICAL_DIFFERENCE_OBSERVED,
                            status="OBSERVED",
                            tensor_ids=(metric.source_tensor_id, metric.candidate_tensor_id),
                            detail="A numerical difference was observed; policy evaluates it.",
                        )
                    )
    else:
        numerical = NumericalStatus.PAYLOAD_VALUES_UNAVAILABLE
        findings.append(
            QuantizationFinding(
                kind=FindingKind.PAYLOAD_VALUES_UNAVAILABLE,
                status="NOT_EVALUATED",
                tensor_ids=(),
                detail="No exact source/candidate numerical values were supplied.",
            )
        )
    body = {
        "schema": "omiv.quantization-fidelity-comparison.v1",
        "subject": declaration.subject,
        "scope": declaration.scope,
        "declaration": object_reference(declaration),
        "source_observation": object_reference(source),
        "candidate_observation": object_reference(candidate),
        "correspondence": object_reference(correspondence),
        "parameter_observations": parameter_refs,
        "measurements": tuple(object_reference(x) for x in measurement_values),
        "expectation_scope": expectation_scope,
        "structural_status": structural,
        "numerical_status": numerical,
        "findings": tuple(findings),
        "coverage": coverage,
        "complete_model_equivalence_claimed": False,
        "behavioral_equivalence_claimed": False,
        "limitations": limitations,
    }
    return _build(
        QuantizationFidelityComparison,
        body,
        "comparison_id",
        "quantization_comparison_",
        "comparison_digest",
    )


def _coverage_ratio(coverage: Sequence[CoverageDimension], dimension: str) -> Decimal | None:
    value = next((x for x in coverage if x.dimension == dimension), None)
    if value is None or value.denominator is None:
        return None
    if value.denominator == 0:
        return None
    with localcontext(decimal_context()):
        return Decimal(value.numerator) / Decimal(value.denominator)


def evaluate_policy(
    policy: QuantizationFidelityPolicy,
    comparison: QuantizationFidelityComparison,
    measurement: NumericalFidelityMeasurement | None,
    candidate: RepresentationObservation,
    authority: QuantizationAuthorityEvaluation | None = None,
    *,
    declaration: QuantizationRelationshipDeclaration,
    evaluated_at: str = "NOT_RECORDED",
) -> QuantizationPolicyEvaluation:
    if object_reference(declaration) != comparison.declaration:
        raise ValueError("policy declaration is not bound by comparison")
    if measurement is not None and object_reference(measurement) not in comparison.measurements:
        raise ValueError("policy measurement is not bound by comparison")
    if authority is not None and authority.declaration != comparison.declaration:
        raise ValueError("policy authority context references another declaration")
    requirements: list[PolicyRequirementResult] = []

    def add(
        name: str,
        ok: bool | None,
        observed: str | None,
        required: str,
        *,
        status_override: RequirementStatus | None = None,
        tensor_ids: tuple[str, ...] = (),
    ) -> None:
        status = status_override or (
            RequirementStatus.POLICY_REQUIREMENT_NOT_EVALUATED
            if ok is None
            else RequirementStatus.POLICY_REQUIREMENT_SATISFIED
            if ok
            else RequirementStatus.POLICY_REQUIREMENT_FAILED
        )
        requirements.append(
            PolicyRequirementResult(
                requirement=name,
                status=status,
                observed_value=observed,
                required_value=required,
                tensor_ids=tensor_ids,
                detail=f"{name} was evaluated without strengthening evidence scope.",
            )
        )

    add(
        "scheme.family",
        candidate.format_descriptor.scheme_family in policy.allowed_scheme_families,
        candidate.format_descriptor.scheme_family.value,
        ",".join(x.value for x in policy.allowed_scheme_families),
    )
    availability_order = {
        "EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE": 6,
        "REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE": 5,
        "REMOTE_NON_PAYLOAD_IDENTITY_ONLY": 4,
        "METADATA_IDENTITY_ONLY": 3,
        "DIGEST_REFERENCE_ONLY": 2,
        "ARTIFACT_NOT_SUPPLIED": 1,
        "IDENTITY_UNAVAILABLE": 0,
        "IDENTITY_INVALID": 0,
    }
    actual_availability = candidate.artifact.availability.value
    required_availability = policy.required_artifact_availability.value
    add(
        "artifact.identity-level",
        availability_order[actual_availability] >= availability_order[required_availability],
        actual_availability,
        required_availability,
    )
    missing_states = {
        ArtifactAvailability.ARTIFACT_NOT_SUPPLIED,
        ArtifactAvailability.IDENTITY_UNAVAILABLE,
        ArtifactAvailability.IDENTITY_INVALID,
    }
    for label, artifact, behavior in (
        ("source", declaration.source_artifact, policy.missing_source_behavior),
        ("candidate", declaration.candidate_artifact, policy.missing_candidate_behavior),
    ):
        missing = artifact.availability in missing_states
        add(
            f"artifact.{label}.available",
            (not missing) if behavior == "FAIL" else None if missing else True,
            artifact.availability.value,
            behavior,
        )
    unsupported = comparison.structural_status == StructuralStatus.FORMAT_UNSUPPORTED or (
        comparison.numerical_status == NumericalStatus.FORMAT_NOT_NUMERICALLY_SUPPORTED
    )
    add(
        "format.supported",
        (not unsupported)
        if policy.unsupported_format_behavior == "FAIL"
        else None
        if unsupported
        else True,
        comparison.numerical_status.value,
        policy.unsupported_format_behavior,
    )
    observed_roles = {x.role for x in candidate.tensors}
    add(
        "scope.non-empty-candidate-tensors",
        bool(candidate.tensors),
        str(len(candidate.tensors)),
        "at-least-one",
    )
    numerically_positive = comparison.numerical_status in {
        NumericalStatus.EXACT_FOR_EVALUATED_SCOPE,
        NumericalStatus.NUMERICALLY_EVALUATED_FOR_SCOPE,
        NumericalStatus.SAMPLED_NUMERICALLY_EVALUATED,
    }
    evaluated_elements = 0 if measurement is None else measurement.total_evaluated_elements
    add(
        "scope.non-empty-numerical-elements",
        evaluated_elements > 0 if numerically_positive else None,
        str(evaluated_elements),
        "at-least-one",
    )
    missing_roles = set(policy.required_tensor_roles) - observed_roles
    add(
        "tensor.required-roles",
        not missing_roles,
        ",".join(sorted(x.value for x in observed_roles)),
        ",".join(x.value for x in policy.required_tensor_roles),
    )
    add(
        "storage.dtype",
        all(x.storage_dtype in policy.allowed_storage_dtypes for x in candidate.tensors),
        ",".join(sorted({x.storage_dtype for x in candidate.tensors})),
        ",".join(policy.allowed_storage_dtypes),
    )
    add(
        "logical.dtype",
        all(x.logical_dtype in policy.allowed_logical_dtypes for x in candidate.tensors),
        ",".join(sorted({x.logical_dtype for x in candidate.tensors})),
        ",".join(policy.allowed_logical_dtypes),
    )
    coverage_requirements = (
        ("coverage.tensor", "NUMERICAL_TENSOR", policy.minimum_tensor_coverage),
        ("coverage.element", "NUMERICAL_ELEMENT", policy.minimum_element_coverage),
        ("coverage.byte", "BYTE", policy.minimum_byte_coverage),
        ("coverage.parameter", "QUANTIZATION_PARAMETER", policy.minimum_parameter_coverage),
    )
    for name, dimension, minimum in coverage_requirements:
        ratio = _coverage_ratio(comparison.coverage, dimension)
        minimum_value = parse_bounded_decimal(minimum)
        if ratio is None and minimum_value == 0:
            add(
                name,
                None,
                "UNAVAILABLE_NOT_REQUIRED",
                minimum,
                status_override=RequirementStatus.POLICY_REQUIREMENT_NOT_APPLICABLE,
            )
        else:
            add(
                name,
                None if ratio is None else ratio >= minimum_value,
                None if ratio is None else str(ratio),
                minimum,
            )
    if comparison.expectation_scope == ExpectationScope.DETERMINISTIC_SAMPLE_SCOPE:
        add(
            "sampling.permitted",
            policy.deterministic_sampling_permitted,
            "true",
            str(policy.deterministic_sampling_permitted).lower(),
        )
        sampling_ratio = _coverage_ratio(comparison.coverage, "SAMPLING")
        sampling_gap = None if sampling_ratio is None else Decimal(1) - sampling_ratio
        maximum_gap = parse_bounded_decimal(policy.maximum_sampling_gap)
        add(
            "sampling.maximum-gap",
            None if sampling_gap is None else sampling_gap <= maximum_gap,
            None if sampling_gap is None else str(+sampling_gap),
            policy.maximum_sampling_gap,
        )
    metric_fields = {
        "maximum_absolute_error": ("maximum_absolute_error", False),
        "maximum_mean_absolute_error": ("mean_absolute_error", False),
        "maximum_rmse": ("root_mean_squared_error", False),
        "maximum_relative_l2_error": ("relative_l2_error", False),
        "minimum_cosine_similarity": ("cosine_similarity", True),
        "maximum_bias": ("signed_mean_error", False),
        "maximum_quantization_bound_rate": ("__quantization_bound_rate__", False),
    }
    metrics_by_candidate = (
        {} if measurement is None else {x.candidate_tensor_id: x for x in measurement.metrics}
    )
    role_by_tensor = {x.tensor_id: x.role for x in candidate.tensors}

    role_thresholds = {value.role: value.thresholds for value in policy.per_role_thresholds}
    tensor_thresholds = {value.tensor_id: value.thresholds for value in policy.per_tensor_overrides}

    def thresholds_for_role(tensor_id: str) -> FidelityThresholds:
        role = role_by_tensor.get(tensor_id)
        if role is None:
            return FidelityThresholds()
        return role_thresholds.get(role, FidelityThresholds())

    def metric_value(tensor_id: str, field_name: str) -> Decimal | None:
        metric = metrics_by_candidate.get(tensor_id)
        if metric is None:
            return None
        if field_name == "__quantization_bound_rate__":
            if metric.at_quantization_bound_count is None or metric.compared_element_count == 0:
                return None
            with localcontext(decimal_context()):
                return Decimal(metric.at_quantization_bound_count) / Decimal(
                    metric.compared_element_count
                )
        value = getattr(metric, field_name).value
        return (
            None if value is None else parse_bounded_decimal(value, maximum_adjusted_exponent=640)
        )

    def apply_threshold_set(
        prefix: str,
        threshold_set: FidelityThresholds,
        tensor_ids: tuple[str, ...],
        *,
        excluded_by_precedence: bool = False,
    ) -> None:
        for threshold_name, (field_name, minimum_required) in metric_fields.items():
            threshold_value = getattr(threshold_set, threshold_name)
            if threshold_value is None:
                continue
            comparable_values = [
                value
                for tensor_id in tensor_ids
                if (value := metric_value(tensor_id, field_name)) is not None
            ]
            if not comparable_values:
                add(
                    f"{prefix}.{threshold_name}",
                    None,
                    None,
                    threshold_value,
                    status_override=(
                        RequirementStatus.POLICY_REQUIREMENT_NOT_APPLICABLE
                        if excluded_by_precedence
                        else None
                    ),
                    tensor_ids=tensor_ids,
                )
                continue
            observed_value = (
                min(comparable_values)
                if minimum_required
                else max(abs(value) for value in comparable_values)
            )
            add(
                f"{prefix}.{threshold_name}",
                observed_value >= parse_bounded_decimal(threshold_value)
                if minimum_required
                else observed_value <= parse_bounded_decimal(threshold_value),
                str(+observed_value),
                threshold_value,
                tensor_ids=tensor_ids,
            )

    all_metric_tensor_ids = tuple(sorted(metrics_by_candidate))
    for threshold_name in metric_fields:
        if getattr(policy.default_thresholds, threshold_name) is None:
            continue
        eligible = tuple(
            tensor_id
            for tensor_id in all_metric_tensor_ids
            if getattr(tensor_thresholds.get(tensor_id, FidelityThresholds()), threshold_name)
            is None
            and getattr(thresholds_for_role(tensor_id), threshold_name) is None
        )
        single = FidelityThresholds(
            **{threshold_name: getattr(policy.default_thresholds, threshold_name)}
        )
        apply_threshold_set(
            "metric.default",
            single,
            eligible,
            excluded_by_precedence=bool(all_metric_tensor_ids and not eligible),
        )

    for role_threshold in policy.per_role_thresholds:
        role_tensor_ids = tuple(
            sorted(
                tensor_id
                for tensor_id, role in role_by_tensor.items()
                if role == role_threshold.role
            )
        )
        eligible_by_field: dict[str, tuple[str, ...]] = {
            name: tuple(
                tensor_id
                for tensor_id in role_tensor_ids
                if getattr(tensor_thresholds.get(tensor_id, FidelityThresholds()), name) is None
            )
            for name in metric_fields
        }
        for threshold_name in metric_fields:
            threshold_value = getattr(role_threshold.thresholds, threshold_name)
            if threshold_value is None:
                continue
            apply_threshold_set(
                f"role.{role_threshold.role.value.lower()}",
                FidelityThresholds(**{threshold_name: threshold_value}),
                eligible_by_field[threshold_name],
                excluded_by_precedence=bool(
                    role_tensor_ids and not eligible_by_field[threshold_name]
                ),
            )
    for tensor_threshold in policy.per_tensor_overrides:
        apply_threshold_set(
            f"tensor.{tensor_threshold.tensor_id}",
            tensor_threshold.thresholds,
            (tensor_threshold.tensor_id,),
        )
    if measurement is not None and policy.non_finite_value_policy == "FAIL":
        non_finite = sum(
            metric.non_finite_source_count + metric.non_finite_reconstructed_count
            for metric in measurement.metrics
        )
        add("non-finite.values", non_finite == 0, str(non_finite), "0")
    if policy.source_publisher_authority_required:
        add(
            "authority.source.publisher",
            None
            if authority is None
            else authority.source_publisher_authority == AuthorityStatus.ESTABLISHED,
            None if authority is None else authority.source_publisher_authority.value,
            AuthorityStatus.ESTABLISHED.value,
        )
    if policy.candidate_publisher_authority_required:
        add(
            "authority.candidate.publisher",
            None
            if authority is None
            else authority.candidate_publisher_authority == AuthorityStatus.ESTABLISHED,
            None if authority is None else authority.candidate_publisher_authority.value,
            AuthorityStatus.ESTABLISHED.value,
        )
    if policy.transformation_authority_required:
        add(
            "authority.transformation",
            None
            if authority is None
            else authority.transformation_authority == AuthorityStatus.ESTABLISHED,
            None if authority is None else authority.transformation_authority.value,
            AuthorityStatus.ESTABLISHED.value,
        )
    failed = any(x.status == RequirementStatus.POLICY_REQUIREMENT_FAILED for x in requirements)
    pending = any(
        x.status
        in {
            RequirementStatus.POLICY_REQUIREMENT_NOT_EVALUATED,
            RequirementStatus.POLICY_REQUIREMENT_INVALID,
        }
        for x in requirements
    )
    satisfied = bool(requirements) and not failed and not pending
    overall = (
        OverallEvidenceStatus.CONFORMS_FOR_DECLARED_SCOPE
        if satisfied
        else OverallEvidenceStatus.DOES_NOT_CONFORM_FOR_DECLARED_SCOPE
        if failed
        else OverallEvidenceStatus.INDETERMINATE
    )
    body = {
        "schema": "omiv.quantization-policy-evaluation.v1",
        "subject": comparison.subject,
        "scope": comparison.scope,
        "policy": object_reference(policy),
        "comparison": object_reference(comparison),
        "authority_evaluation": object_reference(authority) if authority else None,
        "requirements": tuple(requirements),
        "policy_satisfied_for_declared_scope": satisfied,
        "overall_status": overall,
        "evaluated_at": evaluated_at,
        "limitations": ("A policy result is scope-qualified and is not deployment approval.",),
    }
    return _build(
        QuantizationPolicyEvaluation,
        body,
        "evaluation_id",
        "quantization_policy_evaluation_",
        "evaluation_digest",
    )


def build_authority_evaluation(
    declaration: QuantizationRelationshipDeclaration,
    *,
    source_publisher: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    candidate_publisher: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    transformation: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    expectation_publisher: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    measurement_signature: str = "SIGNATURE_NOT_SUPPLIED",
    measurement_signer_trust: str = "NOT_EVALUATED",
    measurement_signer_authorized: str = "NOT_EVALUATED",
    policy_authority: AuthorityStatus = AuthorityStatus.NOT_EVALUATED,
    subject_scope_authorized: bool = False,
    limitations: tuple[str, ...] = (),
) -> QuantizationAuthorityEvaluation:
    body = {
        "schema": "omiv.quantization-authority-evaluation.v1",
        "subject": declaration.subject,
        "scope": declaration.scope,
        "declaration": object_reference(declaration),
        "source_publisher_authority": source_publisher,
        "candidate_publisher_authority": candidate_publisher,
        "transformation_authority": transformation,
        "expectation_publisher_authority": expectation_publisher,
        "measurement_signature_status": measurement_signature,
        "measurement_signer_trust": measurement_signer_trust,
        "measurement_signer_authorized": measurement_signer_authorized,
        "policy_authority": policy_authority,
        "subject_scope_authorized": subject_scope_authorized,
        "namespace_creates_authority": False,
        "signature_creates_publisher_authority": False,
        "limitations": limitations,
    }
    return _build(
        QuantizationAuthorityEvaluation,
        body,
        "authority_evaluation_id",
        "quantization_authority_",
        "authority_evaluation_digest",
    )


def build_evidence(
    comparison: QuantizationFidelityComparison,
    policy_evaluation: QuantizationPolicyEvaluation,
    authority: QuantizationAuthorityEvaluation,
    *,
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    evaluated_at: str = "NOT_RECORDED",
    limitations: tuple[str, ...] = (),
) -> QuantizationFidelityEvidence:
    if policy_evaluation.comparison != object_reference(comparison):
        raise ValueError("evidence policy evaluation references another comparison")
    if authority.declaration != comparison.declaration:
        raise ValueError("evidence authority evaluation references another declaration")
    if any(
        value != comparison.subject or scope != comparison.scope
        for value, scope in (
            (policy_evaluation.subject, policy_evaluation.scope),
            (authority.subject, authority.scope),
        )
    ):
        raise ValueError("evidence upstream subject or scope mismatch")
    status = policy_evaluation.overall_status
    if comparison.numerical_status in {
        NumericalStatus.NOT_EVALUATED,
        NumericalStatus.PAYLOAD_VALUES_UNAVAILABLE,
        NumericalStatus.FORMAT_NOT_NUMERICALLY_SUPPORTED,
        NumericalStatus.INSUFFICIENT_NUMERICAL_COVERAGE,
    }:
        status = OverallEvidenceStatus.NOT_EVALUATED
    numerical_status = comparison.numerical_status
    if comparison.numerical_status == NumericalStatus.NUMERICALLY_EVALUATED_FOR_SCOPE:
        numerical_status = (
            NumericalStatus.WITHIN_POLICY_FOR_EVALUATED_SCOPE
            if policy_evaluation.policy_satisfied_for_declared_scope
            else NumericalStatus.OUTSIDE_POLICY_FOR_EVALUATED_SCOPE
        )
    elif comparison.numerical_status == NumericalStatus.SAMPLED_NUMERICALLY_EVALUATED:
        numerical_status = (
            NumericalStatus.SAMPLED_WITHIN_POLICY
            if policy_evaluation.policy_satisfied_for_declared_scope
            else NumericalStatus.SAMPLED_OUTSIDE_POLICY
        )
    body = {
        "schema": "omiv.quantization-fidelity-evidence.v1",
        "subject": comparison.subject,
        "scope": comparison.scope,
        "comparison": object_reference(comparison),
        "policy_evaluation": object_reference(policy_evaluation),
        "authority_evaluation": object_reference(authority),
        "overall_status": status,
        "structural_status": comparison.structural_status,
        "numerical_status": numerical_status,
        "expectation_scope": comparison.expectation_scope,
        "coverage": comparison.coverage,
        "policy_satisfied_for_declared_scope": (
            policy_evaluation.policy_satisfied_for_declared_scope
        ),
        "authority_established": all(
            x == AuthorityStatus.ESTABLISHED
            for x in (
                authority.source_publisher_authority,
                authority.candidate_publisher_authority,
                authority.transformation_authority,
            )
        ),
        "model_correctness": "NOT_ESTABLISHED",
        "behavioral_parity": "NOT_EVALUATED",
        "security_safety": "NOT_EVALUATED",
        "runtime_identity": "NOT_OBSERVED",
        "available_at": available_at,
        "observed_at": observed_at,
        "evaluated_at": evaluated_at,
        "limitations": limitations,
    }
    return _build(
        QuantizationFidelityEvidence,
        body,
        "evidence_id",
        "quantization_evidence_",
        "evidence_digest",
    )


def build_report(
    evidence: QuantizationFidelityEvidence,
    comparison: QuantizationFidelityComparison,
    policy_evaluation: QuantizationPolicyEvaluation,
    authority: QuantizationAuthorityEvaluation,
    *,
    finding_limit: int = 100,
) -> QuantizationFidelityReport:
    if evidence.comparison != object_reference(comparison):
        raise ValueError("report evidence references another comparison")
    if evidence.policy_evaluation != object_reference(policy_evaluation):
        raise ValueError("report evidence references another policy evaluation")
    if evidence.authority_evaluation != object_reference(authority):
        raise ValueError("report evidence references another authority evaluation")
    total = len(comparison.findings) + len(policy_evaluation.requirements)
    included = min(total, finding_limit)
    body = {
        "schema": "omiv.quantization-fidelity-report.v1",
        "evidence": object_reference(evidence),
        "comparison": object_reference(comparison),
        "policy_evaluation": object_reference(policy_evaluation),
        "authority_evaluation": object_reference(authority),
        "overall_status": evidence.overall_status,
        "structural_status": evidence.structural_status,
        "numerical_status": evidence.numerical_status,
        "expectation_scope": evidence.expectation_scope,
        "total_finding_count": total,
        "included_finding_count": included,
        "omitted_finding_count": total - included,
        "finding_selection_rule": "CANONICAL_ORDER_PREFIX",
        "truncation_status": "TRUNCATED" if total > included else "NOT_TRUNCATED",
        "limitations": (
            "Report presentation is derived and does not feed canonical evidence identity.",
        ),
    }
    return _build(
        QuantizationFidelityReport,
        body,
        "report_id",
        "quantization_report_",
        "report_digest",
    )


def build_integration(
    evidence: QuantizationFidelityEvidence,
    integration_type: str,
    *,
    source_object: ObjectReference | None = None,
    subject_identity_match: bool | None = None,
    payload_identity_match: bool | None = None,
    derived_status: str,
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    evaluated_at: str = "NOT_RECORDED",
    limitations: tuple[str, ...] = (),
) -> QuantizationIntegrationSummary:
    if (
        integration_type in {"SECURITY", "RUNTIME", "GOVERNANCE"}
        and source_object is not None
        and (subject_identity_match is not True or payload_identity_match is not True)
    ):
        raise ValueError("cross-phase evidence identity mismatch")
    body = {
        "schema": "omiv.quantization-integration-summary.v1",
        "integration_type": integration_type,
        "evidence": object_reference(evidence),
        "source_object": source_object,
        "subject_identity_match": subject_identity_match,
        "payload_identity_match": payload_identity_match,
        "derived_status": derived_status,
        "creates_governance_approval": False,
        "creates_security_pass": False,
        "creates_observed_runtime_identity": False,
        "mutates_prior_artifact": False,
        "available_at": available_at,
        "observed_at": observed_at,
        "evaluated_at": evaluated_at,
        "limitations": limitations,
    }
    return _build(
        QuantizationIntegrationSummary,
        body,
        "integration_id",
        "quantization_integration_",
        "integration_digest",
    )


def reference(value: BaseModel) -> ObjectReference:
    return object_reference(cast(Any, value))
