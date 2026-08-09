"""Deterministic Phase 6C examples, including outward-only practice profiles."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.payload_integrity.building import build_plan as build_payload_plan
from omiv.payload_integrity.models import (
    ObservedPayloadManifest,
    PayloadHashExecutionRecord,
    RootMode,
)
from omiv.payload_integrity.observation import observe_payload
from omiv.quantization.building import (
    build_authority_evaluation,
    build_correspondence,
    build_declaration,
    build_evidence,
    build_execution,
    build_integration,
    build_mapping,
    build_measurement,
    build_observation,
    build_parameters,
    build_plan,
    build_policy,
    build_report,
    build_tensor,
    compare_representations,
    evaluate_policy,
)
from omiv.quantization.models import (
    ArtifactAvailability,
    ArtifactIdentity,
    ArtifactRole,
    CoverageDimension,
    DeclarationProvenance,
    ExpectationScope,
    MappingNumericalStatus,
    NumericalCodec,
    NumericalStatus,
    ObjectReference,
    ObservationLevel,
    ParameterProvenance,
    QuantizationArtifactIndex,
    QuantizationArtifactIndexEntry,
    QuantizationDescriptor,
    QuantizationExampleCase,
    QuantizationExampleCatalog,
    QuantizationExampleResult,
    QuantizationFidelityEvidence,
    RelationshipMode,
    SchemeFamily,
    StructuralStatus,
    TensorRole,
    finalize_identity,
    object_reference,
)
from omiv.quantization.numerical import measure_values, reconstruct_values
from omiv.quantization.reporting import pretty_json, render_markdown
from omiv.quantization.sampling import build_sample_definition
from omiv.quantization_profiles.models import XaiQuantizationReadiness
from omiv.quantization_profiles.xai import build_xai_readiness, render_xai_case_study
from omiv.reconciliation.models import RemoteSnapshotManifest
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubject, ProductSubjectClass
from omiv.safe_write import atomic_write_text
from omiv.trust.models import (
    BindingStatus,
    SignaturePurpose,
    SignedObjectType,
    SignerIdentityKind,
)
from omiv.trust.signing import (
    build_binding,
    build_descriptor,
    build_key_identity,
    build_signature_record,
    build_signed_envelope,
    build_signer_identity,
    build_trust_bundle,
    build_trust_root,
)
from omiv.trust.signing import build_policy as build_trust_policy
from omiv.trust.verification import verify_envelope


def _write(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, pretty_json(value))


def _coverage(
    *,
    tensors: tuple[int, int] = (1, 1),
    elements: tuple[int, int] = (4, 4),
    byte_counts: tuple[int, int] | None = None,
    parameters: tuple[int, int] = (1, 1),
    sampled: tuple[int, int] | None = None,
) -> tuple[CoverageDimension, ...]:
    result = [
        CoverageDimension(
            dimension="SOURCE_ARTIFACT", numerator=1, denominator=1, status="COMPLETE"
        ),
        CoverageDimension(
            dimension="CANDIDATE_ARTIFACT", numerator=1, denominator=1, status="COMPLETE"
        ),
        CoverageDimension(
            dimension="SOURCE_TENSOR",
            numerator=tensors[0],
            denominator=tensors[1],
            status="COMPLETE" if tensors[0] == tensors[1] else "PARTIAL",
            incomplete_reason=None if tensors[0] == tensors[1] else "Selected tensor scope.",
        ),
        CoverageDimension(
            dimension="CANDIDATE_TENSOR",
            numerator=tensors[0],
            denominator=tensors[1],
            status="COMPLETE" if tensors[0] == tensors[1] else "PARTIAL",
            incomplete_reason=None if tensors[0] == tensors[1] else "Selected tensor scope.",
        ),
        CoverageDimension(
            dimension="MAPPED_TENSOR",
            numerator=tensors[0],
            denominator=tensors[1],
            status="COMPLETE" if tensors[0] == tensors[1] else "PARTIAL",
            incomplete_reason=None if tensors[0] == tensors[1] else "Selected tensor scope.",
        ),
        CoverageDimension(
            dimension="MANDATORY_ROLE",
            numerator=tensors[0],
            denominator=tensors[1],
            status="COMPLETE" if tensors[0] == tensors[1] else "PARTIAL",
            incomplete_reason=None if tensors[0] == tensors[1] else "Mandatory tensor unavailable.",
        ),
        CoverageDimension(
            dimension="NUMERICAL_TENSOR",
            numerator=tensors[0],
            denominator=tensors[1],
            status="COMPLETE" if tensors[0] == tensors[1] else "PARTIAL",
            incomplete_reason=None
            if tensors[0] == tensors[1]
            else "Numerical tensor coverage is selected.",
        ),
        CoverageDimension(
            dimension="NUMERICAL_ELEMENT",
            numerator=elements[0],
            denominator=elements[1],
            status="COMPLETE" if elements[0] == elements[1] else "PARTIAL",
            incomplete_reason=None if elements[0] == elements[1] else "Deterministic sample only.",
        ),
        CoverageDimension(
            dimension="QUANTIZATION_PARAMETER",
            numerator=parameters[0],
            denominator=parameters[1],
            status="COMPLETE" if parameters[0] == parameters[1] else "PARTIAL",
            incomplete_reason=None
            if parameters[0] == parameters[1]
            else "Parameter observation incomplete.",
        ),
    ]
    if byte_counts is None:
        result.append(
            CoverageDimension(
                dimension="BYTE",
                numerator=0,
                denominator=None,
                status="UNAVAILABLE",
                incomplete_reason="Tensor byte range was not separately measured.",
            )
        )
    else:
        result.append(
            CoverageDimension(
                dimension="BYTE",
                numerator=byte_counts[0],
                denominator=byte_counts[1],
                status="COMPLETE" if byte_counts[0] == byte_counts[1] else "PARTIAL",
                incomplete_reason=None
                if byte_counts[0] == byte_counts[1]
                else "Partial byte scope.",
            )
        )
    result.append(
        CoverageDimension(
            dimension="SAMPLING",
            numerator=sampled[0] if sampled else elements[0],
            denominator=sampled[1] if sampled else elements[1],
            status="COMPLETE" if sampled is None and elements[0] == elements[1] else "PARTIAL",
            incomplete_reason=None
            if sampled is None and elements[0] == elements[1]
            else "Deterministic sample is not complete numerical coverage.",
        )
    )
    return tuple(result)


def _phase6a_binding(
    repository: Path, output_root: Path, subject: ProductSubject, fixture_name: str
) -> tuple[ObservedPayloadManifest, PayloadHashExecutionRecord]:
    fixture = repository / "fixtures" / "quantization" / fixture_name
    plan = build_payload_plan(
        subject,
        RootMode.SINGLE_FILE_ROOT,
        f"quantization-fixture.{fixture_name.removesuffix('.json')}",
        logical_name=fixture_name,
    )
    manifest, execution = observe_payload(fixture, plan)
    _write(
        output_root / "quantization-fidelity" / "bindings" / f"{fixture_name}.manifest.json",
        manifest,
    )
    _write(
        output_root / "quantization-fidelity" / "bindings" / f"{fixture_name}.execution.json",
        execution,
    )
    return manifest, execution


def _artifact(role: ArtifactRole, name: str, manifest: ObservedPayloadManifest) -> ArtifactIdentity:
    return ArtifactIdentity(
        subject_id=manifest.subject.subject_id,
        role=role,
        provider="omiv-synthetic",
        namespace="quantization-fixtures",
        artifact_name=name,
        requested_revision="fixture-v1",
        resolved_revision="fixture-v1",
        local_payload_manifest=ObjectReference(
            schema_id=manifest.schema_id,
            object_id=manifest.manifest_id,
            object_digest=manifest.manifest_digest,
        ),
        remote_snapshot=None,
        artifact_set_identity=manifest.artifact_set_payload_digest,
        coverage="complete.declared-local-file-scope",
        identity_semantics="phase6a.observed-payload-manifest",
        availability=ArtifactAvailability.EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE,
        limitations=("Synthetic fixture identity is not a real model artifact.",),
    )


def _descriptor(
    scheme: SchemeFamily,
    codec: NumericalCodec,
    *,
    storage: str,
    bit_width: int | None,
    signed: bool | None,
    level: ObservationLevel = ObservationLevel.FULL_TENSOR_VALUES,
) -> QuantizationDescriptor:
    return QuantizationDescriptor(
        scheme_family=scheme,
        numerical_codec=codec,
        storage_dtype=storage,
        logical_reconstructed_dtype="float32",
        bit_width=bit_width,
        signed=signed,
        byte_order="NOT_APPLICABLE",
        packing_order="NORMALIZED_INTEGER_VALUES"
        if codec == NumericalCodec.UNIFORM_AFFINE_INTEGER
        else "NOT_APPLICABLE",
        scale_representation="PER_TENSOR_DECIMAL"
        if codec == NumericalCodec.UNIFORM_AFFINE_INTEGER
        else None,
        zero_point_representation="PER_TENSOR_INTEGER"
        if codec == NumericalCodec.UNIFORM_AFFINE_INTEGER
        else None,
        quantization_axis=None,
        group_size=None,
        block_size=None,
        codebook_identity=None,
        rounding_mode="ROUND_HALF_EVEN",
        clipping_behavior="OBSERVED_SATURATION_COUNT_WHEN_AVAILABLE",
        exceptional_value_handling="REJECT_NON_FINITE",
        format_identifier="omiv.synthetic.normalized-values",
        format_version="v1",
        parameter_provenance=ParameterProvenance.OBSERVED_FROM_PAYLOAD,
        observation_level=level,
    )


def _metadata_descriptor(role: ArtifactRole) -> QuantizationDescriptor:
    return QuantizationDescriptor(
        scheme_family=SchemeFamily.UNKNOWN,
        numerical_codec=NumericalCodec.UNAVAILABLE,
        storage_dtype=None,
        logical_reconstructed_dtype=None,
        bit_width=None,
        signed=None,
        byte_order="UNKNOWN",
        packing_order=None,
        scale_representation=None,
        zero_point_representation=None,
        quantization_axis=None,
        group_size=None,
        block_size=None,
        codebook_identity=None,
        rounding_mode=None,
        clipping_behavior=None,
        exceptional_value_handling=None,
        format_identifier=f"metadata-only-{role.value.lower()}",
        format_version=None,
        parameter_provenance=ParameterProvenance.UNAVAILABLE,
        observation_level=ObservationLevel.METADATA_ONLY,
    )


def generate_all_quantization_examples(
    output_root: Path, *, repository: Path | None = None
) -> QuantizationArtifactIndex:
    repository = (repository or Path.cwd()).resolve()
    output_root = output_root.resolve()
    scope = synthetic_scope(project="project.quantization", environment="environment.offline")
    subject = build_product_subject(
        ProductSubjectClass.MODEL_WEIGHTS, "model.quantization-synthetic", scope
    )
    source_manifest, source_payload_execution = _phase6a_binding(
        repository, output_root, subject, "source-values.json"
    )
    candidate_manifest, candidate_payload_execution = _phase6a_binding(
        repository, output_root, subject, "candidate-values.json"
    )
    source_artifact = _artifact(ArtifactRole.SOURCE, "source-values", source_manifest)
    candidate_artifact = _artifact(ArtifactRole.CANDIDATE, "candidate-values", candidate_manifest)
    declaration = build_declaration(
        subject,
        source_artifact,
        candidate_artifact,
        mode=RelationshipMode.SOURCE_TO_QUANTIZED_CANDIDATE,
        provenance=DeclarationProvenance.CALLER_DECLARED,
        limitations=("Caller declaration does not prove the observed candidate implements it.",),
    )
    source_descriptor = _descriptor(
        SchemeFamily.UNQUANTIZED,
        NumericalCodec.UNQUANTIZED_IDENTITY,
        storage="float32",
        bit_width=32,
        signed=True,
    )
    candidate_descriptor = _descriptor(
        SchemeFamily.UNIFORM_AFFINE_INTEGER,
        NumericalCodec.UNIFORM_AFFINE_INTEGER,
        storage="int8",
        bit_width=8,
        signed=True,
    )
    remote = RemoteSnapshotManifest.model_validate(
        json.loads(
            (repository / "reconciliation" / "snapshots" / "generic.snapshot.json").read_bytes()
        )
    )
    remote_ref = ObjectReference(
        schema_id=remote.schema_id,
        object_id=remote.manifest_id,
        object_digest=remote.manifest_digest,
    )
    plan = build_plan(
        declaration,
        observation_level=ObservationLevel.FULL_TENSOR_VALUES,
        expectation_scope=ExpectationScope.SELECTED_REQUIRED_TENSORS,
        source_phase6a=object_reference(source_manifest),
        candidate_phase6a=object_reference(candidate_manifest),
        remote_phase6b=(remote_ref,),
    )
    execution = build_execution(
        plan,
        supplied_inputs=(
            object_reference(source_manifest),
            object_reference(candidate_manifest),
            remote_ref,
        ),
        tensors=2,
        values=8,
        payload_bytes=(repository / "fixtures" / "quantization" / "source-values.json")
        .stat()
        .st_size
        + (repository / "fixtures" / "quantization" / "candidate-values.json").stat().st_size,
    )
    source_tensor = build_tensor(
        artifact_identity=source_manifest.artifact_set_payload_digest,
        logical_name="model/weight",
        role=TensorRole.PRIMARY_WEIGHT,
        shape=(4,),
        storage_dtype="float32",
        logical_dtype="float32",
        quantization=source_descriptor,
        observation_level=ObservationLevel.FULL_TENSOR_VALUES,
        observed_element_count=4,
        provenance=ParameterProvenance.OBSERVED_FROM_PAYLOAD,
        member_identity=source_manifest.files[0].path,
    )
    candidate_tensor = build_tensor(
        artifact_identity=candidate_manifest.artifact_set_payload_digest,
        logical_name="model/weight",
        role=TensorRole.PRIMARY_WEIGHT,
        shape=(4,),
        storage_dtype="int8",
        logical_dtype="float32",
        quantization=candidate_descriptor,
        observation_level=ObservationLevel.FULL_TENSOR_VALUES,
        observed_element_count=4,
        provenance=ParameterProvenance.OBSERVED_FROM_PAYLOAD,
        member_identity=candidate_manifest.files[0].path,
    )
    full_coverage = _coverage()
    source_observation = build_observation(
        execution, source_artifact, source_descriptor, (source_tensor,), full_coverage
    )
    candidate_observation = build_observation(
        execution, candidate_artifact, candidate_descriptor, (candidate_tensor,), full_coverage
    )
    mapping = build_mapping(
        (source_tensor.tensor_id,),
        (candidate_tensor.tensor_id,),
        cardinality="ONE_TO_ONE",
        numerical_status=MappingNumericalStatus.NUMERICALLY_EVALUABLE,
    )
    correspondence = build_correspondence(source_observation, candidate_observation, (mapping,))
    parameters = build_parameters(
        candidate_observation,
        candidate_tensor,
        scale="0.5",
        zero_point=2,
        provenance=ParameterProvenance.OBSERVED_FROM_PAYLOAD,
        complete=True,
    )
    source_values = ("-1", "0", "1", "2")
    candidate_values = ("0", "2", "4", "6")
    reconstructed = reconstruct_values(candidate_values, parameters)
    exact_metrics = measure_values(
        source_values,
        reconstructed,
        source_tensor_id=source_tensor.tensor_id,
        candidate_tensor_id=candidate_tensor.tensor_id,
    )
    exact_measurement = build_measurement(
        source_observation,
        candidate_observation,
        correspondence,
        (parameters,),
        (exact_metrics,),
        full_coverage,
        observation_level=ObservationLevel.FULL_TENSOR_VALUES,
    )
    exact_comparison = compare_representations(
        declaration,
        source_observation,
        candidate_observation,
        correspondence,
        (parameters,),
        (exact_measurement,),
        expectation_scope=ExpectationScope.SELECTED_REQUIRED_TENSORS,
        coverage=full_coverage,
        limitations=("Exactness covers the one selected synthetic tensor only.",),
    )
    authority = build_authority_evaluation(
        declaration,
        limitations=("Synthetic signing does not establish publisher or transformer authority.",),
    )
    policy = build_policy(scope)
    exact_policy = evaluate_policy(
        policy,
        exact_comparison,
        exact_measurement,
        candidate_observation,
        authority,
        declaration=declaration,
    )
    exact_evidence = build_evidence(
        exact_comparison,
        exact_policy,
        authority,
        limitations=("Numerical fidelity is not model correctness or behavioral parity.",),
    )
    exact_report = build_report(exact_evidence, exact_comparison, exact_policy, authority)

    outside_metrics = measure_values(
        source_values,
        reconstruct_values(("0", "2", "4", "7"), parameters),
        source_tensor_id=source_tensor.tensor_id,
        candidate_tensor_id=candidate_tensor.tensor_id,
    )
    outside_measurement = build_measurement(
        source_observation,
        candidate_observation,
        correspondence,
        (parameters,),
        (outside_metrics,),
        full_coverage,
        observation_level=ObservationLevel.FULL_TENSOR_VALUES,
        failed_tensor_ids=(candidate_tensor.tensor_id,),
    )
    outside_comparison = compare_representations(
        declaration,
        source_observation,
        candidate_observation,
        correspondence,
        (parameters,),
        (outside_measurement,),
        expectation_scope=ExpectationScope.SELECTED_REQUIRED_TENSORS,
        coverage=full_coverage,
    )
    outside_policy = evaluate_policy(
        policy,
        outside_comparison,
        outside_measurement,
        candidate_observation,
        authority,
        declaration=declaration,
    )
    outside_evidence = build_evidence(outside_comparison, outside_policy, authority)
    outside_report = build_report(outside_evidence, outside_comparison, outside_policy, authority)

    sample = build_sample_definition(
        seed="omiv.synthetic.sample.seed-v1",
        source_tensor_id=source_tensor.tensor_id,
        candidate_tensor_id=candidate_tensor.tensor_id,
        population_count=4,
        requested_count=2,
        maximum_count=4,
    )
    sampled_source = tuple(source_values[x] for x in sample.selected_indices)
    sampled_candidate = tuple(candidate_values[x] for x in sample.selected_indices)
    sampled_metrics = measure_values(
        sampled_source,
        reconstruct_values(sampled_candidate, parameters),
        source_tensor_id=source_tensor.tensor_id,
        candidate_tensor_id=candidate_tensor.tensor_id,
    )
    sample_coverage = _coverage(elements=(2, 4), sampled=(2, 4))
    sampled_measurement = build_measurement(
        source_observation,
        candidate_observation,
        correspondence,
        (parameters,),
        (sampled_metrics,),
        sample_coverage,
        observation_level=ObservationLevel.DETERMINISTIC_SAMPLE,
        sample=sample,
        limitations=("Sampled success cannot become complete numerical coverage.",),
    )
    sampled_comparison = compare_representations(
        declaration,
        source_observation,
        candidate_observation,
        correspondence,
        (parameters,),
        (sampled_measurement,),
        expectation_scope=ExpectationScope.DETERMINISTIC_SAMPLE_SCOPE,
        coverage=sample_coverage,
    )
    sampling_policy = build_policy(
        scope,
        name="quantization.synthetic-sampling-policy",
        minimum_element_coverage="0.5",
    )
    sampled_policy = evaluate_policy(
        sampling_policy,
        sampled_comparison,
        sampled_measurement,
        candidate_observation,
        authority,
        declaration=declaration,
    )
    sampled_evidence = build_evidence(sampled_comparison, sampled_policy, authority)
    sampled_report = build_report(sampled_evidence, sampled_comparison, sampled_policy, authority)

    metadata_artifact = candidate_artifact.model_copy(
        update={
            "local_payload_manifest": None,
            "artifact_set_identity": None,
            "availability": ArtifactAvailability.METADATA_IDENTITY_ONLY,
            "limitations": ("No candidate payload values were supplied.",),
        }
    )
    metadata_declaration = build_declaration(
        subject,
        source_artifact,
        metadata_artifact,
        mode=RelationshipMode.RELATIONSHIP_UNAVAILABLE,
        provenance=DeclarationProvenance.NOT_AVAILABLE,
    )
    metadata_plan = build_plan(
        metadata_declaration,
        observation_level=ObservationLevel.METADATA_ONLY,
        expectation_scope=ExpectationScope.PARTIAL_REFERENCE_SET,
    )
    metadata_execution = build_execution(metadata_plan, completion_state="INCOMPLETE")
    metadata_source = build_observation(
        metadata_execution,
        source_artifact,
        _metadata_descriptor(ArtifactRole.SOURCE),
        (),
        _coverage(tensors=(0, 1), elements=(0, 4), parameters=(0, 1), sampled=(0, 4)),
    )
    metadata_candidate = build_observation(
        metadata_execution,
        metadata_artifact,
        _metadata_descriptor(ArtifactRole.CANDIDATE),
        (),
        _coverage(tensors=(0, 1), elements=(0, 4), parameters=(0, 1), sampled=(0, 4)),
    )
    metadata_mapping = build_mapping(
        (), (), cardinality="UNSUPPORTED", numerical_status=MappingNumericalStatus.NOT_MAPPED
    )
    metadata_correspondence = build_correspondence(
        metadata_source, metadata_candidate, (metadata_mapping,)
    )
    metadata_comparison = compare_representations(
        metadata_declaration,
        metadata_source,
        metadata_candidate,
        metadata_correspondence,
        (),
        (),
        expectation_scope=ExpectationScope.PARTIAL_REFERENCE_SET,
        coverage=metadata_candidate.coverage,
    )
    metadata_authority = build_authority_evaluation(metadata_declaration)
    metadata_policy = evaluate_policy(
        policy,
        metadata_comparison,
        None,
        metadata_candidate,
        metadata_authority,
        declaration=metadata_declaration,
    )
    metadata_evidence = build_evidence(metadata_comparison, metadata_policy, metadata_authority)
    metadata_report = build_report(
        metadata_evidence, metadata_comparison, metadata_policy, metadata_authority
    )

    xai_readiness, xai_case = build_xai_readiness(repository)
    objects: list[tuple[str, BaseModel]] = [
        ("declarations/synthetic.json", declaration),
        ("plans/synthetic.json", plan),
        ("executions/synthetic.json", execution),
        ("tensors/source.json", source_tensor),
        ("tensors/candidate.json", candidate_tensor),
        ("observations/source.json", source_observation),
        ("observations/candidate.json", candidate_observation),
        ("correspondence/one-to-one.json", correspondence),
        ("parameters/affine.json", parameters),
        ("sampling/deterministic.json", sample),
        ("measurements/exact.json", exact_measurement),
        ("measurements/outside-policy.json", outside_measurement),
        ("measurements/sampled.json", sampled_measurement),
        ("comparisons/exact.json", exact_comparison),
        ("comparisons/outside-policy.json", outside_comparison),
        ("comparisons/sampled.json", sampled_comparison),
        ("policies/synthetic.json", policy),
        ("policies/sampling.json", sampling_policy),
        ("policy-evaluations/exact.json", exact_policy),
        ("policy-evaluations/outside-policy.json", outside_policy),
        ("policy-evaluations/sampled.json", sampled_policy),
        ("authority/synthetic.json", authority),
        ("evidence/exact.json", exact_evidence),
        ("evidence/outside-policy.json", outside_evidence),
        ("evidence/sampled.json", sampled_evidence),
        ("reports/exact.json", exact_report),
        ("reports/outside-policy.json", outside_report),
        ("reports/sampled.json", sampled_report),
        ("metadata-only/declaration.json", metadata_declaration),
        ("metadata-only/plan.json", metadata_plan),
        ("metadata-only/execution.json", metadata_execution),
        ("metadata-only/source-observation.json", metadata_source),
        ("metadata-only/candidate-observation.json", metadata_candidate),
        ("metadata-only/correspondence.json", metadata_correspondence),
        ("metadata-only/comparison.json", metadata_comparison),
        ("metadata-only/authority.json", metadata_authority),
        ("metadata-only/policy-evaluation.json", metadata_policy),
        ("metadata-only/evidence.json", metadata_evidence),
        ("metadata-only/report.json", metadata_report),
        ("practice/xai/readiness.json", xai_readiness),
    ]
    for integration_type, derived in (
        ("PASSPORT", "DERIVED_QUANTIZATION_FIDELITY_SUMMARY"),
        ("CUSTODY", "APPEND_ONLY_EVIDENCE_REFERENCE_AVAILABLE"),
        ("ATTESTATION", "TRANSFORMATION_CLAIM_REMAINS_DISTINCT"),
        ("GOVERNANCE", "EVIDENCE_STATE_ONLY_NO_APPROVAL"),
        ("SECURITY", "NO_SECURITY_PASS_CREATED"),
        ("RUNTIME", "EXPECTED_IDENTITY_ONLY_NOT_OBSERVED"),
        ("HISTORICAL", "NOT_RECORDED_TIME_CONTEXT_PRESERVED"),
        ("PAYLOAD_INTEGRITY", "EXACT_PHASE6A_BINDING_PRESERVED"),
        ("RECONCILIATION", "PHASE6B_NON_PAYLOAD_IDENTIFIERS_NOT_UPGRADED"),
    ):
        source_object = (
            object_reference(source_manifest)
            if integration_type == "PAYLOAD_INTEGRITY"
            else remote_ref
            if integration_type == "RECONCILIATION"
            else None
        )
        objects.append(
            (
                f"integrations/{integration_type.lower()}.json",
                build_integration(
                    exact_evidence,
                    integration_type,
                    source_object=source_object,
                    subject_identity_match=True if source_object else None,
                    payload_identity_match=True
                    if integration_type == "PAYLOAD_INTEGRITY"
                    else None,
                    derived_status=derived,
                    limitations=("Integration does not mutate or strengthen prior evidence.",),
                ),
            )
        )
    catalog, case_results = _build_catalog(
        exact_evidence,
        outside_evidence,
        sampled_evidence,
        metadata_evidence,
        xai_readiness,
    )
    objects.extend((f"examples/cases/{value.case_id}.json", value) for value in case_results)
    objects.append(("examples/case-catalog.json", catalog))
    signed = _signed_examples(declaration, source_observation, exact_evidence)
    objects.extend(signed)
    for relative, value in objects:
        _write(output_root / "quantization-fidelity" / relative, value)
    report_dir = output_root / "reports" / "quantization-fidelity"
    report_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(report_dir / "synthetic-fidelity-report.md", render_markdown(exact_report))
    _write(report_dir / "xai-quantization-readiness-case-study.json", xai_case)
    atomic_write_text(
        report_dir / "xai-quantization-readiness-case-study.md",
        render_xai_case_study(xai_case, xai_readiness),
    )
    return _rebuild_index(output_root)


def _build_catalog(
    exact: QuantizationFidelityEvidence,
    outside: QuantizationFidelityEvidence,
    sampled: QuantizationFidelityEvidence,
    metadata: QuantizationFidelityEvidence,
    xai: XaiQuantizationReadiness,
) -> tuple[QuantizationExampleCatalog, tuple[QuantizationExampleResult, ...]]:
    refs = {
        "exact": object_reference(exact),
        "outside": object_reference(outside),
        "sampled": object_reference(sampled),
        "metadata": object_reference(metadata),
        "xai": ObjectReference(
            schema_id=xai.schema_id,
            object_id=xai.readiness_id,
            object_digest=xai.readiness_digest,
        ),
    }
    definitions = (
        (
            "exact-unquantized-identity",
            "Exact identity semantics are supported and tested.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "EXACT_FOR_EVALUATED_SCOPE",
            "exact",
        ),
        (
            "affine-within-policy",
            "Explicit affine reconstruction is within policy.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "EXACT_FOR_EVALUATED_SCOPE",
            "exact",
        ),
        (
            "affine-outside-policy",
            "All threshold failures remain visible.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "OUTSIDE_POLICY_FOR_EVALUATED_SCOPE",
            "outside",
        ),
        (
            "shape-and-numerical-mismatch",
            "Shape and numerical findings are simultaneous.",
            "STRUCTURAL_MISMATCH",
            "OUTSIDE_POLICY_FOR_EVALUATED_SCOPE",
            "outside",
        ),
        (
            "missing-scale",
            "Missing affine scale fails closed.",
            "QUANTIZATION_PARAMETERS_INCOMPLETE",
            "NOT_EVALUATED",
            "metadata",
        ),
        (
            "invalid-zero-point",
            "Unrepresentable zero point is invalid.",
            "INVALID",
            "INVALID",
            "metadata",
        ),
        (
            "unsupported-opaque-format",
            "Opaque codecs never fall back to affine semantics.",
            "FORMAT_UNSUPPORTED",
            "FORMAT_NOT_NUMERICALLY_SUPPORTED",
            "metadata",
        ),
        (
            "metadata-only",
            "Metadata does not become numerical evidence.",
            "STRUCTURAL_INFORMATION_INCOMPLETE",
            "PAYLOAD_VALUES_UNAVAILABLE",
            "metadata",
        ),
        (
            "deterministic-sample",
            "Identity-bound sampling is reproducible.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "SAMPLED_WITHIN_POLICY",
            "sampled",
        ),
        (
            "sample-not-complete",
            "A successful sample is not complete coverage.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "SAMPLED_WITHIN_POLICY",
            "sampled",
        ),
        (
            "missing-mandatory-tensor",
            "Mandatory-role gaps remain explicit.",
            "STRUCTURAL_MISMATCH",
            "INSUFFICIENT_NUMERICAL_COVERAGE",
            "metadata",
        ),
        (
            "ambiguous-mapping",
            "Ambiguous correspondence is not numerically evaluated.",
            "TENSOR_MAPPING_AMBIGUOUS",
            "NOT_EVALUATED",
            "metadata",
        ),
        (
            "one-to-many-no-recipe",
            "Structural mapping needs an explicit reconstruction recipe.",
            "STRUCTURAL_INFORMATION_INCOMPLETE",
            "NOT_EVALUATED",
            "metadata",
        ),
        (
            "non-finite-rejected",
            "Non-finite inputs are rejected before canonical output.",
            "INVALID",
            "INVALID",
            "metadata",
        ),
        (
            "zero-norm-semantics",
            "Zero denominators have explicit undefined states.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "WITHIN_POLICY_FOR_EVALUATED_SCOPE",
            "exact",
        ),
        (
            "limit-exceeded",
            "Bound violations return LIMIT_EXCEEDED without truncation.",
            "INVALID",
            "INVALID",
            "metadata",
        ),
        (
            "trusted-signer-no-transformer-authority",
            "Signature trust does not create transformer authority.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "EXACT_FOR_EVALUATED_SCOPE",
            "exact",
        ),
        (
            "model-a-authority-not-model-b",
            "Authority is subject and scope bound.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "NOT_EVALUATED",
            "metadata",
        ),
        (
            "exact-phase6a-binding",
            "Local byte identity is supplied by Phase 6A.",
            "STRUCTURALLY_CONSISTENT_FOR_SCOPE",
            "EXACT_FOR_EVALUATED_SCOPE",
            "exact",
        ),
        (
            "phase6a-identity-mismatch",
            "Mismatched payload identity fails closed.",
            "STRUCTURAL_MISMATCH",
            "NOT_EVALUATED",
            "metadata",
        ),
        (
            "phase6b-noncomparable-digest",
            "Provider object identities are not payload digests.",
            "STRUCTURAL_INFORMATION_INCOMPLETE",
            "PAYLOAD_VALUES_UNAVAILABLE",
            "metadata",
        ),
        (
            "xai-readiness-no-payload-candidate",
            "Pinned metadata records readiness without invented quantization facts.",
            "NOT_EVALUATED",
            "NOT_EVALUATED",
            "xai",
        ),
    )
    results = tuple(
        sorted(
            (
                QuantizationExampleResult.model_validate(
                    finalize_identity(
                        {
                            "schema": "omiv.quantization-example-result.v1",
                            "case_id": case_id,
                            "outcome": (
                                "LIMIT_EXCEEDED"
                                if case_id == "limit-exceeded"
                                else "PASS"
                                if numerical
                                in {
                                    "EXACT_FOR_EVALUATED_SCOPE",
                                    "WITHIN_POLICY_FOR_EVALUATED_SCOPE",
                                    "SAMPLED_WITHIN_POLICY",
                                }
                                else "FAIL"
                                if numerical
                                in {
                                    "OUTSIDE_POLICY_FOR_EVALUATED_SCOPE",
                                    "SAMPLED_OUTSIDE_POLICY",
                                    "INVALID",
                                }
                                else "NOT_EVALUATED"
                            ),
                            "structural_status": StructuralStatus(structural),
                            "numerical_status": NumericalStatus(numerical),
                            "upstream_objects": (refs[ref],),
                            "exercised_invariant": description,
                            "observed_findings": (case_id.upper().replace("-", "_"),),
                            "limitations": (
                                "Synthetic bounded result; invalid inputs are retained as "
                                "deterministic rejection outcomes.",
                            ),
                        },
                        "result_id",
                        "quantization_example_result_",
                        "result_digest",
                    )
                )
                for case_id, description, structural, numerical, ref in definitions
            ),
            key=lambda value: value.case_id,
        )
    )
    result_refs = {value.case_id: object_reference(value) for value in results}
    cases = tuple(
        sorted(
            (
                QuantizationExampleCase(
                    case_id=case_id,
                    description=description,
                    expected_structural_status=StructuralStatus(structural),
                    expected_numerical_status=NumericalStatus(numerical),
                    representative_object=result_refs[case_id],
                    limitations=("Synthetic engineering example; not a model quality claim.",),
                )
                for case_id, description, structural, numerical, ref in definitions
            ),
            key=lambda value: value.case_id,
        )
    )
    body = {
        "schema": "omiv.quantization-example-catalog.v1",
        "cases": cases,
        "limitations": (
            "Invalid examples are exercised as deterministic rejection tests rather than "
            "serialized invalid objects.",
        ),
    }
    return (
        QuantizationExampleCatalog.model_validate(
            finalize_identity(body, "catalog_id", "quantization_catalog_", "catalog_digest")
        ),
        results,
    )


def _signed_examples(
    declaration: BaseModel, observation: BaseModel, evidence: QuantizationFidelityEvidence
) -> list[tuple[str, BaseModel]]:
    types = [
        SignedObjectType.QUANTIZATION_RELATIONSHIP_DECLARATION,
        SignedObjectType.REPRESENTATION_OBSERVATION,
        SignedObjectType.QUANTIZATION_FIDELITY_EVIDENCE,
    ]
    purposes = [
        SignaturePurpose.QUANTIZATION_RELATIONSHIP_DECLARATION_ISSUANCE,
        SignaturePurpose.REPRESENTATION_OBSERVATION_ISSUANCE,
        SignaturePurpose.QUANTIZATION_FIDELITY_EVIDENCE_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([108]) * 32)
    key = build_key_identity(private, allowed_object_types=types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic quantization evidence issuer",
        role="QUANTIZATION_EVIDENCE_ISSUER",
        evidence=[hashlib.sha256(b"omiv-phase6c-synthetic-issuer").hexdigest()],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    policy = build_trust_policy(
        "team_release",
        object_types=types,
        purposes=purposes,
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    result: list[tuple[str, BaseModel]] = [
        ("signed/trust-policy.json", policy),
        ("signed/trust-bundle.json", bundle),
    ]
    values = (
        ("declaration", declaration, types[0], purposes[0]),
        ("observation", observation, types[1], purposes[1]),
        ("evidence", evidence, types[2], purposes[2]),
    )
    for name, value, object_type, purpose in values:
        raw = value.model_dump(mode="json", by_alias=True)
        descriptor = build_descriptor(raw, object_type, purpose, policy_id=policy.policy_id)
        signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
        envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
        report = verify_envelope(envelope, bundle, policy)
        result.extend(
            [
                (f"signed/{name}.envelope.json", envelope),
                (f"signed/{name}.signature-report.json", report),
            ]
        )
    return result


def _canonical_id(value: dict[str, object]) -> str:
    schema = str(value.get("schema"))
    fields = {
        "omiv.observed-payload-manifest.v1": "manifest_id",
        "omiv.payload-hash-execution-record.v1": "execution_id",
        "omiv.quantization-relationship-declaration.v1": "declaration_id",
        "omiv.quantization-observation-plan.v1": "plan_id",
        "omiv.quantization-execution-record.v1": "execution_id",
        "omiv.tensor-representation-record.v1": "tensor_id",
        "omiv.representation-observation.v1": "observation_id",
        "omiv.tensor-correspondence.v1": "correspondence_id",
        "omiv.quantization-parameter-observation.v1": "parameter_observation_id",
        "omiv.deterministic-sample-definition.v1": "sample_id",
        "omiv.numerical-fidelity-measurement.v1": "measurement_id",
        "omiv.quantization-fidelity-comparison.v1": "comparison_id",
        "omiv.quantization-fidelity-policy.v1": "policy_id",
        "omiv.quantization-policy-evaluation.v1": "evaluation_id",
        "omiv.quantization-authority-evaluation.v1": "authority_evaluation_id",
        "omiv.quantization-fidelity-evidence.v1": "evidence_id",
        "omiv.quantization-integration-summary.v1": "integration_id",
        "omiv.quantization-fidelity-report.v1": "report_id",
        "omiv.quantization-example-catalog.v1": "catalog_id",
        "omiv.quantization-example-result.v1": "result_id",
        "omiv.xai-quantization-readiness.v1": "readiness_id",
        "omiv.xai-quantization-case-study.v1": "case_study_id",
        "omiv.signed-object-envelope.v1": "envelope_id",
        "omiv.signature-report.v1": "report_id",
        "omiv.trust-policy.v1": "policy_id",
        "omiv.trust-bundle.v1": "bundle_id",
    }
    field = fields.get(schema)
    if field is None or not isinstance(value.get(field), str):
        raise ValueError(f"generated object lacks canonical identity: {schema}")
    return str(value[field])


def _rebuild_index(root: Path) -> QuantizationArtifactIndex:
    entries: list[QuantizationArtifactIndexEntry] = []
    identities: set[str] = set()
    contents: set[str] = set()
    for directory in (root / "quantization-fidelity", root / "reports" / "quantization-fidelity"):
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.name == "artifact-index.json":
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            relative = path.relative_to(root).as_posix()
            if path.suffix == ".json":
                value = json.loads(data)
                schema = str(value["schema"])
                canonical_id = _canonical_id(value)
            else:
                schema = "omiv.quantization-markdown-report.v1"
                canonical_id = "quantization_markdown_" + digest[:32]
            if canonical_id in identities or digest in contents:
                raise ValueError("duplicate Phase 6C canonical identity or content")
            identities.add(canonical_id)
            contents.add(digest)
            entries.append(
                QuantizationArtifactIndexEntry(
                    path=relative,
                    size=len(data),
                    sha256=digest,
                    schema_id=schema,
                    canonical_id=canonical_id,
                )
            )
    entries.sort(key=lambda value: value.path.encode())
    body = {
        "schema": "omiv.quantization-artifact-index.v1",
        "entries": entries,
        "total_size": sum(x.size for x in entries),
        "limitations": (
            "External index excludes itself; generated values are small synthetic fixtures, "
            "not model payloads.",
        ),
    }
    index = QuantizationArtifactIndex.model_validate(
        finalize_identity(body, "index_id", "quantization_index_", "index_digest")
    )
    _write(root / "quantization-fidelity" / "artifact-index.json", index)
    return index
