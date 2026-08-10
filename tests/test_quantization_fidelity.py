"""Focused semantic and adversarial coverage for Phase 6C."""

from __future__ import annotations

import ast
import hashlib
import json
from decimal import ROUND_DOWN, Decimal, InvalidOperation, getcontext, setcontext
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.external_artifacts import (
    KIMI_K3_TENSOR_INVENTORY,
    ExternalArtifactStatus,
    observe_external_artifact,
)
from omiv.quantization.artifact_index import verify_quantization_artifact_index
from omiv.quantization.building import (
    build_authority_evaluation,
    build_correspondence,
    build_integration,
    build_mapping,
    build_measurement,
    build_observation,
    build_parameters,
    build_report,
    build_tensor,
    compare_representations,
    evaluate_policy,
)
from omiv.quantization.dependency import assert_acyclic, verify_generated_dependency_graph
from omiv.quantization.models import (
    ArtifactAvailability,
    ArtifactIdentity,
    ArtifactRole,
    AuthorityStatus,
    CorrespondenceCardinality,
    CoverageDimension,
    ExpectationScope,
    FidelityThresholds,
    FindingKind,
    MappingNumericalStatus,
    MetricState,
    NumericalCodec,
    NumericalFidelityMeasurement,
    NumericalStatus,
    ObservationLevel,
    OverallEvidenceStatus,
    ParameterProvenance,
    QuantizationArtifactIndex,
    QuantizationAuthorityEvaluation,
    QuantizationExampleResult,
    QuantizationExecutionRecord,
    QuantizationFidelityComparison,
    QuantizationFidelityEvidence,
    QuantizationFidelityPolicy,
    QuantizationLimits,
    QuantizationParameterObservation,
    QuantizationPolicyEvaluation,
    QuantizationRelationshipDeclaration,
    RepresentationObservation,
    RequirementStatus,
    RoleThreshold,
    TensorCorrespondence,
    TensorRepresentationRecord,
    TensorRole,
    TensorThreshold,
    finalize_identity,
    parse_bounded_decimal,
)
from omiv.quantization.numerical import (
    canonical_decimal,
    measure_values,
    reconstruct_values,
)
from omiv.quantization.preservation import audit_baseline
from omiv.quantization.reporting import pretty_json
from omiv.quantization.sampling import build_sample_definition
from omiv.quantization.schema import SCHEMA_MODELS, parse_quantization_bytes
from omiv.quantization_profiles.examples import generate_all_quantization_examples
from omiv.quantization_profiles.models import XaiQuantizationReadiness
from omiv.quantization_profiles.xai import build_xai_readiness
from omiv.reconciliation.models import DigestKind, RemoteSnapshotManifest
from omiv.trust.models import SignaturePurpose, SignedObjectEnvelope, SignedObjectType
from omiv.trust.signing import build_descriptor
from omiv.trust.verification import _validate_source_object

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase6c-generated")
    generate_all_quantization_examples(root, repository=ROOT)
    return root


def _load(root: Path, relative: str, model: type[Any]) -> Any:
    return model.model_validate(json.loads((root / relative).read_bytes()))


def _core(generated: Path) -> dict[str, Any]:
    prefix = "quantization-fidelity"
    return {
        "declaration": _load(
            generated,
            f"{prefix}/declarations/synthetic.json",
            QuantizationRelationshipDeclaration,
        ),
        "execution": _load(
            generated,
            f"{prefix}/executions/synthetic.json",
            QuantizationExecutionRecord,
        ),
        "source": _load(
            generated,
            f"{prefix}/observations/source.json",
            RepresentationObservation,
        ),
        "candidate": _load(
            generated,
            f"{prefix}/observations/candidate.json",
            RepresentationObservation,
        ),
        "correspondence": _load(
            generated,
            f"{prefix}/correspondence/one-to-one.json",
            TensorCorrespondence,
        ),
        "parameters": _load(
            generated,
            f"{prefix}/parameters/affine.json",
            QuantizationParameterObservation,
        ),
        "measurement": _load(
            generated,
            f"{prefix}/measurements/exact.json",
            NumericalFidelityMeasurement,
        ),
        "comparison": _load(
            generated,
            f"{prefix}/comparisons/exact.json",
            QuantizationFidelityComparison,
        ),
        "policy": _load(
            generated,
            f"{prefix}/policies/synthetic.json",
            QuantizationFidelityPolicy,
        ),
        "authority": _load(
            generated,
            f"{prefix}/authority/synthetic.json",
            QuantizationAuthorityEvaluation,
        ),
    }


def test_generated_schema_round_trips(generated: Path) -> None:
    index = _load(
        generated,
        "quantization-fidelity/artifact-index.json",
        QuantizationArtifactIndex,
    )
    checked = 0
    for entry in index.entries:
        if not entry.path.endswith(".json") or entry.schema_id not in SCHEMA_MODELS:
            continue
        value = SCHEMA_MODELS[entry.schema_id].model_validate(
            json.loads((generated / entry.path).read_bytes())
        )
        assert json.loads(pretty_json(value))["schema"] == entry.schema_id
        checked += 1
    assert checked >= 45


def test_canonical_ids_and_digests_are_stable(generated: Path) -> None:
    first = (generated / "quantization-fidelity/evidence/exact.json").read_bytes()
    parsed = QuantizationFidelityEvidence.model_validate(json.loads(first))
    assert pretty_json(parsed).encode() == first
    assert parsed.evidence_id.startswith("quantization_evidence_")


def test_strict_schema_dispatch_rejects_unknown() -> None:
    with pytest.raises(OmivInputError, match="unsupported quantization schema"):
        parse_quantization_bytes(b'{"schema":"omiv.unknown.v9"}')


def test_strict_json_rejects_duplicate_keys() -> None:
    with pytest.raises(OmivInputError, match="duplicate object key"):
        parse_quantization_bytes(b'{"schema":"x","schema":"y"}')


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_strict_json_rejects_non_finite(constant: str) -> None:
    with pytest.raises(OmivInputError, match="non-finite"):
        parse_quantization_bytes(
            f'{{"schema":"omiv.quantization-fidelity-policy.v1","x":{constant}}}'.encode()
        )


def test_invalid_enum_is_rejected(generated: Path) -> None:
    raw = json.loads((generated / "quantization-fidelity/evidence/exact.json").read_bytes())
    raw["numerical_status"] = "VERIFIED"
    with pytest.raises(ValidationError):
        QuantizationFidelityEvidence.model_validate(raw)


def test_strict_schema_import_rejects_exponent_bomb(generated: Path) -> None:
    raw = json.loads((generated / "quantization-fidelity/policies/synthetic.json").read_bytes())
    raw["minimum_element_coverage"] = "1E999999999"
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED"):
        parse_quantization_bytes(json.dumps(raw).encode())


def test_canonical_json_rejects_binary_non_finite() -> None:
    with pytest.raises(OmivInputError):
        canonical_json_bytes({"value": float("nan")})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (Decimal("-0"), "0"),
        (Decimal("0.000"), "0"),
        (Decimal("1.2300"), "1.23"),
        (Decimal("1E+3"), "1000"),
    ],
)
def test_decimal_canonicalization(value: Decimal, expected: str) -> None:
    assert canonical_decimal(value) == expected


def test_decimal_rounding_is_half_even() -> None:
    value = Decimal("1." + "0" * 48 + "15")
    assert canonical_decimal(value).endswith("2")


def test_negative_zero_decimal_input_is_rejected() -> None:
    with pytest.raises(ValidationError, match="canonical decimal"):
        FidelityThresholds(maximum_absolute_error="-0")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", "0"),
        ("-0", "0"),
        ("0.0", "0"),
        ("-0.000", "0"),
        ("1", "1"),
        ("1.0", "1"),
        ("1.00", "1"),
        ("1e0", "1"),
        ("1E+0", "1"),
        ("0.1", "0.1"),
        ("1e-308", "0." + "0" * 307 + "1"),
        ("1e308", "1" + "0" * 308),
    ],
)
def test_bounded_decimal_equivalent_inputs_normalize(value: str, expected: str) -> None:
    assert canonical_decimal(parse_bounded_decimal(value)) == expected


@pytest.mark.parametrize(
    "value",
    [
        "1e999999999",
        "1e309",
        "1e-309",
        "1" * 101,
        " 1",
        "1 ",
        "+1",
        "01",
        ".1",
        "1.",
        "--1",
        "1e",
        "NaN",
        "sNaN",
        "Infinity",
        "-Infinity",
    ],
)
def test_bounded_decimal_rejects_invalid_or_excessive_values(value: str) -> None:
    with pytest.raises(ValueError):
        parse_bounded_decimal(value)


def test_decimal_scale_has_stricter_magnitude_bound() -> None:
    assert parse_bounded_decimal("1e128", maximum_adjusted_exponent=128).adjusted() == 128
    with pytest.raises(ValueError, match="LIMIT_EXCEEDED"):
        parse_bounded_decimal("1e129", maximum_adjusted_exponent=128)


def test_non_string_numerical_inputs_are_rejected() -> None:
    with pytest.raises(ValueError, match="must be strings"):
        measure_values(
            (1,),  # type: ignore[arg-type]
            ("1",),
            source_tensor_id="quantization_tensor_" + "1" * 32,
            candidate_tensor_id="quantization_tensor_" + "2" * 32,
        )


def test_global_decimal_context_cannot_change_output() -> None:
    value = Decimal("1.234567890123456789012345678901234567890123456789055")
    expected = canonical_decimal(value)
    original = getcontext().copy()
    try:
        getcontext().prec = 2
        getcontext().rounding = ROUND_DOWN
        getcontext().traps[InvalidOperation] = False
        getcontext().flags[InvalidOperation] = True
        assert canonical_decimal(value) == expected
    finally:
        setcontext(original)


def test_canonical_object_domain_separators_do_not_collide() -> None:
    left = finalize_identity(
        {"schema": "omiv.example-left.v1", "value": "same"},
        "left_id",
        "left_",
        "left_digest",
    )
    right = finalize_identity(
        {"schema": "omiv.example-right.v1", "value": "same"},
        "right_id",
        "right_",
        "right_digest",
    )
    assert left["left_id"] != right["right_id"]
    assert left["left_digest"] != right["right_digest"]


def test_declaration_is_not_observation(generated: Path) -> None:
    values = _core(generated)
    declaration = values["declaration"]
    source = values["source"]
    assert declaration.declaration_id != source.observation_id
    assert "execution" not in declaration.model_fields_set
    assert source.execution.object_id.startswith("quantization_execution_")


def test_execution_has_no_future_result_reference(generated: Path) -> None:
    raw = json.loads((generated / "quantization-fidelity/executions/synthetic.json").read_bytes())
    serialized = json.dumps(raw, sort_keys=True)
    assert "observation_id" not in serialized
    assert "measurement_id" not in serialized
    assert "comparison_id" not in serialized
    assert "evidence_id" not in serialized


def test_downstream_references_are_finalized(generated: Path) -> None:
    values = _core(generated)
    comparison = values["comparison"]
    assert comparison.source_observation.object_id == values["source"].observation_id
    assert comparison.correspondence.object_digest == values["correspondence"].correspondence_digest


@pytest.mark.parametrize(
    "edges",
    [
        {"a": {"a"}},
        {"a": {"b"}, "b": {"a"}},
        {"a": {"b"}, "b": {"c"}, "c": {"a"}},
    ],
)
def test_dependency_graph_rejects_cycles(edges: dict[str, set[str]]) -> None:
    with pytest.raises(ValueError, match="cycle"):
        assert_acyclic(edges)


def test_generated_dependency_graph_is_acyclic(generated: Path) -> None:
    index = _load(
        generated,
        "quantization-fidelity/artifact-index.json",
        QuantizationArtifactIndex,
    )
    verify_generated_dependency_graph(generated, index)


def test_signature_is_outside_unsigned_identity(generated: Path) -> None:
    evidence = json.loads((generated / "quantization-fidelity/evidence/exact.json").read_bytes())
    envelope = _load(
        generated,
        "quantization-fidelity/signed/evidence.envelope.json",
        SignedObjectEnvelope,
    )
    assert envelope.signed_object == evidence
    assert "signatures" not in evidence
    assert envelope.signed_object_digest == canonical_sha256(evidence)
    assert envelope.signed_object_digest != evidence["evidence_digest"]


@pytest.mark.parametrize(
    "name",
    ["declaration", "observation", "evidence"],
)
def test_representative_signed_objects_verify(generated: Path, name: str) -> None:
    envelope = _load(
        generated,
        f"quantization-fidelity/signed/{name}.envelope.json",
        SignedObjectEnvelope,
    )
    _validate_source_object(envelope)


def test_only_representative_objects_are_signed(generated: Path) -> None:
    signed = sorted(
        path.name for path in (generated / "quantization-fidelity/signed").glob("*.envelope.json")
    )
    assert signed == [
        "declaration.envelope.json",
        "evidence.envelope.json",
        "observation.envelope.json",
    ]


def test_source_and_candidate_identity_are_distinct(generated: Path) -> None:
    values = _core(generated)
    assert values["source"].artifact.role == ArtifactRole.SOURCE
    assert values["candidate"].artifact.role == ArtifactRole.CANDIDATE
    assert (
        values["source"].artifact.artifact_set_identity
        != values["candidate"].artifact.artifact_set_identity
    )


def test_digest_only_does_not_become_available() -> None:
    artifact = ArtifactIdentity(
        subject_id="product_subject_" + "0" * 32,
        role=ArtifactRole.SOURCE,
        provider=None,
        namespace=None,
        artifact_name="digest-only",
        requested_revision=None,
        resolved_revision=None,
        local_payload_manifest=None,
        remote_snapshot=None,
        artifact_set_identity="1" * 64,
        coverage="digest.reference-only",
        identity_semantics="sha256.unmaterialized-reference",
        availability=ArtifactAvailability.DIGEST_REFERENCE_ONLY,
        limitations=("Referenced canonical object was not supplied.",),
    )
    assert artifact.availability == ArtifactAvailability.DIGEST_REFERENCE_ONLY


def test_phase6a_exact_binding_is_preserved(generated: Path) -> None:
    source = _core(generated)["source"]
    assert source.artifact.local_payload_manifest is not None
    manifest = json.loads(
        (generated / "quantization-fidelity/bindings/source-values.json.manifest.json").read_bytes()
    )
    assert source.artifact.local_payload_manifest.object_id == manifest["manifest_id"]
    assert source.artifact.artifact_set_identity == manifest["artifact_set_payload_digest"]


def test_phase6a_exact_binding_requires_artifact_set(generated: Path) -> None:
    source = _core(generated)["source"].artifact
    with pytest.raises(ValidationError, match="artifact set"):
        source.model_copy(
            update={"artifact_set_identity": None}, deep=True
        ).__class__.model_validate(
            {**source.model_dump(mode="json"), "artifact_set_identity": None}
        )


def test_phase6b_non_payload_identifiers_are_not_upgraded() -> None:
    snapshot = RemoteSnapshotManifest.model_validate(
        json.loads((ROOT / "reconciliation/practice/xai/grok-1/snapshot.json").read_bytes())
    )
    assert not any(
        digest.payload_comparable for member in snapshot.members for digest in member.digests
    )
    kinds = {digest.kind for member in snapshot.members for digest in member.digests}
    assert {
        DigestKind.LFS_OID_SHA256,
        DigestKind.XET_OBJECT_ID,
        DigestKind.PROVIDER_OPAQUE_ID,
    } <= kinds
    assert DigestKind.PAYLOAD_SHA256 not in kinds


def test_phase6b_listing_completeness_does_not_create_numerical_completeness(
    generated: Path,
) -> None:
    comparison = _load(
        generated,
        "quantization-fidelity/metadata-only/comparison.json",
        QuantizationFidelityComparison,
    )
    assert comparison.numerical_status == NumericalStatus.PAYLOAD_VALUES_UNAVAILABLE


@pytest.mark.parametrize(
    "name",
    [
        "/absolute",
        "../parent",
        "a\\b",
        "con",
        "bad\x00name",
        "bad\ud800name",
        "bad\uffffname",
        "trailing. ",
    ],
)
def test_tensor_name_portability(generated: Path, name: str) -> None:
    values = _core(generated)
    tensor = values["source"].tensors[0]
    raw = tensor.model_dump(mode="json", by_alias=True)
    raw["logical_name"] = name
    with pytest.raises((ValidationError, ValueError)):
        TensorRepresentationRecord.model_validate(raw)


def test_tensor_unicode_normalization_collision(generated: Path) -> None:
    values = _core(generated)
    tensor = values["source"].tensors[0]
    other = build_tensor(
        artifact_identity=tensor.artifact_identity,
        logical_name="Model/Weight",
        role=tensor.role,
        shape=tensor.shape,
        storage_dtype=tensor.storage_dtype,
        logical_dtype=tensor.logical_dtype,
        quantization=tensor.quantization,
        observation_level=tensor.observation_level,
        observed_element_count=tensor.observed_element_count,
        provenance=tensor.provenance,
    )
    with pytest.raises(ValueError, match="colliding"):
        build_observation(
            values["execution"],
            values["source"].artifact,
            values["source"].format_descriptor,
            (tensor, other),
            values["source"].coverage,
        )


def test_tensor_shape_product_is_bounded_before_identity(generated: Path) -> None:
    tensor = _core(generated)["source"].tensors[0]
    with pytest.raises(ValueError, match="LIMIT_EXCEEDED"):
        build_tensor(
            artifact_identity=tensor.artifact_identity,
            logical_name="huge/weight",
            role=tensor.role,
            shape=(100_000_000, 2),
            storage_dtype=tensor.storage_dtype,
            logical_dtype=tensor.logical_dtype,
            quantization=tensor.quantization,
            observation_level=tensor.observation_level,
            observed_element_count=0,
            provenance=tensor.provenance,
        )


def test_tensor_roles_remain_distinct() -> None:
    assert len(set(TensorRole)) == 7
    assert TensorRole.ABSENT_ROLE != TensorRole.OTHER_DECLARED
    assert TensorRole.PRIMARY_WEIGHT != TensorRole.QUANTIZATION_PARAMETER


@pytest.mark.parametrize("cardinality", list(CorrespondenceCardinality))
def test_correspondence_cardinality_is_explicit(cardinality: CorrespondenceCardinality) -> None:
    assert cardinality.value


def test_ambiguous_correspondence_is_not_numerically_evaluable() -> None:
    mapping = build_mapping(
        (),
        (),
        cardinality="AMBIGUOUS",
        numerical_status=MappingNumericalStatus.AMBIGUOUS,
    )
    assert mapping.cardinality == CorrespondenceCardinality.AMBIGUOUS


def test_one_to_many_requires_recipe_for_numerical_evaluation() -> None:
    with pytest.raises(ValidationError, match="requires recipe"):
        build_mapping(
            ("quantization_tensor_" + "1" * 32,),
            ("quantization_tensor_" + "2" * 32, "quantization_tensor_" + "3" * 32),
            cardinality="ONE_TO_MANY_DECLARED",
            numerical_status=MappingNumericalStatus.NUMERICALLY_EVALUABLE,
        )


def test_structural_and_numerical_findings_are_simultaneous(generated: Path) -> None:
    values = _core(generated)
    original = values["candidate"].tensors[0]
    reshaped = build_tensor(
        artifact_identity=original.artifact_identity,
        logical_name=original.logical_name,
        role=original.role,
        shape=(2, 2),
        storage_dtype=original.storage_dtype,
        logical_dtype=original.logical_dtype,
        quantization=original.quantization,
        observation_level=original.observation_level,
        observed_element_count=4,
        provenance=original.provenance,
    )
    candidate = build_observation(
        values["execution"],
        values["candidate"].artifact,
        values["candidate"].format_descriptor,
        (reshaped,),
        values["candidate"].coverage,
    )
    mapping = build_mapping(
        (values["source"].tensors[0].tensor_id,),
        (reshaped.tensor_id,),
        cardinality="ONE_TO_ONE",
        numerical_status=MappingNumericalStatus.NUMERICALLY_EVALUABLE,
    )
    correspondence = build_correspondence(values["source"], candidate, (mapping,))
    parameters = build_parameters(
        candidate,
        reshaped,
        scale="0.5",
        zero_point=2,
        provenance=ParameterProvenance.OBSERVED_FROM_PAYLOAD,
        complete=True,
    )
    metric = measure_values(
        ("-1", "0", "1", "2"),
        ("-1", "0", "1", "2.5"),
        source_tensor_id=values["source"].tensors[0].tensor_id,
        candidate_tensor_id=reshaped.tensor_id,
    )
    measurement = build_measurement(
        values["source"],
        candidate,
        correspondence,
        (parameters,),
        (metric,),
        values["candidate"].coverage,
        observation_level=ObservationLevel.FULL_TENSOR_VALUES,
    )
    comparison = compare_representations(
        values["declaration"],
        values["source"],
        candidate,
        correspondence,
        (parameters,),
        (measurement,),
        expectation_scope=values["comparison"].expectation_scope,
        coverage=values["candidate"].coverage,
    )
    kinds = {finding.kind for finding in comparison.findings}
    assert FindingKind.SHAPE_MISMATCH in kinds
    assert FindingKind.NUMERICAL_DIFFERENCE_OBSERVED in kinds


def test_affine_reconstruction(generated: Path) -> None:
    parameters = _core(generated)["parameters"]
    assert reconstruct_values(("0", "2", "4", "6"), parameters) == ("-1", "0", "1", "2")


@pytest.mark.parametrize("scale", ["0", "-1"])
def test_affine_scale_must_be_positive(generated: Path, scale: str) -> None:
    parameters = _core(generated)["parameters"].model_copy(update={"scale": scale})
    with pytest.raises(ValueError, match="scale"):
        reconstruct_values(("0",), parameters)


@pytest.mark.parametrize(
    ("signed", "zero_point"),
    [(True, 128), (True, -129), (False, -1), (False, 256)],
)
def test_affine_zero_point_range(generated: Path, signed: bool, zero_point: int) -> None:
    parameters = _core(generated)["parameters"].model_copy(
        update={"storage_signed": signed, "zero_point": zero_point}
    )
    with pytest.raises(ValueError, match="zero point"):
        reconstruct_values(("0",), parameters)


@pytest.mark.parametrize(
    ("signed", "value"),
    [(True, 128), (True, -129), (False, -1), (False, 256)],
)
def test_affine_value_range(generated: Path, signed: bool, value: int) -> None:
    parameters = _core(generated)["parameters"].model_copy(update={"storage_signed": signed})
    with pytest.raises(ValueError, match="outside declared range"):
        reconstruct_values((str(value),), parameters)


@pytest.mark.parametrize(
    "update",
    [{"quantization_axis": 0}, {"block_size": 2}, {"group_size": 2}],
)
def test_unsupported_axis_group_block_fail_closed(generated: Path, update: dict[str, int]) -> None:
    parameters = _core(generated)["parameters"].model_copy(update=update)
    with pytest.raises(ValueError, match="FORMAT_NOT_NUMERICALLY_SUPPORTED"):
        reconstruct_values(("0", "2", "4", "6"), parameters)


def test_unsupported_codec_never_falls_back_to_affine(generated: Path) -> None:
    parameters = _core(generated)["parameters"].model_copy(
        update={"numerical_codec": NumericalCodec.UNSUPPORTED}
    )
    with pytest.raises(ValueError, match="FORMAT_NOT_NUMERICALLY_SUPPORTED"):
        reconstruct_values(("0",), parameters)


def test_exact_metrics(generated: Path) -> None:
    metric = _core(generated)["measurement"].metrics[0]
    assert metric.exact_equality_count == 4
    assert metric.maximum_absolute_error.value == "0"
    assert metric.mean_absolute_error.value == "0"
    assert metric.mean_squared_error.value == "0"
    assert metric.root_mean_squared_error.value == "0"
    assert metric.relative_l2_error.value == "0"
    assert metric.cosine_similarity.value == "1"


def test_non_exact_metrics() -> None:
    metric = measure_values(
        ("0", "1"),
        ("1", "3"),
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
    )
    assert metric.maximum_absolute_error.value == "2"
    assert metric.mean_absolute_error.value == "1.5"
    assert metric.mean_squared_error.value == "2.5"
    assert metric.signed_mean_error.value == "1.5"


@pytest.mark.parametrize(
    ("source", "candidate", "maximum", "mae", "mse", "rmse", "relative", "dot", "cosine", "bias"),
    [
        (("1",), ("1",), "0", "0", "0", "0", "0", "1", "1", "0"),
        (("-1",), ("1",), "2", "2", "4", "2", "2", "-1", "-1", "2"),
        (("1", "-1"), ("-1", "1"), "2", "2", "4", "2", "2", "-2", "-1", "0"),
        (
            ("1", "0"),
            ("0", "1"),
            "1",
            "1",
            "1",
            "1",
            "1.4142135623730950488016887242096980785696718753769",
            "0",
            "0",
            "0",
        ),
        (
            ("0", "0"),
            ("1", "3"),
            "3",
            "2",
            "5",
            "2.2360679774997896964091736687312762354406183596115",
            None,
            "0",
            None,
            "2",
        ),
        (
            ("0", "0"),
            ("-1", "-3"),
            "3",
            "2",
            "5",
            "2.2360679774997896964091736687312762354406183596115",
            None,
            "0",
            None,
            "-2",
        ),
    ],
)
def test_manually_calculable_metric_vectors(
    source: tuple[str, ...],
    candidate: tuple[str, ...],
    maximum: str,
    mae: str,
    mse: str,
    rmse: str | None,
    relative: str | None,
    dot: str,
    cosine: str | None,
    bias: str,
) -> None:
    metric = measure_values(
        source,
        candidate,
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
    )
    assert metric.maximum_absolute_error.value == maximum
    assert metric.mean_absolute_error.value == mae
    assert metric.mean_squared_error.value == mse
    if rmse is not None:
        assert metric.root_mean_squared_error.value == rmse
    if relative is not None:
        assert metric.relative_l2_error.value == relative
    assert metric.dot_product.value == dot
    assert metric.cosine_similarity.value == cosine
    assert metric.signed_mean_error.value == bias


def test_quantization_boundary_count_is_not_clipping() -> None:
    metric = measure_values(
        ("0", "1"),
        ("0", "1"),
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
        at_quantization_bound_count=1,
    )
    assert metric.at_quantization_bound_count == 1
    assert metric.clipping_status == "CLIPPING_NOT_EVALUATED"


def test_zero_vector_metric_states() -> None:
    metric = measure_values(
        ("0", "0"),
        ("0", "0"),
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
    )
    assert metric.relative_l2_error.state == MetricState.UNDEFINED_ZERO_REFERENCE_NORM
    assert metric.cosine_similarity.state == MetricState.UNDEFINED_ZERO_VECTOR


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_input_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="NON_FINITE_INPUT"):
        measure_values(
            (value,),
            ("0",),
            source_tensor_id="quantization_tensor_" + "1" * 32,
            candidate_tensor_id="quantization_tensor_" + "2" * 32,
        )


@pytest.mark.parametrize(
    ("population", "requested", "expected"),
    [(0, 0, ()), (0, 5, ()), (1, 1, (0,)), (3, 9, (0, 1, 2)), (10, 0, ())],
)
def test_sampling_boundaries(population: int, requested: int, expected: tuple[int, ...]) -> None:
    sample = build_sample_definition(
        seed="seed",
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
        population_count=population,
        requested_count=requested,
        maximum_count=10,
    )
    assert sample.selected_indices == expected


def test_sampling_is_deterministic_and_identity_bound() -> None:
    arguments = {
        "seed": "seed",
        "source_tensor_id": "quantization_tensor_" + "1" * 32,
        "candidate_tensor_id": "quantization_tensor_" + "2" * 32,
        "population_count": 100,
        "requested_count": 10,
        "maximum_count": 10,
    }
    first = build_sample_definition(**arguments)
    assert first == build_sample_definition(**arguments)
    assert (
        first.selected_indices
        != build_sample_definition(**{**arguments, "seed": "other"}).selected_indices
    )
    assert (
        first.selected_indices
        != build_sample_definition(
            **{**arguments, "source_tensor_id": "quantization_tensor_" + "3" * 32}
        ).selected_indices
    )
    assert (
        first.selected_indices
        != build_sample_definition(**{**arguments, "population_count": 101}).selected_indices
    )


def test_sampling_limit_exceeded() -> None:
    sample = build_sample_definition(
        seed="seed",
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
        population_count=100,
        requested_count=11,
        maximum_count=10,
    )
    assert sample.status == "LIMIT_EXCEEDED"
    assert sample.selected_indices == ()


def test_sampling_population_and_work_bounds_are_explicit() -> None:
    sample = build_sample_definition(
        seed="seed",
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
        population_count=1_000_000_001,
        requested_count=1,
        maximum_count=1,
    )
    assert sample.status == "LIMIT_EXCEEDED"
    assert sample.hash_attempt_count == 0
    assert sample.maximum_population_count == 1_000_000_000
    assert sample.maximum_population_traversal_count == 100_000
    assert sample.maximum_hash_attempts == 12_800_000
    assert sample.maximum_stored_candidates == 100_000


def test_sampling_caller_cannot_raise_hard_sample_limit() -> None:
    with pytest.raises(ValueError, match="LIMIT_EXCEEDED"):
        build_sample_definition(
            seed="seed",
            source_tensor_id="quantization_tensor_" + "1" * 32,
            candidate_tensor_id="quantization_tensor_" + "2" * 32,
            population_count=1_000_000_000,
            requested_count=100_001,
            maximum_count=100_001,
        )


def test_sampled_success_is_never_complete(generated: Path) -> None:
    evidence = _load(
        generated,
        "quantization-fidelity/evidence/sampled.json",
        QuantizationFidelityEvidence,
    )
    element = next(x for x in evidence.coverage if x.dimension == "NUMERICAL_ELEMENT")
    assert evidence.numerical_status == NumericalStatus.SAMPLED_WITHIN_POLICY
    assert (
        evidence.expectation_scope
        == __import__(
            "omiv.quantization.models", fromlist=["ExpectationScope"]
        ).ExpectationScope.DETERMINISTIC_SAMPLE_SCOPE
    )
    assert element.numerator < element.denominator


def test_coverage_keeps_counts_not_only_percentages(generated: Path) -> None:
    evidence = _load(
        generated,
        "quantization-fidelity/evidence/sampled.json",
        QuantizationFidelityEvidence,
    )
    assert all(value.numerator >= 0 for value in evidence.coverage)
    assert any(value.denominator is None for value in evidence.coverage)


def test_complete_and_selected_scopes_remain_distinct(generated: Path) -> None:
    comparison = _core(generated)["comparison"]
    assert comparison.expectation_scope.value == "SELECTED_REQUIRED_TENSORS"
    assert not comparison.complete_model_equivalence_claimed


def test_policy_preserves_multiple_failures(generated: Path) -> None:
    evaluation = _load(
        generated,
        "quantization-fidelity/policy-evaluations/outside-policy.json",
        QuantizationPolicyEvaluation,
    )
    failures = [
        value
        for value in evaluation.requirements
        if value.status == RequirementStatus.POLICY_REQUIREMENT_FAILED
    ]
    assert len(failures) >= 4


def test_policy_per_role_and_tensor_thresholds(generated: Path) -> None:
    values = _core(generated)
    strict = FidelityThresholds(maximum_absolute_error="0")
    base = values["policy"]
    raw = base.model_dump(mode="json", by_alias=True)
    raw["per_role_thresholds"] = [
        RoleThreshold(role=TensorRole.PRIMARY_WEIGHT, thresholds=strict).model_dump(mode="json")
    ]
    raw["per_tensor_overrides"] = [
        TensorThreshold(
            tensor_id=values["candidate"].tensors[0].tensor_id, thresholds=strict
        ).model_dump(mode="json")
    ]
    raw.pop("policy_id")
    raw.pop("policy_digest")
    policy = QuantizationFidelityPolicy.model_validate(
        finalize_identity(raw, "policy_id", "quantization_policy_", "policy_digest")
    )
    evaluation = evaluate_policy(
        policy,
        values["comparison"],
        values["measurement"],
        values["candidate"],
        values["authority"],
        declaration=values["declaration"],
    )
    names = {value.requirement for value in evaluation.requirements}
    assert any(name.startswith("role.primary_weight") for name in names)
    assert any(name.startswith("tensor.quantization_tensor_") for name in names)
    role_result = next(
        value
        for value in evaluation.requirements
        if value.requirement.startswith("role.primary_weight.maximum_absolute_error")
    )
    tensor_result = next(
        value
        for value in evaluation.requirements
        if value.requirement.startswith("tensor.quantization_tensor_")
        and value.requirement.endswith("maximum_absolute_error")
    )
    assert role_result.status == RequirementStatus.POLICY_REQUIREMENT_NOT_APPLICABLE
    assert tensor_result.status == RequirementStatus.POLICY_REQUIREMENT_SATISFIED


def test_empty_scope_cannot_pass_vacuously(generated: Path) -> None:
    values = _core(generated)
    empty_coverage = tuple(
        CoverageDimension(
            dimension=dimension,
            numerator=0,
            denominator=0,
            status="COMPLETE",
        )
        for dimension in (
            "SOURCE_TENSOR",
            "CANDIDATE_TENSOR",
            "MAPPED_TENSOR",
            "MANDATORY_ROLE",
            "NUMERICAL_TENSOR",
            "NUMERICAL_ELEMENT",
            "BYTE",
            "QUANTIZATION_PARAMETER",
        )
    )
    candidate = build_observation(
        values["execution"],
        values["candidate"].artifact,
        values["candidate"].format_descriptor,
        (),
        empty_coverage,
    )
    correspondence = build_correspondence(values["source"], candidate, ())
    comparison = compare_representations(
        values["declaration"],
        values["source"],
        candidate,
        correspondence,
        (),
        (),
        expectation_scope=ExpectationScope.PARTIAL_REFERENCE_SET,
        coverage=empty_coverage,
    )
    raw = values["policy"].model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "required_tensor_roles": [],
            "minimum_tensor_coverage": "0",
            "minimum_element_coverage": "0",
            "minimum_byte_coverage": "0",
            "minimum_parameter_coverage": "0",
            "default_thresholds": FidelityThresholds().model_dump(mode="json"),
        }
    )
    raw.pop("policy_id")
    raw.pop("policy_digest")
    policy = QuantizationFidelityPolicy.model_validate(
        finalize_identity(raw, "policy_id", "quantization_policy_", "policy_digest")
    )
    evaluation = evaluate_policy(
        policy, comparison, None, candidate, declaration=values["declaration"]
    )
    assert not evaluation.policy_satisfied_for_declared_scope
    assert evaluation.overall_status != OverallEvidenceStatus.CONFORMS_FOR_DECLARED_SCOPE
    scope = next(
        value
        for value in evaluation.requirements
        if value.requirement == "scope.non-empty-candidate-tensors"
    )
    assert scope.status == RequirementStatus.POLICY_REQUIREMENT_FAILED


def test_cross_phase_different_bytes_cannot_be_linked(generated: Path) -> None:
    evidence = _load(
        generated,
        "quantization-fidelity/evidence/exact.json",
        QuantizationFidelityEvidence,
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        build_integration(
            evidence,
            "SECURITY",
            source_object=evidence.comparison,
            subject_identity_match=True,
            payload_identity_match=False,
            derived_status="MUST_NOT_LINK",
        )


def test_phase6c_signing_rejects_wrong_object_type_and_purpose(generated: Path) -> None:
    evidence = json.loads((generated / "quantization-fidelity/evidence/exact.json").read_bytes())
    with pytest.raises(OmivInputError, match="does not match"):
        build_descriptor(
            evidence,
            SignedObjectType.QUANTIZATION_RELATIONSHIP_DECLARATION,
            SignaturePurpose.QUANTIZATION_RELATIONSHIP_DECLARATION_ISSUANCE,
        )
    with pytest.raises(OmivInputError, match="purpose"):
        build_descriptor(
            evidence,
            SignedObjectType.QUANTIZATION_FIDELITY_EVIDENCE,
            SignaturePurpose.REPRESENTATION_OBSERVATION_ISSUANCE,
        )


def test_metadata_signature_namespace_cannot_create_pass_or_authority(generated: Path) -> None:
    evidence = _load(
        generated,
        "quantization-fidelity/metadata-only/evidence.json",
        QuantizationFidelityEvidence,
    )
    envelope = _load(
        generated,
        "quantization-fidelity/signed/evidence.envelope.json",
        SignedObjectEnvelope,
    )
    assert envelope.signed_object_type == SignedObjectType.QUANTIZATION_FIDELITY_EVIDENCE
    assert evidence.overall_status != OverallEvidenceStatus.CONFORMS_FOR_DECLARED_SCOPE
    assert not evidence.authority_established


def test_trusted_signature_does_not_create_transformer_authority(generated: Path) -> None:
    authority = _core(generated)["authority"]
    report = json.loads(
        (generated / "quantization-fidelity/signed/evidence.signature-report.json").read_bytes()
    )
    assert report["overall_status"] == "TRUSTED_SIGNATURE_WITH_LIMITATIONS"
    assert authority.transformation_authority == AuthorityStatus.NOT_ESTABLISHED
    assert not authority.signature_creates_publisher_authority


def test_authority_scope_mismatch_is_explicit(generated: Path) -> None:
    declaration = _core(generated)["declaration"]
    authority = build_authority_evaluation(
        declaration,
        transformation=AuthorityStatus.SCOPE_MISMATCH,
        measurement_signature="SIGNATURE_VALID",
        measurement_signer_trust="SIGNER_TRUSTED",
        measurement_signer_authorized="SIGNER_NOT_AUTHORIZED_FOR_PURPOSE",
    )
    assert authority.transformation_authority == AuthorityStatus.SCOPE_MISMATCH
    assert not authority.subject_scope_authorized


def test_integrations_do_not_create_approval_security_or_runtime(generated: Path) -> None:
    paths = (generated / "quantization-fidelity/integrations").glob("*.json")
    for path in paths:
        value = json.loads(path.read_bytes())
        assert value["creates_governance_approval"] is False
        assert value["creates_security_pass"] is False
        assert value["creates_observed_runtime_identity"] is False
        assert value["mutates_prior_artifact"] is False


def test_historical_not_recorded_is_preserved(generated: Path) -> None:
    value = json.loads(
        (generated / "quantization-fidelity/integrations/historical.json").read_bytes()
    )
    assert value["available_at"] == value["observed_at"] == value["evaluated_at"] == "NOT_RECORDED"


def test_xai_readiness_exact_offline_facts() -> None:
    readiness, _ = build_xai_readiness(ROOT)
    assert readiness.classification == (
        "XAI_QUANTIZATION_FIDELITY_READINESS_RECORDED_WITHOUT_PAYLOAD_OR_QUANTIZED_CANDIDATE"
    )
    assert readiness.payload_comparable_members == 0
    assert readiness.quantization_fidelity == "NOT_EVALUATED"
    assert readiness.quantization_relationship == "NOT_ESTABLISHED"
    assert readiness.candidate_quantized_artifact == "NOT_SUPPLIED"
    assert [item.resolved_revision for item in readiness.pinned_metadata] == [
        "5de83eb225f49624b424f1c8aa74f96983b5885c",
        "daf4395a80ad177386cfe39641b64fc12b1d70ed",
    ]


def test_xai_fixtures_remain_exact() -> None:
    expected = {
        "grok-1": (466_308, "645ea0fbd09c85a1d69d4fd217bae43e580a04fcd484308d1cd71b528658ae78"),
        "grok-2": (27_473, "ad495d2fbb3daaed25ddf8d351647254f2d7020d2d4492b89f90aea486c3a60b"),
    }
    for name, (size, digest) in expected.items():
        raw = (ROOT / f"fixtures/reconciliation/xai/{name}.pinned-metadata.json").read_bytes()
        assert (len(raw), hashlib.sha256(raw).hexdigest()) == (size, digest)


def test_xai_readiness_invents_no_quantization_facts(generated: Path) -> None:
    value = _load(
        generated,
        "quantization-fidelity/practice/xai/readiness.json",
        XaiQuantizationReadiness,
    )
    text = pretty_json(value)
    for prohibited in ("bit_width", "group_size", "zero_point", "candidate_revision", "scale"):
        assert prohibited not in text


def test_core_imports_no_profiles_or_model_families() -> None:
    forbidden = {
        "quantization_profiles",
        "reconciliation_profiles",
        "xai",
        "grok",
        "kimi",
        "deepseek",
    }
    for path in (ROOT / "src/omiv/quantization").glob("*.py"):
        tree = ast.parse(path.read_text())
        imports = {
            alias.name.casefold()
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        imports.update(
            node.module.casefold()
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        assert not any(any(token in imported for token in forbidden) for imported in imports)


def test_profiles_import_core_outward_only() -> None:
    text = (ROOT / "src/omiv/quantization_profiles/xai.py").read_text()
    assert "from omiv.quantization.models" in text


def test_artifact_index_is_external_self_excluding(generated: Path) -> None:
    index = _load(
        generated,
        "quantization-fidelity/artifact-index.json",
        QuantizationArtifactIndex,
    )
    verify_quantization_artifact_index(generated, index)
    assert "quantization-fidelity/artifact-index.json" not in {
        entry.path for entry in index.entries
    }


def test_generated_content_and_ids_are_unique(generated: Path) -> None:
    index = _load(
        generated,
        "quantization-fidelity/artifact-index.json",
        QuantizationArtifactIndex,
    )
    assert len({entry.sha256 for entry in index.entries}) == len(index.entries)
    assert len({entry.canonical_id for entry in index.entries}) == len(index.entries)


def test_all_required_scenarios_have_distinct_canonical_results(generated: Path) -> None:
    catalog = json.loads(
        (generated / "quantization-fidelity/examples/case-catalog.json").read_bytes()
    )
    assert len(catalog["cases"]) == 22
    references = [value["representative_object"] for value in catalog["cases"]]
    assert len({value["object_id"] for value in references}) == 22
    for case, reference in zip(catalog["cases"], references, strict=True):
        path = generated / f"quantization-fidelity/examples/cases/{case['case_id']}.json"
        result = QuantizationExampleResult.model_validate(json.loads(path.read_bytes()))
        assert result.result_id == reference["object_id"]
        assert result.result_digest == reference["object_digest"]
        assert result.case_id == case["case_id"]


def test_repeated_generation_is_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_all_quantization_examples(first, repository=ROOT)
    generate_all_quantization_examples(second, repository=ROOT)
    paths_first = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    paths_second = sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
    assert paths_first == paths_second
    assert all((first / path).read_bytes() == (second / path).read_bytes() for path in paths_first)


def test_resource_limit_graph_nodes() -> None:
    limits = QuantizationLimits(maximum_dependency_graph_nodes=1)
    with pytest.raises(ValueError, match="LIMIT_EXCEEDED"):
        assert_acyclic({"a": {"b"}}, limits)


def test_bounded_report_preserves_omission_counts(generated: Path) -> None:
    values = _core(generated)
    evaluation = _load(
        generated,
        "quantization-fidelity/policy-evaluations/outside-policy.json",
        QuantizationPolicyEvaluation,
    )
    evidence = _load(
        generated,
        "quantization-fidelity/evidence/outside-policy.json",
        QuantizationFidelityEvidence,
    )
    comparison = _load(
        generated,
        "quantization-fidelity/comparisons/outside-policy.json",
        QuantizationFidelityComparison,
    )
    report = build_report(evidence, comparison, evaluation, values["authority"], finding_limit=1)
    assert report.included_finding_count == 1
    assert report.omitted_finding_count == report.total_finding_count - 1
    assert report.truncation_status == "TRUNCATED"


def test_ten_thousand_tensor_metadata_smoke(generated: Path) -> None:
    values = _core(generated)
    descriptor = values["source"].format_descriptor
    records = tuple(
        build_tensor(
            artifact_identity="1" * 64,
            logical_name=f"layers/{index:05d}/weight",
            role=TensorRole.PRIMARY_WEIGHT,
            shape=(0,),
            storage_dtype="float32",
            logical_dtype="float32",
            quantization=descriptor,
            observation_level=ObservationLevel.METADATA_ONLY,
            observed_element_count=0,
            provenance=ParameterProvenance.OBSERVED_FROM_FORMAT_METADATA,
        )
        for index in range(10_000)
    )
    assert len(records) == 10_000
    assert len({record.tensor_id for record in records}) == 10_000


def test_large_synthetic_value_stream_is_bounded_and_deterministic() -> None:
    values = tuple(str(index % 17) for index in range(20_000))
    metric = measure_values(
        values,
        values,
        source_tensor_id="quantization_tensor_" + "1" * 32,
        candidate_tensor_id="quantization_tensor_" + "2" * 32,
    )
    assert metric.compared_element_count == 20_000
    assert metric.maximum_absolute_error.value == "0"


def test_preservation_audit_covers_every_prior_artifact() -> None:
    audit = audit_baseline(ROOT)
    assert audit["counts"]["included"] == 690
    assert audit["counts"]["excluded"] == 258
    assert audit["counts"]["prior_indexed_members"] == 538
    assert audit["counts"]["prior_indexes"] == 7
    assert audit["path_set_digest"] == (
        "30fe852d53390cc2b3508ac9c0ee94b5be552014bc8c55b04f1436544318dd8f"
    )
    assert audit["changed_paths"] == []
    assert audit["missing_paths"] == []
    assert audit["unexpected_omissions"] == []
    external = audit["external_artifacts"]
    assert len(external) == 1
    assert external[0]["expected_identity_status"] == "EXPECTED_IDENTITY_RECORDED"
    assert external[0]["availability_status"] in {
        "PRESENT_AND_VERIFIED",
        "NOT_AVAILABLE",
    }
    if external[0]["availability_status"] == "PRESENT_AND_VERIFIED":
        assert audit["inventory_digest"] == (
            "b904857eaa150755bc8854ffc8d1238f1f495b8626a26bdc1dad4e92ea98c57c"
        )


def test_ignored_kimi_tensor_identity_is_preserved() -> None:
    observation = observe_external_artifact(ROOT, KIMI_K3_TENSOR_INVENTORY)
    assert observation.expected.identity_status == (
        ExternalArtifactStatus.EXPECTED_IDENTITY_RECORDED
    )
    assert observation.status in {
        ExternalArtifactStatus.PRESENT_AND_VERIFIED,
        ExternalArtifactStatus.NOT_AVAILABLE,
    }
    if observation.available:
        assert observation.observed_size_bytes == 115_542_096
        assert observation.observed_sha256 == KIMI_K3_TENSOR_INVENTORY.sha256
    else:
        assert observation.observed_size_bytes is None
        assert observation.observed_sha256 is None


def test_cli_inspect_and_verify(generated: Path) -> None:
    runner = CliRunner()
    evidence = generated / "quantization-fidelity/evidence/exact.json"
    assert runner.invoke(app, ["quantization", "inspect", str(evidence)]).exit_code == 0
    assert runner.invoke(app, ["quantization", "verify", str(evidence)]).exit_code == 0


def test_cli_metadata_not_evaluated_exit_code(generated: Path) -> None:
    runner = CliRunner()
    evidence = generated / "quantization-fidelity/metadata-only/evidence.json"
    assert runner.invoke(app, ["quantization", "verify", str(evidence)]).exit_code == 1


def test_cli_invalid_input_exit_code(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema":"omiv.unknown.v1"}')
    result = CliRunner().invoke(app, ["quantization", "verify", str(invalid)])
    assert result.exit_code == 2


def test_cli_sample_limit_exit_code(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "quantization",
            "sample",
            "--source-tensor-id",
            "quantization_tensor_" + "1" * 32,
            "--candidate-tensor-id",
            "quantization_tensor_" + "2" * 32,
            "--population",
            "100",
            "--count",
            "11",
            "--maximum-count",
            "10",
            "--seed",
            "seed",
            "--output",
            str(tmp_path / "sample.json"),
        ],
    )
    assert result.exit_code == 2


def test_cli_xai_is_truthful_not_evaluated() -> None:
    result = CliRunner().invoke(app, ["quantization", "practice-xai"])
    assert result.exit_code == 1
    assert "payload_comparable_members=0" in result.stderr


def test_all_generated_json_is_strict(generated: Path) -> None:
    for path in generated.rglob("*.json"):
        raw = path.read_bytes()
        assert b"NaN" not in raw and b"Infinity" not in raw
        json.loads(raw)


def test_no_generated_file_exceeds_five_mib(generated: Path) -> None:
    files = [path for path in generated.rglob("*") if path.is_file()]
    assert max(path.stat().st_size for path in files) < 5 * 1024 * 1024
