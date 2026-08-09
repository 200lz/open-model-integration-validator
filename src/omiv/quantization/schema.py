"""Phase 6C schema registry and bounded strict input loading."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.quantization import models
from omiv.quantization.models import INPUT_DECIMAL_PATTERN, MAX_DECIMAL_INPUT_LENGTH

MAX_QUANTIZATION_JSON_BYTES = 64 * 1024 * 1024

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "omiv.quantization-relationship-declaration.v1": models.QuantizationRelationshipDeclaration,
    "omiv.quantization-observation-plan.v1": models.QuantizationObservationPlan,
    "omiv.quantization-execution-record.v1": models.QuantizationExecutionRecord,
    "omiv.representation-observation.v1": models.RepresentationObservation,
    "omiv.tensor-representation-record.v1": models.TensorRepresentationRecord,
    "omiv.tensor-correspondence.v1": models.TensorCorrespondence,
    "omiv.quantization-parameter-observation.v1": models.QuantizationParameterObservation,
    "omiv.deterministic-sample-definition.v1": models.DeterministicSampleDefinition,
    "omiv.numerical-fidelity-measurement.v1": models.NumericalFidelityMeasurement,
    "omiv.quantization-fidelity-comparison.v1": models.QuantizationFidelityComparison,
    "omiv.quantization-fidelity-policy.v1": models.QuantizationFidelityPolicy,
    "omiv.quantization-policy-evaluation.v1": models.QuantizationPolicyEvaluation,
    "omiv.quantization-authority-evaluation.v1": models.QuantizationAuthorityEvaluation,
    "omiv.quantization-fidelity-evidence.v1": models.QuantizationFidelityEvidence,
    "omiv.quantization-integration-summary.v1": models.QuantizationIntegrationSummary,
    "omiv.quantization-fidelity-report.v1": models.QuantizationFidelityReport,
    "omiv.quantization-example-catalog.v1": models.QuantizationExampleCatalog,
    "omiv.quantization-example-result.v1": models.QuantizationExampleResult,
    "omiv.quantization-artifact-index.v1": models.QuantizationArtifactIndex,
}


def parse_quantization_bytes(raw: bytes, *, source_name: str = "quantization input") -> BaseModel:
    value = parse_bounded_json_bytes(
        raw,
        source_name=source_name,
        max_bytes=MAX_QUANTIZATION_JSON_BYTES,
    )
    _check_phase6c_bounds(value)
    model = SCHEMA_MODELS.get(value.get("schema"))
    if model is None:
        raise OmivInputError("unsupported quantization schema")
    try:
        return model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid quantization record: {exc}") from exc


def load_quantization(path: Path, model: type[BaseModel] | None = None) -> BaseModel:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("quantization input must be a regular non-symlink file")
    value, _ = load_bounded_json(path, max_bytes=MAX_QUANTIZATION_JSON_BYTES)
    _check_phase6c_bounds(value)
    selected = model or SCHEMA_MODELS.get(value.get("schema"))
    if selected is None:
        raise OmivInputError("unsupported quantization schema")
    try:
        parsed = selected.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid quantization record: {exc}") from exc
    if model is not None and value.get("schema") not in {
        schema for schema, registered in SCHEMA_MODELS.items() if registered is model
    }:
        raise OmivInputError("quantization schema does not match requested object type")
    return parsed


def _check_phase6c_bounds(value: object) -> None:
    object_count = 0

    def walk(child: object) -> None:
        nonlocal object_count
        object_count += 1
        if object_count > 200_000:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_OBJECT_COUNT")
        if isinstance(child, str):
            if len(child) > 8192:
                raise OmivInputError("LIMIT_EXCEEDED:CANONICAL_STRING_LENGTH")
            if len(child) > MAX_DECIMAL_INPUT_LENGTH and (
                INPUT_DECIMAL_PATTERN.fullmatch(child) is not None
                or child[:1] in {"-", "+"}
                or child[:1].isdigit()
            ):
                raise OmivInputError("LIMIT_EXCEEDED:NUMERIC_STRING_LENGTH")
        elif isinstance(child, dict):
            for key, nested in child.items():
                walk(key)
                walk(nested)
        elif isinstance(child, list):
            for nested in child:
                walk(nested)

    walk(value)
