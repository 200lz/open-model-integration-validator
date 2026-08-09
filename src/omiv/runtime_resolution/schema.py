"""Strict bounded Phase 6E schema dispatch."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.runtime_resolution import models

MAX_INPUT_BYTES = 64 * 1024 * 1024
SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    schema: getattr(models, name)
    for schema, name in {
        "omiv.requested-model-identifier.v1": "RequestedModelIdentifier",
        "omiv.identifier-classification.v1": "IdentifierClassification",
        "omiv.resolution-plan.v1": "ResolutionPlan",
        "omiv.resolution-execution-record.v1": "ResolutionExecutionRecord",
        "omiv.provider-routing-statement.v1": "ProviderRoutingStatement",
        "omiv.registry-resolution-receipt.v1": "RegistryResolutionReceipt",
        "omiv.resolution-continuity-assessment.v1": "ResolutionContinuityAssessment",
        "omiv.runtime-artifact-expectation.v1": "RuntimeArtifactExpectation",
        "omiv.deployment-declaration.v1": "DeploymentDeclaration",
        "omiv.deployment-observation.v1": "DeploymentObservation",
        "omiv.runtime-identity-expectation.v1": "RuntimeIdentityExpectation",
        "omiv.runtime-identity-observation.v1": "RuntimeIdentityObservation",
        "omiv.model-runtime-binding.v1": "ModelRuntimeBinding",
        "omiv.backend-descriptor.v1": "BackendDescriptor",
        "omiv.cross-backend-probe-set.v1": "CrossBackendProbeSet",
        "omiv.backend-execution-plan.v1": "BackendExecutionPlan",
        "omiv.backend-execution-record.v1": "BackendExecutionRecord",
        "omiv.backend-result-observation.v1": "BackendResultObservation",
        "omiv.cross-backend-comparison.v1": "CrossBackendComparison",
        "omiv.inference-identity.v1": "InferenceIdentity",
        "omiv.inference-attestation.v1": "InferenceAttestation",
        "omiv.output-provenance-evidence.v1": "OutputProvenanceEvidence",
        "omiv.runtime-resolution-policy.v1": "RuntimeResolutionPolicy",
        "omiv.runtime-resolution-policy-evaluation.v1": "RuntimeResolutionPolicyEvaluation",
        "omiv.runtime-resolution-authority-evaluation.v1": "RuntimeResolutionAuthorityEvaluation",
        "omiv.runtime-resolution-parity-evidence.v1": "RuntimeResolutionParityEvidence",
        "omiv.runtime-resolution-integration-summary.v1": "RuntimeResolutionIntegrationSummary",
        "omiv.assumption-register-entry.v1": "AssumptionRegisterEntry",
        "omiv.runtime-resolution-report.v1": "RuntimeResolutionReport",
        "omiv.runtime-resolution-scenario-result.v1": "RuntimeResolutionScenarioResult",
        "omiv.runtime-resolution-scenario-catalog.v1": "RuntimeResolutionScenarioCatalog",
        "omiv.runtime-resolution-artifact-index.v1": "RuntimeResolutionArtifactIndex",
    }.items()
}


def parse_runtime_resolution_bytes(
    raw: bytes, *, source_name: str = "runtime-resolution input"
) -> BaseModel:
    value = parse_bounded_json_bytes(raw, source_name=source_name, max_bytes=MAX_INPUT_BYTES)
    _bounded(value)
    model = SCHEMA_MODELS.get(value.get("schema"))
    if model is None:
        raise OmivInputError("unsupported runtime-resolution schema")
    try:
        return model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime-resolution record: {exc}") from exc


def load_runtime_resolution(path: Path, model: type[BaseModel] | None = None) -> BaseModel:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("runtime-resolution input must be a regular non-symlink file")
    value, _raw = load_bounded_json(path, max_bytes=MAX_INPUT_BYTES)
    _bounded(value)
    selected = model or SCHEMA_MODELS.get(value.get("schema"))
    if selected is None:
        raise OmivInputError("unsupported runtime-resolution schema")
    if model is not None and value.get("schema") not in {
        schema for schema, registered in SCHEMA_MODELS.items() if registered is model
    }:
        raise OmivInputError("runtime-resolution schema does not match requested type")
    try:
        return selected.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime-resolution record: {exc}") from exc


def _bounded(value: object) -> None:
    count = 0

    def walk(child: object, depth: int) -> None:
        nonlocal count
        count += 1
        if count > 500_000:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_MEMBER_COUNT")
        if depth > 64:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_NESTING")
        if isinstance(child, str) and len(child) > 65_536:
            raise OmivInputError("LIMIT_EXCEEDED:STRING_LENGTH")
        if isinstance(child, dict):
            for key, item in child.items():
                walk(key, depth + 1)
                walk(item, depth + 1)
        elif isinstance(child, list):
            for item in child:
                walk(item, depth + 1)

    walk(value, 0)
