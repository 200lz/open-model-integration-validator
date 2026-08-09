"""Strict bounded schema dispatch for Phase 6D canonical objects."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.tokenizer_parity import models

MAX_INPUT_BYTES = 64 * 1024 * 1024
SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "omiv.tokenizer-configuration-expectation.v1": models.TokenizerConfigurationExpectation,
    "omiv.tokenizer-configuration-parity-declaration.v1": (
        models.TokenizerConfigurationParityDeclaration
    ),
    "omiv.tokenizer-configuration-inspection-plan.v1": models.TokenizerConfigurationInspectionPlan,
    "omiv.tokenizer-configuration-execution-record.v1": (
        models.TokenizerConfigurationExecutionRecord
    ),
    "omiv.configuration-observation.v1": models.ConfigurationObservation,
    "omiv.tokenizer-asset-observation.v1": models.TokenizerAssetObservation,
    "omiv.vocabulary-observation.v1": models.VocabularyObservation,
    "omiv.merge-table-observation.v1": models.MergeTableObservation,
    "omiv.added-token-observation.v1": models.AddedTokenObservation,
    "omiv.special-token-observation.v1": models.SpecialTokenObservation,
    "omiv.tokenizer-pipeline-observation.v1": models.TokenizerPipelineObservation,
    "omiv.chat-template-observation.v1": models.ChatTemplateObservation,
    "omiv.tokenizer-probe-set-definition.v1": models.TokenizerProbeSetDefinition,
    "omiv.tokenizer-probe-execution-record.v1": models.TokenizerProbeExecutionRecord,
    "omiv.tokenizer-probe-result-observation.v1": models.TokenizerProbeResultObservation,
    "omiv.tokenizer-configuration-comparison.v1": models.TokenizerConfigurationComparison,
    "omiv.tokenizer-configuration-policy.v1": models.TokenizerConfigurationPolicy,
    "omiv.tokenizer-configuration-policy-evaluation.v1": (
        models.TokenizerConfigurationPolicyEvaluation
    ),
    "omiv.tokenizer-configuration-authority-evaluation.v1": (
        models.TokenizerConfigurationAuthorityEvaluation
    ),
    "omiv.tokenizer-configuration-parity-evidence.v1": models.TokenizerConfigurationParityEvidence,
    "omiv.tokenizer-configuration-integration-summary.v1": (
        models.TokenizerConfigurationIntegrationSummary
    ),
    "omiv.tokenizer-configuration-report.v1": models.TokenizerConfigurationReport,
    "omiv.tokenizer-configuration-scenario-result.v1": models.TokenizerConfigurationScenarioResult,
    "omiv.tokenizer-configuration-scenario-catalog.v1": (
        models.TokenizerConfigurationScenarioCatalog
    ),
    "omiv.tokenizer-configuration-artifact-index.v1": models.TokenizerConfigurationArtifactIndex,
}


def parse_tokenizer_configuration_bytes(
    raw: bytes, *, source_name: str = "tokenizer/config input"
) -> BaseModel:
    value = parse_bounded_json_bytes(raw, source_name=source_name, max_bytes=MAX_INPUT_BYTES)
    _bounded(value)
    model = SCHEMA_MODELS.get(value.get("schema"))
    if model is None:
        raise OmivInputError("unsupported tokenizer/configuration schema")
    try:
        return model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid tokenizer/configuration record: {exc}") from exc


def load_tokenizer_configuration(path: Path, model: type[BaseModel] | None = None) -> BaseModel:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("tokenizer/configuration input must be a regular non-symlink file")
    value, _raw = load_bounded_json(path, max_bytes=MAX_INPUT_BYTES)
    _bounded(value)
    selected = model or SCHEMA_MODELS.get(value.get("schema"))
    if selected is None:
        raise OmivInputError("unsupported tokenizer/configuration schema")
    if model is not None and value.get("schema") not in {
        key for key, item in SCHEMA_MODELS.items() if item is model
    }:
        raise OmivInputError("tokenizer/configuration schema does not match requested type")
    try:
        return selected.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid tokenizer/configuration record: {exc}") from exc


def _bounded(value: object) -> None:
    count = 0

    def walk(child: object, depth: int) -> None:
        nonlocal count
        count += 1
        if count > 500_000:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_MEMBER_COUNT")
        if depth > 64:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_NESTING")
        if isinstance(child, str) and len(child) > 65536:
            raise OmivInputError("LIMIT_EXCEEDED:STRING_LENGTH")
        if isinstance(child, dict):
            for key, item in child.items():
                walk(key, depth + 1)
                walk(item, depth + 1)
        elif isinstance(child, list):
            for item in child:
                walk(item, depth + 1)

    walk(value, 0)
