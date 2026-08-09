"""Canonical provider-profile records outside the provider-neutral core."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.quantization.models import ObjectReference

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ProfileModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class PinnedMetadataReference(ProfileModel):
    provider: Literal["HUGGING_FACE"] = "HUGGING_FACE"
    namespace: Literal["xai-org"] = "xai-org"
    repository: Literal["grok-1", "grok-2"]
    resolved_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    fixture_size: int = Field(ge=0)
    fixture_sha256: str = Field(pattern=SHA256_PATTERN)
    member_count: int = Field(ge=0)
    declared_total_bytes: int = Field(ge=0)
    payload_comparable_members: Literal[0] = 0
    remote_snapshot: ObjectReference
    observation_time: Literal["NOT_RECORDED"] = "NOT_RECORDED"


class XaiQuantizationReadiness(ProfileModel):
    schema_id: Literal["omiv.xai-quantization-readiness.v1"] = Field(
        default="omiv.xai-quantization-readiness.v1", alias="schema"
    )
    readiness_id: str = Field(pattern=r"^xai_quantization_readiness_[0-9a-f]{32}$")
    classification: Literal[
        "XAI_QUANTIZATION_FIDELITY_READINESS_RECORDED_WITHOUT_PAYLOAD_OR_QUANTIZED_CANDIDATE"
    ]
    pinned_metadata: tuple[PinnedMetadataReference, PinnedMetadataReference]
    pinned_public_metadata_available: Literal[True] = True
    phase6b_remote_metadata_evidence_available: Literal[True] = True
    payload_comparable_members: Literal[0] = 0
    source_numerical_values: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"
    candidate_quantized_artifact: Literal["NOT_SUPPLIED"] = "NOT_SUPPLIED"
    quantization_relationship: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    quantization_codec: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    tensor_quantization_parameters: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"
    numerical_comparison: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    quantization_fidelity: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    publisher_authority: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    authenticity: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    freshness: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    runtime_identity: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"
    security: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    behavioral_parity: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    observation_time: Literal["NOT_RECORDED"] = "NOT_RECORDED"
    affiliation: Literal["NO_XAI_ENDORSEMENT_AFFILIATION_APPROVAL_OR_PRODUCTION_CLAIM"]
    future_evidence_required: tuple[str, ...]
    limitations: tuple[str, ...]
    readiness_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> XaiQuantizationReadiness:
        _identity(self, "readiness_id", "xai_quantization_readiness_", "readiness_digest")
        return self


class XaiQuantizationCaseStudy(ProfileModel):
    schema_id: Literal["omiv.xai-quantization-case-study.v1"] = Field(
        default="omiv.xai-quantization-case-study.v1", alias="schema"
    )
    case_study_id: str = Field(pattern=r"^xai_quantization_case_study_[0-9a-f]{32}$")
    title: Literal["OMIV xAI Quantization Fidelity Readiness Case Study"]
    readiness: ObjectReference
    available_evidence: tuple[str, ...]
    unavailable_evidence: tuple[str, ...]
    phase6a_future_binding: str
    phase6b_provenance_context: str
    sampled_vs_full_evaluation: str
    provider_neutral_architecture: Literal[True] = True
    affiliation: Literal["NO_XAI_ENDORSEMENT_AFFILIATION_APPROVAL_OR_PRODUCTION_CLAIM"]
    limitations: tuple[str, ...]
    case_study_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> XaiQuantizationCaseStudy:
        _identity(self, "case_study_id", "xai_quantization_case_study_", "case_study_digest")
        return self


def _identity(value: ProfileModel, id_field: str, prefix: str, digest_field: str) -> None:
    body: dict[str, Any] = value.model_dump(mode="json", by_alias=True)
    digest = body.pop(digest_field)
    identity = body.pop(id_field)
    expected_id = prefix + canonical_sha256(body)[:32]
    if identity != expected_id or digest != canonical_sha256({**body, id_field: expected_id}):
        raise ValueError("canonical identity or digest mismatch")


def finalize_profile(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    value = _json_compatible(body)
    if not isinstance(value, dict):
        raise TypeError("profile identity body must be an object")
    identity = prefix + canonical_sha256(value)[:32]
    value[id_field] = identity
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
