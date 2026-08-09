"""Canonical profile-only models for Phase 6D readiness evidence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.tokenizer_parity.models import ObjectReference


class ProfileModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class PinnedMetadataReference(ProfileModel):
    repository: Literal["grok-1", "grok-2"]
    namespace: Literal["xai-org"] = "xai-org"
    resolved_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    fixture_size: int = Field(ge=0)
    fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    member_count: int = Field(ge=0)
    declared_total_bytes: int = Field(ge=0)
    remote_snapshot: ObjectReference


class XaiTokenizerConfigurationReadiness(ProfileModel):
    schema_id: Literal["omiv.xai-tokenizer-configuration-readiness.v1"] = Field(
        default="omiv.xai-tokenizer-configuration-readiness.v1", alias="schema"
    )
    readiness_id: str = Field(pattern=r"^xai_tokenizer_readiness_[0-9a-f]{32}$")
    readiness_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    classification: Literal[
        "XAI_TOKENIZER_AND_CONFIGURATION_PARITY_READINESS_RECORDED_WITHOUT_REQUIRED_PAYLOAD_ASSETS"
    ]
    pinned_metadata: tuple[PinnedMetadataReference, ...] = Field(min_length=2, max_length=2)
    pinned_repository_tree_metadata: Literal["AVAILABLE"]
    historical_revisions: Literal["AVAILABLE"]
    payload_comparable_members: Literal[0]
    tokenizer_configuration_asset_contents: Literal["NOT_DOWNLOADED"]
    vocabulary: Literal["NOT_OBSERVED"]
    added_tokens: Literal["NOT_OBSERVED"]
    special_tokens: Literal["NOT_OBSERVED"]
    merge_table: Literal["NOT_OBSERVED"]
    tokenizer_pipeline: Literal["NOT_OBSERVED"]
    chat_template: Literal["NOT_OBSERVED"]
    configuration_fields: Literal["NOT_OBSERVED"]
    probes: Literal["NOT_EXECUTED"]
    parity: Literal["NOT_EVALUATED"]
    publisher_authority: Literal["NOT_ESTABLISHED"]
    authenticity: Literal["NOT_ESTABLISHED"]
    freshness: Literal["NOT_ESTABLISHED"]
    runtime_identity: Literal["NOT_OBSERVED"]
    security: Literal["NOT_EVALUATED"]
    model_behavior: Literal["NOT_EVALUATED"]
    observation_time: Literal["NOT_RECORDED"]
    affiliation: Literal["NO_XAI_ENDORSEMENT_AFFILIATION_OR_APPROVAL_CLAIM"]
    future_evidence_required: tuple[str, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def identity(self) -> XaiTokenizerConfigurationReadiness:
        _verify(self, "readiness_id", "xai_tokenizer_readiness_", "readiness_digest")
        return self


class XaiTokenizerConfigurationCaseStudy(ProfileModel):
    schema_id: Literal["omiv.xai-tokenizer-configuration-case-study.v1"] = Field(
        default="omiv.xai-tokenizer-configuration-case-study.v1", alias="schema"
    )
    case_study_id: str = Field(pattern=r"^xai_tokenizer_case_study_[0-9a-f]{32}$")
    case_study_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    title: Literal["OMIV xAI Tokenizer and Configuration Parity Readiness Case Study"]
    readiness: ObjectReference
    established: tuple[str, ...] = Field(max_length=32)
    unavailable: tuple[str, ...] = Field(max_length=32)
    future_phase6a_binding: str
    phase6b_context: str
    phase6c_independence: str
    supplied_probes_boundary: str
    runtime_boundary: str
    affiliation: Literal["NO_XAI_ENDORSEMENT_AFFILIATION_OR_APPROVAL_CLAIM"]
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def identity(self) -> XaiTokenizerConfigurationCaseStudy:
        _verify(self, "case_study_id", "xai_tokenizer_case_study_", "case_study_digest")
        return self


def finalize_profile(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    canonical = _json_compatible(body)
    object_id = prefix + canonical_sha256(canonical)[:32]
    with_id = {**canonical, id_field: object_id}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_compatible(item) for item in value]
    return value


def _verify(value: BaseModel, id_field: str, prefix: str, digest_field: str) -> None:
    body = value.model_dump(mode="json", by_alias=True)
    digest = body.pop(digest_field)
    object_id = body.pop(id_field)
    expected = prefix + canonical_sha256(body)[:32]
    if object_id != expected or digest != canonical_sha256({**body, id_field: expected}):
        raise ValueError("profile canonical identity mismatch")
