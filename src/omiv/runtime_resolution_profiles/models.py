"""Strict normalized public-document and practice-result models."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.runtime_resolution.models import ObjectReference

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class PublicDocumentClaim(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=r"^[a-z0-9_.-]{3,128}$")
    fact: str = Field(min_length=1, max_length=1024)
    location: str = Field(min_length=1, max_length=256)
    body_byte_start: int = Field(ge=0, le=2 * 1024 * 1024)
    body_byte_length: int = Field(ge=1, le=4096)
    body_region_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_kind: Literal["HUMAN_REVIEWED_SOURCE_BODY_REGION"]


class PublicDocumentSource(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal["omiv.public-document-source.v1"] = Field(
        default="omiv.public-document-source.v1", alias="schema"
    )
    source_url: str
    final_url: str
    retrieval_method: Literal["GET"]
    head_request_count: Literal[1]
    get_request_count: Literal[1]
    source_kind: str
    response_body_sha256: str = Field(pattern=SHA256_PATTERN)
    content_type: Literal["text/html; charset=utf-8"]
    content_length: int = Field(ge=1, le=2 * 1024 * 1024)
    collection_status: Literal[
        "BOUNDED_PUBLIC_DOCUMENT_CAPTURED", "LIVE_PUBLIC_DOCUMENT_CAPTURE_UNAVAILABLE"
    ]
    collection_time: Literal["NOT_RECORDED"]
    document_published_at: str = Field(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    )
    document_updated_at: str = Field(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    )
    claims: tuple[PublicDocumentClaim, ...] = Field(max_length=32)
    availability: Literal["AVAILABLE", "UNAVAILABLE"]
    observation_state: Literal["PUBLIC_DOCUMENT_BODY_CAPTURED_NOT_RUNTIME_OBSERVATION"]
    limitations: tuple[str, ...] = Field(max_length=16)
    human_review_status: Literal["REVIEWED", "NOT_REVIEWED"]

    @model_validator(mode="after")
    def constrained_source(self) -> PublicDocumentSource:
        allowed = {
            "https://docs.x.ai/developers/release-notes",
            "https://docs.x.ai/developers/migration/may-15-retirement",
            "https://www.anthropic.com/responsible-scaling-policy/roadmap",
        }
        if self.source_url not in allowed or self.final_url not in allowed:
            raise ValueError("public document URL is outside the Phase 6E allowlist")
        if self.availability == "AVAILABLE" and not self.claims:
            raise ValueError("available reviewed source requires claims")
        if any(
            claim.body_byte_start + claim.body_byte_length > self.content_length
            for claim in self.claims
        ):
            raise ValueError("claim evidence region exceeds the captured GET body")
        if len({claim.claim_id for claim in self.claims}) != len(self.claims):
            raise ValueError("duplicate normalized public-document claim")
        return self


class XaiRuntimeResolutionReadiness(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: Literal["omiv.xai-runtime-resolution-readiness.v1"] = Field(
        default="omiv.xai-runtime-resolution-readiness.v1", alias="schema"
    )
    readiness_id: str = Field(pattern=r"^xai_runtime_readiness_[0-9a-f]{32}$")
    readiness_digest: str = Field(pattern=SHA256_PATTERN)
    classification: Literal[
        "XAI_PROVIDER_DOCUMENTED_MUTABLE_ALIAS_AND_REDIRECT_EVIDENCE_RECORDED_WITHOUT_OBSERVED_RUNTIME_WEIGHT_IDENTITY"
    ]
    routing_statements: tuple[ObjectReference, ...] = Field(min_length=2, max_length=2)
    evidence_layer: Literal["PROVIDER_DOCUMENTED_POLICY"]
    production_request: Literal["NOT_PERFORMED"]
    api_response: Literal["NOT_OBSERVED"]
    artifact_identity: Literal["UNAVAILABLE"]
    runtime_identity: Literal["NOT_OBSERVED"]
    weight_identity: Literal["NOT_OBSERVED"]
    publisher_authority: Literal["NOT_ESTABLISHED"]
    authenticity: Literal["NOT_ESTABLISHED"]
    freshness: Literal["NOT_ESTABLISHED"]
    observation_time: Literal["NOT_RECORDED"]
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def identity(self) -> XaiRuntimeResolutionReadiness:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("readiness_digest")
        identity = body.pop("readiness_id")
        expected = "xai_runtime_readiness_" + canonical_sha256(body)[:32]
        if identity != expected or digest != canonical_sha256({**body, "readiness_id": expected}):
            raise ValueError("xAI readiness canonical identity mismatch")
        return self


class AnthropicProvableInferenceReadiness(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: Literal["omiv.anthropic-provable-inference-readiness.v1"] = Field(
        default="omiv.anthropic-provable-inference-readiness.v1", alias="schema"
    )
    readiness_id: str = Field(pattern=r"^anthropic_runtime_readiness_[0-9a-f]{32}$")
    readiness_digest: str = Field(pattern=SHA256_PATTERN)
    classification: Literal[
        "ANTHROPIC_PROVABLE_INFERENCE_ROADMAP_SIGNAL_RECORDED_WITHOUT_PUBLIC_PROOF_FORMAT_OR_IMPLEMENTATION"
    ]
    roadmap_statement: ObjectReference
    signal: Literal["PROVIDER_RESEARCH_ROADMAP_STATEMENT"]
    prototype: Literal["PROTOTYPE_NOT_OBSERVED"]
    proof_format: Literal["PUBLIC_PROOF_FORMAT_NOT_SUPPLIED"]
    verifier: Literal["VERIFIER_NOT_AVAILABLE"]
    implementation: Literal["PROVABLE_INFERENCE_NOT_IMPLEMENTED"]
    weight_attribution: Literal["WEIGHT_ATTRIBUTION_NOT_ESTABLISHED"]
    observation_time: Literal["NOT_RECORDED"]
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def identity(self) -> AnthropicProvableInferenceReadiness:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("readiness_digest")
        identity = body.pop("readiness_id")
        expected = "anthropic_runtime_readiness_" + canonical_sha256(body)[:32]
        if identity != expected or digest != canonical_sha256({**body, "readiness_id": expected}):
            raise ValueError("Anthropic readiness canonical identity mismatch")
        return self
