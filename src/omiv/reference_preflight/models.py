"""Strict models for provider-neutral, metadata-only reference preflight evidence."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_portable_path


class ObservationAuthority(StrEnum):
    PROVIDER_API = "PROVIDER_API"
    PINNED_PROVIDER_DOCUMENT = "PINNED_PROVIDER_DOCUMENT"
    UPSTREAM_VCS = "UPSTREAM_VCS"
    UPSTREAM_RELEASE = "UPSTREAM_RELEASE"
    REGISTRY_MANIFEST = "REGISTRY_MANIFEST"
    LOCAL_DOCUMENT_FETCH = "LOCAL_DOCUMENT_FETCH"


class ArtifactRole(StrEnum):
    MAIN_MODEL = "MAIN_MODEL"
    PERCEPTION_ENCODER = "PERCEPTION_ENCODER"
    DRAFTER = "DRAFTER"


class RelationshipKind(StrEnum):
    QUANTIZED_FROM = "QUANTIZED_FROM"
    COMPANION_OF = "COMPANION_OF"


class SourceObservation(StrictModel):
    source_id: str = Field(min_length=3, max_length=96, pattern=r"^[A-Za-z0-9._-]+$")
    provider: str = Field(min_length=1, max_length=100)
    authority: ObservationAuthority
    url: str = Field(min_length=8, max_length=2000)
    resolved_identity: str = Field(min_length=1, max_length=512)
    observed_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    raw_fields: dict[str, JsonValue] = Field(default_factory=dict, max_length=64)
    limitations: list[str] = Field(default_factory=list, max_length=16)


class ArtifactObservation(StrictModel):
    artifact_id: str = Field(min_length=3, max_length=96, pattern=r"^[A-Za-z0-9._-]+$")
    repository: str = Field(min_length=1, max_length=512)
    revision: str = Field(min_length=1, max_length=512)
    path: str = Field(min_length=1, max_length=1000)
    role: ArtifactRole
    required: bool
    declared_size: int = Field(ge=0)
    provider_identity_kind: str = Field(min_length=1, max_length=100)
    provider_identity: str = Field(min_length=1, max_length=512)
    authority_source_id: str = Field(min_length=3, max_length=96)
    availability: Literal["REMOTE_ONLY"] = "REMOTE_ONLY"
    payload_verification: Literal["NOT_DOWNLOADED"] = "NOT_DOWNLOADED"


class DeclaredRelationship(StrictModel):
    subject_artifact_id: str = Field(min_length=3, max_length=96)
    object_reference: str = Field(min_length=1, max_length=512)
    relationship: RelationshipKind
    authority_source_id: str = Field(min_length=3, max_length=96)
    status: Literal["PROVIDER_DECLARED"] = "PROVIDER_DECLARED"
    cryptographic_binding: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"


class ConfigurationObservation(StrictModel):
    architecture: str = Field(min_length=1, max_length=200)
    architecture_authority_source_id: str = Field(min_length=3, max_length=96)
    config_identity: str = Field(min_length=1, max_length=512)
    tokenizer_identity: str = Field(min_length=1, max_length=512)
    chat_template_identity: str = Field(min_length=1, max_length=512)
    context_length: int = Field(ge=1)
    bos_token_id: int = Field(ge=0)
    eos_token_ids: list[int] = Field(min_length=1, max_length=16)
    pad_token_id: int = Field(ge=0)
    stop_tokens: list[str] = Field(min_length=1, max_length=16)
    input_modalities: list[str] = Field(min_length=1, max_length=16)
    output_modalities: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def validate_unique_values(self) -> ConfigurationObservation:
        if len(set(self.eos_token_ids)) != len(self.eos_token_ids):
            raise ValueError("EOS token identifiers must be unique")
        if len(set(self.stop_tokens)) != len(self.stop_tokens):
            raise ValueError("stop tokens must be unique")
        return self


class RuntimeRequirement(StrictModel):
    runtime: str = Field(min_length=1, max_length=100)
    requirement: str = Field(min_length=1, max_length=500)
    exact_release: str | None = Field(default=None, max_length=200)
    exact_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    support_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    authority_source_ids: list[str] = Field(min_length=1, max_length=16)
    compatibility_status: Literal["DECLARED_NOT_PROBED"] = "DECLARED_NOT_PROBED"


class RegistryLayer(StrictModel):
    role: str = Field(min_length=1, max_length=100)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    declared_size: int = Field(ge=0)


class RegistryObservation(StrictModel):
    runtime: str = Field(min_length=1, max_length=100)
    tag: str = Field(min_length=1, max_length=512)
    mutable_tag: Literal[True] = True
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authority_source_id: str = Field(min_length=3, max_length=96)
    layers: list[RegistryLayer] = Field(min_length=1, max_length=32)
    locally_resolved: Literal[False] = False
    runtime_probe: Literal["NOT_RUN"] = "NOT_RUN"


class FutureArtifactPin(StrictModel):
    artifact_id: str = Field(min_length=3, max_length=96)
    repository: str = Field(min_length=1, max_length=512)
    revision: str = Field(min_length=1, max_length=512)
    path: str = Field(min_length=1, max_length=1000)
    role: ArtifactRole
    provider_identity_kind: str = Field(min_length=1, max_length=100)
    provider_identity: str = Field(min_length=1, max_length=512)
    declared_size: int = Field(ge=0)
    downloaded: Literal[False] = False


class FutureRuntimePlanBody(StrictModel):
    question: str = Field(min_length=1, max_length=1000)
    artifacts: list[FutureArtifactPin] = Field(min_length=1, max_length=16)
    runtime_requirements: list[RuntimeRequirement] = Field(min_length=1, max_length=16)
    preferred_gpu_class: str = Field(min_length=1, max_length=200)
    maximum_gpu_count: Literal[1]
    maximum_pod_count: Literal[1]
    maximum_total_authorized_compute_usd: int = Field(ge=1)
    maximum_working_duration_seconds: int = Field(ge=1)
    stop_new_work_before_deadline_seconds: int = Field(ge=1)
    artifact_payload_bytes: int = Field(ge=1)
    direct_llama_cpp_workspace_bytes: int = Field(ge=1)
    llama_cpp_plus_ollama_workspace_bytes: int = Field(ge=1)
    text_probe: str = Field(min_length=1, max_length=4000)
    image_fixture: str
    image_fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_probe: str = Field(min_length=1, max_length=4000)
    dflash_observations: list[Literal["DISABLED", "ENABLED"]] = Field(min_length=2, max_length=2)
    ollama_role: Literal["SECONDARY_RUNTIME_OBSERVATION"]
    ollama_mutable_tags: list[str] = Field(min_length=1, max_length=16)
    direct_llama_cpp_independent_of_ollama: Literal[True]
    ollama_observation: str = Field(min_length=1, max_length=1000)
    evidence_to_retain: list[str] = Field(min_length=1, max_length=32)
    stop_conditions: list[str] = Field(min_length=1, max_length=32)
    pod_termination_requirement: str = Field(min_length=1, max_length=1000)
    unknown_stages: list[Literal["LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT"]] = Field(
        min_length=5, max_length=5
    )
    non_claims: list[str] = Field(min_length=1, max_length=32)
    execution_status: Literal["NOT_RUN"] = "NOT_RUN"

    @model_validator(mode="after")
    def validate_plan_scope(self) -> FutureRuntimePlanBody:
        validate_portable_path(self.image_fixture)
        if not self.image_fixture.lower().endswith(".png"):
            raise ValueError("future runtime image fixture must be a raster PNG")
        if self.dflash_observations != ["DISABLED", "ENABLED"]:
            raise ValueError("future plan must observe DFlash disabled before enabled")
        if self.unknown_stages != ["LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT"]:
            raise ValueError("future plan must retain every runtime stage as unknown")
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("future artifact pins must be unique")
        if sum(item.declared_size for item in self.artifacts) != self.artifact_payload_bytes:
            raise ValueError("artifact payload total must equal the sum of planned artifact sizes")
        if self.direct_llama_cpp_workspace_bytes < 50_000_000_000:
            raise ValueError("direct llama.cpp workspace recommendation must be at least 50 GB")
        if self.llama_cpp_plus_ollama_workspace_bytes < 80_000_000_000:
            raise ValueError("combined llama.cpp and Ollama workspace must be at least 80 GB")
        if (
            self.llama_cpp_plus_ollama_workspace_bytes
            < self.direct_llama_cpp_workspace_bytes
        ):
            raise ValueError("combined workspace recommendation cannot be smaller than direct")
        if self.stop_new_work_before_deadline_seconds >= self.maximum_working_duration_seconds:
            raise ValueError("new-work cutoff must precede the working deadline")
        if len(set(self.ollama_mutable_tags)) != len(self.ollama_mutable_tags):
            raise ValueError("Ollama mutable tags must be unique")
        return self


class FutureRuntimePlan(FutureRuntimePlanBody):
    schema_id: Literal["omiv.reference-runtime-plan.v1"] = Field(
        default="omiv.reference-runtime-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_identity(self) -> FutureRuntimePlan:
        body = self.model_dump(mode="json", by_alias=True, exclude={"plan_id", "plan_digest"})
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.plan_digest != digest or self.plan_id != f"reference_runtime_plan_{digest[:32]}":
            raise ValueError("future runtime plan canonical identity mismatch")
        return self


class ReferencePreflightProfile(StrictModel):
    schema_id: Literal["omiv.reference-preflight-profile.v1"] = Field(
        default="omiv.reference-preflight-profile.v1", alias="schema"
    )
    profile_name: str = Field(min_length=3, max_length=200)
    canonical_reference: str = Field(min_length=1, max_length=512)
    reference_aliases: list[str] = Field(min_length=1, max_length=32)
    resolved_revision: str = Field(min_length=1, max_length=512)
    sources: list[SourceObservation] = Field(min_length=1, max_length=64)
    artifacts: list[ArtifactObservation] = Field(min_length=1, max_length=64)
    relationships: list[DeclaredRelationship] = Field(max_length=64)
    configuration: ConfigurationObservation
    runtime_candidates: list[RuntimeRequirement] = Field(min_length=1, max_length=16)
    registry_observations: list[RegistryObservation] = Field(max_length=16)
    provenance_gaps: list[str] = Field(min_length=1, max_length=32)
    limitations: list[str] = Field(min_length=1, max_length=32)
    future_runtime_plan: FutureRuntimePlanBody

    @model_validator(mode="after")
    def validate_references(self) -> ReferencePreflightProfile:
        if self.canonical_reference not in self.reference_aliases:
            raise ValueError("canonical reference must be an accepted alias")
        if len(set(self.reference_aliases)) != len(self.reference_aliases):
            raise ValueError("reference aliases must be unique")
        sources = {item.source_id for item in self.sources}
        if len(sources) != len(self.sources):
            raise ValueError("source identifiers must be unique")
        artifacts = {item.artifact_id for item in self.artifacts}
        if len(artifacts) != len(self.artifacts):
            raise ValueError("artifact identifiers must be unique")
        for artifact in self.artifacts:
            if artifact.authority_source_id not in sources:
                raise ValueError("artifact authority source is missing")
        for relationship in self.relationships:
            if (
                relationship.subject_artifact_id not in artifacts
                or relationship.authority_source_id not in sources
            ):
                raise ValueError("declared relationship references missing evidence")
        for runtime in self.runtime_candidates:
            if not set(runtime.authority_source_ids).issubset(sources):
                raise ValueError("runtime requirement authority source is missing")
        for registry in self.registry_observations:
            if registry.authority_source_id not in sources:
                raise ValueError("registry authority source is missing")
        if self.configuration.architecture_authority_source_id not in sources:
            raise ValueError("architecture authority source is missing")
        planned_artifacts = {
            item.artifact_id: item for item in self.future_runtime_plan.artifacts
        }
        if set(planned_artifacts) != artifacts:
            raise ValueError("future runtime plan must pin every observed artifact exactly once")
        for artifact in self.artifacts:
            planned = planned_artifacts[artifact.artifact_id]
            observed_pin = (
                artifact.repository,
                artifact.revision,
                artifact.path,
                artifact.role,
                artifact.provider_identity_kind,
                artifact.provider_identity,
                artifact.declared_size,
            )
            planned_pin = (
                planned.repository,
                planned.revision,
                planned.path,
                planned.role,
                planned.provider_identity_kind,
                planned.provider_identity,
                planned.declared_size,
            )
            if planned_pin != observed_pin:
                raise ValueError("future runtime artifact pin differs from observed metadata")
        if self.future_runtime_plan.runtime_requirements != self.runtime_candidates:
            raise ValueError("future runtime requirements differ from observed declarations")
        return self


class ReferencePreflightEvidence(StrictModel):
    schema_id: Literal["omiv.reference-preflight-evidence.v1"] = Field(
        default="omiv.reference-preflight-evidence.v1", alias="schema"
    )
    evidence_id: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_notice: Literal["P7_REFERENCE_PREFLIGHT_CANDIDATE"] = (
        "P7_REFERENCE_PREFLIGHT_CANDIDATE"
    )
    input_reference: str = Field(min_length=1, max_length=2000)
    artifact_reference: str = Field(min_length=1, max_length=512)
    resolved_identity_status: Literal["REMOTE_REVISION_PINNED"] = "REMOTE_REVISION_PINNED"
    resolved_identity: str = Field(min_length=1, max_length=1200)
    payload_verification: Literal["NOT_DOWNLOADED"] = "NOT_DOWNLOADED"
    source_binding: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    architecture_status: Literal["DECLARED"] = "DECLARED"
    architecture: str = Field(min_length=1, max_length=200)
    tokenizer_configuration: Literal["REMOTE_METADATA_OBSERVED"] = "REMOTE_METADATA_OBSERVED"
    companion_roles: list[ArtifactRole] = Field(max_length=16)
    runtime_candidates: list[str] = Field(min_length=1, max_length=16)
    runtime_requirement: Literal["DECLARED_OFFICIAL_REQUIREMENT"] = "DECLARED_OFFICIAL_REQUIREMENT"
    runtime_probe: Literal["NOT_RUN"] = "NOT_RUN"
    numerical_fidelity: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    semantic_fidelity: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    performance: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    safety: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    production_readiness: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    provenance_gaps: list[str] = Field(min_length=1, max_length=32)
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile: ReferencePreflightProfile
    future_runtime_plan: FutureRuntimePlan
    limitations: list[str] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_identity_and_projection(self) -> ReferencePreflightEvidence:
        body = self.model_dump(
            mode="json", by_alias=True, exclude={"evidence_id", "evidence_digest"}
        )
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.evidence_digest != digest or self.evidence_id != (
            f"reference_preflight_evidence_{digest[:32]}"
        ):
            raise ValueError("reference preflight evidence canonical identity mismatch")
        expected_profile_digest = canonical_sha256(
            {"reference-preflight-profile": self.profile.model_dump(mode="json", by_alias=True)}
        )
        if self.profile_digest != expected_profile_digest:
            raise ValueError("reference preflight profile digest mismatch")
        if (
            self.artifact_reference != self.profile.canonical_reference
            or self.resolved_identity
            != (f"{self.profile.canonical_reference}@{self.profile.resolved_revision}")
        ):
            raise ValueError("reference and resolved identity projection mismatch")
        expected_companions = sorted(
            {item.role for item in self.profile.artifacts if item.role != ArtifactRole.MAIN_MODEL},
            key=lambda item: item.value,
        )
        if self.companion_roles != expected_companions:
            raise ValueError("companion-role projection mismatch")
        if self.runtime_candidates != [item.runtime for item in self.profile.runtime_candidates]:
            raise ValueError("runtime-candidate projection mismatch")
        if self.architecture != self.profile.configuration.architecture:
            raise ValueError("architecture projection mismatch")
        if self.provenance_gaps != self.profile.provenance_gaps:
            raise ValueError("provenance-gap projection mismatch")
        if self.limitations != self.profile.limitations:
            raise ValueError("limitation projection mismatch")
        plan_body = self.future_runtime_plan.model_dump(
            mode="json", by_alias=True, exclude={"schema_id", "plan_id", "plan_digest"}
        )
        if plan_body != self.profile.future_runtime_plan.model_dump(mode="json"):
            raise ValueError("future runtime plan differs from the bound profile plan")
        return self
