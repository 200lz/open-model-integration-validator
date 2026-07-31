"""Strict versioned domain models for Model Passports."""

from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from omiv.models import StrictModel

PASSPORT_SCHEMA = "omiv.model-passport.v1"
PASSPORT_POLICY_SCHEMA = "omiv.model-passport-policy.v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class PassportStageStatus(StrEnum):
    PASS = "PASS"
    AVAILABLE = "AVAILABLE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAIL = "FAIL"


class PassportStageName(StrEnum):
    ARTIFACT_IDENTITY = "artifact_identity"
    REPOSITORY_LAYOUT = "repository_layout"
    FORMAT_STRUCTURE = "format_structure"
    HEADER_INTEGRITY = "header_integrity"
    SPLIT_CONTAINER = "split_container"
    PAYLOAD_SPAN_BOUNDS = "payload_span_bounds"
    TARGET_ONTOLOGY = "target_ontology"
    SEMANTIC_MAPPING = "semantic_mapping"
    CONVERTER_RULE_SUPPORT = "converter_rule_support"
    ARTIFACT_SPECIFIC_PROVENANCE = "artifact_specific_provenance"
    PAYLOAD_INTEGRITY = "payload_integrity"
    QUANTIZATION_FIDELITY = "quantization_fidelity"
    TOKENIZER_PARITY = "tokenizer_parity"
    RUNTIME_PARITY = "runtime_parity"
    SECURITY_INSPECTION = "security_inspection"
    CUSTODY_CHAIN = "custody_chain"
    APPROVAL = "approval"
    DEPLOYMENT_OBSERVATION = "deployment_observation"


class TrustOutcome(StrEnum):
    IDENTITY_VERIFIED = "IDENTITY_VERIFIED"
    STRUCTURALLY_VALIDATED_WITH_LIMITATIONS = "STRUCTURALLY_VALIDATED_WITH_LIMITATIONS"
    STRUCTURAL_VALIDATION_FAILED = "STRUCTURAL_VALIDATION_FAILED"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    TRUST_CHAIN_INCOMPLETE = "TRUST_CHAIN_INCOMPLETE"
    TRUST_CHAIN_BROKEN = "TRUST_CHAIN_BROKEN"
    NOT_ASSESSED = "NOT_ASSESSED"


class UsageOutcome(StrEnum):
    SUITABLE_WITH_LIMITATIONS = "SUITABLE_WITH_LIMITATIONS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NOT_SUITABLE = "NOT_SUITABLE"
    NOT_ASSESSED = "NOT_ASSESSED"


class CustodyStatus(StrEnum):
    NOT_AVAILABLE = "NOT_AVAILABLE"
    INCOMPLETE = "INCOMPLETE"
    AVAILABLE_UNVERIFIED = "AVAILABLE_UNVERIFIED"
    VERIFIED = "VERIFIED"


class SummaryStatus(StrEnum):
    NOT_CHECKED = "NOT_CHECKED"
    PARTIAL = "PARTIAL"
    FAIL = "FAIL"
    PASS = "PASS"


class EvidenceAvailability(StrEnum):
    INCLUDED = "included"
    DIGEST_ONLY = "digest_only"
    PRIVATE = "private"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class ReferenceVerificationMode(StrEnum):
    FULL_VERIFICATION = "full_verification"
    DIGEST_ONLY_VERIFICATION = "digest_only_verification"
    UNVERIFIABLE_REFERENCE = "unverifiable_reference"


class VerificationMode(StrEnum):
    FULL_VERIFICATION = "full_verification"
    DIGEST_ONLY_VERIFICATION = "digest_only_verification"
    UNVERIFIABLE_REFERENCE = "unverifiable_reference"


class PassportSubject(StrictModel):
    display_name: str
    model_family: str
    artifact_variant: str
    artifact_kind: str
    artifact_scope: str


class OriginIdentity(StrictModel):
    origin_type: Literal[
        "huggingface", "local_file", "s3", "oci", "internal_registry", "air_gapped", "other"
    ]
    provider: str | None = None
    repository: str | None = None
    repository_type: str | None = None
    resolved_revision: str | None = None

    @model_validator(mode="after")
    def immutable_remote_origin(self) -> OriginIdentity:
        if self.origin_type == "huggingface" and not (
            self.provider and self.repository and self.resolved_revision
        ):
            raise ValueError("Hugging Face origins require provider, repository, and revision")
        return self


class FormatIdentity(StrictModel):
    format: str
    architecture: str | None = None
    split_container: bool


class ModelIdentity(StrictModel):
    model_family: str
    architecture: str | None = None


class VariantIdentity(StrictModel):
    variant: str
    selection: str | None = None


class ContentIdentity(StrictModel):
    file_count: int = Field(ge=0)
    total_declared_bytes: int = Field(ge=0)
    artifact_set_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    individual_file_digest_availability: EvidenceAvailability


class ArtifactIdentity(StrictModel):
    origin: OriginIdentity
    format_identity: FormatIdentity
    model_identity: ModelIdentity
    variant_identity: VariantIdentity
    content_identity: ContentIdentity
    model_pack: str
    model_pack_version: int = Field(ge=1)
    model_pack_digest: str = Field(pattern=SHA256_PATTERN)


class EvidenceIdentity(StrictModel):
    validation_schema: str
    validation_inventory_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_graph_digest: str = Field(pattern=SHA256_PATTERN)
    artifact_index_digest: str = Field(pattern=SHA256_PATTERN)
    model_pack_digest: str = Field(pattern=SHA256_PATTERN)
    ontology_policy_digest: str = Field(pattern=SHA256_PATTERN)
    mapping_policy_digest: str = Field(pattern=SHA256_PATTERN)


class PassportEvidenceStage(StrictModel):
    stage: PassportStageName
    status: PassportStageStatus
    evidence_source: str
    artifact_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    finding_ids: list[str]
    scope: list[str]
    limitations: list[str]
    next_step: list[str]


class TrustSummary(StrictModel):
    identity_status: TrustOutcome
    structural_status: TrustOutcome
    provenance_status: TrustOutcome
    payload_status: TrustOutcome
    security_status: TrustOutcome
    custody_status: TrustOutcome
    runtime_status: TrustOutcome


class UsageProfileResult(StrictModel):
    profile: str
    outcome: UsageOutcome
    guidance: str
    unmet_stages: list[PassportStageName]
    review_requirements: list[str]


class CustodySummary(StrictModel):
    status: CustodyStatus
    chain_id: str | None = None
    chain_schema: str | None = None
    event_count: int = Field(ge=0)
    first_event_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    latest_event_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    required_event_types: list[str]
    missing_event_types: list[str]
    broken_links: int = Field(ge=0)
    revoked_events: int = Field(ge=0)
    expired_attestations: int = Field(ge=0)

    @model_validator(mode="after")
    def coherent_chain(self) -> CustodySummary:
        if self.event_count == 0:
            if self.status != CustodyStatus.NOT_AVAILABLE:
                raise ValueError("zero-event custody must be NOT_AVAILABLE")
            if any(
                (
                    self.chain_id,
                    self.chain_schema,
                    self.first_event_digest,
                    self.latest_event_digest,
                )
            ):
                raise ValueError("zero-event custody cannot claim chain identity or event digests")
        else:
            complete_identity = (
                self.chain_id
                and self.chain_schema
                and self.first_event_digest
                and self.latest_event_digest
            )
            if not complete_identity:
                raise ValueError("custody events require chain identity and endpoint digests")
        if self.status == CustodyStatus.VERIFIED and (
            self.broken_links or self.missing_event_types
        ):
            raise ValueError("verified custody cannot contain broken links or missing events")
        return self


class SecuritySummary(StrictModel):
    status: SummaryStatus
    scanner_results: list[str]
    unsafe_serialization: SummaryStatus
    executable_code: SummaryStatus
    remote_code: SummaryStatus
    dependency_risk: SummaryStatus
    archive_safety: SummaryStatus
    malware_result: SummaryStatus
    known_vulnerabilities: list[str]
    policy_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def no_false_clean(self) -> SecuritySummary:
        if not self.scanner_results and self.status != SummaryStatus.NOT_CHECKED:
            raise ValueError("security cannot be assessed without scanner results")
        checks = (
            self.unsafe_serialization,
            self.executable_code,
            self.remote_code,
            self.dependency_risk,
            self.archive_safety,
            self.malware_result,
        )
        if self.status == SummaryStatus.PASS and any(
            item != SummaryStatus.PASS for item in checks
        ):
            raise ValueError("passing security requires every typed check to pass")
        return self


class RuntimeSummary(StrictModel):
    status: SummaryStatus
    expected_artifact_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_artifact_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    backend: str | None = None
    backend_revision: str | None = None
    deployment_identity: str | None = None
    runtime_observation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    compatibility_status: SummaryStatus

    @model_validator(mode="after")
    def observation_required(self) -> RuntimeSummary:
        if self.status != SummaryStatus.NOT_CHECKED and not self.runtime_observation_digest:
            raise ValueError("runtime assessment requires an observation digest")
        if self.status == SummaryStatus.NOT_CHECKED and any(
            (self.observed_artifact_digest, self.backend, self.deployment_identity)
        ):
            raise ValueError("unchecked runtime cannot claim an observation")
        if self.status == SummaryStatus.PASS and not all(
            (
                self.expected_artifact_digest,
                self.observed_artifact_digest,
                self.backend,
                self.backend_revision,
                self.deployment_identity,
            )
        ):
            raise ValueError("passing runtime requires artifact, backend, and deployment identity")
        return self


class EvidenceReference(StrictModel):
    role: str
    schema_id: str = Field(alias="schema")
    digest: str = Field(pattern=SHA256_PATTERN)
    availability: EvidenceAvailability
    verification_mode: ReferenceVerificationMode
    relative_path: str | None = None

    @model_validator(mode="after")
    def safe_reference(self) -> EvidenceReference:
        if self.relative_path is not None:
            path = PurePosixPath(self.relative_path)
            if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
                raise ValueError("evidence paths must be repository-relative POSIX paths")
        return self


class PolicyIdentity(StrictModel):
    passport_policy_schema: Literal["omiv.model-passport-policy.v1"] = (
        "omiv.model-passport-policy.v1"
    )
    passport_policy_digest: str = Field(pattern=SHA256_PATTERN)
    profile_policy_digest: str = Field(pattern=SHA256_PATTERN)
    validation_profile_policy_digest: str = Field(pattern=SHA256_PATTERN)
    ontology_policy_digest: str = Field(pattern=SHA256_PATTERN)
    mapping_policy_digest: str = Field(pattern=SHA256_PATTERN)


class PassportPolicyProfile(StrictModel):
    name: str
    required_stages: list[PassportStageName]
    review_stages: list[PassportStageName]
    missing_requirement_outcome: UsageOutcome


class PassportPolicy(StrictModel):
    schema_id: Literal["omiv.model-passport-policy.v1"] = Field(
        default="omiv.model-passport-policy.v1", alias="schema"
    )
    profiles: list[PassportPolicyProfile]
    structural_stages: list[PassportStageName]
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class ModelPassport(StrictModel):
    schema_id: Literal["omiv.model-passport.v1"] = Field(
        default="omiv.model-passport.v1", alias="schema"
    )
    passport_id: str = Field(pattern=r"^mp_[0-9a-f]{32}$")
    subject: PassportSubject
    artifact_identity: ArtifactIdentity
    evidence_identity: EvidenceIdentity
    evidence_stages: list[PassportEvidenceStage]
    trust_summary: TrustSummary
    usage_profiles: list[UsageProfileResult]
    custody_summary: CustodySummary
    security_summary: SecuritySummary
    runtime_summary: RuntimeSummary
    limitations: list[str]
    warnings: list[str]
    evidence_references: list[EvidenceReference]
    policy_identity: PolicyIdentity
    passport_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def deterministic_collections(self) -> ModelPassport:
        stages = [item.stage.value for item in self.evidence_stages]
        if stages != sorted(stages) or len(stages) != len(set(stages)):
            raise ValueError("passport stages must be unique and sorted")
        profiles = [item.profile for item in self.usage_profiles]
        if profiles != sorted(profiles) or len(profiles) != len(set(profiles)):
            raise ValueError("usage profiles must be unique and sorted")
        refs = [(item.role, item.digest) for item in self.evidence_references]
        roles = [item.role for item in self.evidence_references]
        if refs != sorted(refs) or len(roles) != len(set(roles)):
            raise ValueError("evidence references must be unique and sorted")
        values = self.model_dump(mode="json", by_alias=True)

        def contains_absolute_path(value: object) -> bool:
            if isinstance(value, str):
                return value.startswith(("/", "~/")) or (
                    len(value) >= 3
                    and value[0].isalpha()
                    and value[1:3] in {":/", ":\\"}
                )
            if isinstance(value, list):
                return any(contains_absolute_path(item) for item in value)
            if isinstance(value, dict):
                return any(contains_absolute_path(item) for item in value.values())
            return False

        if contains_absolute_path(values):
            raise ValueError("Model Passports cannot contain absolute paths")
        return self


class PassportVerificationResult(StrictModel):
    mode: VerificationMode
    passport_id: str
    passport_digest: str
    message: str
