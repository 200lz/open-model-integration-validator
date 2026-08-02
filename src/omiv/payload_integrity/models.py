"""Strict canonical Phase 6A records."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StringConstraints, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.runtime.models import ProductSubject, ScopeContext

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
MAX_FILES = 100_000
MAX_DEPTH = 64
MAX_PATH_LENGTH = 1024
MAX_COMPONENT_LENGTH = 255
MAX_EXCLUSIONS = 256
MAX_FINDINGS = 100_000
MAX_REPORT_ENTRIES = 100_000
MAX_INDEX_ENTRIES = 140
MAX_METADATA_BYTES = 64 * 1024 * 1024
MIN_CHUNK_SIZE = 64 * 1024
DEFAULT_CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
ExplicitTime = Annotated[
    str,
    StringConstraints(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    ),
]


class PayloadModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class RootMode(StrEnum):
    SINGLE_FILE_ROOT = "SINGLE_FILE_ROOT"
    DIRECTORY_ROOT = "DIRECTORY_ROOT"


class ArtifactRole(StrEnum):
    ABSENT_ROLE = "ABSENT_ROLE"
    OTHER_DECLARED = "OTHER_DECLARED"
    PRIMARY = "PRIMARY"
    MANDATORY_COMPANION = "MANDATORY_COMPANION"
    OPTIONAL_COMPANION = "OPTIONAL_COMPANION"


class ExpectationMode(StrEnum):
    EMBEDDED_EXPECTATION = "EMBEDDED_EXPECTATION"
    REFERENCED_EXPECTATION = "REFERENCED_EXPECTATION"


class ExpectationScope(StrEnum):
    COMPLETE_DECLARED_FILE_SET = "COMPLETE_DECLARED_FILE_SET"
    SELECTED_REQUIRED_MEMBERS = "SELECTED_REQUIRED_MEMBERS"
    PARTIAL_REFERENCE_SET = "PARTIAL_REFERENCE_SET"


class MaterializationState(StrEnum):
    FULL_EXPECTATION_AVAILABLE = "FULL_EXPECTATION_AVAILABLE"
    DIGEST_REFERENCE_ONLY = "DIGEST_REFERENCE_ONLY"
    EXPECTATION_UNAVAILABLE = "EXPECTATION_UNAVAILABLE"
    EXPECTATION_INVALID = "EXPECTATION_INVALID"


class CompletionState(StrEnum):
    COMPLETE_FOR_DECLARED_LOCAL_SCOPE = "COMPLETE_FOR_DECLARED_LOCAL_SCOPE"
    INCOMPLETE = "INCOMPLETE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    FAILED = "FAILED"


class ComparisonStatus(StrEnum):
    EXACT_MATCH_FOR_EXPECTATION_SCOPE = "EXACT_MATCH_FOR_EXPECTATION_SCOPE"
    MISMATCH = "MISMATCH"
    INCOMPLETE_OBSERVATION = "INCOMPLETE_OBSERVATION"
    INCOMPATIBLE_SCOPE = "INCOMPATIBLE_SCOPE"
    DIGEST_REFERENCE_ONLY = "DIGEST_REFERENCE_ONLY"
    EXPECTATION_UNAVAILABLE = "EXPECTATION_UNAVAILABLE"
    INVALID_EXPECTATION = "INVALID_EXPECTATION"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class EvidenceOutcome(StrEnum):
    OBSERVED = "OBSERVED"
    MATCHES_EXPECTATION_SCOPE = "MATCHES_EXPECTATION_SCOPE"
    MATCHES_COMPLETE_EXPECTATION = "MATCHES_COMPLETE_EXPECTATION"
    MATCHES_AUTHORIZED_COMPLETE_EXPECTATION = "MATCHES_AUTHORIZED_COMPLETE_EXPECTATION"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    DIGEST_REFERENCE_ONLY = "DIGEST_REFERENCE_ONLY"
    EXPECTATION_UNAVAILABLE = "EXPECTATION_UNAVAILABLE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    INVALID = "INVALID"


class FindingKind(StrEnum):
    PATH_MATCH = "PATH_MATCH"
    PATH_MISSING = "PATH_MISSING"
    PATH_EXTRA = "PATH_EXTRA"
    PATH_OUTSIDE_EXPECTATION_SCOPE = "PATH_OUTSIDE_EXPECTATION_SCOPE"
    SIZE_MATCH = "SIZE_MATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    CONTENT_DIGEST_MATCH = "CONTENT_DIGEST_MATCH"
    CONTENT_DIGEST_MISMATCH = "CONTENT_DIGEST_MISMATCH"
    ROLE_MATCH = "ROLE_MATCH"
    ROLE_MISMATCH = "ROLE_MISMATCH"
    TYPE_MATCH = "TYPE_MATCH"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    PATH_REBOUND_DURING_OBSERVATION = "PATH_REBOUND_DURING_OBSERVATION"
    OPENED_FILE_CHANGED_DURING_HASH = "OPENED_FILE_CHANGED_DURING_HASH"
    ROOT_CHANGED_DURING_OBSERVATION = "ROOT_CHANGED_DURING_OBSERVATION"
    HARDLINK_ALIAS_REJECTED = "HARDLINK_ALIAS_REJECTED"
    HARDLINK_DETECTION_UNAVAILABLE = "HARDLINK_DETECTION_UNAVAILABLE"
    UNSUPPORTED_ENTRY = "UNSUPPORTED_ENTRY"


class PrimaryContentDigest(PayloadModel):
    algorithm: Literal["SHA256"] = "SHA256"
    value: str = Field(pattern=SHA256_PATTERN)


class PayloadFileRecord(PayloadModel):
    path: str = Field(min_length=1, max_length=MAX_PATH_LENGTH)
    logical_file_kind: str = Field(pattern=ID_PATTERN)
    size: int = Field(ge=0)
    primary_content_digest: PrimaryContentDigest
    artifact_role: ArtifactRole
    declared_role_detail: str | None = Field(default=None, pattern=ID_PATTERN)
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def role_detail(self) -> PayloadFileRecord:
        from omiv.payload_integrity.paths import validate_portable_path

        validate_portable_path(self.path)
        if (self.artifact_role == ArtifactRole.OTHER_DECLARED) != (
            self.declared_role_detail is not None
        ):
            raise ValueError("OTHER_DECLARED requires, and alone permits, role detail")
        return self


class ResourceLimits(PayloadModel):
    maximum_files: int = Field(default=MAX_FILES, ge=1, le=MAX_FILES)
    maximum_depth: int = Field(default=MAX_DEPTH, ge=0, le=MAX_DEPTH)
    maximum_path_length: int = Field(default=MAX_PATH_LENGTH, ge=1, le=MAX_PATH_LENGTH)
    maximum_component_length: int = Field(
        default=MAX_COMPONENT_LENGTH, ge=1, le=MAX_COMPONENT_LENGTH
    )
    maximum_metadata_bytes: int = Field(default=MAX_METADATA_BYTES, ge=1024, le=MAX_METADATA_BYTES)
    maximum_logical_bytes: int | None = Field(default=None, ge=0)


class PayloadInventoryPlan(PayloadModel):
    schema_id: Literal["omiv.payload-inventory-plan.v1"] = Field(
        default="omiv.payload-inventory-plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=r"^payload_plan_[0-9a-f]{32}$")
    subject: ProductSubject
    root_mode: RootMode
    logical_root: str = Field(pattern=ID_PATTERN)
    single_file_logical_name: str | None = None
    traversal_policy: Literal["ITERATIVE_NO_FOLLOW"] = "ITERATIVE_NO_FOLLOW"
    hardlink_policy: Literal["REJECT_HARDLINK_ALIASES"] = "REJECT_HARDLINK_ALIASES"
    symlink_policy: Literal["REJECT"] = "REJECT"
    special_file_policy: Literal["REJECT"] = "REJECT"
    path_normalization_policy: Literal["OMIV_PORTABLE_NFC_V1"] = "OMIV_PORTABLE_NFC_V1"
    primary_digest_algorithm: Literal["SHA256"] = "SHA256"
    chunk_size: int = Field(default=DEFAULT_CHUNK_SIZE, ge=MIN_CHUNK_SIZE, le=MAX_CHUNK_SIZE)
    limits: ResourceLimits = ResourceLimits()
    exclusions: tuple[str, ...] = Field(default=(), max_length=MAX_EXCLUSIONS)
    requested_coverage: Literal["ALL_REGULAR_FILES_IN_DECLARED_LOCAL_SCOPE"] = (
        "ALL_REGULAR_FILES_IN_DECLARED_LOCAL_SCOPE"
    )
    declared_context: str = Field(pattern=ID_PATTERN)
    limitations: tuple[str, ...]
    plan_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_plan(self) -> PayloadInventoryPlan:
        from omiv.payload_integrity.paths import validate_path_set, validate_portable_path

        if self.root_mode == RootMode.SINGLE_FILE_ROOT:
            if self.single_file_logical_name is None:
                raise ValueError("single-file root requires explicit logical name")
            validate_portable_path(self.single_file_logical_name)
        elif self.single_file_logical_name is not None:
            raise ValueError("directory root cannot carry single-file logical name")
        validate_path_set(self.exclusions)
        _identity(self, "plan_id", "payload_plan_", "plan_digest")
        return self


class PayloadExpectation(PayloadModel):
    schema_id: Literal["omiv.payload-expectation.v1"] = Field(
        default="omiv.payload-expectation.v1", alias="schema"
    )
    expectation_id: str = Field(pattern=r"^payload_expectation_[0-9a-f]{32}$")
    subject: ProductSubject
    root_mode: RootMode
    logical_root: str = Field(pattern=ID_PATTERN)
    representation_mode: ExpectationMode
    materialization_state: MaterializationState
    expectation_scope: ExpectationScope
    expected_records: tuple[PayloadFileRecord, ...] = Field(max_length=MAX_FILES)
    expected_artifact_set_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    referenced_schema_id: str | None = None
    referenced_object_id: str | None = None
    referenced_object_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    declaration_provenance: Literal[
        "DECLARED", "IMPORTED_UNVERIFIED", "SIGNED", "SIGNED_AND_TRUSTED"
    ]
    declared_purpose: str = Field(pattern=ID_PATTERN)
    authority_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    source_provider: str = Field(pattern=ID_PATTERN)
    source_namespace: str = Field(pattern=ID_PATTERN)
    available_at: ExplicitTime
    limitations: tuple[str, ...]
    expectation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_expectation(self) -> PayloadExpectation:
        from omiv.payload_integrity.building import artifact_set_digest
        from omiv.payload_integrity.paths import validate_path_set

        validate_path_set(tuple(x.path for x in self.expected_records))
        embedded = self.representation_mode == ExpectationMode.EMBEDDED_EXPECTATION
        if embedded:
            if (
                self.materialization_state != MaterializationState.FULL_EXPECTATION_AVAILABLE
                or not self.expected_records
            ):
                raise ValueError("embedded expectation must be fully materialized")
            if any(
                (
                    self.referenced_schema_id,
                    self.referenced_object_id,
                    self.referenced_object_digest,
                )
            ):
                raise ValueError("embedded expectation cannot contain a reference")
            expected = artifact_set_digest(self.root_mode, self.logical_root, self.expected_records)
            if self.expected_artifact_set_digest != expected:
                raise ValueError("expected artifact-set digest mismatch")
        else:
            if not all(
                (
                    self.referenced_schema_id,
                    self.referenced_object_id,
                    self.referenced_object_digest,
                )
            ):
                raise ValueError("referenced expectation requires a complete canonical reference")
            if self.expected_records:
                raise ValueError("referenced expectation declaration cannot embed expected records")
            if self.materialization_state == MaterializationState.FULL_EXPECTATION_AVAILABLE:
                raise ValueError("full availability belongs to a materialization result")
        _identity(self, "expectation_id", "payload_expectation_", "expectation_digest")
        return self


class PayloadPublisherAuthorityEvaluation(PayloadModel):
    schema_id: Literal["omiv.payload-publisher-authority-evaluation.v1"] = Field(
        default="omiv.payload-publisher-authority-evaluation.v1", alias="schema"
    )
    authority_evaluation_id: str = Field(pattern=r"^payload_authority_[0-9a-f]{32}$")
    expectation_id: str = Field(pattern=r"^payload_expectation_[0-9a-f]{32}$")
    expectation_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str
    source_provider: str = Field(pattern=ID_PATTERN)
    source_namespace: str = Field(pattern=ID_PATTERN)
    purpose: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    expectation_scope: ExpectationScope
    trust_report_id: str = Field(pattern=r"^trust_report_[0-9a-f]{32}$")
    trust_report_digest: str = Field(pattern=SHA256_PATTERN)
    signer_id: str = Field(pattern=ID_PATTERN)
    key_id: str = Field(pattern=ID_PATTERN)
    signer_binding_status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    signature_trust: Literal["TRUSTED", "UNTRUSTED", "NOT_EVALUATED"]
    authority_status: Literal["AUTHORIZED_PUBLISHER", "UNAUTHORIZED"]
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...]
    authority_evaluation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadPublisherAuthorityEvaluation:
        _identity(
            self,
            "authority_evaluation_id",
            "payload_authority_",
            "authority_evaluation_digest",
        )
        return self


class PayloadExpectationMaterialization(PayloadModel):
    schema_id: Literal["omiv.payload-expectation-materialization.v1"] = Field(
        default="omiv.payload-expectation-materialization.v1", alias="schema"
    )
    materialization_id: str = Field(pattern=r"^payload_materialization_[0-9a-f]{32}$")
    reference_expectation_id: str = Field(pattern=r"^payload_expectation_[0-9a-f]{32}$")
    reference_expectation_digest: str = Field(pattern=SHA256_PATTERN)
    supplied_schema_id: Literal["omiv.payload-expectation.v1"]
    supplied_expectation_id: str = Field(pattern=r"^payload_expectation_[0-9a-f]{32}$")
    supplied_expectation_digest: str = Field(pattern=SHA256_PATTERN)
    materialization_state: Literal[MaterializationState.FULL_EXPECTATION_AVAILABLE]
    reference_available_at: ExplicitTime
    supplied_available_at: ExplicitTime
    evaluated_at: ExplicitTime
    authority_transfer: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    limitations: tuple[str, ...]
    materialization_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadExpectationMaterialization:
        _identity(
            self,
            "materialization_id",
            "payload_materialization_",
            "materialization_digest",
        )
        return self


class Coverage(PayloadModel):
    discovered_regular_files: int = Field(ge=0)
    hashed_files: int = Field(ge=0)
    discovered_bytes: int = Field(ge=0)
    hashed_bytes: int = Field(ge=0)
    excluded_paths: tuple[str, ...] = ()
    inaccessible_paths: tuple[str, ...] = ()
    unsupported_paths: tuple[str, ...] = ()
    rejected_hardlink_paths: tuple[str, ...] = ()
    unstable_paths: tuple[str, ...] = ()
    hardlink_detection: Literal["AVAILABLE", "UNAVAILABLE"] = "AVAILABLE"


class PayloadHashExecutionRecord(PayloadModel):
    schema_id: Literal["omiv.payload-hash-execution-record.v1"] = Field(
        default="omiv.payload-hash-execution-record.v1", alias="schema"
    )
    execution_id: str = Field(pattern=r"^payload_execution_[0-9a-f]{32}$")
    tool_id: Literal["omiv.payload.local-hasher.v1"] = "omiv.payload.local-hasher.v1"
    tool_version: Literal["1"] = "1"
    implementation_digest: str = Field(pattern=SHA256_PATTERN)
    plan_id: str
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str
    root_mode: RootMode
    primary_digest_algorithm: Literal["SHA256"] = "SHA256"
    chunk_size: int
    limits: ResourceLimits
    available_at: ExplicitTime
    observed_at: ExplicitTime
    result_reference_status: Literal["LINKED_DOWNSTREAM_BY_MANIFEST"] = (
        "LINKED_DOWNSTREAM_BY_MANIFEST"
    )
    coverage: Coverage
    local_path_disclosure: Literal["OMITTED_FROM_CANONICAL_RECORD"] = (
        "OMITTED_FROM_CANONICAL_RECORD"
    )
    network_use: Literal["NONE"] = "NONE"
    model_deserialization: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    model_execution: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    limitations: tuple[str, ...]
    execution_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadHashExecutionRecord:
        _identity(self, "execution_id", "payload_execution_", "execution_digest")
        return self


class ObservedPayloadManifest(PayloadModel):
    schema_id: Literal["omiv.observed-payload-manifest.v1"] = Field(
        default="omiv.observed-payload-manifest.v1", alias="schema"
    )
    manifest_id: str = Field(pattern=r"^observed_payload_[0-9a-f]{32}$")
    subject: ProductSubject
    root_mode: RootMode
    logical_root: str
    plan_id: str
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    files: tuple[PayloadFileRecord, ...] = Field(max_length=MAX_FILES)
    artifact_set_payload_digest: str = Field(pattern=SHA256_PATTERN)
    coverage: Coverage
    findings: tuple[FindingKind, ...] = Field(max_length=MAX_FINDINGS)
    completion_state: CompletionState
    observation_provenance: Literal["SYSTEM_OBSERVED"] = "SYSTEM_OBSERVED"
    execution_id: str
    execution_digest: str = Field(pattern=SHA256_PATTERN)
    available_at: ExplicitTime
    observed_at: ExplicitTime
    limitations: tuple[str, ...]
    manifest_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_manifest(self) -> ObservedPayloadManifest:
        from omiv.payload_integrity.building import artifact_set_digest
        from omiv.payload_integrity.paths import validate_path_set

        validate_path_set(tuple(x.path for x in self.files))
        if tuple(sorted(self.files, key=lambda x: x.path.encode())) != self.files:
            raise ValueError("payload records must be canonically ordered")
        if self.artifact_set_payload_digest != artifact_set_digest(
            self.root_mode, self.logical_root, self.files
        ):
            raise ValueError("observed artifact-set digest mismatch")
        complete = (
            not self.findings
            and not any(
                (
                    self.coverage.excluded_paths,
                    self.coverage.inaccessible_paths,
                    self.coverage.unsupported_paths,
                    self.coverage.rejected_hardlink_paths,
                    self.coverage.unstable_paths,
                )
            )
            and self.coverage.hashed_files == self.coverage.discovered_regular_files
            and self.coverage.hashed_bytes == self.coverage.discovered_bytes
        )
        if (self.completion_state == CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE) != complete:
            raise ValueError("manifest completion state does not match reconstructed coverage")
        _identity(self, "manifest_id", "observed_payload_", "manifest_digest")
        return self


class PathFinding(PayloadModel):
    path: str
    findings: tuple[FindingKind, ...]
    expected_size: int | None = None
    observed_size: int | None = None
    expected_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)


class PayloadManifestComparison(PayloadModel):
    schema_id: Literal["omiv.payload-manifest-comparison.v1"] = Field(
        default="omiv.payload-manifest-comparison.v1", alias="schema"
    )
    comparison_id: str = Field(pattern=r"^payload_comparison_[0-9a-f]{32}$")
    expectation_id: str
    expectation_digest: str = Field(pattern=SHA256_PATTERN)
    reference_expectation_id: str | None = Field(
        default=None, pattern=r"^payload_expectation_[0-9a-f]{32}$"
    )
    reference_expectation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    supplied_expectation_id: str | None = Field(
        default=None, pattern=r"^payload_expectation_[0-9a-f]{32}$"
    )
    supplied_expectation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    materialization_id: str | None = Field(
        default=None, pattern=r"^payload_materialization_[0-9a-f]{32}$"
    )
    materialization_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    representation_mode: ExpectationMode
    materialization_state: MaterializationState
    expectation_scope: ExpectationScope
    observed_manifest_id: str
    observed_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    subject_compatible: bool
    root_mode_compatible: bool
    logical_scope_compatible: bool
    findings: tuple[PathFinding, ...] = Field(max_length=MAX_FINDINGS)
    matching_required_members: tuple[str, ...]
    missing_members: tuple[str, ...]
    extra_members: tuple[str, ...]
    outside_scope_members: tuple[str, ...]
    status: ComparisonStatus
    limitations: tuple[str, ...]
    comparison_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadManifestComparison:
        materialized = (
            self.reference_expectation_id,
            self.reference_expectation_digest,
            self.supplied_expectation_id,
            self.supplied_expectation_digest,
            self.materialization_id,
            self.materialization_digest,
        )
        if any(materialized) and not all(materialized):
            raise ValueError("materialized comparison requires both complete input references")
        _identity(self, "comparison_id", "payload_comparison_", "comparison_digest")
        return self


class PayloadIntegrityPolicy(PayloadModel):
    schema_id: Literal["omiv.payload-integrity-policy.v1"] = Field(
        default="omiv.payload-integrity-policy.v1", alias="schema"
    )
    policy_id: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    accepted_algorithms: tuple[Literal["SHA256"], ...] = ("SHA256",)
    required_expectation_scope: ExpectationScope
    require_authorized_publisher: bool
    allow_extra_files: bool
    allow_outside_scope: bool
    allow_exclusions: bool
    accepted_completion_states: tuple[CompletionState, ...]
    limitations: tuple[str, ...]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadIntegrityPolicy:
        _digest_only(self, "policy_digest")
        return self


class PayloadIntegrityEvidence(PayloadModel):
    schema_id: Literal["omiv.payload-integrity-evidence.v1"] = Field(
        default="omiv.payload-integrity-evidence.v1", alias="schema"
    )
    evidence_id: str = Field(pattern=r"^payload_evidence_[0-9a-f]{32}$")
    subject_id: str
    subject_scope_digest: str = Field(pattern=SHA256_PATTERN)
    root_mode: RootMode
    logical_root: str
    plan_id: str
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    manifest_id: str
    manifest_digest: str = Field(pattern=SHA256_PATTERN)
    execution_id: str
    execution_digest: str = Field(pattern=SHA256_PATTERN)
    expectation_id: str | None
    expectation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    expectation_scope: ExpectationScope | None
    materialization_state: MaterializationState | None
    comparison_id: str | None
    comparison_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    policy_id: str | None
    policy_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    artifact_set_payload_digest: str = Field(pattern=SHA256_PATTERN)
    comparison_status: ComparisonStatus | None
    policy_satisfied: bool | None
    publisher_authority_status: Literal["AUTHORIZED_PUBLISHER", "UNAUTHORIZED", "NOT_EVALUATED"]
    authority_evaluation_id: str | None = Field(default=None, pattern=ID_PATTERN)
    authority_evaluation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    coverage: Coverage
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    provenance_strength: Literal["SYSTEM_OBSERVED", "SIGNED", "SIGNED_AND_TRUSTED"]
    outcome: EvidenceOutcome
    limitations: tuple[str, ...]
    evidence_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadIntegrityEvidence:
        _identity(self, "evidence_id", "payload_evidence_", "evidence_digest")
        return self


class IntegrationLink(PayloadModel):
    schema_id: Literal["omiv.payload-integrity-integration.v1"] = Field(
        default="omiv.payload-integrity-integration.v1", alias="schema"
    )
    integration_id: str = Field(pattern=r"^payload_integration_[0-9a-f]{32}$")
    integration_type: Literal[
        "PASSPORT", "CUSTODY", "GOVERNANCE", "SECURITY", "RUNTIME", "HISTORICAL"
    ]
    subject_id: str
    payload_evidence_id: str
    payload_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    payload_digest: str = Field(pattern=SHA256_PATTERN)
    accepted: bool
    source_status: str
    source_object_id: str | None = None
    source_object_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    source_scope_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    coverage_status: str | None = None
    source_limitations: tuple[str, ...] = ()
    expected_runtime_payload_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_runtime_payload_digest: None = None
    runtime_observer_assertion: Literal["NOT_CREATED"] | None = None
    deployment_status: Literal["NOT_PERFORMED"] | None = None
    runtime_continuity: Literal["NOT_EVALUATED"] | None = None
    behavioral_correctness: Literal["NOT_EVALUATED"] | None = None
    available_at: ExplicitTime | None = None
    observed_at: ExplicitTime | None = None
    evaluated_at: ExplicitTime | None = None
    known_as_of_cutoff_eligible: bool | None = None
    limitations: tuple[str, ...]
    integration_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> IntegrationLink:
        if self.integration_type == "SECURITY" and not all(
            (
                self.source_object_id,
                self.source_object_digest,
                self.source_scope_digest,
                self.coverage_status,
            )
        ):
            raise ValueError("security linkage requires exact source identity, scope, and coverage")
        if self.integration_type == "RUNTIME" and (
            self.expected_runtime_payload_digest is None
            or self.observed_runtime_payload_digest is not None
            or self.runtime_observer_assertion != "NOT_CREATED"
            or self.deployment_status != "NOT_PERFORMED"
            or self.runtime_continuity != "NOT_EVALUATED"
            or self.behavioral_correctness != "NOT_EVALUATED"
        ):
            raise ValueError("runtime linkage may provide expected identity only")
        if self.integration_type == "HISTORICAL" and any(
            value is None
            for value in (
                self.available_at,
                self.observed_at,
                self.evaluated_at,
                self.known_as_of_cutoff_eligible,
            )
        ):
            raise ValueError("historical linkage requires explicit temporal states")
        _identity(self, "integration_id", "payload_integration_", "integration_digest")
        return self


class PayloadIntegrityReport(PayloadModel):
    schema_id: Literal["omiv.payload-integrity-report.v1"] = Field(
        default="omiv.payload-integrity-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^payload_report_[0-9a-f]{32}$")
    evidence: PayloadIntegrityEvidence
    comparison: PayloadManifestComparison | None
    local_payload_bytes_match: bool
    model_semantic_correctness: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    remote_repository_completeness: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    runtime_safety: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    continuous_verification: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    limitations: tuple[str, ...]
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadIntegrityReport:
        _identity(self, "report_id", "payload_report_", "report_digest")
        return self


class ArtifactIndexEntry(PayloadModel):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str
    canonical_id: str


class PayloadArtifactIndex(PayloadModel):
    schema_id: Literal["omiv.payload-artifact-index.v1"] = Field(
        default="omiv.payload-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^payload_index_[0-9a-f]{32}$")
    entries: tuple[ArtifactIndexEntry, ...] = Field(max_length=MAX_INDEX_ENTRIES)
    total_size: int = Field(ge=0)
    limitations: tuple[str, ...]
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PayloadArtifactIndex:
        _identity(self, "index_id", "payload_index_", "index_digest")
        return self


def _identity(value: PayloadModel, id_field: str, prefix: str, digest_field: str) -> None:
    body = value.model_dump(mode="json", by_alias=True)
    digest = str(body.pop(digest_field))
    identity = str(body.pop(id_field))
    expected_id = prefix + canonical_sha256(body)[:32]
    if identity != expected_id or digest != canonical_sha256({**body, id_field: expected_id}):
        raise ValueError("canonical identity or digest mismatch")


def _digest_only(value: PayloadModel, digest_field: str) -> None:
    body = value.model_dump(mode="json", by_alias=True)
    digest = str(body.pop(digest_field))
    if digest != canonical_sha256(body):
        raise ValueError("canonical digest mismatch")
