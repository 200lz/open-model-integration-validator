"""Strict Phase 7B.2 models for reviewed external runtime observations."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.reference_preflight.models import ReferencePreflightEvidence

CAPTURE_PROFILE = "llama.cpp-cuda-capture.v1"
SAFE_IDENTIFIER_PATTERN = r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$"


class ExternalStatus(StrEnum):
    VERIFIED = "VERIFIED"
    MATCHED_PLAN_OBSERVATION = "MATCHED_PLAN_OBSERVATION"
    OBSERVED = "OBSERVED"
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"
    NOT_RUN = "NOT_RUN"


class ExternalOverallStatus(StrEnum):
    PARTIAL = "PARTIAL"
    NOT_VERIFIED = "NOT_VERIFIED"


class AttemptKind(StrEnum):
    TEXT = "TEXT"
    IMAGE = "IMAGE"
    DFLASH_TEXT = "DFLASH_TEXT"
    DIAGNOSTIC = "DIAGNOSTIC"


class AttemptDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    RETAINED_FAILED = "RETAINED_FAILED"
    DIAGNOSTIC = "DIAGNOSTIC"


class ArtifactControl(StrictModel):
    artifact_id: str = Field(min_length=1, max_length=128, pattern=SAFE_IDENTIFIER_PATTERN)
    role: Literal["MAIN_MODEL", "PERCEPTION_ENCODER", "DRAFTER"]
    observation_member: str
    observation_format: Literal["LABELED_V1", "BARE_FILENAME_V1"]
    payload_member: str | None = None

    @model_validator(mode="after")
    def portable_members(self) -> ArtifactControl:
        validate_portable_path(self.observation_member)
        if self.payload_member is not None:
            validate_portable_path(self.payload_member)
        return self


class RuntimeControl(StrictModel):
    name: Literal["llama.cpp"]
    build_identity_member: str
    version_member: str
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: str = Field(min_length=1, max_length=128)
    runtime_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    cuda_version: str = Field(min_length=1, max_length=64)
    backend: Literal["CUDA"]

    @model_validator(mode="after")
    def portable_members(self) -> RuntimeControl:
        validate_portable_path(self.build_identity_member)
        validate_portable_path(self.version_member)
        return self


class OutputPredicate(StrictModel):
    kind: Literal["NONE", "CONTAINS_EXACT_UTF8"] = "NONE"
    value: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def coherent(self) -> OutputPredicate:
        if (self.kind == "CONTAINS_EXACT_UTF8") != (self.value is not None):
            raise ValueError("output predicate value is incoherent")
        return self


class AttemptControl(StrictModel):
    attempt_id: str = Field(min_length=1, max_length=128, pattern=SAFE_IDENTIFIER_PATTERN)
    kind: AttemptKind
    disposition: AttemptDisposition
    argv_member: str
    process_member: str
    environment_member: str
    input_identities_member: str
    stdout_member: str
    stderr_member: str
    stdout_digest_member: str
    stderr_digest_member: str
    telemetry_member: str | None = None
    supersedes: str | None = None
    retry_reason: str | None = Field(default=None, max_length=1000)
    require_single_turn: bool = False
    positive_activation_member: str | None = None
    output_predicate: OutputPredicate = Field(default_factory=OutputPredicate)

    @model_validator(mode="after")
    def validate_attempt(self) -> AttemptControl:
        for value in self.member_paths():
            validate_portable_path(value)
        if (self.supersedes is None) != (self.retry_reason is None):
            raise ValueError("retry relationship and reason must be supplied together")
        if self.positive_activation_member is not None and self.kind != AttemptKind.DIAGNOSTIC:
            raise ValueError("positive activation is supported only by a diagnostic attempt")
        return self

    def member_paths(self) -> tuple[str, ...]:
        return tuple(
            value
            for value in (
                self.argv_member,
                self.process_member,
                self.environment_member,
                self.input_identities_member,
                self.stdout_member,
                self.stderr_member,
                self.stdout_digest_member,
                self.stderr_digest_member,
                self.telemetry_member,
                self.positive_activation_member,
            )
            if value is not None
        )


class FindingControl(StrictModel):
    code: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z0-9_]+$")
    severity: Literal["INFO", "WARN", "ERROR"]
    member: str
    exact_text: str = Field(min_length=1, max_length=1024)
    detail: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def portable_member(self) -> FindingControl:
        validate_portable_path(self.member)
        return self


class SkipControl(StrictModel):
    target: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z0-9_]+$")
    reason: str = Field(min_length=1, max_length=1000)
    member: str | None = None

    @model_validator(mode="after")
    def portable_member(self) -> SkipControl:
        if self.member is not None:
            validate_portable_path(self.member)
        return self


class ExternalObservationControl(StrictModel):
    schema_id: Literal["omiv.external-runtime-observation-control.v2"] = Field(
        default="omiv.external-runtime-observation-control.v2", alias="schema"
    )
    capture_profile: Literal["llama.cpp-cuda-capture.v1"]
    control_id: str = Field(min_length=1, max_length=128, pattern=SAFE_IDENTIFIER_PATTERN)
    manifest_member: Literal["SHA256SUMS"] = "SHA256SUMS"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    complete_set: Literal[True] = True
    max_files: int = Field(default=512, ge=1, le=10_000)
    max_member_bytes: int = Field(default=8 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_total_bytes: int = Field(default=64 * 1024 * 1024, ge=1, le=1024 * 1024 * 1024)
    reference_evidence_member: str
    plan_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_fixture_bytes: int = Field(ge=1, le=64 * 1024 * 1024)
    source_identity_member: str
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_tree: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_signature: Literal["NOT_PRESENT", "UNKNOWN"] = "UNKNOWN"
    artifacts: list[ArtifactControl] = Field(min_length=1, max_length=64)
    runtime: RuntimeControl
    attempts: list[AttemptControl] = Field(min_length=1, max_length=64)
    findings: list[FindingControl] = Field(max_length=64)
    skips: list[SkipControl] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_control(self) -> ExternalObservationControl:
        validate_portable_path(self.reference_evidence_member)
        validate_portable_path(self.source_identity_member)
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("artifact controls must have unique identifiers")
        if len({item.role for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("artifact controls must have unique roles")
        attempt_ids = [item.attempt_id for item in self.attempts]
        if len(set(attempt_ids)) != len(attempt_ids):
            raise ValueError("attempt controls must be unique")
        seen: dict[str, AttemptControl] = {}
        for item in self.attempts:
            if item.supersedes is not None:
                target = seen.get(item.supersedes)
                if target is None:
                    raise ValueError("retry must follow the attempt it supersedes")
                if item.disposition != AttemptDisposition.ACCEPTED:
                    raise ValueError("superseding attempt must be accepted")
                if target.disposition != AttemptDisposition.RETAINED_FAILED:
                    raise ValueError("retry target must be a retained failed attempt")
                if not item.require_single_turn:
                    raise ValueError("superseding attempt must require single-turn")
            seen[item.attempt_id] = item
        attempt_owners: dict[str, str] = {}
        global_owners: dict[str, str] = {}

        def claim_attempt(path: str, attempt_id: str) -> None:
            owner = attempt_owners.setdefault(path, attempt_id)
            if owner != attempt_id:
                raise ValueError("attempt-owned evidence member is reused across attempts")
            if path in global_owners and global_owners[path] != "finding_source":
                raise ValueError("attempt-owned evidence member overlaps global evidence")

        def claim_global(path: str, role: str) -> None:
            owner = global_owners.setdefault(path, role)
            if owner != role:
                raise ValueError("global evidence member is reused across incompatible roles")
            if path in attempt_owners and role != "finding_source":
                raise ValueError("global evidence member overlaps attempt-owned evidence")

        claim_global(self.reference_evidence_member, "reference_evidence")
        claim_global(self.source_identity_member, "source_identity")
        claim_global(self.runtime.build_identity_member, "runtime_build_identity")
        claim_global(self.runtime.version_member, "runtime_version")
        for artifact in self.artifacts:
            claim_global(artifact.observation_member, f"artifact_report:{artifact.artifact_id}")
            if artifact.payload_member is not None:
                claim_global(artifact.payload_member, f"artifact_payload:{artifact.artifact_id}")
        for finding in self.findings:
            claim_global(finding.member, "finding_source")
        for skip in self.skips:
            if skip.member is not None:
                claim_global(skip.member, "skip_source")
        for attempt in self.attempts:
            for path in attempt.member_paths():
                claim_attempt(path, attempt.attempt_id)
        if len({item.code for item in self.findings}) != len(self.findings):
            raise ValueError("finding controls must be unique")
        if len({item.target for item in self.skips}) != len(self.skips):
            raise ValueError("skip targets must be unique")
        return self


class SourceMemberBinding(StrictModel):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def portable_path(self) -> SourceMemberBinding:
        validate_portable_path(self.path)
        return self


class ManifestObservation(StrictModel):
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    member_count: int = Field(ge=1)
    total_bytes: int = Field(ge=0)
    members: list[SourceMemberBinding] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def coherent(self) -> ManifestObservation:
        if self.member_count != len(self.members):
            raise ValueError("manifest member count mismatch")
        try:
            ordered = validate_path_set(tuple(item.path for item in self.members))
        except ValueError as exc:
            raise ValueError(f"unsafe manifest member projection: {exc}") from exc
        if tuple(item.path for item in self.members) != ordered:
            raise ValueError("manifest members are not in portable order")
        if self.total_bytes != sum(item.size for item in self.members):
            raise ValueError("manifest total byte projection mismatch")
        return self


class SourceIdentityObservation(StrictModel):
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    tree: str = Field(pattern=r"^[0-9a-f]{40}$")
    signature: Literal["NOT_PRESENT", "UNKNOWN"]
    source: SourceMemberBinding


class ArtifactIdentityObservation(StrictModel):
    artifact_id: str
    role: Literal["MAIN_MODEL", "PERCEPTION_ENCODER", "DRAFTER"]
    filename: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal[ExternalStatus.VERIFIED, ExternalStatus.MATCHED_PLAN_OBSERVATION]
    payload_verified: bool
    report_source: SourceMemberBinding
    payload_source: SourceMemberBinding | None = None

    @model_validator(mode="after")
    def coherent(self) -> ArtifactIdentityObservation:
        if self.payload_verified != (self.status == ExternalStatus.VERIFIED):
            raise ValueError("artifact payload-verification status is incoherent")
        if self.payload_verified != (self.payload_source is not None):
            raise ValueError("artifact payload source is incoherent")
        return self


class ArtifactSourceRecord(StrictModel):
    artifact_id: str
    role: Literal["MAIN_MODEL", "PERCEPTION_ENCODER", "DRAFTER"]
    reported_filename: str
    reported_size: int = Field(ge=0)
    reported_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_source: SourceMemberBinding
    payload_source: SourceMemberBinding | None = None


class RuntimeIdentityObservation(StrictModel):
    name: Literal["llama.cpp"]
    version: str
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cuda_version: str
    backend: Literal["CUDA"]
    ui_disabled: Literal[True]
    build_source: SourceMemberBinding
    version_source: SourceMemberBinding


class RuntimeSourceRecord(RuntimeIdentityObservation):
    pass


class EnvironmentObservation(StrictModel):
    cuda_visible_devices: Literal["UNSET"]
    lang: Literal["C.UTF-8"]
    lc_all: Literal["C.UTF-8"]
    stream_cap_bytes: int = Field(ge=1, le=64 * 1024 * 1024)
    correction: Literal["SINGLE_TURN_RETRY"] | None = None
    correction_target: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=SAFE_IDENTIFIER_PATTERN
    )
    diagnostic_reason: Literal["DFLASH_INFO_ACTIVATION_CAPTURE"] | None = None

    @model_validator(mode="after")
    def coherent_correction(self) -> EnvironmentObservation:
        if (self.correction is None) != (self.correction_target is None):
            raise ValueError("typed retry correction and target must be supplied together")
        return self


class InputBindingObservation(StrictModel):
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    main_artifact_id: str
    projector_artifact_id: str | None = None
    draft_artifact_id: str | None = None
    image_fixture: str | None = None
    image_bytes: int | None = Field(default=None, ge=0)
    image_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class StreamObservation(StrictModel):
    captured_bytes: int = Field(ge=0)
    limit_bytes: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    complete: bool | None
    overflow: bool | None
    source: SourceMemberBinding
    digest_source: SourceMemberBinding

    @model_validator(mode="after")
    def coherent(self) -> StreamObservation:
        if self.captured_bytes != self.source.size or self.sha256 != self.source.sha256:
            raise ValueError("stream byte count/hash differs from source binding")
        if (self.complete is None) != (self.overflow is None):
            raise ValueError("stream completeness facts must be both present or both absent")
        if self.complete is True and (
            self.overflow is not False or self.captured_bytes >= self.limit_bytes
        ):
            raise ValueError("complete stream is inconsistent with overflow facts or exact cap")
        if self.overflow is True and (
            self.complete is not False or self.captured_bytes != self.limit_bytes
        ):
            raise ValueError("overflow stream is inconsistent with completeness or capture cap")
        return self


class TelemetrySample(StrictModel):
    sample_utc: str
    device_index: int = Field(ge=0)
    device_name_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    device_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_used_mib: int = Field(ge=0)
    memory_total_mib: int = Field(ge=0)
    gpu_utilization_percent: int = Field(ge=0, le=100)


class TelemetrySummary(StrictModel):
    backend: Literal["CUDA"]
    device_index: int = Field(ge=0)
    device_name_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    device_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sample_count: int = Field(ge=1)
    first_sample_utc: str
    last_sample_utc: str
    memory_total_mib: int = Field(ge=0)
    memory_used_peak_mib: int = Field(ge=0)
    gpu_utilization_peak_percent: int = Field(ge=0, le=100)
    source: SourceMemberBinding


class PredicateSourceFact(StrictModel):
    kind: Literal["NONE", "CONTAINS_EXACT_UTF8"]
    value_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    occurrence_count: int = Field(ge=0)


class DFlashActivationObservation(StrictModel):
    implementation: Literal["draft-dflash"]
    accepted_draft_tokens: int = Field(ge=0)
    generated_draft_tokens: int = Field(ge=1)
    draft_artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: SourceMemberBinding

    @model_validator(mode="after")
    def coherent(self) -> DFlashActivationObservation:
        if self.accepted_draft_tokens > self.generated_draft_tokens:
            raise ValueError("DFlash accepted-token count exceeds generated count")
        return self


class AttemptSourceRecord(StrictModel):
    attempt_id: str
    argv: list[str] = Field(min_length=1, max_length=128)
    argv_source: SourceMemberBinding
    environment: EnvironmentObservation
    environment_source: SourceMemberBinding
    input_bindings: InputBindingObservation
    input_identities_source: SourceMemberBinding
    process_source: SourceMemberBinding
    return_code: int
    timed_out: bool
    duration_ms: int = Field(ge=0)
    start_utc: str
    end_utc: str
    stdout: StreamObservation
    stderr: StreamObservation
    telemetry_samples: list[TelemetrySample] | None = Field(default=None, max_length=10_000)
    telemetry_source: SourceMemberBinding | None = None
    predicate: PredicateSourceFact
    dflash_activation: DFlashActivationObservation | None = None
    sources: list[SourceMemberBinding] = Field(min_length=7, max_length=16)


class AttemptObservation(StrictModel):
    attempt_id: str
    kind: AttemptKind
    disposition: AttemptDisposition
    argv: list[str] = Field(min_length=1, max_length=128)
    normalized_argv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment: EnvironmentObservation
    input_bindings: InputBindingObservation
    return_code: int
    timed_out: bool
    duration_ms: int = Field(ge=0)
    start_utc: str
    end_utc: str
    stdout: StreamObservation
    stderr: StreamObservation
    telemetry: TelemetrySummary | None
    supersedes: str | None
    retry_reason: str | None
    process_status: ExternalStatus
    output_predicate_status: Literal[ExternalStatus.UNKNOWN, ExternalStatus.OBSERVED]
    dflash_activation: DFlashActivationObservation | None
    sources: list[SourceMemberBinding] = Field(min_length=7, max_length=16)


class FindingSourceFact(StrictModel):
    code: str
    exact_text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    occurrence_count: int = Field(ge=1)
    source: SourceMemberBinding


class CanonicalSourceRecord(StrictModel):
    reference_source: SourceMemberBinding
    reference_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_identity: SourceIdentityObservation
    artifacts: list[ArtifactSourceRecord] = Field(min_length=1, max_length=64)
    runtime: RuntimeSourceRecord
    attempts: list[AttemptSourceRecord] = Field(min_length=1, max_length=64)
    findings: list[FindingSourceFact] = Field(max_length=64)


class ExternalFinding(StrictModel):
    code: str
    severity: Literal["INFO", "WARN", "ERROR"]
    detail: str
    source: SourceMemberBinding


class ExternalSkip(StrictModel):
    target: str
    status: Literal[ExternalStatus.NOT_RUN] = ExternalStatus.NOT_RUN
    reason: str
    source: SourceMemberBinding | None = None


class StageObservation(StrictModel):
    stage: Literal["LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT"]
    status: ExternalStatus
    basis: str


class ExternalProjection(StrictModel):
    observation_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempts: list[AttemptObservation] = Field(min_length=1, max_length=64)
    stages: list[StageObservation] = Field(min_length=5, max_length=5)
    skips: list[ExternalSkip] = Field(max_length=32)
    findings: list[ExternalFinding] = Field(max_length=64)
    unknowns: list[str] = Field(min_length=1, max_length=64)
    limitations: list[str] = Field(min_length=1, max_length=64)
    overall_status: ExternalOverallStatus


class ExternalRuntimeObservationEvidence(StrictModel):
    schema_id: Literal["omiv.external-runtime-observation-evidence.v2"] = Field(
        default="omiv.external-runtime-observation-evidence.v2", alias="schema"
    )
    evidence_id: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_notice: Literal["PHASE_7B2_CANDIDATE_PHASE_7_UNFROZEN"] = (
        "PHASE_7B2_CANDIDATE_PHASE_7_UNFROZEN"
    )
    control: ExternalObservationControl
    manifest: ManifestObservation
    reference_evidence: ReferencePreflightEvidence
    source_record: CanonicalSourceRecord
    source_identity: SourceIdentityObservation
    artifacts: list[ArtifactIdentityObservation] = Field(min_length=1, max_length=64)
    runtime: RuntimeIdentityObservation
    projection: ExternalProjection

    @model_validator(mode="after")
    def validate_identity(self) -> ExternalRuntimeObservationEvidence:
        body = self.model_dump(
            mode="json", by_alias=True, exclude={"evidence_id", "evidence_digest"}
        )
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.evidence_digest != digest or self.evidence_id != (
            f"external_runtime_observation_{digest[:32]}"
        ):
            raise ValueError("external runtime observation canonical identity mismatch")
        return self
