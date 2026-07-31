"""Strict generic schemas for artifact attestations and execution records."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.models import StrictModel
from omiv.passport.models import EvidenceAvailability, ReferenceVerificationMode

SHA256_PATTERN = r"^[0-9a-f]{64}$"
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")


def contains_unsafe_value(value: object) -> bool:
    """Reject machine-local, temporal, random, and credential-bearing values."""
    if isinstance(value, str):
        forbidden = (
            "Authorization",
            "Bearer ",
            "X-Amz-",
            "github_pat_",
            "ghp_",
            "Signature=",
            "Expires=",
            "password=",
            "api_key=",
            "token=",
        )
        return (
            value.startswith(("/", "~/"))
            or bool(UUID_PATTERN.fullmatch(value))
            or bool(TIMESTAMP_PATTERN.match(value))
            or any(item in value for item in forbidden)
            or (value.startswith(("http://", "https://")) and "?" in value)
        )
    if isinstance(value, list):
        return any(contains_unsafe_value(item) for item in value)
    if isinstance(value, dict):
        return any(contains_unsafe_value(item) for item in value.values())
    return False


class AttestationKind(StrEnum):
    ACQUISITION = "ACQUISITION"
    TRANSFER = "TRANSFER"
    TRANSFORMATION = "TRANSFORMATION"
    QUANTIZATION = "QUANTIZATION"


class ClaimType(StrEnum):
    ARTIFACT_OBTAINED = "ARTIFACT_OBTAINED"
    ARTIFACT_IMPORTED = "ARTIFACT_IMPORTED"
    ARTIFACT_COPIED = "ARTIFACT_COPIED"
    ARTIFACT_TRANSFERRED = "ARTIFACT_TRANSFERRED"
    ARTIFACT_TRANSFORMED = "ARTIFACT_TRANSFORMED"
    ARTIFACT_CONVERTED = "ARTIFACT_CONVERTED"
    ARTIFACT_QUANTIZED = "ARTIFACT_QUANTIZED"


class AttestationAssertionOrigin(StrEnum):
    USER_DECLARED = "USER_DECLARED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    DERIVED_FROM_VERIFIED_EVIDENCE = "DERIVED_FROM_VERIFIED_EVIDENCE"
    IMPORTED_ATTESTATION = "IMPORTED_ATTESTATION"
    VERIFIED_EXECUTION_RECORD = "VERIFIED_EXECUTION_RECORD"
    SIGNED_ATTESTATION_RESERVED = "SIGNED_ATTESTATION_RESERVED"


class Authenticity(StrEnum):
    UNATTESTED = "UNATTESTED"
    DECLARED = "DECLARED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    EXECUTION_VERIFIED = "EXECUTION_VERIFIED"
    SIGNED_RESERVED = "SIGNED_RESERVED"
    UNVERIFIED = "UNVERIFIED"
    INVALID = "INVALID"


class IssuerStatus(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    USER_DECLARED = "USER_DECLARED"
    SYSTEM_DERIVED = "SYSTEM_DERIVED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    VERIFIED_RESERVED = "VERIFIED_RESERVED"


class EvidenceLinkage(StrEnum):
    FULLY_VERIFIED = "FULLY_VERIFIED"
    DIGEST_LINKED = "DIGEST_LINKED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    BROKEN = "BROKEN"


class ExecutionVerification(StrEnum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FAILED = "FAILED"


class MaterializationEligibility(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    NOT_ELIGIBLE = "NOT_ELIGIBLE"
    UNSUPPORTED = "UNSUPPORTED"


class ArtifactContinuity(StrEnum):
    VALID = "VALID"
    DIVERGED = "DIVERGED"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


class ProvenanceStrength(StrEnum):
    NO_PROVENANCE = "NO_PROVENANCE"
    DECLARED_PROVENANCE = "DECLARED_PROVENANCE"
    LOCATOR_PROVENANCE = "LOCATOR_PROVENANCE"
    EVIDENCE_LINKED_PROVENANCE = "EVIDENCE_LINKED_PROVENANCE"
    EXECUTION_LINKED_PROVENANCE = "EXECUTION_LINKED_PROVENANCE"
    ARTIFACT_SPECIFIC_PROVENANCE = "ARTIFACT_SPECIFIC_PROVENANCE"
    SIGNED_PROVENANCE_RESERVED = "SIGNED_PROVENANCE_RESERVED"
    BROKEN_PROVENANCE = "BROKEN_PROVENANCE"


class AcquisitionMethod(StrEnum):
    DOWNLOAD = "DOWNLOAD"
    COPY = "COPY"
    IMPORT = "IMPORT"
    REGISTRY_PULL = "REGISTRY_PULL"
    AIR_GAPPED_TRANSFER = "AIR_GAPPED_TRANSFER"
    LOCAL_DISCOVERY = "LOCAL_DISCOVERY"
    UNKNOWN = "UNKNOWN"


class AcquisitionOutcome(StrEnum):
    DECLARED_ONLY = "DECLARED_ONLY"
    SOURCE_IDENTITY_VERIFIED = "SOURCE_IDENTITY_VERIFIED"
    DESTINATION_IDENTITY_VERIFIED = "DESTINATION_IDENTITY_VERIFIED"
    SOURCE_AND_DESTINATION_IDENTIFIED = "SOURCE_AND_DESTINATION_IDENTIFIED"
    TRANSFER_EVIDENCE_LINKED = "TRANSFER_EVIDENCE_LINKED"
    REMOTE_LOCAL_MATCH_VERIFIED = "REMOTE_LOCAL_MATCH_VERIFIED"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


class TransformationKind(StrEnum):
    FORMAT_CONVERSION = "FORMAT_CONVERSION"
    WEIGHT_REPACKING = "WEIGHT_REPACKING"
    TENSOR_FUSION = "TENSOR_FUSION"
    TENSOR_SPLIT = "TENSOR_SPLIT"
    SHARD_RELAYOUT = "SHARD_RELAYOUT"
    MODEL_EXPORT = "MODEL_EXPORT"
    COMPILATION = "COMPILATION"
    OPTIMIZATION = "OPTIMIZATION"
    QUANTIZATION = "QUANTIZATION"
    OTHER = "OTHER"


class ExecutionResult(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class IdentityStatus(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    DECLARED = "DECLARED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"


class IssuerReference(StrictModel):
    issuer_status: IssuerStatus
    issuer_kind: str | None = None
    stable_issuer_id: str | None = None
    organization_id: str | None = None
    system_id: str | None = None
    evidence_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    display_label: str | None = None

    @model_validator(mode="after")
    def coherent(self) -> IssuerReference:
        identity = (
            self.issuer_kind,
            self.stable_issuer_id,
            self.organization_id,
            self.system_id,
            self.evidence_digest,
            self.display_label,
        )
        if self.issuer_status == IssuerStatus.UNAVAILABLE and any(identity):
            raise ValueError("unavailable issuer cannot claim identity")
        if self.issuer_status == IssuerStatus.VERIFIED_RESERVED:
            raise ValueError("verified issuer identity is reserved")
        return self


class LocationReference(StrictModel):
    location_kind: Literal[
        "local", "huggingface", "s3", "oci", "internal_registry", "air_gapped", "other"
    ]
    stable_location_id: str
    context_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)


class AttestationEvidenceReference(StrictModel):
    role: str
    schema_id: str = Field(alias="schema")
    digest: str = Field(pattern=SHA256_PATTERN)
    availability: EvidenceAvailability
    verification_mode: ReferenceVerificationMode
    finding_ids: list[str] = Field(default_factory=list)
    policy_digests: list[str] = Field(default_factory=list)
    source_phase: str
    claim_scope: list[str]
    relative_path: str | None = None
    included_payload: JsonValue | None = None

    @model_validator(mode="after")
    def coherent(self) -> AttestationEvidenceReference:
        if self.schema_id == "omiv.artifact-attestation-gap-report.v1":
            raise ValueError("attestation gap reports are analysis-only, not evidence")
        if self.relative_path is not None:
            path = PurePosixPath(self.relative_path)
            if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
                raise ValueError("attestation evidence path must be repository-relative")
        if self.availability == EvidenceAvailability.INCLUDED:
            if self.included_payload is None:
                raise ValueError("included evidence requires an included payload")
            if canonical_sha256(self.included_payload) != self.digest:
                raise ValueError("included evidence digest mismatch")
        elif self.included_payload is not None:
            raise ValueError("only included evidence may contain a payload")
        if self.verification_mode == ReferenceVerificationMode.FULL_VERIFICATION and not (
            self.included_payload is not None or self.relative_path is not None
        ):
            raise ValueError("full verification evidence requires reconstructable content")
        return self


class CommandIdentity(StrictModel):
    program: str
    normalized_arguments: list[str]
    argument_digests: list[str] = Field(default_factory=list)
    redacted_fields: list[str] = Field(default_factory=list)
    working_directory_status: Literal["UNAVAILABLE", "REDACTED", "NOT_APPLICABLE"]
    command_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> CommandIdentity:
        body = self.model_dump(mode="json")
        stored = body.pop("command_digest")
        if contains_unsafe_value(body):
            raise ValueError("command identity contains a path, timestamp, UUID, or secret")
        if stored != canonical_sha256(body):
            raise ValueError("command identity digest mismatch")
        return self


class ConfigurationIdentity(StrictModel):
    configuration_schema: str
    normalized_parameters: dict[str, JsonValue]
    redacted_parameter_names: list[str] = Field(default_factory=list)
    source_reference: str | None = None
    availability: EvidenceAvailability
    verification_mode: ReferenceVerificationMode
    configuration_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> ConfigurationIdentity:
        body = self.model_dump(mode="json")
        stored = body.pop("configuration_digest")
        if contains_unsafe_value(body):
            raise ValueError("configuration contains a path, timestamp, UUID, or secret")
        if stored != canonical_sha256(body):
            raise ValueError("configuration digest mismatch")
        return self


class EnvironmentIdentity(StrictModel):
    status: IdentityStatus
    environment_kind: str | None = None
    environment_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    container_image_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    runtime_identity: str | None = None
    os_identity: str | None = None
    architecture_identity: str | None = None
    dependency_lock_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    evidence_references: list[AttestationEvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent(self) -> EnvironmentIdentity:
        body = self.model_dump(mode="json")
        if contains_unsafe_value(body):
            raise ValueError("environment identity contains unsafe machine-local data")
        if self.status == IdentityStatus.UNAVAILABLE and any(
            (
                self.environment_kind,
                self.environment_digest,
                self.container_image_digest,
                self.runtime_identity,
                self.os_identity,
                self.architecture_identity,
                self.dependency_lock_digest,
                self.evidence_references,
            )
        ):
            raise ValueError("unavailable environment cannot claim an identity")
        if self.status == IdentityStatus.EVIDENCE_LINKED and (
            self.environment_digest is None
            or not any(
                item.role == "environment_identity"
                and item.digest == self.environment_digest
                and item.verification_mode == ReferenceVerificationMode.FULL_VERIFICATION
                for item in self.evidence_references
            )
        ):
            raise ValueError(
                "evidence-linked environment requires matching reconstructable evidence"
            )
        return self


class ToolIdentity(StrictModel):
    tool_name: str
    tool_version: str | None = None
    tool_revision: str | None = None
    tool_identity_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> ToolIdentity:
        body = self.model_dump(mode="json")
        stored = body.pop("tool_identity_digest")
        if stored != canonical_sha256(body):
            raise ValueError("tool identity digest mismatch")
        return self


class ToolExecutionRecordInput(StrictModel):
    schema_id: Literal["omiv.tool-execution-record-input.v1"] = Field(
        default="omiv.tool-execution-record-input.v1", alias="schema"
    )
    tool_identity: ToolIdentity
    command_identity: CommandIdentity
    configuration_identity: ConfigurationIdentity
    environment_identity: EnvironmentIdentity
    input_artifacts: list[ArtifactReference]
    output_artifacts: list[ArtifactReference]
    execution_result: ExecutionResult
    evidence_references: list[AttestationEvidenceReference]
    limitations: list[str]


class ToolExecutionRecord(ToolExecutionRecordInput):
    schema_id: Literal["omiv.tool-execution-record.v1"] = Field(  # type: ignore[assignment]
        default="omiv.tool-execution-record.v1", alias="schema"
    )
    execution_record_id: str = Field(pattern=r"^exec_[0-9a-f]{32}$")
    execution_record_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> ToolExecutionRecord:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("execution_record_digest")
        identity = dict(body)
        record_id = identity.pop("execution_record_id")
        if record_id != "exec_" + canonical_sha256(identity)[:32]:
            raise ValueError("execution record identity mismatch")
        body["execution_record_id"] = record_id
        if digest != canonical_sha256(body):
            raise ValueError("execution record digest mismatch")
        return self


class QuantizationSpecification(StrictModel):
    quantization_family: str
    target_type_policy: str
    block_size: int | None = Field(default=None, ge=1)
    group_size: int | None = Field(default=None, ge=1)
    calibration_identity: str | None = None
    importance_matrix_identity: str | None = None
    mixed_precision_policy: dict[str, JsonValue] = Field(default_factory=dict)
    excluded_tensor_classes: list[str] = Field(default_factory=list)
    numerical_fidelity_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    payload_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"


class ArtifactAttestationInput(StrictModel):
    schema_id: Literal["omiv.artifact-attestation-input.v1"] = Field(
        default="omiv.artifact-attestation-input.v1", alias="schema"
    )
    attestation_kind: AttestationKind
    claim_type: ClaimType
    subject: ArtifactReference
    inputs: list[ArtifactReference]
    outputs: list[ArtifactReference]
    source_location: LocationReference | None = None
    destination_location: LocationReference | None = None
    acquisition_method: AcquisitionMethod | None = None
    transformation_kind: TransformationKind | None = None
    quantization: QuantizationSpecification | None = None
    issuer: IssuerReference
    assertion_origin: AttestationAssertionOrigin
    tool_identity: ToolIdentity | None = None
    command_identity: CommandIdentity | None = None
    configuration_identity: ConfigurationIdentity | None = None
    environment_identity: EnvironmentIdentity
    policy_references: list[str] = Field(default_factory=list)
    evidence_references: list[AttestationEvidenceReference]
    execution_record: ToolExecutionRecord | None = None
    claim_details: dict[str, JsonValue]
    limitations: list[str]
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_kind(self) -> ArtifactAttestationInput:
        if self.assertion_origin == AttestationAssertionOrigin.SIGNED_ATTESTATION_RESERVED:
            raise ValueError("signed attestations are reserved for Phase 5D")
        expected = {
            AttestationKind.ACQUISITION: {
                ClaimType.ARTIFACT_OBTAINED,
                ClaimType.ARTIFACT_IMPORTED,
                ClaimType.ARTIFACT_COPIED,
            },
            AttestationKind.TRANSFER: {ClaimType.ARTIFACT_TRANSFERRED},
            AttestationKind.TRANSFORMATION: {
                ClaimType.ARTIFACT_TRANSFORMED,
                ClaimType.ARTIFACT_CONVERTED,
            },
            AttestationKind.QUANTIZATION: {ClaimType.ARTIFACT_QUANTIZED},
        }
        if self.claim_type not in expected[self.attestation_kind]:
            raise ValueError("attestation kind and claim type are incompatible")
        if not self.inputs or not self.outputs:
            raise ValueError("attestations require explicit input and output artifacts")
        if self.attestation_kind in {AttestationKind.ACQUISITION, AttestationKind.TRANSFER}:
            if self.source_location is None or self.destination_location is None:
                raise ValueError("acquisition and transfer require source and destination")
            if self.acquisition_method is None:
                raise ValueError("acquisition and transfer require a method")
        if self.attestation_kind in {AttestationKind.TRANSFORMATION, AttestationKind.QUANTIZATION}:
            if self.transformation_kind is None:
                raise ValueError("transformation attestations require a transformation kind")
            if not self.tool_identity or not self.configuration_identity:
                raise ValueError("transformations require tool and configuration identity")
        if self.attestation_kind == AttestationKind.QUANTIZATION:
            if self.transformation_kind != TransformationKind.QUANTIZATION or not self.quantization:
                raise ValueError("quantization requires a target policy and quantization relation")
        elif self.quantization is not None:
            raise ValueError("quantization details require QUANTIZATION kind")
        if contains_unsafe_value(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("attestation input contains a path, timestamp, UUID, or secret")
        return self


class AttestationPolicyIdentity(StrictModel):
    policy_schema: Literal["omiv.artifact-attestation-policy.v1"]
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class AttestationVerificationSummary(StrictModel):
    integrity: Literal["VALID"]
    evidence_linkage: EvidenceLinkage
    execution_verification: ExecutionVerification
    artifact_continuity: ArtifactContinuity
    provenance_strength: ProvenanceStrength
    materialization_eligibility: MaterializationEligibility
    execution_record_integrity: Literal["VERIFIED", "NOT_AVAILABLE"]
    cryptographic_signature: Literal["NOT_AVAILABLE"]
    issuer_authentication: Literal["UNVERIFIED"]
    actor_authenticity: Literal["UNVERIFIED"]
    attestation_signature_boundary: Literal["UNSIGNED"]
    payload_status: Literal["NOT_CHECKED"]
    numerical_fidelity_status: Literal["NOT_CHECKED"]
    security_status: Literal["NOT_CHECKED"]
    runtime_status: Literal["NOT_CHECKED"]


class ArtifactAttestation(ArtifactAttestationInput):
    schema_id: Literal["omiv.artifact-attestation.v1"] = Field(  # type: ignore[assignment]
        default="omiv.artifact-attestation.v1", alias="schema"
    )
    attestation_id: str = Field(pattern=r"^att_[0-9a-f]{32}$")
    authenticity: Authenticity
    acquisition_outcome: AcquisitionOutcome | None = None
    verification_summary: AttestationVerificationSummary
    policy_identity: AttestationPolicyIdentity
    attestation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical_identity(self) -> ArtifactAttestation:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("attestation_digest")
        identity = dict(body)
        attestation_id = identity.pop("attestation_id")
        if attestation_id != "att_" + canonical_sha256(identity)[:32]:
            raise ValueError("attestation identity mismatch")
        body["attestation_id"] = attestation_id
        if digest != canonical_sha256(body):
            raise ValueError("attestation digest mismatch")
        if self.authenticity in {Authenticity.SIGNED_RESERVED, Authenticity.INVALID}:
            raise ValueError("signed or invalid canonical authenticity is not permitted")
        return self


class ArtifactAttestationPolicy(StrictModel):
    schema_id: Literal["omiv.artifact-attestation-policy.v1"] = Field(
        default="omiv.artifact-attestation-policy.v1", alias="schema"
    )
    supported_kinds: list[AttestationKind]
    supported_claim_types: list[ClaimType]
    allowed_assertion_origins: list[AttestationAssertionOrigin]
    required_artifact_roles: dict[str, list[str]]
    evidence_link_rules: dict[str, JsonValue]
    authenticity_rules: dict[str, JsonValue]
    execution_verification_requirements: list[str]
    artifact_continuity_rules: list[str]
    custody_event_mapping: dict[str, str]
    materialization_eligibility: dict[str, str]
    forbidden_trust_escalations: list[str]
    sensitive_field_restrictions: list[str]
    deterministic_ordering: list[str]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> ArtifactAttestationPolicy:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("policy_digest")
        if digest != canonical_sha256(body):
            raise ValueError("artifact attestation policy digest mismatch")
        return self


class AttestationFinding(StrictModel):
    finding_id: str = Field(pattern=r"^ATTEST-[0-9]{3}$")
    status: str
    summary: str
    limitation: str | None = None


class ArtifactAttestationReport(StrictModel):
    schema_id: Literal["omiv.artifact-attestation-report.v1"] = Field(
        default="omiv.artifact-attestation-report.v1", alias="schema"
    )
    attestation_id: str
    attestation_digest: str = Field(pattern=SHA256_PATTERN)
    attestation_kind: AttestationKind
    claim_type: ClaimType
    subject: ArtifactReference
    inputs: list[ArtifactReference]
    outputs: list[ArtifactReference]
    issuer_status: IssuerStatus
    assertion_origin: AttestationAssertionOrigin
    authenticity: Authenticity
    tool_identity_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    configuration_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    environment_status: IdentityStatus
    evidence_linkage: EvidenceLinkage
    execution_verification: ExecutionVerification
    artifact_continuity: ArtifactContinuity
    provenance_strength: ProvenanceStrength
    materialization_eligibility: MaterializationEligibility
    execution_record_integrity: Literal["VERIFIED", "NOT_AVAILABLE"]
    cryptographic_signature: Literal["NOT_AVAILABLE"]
    issuer_authentication: Literal["UNVERIFIED"]
    actor_authenticity: Literal["UNVERIFIED"]
    attestation_signature_boundary: Literal["UNSIGNED"]
    payload_status: Literal["NOT_CHECKED"]
    numerical_fidelity_status: Literal["NOT_CHECKED"]
    security_status: Literal["NOT_CHECKED"]
    runtime_status: Literal["NOT_CHECKED"]
    custody_event_mapping: str
    limitations: list[str]
    warnings: list[str]
    next_evidence_required: list[str]
    findings: list[AttestationFinding]
    report_digest: str = Field(pattern=SHA256_PATTERN)


class ArtifactAttestationReportEnvelope(StrictModel):
    report: ArtifactAttestationReport
    integrity: dict[str, str]
