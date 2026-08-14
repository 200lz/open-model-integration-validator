"""Strict, bounded models for the Phase 6F Assurance Bundle vertical slice."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path

MAX_MEMBERS = 256


class EvidencePhase(StrEnum):
    PHASE_5 = "PHASE_5"
    PHASE_6A = "PHASE_6A"
    PHASE_6B = "PHASE_6B"
    PHASE_6C = "PHASE_6C"
    PHASE_6D = "PHASE_6D"
    PHASE_6E = "PHASE_6E"
    PHASE_6F = "PHASE_6F"
    EXTERNAL = "EXTERNAL"


class AssuranceDimension(StrEnum):
    IDENTITY = "IDENTITY"
    STRUCTURE = "STRUCTURE"
    TRANSFORMATION = "TRANSFORMATION"
    FIDELITY = "FIDELITY"
    TOKENIZER_CONFIGURATION = "TOKENIZER_CONFIGURATION"
    RUNTIME = "RUNTIME"
    PROVENANCE = "PROVENANCE"
    TRUST = "TRUST"
    OTHER = "OTHER"


class VerdictRole(StrEnum):
    SUPPORTING = "SUPPORTING"
    DIMENSION_VERDICT = "DIMENSION_VERDICT"


class VerdictStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_TESTED = "NOT_TESTED"


class CostClass(StrEnum):
    LOCAL_VALIDATION = "LOCAL_VALIDATION"
    DOWNLOAD = "DOWNLOAD"
    NETWORK = "NETWORK"
    CONVERSION = "CONVERSION"
    GPU = "GPU"


class Availability(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    INVALID_LOCAL_OBJECT = "INVALID_LOCAL_OBJECT"


class SchemaSupport(StrEnum):
    SUPPORTED_AND_VALID = "SUPPORTED_AND_VALID"
    UNSUPPORTED = "UNSUPPORTED"
    MISMATCH = "MISMATCH"
    NOT_DECLARED = "NOT_DECLARED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class PreflightStatus(StrEnum):
    READY = "READY"
    READY_WITH_GAPS = "READY_WITH_GAPS"
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class BundleStatus(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


class AssuranceRequirement(StrictModel):
    member_path: str
    source_path: str
    phase: EvidencePhase
    required: bool = True
    media_type: Literal["application/json", "application/octet-stream"] = "application/json"
    expected_schema: str | None = Field(default=None, max_length=200)
    dimension: AssuranceDimension = AssuranceDimension.OTHER
    verdict_role: VerdictRole = VerdictRole.SUPPORTING

    @model_validator(mode="after")
    def validate_paths(self) -> AssuranceRequirement:
        validate_portable_path(self.member_path)
        validate_portable_path(self.source_path)
        if self.member_path == "assurance-bundle.json":
            raise ValueError("Assurance Bundle manifest must exclude itself")
        if self.media_type != "application/json" and self.expected_schema is not None:
            raise ValueError("only JSON evidence may declare an expected schema")
        if self.media_type == "application/octet-stream" and self.phase != EvidencePhase.EXTERNAL:
            raise ValueError("opaque binary evidence is supported only for EXTERNAL members")
        return self


class PlannedOperation(StrictModel):
    cost_class: CostClass
    reason: str = Field(min_length=1, max_length=1000)


class AssuranceRequest(StrictModel):
    schema_id: Literal["omiv.assurance-request.v1"] = Field(
        default="omiv.assurance-request.v1", alias="schema"
    )
    request_id: str = Field(min_length=3, max_length=128)
    subject: str = Field(min_length=1, max_length=1000)
    requirements: list[AssuranceRequirement] = Field(min_length=1, max_length=MAX_MEMBERS)
    planned_operations: list[PlannedOperation] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def validate_member_paths(self) -> AssuranceRequest:
        validate_path_set(tuple(item.member_path for item in self.requirements))
        return self


class CostSummary(StrictModel):
    download: bool
    network: bool
    conversion: bool
    gpu: bool
    reasons: list[str] = Field(max_length=64)


class PreflightMember(StrictModel):
    member_path: str
    source_path: str
    phase: EvidencePhase
    required: bool
    media_type: Literal["application/json", "application/octet-stream"]
    expected_schema: str | None = Field(max_length=200)
    dimension: AssuranceDimension
    verdict_role: VerdictRole
    availability: Availability
    schema_support: SchemaSupport
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    issues: list[str] = Field(max_length=16)
    semantic_status: VerdictStatus = VerdictStatus.NOT_TESTED
    semantic_summary: str = Field(default="Supporting evidence only.", max_length=1000)

    @model_validator(mode="after")
    def validate_state(self) -> PreflightMember:
        validate_portable_path(self.member_path)
        validate_portable_path(self.source_path)
        _validate_member_state(self)
        return self


class AssurancePlan(StrictModel):
    schema_id: Literal["omiv.assurance-plan.v1"] = Field(
        default="omiv.assurance-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_id: str
    subject: str
    status: PreflightStatus
    members: list[PreflightMember] = Field(min_length=1, max_length=MAX_MEMBERS)
    costs: CostSummary
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_identity(self) -> AssurancePlan:
        body = self.model_dump(mode="json", by_alias=True, exclude={"plan_id", "plan_digest"})
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.plan_digest != digest or self.plan_id != f"assurance_plan_{digest[:32]}":
            raise ValueError("Assurance Plan canonical identity mismatch")
        validate_path_set(tuple(item.member_path for item in self.members))
        return self


class BundleMember(StrictModel):
    member_path: str
    phase: EvidencePhase
    required: bool
    media_type: Literal["application/json", "application/octet-stream"]
    expected_schema: str | None = Field(max_length=200)
    dimension: AssuranceDimension
    verdict_role: VerdictRole
    availability: Availability
    schema_support: SchemaSupport
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    issues: list[str] = Field(max_length=16)
    semantic_status: VerdictStatus
    semantic_summary: str = Field(max_length=1000)

    @model_validator(mode="after")
    def validate_state(self) -> BundleMember:
        validate_portable_path(self.member_path)
        _validate_member_state(self)
        return self


def _validate_member_state(value: PreflightMember | BundleMember) -> None:
    if value.availability == Availability.AVAILABLE:
        if value.size is None or value.sha256 is None:
            raise ValueError("available evidence requires size and SHA-256")
    elif value.size is not None or value.sha256 is not None:
        raise ValueError("unavailable evidence cannot claim size or SHA-256")
    if value.media_type == "application/octet-stream":
        if value.phase != EvidencePhase.EXTERNAL or value.expected_schema is not None:
            raise ValueError("opaque binary evidence is supported only for EXTERNAL members")
        if value.schema_support != SchemaSupport.NOT_APPLICABLE:
            raise ValueError("opaque binary evidence schema support must be NOT_APPLICABLE")
    elif value.schema_support == SchemaSupport.NOT_APPLICABLE:
        raise ValueError("JSON evidence cannot use NOT_APPLICABLE schema support")


class CoreFileRecord(StrictModel):
    path: str
    schema_id: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_path(self) -> CoreFileRecord:
        validate_portable_path(self.path)
        return self


class AssuranceBundleManifest(StrictModel):
    schema_id: Literal["omiv.assurance-bundle.v1"] = Field(
        default="omiv.assurance-bundle.v1", alias="schema"
    )
    bundle_id: str
    bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject: str
    source_plan_id: str
    source_plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    preflight_status: PreflightStatus
    status: BundleStatus
    members: list[BundleMember] = Field(min_length=1, max_length=MAX_MEMBERS)
    core_files: list[CoreFileRecord] = Field(min_length=6, max_length=16)
    bundle_profile: Literal["omiv.assurance-bundle.v1"] = "omiv.assurance-bundle.v1"
    required_features: list[str] = Field(max_length=64)
    costs: CostSummary
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_identity(self) -> AssuranceBundleManifest:
        body = self.model_dump(mode="json", by_alias=True, exclude={"bundle_id", "bundle_digest"})
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.bundle_digest != digest or self.bundle_id != f"assurance_bundle_{digest[:32]}":
            raise ValueError("Assurance Bundle canonical identity mismatch")
        validate_path_set(tuple(item.member_path for item in self.members))
        validate_path_set(tuple(item.path for item in self.core_files))
        return self


class AssuranceSubjectDocument(StrictModel):
    schema_id: Literal["omiv.assurance-subject.v1"] = Field(
        default="omiv.assurance-subject.v1", alias="schema"
    )
    subject_id: str
    subject_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    display_name: str = Field(min_length=1, max_length=1000)
    limitations: list[str] = Field(max_length=16)

    @model_validator(mode="after")
    def validate_identity(self) -> AssuranceSubjectDocument:
        _validate_identity(self, "subject_id", "subject_digest", "assurance_subject_")
        return self


class EvidenceIndexDocument(StrictModel):
    schema_id: Literal["omiv.assurance-evidence-index.v1"] = Field(
        default="omiv.assurance-evidence-index.v1", alias="schema"
    )
    index_id: str
    index_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    entries: list[BundleMember] = Field(min_length=1, max_length=MAX_MEMBERS)

    @model_validator(mode="after")
    def validate_identity(self) -> EvidenceIndexDocument:
        validate_path_set(tuple(item.member_path for item in self.entries))
        _validate_identity(self, "index_id", "index_digest", "assurance_index_")
        return self


class DimensionVerdict(StrictModel):
    dimension: AssuranceDimension
    status: VerdictStatus
    summary: str = Field(max_length=1000)
    evidence_paths: list[str] = Field(max_length=MAX_MEMBERS)


class AssuranceVerdictDocument(StrictModel):
    schema_id: Literal["omiv.assurance-verdict.v1"] = Field(
        default="omiv.assurance-verdict.v1", alias="schema"
    )
    verdict_id: str
    verdict_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    overall: VerdictStatus
    dimensions: list[DimensionVerdict] = Field(min_length=1, max_length=32)
    unresolved_claims: int = Field(ge=0)
    integrity_failures: int = Field(ge=0)
    summary: str = Field(max_length=2000)
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_identity(self) -> AssuranceVerdictDocument:
        _validate_identity(self, "verdict_id", "verdict_digest", "assurance_verdict_")
        return self


class FindingRecord(StrictModel):
    code: str
    severity: Literal["INFO", "WARN", "ERROR"]
    member_path: str | None = None
    detail: str = Field(max_length=2000)


class FindingsDocument(StrictModel):
    schema_id: Literal["omiv.assurance-findings.v1"] = Field(
        default="omiv.assurance-findings.v1", alias="schema"
    )
    findings_id: str
    findings_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    findings: list[FindingRecord] = Field(max_length=MAX_MEMBERS * 4)

    @model_validator(mode="after")
    def validate_identity(self) -> FindingsDocument:
        _validate_identity(self, "findings_id", "findings_digest", "assurance_findings_")
        return self


class UnknownRecord(StrictModel):
    member_path: str
    dimension: AssuranceDimension
    required: bool
    reason: str = Field(max_length=1000)
    next_action: str = Field(max_length=1000)


class UnknownsDocument(StrictModel):
    schema_id: Literal["omiv.assurance-unknowns.v1"] = Field(
        default="omiv.assurance-unknowns.v1", alias="schema"
    )
    unknowns_id: str
    unknowns_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    unknowns: list[UnknownRecord] = Field(max_length=MAX_MEMBERS * 2)

    @model_validator(mode="after")
    def validate_identity(self) -> UnknownsDocument:
        _validate_identity(self, "unknowns_id", "unknowns_digest", "assurance_unknowns_")
        return self


class CapabilitiesDocument(StrictModel):
    schema_id: Literal["omiv.assurance-capabilities.v1"] = Field(
        default="omiv.assurance-capabilities.v1", alias="schema"
    )
    profile: Literal["omiv.assurance-bundle.v1"] = "omiv.assurance-bundle.v1"
    features: list[str] = Field(min_length=1, max_length=64)
    transports: list[Literal["DIRECTORY", "ZIP_STORED"]]
    signature_algorithms: list[Literal["ED25519"]]
    supported_evidence_schemas: list[str] = Field(max_length=4096)
    limits: dict[str, int]


class AssuranceSignature(StrictModel):
    schema_id: Literal["omiv.assurance-signature.v1"] = Field(
        default="omiv.assurance-signature.v1", alias="schema"
    )
    signature_id: str
    signature_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    algorithm: Literal["ED25519"] = "ED25519"
    key_id: str = Field(min_length=3, max_length=200)
    public_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{128}$")
    limitations: list[str] = Field(max_length=16)

    @model_validator(mode="after")
    def validate_identity(self) -> AssuranceSignature:
        _validate_identity(self, "signature_id", "signature_digest", "assurance_signature_")
        return self


class AssuranceTrustPolicy(StrictModel):
    schema_id: Literal["omiv.assurance-trust-policy.v1"] = Field(
        default="omiv.assurance-trust-policy.v1", alias="schema"
    )
    policy_id: str = Field(min_length=3, max_length=200)
    require_signature: bool = True
    minimum_valid_signatures: int = Field(default=1, ge=0, le=32)
    allowed_key_ids: list[str] = Field(default_factory=list, max_length=64)
    allowed_public_key_sha256: list[str] = Field(default_factory=list, max_length=64)


def _validate_identity(value: StrictModel, id_field: str, digest_field: str, prefix: str) -> None:
    body = value.model_dump(mode="json", by_alias=True, exclude={id_field, digest_field})
    schema_id = value.model_dump(mode="json", by_alias=True)["schema"]
    digest = canonical_sha256({"domain": schema_id, "body": body})
    if getattr(value, digest_field) != digest or getattr(value, id_field) != prefix + digest[:32]:
        raise ValueError(f"{schema_id} canonical identity mismatch")


class VerificationFinding(StrictModel):
    member_path: str | None = None
    code: str
    detail: str


class AssuranceVerificationReport(StrictModel):
    schema_id: Literal["omiv.assurance-verification-report.v1"] = Field(
        default="omiv.assurance-verification-report.v1",
        alias="schema",
    )
    bundle_id: str
    bundle_digest: str
    status: BundleStatus
    available: int = Field(ge=0)
    missing: int = Field(ge=0)
    unknown: int = Field(ge=0)
    invalid: int = Field(ge=0)
    transport: Literal["DIRECTORY", "ZIP_STORED"] = "DIRECTORY"
    valid_signatures: int = Field(default=0, ge=0)
    trusted_signatures: int = Field(default=0, ge=0)
    signature_status: Literal["NOT_PRESENT", "VALID_UNTRUSTED", "TRUSTED", "INVALID"] = (
        "NOT_PRESENT"
    )
    findings: list[VerificationFinding] = Field(max_length=MAX_MEMBERS * 4)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
