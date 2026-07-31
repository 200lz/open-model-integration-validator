"""Strict custody event, ledger, policy, and report schemas."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.passport.models import (
    ArtifactIdentity,
    EvidenceAvailability,
    EvidenceIdentity,
    PassportEvidenceStage,
    PassportSubject,
    PolicyIdentity,
    RuntimeSummary,
    SecuritySummary,
    TrustSummary,
    UsageProfileResult,
)

SHA256_PATTERN = r"^[0-9a-f]{64}$"
REVISION_PATTERN = r"^[0-9a-f]{40,64}$"
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")


class CustodyEventType(StrEnum):
    SOURCE_LOCATOR_RECORDED = "SOURCE_LOCATOR_RECORDED"
    IMMUTABLE_IDENTITY_ESTABLISHED = "IMMUTABLE_IDENTITY_ESTABLISHED"
    ARTIFACT_ACQUISITION_RECORDED = "ARTIFACT_ACQUISITION_RECORDED"
    REMOTE_INSPECTION_RECORDED = "REMOTE_INSPECTION_RECORDED"
    FORMAT_INSPECTION_COMPLETED = "FORMAT_INSPECTION_COMPLETED"
    STRUCTURAL_VALIDATION_COMPLETED = "STRUCTURAL_VALIDATION_COMPLETED"
    TRANSFORMATION_RECORDED = "TRANSFORMATION_RECORDED"
    QUANTIZATION_RECORDED = "QUANTIZATION_RECORDED"
    PASSPORT_ISSUED = "PASSPORT_ISSUED"
    SECURITY_INSPECTION_COMPLETED = "SECURITY_INSPECTION_COMPLETED"
    APPROVAL_RECORDED = "APPROVAL_RECORDED"
    REGISTRY_PROMOTION_RECORDED = "REGISTRY_PROMOTION_RECORDED"
    DEPLOYMENT_RECORDED = "DEPLOYMENT_RECORDED"
    RUNTIME_OBSERVATION_RECORDED = "RUNTIME_OBSERVATION_RECORDED"
    REVOCATION_RECORDED_RESERVED = "REVOCATION_RECORDED_RESERVED"
    EXPIRATION_RECORDED_RESERVED = "EXPIRATION_RECORDED_RESERVED"


class AssertionOrigin(StrEnum):
    DERIVED_FROM_VERIFIED_EVIDENCE = "DERIVED_FROM_VERIFIED_EVIDENCE"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    USER_DECLARED = "USER_DECLARED"
    IMPORTED_ATTESTATION = "IMPORTED_ATTESTATION"
    SIGNED_ATTESTATION_RESERVED = "SIGNED_ATTESTATION_RESERVED"


class ReferenceStatus(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    USER_DECLARED = "USER_DECLARED"
    SYSTEM_DERIVED = "SYSTEM_DERIVED"
    UNVERIFIED = "UNVERIFIED"


class EventAuthenticity(StrEnum):
    EVIDENCE_DERIVED = "EVIDENCE_DERIVED"
    USER_DECLARED = "USER_DECLARED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    UNATTESTED = "UNATTESTED"
    SIGNED_ATTESTATION_RESERVED = "SIGNED_ATTESTATION_RESERVED"
    UNVERIFIED = "UNVERIFIED"


class AttestationStatus(StrEnum):
    UNATTESTED = "UNATTESTED"
    SIGNED_ATTESTATION_RESERVED = "SIGNED_ATTESTATION_RESERVED"


class IntegrityStatus(StrEnum):
    INTACT = "INTACT"
    BROKEN = "BROKEN"
    UNVERIFIED = "UNVERIFIED"


class SubjectContinuityStatus(StrEnum):
    CONSISTENT = "CONSISTENT"
    DIVERGED = "DIVERGED"
    UNVERIFIED = "UNVERIFIED"


class EvidenceLinkageStatus(StrEnum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    BROKEN = "BROKEN"
    UNAVAILABLE = "UNAVAILABLE"


class LifecycleCompleteness(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_ASSESSED = "NOT_ASSESSED"


class RevocationStatus(StrEnum):
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_REVOKED = "NOT_REVOKED"
    REVOKED = "REVOKED"


class ExpirationStatus(StrEnum):
    NOT_ASSESSED = "NOT_ASSESSED"
    CURRENT = "CURRENT"
    EXPIRED = "EXPIRED"


class OverallCustodyStatus(StrEnum):
    INTACT = "INTACT"
    INCOMPLETE = "INCOMPLETE"
    DIVERGED = "DIVERGED"
    BROKEN = "BROKEN"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    UNVERIFIED = "UNVERIFIED"


class ProfileCompleteness(StrictModel):
    profile: str
    status: LifecycleCompleteness
    missing_event_types: list[CustodyEventType]
    missing_evidence_concepts: list[str]


class ArtifactReference(StrictModel):
    origin_type: str
    provider: str | None = None
    repository: str | None = None
    repository_type: str | None = None
    resolved_revision: str | None = None
    selection: str | None = None
    artifact_set_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    content_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    format: str | None = None
    architecture: str | None = None
    variant: str
    file_count: int = Field(ge=0)
    total_declared_bytes: int = Field(ge=0)
    passport_id: str | None = Field(default=None, pattern=r"^mp_[0-9a-f]{32}$")
    passport_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    validation_inventory_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    identity_digest: str = Field(pattern=SHA256_PATTERN)

    def identity_payload(self) -> dict[str, JsonValue]:
        data = self.model_dump(mode="json")
        data.pop("identity_digest")
        data.pop("passport_id")
        data.pop("passport_digest")
        data.pop("validation_inventory_digest")
        return data

    @model_validator(mode="after")
    def valid_identity(self) -> ArtifactReference:
        if self.identity_digest != canonical_sha256(self.identity_payload()):
            raise ValueError("artifact-reference identity digest mismatch")
        return self


class ActorReference(StrictModel):
    status: ReferenceStatus
    actor_kind: str | None = None
    stable_actor_id: str | None = None
    organization_id: str | None = None
    evidence_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def unavailable_is_empty(self) -> ActorReference:
        if self.status == ReferenceStatus.UNAVAILABLE and any(
            (self.actor_kind, self.stable_actor_id, self.organization_id, self.evidence_digest)
        ):
            raise ValueError("unavailable actor reference cannot claim identity")
        return self


class ToolReference(StrictModel):
    status: ReferenceStatus
    tool_name: str | None = None
    tool_version: str | None = None
    tool_revision: str | None = None
    tool_identity_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    evidence_status: EvidenceLinkageStatus

    @model_validator(mode="after")
    def unavailable_is_empty(self) -> ToolReference:
        if self.status == ReferenceStatus.UNAVAILABLE and any(
            (
                self.tool_name,
                self.tool_version,
                self.tool_revision,
                self.tool_identity_digest,
            )
        ):
            raise ValueError("unavailable tool reference cannot claim identity")
        return self


class EnvironmentReference(StrictModel):
    status: ReferenceStatus
    environment_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    runtime_identity: str | None = None
    container_identity: str | None = None
    evidence_reference: str | None = None

    @model_validator(mode="after")
    def unavailable_is_empty(self) -> EnvironmentReference:
        if self.status == ReferenceStatus.UNAVAILABLE and any(
            (
                self.environment_digest,
                self.runtime_identity,
                self.container_identity,
                self.evidence_reference,
            )
        ):
            raise ValueError("unavailable environment reference cannot claim identity")
        return self


class CustodyPolicyReference(StrictModel):
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class CustodyEvidenceReference(StrictModel):
    role: str
    schema_id: str = Field(alias="schema")
    digest: str = Field(pattern=SHA256_PATTERN)
    availability: EvidenceAvailability
    verification_mode: Literal[
        "full_verification", "digest_only_verification", "unverifiable_reference"
    ]
    finding_ids: list[str]
    policy_digests: list[str]
    source_phase: str
    relative_path: str | None = None

    @model_validator(mode="after")
    def safe_reference(self) -> CustodyEvidenceReference:
        if self.relative_path is not None:
            path = PurePosixPath(self.relative_path)
            if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
                raise ValueError("custody evidence paths must be repository-relative POSIX paths")
        if self.verification_mode == "full_verification" and self.relative_path is None:
            raise ValueError("full verification evidence requires a relative path")
        return self


class CustodyEventInput(StrictModel):
    schema_id: Literal["omiv.custody-event-input.v1"] = Field(
        default="omiv.custody-event-input.v1", alias="schema"
    )
    event_type: CustodyEventType
    subject: ArtifactReference
    input_artifacts: list[ArtifactReference]
    output_artifacts: list[ArtifactReference]
    action: str
    assertion_origin: AssertionOrigin
    actor_reference: ActorReference
    tool_reference: ToolReference | None = None
    environment_reference: EnvironmentReference
    policy_references: list[CustodyPolicyReference]
    evidence_references: list[CustodyEvidenceReference]
    event_claims: dict[str, JsonValue]
    limitations: list[str]

    @model_validator(mode="after")
    def reserved_claims_rejected(self) -> CustodyEventInput:
        if self.assertion_origin == AssertionOrigin.SIGNED_ATTESTATION_RESERVED:
            raise ValueError("signed attestations are reserved for a future phase")
        return self


def event_id_payload(event: CustodyEvent) -> dict[str, JsonValue]:
    data = event.model_dump(mode="json", by_alias=True)
    data.pop("event_id", None)
    data.pop("event_digest", None)
    return data


def event_digest_payload(event: CustodyEvent) -> dict[str, JsonValue]:
    data = event.model_dump(mode="json", by_alias=True)
    data.pop("event_digest", None)
    return data


class CustodyEvent(CustodyEventInput):
    schema_id: Literal["omiv.custody-event.v1"] = Field(  # type: ignore[assignment]
        default="omiv.custody-event.v1", alias="schema"
    )
    event_id: str = Field(pattern=r"^ce_[0-9a-f]{32}$")
    sequence: int = Field(ge=0)
    chain_id: str = Field(pattern=r"^mcoc_[0-9a-f]{32}$")
    previous_event_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    event_digest: str = Field(pattern=SHA256_PATTERN)
    authenticity: EventAuthenticity
    attestation_status: AttestationStatus

    @model_validator(mode="after")
    def canonical_identity(self) -> CustodyEvent:
        expected_id = "ce_" + canonical_sha256(event_id_payload(self))[:32]
        if self.event_id != expected_id:
            raise ValueError("custody event ID mismatch")
        if self.event_digest != canonical_sha256(event_digest_payload(self)):
            raise ValueError("custody event digest mismatch")
        values = self.model_dump(mode="json", by_alias=True)

        def unsafe(value: object) -> bool:
            if isinstance(value, str):
                forbidden = (
                    "Authorization",
                    "Bearer ",
                    "X-Amz-",
                    "github_pat_",
                    "ghp_",
                    "Signature=",
                    "Expires=",
                )
                return (
                    value.startswith(("/", "~/"))
                    or bool(UUID_PATTERN.fullmatch(value))
                    or bool(TIMESTAMP_PATTERN.match(value))
                    or any(item in value for item in forbidden)
                    or (value.startswith(("http://", "https://")) and "?" in value)
                )
            if isinstance(value, list):
                return any(unsafe(item) for item in value)
            if isinstance(value, dict):
                return any(unsafe(item) for item in value.values())
            return False

        if unsafe(values):
            raise ValueError(
                "custody events cannot contain paths, timestamps, UUIDs, or secrets"
            )
        if self.attestation_status != AttestationStatus.UNATTESTED:
            raise ValueError("signed event attestations are reserved")
        return self


class CustodyPolicyProfile(StrictModel):
    name: str
    required_event_types: list[CustodyEventType]
    any_of_event_types: list[CustodyEventType]
    required_evidence_concepts: list[str]


class CustodyPolicy(StrictModel):
    schema_id: Literal["omiv.custody-policy.v1"] = Field(
        default="omiv.custody-policy.v1", alias="schema"
    )
    allowed_event_types: list[CustodyEventType]
    generated_event_types: list[CustodyEventType]
    lifecycle_event_types: list[CustodyEventType]
    profiles: list[CustodyPolicyProfile]
    policy_digest: str = Field(pattern=SHA256_PATTERN)


class MissingEventAnalysis(StrictModel):
    selected_profile: str
    profile_results: list[ProfileCompleteness]
    missing_event_types: list[CustodyEventType]
    missing_evidence_concepts: list[str]


class EventAuthenticitySummary(StrictModel):
    statuses: list[EventAuthenticity]
    unattested_event_count: int = Field(ge=0)
    signed_event_count: int = Field(ge=0)
    limitation: str


class LedgerPolicyIdentity(StrictModel):
    custody_policy_schema: Literal["omiv.custody-policy.v1"] = "omiv.custody-policy.v1"
    custody_policy_digest: str = Field(pattern=SHA256_PATTERN)
    passport_policy_digest: str = Field(pattern=SHA256_PATTERN)
    validation_profile_policy_digest: str = Field(pattern=SHA256_PATTERN)
    ontology_policy_digest: str = Field(pattern=SHA256_PATTERN)
    mapping_policy_digest: str = Field(pattern=SHA256_PATTERN)


class LedgerArtifactReference(StrictModel):
    role: str
    schema_id: str = Field(alias="schema")
    digest: str = Field(pattern=SHA256_PATTERN)
    relative_path: str

    @model_validator(mode="after")
    def safe_path(self) -> LedgerArtifactReference:
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
            raise ValueError("ledger references must be repository-relative POSIX paths")
        return self


class CustodyLedger(StrictModel):
    schema_id: Literal["omiv.custody-ledger.v1"] = Field(
        default="omiv.custody-ledger.v1", alias="schema"
    )
    chain_id: str = Field(pattern=r"^mcoc_[0-9a-f]{32}$")
    subject: ArtifactReference
    policy_identity: LedgerPolicyIdentity
    passport_reference: LedgerArtifactReference
    validation_reference: LedgerArtifactReference
    selected_profile: str
    events: list[CustodyEvent]
    event_count: int = Field(ge=0)
    genesis_event_digest: str = Field(pattern=SHA256_PATTERN)
    latest_event_digest: str = Field(pattern=SHA256_PATTERN)
    ledger_integrity: IntegrityStatus
    event_digest_integrity: IntegrityStatus
    parent_link_integrity: IntegrityStatus
    subject_continuity: SubjectContinuityStatus
    evidence_linkage: EvidenceLinkageStatus
    event_authenticity_summary: EventAuthenticitySummary
    lifecycle_completeness: LifecycleCompleteness
    missing_event_analysis: MissingEventAnalysis
    revocation_status: RevocationStatus
    expiration_status: ExpirationStatus
    overall_custody_status: OverallCustodyStatus
    ledger_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def linear_structure(self) -> CustodyLedger:
        if not self.events:
            raise ValueError("custody ledger requires a genesis event")
        if self.event_count != len(self.events):
            raise ValueError("custody event count mismatch")
        ids = [item.event_id for item in self.events]
        sequences = [item.sequence for item in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate custody event ID")
        if len(sequences) != len(set(sequences)):
            raise ValueError("duplicate custody sequence")
        if sequences != list(range(len(self.events))):
            raise ValueError("custody event sequence is reordered or has a gap")
        if self.events[0].previous_event_digest is not None:
            raise ValueError("custody ledger is missing a valid genesis event")
        if sum(item.previous_event_digest is None for item in self.events) != 1:
            raise ValueError("custody ledger must contain exactly one genesis event")
        for previous, current in zip(self.events, self.events[1:], strict=False):
            if current.previous_event_digest != previous.event_digest:
                raise ValueError("custody parent link is stale, unknown, or forked")
        if self.genesis_event_digest != self.events[0].event_digest:
            raise ValueError("genesis event digest mismatch")
        if self.latest_event_digest != self.events[-1].event_digest:
            raise ValueError("latest event digest mismatch")
        return self


class CustodyFinding(StrictModel):
    finding_id: str = Field(pattern=r"^CUSTODY-[0-9]{3}$")
    status: str
    summary: str
    limitation: str | None = None


class CustodyTimelineEntry(StrictModel):
    sequence: int = Field(ge=0)
    event_id: str
    event_type: CustodyEventType
    event_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_roles: list[str]
    authenticity: EventAuthenticity
    attestation_status: AttestationStatus
    action: str


class CustodyLedgerReport(StrictModel):
    schema_id: Literal["omiv.custody-ledger-report.v1"] = Field(
        default="omiv.custody-ledger-report.v1", alias="schema"
    )
    subject: ArtifactReference
    chain_id: str
    ledger_digest: str = Field(pattern=SHA256_PATTERN)
    selected_profile: str
    event_timeline: list[CustodyTimelineEntry]
    link_integrity_summary: dict[str, str]
    subject_continuity_summary: str
    evidence_linkage_summary: str
    authenticity_summary: EventAuthenticitySummary
    lifecycle_completeness: LifecycleCompleteness
    overall_custody_status: OverallCustodyStatus
    revocation_status: RevocationStatus
    expiration_status: ExpirationStatus
    profile_completeness: list[ProfileCompleteness]
    missing_event_types: list[CustodyEventType]
    limitations: list[str]
    next_evidence_required: list[str]
    findings: list[CustodyFinding]
    report_digest: str = Field(pattern=SHA256_PATTERN)


class CustodyReportEnvelope(StrictModel):
    report: CustodyLedgerReport
    integrity: dict[str, str]


class LinkedCustodySummary(StrictModel):
    status: Literal["AVAILABLE"] = "AVAILABLE"
    chain_id: str
    ledger_schema: Literal["omiv.custody-ledger.v1"] = "omiv.custody-ledger.v1"
    ledger_digest: str = Field(pattern=SHA256_PATTERN)
    event_count: int = Field(ge=0)
    genesis_event_digest: str = Field(pattern=SHA256_PATTERN)
    latest_event_digest: str = Field(pattern=SHA256_PATTERN)
    ledger_integrity: IntegrityStatus
    subject_continuity: SubjectContinuityStatus
    evidence_linkage: EvidenceLinkageStatus
    event_authenticity: list[EventAuthenticity]
    lifecycle_completeness: LifecycleCompleteness
    overall_custody_status: OverallCustodyStatus
    missing_event_types: list[CustodyEventType]


class CustodyLinkedPassport(StrictModel):
    schema_id: Literal["omiv.model-passport.v2"] = Field(
        default="omiv.model-passport.v2", alias="schema"
    )
    passport_id: str = Field(pattern=r"^mp_[0-9a-f]{32}$")
    base_passport_id: str = Field(pattern=r"^mp_[0-9a-f]{32}$")
    base_passport_digest: str = Field(pattern=SHA256_PATTERN)
    subject: PassportSubject
    artifact_identity: ArtifactIdentity
    evidence_identity: EvidenceIdentity
    evidence_stages: list[PassportEvidenceStage]
    trust_summary: TrustSummary
    usage_profiles: list[UsageProfileResult]
    custody_summary: LinkedCustodySummary
    security_summary: SecuritySummary
    runtime_summary: RuntimeSummary
    limitations: list[str]
    warnings: list[str]
    custody_reference: LedgerArtifactReference
    policy_identity: PolicyIdentity
    passport_digest: str = Field(pattern=SHA256_PATTERN)
