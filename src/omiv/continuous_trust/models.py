"""Strict canonical Phase 5H historical trust and audit-bundle models."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.runtime.models import ScopeContext

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
UTC_TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
MAX_PROPAGATION_NODES = 256
MAX_PROPAGATION_EDGES = 512
MAX_PROPAGATION_DEPTH = 32
MAX_SUPERSESSION_NODES = 128
MAX_SUPERSESSION_EDGES = 128
MAX_SUPERSESSION_DEPTH = 64
MAX_RENEWAL_CHAIN_DEPTH = 64
MAX_TIMELINE_EVENTS = 256
MAX_TIMELINE_TRANSITIONS = 256
MAX_TIMELINE_FORKS = 64
MAX_BUNDLE_MEMBERS = 512
MAX_BUNDLE_PATH_LENGTH = 256
MAX_BUNDLE_METADATA_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_INDEX_ENTRIES = 180
MAX_REPORT_INPUTS = 512
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def normalized_portable_path(value: str) -> str:
    """Validate the canonical NFC, slash-separated portable bundle path policy."""
    if len(value) > MAX_BUNDLE_PATH_LENGTH or unicodedata.normalize("NFC", value) != value:
        raise ValueError("unsafe bundle path: length or Unicode normalization")
    if not value or value.startswith("/") or "\\" in value or "\x00" in value:
        raise ValueError("unsafe bundle path: absolute, alternate separator, or NUL")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("unsafe bundle path: ASCII control character")
    parts = value.split("/")
    for part in parts:
        if not part or part in {".", ".."} or part.endswith((" ", ".")):
            raise ValueError("unsafe bundle path component")
        basename = part.split(".", 1)[0].casefold()
        if basename in WINDOWS_RESERVED_NAMES or ":" in part:
            raise ValueError("unsafe or platform-reserved bundle path component")
    return value


def _validate_utc_timestamp(value: str | None) -> None:
    if value is None:
        return
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("timestamp must be a valid canonical UTC second") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("timestamp is not canonical UTC")


def _unsafe(value: object) -> bool:
    if isinstance(value, str):
        low = value.lower()
        denied = (
            "authorization:",
            "bearer ",
            "github_pat_",
            "ghp_",
            "x-amz-",
            "signature=",
            "password=",
            "api_key=",
            "access_token=",
            "begin private key",
            "begin openssh private key",
        )
        return (
            value.startswith(("/", "~/", "git@"))
            or "\\" in value
            or "${" in value
            or bool(UUID_PATTERN.fullmatch(value))
            or any(x in low for x in denied)
            or (value.startswith(("http://", "https://", "ssh://")) and "?" in value)
        )
    if isinstance(value, list):
        return len(value) > 512 or any(_unsafe(x) for x in value)
    if isinstance(value, dict):
        forbidden = {
            "secret",
            "secret_value",
            "private_key",
            "credentials",
            "raw_payload",
            "model_payload",
            "hostname",
            "username",
            "process_id",
        }
        return bool(forbidden.intersection(value)) or any(_unsafe(x) for x in value.values())
    return False


def _identity(model: StrictModel, id_field: str, prefix: str, digest_field: str) -> None:
    body = model.model_dump(mode="json", by_alias=True)
    digest = body.pop(digest_field)
    if digest != canonical_sha256(body):
        raise ValueError(f"{digest_field} mismatch")
    object_id = body.pop(id_field)
    if object_id != prefix + canonical_sha256(body)[:32]:
        raise ValueError(f"{id_field} mismatch")


class AuditModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def portable(self) -> AuditModel:
        if _unsafe(self.model_dump(mode="json", by_alias=True)):
            raise ValueError(
                "historical record contains unsafe identity, path, or private material"
            )
        return self


class Availability(StrEnum):
    AVAILABLE = "AVAILABLE"
    OMITTED = "OMITTED"
    UNAVAILABLE = "UNAVAILABLE"
    MISSING = "MISSING"
    EXCLUDED = "EXCLUDED"
    UNSUPPORTED = "UNSUPPORTED"
    BROKEN = "BROKEN"


class DimensionState(StrEnum):
    SATISFIED = "SATISFIED"
    SATISFIED_WITH_LIMITATIONS = "SATISFIED_WITH_LIMITATIONS"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_EVALUATED = "NOT_EVALUATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"
    BROKEN = "BROKEN"
    MISMATCH = "MISMATCH"
    DRIFT = "DRIFT"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"


class SnapshotState(StrEnum):
    TRUSTED_FOR_SCOPED_USE = "TRUSTED_FOR_SCOPED_USE"
    TRUSTED_WITH_LIMITATIONS = "TRUSTED_WITH_LIMITATIONS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DENIED = "DENIED"
    STALE = "STALE"
    REVOKED = "REVOKED"
    BROKEN = "BROKEN"
    NOT_EVALUATED = "NOT_EVALUATED"


class EventType(StrEnum):
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    EVIDENCE_REVOKED = "EVIDENCE_REVOKED"
    EVIDENCE_EXPIRED = "EVIDENCE_EXPIRED"
    EVIDENCE_SUPERSEDED = "EVIDENCE_SUPERSEDED"
    EVIDENCE_WITHDRAWN = "EVIDENCE_WITHDRAWN"
    POLICY_CHANGED = "POLICY_CHANGED"
    TRUST_BUNDLE_CHANGED = "TRUST_BUNDLE_CHANGED"
    APPROVAL_ADDED = "APPROVAL_ADDED"
    APPROVAL_WITHDRAWN = "APPROVAL_WITHDRAWN"
    SECURITY_EVIDENCE_ADDED = "SECURITY_EVIDENCE_ADDED"
    SECURITY_EVIDENCE_STALE = "SECURITY_EVIDENCE_STALE"
    DEPLOYMENT_RECORDED = "DEPLOYMENT_RECORDED"
    RUNTIME_OBSERVATION_ADDED = "RUNTIME_OBSERVATION_ADDED"
    RUNTIME_OBSERVATION_RENEWED = "RUNTIME_OBSERVATION_RENEWED"
    RUNTIME_OBSERVATION_STALE = "RUNTIME_OBSERVATION_STALE"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    DRIFT_RESOLVED = "DRIFT_RESOLVED"
    ARTIFACT_REPLACED = "ARTIFACT_REPLACED"
    CUSTODY_EVENT_ADDED = "CUSTODY_EVENT_ADDED"
    OTHER_NORMALIZED_EVENT = "OTHER_NORMALIZED_EVENT"


class TransitionOutcome(StrEnum):
    UNCHANGED = "UNCHANGED"
    STRENGTHENED = "STRENGTHENED"
    WEAKENED = "WEAKENED"
    LIMITED = "LIMITED"
    STALE = "STALE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    WITHDRAWN = "WITHDRAWN"
    SUPERSEDED = "SUPERSEDED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    DRIFT_RESOLVED = "DRIFT_RESOLVED"
    DENIED = "DENIED"
    RESTORED_WITH_NEW_EVIDENCE = "RESTORED_WITH_NEW_EVIDENCE"
    POLICY_RECLASSIFIED = "POLICY_RECLASSIFIED"
    BROKEN = "BROKEN"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class TimelineCompleteness(StrEnum):
    COMPLETE_FOR_DECLARED_RANGE = "COMPLETE_FOR_DECLARED_RANGE"
    PARTIAL = "PARTIAL"
    MISSING_PREDECESSOR = "MISSING_PREDECESSOR"
    FORKED = "FORKED"
    CONFLICTING = "CONFLICTING"
    BROKEN = "BROKEN"
    NOT_ASSESSED = "NOT_ASSESSED"


class ForkOutcome(StrEnum):
    NO_FORK = "NO_FORK"
    FORK_DETECTED = "FORK_DETECTED"
    CONFLICT_DETECTED = "CONFLICT_DETECTED"
    MISSING_HISTORY = "MISSING_HISTORY"
    NOT_EVALUATED = "NOT_EVALUATED"


class BundlePurpose(StrEnum):
    LOCAL_REPRODUCIBILITY = "LOCAL_REPRODUCIBILITY"
    TEAM_RELEASE_REVIEW = "TEAM_RELEASE_REVIEW"
    ENTERPRISE_AUDIT = "ENTERPRISE_AUDIT"
    SECURITY_INCIDENT_REVIEW = "SECURITY_INCIDENT_REVIEW"
    DEPLOYMENT_CONTINUITY_REVIEW = "DEPLOYMENT_CONTINUITY_REVIEW"
    REGULATORY_EVIDENCE_EXPORT = "REGULATORY_EVIDENCE_EXPORT"
    AIR_GAPPED_TRANSFER = "AIR_GAPPED_TRANSFER"
    HISTORICAL_RECONSTRUCTION = "HISTORICAL_RECONSTRUCTION"
    DISPUTE_OR_FORENSIC_REVIEW = "DISPUTE_OR_FORENSIC_REVIEW"
    OTHER_DECLARED = "OTHER_DECLARED"


class BundleCompletenessState(StrEnum):
    COMPLETE_FOR_PURPOSE = "COMPLETE_FOR_PURPOSE"
    COMPLETE_WITH_LIMITATIONS = "COMPLETE_WITH_LIMITATIONS"
    PARTIAL = "PARTIAL"
    MISSING_REQUIRED_MEMBER = "MISSING_REQUIRED_MEMBER"
    BROKEN_REFERENCE = "BROKEN_REFERENCE"
    CONFLICTING_HISTORY = "CONFLICTING_HISTORY"
    FORKED_HISTORY = "FORKED_HISTORY"
    NOT_EVALUATED = "NOT_EVALUATED"


class VerificationOutcome(StrEnum):
    VERIFIED = "VERIFIED"
    VERIFIED_WITH_LIMITATIONS = "VERIFIED_WITH_LIMITATIONS"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


class HistoricalKnowledgeMode(StrEnum):
    KNOWN_AS_OF_CUTOFF = "KNOWN_AS_OF_CUTOFF"


class DependencyEdgeType(StrEnum):
    SIGNATURE_DEPENDENCY = "SIGNATURE_DEPENDENCY"
    AUTHORITY_DEPENDENCY = "AUTHORITY_DEPENDENCY"
    EVIDENCE_DEPENDENCY = "EVIDENCE_DEPENDENCY"
    POLICY_DEPENDENCY = "POLICY_DEPENDENCY"
    CONTINUITY_DEPENDENCY = "CONTINUITY_DEPENDENCY"


class ExplicitDependencyEdge(AuditModel):
    source_object_id: str = Field(pattern=ID_PATTERN)
    dependent_object_id: str = Field(pattern=ID_PATTERN)
    edge_type: DependencyEdgeType
    affected_dimensions: list[str] = Field(min_length=1, max_length=64)


class HistoricalSubject(AuditModel):
    subject_id: str = Field(pattern=ID_PATTERN)
    subject_digest: str = Field(pattern=SHA256_PATTERN)
    subject_class: str = Field(min_length=3, max_length=64)
    scope: ScopeContext


class EvidenceObjectReference(AuditModel):
    schema_id: str = Field(alias="schema", pattern=ID_PATTERN)
    object_id: str = Field(pattern=ID_PATTERN)
    object_digest: str = Field(pattern=SHA256_PATTERN)
    source_phase: str = Field(pattern=r"^5[A-H]$")


class EvidenceSetMember(AuditModel):
    reference: EvidenceObjectReference
    role: str = Field(min_length=3, max_length=64)
    availability: Availability
    verification_mode: str = Field(min_length=3, max_length=64)
    evidence_origin: str = Field(min_length=3, max_length=64)
    authority_status: str = Field(min_length=3, max_length=64)
    available_at: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    inclusion_reason: str = Field(min_length=3, max_length=256)

    @model_validator(mode="after")
    def valid_availability(self) -> EvidenceSetMember:
        _validate_utc_timestamp(self.available_at)
        return self


class EvidenceSetManifest(AuditModel):
    schema_id: Literal["omiv.evidence-set-manifest.v1"] = Field(
        default="omiv.evidence-set-manifest.v1", alias="schema"
    )
    manifest_id: str = Field(pattern=r"^evidence_set_[0-9a-f]{32}$")
    subject: HistoricalSubject
    evidence_set_version: int = Field(ge=1)
    members: list[EvidenceSetMember] = Field(max_length=256)
    predecessor_manifest_id: str | None = Field(
        default=None, pattern=r"^evidence_set_[0-9a-f]{32}$"
    )
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    limitations: list[str] = Field(max_length=64)
    manifest_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_manifest(self) -> EvidenceSetManifest:
        keys = [(x.reference.object_id, x.reference.object_digest) for x in self.members]
        if len(keys) != len(set(keys)) or len({x[0] for x in keys}) != len(keys):
            raise ValueError("duplicate or conflicting evidence-set member")
        if self.predecessor_manifest_id == self.manifest_id:
            raise ValueError("evidence set cannot reference itself")
        _identity(self, "manifest_id", "evidence_set_", "manifest_digest")
        return self


class TrustDimensionState(AuditModel):
    dimension: str = Field(min_length=3, max_length=64)
    state: DimensionState
    evidence_ids: list[str] = Field(max_length=64)
    limitations: list[str] = Field(max_length=32)


class TrustGap(AuditModel):
    category: str = Field(min_length=3, max_length=64)
    state: Availability
    affected_conclusion: str = Field(min_length=3, max_length=256)
    remediation: str = Field(min_length=3, max_length=256)


class TrustSnapshot(AuditModel):
    schema_id: Literal["omiv.trust-snapshot.v1"] = Field(
        default="omiv.trust-snapshot.v1", alias="schema"
    )
    snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    subject: HistoricalSubject
    evidence_manifest_id: str = Field(pattern=r"^evidence_set_[0-9a-f]{32}$")
    evidence_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    policy_set_id: str = Field(pattern=ID_PATTERN)
    policy_set_digest: str = Field(pattern=SHA256_PATTERN)
    trust_bundle_id: str = Field(pattern=ID_PATTERN)
    trust_bundle_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    cutoff: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF]
    dimensions: list[TrustDimensionState] = Field(max_length=64)
    overall_state: SnapshotState
    gaps: list[TrustGap] = Field(max_length=64)
    limitations: list[str] = Field(max_length=64)
    snapshot_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_snapshot(self) -> TrustSnapshot:
        _validate_utc_timestamp(self.cutoff)
        if len({x.dimension for x in self.dimensions}) != len(self.dimensions):
            raise ValueError("duplicate trust dimension")
        states = {row.state for row in self.dimensions}
        if DimensionState.BROKEN in states:
            reconstructed = SnapshotState.BROKEN
        elif DimensionState.REVOKED in states:
            reconstructed = SnapshotState.REVOKED
        elif states.intersection({DimensionState.DENIED, DimensionState.WITHDRAWN}):
            reconstructed = SnapshotState.DENIED
        elif DimensionState.STALE in states:
            reconstructed = SnapshotState.STALE
        elif states.intersection({DimensionState.MISSING, DimensionState.UNKNOWN}):
            reconstructed = SnapshotState.REVIEW_REQUIRED
        elif states.intersection(
            {
                DimensionState.SATISFIED_WITH_LIMITATIONS,
                DimensionState.PARTIAL,
                DimensionState.NOT_CHECKED,
                DimensionState.NOT_EVALUATED,
            }
        ):
            reconstructed = SnapshotState.TRUSTED_WITH_LIMITATIONS
        else:
            reconstructed = SnapshotState.TRUSTED_FOR_SCOPED_USE
        if self.overall_state != reconstructed:
            raise ValueError("snapshot overall state does not match reconstructed dimensions")
        _identity(self, "snapshot_id", "trust_snapshot_", "snapshot_digest")
        return self


class EventAuthority(AuditModel):
    actor_id: str = Field(pattern=ID_PATTERN)
    key_id: str | None = Field(default=None, pattern=ID_PATTERN)
    trusted: bool
    authorized: bool
    assertion_types: list[str] = Field(max_length=32)
    subject_id: str = Field(pattern=ID_PATTERN)
    allowed_object_schemas: list[str] = Field(min_length=1, max_length=32)
    purpose: Literal["HISTORICAL_EVENT_ASSERTION"] = "HISTORICAL_EVENT_ASSERTION"
    key_usage: Literal["SIGNING"] = "SIGNING"
    signer_binding_status: Literal["BOUND_AND_TRUSTED", "UNTRUSTED", "REVOKED", "EXPIRED"]
    scope: ScopeContext
    valid_from_sequence: int = Field(ge=1)
    valid_through_sequence: int = Field(ge=1)


class HistoricalEvent(AuditModel):
    schema_id: Literal["omiv.historical-event.v1"] = Field(
        default="omiv.historical-event.v1", alias="schema"
    )
    event_id: str = Field(pattern=r"^historical_event_[0-9a-f]{32}$")
    subject: HistoricalSubject
    event_type: EventType
    affected_object: EvidenceObjectReference
    predecessor_event_id: str | None = Field(
        default=None, pattern=r"^historical_event_[0-9a-f]{32}$"
    )
    sequence_namespace: str = Field(pattern=ID_PATTERN)
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    assertion_origin: str = Field(min_length=3, max_length=64)
    authority: EventAuthority
    evidence_references: list[EvidenceObjectReference] = Field(max_length=64)
    effective_at: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    available_at: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    observed_at: str | None = Field(default=None, pattern=UTC_TIMESTAMP_PATTERN)
    trusted_time_status: Literal["NOT_AVAILABLE", "UNTRUSTED_DECLARED", "TRUSTED_EVIDENCE"]
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    limitations: list[str] = Field(max_length=64)
    event_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_event(self) -> HistoricalEvent:
        _validate_utc_timestamp(self.effective_at)
        _validate_utc_timestamp(self.available_at)
        _validate_utc_timestamp(self.observed_at)
        if self.predecessor_event_id == self.event_id:
            raise ValueError("event cannot reference itself")
        if not (
            self.authority.valid_from_sequence
            <= self.sequence
            <= self.authority.valid_through_sequence
        ):
            raise ValueError("event sequence outside authority interval")
        if self.authority.scope != self.subject.scope:
            raise ValueError("event authority scope mismatch")
        if self.authority.subject_id != self.subject.subject_id:
            raise ValueError("event authority subject mismatch")
        if self.event_type.value not in self.authority.assertion_types:
            raise ValueError("event type outside authority")
        if self.affected_object.schema_id not in self.authority.allowed_object_schemas:
            raise ValueError("affected object schema outside authority")
        if (
            not self.authority.trusted
            or not self.authority.authorized
            or self.authority.signer_binding_status != "BOUND_AND_TRUSTED"
        ):
            raise ValueError("event authority is not trusted, bound, and authorized")
        _identity(self, "event_id", "historical_event_", "event_digest")
        return self


class TimelineFork(AuditModel):
    schema_id: Literal["omiv.timeline-fork.v1"] = Field(
        default="omiv.timeline-fork.v1", alias="schema"
    )
    fork_id: str = Field(pattern=r"^timeline_fork_[0-9a-f]{32}$")
    outcome: ForkOutcome
    conflicting_event_ids: list[str] = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=256)
    fork_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_fork(self) -> TimelineFork:
        _identity(self, "fork_id", "timeline_fork_", "fork_digest")
        return self


class TrustTimeline(AuditModel):
    schema_id: Literal["omiv.trust-timeline.v1"] = Field(
        default="omiv.trust-timeline.v1", alias="schema"
    )
    timeline_id: str = Field(pattern=r"^trust_timeline_[0-9a-f]{32}$")
    subject: HistoricalSubject
    sequence_namespace: str = Field(pattern=ID_PATTERN)
    epoch: int = Field(ge=1)
    event_ids: list[str] = Field(max_length=256)
    snapshot_ids: list[str] = Field(max_length=256)
    transition_ids: list[str] = Field(max_length=256)
    fork_ids: list[str] = Field(max_length=64)
    completeness: TimelineCompleteness
    declared_start_sequence: int = Field(ge=1)
    declared_end_sequence: int = Field(ge=1)
    limitations: list[str] = Field(max_length=64)
    timeline_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_timeline(self) -> TrustTimeline:
        if self.declared_end_sequence < self.declared_start_sequence:
            raise ValueError("invalid declared timeline range")
        _identity(self, "timeline_id", "trust_timeline_", "timeline_digest")
        return self


class TrustTransition(AuditModel):
    schema_id: Literal["omiv.trust-transition.v1"] = Field(
        default="omiv.trust-transition.v1", alias="schema"
    )
    transition_id: str = Field(pattern=r"^trust_transition_[0-9a-f]{32}$")
    previous_snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    new_snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    outcome: TransitionOutcome
    changed_dimensions: list[str] = Field(max_length=64)
    unchanged_dimensions: list[str] = Field(max_length=64)
    changed_evidence: list[str] = Field(max_length=64)
    changed_policy: bool
    reasons: list[str] = Field(max_length=64)
    limitations: list[str] = Field(max_length=64)
    transition_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_transition(self) -> TrustTransition:
        _identity(self, "transition_id", "trust_transition_", "transition_digest")
        return self


class ReevaluationPolicySet(AuditModel):
    schema_id: Literal["omiv.reevaluation-policy-set.v1"] = Field(
        default="omiv.reevaluation-policy-set.v1", alias="schema"
    )
    policy_set_id: str = Field(pattern=ID_PATTERN)
    policy_references: list[EvidenceObjectReference] = Field(min_length=1, max_length=16)
    scope: ScopeContext
    authority_actor_id: str = Field(pattern=ID_PATTERN)
    authority_key_id: str = Field(pattern=ID_PATTERN)
    authority_status: Literal["AUTHORIZED", "UNAUTHORIZED", "REVOKED", "EXPIRED"]
    authority_purpose: Literal["HISTORICAL_REEVALUATION"] = "HISTORICAL_REEVALUATION"
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF] = (
        HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF
    )
    policy_version: int = Field(ge=1)
    available_at: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    allow_limited_security: bool
    require_current_runtime: bool
    require_no_revocations: bool
    policy_set_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_policy(self) -> ReevaluationPolicySet:
        _validate_utc_timestamp(self.available_at)
        if self.authority_status != "AUTHORIZED":
            raise ValueError("reevaluation policy authority is not authorized")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("policy_set_digest")
        if digest != canonical_sha256(body):
            raise ValueError("policy-set digest mismatch")
        return self


class HistoricalEvaluationRequest(AuditModel):
    schema_id: Literal["omiv.historical-evaluation-request.v1"] = Field(
        default="omiv.historical-evaluation-request.v1", alias="schema"
    )
    request_id: str = Field(pattern=ID_PATTERN)
    subject: HistoricalSubject
    evidence_manifest_id: str = Field(pattern=r"^evidence_set_[0-9a-f]{32}$")
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    policy_set_id: str = Field(pattern=ID_PATTERN)
    policy_set_digest: str = Field(pattern=SHA256_PATTERN)
    requested_dimensions: list[str] = Field(min_length=1, max_length=64)
    cutoff_sequence: int = Field(ge=1)
    cutoff: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    evaluated_at: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF] = (
        HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF
    )
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def valid_request(self) -> HistoricalEvaluationRequest:
        _validate_utc_timestamp(self.cutoff)
        _validate_utc_timestamp(self.evaluated_at)
        return self


class HistoricalEvaluationResult(AuditModel):
    schema_id: Literal["omiv.historical-evaluation-result.v1"] = Field(
        default="omiv.historical-evaluation-result.v1", alias="schema"
    )
    result_id: str = Field(pattern=r"^historical_eval_[0-9a-f]{32}$")
    request_id: str = Field(pattern=ID_PATTERN)
    snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    accepted_evidence_ids: list[str] = Field(max_length=256)
    rejected_evidence_ids: list[str] = Field(max_length=256)
    late_arriving_evidence_ids: list[str] = Field(max_length=256)
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF]
    cutoff: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    revocation_event_ids: list[str] = Field(max_length=64)
    superseded_object_ids: list[str] = Field(max_length=64)
    fork_ids: list[str] = Field(max_length=64)
    transition_id: str | None = Field(default=None, pattern=r"^trust_transition_[0-9a-f]{32}$")
    gaps: list[TrustGap] = Field(max_length=64)
    limitations: list[str] = Field(max_length=64)
    result_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_result(self) -> HistoricalEvaluationResult:
        _identity(self, "result_id", "historical_eval_", "result_digest")
        return self


class RevocationPropagationResult(AuditModel):
    schema_id: Literal["omiv.revocation-propagation-result.v1"] = Field(
        default="omiv.revocation-propagation-result.v1", alias="schema"
    )
    propagation_id: str = Field(pattern=r"^revocation_propagation_[0-9a-f]{32}$")
    direct_target_ids: list[str] = Field(min_length=1, max_length=64)
    transitive_dependent_ids: list[str] = Field(max_length=256)
    affected_dimensions: list[str] = Field(max_length=64)
    unchanged_historical_snapshot_ids: list[str] = Field(max_length=64)
    reevaluation_required: bool
    status: Literal["PROPAGATED", "PARTIAL", "UNAUTHORIZED", "BROKEN"]
    limitations: list[str] = Field(max_length=64)
    propagation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_propagation(self) -> RevocationPropagationResult:
        _identity(self, "propagation_id", "revocation_propagation_", "propagation_digest")
        return self


class SupersessionEdge(AuditModel):
    old_object_id: str = Field(pattern=ID_PATTERN)
    replacement_object_id: str = Field(pattern=ID_PATTERN)
    event_id: str = Field(pattern=r"^historical_event_[0-9a-f]{32}$")


class SupersessionGraph(AuditModel):
    schema_id: Literal["omiv.supersession-graph.v1"] = Field(
        default="omiv.supersession-graph.v1", alias="schema"
    )
    graph_id: str = Field(pattern=r"^supersession_graph_[0-9a-f]{32}$")
    subject_id: str = Field(pattern=ID_PATTERN)
    edges: list[SupersessionEdge] = Field(max_length=MAX_SUPERSESSION_EDGES)
    withdrawn_object_ids: list[str] = Field(max_length=64)
    conflicting_object_ids: list[str] = Field(max_length=64)
    limitations: list[str] = Field(max_length=64)
    graph_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_graph(self) -> SupersessionGraph:
        mapping = {x.old_object_id: x.replacement_object_id for x in self.edges}
        if len(mapping) != len(self.edges):
            raise ValueError("conflicting supersession source")
        for start in mapping:
            seen: set[str] = set()
            node = start
            depth = 0
            while node in mapping:
                depth += 1
                if depth > MAX_SUPERSESSION_DEPTH:
                    raise ValueError("LIMIT_EXCEEDED:SUPERSESSION_DEPTH")
                if node in seen:
                    raise ValueError("supersession cycle")
                seen.add(node)
                node = mapping[node]
        _identity(self, "graph_id", "supersession_graph_", "graph_digest")
        return self


class FreshnessTransitionResult(AuditModel):
    schema_id: Literal["omiv.freshness-transition-result.v1"] = Field(
        default="omiv.freshness-transition-result.v1", alias="schema"
    )
    freshness_id: str = Field(pattern=r"^freshness_transition_[0-9a-f]{32}$")
    object_id: str = Field(pattern=ID_PATTERN)
    previous_state: str = Field(min_length=3, max_length=32)
    new_state: str = Field(min_length=3, max_length=32)
    previous_context_digest: str = Field(pattern=SHA256_PATTERN)
    new_context_digest: str = Field(pattern=SHA256_PATTERN)
    limitations: list[str] = Field(max_length=32)
    freshness_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_freshness(self) -> FreshnessTransitionResult:
        _identity(self, "freshness_id", "freshness_transition_", "freshness_digest")
        return self


class RenewalRecord(AuditModel):
    schema_id: Literal["omiv.renewal-record.v1"] = Field(
        default="omiv.renewal-record.v1", alias="schema"
    )
    renewal_id: str = Field(pattern=r"^renewal_[0-9a-f]{32}$")
    previous_observation_id: str = Field(pattern=ID_PATTERN)
    new_observation_id: str = Field(pattern=ID_PATTERN)
    deployment_instance_id: str = Field(pattern=ID_PATTERN)
    observer_id: str = Field(pattern=ID_PATTERN)
    authority_event_id: str = Field(pattern=r"^historical_event_[0-9a-f]{32}$")
    policy_id: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    sequence: int = Field(ge=1)
    renewed_dimensions: list[str] = Field(min_length=1, max_length=64)
    dimensions_not_renewed: list[str] = Field(max_length=64)
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    limitations: list[str] = Field(max_length=32)
    renewal_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_renewal(self) -> RenewalRecord:
        if set(self.renewed_dimensions).intersection(self.dimensions_not_renewed):
            raise ValueError("renewal dimensions overlap")
        _identity(self, "renewal_id", "renewal_", "renewal_digest")
        return self


class AuditBundleGap(AuditModel):
    category: str = Field(min_length=3, max_length=64)
    required: bool
    state: Availability
    reason: str = Field(min_length=3, max_length=256)
    affected_conclusion: str = Field(min_length=3, max_length=256)
    remediation: str = Field(min_length=3, max_length=256)


class AuditBundleMember(AuditModel):
    relative_path: str = Field(min_length=1, max_length=MAX_BUNDLE_PATH_LENGTH)
    schema_id: str = Field(pattern=ID_PATTERN)
    object_id: str = Field(pattern=ID_PATTERN)
    object_digest: str = Field(pattern=SHA256_PATTERN)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(ge=0, le=1_048_576)
    inclusion_reason: str = Field(min_length=3, max_length=256)

    @model_validator(mode="after")
    def safe_path(self) -> AuditBundleMember:
        normalized_portable_path(self.relative_path)
        return self


class AuditBundleManifest(AuditModel):
    schema_id: Literal["omiv.audit-bundle-manifest.v1"] = Field(
        default="omiv.audit-bundle-manifest.v1", alias="schema"
    )
    bundle_id: str = Field(pattern=r"^audit_bundle_[0-9a-f]{32}$")
    purpose: BundlePurpose
    subject: HistoricalSubject
    range_start_sequence: int = Field(ge=1)
    range_end_sequence: int = Field(ge=1)
    members: list[AuditBundleMember] = Field(max_length=MAX_BUNDLE_MEMBERS)
    exclusions: list[AuditBundleGap] = Field(max_length=64)
    completeness_policy_id: str = Field(pattern=ID_PATTERN)
    completeness_policy_digest: str = Field(pattern=SHA256_PATTERN)
    model_payload_included: Literal[False] = False
    limitations: list[str] = Field(max_length=64)
    manifest_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_bundle(self) -> AuditBundleManifest:
        paths = [unicodedata.normalize("NFC", x.relative_path).casefold() for x in self.members]
        ids = [x.object_id for x in self.members]
        if len(paths) != len(set(paths)) or len(ids) != len(set(ids)):
            duplicate_ids = sorted({x for x in ids if ids.count(x) > 1})
            raise ValueError(f"duplicate or case-conflicting bundle member: {duplicate_ids}")
        if "manifest.json" in paths:
            raise ValueError("bundle manifest cannot include itself")
        path_set = set(paths)
        for path in paths:
            parts = path.split("/")
            if any("/".join(parts[:index]) in path_set for index in range(1, len(parts))):
                raise ValueError("bundle file/directory prefix conflict")
        if self.range_end_sequence < self.range_start_sequence:
            raise ValueError("invalid bundle range")
        _identity(self, "bundle_id", "audit_bundle_", "manifest_digest")
        return self


class AuditBundleCompleteness(AuditModel):
    schema_id: Literal["omiv.audit-bundle-completeness.v1"] = Field(
        default="omiv.audit-bundle-completeness.v1", alias="schema"
    )
    completeness_id: str = Field(pattern=r"^bundle_completeness_[0-9a-f]{32}$")
    bundle_id: str = Field(pattern=r"^audit_bundle_[0-9a-f]{32}$")
    purpose: BundlePurpose
    state: BundleCompletenessState
    satisfied_dimensions: list[str] = Field(max_length=64)
    missing_dimensions: list[str] = Field(max_length=64)
    gaps: list[AuditBundleGap] = Field(max_length=64)
    limitations: list[str] = Field(max_length=64)
    completeness_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_completeness(self) -> AuditBundleCompleteness:
        _identity(self, "completeness_id", "bundle_completeness_", "completeness_digest")
        return self


class AuditBundleVerificationResult(AuditModel):
    schema_id: Literal["omiv.audit-bundle-verification-result.v1"] = Field(
        default="omiv.audit-bundle-verification-result.v1", alias="schema"
    )
    verification_id: str = Field(pattern=r"^bundle_verification_[0-9a-f]{32}$")
    bundle_id: str = Field(pattern=r"^audit_bundle_[0-9a-f]{32}$")
    manifest_digest: str = Field(pattern=SHA256_PATTERN)
    outcome: VerificationOutcome
    verified_member_ids: list[str] = Field(max_length=512)
    rejected_member_ids: list[str] = Field(max_length=512)
    completeness_id: str = Field(pattern=r"^bundle_completeness_[0-9a-f]{32}$")
    reconstructed_snapshot_ids: list[str] = Field(max_length=128)
    reconstructed_timeline_ids: list[str] = Field(max_length=128)
    limitations: list[str] = Field(max_length=64)
    verification_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_verification(self) -> AuditBundleVerificationResult:
        _identity(self, "verification_id", "bundle_verification_", "verification_digest")
        return self


class AuditBundleReport(AuditModel):
    schema_id: Literal["omiv.audit-bundle-report.v1"] = Field(
        default="omiv.audit-bundle-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^audit_report_[0-9a-f]{32}$")
    bundle_id: str = Field(pattern=r"^audit_bundle_[0-9a-f]{32}$")
    purpose: BundlePurpose
    evidence_range: str = Field(min_length=3, max_length=128)
    latest_supplied_snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    latest_snapshot_cutoff: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF]
    policy_set_id: str = Field(pattern=ID_PATTERN)
    policy_set_digest: str = Field(pattern=SHA256_PATTERN)
    completeness: BundleCompletenessState
    verification: VerificationOutcome
    continuous_monitoring: Literal["NOT_IMPLEMENTED"] = "NOT_IMPLEMENTED"
    continuous_observation: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    trusted_timestamp: str = "NOT_AVAILABLE"
    model_payload_included: Literal[False] = False
    historical_records_modified: Literal[False] = False
    revoked_records_retained: Literal[True] = True
    outstanding_gaps: list[str] = Field(max_length=64)
    limitations: list[str] = Field(max_length=64)
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_report(self) -> AuditBundleReport:
        _validate_utc_timestamp(self.latest_snapshot_cutoff)
        _identity(self, "report_id", "audit_report_", "report_digest")
        return self


class PassportHistoricalSummary(AuditModel):
    schema_id: Literal["omiv.passport-historical-summary.v1"] = Field(
        default="omiv.passport-historical-summary.v1", alias="schema"
    )
    summary_id: str = Field(pattern=ID_PATTERN)
    passport_id: str = Field(pattern=ID_PATTERN)
    subject_id: str = Field(pattern=ID_PATTERN)
    latest_supplied_snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    latest_snapshot_cutoff: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF]
    policy_set_id: str = Field(pattern=ID_PATTERN)
    policy_set_digest: str = Field(pattern=SHA256_PATTERN)
    historical_snapshot_count: int = Field(ge=1)
    prior_states: list[SnapshotState] = Field(max_length=64)
    current_reconstructed_state: SnapshotState
    revoked_object_ids: list[str] = Field(max_length=64)
    superseded_object_ids: list[str] = Field(max_length=64)
    stale_dimensions: list[str] = Field(max_length=64)
    audit_bundle_ids: list[str] = Field(max_length=64)
    continuous_observation: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    trusted_timestamp: str = "NOT_AVAILABLE"
    limitations: list[str] = Field(max_length=64)
    summary_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_summary(self) -> PassportHistoricalSummary:
        _validate_utc_timestamp(self.latest_snapshot_cutoff)
        _identity(self, "summary_id", "passport_history_", "summary_digest")
        return self


class CustodyHistoricalLinkage(AuditModel):
    schema_id: Literal["omiv.custody-historical-linkage.v1"] = Field(
        default="omiv.custody-historical-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=ID_PATTERN)
    chain_id: str = Field(pattern=ID_PATTERN)
    subject_id: str = Field(pattern=ID_PATTERN)
    event_types: list[str] = Field(max_length=64)
    snapshot_ids: list[str] = Field(max_length=64)
    timeline_id: str = Field(pattern=r"^trust_timeline_[0-9a-f]{32}$")
    audit_bundle_ids: list[str] = Field(max_length=64)
    append_only: Literal[True] = True
    limitations: list[str] = Field(max_length=64)
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_linkage(self) -> CustodyHistoricalLinkage:
        _identity(self, "linkage_id", "custody_history_", "linkage_digest")
        return self


class GovernanceHistoricalAdapter(AuditModel):
    schema_id: Literal["omiv.governance-historical-adapter.v1"] = Field(
        default="omiv.governance-historical-adapter.v1", alias="schema"
    )
    adapter_id: str = Field(pattern=ID_PATTERN)
    subject_id: str = Field(pattern=ID_PATTERN)
    snapshot_id: str = Field(pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    previous_snapshot_id: str | None = Field(default=None, pattern=r"^trust_snapshot_[0-9a-f]{32}$")
    transition_id: str | None = Field(default=None, pattern=r"^trust_transition_[0-9a-f]{32}$")
    policy_set_id: str = Field(pattern=ID_PATTERN)
    policy_set_digest: str = Field(pattern=SHA256_PATTERN)
    knowledge_mode: Literal[HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF]
    cutoff: str = Field(pattern=UTC_TIMESTAMP_PATTERN)
    approval_state: DimensionState
    security_state: DimensionState
    runtime_state: DimensionState
    bundle_completeness: BundleCompletenessState
    outstanding_gaps: list[str] = Field(max_length=64)
    source_limitations: list[str] = Field(max_length=64)
    adapter_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_adapter(self) -> GovernanceHistoricalAdapter:
        _validate_utc_timestamp(self.cutoff)
        _identity(self, "adapter_id", "governance_history_", "adapter_digest")
        return self


class SignedHistoricalLinkage(AuditModel):
    schema_id: Literal["omiv.signed-historical-linkage.v1"] = Field(
        default="omiv.signed-historical-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=ID_PATTERN)
    object_type: str = Field(min_length=3, max_length=64)
    object_id: str = Field(pattern=ID_PATTERN)
    object_digest: str = Field(pattern=SHA256_PATTERN)
    envelope_id: str = Field(pattern=ID_PATTERN)
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    trust_status: str = Field(min_length=3, max_length=64)
    limitations: list[str] = Field(max_length=32)
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_linkage(self) -> SignedHistoricalLinkage:
        _identity(self, "linkage_id", "signed_history_", "linkage_digest")
        return self


class ArtifactIndexEntry(AuditModel):
    relative_path: str = Field(min_length=1, max_length=MAX_BUNDLE_PATH_LENGTH)
    size: int = Field(ge=0, le=1_048_576)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str = Field(pattern=ID_PATTERN)
    canonical_id: str = Field(pattern=ID_PATTERN)

    @model_validator(mode="after")
    def safe_path(self) -> ArtifactIndexEntry:
        normalized_portable_path(self.relative_path)
        return self


class ContinuousTrustArtifactIndex(AuditModel):
    schema_id: Literal["omiv.continuous-trust-artifact-index.v1"] = Field(
        default="omiv.continuous-trust-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^continuous_trust_index_[0-9a-f]{32}$")
    entries: list[ArtifactIndexEntry] = Field(max_length=MAX_INDEX_ENTRIES)
    generated_json_count: int = Field(ge=0)
    generated_markdown_count: int = Field(ge=0)
    total_size: int = Field(ge=0)
    limitations: list[str] = Field(max_length=32)
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_index(self) -> ContinuousTrustArtifactIndex:
        ids = [x.canonical_id for x in self.entries]
        hashes = [x.sha256 for x in self.entries]
        if len(ids) != len(set(ids)) or len(hashes) != len(set(hashes)):
            raise ValueError("continuous trust index contains duplicate IDs or content")
        normalized = [
            unicodedata.normalize("NFC", x.relative_path).casefold() for x in self.entries
        ]
        if len(normalized) != len(set(normalized)):
            raise ValueError("continuous trust index contains normalized path collisions")
        _identity(self, "index_id", "continuous_trust_index_", "index_digest")
        return self
