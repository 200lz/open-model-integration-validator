"""Strict public-only schemas for Phase 5E governance records."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _unsafe(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        forbidden = (
            "authorization:",
            "bearer ",
            "github_pat_",
            "ghp_",
            "x-amz-",
            "signature=",
            "key-pair-id=",
            "password=",
            "api_key=",
            "access_token=",
            "private key",
        )
        return (
            value.startswith(("/", "~/"))
            or "\\" in value
            or value.startswith("git@")
            or "$HOME" in value
            or "${" in value
            or ".venv" in value
            or bool(UUID_PATTERN.fullmatch(value))
            or any(item in lowered for item in forbidden)
            or (value.startswith(("http://", "https://", "ssh://")) and "?" in value)
        )
    if isinstance(value, list):
        return any(_unsafe(item) for item in value)
    if isinstance(value, dict):
        return any(_unsafe(item) for item in value.values())
    return False


class GovernanceModel(StrictModel):
    """Shared portable-value validation for governance artifacts."""

    @model_validator(mode="after")
    def portable_public_values(self) -> GovernanceModel:
        if _unsafe(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("governance object contains a local path or credential-bearing value")
        return self


class GovernanceRole(StrEnum):
    REQUESTER = "REQUESTER"
    ARTIFACT_PRODUCER = "ARTIFACT_PRODUCER"
    TRANSFORMER = "TRANSFORMER"
    VALIDATOR = "VALIDATOR"
    SECURITY_REVIEWER = "SECURITY_REVIEWER"
    APPROVER = "APPROVER"
    RELEASE_MANAGER = "RELEASE_MANAGER"
    PROMOTER = "PROMOTER"
    AUDITOR = "AUDITOR"
    SYSTEM_POLICY_ENGINE = "SYSTEM_POLICY_ENGINE"


class EvidenceCategory(StrEnum):
    ARTIFACT_IDENTITY = "ARTIFACT_IDENTITY"
    IMMUTABLE_REVISION = "IMMUTABLE_REVISION"
    STRUCTURAL_VALIDATION = "STRUCTURAL_VALIDATION"
    ACQUISITION_ATTESTATION = "ACQUISITION_ATTESTATION"
    TRANSFORMATION_ATTESTATION = "TRANSFORMATION_ATTESTATION"
    QUANTIZATION_ATTESTATION = "QUANTIZATION_ATTESTATION"
    TOOL_EXECUTION_RECORD = "TOOL_EXECUTION_RECORD"
    SIGNATURE_TRUST = "SIGNATURE_TRUST"
    SIGNER_IDENTITY_BINDING = "SIGNER_IDENTITY_BINDING"
    CUSTODY_INTEGRITY = "CUSTODY_INTEGRITY"
    CUSTODY_COMPLETENESS = "CUSTODY_COMPLETENESS"
    PAYLOAD_INTEGRITY = "PAYLOAD_INTEGRITY"
    SECURITY_INSPECTION = "SECURITY_INSPECTION"
    QUANTIZATION_FIDELITY = "QUANTIZATION_FIDELITY"
    TOKENIZER_PARITY = "TOKENIZER_PARITY"
    APPROVAL = "APPROVAL"
    PROMOTION = "PROMOTION"
    DEPLOYMENT = "DEPLOYMENT"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    REVOCATION_EVALUATION = "REVOCATION_EVALUATION"
    EXPIRATION_EVALUATION = "EXPIRATION_EVALUATION"


class RequirementOutcome(StrEnum):
    SATISFIED = "SATISFIED"
    SATISFIED_WITH_LIMITATIONS = "SATISFIED_WITH_LIMITATIONS"
    MISSING = "MISSING"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"
    INVALID = "INVALID"
    BROKEN = "BROKEN"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_WITH_LIMITATIONS = "ALLOW_WITH_LIMITATIONS"
    DENY = "DENY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NOT_EVALUATED = "NOT_EVALUATED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    POLICY_INVALID = "POLICY_INVALID"
    EVIDENCE_BROKEN = "EVIDENCE_BROKEN"


class ApprovalOutcome(StrEnum):
    APPROVED = "APPROVED"
    APPROVED_WITH_CONDITIONS = "APPROVED_WITH_CONDITIONS"
    REJECTED = "REJECTED"
    ABSTAINED = "ABSTAINED"
    WITHDRAWN = "WITHDRAWN"
    EXPIRED = "EXPIRED"
    UNVERIFIED = "UNVERIFIED"


class ApprovalAction(StrEnum):
    APPROVE_ARTIFACT_INTAKE = "APPROVE_ARTIFACT_INTAKE"
    APPROVE_RELEASE_CANDIDATE = "APPROVE_RELEASE_CANDIDATE"
    APPROVE_REGISTRY_PROMOTION = "APPROVE_REGISTRY_PROMOTION"
    APPROVE_EXCEPTION_RESERVED = "APPROVE_EXCEPTION_RESERVED"
    APPROVE_DEPLOYMENT_RESERVED = "APPROVE_DEPLOYMENT_RESERVED"


class IdentityTrust(StrEnum):
    TRUSTED_BY_POLICY = "TRUSTED_BY_POLICY"
    DECLARED = "DECLARED"
    UNVERIFIED = "UNVERIFIED"
    UNAVAILABLE = "UNAVAILABLE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class SeparationOutcome(StrEnum):
    SATISFIED = "SATISFIED"
    PARTIALLY_SATISFIED = "PARTIALLY_SATISFIED"
    VIOLATED = "VIOLATED"
    NOT_EVALUATED = "NOT_EVALUATED"
    INSUFFICIENT_IDENTITY_EVIDENCE = "INSUFFICIENT_IDENTITY_EVIDENCE"


class IndependenceDimension(StrEnum):
    DISTINCT_SIGNER_IDENTITY = "DISTINCT_SIGNER_IDENTITY"
    DISTINCT_KEY = "DISTINCT_KEY"
    DISTINCT_TRUST_ROOT = "DISTINCT_TRUST_ROOT"
    DISTINCT_ORGANIZATION = "DISTINCT_ORGANIZATION"
    DISTINCT_ROLE_ASSIGNMENT = "DISTINCT_ROLE_ASSIGNMENT"
    POLICY_DECLARED_INDEPENDENCE = "POLICY_DECLARED_INDEPENDENCE"


class QuorumOutcome(StrEnum):
    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    BLOCKED_BY_REJECTION = "BLOCKED_BY_REJECTION"
    PARTIAL = "PARTIAL"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class PromotionTargetType(StrEnum):
    LOCAL_APPROVED_DIRECTORY = "LOCAL_APPROVED_DIRECTORY"
    TEAM_ARTIFACT_REGISTRY = "TEAM_ARTIFACT_REGISTRY"
    INTERNAL_MODEL_REGISTRY = "INTERNAL_MODEL_REGISTRY"
    ENTERPRISE_RELEASE_REGISTRY = "ENTERPRISE_RELEASE_REGISTRY"
    AIR_GAPPED_RELEASE_PACKAGE = "AIR_GAPPED_RELEASE_PACKAGE"
    DEPLOYMENT_REGISTRY_RESERVED = "DEPLOYMENT_REGISTRY_RESERVED"
    OTHER_DECLARED = "OTHER_DECLARED"


class PromotionOutcome(StrEnum):
    PROMOTION_ALLOWED = "PROMOTION_ALLOWED"
    PROMOTION_ALLOWED_WITH_CONDITIONS = "PROMOTION_ALLOWED_WITH_CONDITIONS"
    PROMOTION_DENIED = "PROMOTION_DENIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NOT_EVALUATED = "NOT_EVALUATED"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    POLICY_INVALID = "POLICY_INVALID"


class ReferenceAvailability(StrEnum):
    INCLUDED = "INCLUDED"
    AVAILABLE = "AVAILABLE"
    DIGEST_ONLY = "DIGEST_ONLY"
    UNAVAILABLE = "UNAVAILABLE"


class VerificationMode(StrEnum):
    FULL = "FULL"
    DIGEST_LINKED = "DIGEST_LINKED"
    DECLARED = "DECLARED"
    NOT_VERIFIED = "NOT_VERIFIED"


class GovernanceSubject(GovernanceModel):
    subject_id: str = Field(pattern=r"^subject_[0-9a-f]{32}$")
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    artifact_set_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    artifact_format: str
    origin_type: Literal["local", "s3", "oci", "internal_registry", "air_gapped", "other"]
    provider: str | None = None
    logical_locator: str
    immutable_revision: str | None = None
    variant: str


class EvidenceReference(GovernanceModel):
    evidence_id: str = Field(pattern=ID_PATTERN)
    category: EvidenceCategory
    schema_id: str = Field(alias="schema")
    object_id: str
    digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str = Field(pattern=r"^subject_[0-9a-f]{32}$")
    governance_policy_id: str | None = None
    availability: ReferenceAvailability
    verification_mode: VerificationMode
    source_phase: str = Field(pattern=r"^[1-5][A-Z0-9]*$")
    observed_at: str | None = None
    valid_until: str | None = None
    trust_status: str | None = None
    signer_roles: list[GovernanceRole] = Field(default_factory=list)
    provenance_strength: str | None = None
    custody_status: str | None = None
    lifecycle_events: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent_reference(self) -> EvidenceReference:
        for timestamp in (self.observed_at, self.valid_until):
            if timestamp is not None and not UTC_PATTERN.fullmatch(timestamp):
                raise ValueError("evidence timestamps must be fixed-width UTC")
        if self.verification_mode == VerificationMode.FULL and self.availability not in {
            ReferenceAvailability.INCLUDED,
            ReferenceAvailability.AVAILABLE,
        }:
            raise ValueError("full verification requires included or available evidence")
        if self.availability == ReferenceAvailability.DIGEST_ONLY and (
            self.verification_mode == VerificationMode.FULL
        ):
            raise ValueError("digest-only evidence cannot claim full verification")
        return self


class EvidenceRequirement(GovernanceModel):
    schema_id: Literal["omiv.evidence-requirement.v1"] = Field(
        default="omiv.evidence-requirement.v1", alias="schema"
    )
    requirement_id: str = Field(pattern=r"^requirement_[0-9a-f]{32}$")
    category: EvidenceCategory
    required_object_types: list[str]
    accepted_schemas: list[str]
    accepted_verification_modes: list[VerificationMode]
    accepted_trust_statuses: list[str]
    minimum_freshness_seconds: int | None = Field(default=None, ge=0)
    minimum_signature_count: int = Field(default=0, ge=0)
    required_signer_roles: list[GovernanceRole]
    required_provenance_strength: str | None = None
    required_custody_status: str | None = None
    required_lifecycle_events: list[str]
    optional: bool = False
    allow_with_limitations: bool = False
    reviewable: bool = False
    not_applicable_policy_evidence: list[str]
    failure_severity: Literal["BLOCKING", "REVIEW", "WARNING"]
    remediation: str
    source_phase: str = Field(pattern=r"^[1-5][A-Z0-9]*$")
    requirement_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_digest(self) -> EvidenceRequirement:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("requirement_digest")
        if self.requirement_digest != canonical_sha256(body):
            raise ValueError("requirement digest mismatch")
        return self


class EvidenceRequirementSet(GovernanceModel):
    schema_id: Literal["omiv.evidence-requirement-set.v1"] = Field(
        default="omiv.evidence-requirement-set.v1", alias="schema"
    )
    requirement_set_id: str = Field(pattern=r"^requirement_set_[0-9a-f]{32}$")
    requirements: list[EvidenceRequirement]
    requirement_set_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_set(self) -> EvidenceRequirementSet:
        if len({item.requirement_id for item in self.requirements}) != len(self.requirements):
            raise ValueError("duplicate evidence requirement")
        if self.requirements != sorted(self.requirements, key=lambda item: item.requirement_id):
            raise ValueError("evidence requirements must be deterministically ordered")
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("requirement_set_digest")
        if self.requirement_set_digest != canonical_sha256(body):
            raise ValueError("requirement-set digest mismatch")
        return self


class GovernanceEvaluationContext(GovernanceModel):
    context_id: str = Field(pattern=r"^gov_eval_[0-9a-f]{32}$")
    evaluation_time: str | None
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    context_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_context(self) -> GovernanceEvaluationContext:
        if self.evaluation_time is not None and not UTC_PATTERN.fullmatch(self.evaluation_time):
            raise ValueError("evaluation time must be fixed-width UTC")
        body = self.model_dump(mode="json")
        body.pop("context_digest")
        if self.context_digest != canonical_sha256(body):
            raise ValueError("governance context digest mismatch")
        return self


class ApprovalActorReference(GovernanceModel):
    signer_identity_id: str | None = None
    key_id: str | None = None
    trust_root_id: str | None = None
    organization_id: str | None = None
    identity_trust: IdentityTrust

    @model_validator(mode="after")
    def unavailable_is_empty(self) -> ApprovalActorReference:
        if self.identity_trust == IdentityTrust.UNAVAILABLE and any(
            (self.signer_identity_id, self.key_id, self.trust_root_id, self.organization_id)
        ):
            raise ValueError("unavailable actor cannot claim identity")
        return self


class RoleAssignment(GovernanceModel):
    assignment_id: str = Field(pattern=r"^role_[0-9a-f]{32}$")
    actor: ApprovalActorReference
    role: GovernanceRole
    allowed_actions: list[ApprovalAction]
    subject_scope: str
    policy_id: str
    limitations: list[str]


class ApprovalQuorum(GovernanceModel):
    quorum_id: str = Field(pattern=r"^quorum_[0-9a-f]{32}$")
    minimum_count: int = Field(ge=1)
    required_roles: list[GovernanceRole]
    minimum_distinct_signers: int = Field(ge=0)
    minimum_distinct_keys: int = Field(ge=0)
    minimum_distinct_trust_roots: int = Field(ge=0)
    rejection_blocks: bool = True
    abstentions_count: bool = False
    conditional_approvals_count: bool = True
    unanimous: bool = False
    quorum_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_quorum(self) -> ApprovalQuorum:
        body = self.model_dump(mode="json")
        body.pop("quorum_digest")
        if self.quorum_digest != canonical_sha256(body):
            raise ValueError("approval quorum digest mismatch")
        return self


class ApprovalPolicy(GovernanceModel):
    schema_id: Literal["omiv.approval-policy.v1"] = Field(
        default="omiv.approval-policy.v1", alias="schema"
    )
    approval_policy_id: str = Field(pattern=r"^approval_policy_[0-9a-f]{32}$")
    requested_action: ApprovalAction
    permitted_roles: list[GovernanceRole]
    require_signed_approval: bool
    accepted_identity_trust: list[IdentityTrust]
    quorum: ApprovalQuorum
    approval_policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_policy(self) -> ApprovalPolicy:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("approval_policy_digest")
        if self.approval_policy_digest != canonical_sha256(body):
            raise ValueError("approval policy digest mismatch")
        return self


class SeparationOfDutiesPolicy(GovernanceModel):
    schema_id: Literal["omiv.separation-of-duties-policy.v1"] = Field(
        default="omiv.separation-of-duties-policy.v1", alias="schema"
    )
    separation_policy_id: str = Field(pattern=r"^separation_policy_[0-9a-f]{32}$")
    requester_must_not_approve: bool
    producer_must_not_be_sole_validator: bool
    transformer_must_not_approve: bool
    validator_must_not_promote: bool
    promoter_must_not_approve_request: bool
    required_independence: list[IndependenceDimension]
    delegates_under_same_root_independent: bool = False
    separation_policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_policy(self) -> SeparationOfDutiesPolicy:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("separation_policy_digest")
        if self.separation_policy_digest != canonical_sha256(body):
            raise ValueError("separation policy digest mismatch")
        return self


class GovernancePolicy(GovernanceModel):
    schema_id: Literal["omiv.governance-policy.v1"] = Field(
        default="omiv.governance-policy.v1", alias="schema"
    )
    policy_id: str
    version: int = Field(ge=1)
    profile: Literal[
        "personal_local_use",
        "team_artifact_intake",
        "team_release_candidate",
        "enterprise_registry_promotion",
        "regulated_production_release",
    ]
    accepted_formats: list[str]
    accepted_origin_types: list[str]
    requirement_set: EvidenceRequirementSet
    trust_policy_ids: list[str]
    approval_policy: ApprovalPolicy | None
    separation_of_duties_policy: SeparationOfDutiesPolicy | None
    allowed_target_types: list[PromotionTargetType]
    missing_evidence_behavior: Literal["DENY", "REVIEW", "LIMITATION"]
    stale_evidence_behavior: Literal["DENY", "REVIEW", "LIMITATION"]
    require_evaluation_time: bool
    require_revocation_evaluation: bool
    require_expiration_evaluation: bool
    decision_precedence: list[DecisionOutcome]
    limitations: list[str]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_policy(self) -> GovernancePolicy:
        expected = [
            DecisionOutcome.POLICY_INVALID,
            DecisionOutcome.EVIDENCE_BROKEN,
            DecisionOutcome.DENY,
            DecisionOutcome.NOT_EVALUATED,
            DecisionOutcome.REVIEW_REQUIRED,
            DecisionOutcome.ALLOW_WITH_LIMITATIONS,
            DecisionOutcome.ALLOW,
        ]
        if self.decision_precedence != expected:
            raise ValueError("governance decision precedence is not canonical")
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("policy_digest")
        if self.policy_digest != canonical_sha256(body):
            raise ValueError("governance policy digest mismatch")
        return self


class PolicyEvaluationInput(GovernanceModel):
    schema_id: Literal["omiv.policy-evaluation-input.v1"] = Field(
        default="omiv.policy-evaluation-input.v1", alias="schema"
    )
    subject: GovernanceSubject
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context: GovernanceEvaluationContext | None
    evidence: list[EvidenceReference]
    role_assignments: list[RoleAssignment]
    approval_request_ids: list[str]
    approval_record_ids: list[str]
    promotion_target_id: str | None

    @model_validator(mode="after")
    def coherent_input(self) -> PolicyEvaluationInput:
        if len({item.evidence_id for item in self.evidence}) != len(self.evidence):
            raise ValueError("duplicate evidence reference")
        if self.evidence != sorted(self.evidence, key=lambda item: item.evidence_id):
            raise ValueError("evidence references must be deterministically ordered")
        return self


class EvidenceRequirementResult(GovernanceModel):
    requirement_id: str
    category: EvidenceCategory
    outcome: RequirementOutcome
    matched_evidence_ids: list[str]
    policy_evidence: list[str]
    blocking: bool
    reviewable: bool
    limitations: list[str]
    reason: str


class DecisionReason(GovernanceModel):
    code: str = Field(pattern=r"^GOV-[0-9]{3}$")
    summary: str
    blocking: bool
    requirement_id: str | None = None


class MissingEvidenceItem(GovernanceModel):
    requirement_id: str
    category: EvidenceCategory
    current_status: RequirementOutcome
    required_status: str
    severity: str
    blocking: bool
    source_phase: str
    remediation: str
    decision_impact: str
    promotion_impact: str
    outside_current_phase: bool


class MissingEvidenceAnalysis(GovernanceModel):
    items: list[MissingEvidenceItem]


class PolicyEvaluationResult(GovernanceModel):
    schema_id: Literal["omiv.policy-evaluation.v1"] = Field(
        default="omiv.policy-evaluation.v1", alias="schema"
    )
    subject_id: str
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context_id: str | None
    requirement_results: list[EvidenceRequirementResult]
    outcome: DecisionOutcome
    reasons: list[DecisionReason]
    blockers: list[str]
    limitations: list[str]
    missing_evidence: MissingEvidenceAnalysis
    result_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_result(self) -> PolicyEvaluationResult:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("result_digest")
        if self.result_digest != canonical_sha256(body):
            raise ValueError("policy evaluation digest mismatch")
        return self


class PolicyDecisionRecord(GovernanceModel):
    schema_id: Literal["omiv.policy-decision-record.v1"] = Field(
        default="omiv.policy-decision-record.v1", alias="schema"
    )
    decision_id: str = Field(pattern=r"^decision_[0-9a-f]{32}$")
    subject: GovernanceSubject
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context_id: str | None
    evaluation_result_digest: str = Field(pattern=SHA256_PATTERN)
    requirement_results: list[EvidenceRequirementResult]
    decision_outcome: DecisionOutcome
    decision_reasons: list[DecisionReason]
    blocking_findings: list[str]
    limitations: list[str]
    missing_evidence: MissingEvidenceAnalysis
    next_required_actions: list[str]
    trust_summary: str
    approval_status: str
    separation_of_duties_status: str
    promotion_eligibility: str
    decision_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_decision(self) -> PolicyDecisionRecord:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("decision_digest")
        expected_id = (
            "decision_"
            + canonical_sha256({k: v for k, v in body.items() if k != "decision_id"})[:32]
        )
        if self.decision_id != expected_id or self.decision_digest != canonical_sha256(body):
            raise ValueError("policy decision identity or digest mismatch")
        return self


class ApprovalRequest(GovernanceModel):
    schema_id: Literal["omiv.approval-request.v1"] = Field(
        default="omiv.approval-request.v1", alias="schema"
    )
    approval_request_id: str = Field(pattern=r"^approval_request_[0-9a-f]{32}$")
    subject: GovernanceSubject
    requested_action: ApprovalAction
    requested_target_id: str | None
    requested_scope: str
    requester_role: GovernanceRole
    requester: ApprovalActorReference
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    approval_policy_id: str
    approval_policy_digest: str = Field(pattern=SHA256_PATTERN)
    decision_id: str
    decision_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_ids: list[str]
    requested_approver_roles: list[GovernanceRole]
    quorum_id: str
    limitations: list[str]
    request_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_request(self) -> ApprovalRequest:
        if self.requested_action in {
            ApprovalAction.APPROVE_EXCEPTION_RESERVED,
            ApprovalAction.APPROVE_DEPLOYMENT_RESERVED,
        }:
            raise ValueError("reserved approval action is not operational in Phase 5E")
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("request_digest")
        identity = {k: v for k, v in body.items() if k != "approval_request_id"}
        if self.approval_request_id != "approval_request_" + canonical_sha256(identity)[:32]:
            raise ValueError("approval request identity mismatch")
        if self.request_digest != canonical_sha256(body):
            raise ValueError("approval request digest mismatch")
        return self


class ApprovalRequestCreateInput(GovernanceModel):
    schema_id: Literal["omiv.approval-request-input.v1"] = Field(
        default="omiv.approval-request-input.v1", alias="schema"
    )
    requested_action: ApprovalAction
    requested_target_id: str | None
    requested_scope: str
    requester_role: GovernanceRole
    requester: ApprovalActorReference
    evidence_ids: list[str]


class SignedDecisionLinkage(GovernanceModel):
    envelope_id: str
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    signature_id: str
    signature_digest: str = Field(pattern=SHA256_PATTERN)
    signature_integrity: Literal["VALID", "INVALID", "UNVERIFIED"]
    trust_status: Literal["TRUSTED_BY_POLICY", "PARTIALLY_TRUSTED", "UNTRUSTED_BY_POLICY"]
    purpose: Literal["POLICY_DECISION_ISSUANCE", "PROMOTION_DECISION_ISSUANCE"]


class SignedApprovalLinkage(GovernanceModel):
    envelope_id: str
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    signature_id: str
    signature_digest: str = Field(pattern=SHA256_PATTERN)
    signature_integrity: Literal["VALID", "INVALID", "UNVERIFIED"]
    trust_status: Literal["TRUSTED_BY_POLICY", "PARTIALLY_TRUSTED", "UNTRUSTED_BY_POLICY"]
    binding_status: str
    purpose: Literal["APPROVAL_RECORD_ISSUANCE", "REJECTION_RECORD_ISSUANCE"]


class ApprovalRecord(GovernanceModel):
    schema_id: Literal["omiv.approval-record.v1"] = Field(
        default="omiv.approval-record.v1", alias="schema"
    )
    approval_id: str = Field(pattern=r"^approval_[0-9a-f]{32}$")
    approval_request_id: str
    request_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str
    artifact_digest: str = Field(pattern=SHA256_PATTERN)
    approver_role: GovernanceRole
    approver: ApprovalActorReference
    outcome: ApprovalOutcome
    scope: str
    conditions: list[str]
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_ids: list[str]
    validity_not_after: str | None
    limitations: list[str]
    approval_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_approval(self) -> ApprovalRecord:
        if self.validity_not_after is not None and not UTC_PATTERN.fullmatch(
            self.validity_not_after
        ):
            raise ValueError("approval expiration must be fixed-width UTC")
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("approval_digest")
        identity = {k: v for k, v in body.items() if k != "approval_id"}
        if self.approval_id != "approval_" + canonical_sha256(identity)[:32]:
            raise ValueError("approval identity mismatch")
        if self.approval_digest != canonical_sha256(body):
            raise ValueError("approval digest mismatch")
        return self


class ApprovalCreateInput(GovernanceModel):
    schema_id: Literal["omiv.approval-input.v1"] = Field(
        default="omiv.approval-input.v1", alias="schema"
    )
    approver_role: GovernanceRole
    approver: ApprovalActorReference
    outcome: ApprovalOutcome
    scope: str
    conditions: list[str]
    evidence_ids: list[str]
    validity_not_after: str | None


class RejectionRecord(GovernanceModel):
    schema_id: Literal["omiv.rejection-record.v1"] = Field(
        default="omiv.rejection-record.v1", alias="schema"
    )
    rejection_id: str = Field(pattern=r"^rejection_[0-9a-f]{32}$")
    approval_request_id: str
    request_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str
    rejecting_role: GovernanceRole
    rejecting_actor: ApprovalActorReference
    scope: str
    reasons: list[str] = Field(min_length=1)
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_ids: list[str]
    limitations: list[str]
    rejection_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_rejection(self) -> RejectionRecord:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("rejection_digest")
        identity = {k: v for k, v in body.items() if k != "rejection_id"}
        if self.rejection_id != "rejection_" + canonical_sha256(identity)[:32]:
            raise ValueError("rejection identity mismatch")
        if self.rejection_digest != canonical_sha256(body):
            raise ValueError("rejection digest mismatch")
        return self


class SeparationOfDutiesResult(GovernanceModel):
    separation_policy_id: str
    outcome: SeparationOutcome
    evaluated_dimensions: list[IndependenceDimension]
    violations: list[str]
    limitations: list[str]
    result_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_result(self) -> SeparationOfDutiesResult:
        body = self.model_dump(mode="json")
        body.pop("result_digest")
        if self.result_digest != canonical_sha256(body):
            raise ValueError("separation result digest mismatch")
        return self


class ApprovalQuorumResult(GovernanceModel):
    quorum_id: str
    outcome: QuorumOutcome
    counted_approval_ids: list[str]
    rejected_record_ids: list[str]
    distinct_signers: int = Field(ge=0)
    distinct_keys: int = Field(ge=0)
    distinct_trust_roots: int = Field(ge=0)
    satisfied_roles: list[GovernanceRole]
    limitations: list[str]
    result_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_result(self) -> ApprovalQuorumResult:
        body = self.model_dump(mode="json")
        body.pop("result_digest")
        if self.result_digest != canonical_sha256(body):
            raise ValueError("quorum result digest mismatch")
        return self


class PromotionTarget(GovernanceModel):
    schema_id: Literal["omiv.promotion-target.v1"] = Field(
        default="omiv.promotion-target.v1", alias="schema"
    )
    target_id: str = Field(pattern=r"^target_[0-9a-f]{32}$")
    target_type: PromotionTargetType
    logical_namespace: str
    environment_class: str
    provider_reference: str | None
    target_policy_id: str
    accepted_formats: list[str]
    required_decision_outcomes: list[DecisionOutcome]
    required_approval_policy_id: str | None
    limitations: list[str]
    target_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_target(self) -> PromotionTarget:
        if self.target_type == PromotionTargetType.DEPLOYMENT_REGISTRY_RESERVED:
            raise ValueError("deployment registry target is reserved in Phase 5E")
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("target_digest")
        identity = {k: v for k, v in body.items() if k != "target_id"}
        if self.target_id != "target_" + canonical_sha256(identity)[:32]:
            raise ValueError("promotion target identity mismatch")
        if self.target_digest != canonical_sha256(body):
            raise ValueError("promotion target digest mismatch")
        return self


class PromotionGatePolicy(GovernanceModel):
    schema_id: Literal["omiv.promotion-gate-policy.v1"] = Field(
        default="omiv.promotion-gate-policy.v1", alias="schema"
    )
    gate_policy_id: str = Field(pattern=r"^promotion_gate_[0-9a-f]{32}$")
    permitted_target_types: list[PromotionTargetType]
    accepted_decision_outcomes: list[DecisionOutcome]
    require_quorum: bool
    require_separation_of_duties: bool
    require_trusted_decision_signature: bool
    require_security_evidence: bool
    require_revocation_evaluation: bool
    require_expiration_evaluation: bool
    allow_conditions: bool
    gate_policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_gate(self) -> PromotionGatePolicy:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("gate_policy_digest")
        identity = {k: v for k, v in body.items() if k != "gate_policy_id"}
        if self.gate_policy_id != "promotion_gate_" + canonical_sha256(identity)[:32]:
            raise ValueError("promotion gate identity mismatch")
        if self.gate_policy_digest != canonical_sha256(body):
            raise ValueError("promotion gate digest mismatch")
        return self


class PromotionGateResult(GovernanceModel):
    gate_policy_id: str
    target_id: str
    outcome: PromotionOutcome
    blockers: list[str]
    conditions: list[str]
    missing_evidence: list[EvidenceCategory]
    limitations: list[str]
    result_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_result(self) -> PromotionGateResult:
        body = self.model_dump(mode="json")
        body.pop("result_digest")
        if self.result_digest != canonical_sha256(body):
            raise ValueError("promotion gate result digest mismatch")
        return self


class ReleaseCandidate(GovernanceModel):
    schema_id: Literal["omiv.release-candidate.v1"] = Field(
        default="omiv.release-candidate.v1", alias="schema"
    )
    candidate_id: str = Field(pattern=r"^candidate_[0-9a-f]{32}$")
    subject: GovernanceSubject
    passport_reference: EvidenceReference | None
    custody_reference: EvidenceReference | None
    evidence_references: list[EvidenceReference]
    attestation_references: list[EvidenceReference]
    signed_evidence_references: list[EvidenceReference]
    decision_id: str
    decision_digest: str = Field(pattern=SHA256_PATTERN)
    target_id: str
    approval_request_id: str | None
    approval_policy_id: str | None
    approval_record_ids: list[str]
    limitations: list[str]
    candidate_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_candidate(self) -> ReleaseCandidate:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("candidate_digest")
        identity = {k: v for k, v in body.items() if k != "candidate_id"}
        if self.candidate_id != "candidate_" + canonical_sha256(identity)[:32]:
            raise ValueError("release candidate identity mismatch")
        if self.candidate_digest != canonical_sha256(body):
            raise ValueError("release candidate digest mismatch")
        return self


class PromotionDecisionRecord(GovernanceModel):
    schema_id: Literal["omiv.promotion-decision-record.v1"] = Field(
        default="omiv.promotion-decision-record.v1", alias="schema"
    )
    promotion_decision_id: str = Field(pattern=r"^promotion_[0-9a-f]{32}$")
    candidate_id: str
    candidate_digest: str = Field(pattern=SHA256_PATTERN)
    target_id: str
    target_digest: str = Field(pattern=SHA256_PATTERN)
    gate_policy_id: str
    gate_policy_digest: str = Field(pattern=SHA256_PATTERN)
    gate_result: PromotionGateResult
    policy_decision_id: str
    policy_decision_digest: str = Field(pattern=SHA256_PATTERN)
    quorum_result: ApprovalQuorumResult | None
    separation_result: SeparationOfDutiesResult | None
    trust_summary: str
    conditions: list[str]
    blockers: list[str]
    missing_evidence: list[EvidenceCategory]
    security_status: Literal["NOT_CHECKED", "MISSING"]
    promotion_performed: Literal["NO"] = "NO"
    registry_write: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    deployment_status: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    runtime_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    limitations: list[str]
    promotion_decision_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_decision(self) -> PromotionDecisionRecord:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("promotion_decision_digest")
        identity = {k: v for k, v in body.items() if k != "promotion_decision_id"}
        if self.promotion_decision_id != "promotion_" + canonical_sha256(identity)[:32]:
            raise ValueError("promotion decision identity mismatch")
        if self.promotion_decision_digest != canonical_sha256(body):
            raise ValueError("promotion decision digest mismatch")
        return self


class PassportGovernanceSummary(GovernanceModel):
    schema_id: Literal["omiv.passport-governance-summary.v1"] = Field(
        default="omiv.passport-governance-summary.v1", alias="schema"
    )
    passport_id: str
    passport_digest: str = Field(pattern=SHA256_PATTERN)
    decision_id: str
    decision_outcome: DecisionOutcome
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    approval_scope: str
    quorum_status: QuorumOutcome | None
    separation_status: SeparationOutcome | None
    promotion_eligibility: str
    target_id: str | None
    blockers: list[str]
    missing_evidence: list[EvidenceCategory]
    signed_decision_status: str
    signed_approval_status: str
    security_status: Literal["NOT_CHECKED", "MISSING"]
    deployment_status: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    runtime_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    limitations: list[str]
    summary_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_summary(self) -> PassportGovernanceSummary:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("summary_digest")
        if self.summary_digest != canonical_sha256(body):
            raise ValueError("Passport governance summary digest mismatch")
        return self


class CustodyGovernanceLinkage(GovernanceModel):
    schema_id: Literal["omiv.custody-governance-linkage.v1"] = Field(
        default="omiv.custody-governance-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=r"^custody_governance_[0-9a-f]{32}$")
    custody_ledger_id: str
    custody_ledger_digest: str = Field(pattern=SHA256_PATTERN)
    event_type: Literal[
        "POLICY_DECISION_RECORDED",
        "APPROVAL_RECORDED",
        "REJECTION_RECORDED",
        "PROMOTION_AUTHORIZED",
        "PROMOTION_DENIED",
    ]
    governance_object_id: str
    governance_object_digest: str = Field(pattern=SHA256_PATTERN)
    lifecycle_completeness: Literal["UNCHANGED_INCOMPLETE", "UNCHANGED_NOT_ASSESSED"]
    limitations: list[str]
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_linkage(self) -> CustodyGovernanceLinkage:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("linkage_digest")
        identity = {k: v for k, v in body.items() if k != "linkage_id"}
        if self.linkage_id != "custody_governance_" + canonical_sha256(identity)[:32]:
            raise ValueError("custody governance linkage identity mismatch")
        if self.linkage_digest != canonical_sha256(body):
            raise ValueError("custody governance linkage digest mismatch")
        return self


class GovernanceReport(GovernanceModel):
    schema_id: Literal["omiv.governance-report.v1"] = Field(
        default="omiv.governance-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^governance_report_[0-9a-f]{32}$")
    subject: GovernanceSubject
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    decision_id: str
    decision_digest: str = Field(pattern=SHA256_PATTERN)
    decision_outcome: DecisionOutcome
    requirement_results: list[EvidenceRequirementResult]
    approval_request_id: str | None
    approval_record_ids: list[str]
    rejection_record_ids: list[str]
    quorum_result: ApprovalQuorumResult | None
    separation_result: SeparationOfDutiesResult | None
    promotion_target_id: str | None
    promotion_outcome: PromotionOutcome | None
    promotion_conditions: list[str]
    blockers: list[str]
    limitations: list[str]
    missing_evidence: MissingEvidenceAnalysis
    next_actions: list[str]
    security_status: Literal["NOT_CHECKED", "MISSING"]
    promotion_performed: Literal["NO"] = "NO"
    registry_write: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    deployment_status: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    runtime_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid_report(self) -> GovernanceReport:
        body = self.model_dump(mode="json", by_alias=True)
        body.pop("report_digest")
        identity = {k: v for k, v in body.items() if k != "report_id"}
        if self.report_id != "governance_report_" + canonical_sha256(identity)[:32]:
            raise ValueError("governance report identity mismatch")
        if self.report_digest != canonical_sha256(body):
            raise ValueError("governance report digest mismatch")
        return self


GovernanceSignedObject = Annotated[
    PolicyDecisionRecord
    | ApprovalRecord
    | RejectionRecord
    | ReleaseCandidate
    | PromotionDecisionRecord,
    Field(discriminator="schema_id"),
]
