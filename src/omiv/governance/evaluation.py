"""Deterministic evidence, approval, duty-separation, and promotion evaluation."""

from __future__ import annotations

from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.governance.models import (
    ApprovalAction,
    ApprovalActorReference,
    ApprovalOutcome,
    ApprovalPolicy,
    ApprovalQuorum,
    ApprovalQuorumResult,
    ApprovalRecord,
    ApprovalRequest,
    DecisionOutcome,
    DecisionReason,
    EvidenceCategory,
    EvidenceReference,
    EvidenceRequirement,
    EvidenceRequirementResult,
    EvidenceRequirementSet,
    GovernanceEvaluationContext,
    GovernancePolicy,
    GovernanceReport,
    GovernanceRole,
    GovernanceSubject,
    IdentityTrust,
    IndependenceDimension,
    MissingEvidenceItem,
    PolicyDecisionRecord,
    PolicyEvaluationInput,
    PolicyEvaluationResult,
    PromotionDecisionRecord,
    PromotionGatePolicy,
    PromotionGateResult,
    PromotionOutcome,
    PromotionTarget,
    PromotionTargetType,
    QuorumOutcome,
    ReferenceAvailability,
    RejectionRecord,
    ReleaseCandidate,
    RequirementOutcome,
    RoleAssignment,
    SeparationOfDutiesPolicy,
    SeparationOfDutiesResult,
    SeparationOutcome,
    SignedApprovalLinkage,
    VerificationMode,
)

PRECEDENCE = [
    DecisionOutcome.POLICY_INVALID,
    DecisionOutcome.EVIDENCE_BROKEN,
    DecisionOutcome.DENY,
    DecisionOutcome.NOT_EVALUATED,
    DecisionOutcome.REVIEW_REQUIRED,
    DecisionOutcome.ALLOW_WITH_LIMITATIONS,
    DecisionOutcome.ALLOW,
]

# These categories are modelled so policies can fail closed, but Phase 5E has no
# verifier capable of accepting evidence from their future implementation phases.
RESERVED_FUTURE_EVIDENCE = {
    EvidenceCategory.PAYLOAD_INTEGRITY,
    EvidenceCategory.QUANTIZATION_FIDELITY,
    EvidenceCategory.TOKENIZER_PARITY,
}


def _identified(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    identity = dict(body)
    identity[id_field] = prefix + canonical_sha256(body)[:32]
    return {**identity, digest_field: canonical_sha256(identity)}


def _digest_record(model: Any, digest_field: str) -> str:
    body = model.model_dump(mode="json", by_alias=True)
    body.pop(digest_field, None)
    return canonical_sha256(body)


def build_subject(
    *,
    artifact_digest: str,
    artifact_format: str,
    origin_type: str,
    logical_locator: str,
    variant: str,
    artifact_set_digest: str | None = None,
    provider: str | None = None,
    immutable_revision: str | None = None,
) -> GovernanceSubject:
    body = {
        "artifact_digest": artifact_digest,
        "artifact_set_digest": artifact_set_digest,
        "artifact_format": artifact_format,
        "origin_type": origin_type,
        "provider": provider,
        "logical_locator": logical_locator,
        "immutable_revision": immutable_revision,
        "variant": variant,
    }
    return GovernanceSubject.model_validate(
        {"subject_id": "subject_" + canonical_sha256(body)[:32], **body}
    )


def build_requirement(
    category: EvidenceCategory,
    *,
    accepted_schemas: list[str],
    required_object_types: list[str] | None = None,
    accepted_verification_modes: list[VerificationMode] | None = None,
    accepted_trust_statuses: list[str] | None = None,
    minimum_freshness_seconds: int | None = None,
    minimum_signature_count: int = 0,
    required_signer_roles: list[GovernanceRole] | None = None,
    required_provenance_strength: str | None = None,
    required_custody_status: str | None = None,
    required_lifecycle_events: list[str] | None = None,
    optional: bool = False,
    allow_with_limitations: bool = False,
    reviewable: bool = False,
    not_applicable_policy_evidence: list[str] | None = None,
    failure_severity: str = "BLOCKING",
    remediation: str = "Supply verified evidence for this requirement.",
    source_phase: str = "5E",
) -> EvidenceRequirement:
    body: dict[str, Any] = {
        "schema": "omiv.evidence-requirement.v1",
        "category": category.value,
        "required_object_types": sorted(required_object_types or []),
        "accepted_schemas": sorted(accepted_schemas),
        "accepted_verification_modes": sorted(
            item.value for item in (accepted_verification_modes or [VerificationMode.FULL])
        ),
        "accepted_trust_statuses": sorted(accepted_trust_statuses or []),
        "minimum_freshness_seconds": minimum_freshness_seconds,
        "minimum_signature_count": minimum_signature_count,
        "required_signer_roles": sorted((required_signer_roles or []), key=lambda item: item.value),
        "required_provenance_strength": required_provenance_strength,
        "required_custody_status": required_custody_status,
        "required_lifecycle_events": sorted(required_lifecycle_events or []),
        "optional": optional,
        "allow_with_limitations": allow_with_limitations,
        "reviewable": reviewable,
        "not_applicable_policy_evidence": sorted(not_applicable_policy_evidence or []),
        "failure_severity": failure_severity,
        "remediation": remediation,
        "source_phase": source_phase,
    }
    with_id = {**body, "requirement_id": "requirement_" + canonical_sha256(body)[:32]}
    return EvidenceRequirement.model_validate(
        {**with_id, "requirement_digest": canonical_sha256(with_id)}
    )


def build_requirement_set(requirements: list[EvidenceRequirement]) -> EvidenceRequirementSet:
    ordered = sorted(requirements, key=lambda item: item.requirement_id)
    body = {
        "schema": "omiv.evidence-requirement-set.v1",
        "requirements": [item.model_dump(mode="json", by_alias=True) for item in ordered],
    }
    with_id = {
        **body,
        "requirement_set_id": "requirement_set_" + canonical_sha256(body)[:32],
    }
    return EvidenceRequirementSet.model_validate(
        {**with_id, "requirement_set_digest": canonical_sha256(with_id)}
    )


def build_evaluation_context(
    policy_id: str, policy_digest: str, evaluation_time: str | None
) -> GovernanceEvaluationContext:
    base = {
        "evaluation_time": evaluation_time,
        "policy_id": policy_id,
        "policy_digest": policy_digest,
    }
    with_id = {**base, "context_id": "gov_eval_" + canonical_sha256(base)[:32]}
    return GovernanceEvaluationContext.model_validate(
        {**with_id, "context_digest": canonical_sha256(with_id)}
    )


def build_quorum(
    *,
    minimum_count: int,
    required_roles: list[GovernanceRole] | None = None,
    minimum_distinct_signers: int = 0,
    minimum_distinct_keys: int = 0,
    minimum_distinct_trust_roots: int = 0,
    rejection_blocks: bool = True,
    abstentions_count: bool = False,
    conditional_approvals_count: bool = True,
    unanimous: bool = False,
) -> ApprovalQuorum:
    body = {
        "minimum_count": minimum_count,
        "required_roles": sorted(required_roles or [], key=lambda item: item.value),
        "minimum_distinct_signers": minimum_distinct_signers,
        "minimum_distinct_keys": minimum_distinct_keys,
        "minimum_distinct_trust_roots": minimum_distinct_trust_roots,
        "rejection_blocks": rejection_blocks,
        "abstentions_count": abstentions_count,
        "conditional_approvals_count": conditional_approvals_count,
        "unanimous": unanimous,
    }
    return ApprovalQuorum.model_validate(_identified(body, "quorum_id", "quorum_", "quorum_digest"))


def build_approval_policy(
    action: ApprovalAction,
    quorum: ApprovalQuorum,
    *,
    permitted_roles: list[GovernanceRole],
    require_signed_approval: bool,
    accepted_identity_trust: list[IdentityTrust] | None = None,
) -> ApprovalPolicy:
    body = {
        "schema": "omiv.approval-policy.v1",
        "requested_action": action.value,
        "permitted_roles": sorted(permitted_roles, key=lambda item: item.value),
        "require_signed_approval": require_signed_approval,
        "accepted_identity_trust": sorted(
            accepted_identity_trust or [IdentityTrust.TRUSTED_BY_POLICY],
            key=lambda item: item.value,
        ),
        "quorum": quorum.model_dump(mode="json"),
    }
    return ApprovalPolicy.model_validate(
        _identified(body, "approval_policy_id", "approval_policy_", "approval_policy_digest")
    )


def build_separation_policy(
    *,
    requester_must_not_approve: bool = True,
    producer_must_not_be_sole_validator: bool = True,
    transformer_must_not_approve: bool = True,
    validator_must_not_promote: bool = True,
    promoter_must_not_approve_request: bool = True,
    required_independence: list[IndependenceDimension] | None = None,
    delegates_under_same_root_independent: bool = False,
) -> SeparationOfDutiesPolicy:
    body = {
        "schema": "omiv.separation-of-duties-policy.v1",
        "requester_must_not_approve": requester_must_not_approve,
        "producer_must_not_be_sole_validator": producer_must_not_be_sole_validator,
        "transformer_must_not_approve": transformer_must_not_approve,
        "validator_must_not_promote": validator_must_not_promote,
        "promoter_must_not_approve_request": promoter_must_not_approve_request,
        "required_independence": sorted(
            required_independence or [IndependenceDimension.DISTINCT_SIGNER_IDENTITY],
            key=lambda item: item.value,
        ),
        "delegates_under_same_root_independent": delegates_under_same_root_independent,
    }
    return SeparationOfDutiesPolicy.model_validate(
        _identified(
            body,
            "separation_policy_id",
            "separation_policy_",
            "separation_policy_digest",
        )
    )


def build_governance_policy(
    profile: str,
    requirement_set: EvidenceRequirementSet,
    *,
    accepted_formats: list[str],
    accepted_origin_types: list[str],
    trust_policy_ids: list[str] | None = None,
    approval_policy: ApprovalPolicy | None = None,
    separation_policy: SeparationOfDutiesPolicy | None = None,
    allowed_target_types: list[PromotionTargetType] | None = None,
    missing_evidence_behavior: str = "DENY",
    stale_evidence_behavior: str = "DENY",
    require_evaluation_time: bool = False,
    require_revocation_evaluation: bool = False,
    require_expiration_evaluation: bool = False,
) -> GovernancePolicy:
    policy_id = f"omiv.governance-policy.{profile}.v1"
    body: dict[str, Any] = {
        "schema": "omiv.governance-policy.v1",
        "policy_id": policy_id,
        "version": 1,
        "profile": profile,
        "accepted_formats": sorted(accepted_formats),
        "accepted_origin_types": sorted(accepted_origin_types),
        "requirement_set": requirement_set.model_dump(mode="json", by_alias=True),
        "trust_policy_ids": sorted(trust_policy_ids or []),
        "approval_policy": (
            approval_policy.model_dump(mode="json", by_alias=True) if approval_policy else None
        ),
        "separation_of_duties_policy": (
            separation_policy.model_dump(mode="json", by_alias=True) if separation_policy else None
        ),
        "allowed_target_types": sorted((allowed_target_types or []), key=lambda item: item.value),
        "missing_evidence_behavior": missing_evidence_behavior,
        "stale_evidence_behavior": stale_evidence_behavior,
        "require_evaluation_time": require_evaluation_time,
        "require_revocation_evaluation": require_revocation_evaluation,
        "require_expiration_evaluation": require_expiration_evaluation,
        "decision_precedence": [item.value for item in PRECEDENCE],
        "limitations": [
            "Policy satisfaction does not independently prove underlying claims.",
            "Policy evaluation does not prove security, deployment, or runtime state.",
        ],
    }
    return GovernancePolicy.model_validate({**body, "policy_digest": canonical_sha256(body)})


def build_evaluation_input(
    subject: GovernanceSubject,
    policy: GovernancePolicy,
    evidence: list[EvidenceReference],
    *,
    context: GovernanceEvaluationContext | None = None,
    role_assignments: list[RoleAssignment] | None = None,
    approval_request_ids: list[str] | None = None,
    approval_record_ids: list[str] | None = None,
    promotion_target_id: str | None = None,
) -> PolicyEvaluationInput:
    if any(item.subject_id != subject.subject_id for item in evidence):
        raise OmivInputError("evidence reference is bound to a different governance subject")
    return PolicyEvaluationInput(
        subject=subject,
        policy_id=policy.policy_id,
        policy_digest=policy.policy_digest,
        evaluation_context=context,
        evidence=sorted(evidence, key=lambda item: item.evidence_id),
        role_assignments=sorted(role_assignments or [], key=lambda item: item.assignment_id),
        approval_request_ids=sorted(approval_request_ids or []),
        approval_record_ids=sorted(approval_record_ids or []),
        promotion_target_id=promotion_target_id,
    )


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _evaluate_requirement(
    requirement: EvidenceRequirement,
    supplied: list[EvidenceReference],
    context: GovernanceEvaluationContext | None,
    policy_id: str,
) -> EvidenceRequirementResult:
    matches = [item for item in supplied if item.category == requirement.category]
    not_applicable = [
        item
        for item in matches
        if item.object_id in requirement.not_applicable_policy_evidence
        and item.schema_id == "omiv.not-applicable-evidence.v1"
        and item.verification_mode == VerificationMode.FULL
        and item.governance_policy_id == policy_id
    ]
    if not_applicable:
        outcome = RequirementOutcome.NOT_APPLICABLE
        reason = "Explicit policy evidence establishes that the requirement is not applicable."
        policy_evidence = sorted(item.evidence_id for item in not_applicable)
        accepted: list[EvidenceReference] = []
    elif not matches:
        outcome = (
            RequirementOutcome.NOT_CHECKED if requirement.optional else RequirementOutcome.MISSING
        )
        reason = "No evidence reference was supplied for this requirement."
        policy_evidence = []
        accepted = []
    elif requirement.category in RESERVED_FUTURE_EVIDENCE:
        outcome = RequirementOutcome.UNAVAILABLE
        reason = (
            "This evidence category has no operational verifier in Phase 5E; "
            "caller-declared future evidence cannot satisfy it."
        )
        policy_evidence = []
        accepted = []
    elif requirement.category == EvidenceCategory.SECURITY_INSPECTION and not any(
        item.schema_id == "omiv.artifact-security-evidence.v1"
        and item.object_id.startswith("security_eval_")
        and len(item.object_id) == len("security_eval_") + 32
        and item.governance_policy_id is not None
        and item.governance_policy_id.startswith("omiv.security-policy.")
        and item.verification_mode == VerificationMode.FULL
        for item in matches
    ):
        outcome = RequirementOutcome.UNAVAILABLE
        reason = (
            "Security evidence was not produced by the strict Phase 5F governance adapter; "
            "declarations and approvals cannot satisfy it."
        )
        policy_evidence = []
        accepted = []
    elif requirement.category in {
        EvidenceCategory.DEPLOYMENT,
        EvidenceCategory.RUNTIME_OBSERVATION,
    } and not any(
        item.schema_id == "omiv.deployment-runtime-evidence.v1"
        and item.object_id.startswith("runtime_evaluation_")
        and len(item.object_id) == len("runtime_evaluation_") + 32
        and item.governance_policy_id is not None
        and item.governance_policy_id.startswith("omiv.continuity-policy.")
        and item.verification_mode == VerificationMode.FULL
        and item.source_phase == "5G"
        for item in matches
    ):
        outcome = RequirementOutcome.UNAVAILABLE
        reason = (
            "Deployment/runtime evidence was not produced by the strict Phase 5G "
            "governance adapter; declarations, manifests, approvals, and signatures "
            "cannot satisfy it."
        )
        policy_evidence = []
        accepted = []
    else:
        policy_evidence = []
        accepted = [
            item
            for item in matches
            if (not requirement.accepted_schemas or item.schema_id in requirement.accepted_schemas)
            and item.verification_mode in requirement.accepted_verification_modes
            and (
                not requirement.accepted_trust_statuses
                or item.trust_status in requirement.accepted_trust_statuses
            )
            and (
                not requirement.required_signer_roles
                or set(requirement.required_signer_roles).issubset(item.signer_roles)
            )
            and (
                requirement.required_provenance_strength is None
                or item.provenance_strength == requirement.required_provenance_strength
            )
            and (
                requirement.required_custody_status is None
                or item.custody_status == requirement.required_custody_status
            )
            and set(requirement.required_lifecycle_events).issubset(item.lifecycle_events)
        ]
        if any(item.availability == ReferenceAvailability.UNAVAILABLE for item in matches):
            outcome = RequirementOutcome.UNAVAILABLE
            reason = "Referenced evidence is explicitly unavailable."
        elif any(item.trust_status == "BROKEN" for item in matches):
            outcome = RequirementOutcome.BROKEN
            reason = "Evidence linkage or reconstructed trust state is broken."
        elif any(item.trust_status in {"INVALID", "REVOKED", "EXPIRED"} for item in matches):
            outcome = RequirementOutcome.INVALID
            reason = "Evidence or required trust state is invalid, revoked, or expired."
        elif not accepted:
            outcome = RequirementOutcome.INVALID
            reason = "Supplied evidence does not meet the requirement constraints."
        elif requirement.minimum_signature_count > len(accepted):
            outcome = RequirementOutcome.INVALID
            reason = "Accepted evidence does not meet the required signature count."
        elif requirement.minimum_freshness_seconds is not None:
            if context is None or context.evaluation_time is None:
                outcome = RequirementOutcome.NOT_EVALUATED
                reason = "Freshness requires an explicit evaluation time."
            elif any(item.observed_at is None for item in accepted):
                outcome = RequirementOutcome.NOT_EVALUATED
                reason = "Freshness metadata is unavailable."
            elif any(
                (_time(context.evaluation_time) - _time(item.observed_at or "")).total_seconds()
                > requirement.minimum_freshness_seconds
                for item in accepted
            ):
                outcome = RequirementOutcome.STALE
                reason = "Evidence falls outside the policy freshness interval."
            else:
                outcome = RequirementOutcome.SATISFIED
                reason = "Evidence satisfies the requirement and freshness interval."
        elif any(item.limitations for item in accepted):
            outcome = RequirementOutcome.SATISFIED_WITH_LIMITATIONS
            reason = "Evidence satisfies the requirement with explicit limitations."
        else:
            outcome = RequirementOutcome.SATISFIED
            reason = "Evidence satisfies the requirement."
    blocking = (
        not requirement.optional
        and not (
            outcome == RequirementOutcome.SATISFIED_WITH_LIMITATIONS
            and requirement.allow_with_limitations
        )
        and outcome
        not in {
            RequirementOutcome.SATISFIED,
            RequirementOutcome.NOT_APPLICABLE,
        }
        and (requirement.failure_severity == "BLOCKING" or not requirement.reviewable)
    )
    limitations = sorted({limit for item in accepted for limit in item.limitations})
    if outcome == RequirementOutcome.SATISFIED_WITH_LIMITATIONS and not limitations:
        limitations = ["Requirement is satisfied only within policy-declared limitations."]
    return EvidenceRequirementResult(
        requirement_id=requirement.requirement_id,
        category=requirement.category,
        outcome=outcome,
        matched_evidence_ids=sorted(item.evidence_id for item in accepted),
        policy_evidence=policy_evidence,
        blocking=blocking,
        reviewable=requirement.reviewable,
        limitations=limitations,
        reason=reason,
    )


def evaluate_policy(
    value: PolicyEvaluationInput, policy: GovernancePolicy
) -> PolicyEvaluationResult:
    """Reconstruct policy outcome; callers cannot supply or override it."""
    if value.policy_id != policy.policy_id or value.policy_digest != policy.policy_digest:
        raise OmivInputError("evaluation input references a different governance policy")
    if value.subject.artifact_format not in policy.accepted_formats:
        raise OmivInputError("subject format is not accepted by governance policy")
    if value.subject.origin_type not in policy.accepted_origin_types:
        raise OmivInputError("subject origin type is not accepted by governance policy")
    context = value.evaluation_context
    if context is not None and (
        context.policy_id != policy.policy_id or context.policy_digest != policy.policy_digest
    ):
        raise OmivInputError("governance evaluation context references a different policy")
    results = [
        _evaluate_requirement(item, value.evidence, context, policy.policy_id)
        for item in policy.requirement_set.requirements
    ]
    missing_items: list[MissingEvidenceItem] = []
    requirements_by_id = {item.requirement_id: item for item in policy.requirement_set.requirements}
    for result in results:
        if result.outcome in {
            RequirementOutcome.SATISFIED,
            RequirementOutcome.SATISFIED_WITH_LIMITATIONS,
            RequirementOutcome.NOT_APPLICABLE,
        }:
            continue
        requirement = requirements_by_id[result.requirement_id]
        missing_items.append(
            MissingEvidenceItem(
                requirement_id=result.requirement_id,
                category=result.category,
                current_status=result.outcome,
                required_status="SATISFIED",
                severity=requirement.failure_severity,
                blocking=result.blocking,
                source_phase=requirement.source_phase,
                remediation=requirement.remediation,
                decision_impact="Blocks policy outcome"
                if result.blocking
                else "Limits or requires review",
                promotion_impact="Blocks promotion"
                if result.blocking
                else "Requires target review",
                outside_current_phase=requirement.source_phase in {"5F", "5G", "5H"},
            )
        )
    if policy.require_evaluation_time and (context is None or context.evaluation_time is None):
        outcome = DecisionOutcome.NOT_EVALUATED
    elif any(item.outcome == RequirementOutcome.BROKEN for item in results):
        outcome = DecisionOutcome.EVIDENCE_BROKEN
    elif any(item.blocking for item in results):
        outcome = DecisionOutcome.DENY
    elif any(
        item.outcome == RequirementOutcome.NOT_EVALUATED
        and not requirements_by_id[item.requirement_id].optional
        for item in results
    ):
        outcome = DecisionOutcome.NOT_EVALUATED
    elif any(
        item.reviewable
        and item.outcome not in {RequirementOutcome.SATISFIED, RequirementOutcome.NOT_APPLICABLE}
        for item in results
    ):
        outcome = DecisionOutcome.REVIEW_REQUIRED
    elif any(
        item.outcome
        in {
            RequirementOutcome.SATISFIED_WITH_LIMITATIONS,
            RequirementOutcome.NOT_CHECKED,
        }
        for item in results
    ):
        outcome = DecisionOutcome.ALLOW_WITH_LIMITATIONS
    else:
        outcome = DecisionOutcome.ALLOW
    reasons = [
        DecisionReason(
            code="GOV-005" if not item.blocking else "GOV-006",
            summary=item.reason,
            blocking=item.blocking,
            requirement_id=item.requirement_id,
        )
        for item in results
    ]
    blockers = sorted(item.requirement_id for item in results if item.blocking)
    limitations = sorted(
        {
            *policy.limitations,
            *(limit for item in results for limit in item.limitations),
            "Promotion permission does not prove upload, deployment, or runtime observation.",
        }
    )
    body: dict[str, Any] = {
        "schema": "omiv.policy-evaluation.v1",
        "subject_id": value.subject.subject_id,
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest,
        "evaluation_context_id": context.context_id if context else None,
        "requirement_results": [item.model_dump(mode="json") for item in results],
        "outcome": outcome.value,
        "reasons": [item.model_dump(mode="json") for item in reasons],
        "blockers": blockers,
        "limitations": limitations,
        "missing_evidence": {"items": [item.model_dump(mode="json") for item in missing_items]},
    }
    return PolicyEvaluationResult.model_validate({**body, "result_digest": canonical_sha256(body)})


def build_policy_decision(
    value: PolicyEvaluationInput, policy: GovernancePolicy
) -> PolicyDecisionRecord:
    result = evaluate_policy(value, policy)
    body: dict[str, Any] = {
        "schema": "omiv.policy-decision-record.v1",
        "subject": value.subject.model_dump(mode="json"),
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest,
        "evaluation_context_id": result.evaluation_context_id,
        "evaluation_result_digest": result.result_digest,
        "requirement_results": [
            item.model_dump(mode="json") for item in result.requirement_results
        ],
        "decision_outcome": result.outcome.value,
        "decision_reasons": [item.model_dump(mode="json") for item in result.reasons],
        "blocking_findings": result.blockers,
        "limitations": result.limitations,
        "missing_evidence": result.missing_evidence.model_dump(mode="json"),
        "next_required_actions": sorted(
            {item.remediation for item in result.missing_evidence.items}
        ),
        "trust_summary": "POLICY_SCOPED_EVIDENCE_EVALUATED",
        "approval_status": "NOT_EVALUATED",
        "separation_of_duties_status": "NOT_EVALUATED",
        "promotion_eligibility": "NOT_EVALUATED",
    }
    return PolicyDecisionRecord.model_validate(
        _identified(body, "decision_id", "decision_", "decision_digest")
    )


def verify_policy_decision(
    observed: PolicyDecisionRecord, value: PolicyEvaluationInput, policy: GovernancePolicy
) -> PolicyDecisionRecord:
    reconstructed = build_policy_decision(value, policy)
    if observed != reconstructed:
        raise OmivInputError("policy decision does not match reconstructed evidence and policy")
    return reconstructed


def build_approval_request(
    decision: PolicyDecisionRecord,
    policy: GovernancePolicy,
    *,
    requested_action: ApprovalAction,
    requester_role: GovernanceRole,
    requester: ApprovalActorReference,
    requested_target_id: str | None = None,
    requested_scope: str,
    evidence_ids: list[str] | None = None,
) -> ApprovalRequest:
    if decision.policy_id != policy.policy_id or decision.policy_digest != policy.policy_digest:
        raise OmivInputError("approval request decision does not match governance policy")
    approval_policy = policy.approval_policy
    if approval_policy is None or approval_policy.requested_action != requested_action:
        raise OmivInputError("governance policy does not permit the requested approval action")
    body: dict[str, Any] = {
        "schema": "omiv.approval-request.v1",
        "subject": decision.subject.model_dump(mode="json"),
        "requested_action": requested_action.value,
        "requested_target_id": requested_target_id,
        "requested_scope": requested_scope,
        "requester_role": requester_role.value,
        "requester": requester.model_dump(mode="json"),
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest,
        "approval_policy_id": approval_policy.approval_policy_id,
        "approval_policy_digest": approval_policy.approval_policy_digest,
        "decision_id": decision.decision_id,
        "decision_digest": decision.decision_digest,
        "evidence_ids": sorted(evidence_ids or []),
        "requested_approver_roles": [item.value for item in approval_policy.permitted_roles],
        "quorum_id": approval_policy.quorum.quorum_id,
        "limitations": ["An approval request does not imply approval, promotion, or deployment."],
    }
    return ApprovalRequest.model_validate(
        _identified(body, "approval_request_id", "approval_request_", "request_digest")
    )


def build_approval_record(
    request: ApprovalRequest,
    *,
    approver_role: GovernanceRole,
    approver: ApprovalActorReference,
    outcome: ApprovalOutcome,
    scope: str,
    conditions: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    validity_not_after: str | None = None,
) -> ApprovalRecord:
    if outcome == ApprovalOutcome.REJECTED:
        raise OmivInputError("use a RejectionRecord for an explicit rejection")
    body: dict[str, Any] = {
        "schema": "omiv.approval-record.v1",
        "approval_request_id": request.approval_request_id,
        "request_digest": request.request_digest,
        "subject_id": request.subject.subject_id,
        "artifact_digest": request.subject.artifact_digest,
        "approver_role": approver_role.value,
        "approver": approver.model_dump(mode="json"),
        "outcome": outcome.value,
        "scope": scope,
        "conditions": sorted(conditions or []),
        "policy_id": request.policy_id,
        "policy_digest": request.policy_digest,
        "evidence_ids": sorted(evidence_ids or []),
        "validity_not_after": validity_not_after,
        "limitations": [
            "Approval is scoped governance evidence; it is not deployment or proof of safety."
        ],
    }
    return ApprovalRecord.model_validate(
        _identified(body, "approval_id", "approval_", "approval_digest")
    )


def build_rejection_record(
    request: ApprovalRequest,
    *,
    rejecting_role: GovernanceRole,
    rejecting_actor: ApprovalActorReference,
    scope: str,
    reasons: list[str],
    evidence_ids: list[str] | None = None,
) -> RejectionRecord:
    body: dict[str, Any] = {
        "schema": "omiv.rejection-record.v1",
        "approval_request_id": request.approval_request_id,
        "request_digest": request.request_digest,
        "subject_id": request.subject.subject_id,
        "rejecting_role": rejecting_role.value,
        "rejecting_actor": rejecting_actor.model_dump(mode="json"),
        "scope": scope,
        "reasons": sorted(reasons),
        "policy_id": request.policy_id,
        "policy_digest": request.policy_digest,
        "evidence_ids": sorted(evidence_ids or []),
        "limitations": ["Rejection blocks this request; it does not revoke the artifact or key."],
    }
    return RejectionRecord.model_validate(
        _identified(body, "rejection_id", "rejection_", "rejection_digest")
    )


def _actor_token(actor: ApprovalActorReference, dimension: IndependenceDimension) -> str | None:
    return {
        IndependenceDimension.DISTINCT_SIGNER_IDENTITY: actor.signer_identity_id,
        IndependenceDimension.DISTINCT_KEY: actor.key_id,
        IndependenceDimension.DISTINCT_TRUST_ROOT: actor.trust_root_id,
        IndependenceDimension.DISTINCT_ORGANIZATION: actor.organization_id,
    }.get(dimension)


def evaluate_separation_of_duties(
    policy: SeparationOfDutiesPolicy,
    request: ApprovalRequest,
    approvals: list[ApprovalRecord],
    role_assignments: list[RoleAssignment] | None = None,
) -> SeparationOfDutiesResult:
    violations: list[str] = []
    approvers = [item.approver for item in approvals]
    requester = request.requester
    if policy.requester_must_not_approve:
        for actor in approvers:
            if (
                requester.signer_identity_id
                and actor.signer_identity_id == requester.signer_identity_id
            ):
                violations.append("REQUESTER_IS_APPROVER")
            if requester.key_id and actor.key_id == requester.key_id:
                violations.append("REQUESTER_KEY_IS_APPROVER_KEY")
    assignments = role_assignments or []
    by_identity: dict[str, set[GovernanceRole]] = {}
    for assignment in assignments:
        if assignment.actor.signer_identity_id:
            by_identity.setdefault(assignment.actor.signer_identity_id, set()).add(assignment.role)
    validators = {
        identity for identity, roles in by_identity.items() if GovernanceRole.VALIDATOR in roles
    }
    if policy.producer_must_not_be_sole_validator and len(validators) == 1:
        validator = next(iter(validators))
        if GovernanceRole.ARTIFACT_PRODUCER in by_identity[validator]:
            violations.append("ARTIFACT_PRODUCER_IS_SOLE_VALIDATOR")
    if policy.validator_must_not_promote and any(
        GovernanceRole.VALIDATOR in roles and GovernanceRole.PROMOTER in roles
        for roles in by_identity.values()
    ):
        violations.append("VALIDATOR_IS_PROMOTER")
    for approval in approvals:
        roles = by_identity.get(approval.approver.signer_identity_id or "", set())
        if policy.transformer_must_not_approve and GovernanceRole.TRANSFORMER in roles:
            violations.append("TRANSFORMER_IS_APPROVER")
        if policy.promoter_must_not_approve_request and GovernanceRole.PROMOTER in roles:
            violations.append("PROMOTER_IS_APPROVER")
    insufficient = False
    if any(actor.identity_trust != IdentityTrust.TRUSTED_BY_POLICY for actor in approvers):
        insufficient = True
    for dimension in policy.required_independence:
        if dimension in {
            IndependenceDimension.DISTINCT_ROLE_ASSIGNMENT,
            IndependenceDimension.POLICY_DECLARED_INDEPENDENCE,
        }:
            if dimension == IndependenceDimension.DISTINCT_ROLE_ASSIGNMENT and not assignments:
                insufficient = True
            continue
        tokens = [_actor_token(actor, dimension) for actor in approvers]
        if not tokens or any(token is None for token in tokens):
            insufficient = True
        elif len(tokens) > 1 and len(set(tokens)) != len(tokens):
            violations.append(f"NOT_{dimension.value}")
    if (
        not policy.delegates_under_same_root_independent
        and len(approvers) > 1
        and all(actor.trust_root_id for actor in approvers)
        and len({actor.trust_root_id for actor in approvers}) < len(approvers)
    ):
        violations.append("DELEGATES_SHARE_TRUST_ROOT")
    if violations:
        outcome = SeparationOutcome.VIOLATED
    elif insufficient:
        outcome = SeparationOutcome.INSUFFICIENT_IDENTITY_EVIDENCE
    elif not approvals:
        outcome = SeparationOutcome.NOT_EVALUATED
    else:
        outcome = SeparationOutcome.SATISFIED
    base = {
        "separation_policy_id": policy.separation_policy_id,
        "outcome": outcome.value,
        "evaluated_dimensions": [item.value for item in policy.required_independence],
        "violations": sorted(set(violations)),
        "limitations": [
            "Duty separation is limited to supplied identity, key, role, and trust evidence."
        ],
    }
    return SeparationOfDutiesResult.model_validate(
        {**base, "result_digest": canonical_sha256(base)}
    )


def evaluate_quorum(
    policy: ApprovalPolicy,
    approvals: list[ApprovalRecord],
    rejections: list[RejectionRecord] | None = None,
    *,
    evaluation_time: str | None = None,
    signed_linkages: dict[str, SignedApprovalLinkage] | None = None,
    request: ApprovalRequest | None = None,
    role_assignments: list[RoleAssignment] | None = None,
) -> ApprovalQuorumResult:
    rejections = rejections or []
    assignments = role_assignments or []
    policy_matches_request = request is not None and (
        request.approval_policy_id == policy.approval_policy_id
        and request.approval_policy_digest == policy.approval_policy_digest
        and request.requested_action == policy.requested_action
    )

    def role_is_assigned(actor: ApprovalActorReference, role: GovernanceRole) -> bool:
        if not policy_matches_request or request is None:
            return False
        return any(
            assignment.actor == actor
            and assignment.role == role
            and assignment.policy_id == request.policy_id
            and request.requested_action in assignment.allowed_actions
            and fnmatchcase(request.subject.logical_locator, assignment.subject_scope)
            for assignment in assignments
        )

    applicable_rejections = [
        item
        for item in rejections
        if item.rejecting_role in policy.permitted_roles
        and item.rejecting_actor.identity_trust in policy.accepted_identity_trust
        and role_is_assigned(item.rejecting_actor, item.rejecting_role)
        and (
            request is None
            or (
                item.approval_request_id == request.approval_request_id
                and item.request_digest == request.request_digest
                and item.subject_id == request.subject.subject_id
                and item.policy_id == request.policy_id
                and item.policy_digest == request.policy_digest
                and item.scope == request.requested_scope
            )
        )
    ]
    valid: list[ApprovalRecord] = []
    for item in approvals:
        if request is not None and (
            item.approval_request_id != request.approval_request_id
            or item.request_digest != request.request_digest
            or item.subject_id != request.subject.subject_id
            or item.artifact_digest != request.subject.artifact_digest
            or item.policy_id != request.policy_id
            or item.policy_digest != request.policy_digest
            or item.scope != request.requested_scope
        ):
            continue
        if item.approver_role not in policy.permitted_roles:
            continue
        if item.approver.identity_trust not in policy.accepted_identity_trust:
            continue
        if not role_is_assigned(item.approver, item.approver_role):
            continue
        if (
            item.outcome == ApprovalOutcome.APPROVED_WITH_CONDITIONS
            and not policy.quorum.conditional_approvals_count
        ):
            continue
        if item.outcome not in {ApprovalOutcome.APPROVED, ApprovalOutcome.APPROVED_WITH_CONDITIONS}:
            if item.outcome == ApprovalOutcome.ABSTAINED and policy.quorum.abstentions_count:
                valid.append(item)
            continue
        linkage = (signed_linkages or {}).get(item.approval_id)
        if policy.require_signed_approval and not (
            linkage
            and linkage.signature_integrity == "VALID"
            and linkage.trust_status == "TRUSTED_BY_POLICY"
            and linkage.purpose == "APPROVAL_RECORD_ISSUANCE"
        ):
            continue
        if item.validity_not_after is not None and (
            evaluation_time is None or _time(evaluation_time) > _time(item.validity_not_after)
        ):
            continue
        valid.append(item)
    unique_by_id = {item.approval_id: item for item in valid}
    valid = list(unique_by_id.values())
    signers = {
        item.approver.signer_identity_id for item in valid if item.approver.signer_identity_id
    }
    keys = {item.approver.key_id for item in valid if item.approver.key_id}
    roots = {item.approver.trust_root_id for item in valid if item.approver.trust_root_id}
    roles = {item.approver_role for item in valid}
    q = policy.quorum
    blocked = bool(applicable_rejections) and q.rejection_blocks
    satisfied = all(
        (
            len(valid) >= q.minimum_count,
            len(signers) >= q.minimum_distinct_signers,
            len(keys) >= q.minimum_distinct_keys,
            len(roots) >= q.minimum_distinct_trust_roots,
            set(q.required_roles).issubset(roles),
        )
    )
    evaluation_ready = policy_matches_request and bool(assignments)
    if request is not None and not policy_matches_request:
        outcome = QuorumOutcome.INVALID
    elif not evaluation_ready and (approvals or rejections):
        outcome = QuorumOutcome.NOT_EVALUATED
    elif blocked:
        outcome = QuorumOutcome.BLOCKED_BY_REJECTION
    elif satisfied:
        outcome = QuorumOutcome.SATISFIED
    elif valid:
        outcome = QuorumOutcome.PARTIAL
    else:
        outcome = QuorumOutcome.NOT_SATISFIED
    base = {
        "quorum_id": q.quorum_id,
        "outcome": outcome.value,
        "counted_approval_ids": sorted(item.approval_id for item in valid),
        "rejected_record_ids": sorted(item.rejection_id for item in applicable_rejections),
        "distinct_signers": len(signers),
        "distinct_keys": len(keys),
        "distinct_trust_roots": len(roots),
        "satisfied_roles": sorted(item.value for item in roles),
        "limitations": ["Approval quorum is independent of cryptographic multi-signature count."],
    }
    return ApprovalQuorumResult.model_validate({**base, "result_digest": canonical_sha256(base)})


def build_promotion_target(
    target_type: PromotionTargetType,
    *,
    logical_namespace: str,
    environment_class: str,
    target_policy_id: str,
    accepted_formats: list[str],
    required_decision_outcomes: list[DecisionOutcome],
    required_approval_policy_id: str | None,
    provider_reference: str | None = None,
) -> PromotionTarget:
    body: dict[str, Any] = {
        "schema": "omiv.promotion-target.v1",
        "target_type": target_type.value,
        "logical_namespace": logical_namespace,
        "environment_class": environment_class,
        "provider_reference": provider_reference,
        "target_policy_id": target_policy_id,
        "accepted_formats": sorted(accepted_formats),
        "required_decision_outcomes": sorted(
            required_decision_outcomes, key=lambda item: item.value
        ),
        "required_approval_policy_id": required_approval_policy_id,
        "limitations": ["This is a logical target; no registry endpoint or credential is stored."],
    }
    return PromotionTarget.model_validate(
        _identified(body, "target_id", "target_", "target_digest")
    )


def build_promotion_gate_policy(
    *,
    permitted_target_types: list[PromotionTargetType],
    accepted_decision_outcomes: list[DecisionOutcome],
    require_quorum: bool,
    require_separation_of_duties: bool,
    require_trusted_decision_signature: bool,
    require_security_evidence: bool,
    require_revocation_evaluation: bool,
    require_expiration_evaluation: bool,
    allow_conditions: bool,
) -> PromotionGatePolicy:
    body = {
        "schema": "omiv.promotion-gate-policy.v1",
        "permitted_target_types": sorted(permitted_target_types, key=lambda item: item.value),
        "accepted_decision_outcomes": sorted(
            accepted_decision_outcomes, key=lambda item: item.value
        ),
        "require_quorum": require_quorum,
        "require_separation_of_duties": require_separation_of_duties,
        "require_trusted_decision_signature": require_trusted_decision_signature,
        "require_security_evidence": require_security_evidence,
        "require_revocation_evaluation": require_revocation_evaluation,
        "require_expiration_evaluation": require_expiration_evaluation,
        "allow_conditions": allow_conditions,
    }
    return PromotionGatePolicy.model_validate(
        _identified(body, "gate_policy_id", "promotion_gate_", "gate_policy_digest")
    )


def build_release_candidate(
    subject: GovernanceSubject,
    decision: PolicyDecisionRecord,
    target: PromotionTarget,
    *,
    evidence: list[EvidenceReference],
    approval_request: ApprovalRequest | None = None,
    approvals: list[ApprovalRecord] | None = None,
) -> ReleaseCandidate:
    if decision.subject != subject:
        raise OmivInputError("release candidate subject differs from policy decision subject")
    if approvals and approval_request is None:
        raise OmivInputError("release candidate approvals require their approval request")
    if approval_request is not None and any(
        item.approval_request_id != approval_request.approval_request_id
        or item.request_digest != approval_request.request_digest
        or item.subject_id != subject.subject_id
        or item.artifact_digest != subject.artifact_digest
        or item.policy_id != decision.policy_id
        or item.policy_digest != decision.policy_digest
        for item in approvals or []
    ):
        raise OmivInputError("release candidate approval does not match request or decision")
    passport = next(
        (item for item in evidence if item.schema_id.startswith("omiv.model-passport.")), None
    )
    custody = next(
        (item for item in evidence if item.category == EvidenceCategory.CUSTODY_INTEGRITY), None
    )
    attestations = [item for item in evidence if "attestation" in item.schema_id]
    signed = [item for item in evidence if item.category == EvidenceCategory.SIGNATURE_TRUST]
    body: dict[str, Any] = {
        "schema": "omiv.release-candidate.v1",
        "subject": subject.model_dump(mode="json"),
        "passport_reference": passport.model_dump(mode="json", by_alias=True) if passport else None,
        "custody_reference": custody.model_dump(mode="json", by_alias=True) if custody else None,
        "evidence_references": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(evidence, key=lambda item: item.evidence_id)
        ],
        "attestation_references": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(attestations, key=lambda item: item.evidence_id)
        ],
        "signed_evidence_references": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(signed, key=lambda item: item.evidence_id)
        ],
        "decision_id": decision.decision_id,
        "decision_digest": decision.decision_digest,
        "target_id": target.target_id,
        "approval_request_id": approval_request.approval_request_id if approval_request else None,
        "approval_policy_id": (
            approval_request.approval_policy_id if approval_request is not None else None
        ),
        "approval_record_ids": sorted(item.approval_id for item in (approvals or [])),
        "limitations": [
            "Release candidate status does not mean release, promotion, or deployment occurred."
        ],
    }
    return ReleaseCandidate.model_validate(
        _identified(body, "candidate_id", "candidate_", "candidate_digest")
    )


def evaluate_promotion_gate(
    candidate: ReleaseCandidate,
    target: PromotionTarget,
    gate_policy: PromotionGatePolicy,
    decision: PolicyDecisionRecord,
    *,
    quorum: ApprovalQuorumResult | None,
    separation: SeparationOfDutiesResult | None,
    trusted_decision_signature: bool,
) -> PromotionGateResult:
    if candidate.target_id != target.target_id:
        raise OmivInputError("release candidate references a different promotion target")
    blockers: list[str] = []
    missing: list[EvidenceCategory] = []
    if target.target_type not in gate_policy.permitted_target_types:
        blockers.append("TARGET_TYPE_NOT_PERMITTED")
    if candidate.subject.artifact_format not in target.accepted_formats:
        blockers.append("TARGET_FORMAT_MISMATCH")
    if decision.policy_id != target.target_policy_id:
        blockers.append("TARGET_POLICY_MISMATCH")
    if decision.decision_outcome not in gate_policy.accepted_decision_outcomes:
        blockers.append("POLICY_DECISION_NOT_ACCEPTED")
    if decision.decision_outcome not in target.required_decision_outcomes:
        blockers.append("TARGET_DECISION_OUTCOME_NOT_ACCEPTED")
    if target.required_approval_policy_id != candidate.approval_policy_id:
        blockers.append("TARGET_APPROVAL_POLICY_MISMATCH")
    if decision.subject != candidate.subject:
        blockers.append("ARTIFACT_CONTINUITY_BROKEN")
    if gate_policy.require_quorum and (quorum is None or quorum.outcome != QuorumOutcome.SATISFIED):
        blockers.append("APPROVAL_QUORUM_NOT_SATISFIED")
    if gate_policy.require_separation_of_duties and (
        separation is None or separation.outcome != SeparationOutcome.SATISFIED
    ):
        blockers.append("SEPARATION_OF_DUTIES_NOT_SATISFIED")
    if gate_policy.require_trusted_decision_signature and not trusted_decision_signature:
        blockers.append("TRUSTED_DECISION_SIGNATURE_MISSING")
    if gate_policy.require_security_evidence:
        # Phase 5E deliberately has no Artifact Security Evidence verifier. A
        # caller-supplied reference, signature, approval, or declaration cannot
        # fabricate the Phase 5F verification result.
        blockers.append("ARTIFACT_SECURITY_EVIDENCE_MISSING")
        missing.append(EvidenceCategory.SECURITY_INSPECTION)
    if gate_policy.require_revocation_evaluation and not any(
        item.category == EvidenceCategory.REVOCATION_EVALUATION
        and item.trust_status == "NOT_REVOKED"
        for item in candidate.evidence_references
    ):
        blockers.append("REVOCATION_EVALUATION_MISSING")
        missing.append(EvidenceCategory.REVOCATION_EVALUATION)
    if gate_policy.require_expiration_evaluation and not any(
        item.category == EvidenceCategory.EXPIRATION_EVALUATION and item.trust_status == "CURRENT"
        for item in candidate.evidence_references
    ):
        blockers.append("EXPIRATION_EVALUATION_MISSING")
        missing.append(EvidenceCategory.EXPIRATION_EVALUATION)
    conditions = sorted(
        {
            condition
            for item in (candidate.approval_record_ids if gate_policy.allow_conditions else [])
            for condition in [f"Approval record remains applicable: {item}"]
        }
    )
    if blockers:
        outcome = PromotionOutcome.PROMOTION_DENIED
    elif conditions and gate_policy.allow_conditions:
        outcome = PromotionOutcome.PROMOTION_ALLOWED_WITH_CONDITIONS
    else:
        outcome = PromotionOutcome.PROMOTION_ALLOWED
    base = {
        "gate_policy_id": gate_policy.gate_policy_id,
        "target_id": target.target_id,
        "outcome": outcome.value,
        "blockers": sorted(blockers),
        "conditions": conditions,
        "missing_evidence": [item.value for item in sorted(missing, key=lambda x: x.value)],
        "limitations": [
            "Promotion allowed means policy permission only; no upload or deployment occurred."
        ],
    }
    return PromotionGateResult.model_validate({**base, "result_digest": canonical_sha256(base)})


def build_promotion_decision(
    candidate: ReleaseCandidate,
    target: PromotionTarget,
    gate_policy: PromotionGatePolicy,
    decision: PolicyDecisionRecord,
    *,
    quorum: ApprovalQuorumResult | None = None,
    separation: SeparationOfDutiesResult | None = None,
    trusted_decision_signature: bool = False,
) -> PromotionDecisionRecord:
    gate = evaluate_promotion_gate(
        candidate,
        target,
        gate_policy,
        decision,
        quorum=quorum,
        separation=separation,
        trusted_decision_signature=trusted_decision_signature,
    )
    body: dict[str, Any] = {
        "schema": "omiv.promotion-decision-record.v1",
        "candidate_id": candidate.candidate_id,
        "candidate_digest": candidate.candidate_digest,
        "target_id": target.target_id,
        "target_digest": target.target_digest,
        "gate_policy_id": gate_policy.gate_policy_id,
        "gate_policy_digest": gate_policy.gate_policy_digest,
        "gate_result": gate.model_dump(mode="json"),
        "policy_decision_id": decision.decision_id,
        "policy_decision_digest": decision.decision_digest,
        "quorum_result": quorum.model_dump(mode="json") if quorum else None,
        "separation_result": separation.model_dump(mode="json") if separation else None,
        "trust_summary": (
            "TRUSTED_DECISION_SIGNATURE"
            if trusted_decision_signature
            else "SIGNATURE_NOT_EVALUATED"
        ),
        "conditions": gate.conditions,
        "blockers": gate.blockers,
        "missing_evidence": [item.value for item in gate.missing_evidence],
        "security_status": (
            "MISSING"
            if EvidenceCategory.SECURITY_INSPECTION in gate.missing_evidence
            else "NOT_CHECKED"
        ),
        "promotion_performed": "NO",
        "registry_write": "NOT_PERFORMED",
        "deployment_status": "NOT_PERFORMED",
        "runtime_status": "NOT_CHECKED",
        "limitations": gate.limitations
        + ["This record does not execute promotion, registry upload, or deployment."],
    }
    return PromotionDecisionRecord.model_validate(
        _identified(
            body,
            "promotion_decision_id",
            "promotion_",
            "promotion_decision_digest",
        )
    )


def build_governance_report(
    decision: PolicyDecisionRecord,
    *,
    approval_request: ApprovalRequest | None = None,
    approvals: list[ApprovalRecord] | None = None,
    rejections: list[RejectionRecord] | None = None,
    quorum: ApprovalQuorumResult | None = None,
    separation: SeparationOfDutiesResult | None = None,
    target: PromotionTarget | None = None,
    promotion: PromotionDecisionRecord | None = None,
) -> GovernanceReport:
    security_result = next(
        (
            item
            for item in decision.requirement_results
            if item.category == EvidenceCategory.SECURITY_INSPECTION
        ),
        None,
    )
    body: dict[str, Any] = {
        "schema": "omiv.governance-report.v1",
        "subject": decision.subject.model_dump(mode="json"),
        "policy_id": decision.policy_id,
        "policy_digest": decision.policy_digest,
        "decision_id": decision.decision_id,
        "decision_digest": decision.decision_digest,
        "decision_outcome": decision.decision_outcome.value,
        "requirement_results": [
            item.model_dump(mode="json") for item in decision.requirement_results
        ],
        "approval_request_id": approval_request.approval_request_id if approval_request else None,
        "approval_record_ids": sorted(item.approval_id for item in (approvals or [])),
        "rejection_record_ids": sorted(item.rejection_id for item in (rejections or [])),
        "quorum_result": quorum.model_dump(mode="json") if quorum else None,
        "separation_result": separation.model_dump(mode="json") if separation else None,
        "promotion_target_id": target.target_id if target else None,
        "promotion_outcome": promotion.gate_result.outcome.value if promotion else None,
        "promotion_conditions": promotion.conditions if promotion else [],
        "blockers": sorted(
            {*decision.blocking_findings, *(promotion.blockers if promotion else [])}
        ),
        "limitations": sorted(
            {
                *decision.limitations,
                *(promotion.limitations if promotion else []),
                "Approval status is scoped; it is not a security or deployment assertion.",
            }
        ),
        "missing_evidence": decision.missing_evidence.model_dump(mode="json"),
        "next_actions": decision.next_required_actions,
        "security_status": (
            "MISSING"
            if security_result is not None
            and security_result.outcome
            not in {
                RequirementOutcome.NOT_CHECKED,
                RequirementOutcome.NOT_APPLICABLE,
                RequirementOutcome.SATISFIED,
                RequirementOutcome.SATISFIED_WITH_LIMITATIONS,
            }
            else "NOT_CHECKED"
        ),
        "promotion_performed": "NO",
        "registry_write": "NOT_PERFORMED",
        "deployment_status": "NOT_PERFORMED",
        "runtime_status": "NOT_CHECKED",
    }
    return GovernanceReport.model_validate(
        _identified(body, "report_id", "governance_report_", "report_digest")
    )


def verify_governance_report(
    observed: GovernanceReport,
    decision: PolicyDecisionRecord,
    **kwargs: Any,
) -> GovernanceReport:
    reconstructed = build_governance_report(decision, **kwargs)
    if observed != reconstructed:
        raise OmivInputError("governance report does not match reconstructed governance state")
    return reconstructed
