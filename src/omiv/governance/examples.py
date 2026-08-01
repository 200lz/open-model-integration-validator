"""Compact deterministic generic Phase 5E example construction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omiv.canonical import canonical_sha256
from omiv.governance.adapters import build_custody_linkage, build_passport_summary
from omiv.governance.evaluation import (
    build_approval_policy,
    build_approval_record,
    build_approval_request,
    build_evaluation_context,
    build_evaluation_input,
    build_governance_policy,
    build_governance_report,
    build_policy_decision,
    build_promotion_decision,
    build_promotion_gate_policy,
    build_promotion_target,
    build_quorum,
    build_rejection_record,
    build_release_candidate,
    build_requirement,
    build_requirement_set,
    build_separation_policy,
    build_subject,
    evaluate_quorum,
    evaluate_separation_of_duties,
)
from omiv.governance.models import (
    ApprovalAction,
    ApprovalActorReference,
    ApprovalCreateInput,
    ApprovalOutcome,
    ApprovalRequestCreateInput,
    DecisionOutcome,
    EvidenceCategory,
    EvidenceReference,
    GovernanceRole,
    IdentityTrust,
    IndependenceDimension,
    PromotionTargetType,
    ReferenceAvailability,
    RoleAssignment,
    VerificationMode,
)
from omiv.governance.reporting import render_markdown
from omiv.governance.signing import approval_linkage, decision_linkage
from omiv.trust.models import SignaturePurpose, SignedObjectType, SignerIdentityKind
from omiv.trust.reporting import render_markdown as render_trust_markdown
from omiv.trust.signing import (
    build_binding,
    build_descriptor,
    build_key_identity,
    build_policy,
    build_signature_record,
    build_signed_envelope,
    build_signer_identity,
    build_trust_bundle,
    build_trust_root,
)
from omiv.trust.verification import verify_envelope

# TEST-ONLY published RFC 8032 vectors. They are public and have no security value.
RFC8032_VECTOR_1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_VECTOR_2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"


def _key(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))


def _evidence(
    name: str,
    category: EvidenceCategory,
    schema: str,
    *,
    subject_id: str,
    limitations: list[str] | None = None,
    trust_status: str | None = None,
    source_phase: str = "5E",
    observed_at: str | None = None,
) -> EvidenceReference:
    digest = canonical_sha256({"name": name, "schema": schema, "category": category.value})
    return EvidenceReference(
        evidence_id=f"evidence_{name}",
        category=category,
        schema=schema,
        object_id=f"object_{name}",
        digest=digest,
        subject_id=subject_id,
        governance_policy_id=None,
        availability=ReferenceAvailability.INCLUDED,
        verification_mode=VerificationMode.FULL,
        source_phase=source_phase,
        observed_at=observed_at,
        valid_until=None,
        trust_status=trust_status,
        signer_roles=[],
        provenance_strength=None,
        custody_status="INTACT" if category == EvidenceCategory.CUSTODY_INTEGRITY else None,
        lifecycle_events=[],
        limitations=limitations or [],
    )


def _assignment(
    actor: ApprovalActorReference,
    role: GovernanceRole,
    policy_id: str,
) -> RoleAssignment:
    body = {
        "actor": actor.model_dump(mode="json"),
        "role": role.value,
        "allowed_actions": [ApprovalAction.APPROVE_ARTIFACT_INTAKE.value],
        "subject_scope": "models/synthetic-*",
        "policy_id": policy_id,
        "limitations": ["Governance role is policy-declared, not an external identity proof."],
    }
    return RoleAssignment.model_validate(
        {"assignment_id": "role_" + canonical_sha256(body)[:32], **body}
    )


def _requirements() -> dict[str, Any]:
    identity = build_requirement(
        EvidenceCategory.ARTIFACT_IDENTITY,
        accepted_schemas=["omiv.synthetic-artifact-identity.v1"],
        remediation="Provide a canonical immutable artifact identity.",
        source_phase="5A",
    )
    immutable = build_requirement(
        EvidenceCategory.IMMUTABLE_REVISION,
        accepted_schemas=["omiv.synthetic-immutable-revision.v1"],
        remediation="Resolve an immutable artifact revision.",
        source_phase="5A",
    )
    structural = build_requirement(
        EvidenceCategory.STRUCTURAL_VALIDATION,
        accepted_schemas=["omiv.synthetic-structural-validation.v1"],
        allow_with_limitations=True,
        remediation="Provide verified structural validation.",
        source_phase="4F",
    )
    acquisition = build_requirement(
        EvidenceCategory.ACQUISITION_ATTESTATION,
        accepted_schemas=["omiv.artifact-attestation.v1"],
        remediation="Provide artifact-specific acquisition evidence.",
        source_phase="5C",
    )
    custody = build_requirement(
        EvidenceCategory.CUSTODY_INTEGRITY,
        accepted_schemas=["omiv.custody-ledger.v2"],
        required_custody_status="INTACT",
        remediation="Provide an intact portable custody segment.",
        source_phase="5B",
    )
    signature = build_requirement(
        EvidenceCategory.SIGNATURE_TRUST,
        accepted_schemas=["omiv.signature-report.v1"],
        accepted_trust_statuses=["TRUSTED_BY_POLICY"],
        remediation="Provide a policy-trusted signed evidence object.",
        source_phase="5D",
    )
    security_optional = build_requirement(
        EvidenceCategory.SECURITY_INSPECTION,
        accepted_schemas=["omiv.artifact-security-evidence.v1"],
        optional=True,
        allow_with_limitations=True,
        failure_severity="WARNING",
        remediation="Phase 5F must provide verifiable artifact security evidence.",
        source_phase="5F",
    )
    security_required = build_requirement(
        EvidenceCategory.SECURITY_INSPECTION,
        accepted_schemas=["omiv.artifact-security-evidence.v1"],
        remediation="Phase 5F must provide verifiable artifact security evidence.",
        source_phase="5F",
    )
    payload = build_requirement(
        EvidenceCategory.PAYLOAD_INTEGRITY,
        accepted_schemas=["omiv.payload-integrity-evidence.v1"],
        remediation="Provide payload integrity evidence in a later phase.",
        source_phase="5F",
    )
    runtime = build_requirement(
        EvidenceCategory.RUNTIME_OBSERVATION,
        accepted_schemas=["omiv.runtime-observation.v1"],
        remediation="Provide runtime observation evidence in Phase 5G.",
        source_phase="5G",
    )
    return {
        "personal": build_requirement_set([identity, structural, security_optional]),
        "intake": build_requirement_set(
            [identity, immutable, structural, acquisition, custody, signature, security_optional]
        ),
        "release": build_requirement_set(
            [identity, immutable, structural, acquisition, custody, signature, security_required]
        ),
        "enterprise": build_requirement_set(
            [identity, immutable, structural, acquisition, custody, signature, security_required]
        ),
        "regulated": build_requirement_set(
            [
                identity,
                immutable,
                structural,
                acquisition,
                custody,
                signature,
                security_required,
                payload,
                runtime,
            ]
        ),
    }


def build_examples(repository: Path) -> dict[str, object | str]:
    """Build every public-only Phase 5E fixture without external side effects."""
    del repository
    requirements = _requirements()
    one = build_quorum(
        minimum_count=1,
        required_roles=[GovernanceRole.APPROVER],
        minimum_distinct_signers=1,
        minimum_distinct_keys=1,
    )
    two = build_quorum(
        minimum_count=2,
        required_roles=[GovernanceRole.APPROVER, GovernanceRole.SECURITY_REVIEWER],
        minimum_distinct_signers=2,
        minimum_distinct_keys=2,
        minimum_distinct_trust_roots=2,
    )
    separation = build_separation_policy(
        required_independence=[
            IndependenceDimension.DISTINCT_SIGNER_IDENTITY,
            IndependenceDimension.DISTINCT_KEY,
        ]
    )
    intake_approval = build_approval_policy(
        ApprovalAction.APPROVE_ARTIFACT_INTAKE,
        one,
        permitted_roles=[GovernanceRole.APPROVER],
        require_signed_approval=True,
    )
    release_approval = build_approval_policy(
        ApprovalAction.APPROVE_RELEASE_CANDIDATE,
        two,
        permitted_roles=[GovernanceRole.APPROVER, GovernanceRole.SECURITY_REVIEWER],
        require_signed_approval=True,
    )
    all_formats = ["GGUF", "SAFETENSORS", "SYNTHETIC"]
    all_origins = ["air_gapped", "internal_registry", "local", "oci", "other", "s3"]
    policies = {
        "personal": build_governance_policy(
            "personal_local_use",
            requirements["personal"],
            accepted_formats=all_formats,
            accepted_origin_types=all_origins,
            missing_evidence_behavior="LIMITATION",
        ),
        "intake": build_governance_policy(
            "team_artifact_intake",
            requirements["intake"],
            accepted_formats=all_formats,
            accepted_origin_types=all_origins,
            approval_policy=intake_approval,
            separation_policy=separation,
            allowed_target_types=[PromotionTargetType.TEAM_ARTIFACT_REGISTRY],
            missing_evidence_behavior="REVIEW",
        ),
        "release": build_governance_policy(
            "team_release_candidate",
            requirements["release"],
            accepted_formats=all_formats,
            accepted_origin_types=all_origins,
            approval_policy=release_approval,
            separation_policy=separation,
            allowed_target_types=[PromotionTargetType.TEAM_ARTIFACT_REGISTRY],
        ),
        "enterprise": build_governance_policy(
            "enterprise_registry_promotion",
            requirements["enterprise"],
            accepted_formats=all_formats,
            accepted_origin_types=all_origins,
            approval_policy=release_approval,
            separation_policy=separation,
            allowed_target_types=[PromotionTargetType.ENTERPRISE_RELEASE_REGISTRY],
            require_evaluation_time=True,
            require_revocation_evaluation=True,
            require_expiration_evaluation=True,
        ),
        "regulated": build_governance_policy(
            "regulated_production_release",
            requirements["regulated"],
            accepted_formats=all_formats,
            accepted_origin_types=all_origins,
            approval_policy=release_approval,
            separation_policy=separation,
            allowed_target_types=[],
            require_evaluation_time=True,
            require_revocation_evaluation=True,
            require_expiration_evaluation=True,
        ),
    }
    subject = build_subject(
        artifact_digest=canonical_sha256({"artifact": "synthetic-governance-model"}),
        artifact_set_digest=canonical_sha256({"files": ["weights-00001.safetensors"]}),
        artifact_format="SAFETENSORS",
        origin_type="internal_registry",
        provider="synthetic-project",
        logical_locator="models/synthetic-transformer",
        immutable_revision="revision-synthetic-001",
        variant="SYNTHETIC-F16",
    )
    identity = _evidence(
        "identity",
        EvidenceCategory.ARTIFACT_IDENTITY,
        "omiv.synthetic-artifact-identity.v1",
        subject_id=subject.subject_id,
    )
    immutable = _evidence(
        "immutable",
        EvidenceCategory.IMMUTABLE_REVISION,
        "omiv.synthetic-immutable-revision.v1",
        subject_id=subject.subject_id,
    )
    structural = _evidence(
        "structural",
        EvidenceCategory.STRUCTURAL_VALIDATION,
        "omiv.synthetic-structural-validation.v1",
        subject_id=subject.subject_id,
        limitations=["Structural validation does not prove payload integrity or security."],
        source_phase="4F",
    )
    acquisition = _evidence(
        "acquisition",
        EvidenceCategory.ACQUISITION_ATTESTATION,
        "omiv.artifact-attestation.v1",
        subject_id=subject.subject_id,
        source_phase="5C",
    )
    custody = _evidence(
        "custody",
        EvidenceCategory.CUSTODY_INTEGRITY,
        "omiv.custody-ledger.v2",
        subject_id=subject.subject_id,
        source_phase="5B",
    )
    signature = _evidence(
        "signature",
        EvidenceCategory.SIGNATURE_TRUST,
        "omiv.signature-report.v1",
        subject_id=subject.subject_id,
        trust_status="TRUSTED_BY_POLICY",
        source_phase="5D",
    )
    supplied = [identity, immutable, structural, acquisition, custody, signature]
    contexts = {
        name: build_evaluation_context(
            policy.policy_id,
            policy.policy_digest,
            "2026-08-02T00:00:00Z" if policy.require_evaluation_time else None,
        )
        for name, policy in policies.items()
    }
    inputs = {
        "personal": build_evaluation_input(subject, policies["personal"], [identity, structural]),
        **{
            name: build_evaluation_input(
                subject,
                policies[name],
                supplied,
                context=contexts[name],
            )
            for name in ("intake", "release", "enterprise", "regulated")
        },
    }
    decisions = {name: build_policy_decision(inputs[name], policies[name]) for name in policies}

    requester_private = _key(RFC8032_VECTOR_1)
    approver_private = _key(RFC8032_VECTOR_2)
    object_types = [
        SignedObjectType.POLICY_DECISION,
        SignedObjectType.APPROVAL_RECORD,
        SignedObjectType.REJECTION_RECORD,
        SignedObjectType.RELEASE_CANDIDATE,
        SignedObjectType.PROMOTION_DECISION,
    ]
    purposes = [
        SignaturePurpose.POLICY_DECISION_ISSUANCE,
        SignaturePurpose.APPROVAL_RECORD_ISSUANCE,
        SignaturePurpose.REJECTION_RECORD_ISSUANCE,
        SignaturePurpose.RELEASE_CANDIDATE_ISSUANCE,
        SignaturePurpose.PROMOTION_DECISION_ISSUANCE,
    ]
    requester_key = build_key_identity(
        requester_private,
        allowed_object_types=object_types,
        allowed_purposes=purposes,
        namespaces=["synthetic"],
    )
    approver_key = build_key_identity(
        approver_private,
        allowed_object_types=object_types,
        allowed_purposes=purposes,
        namespaces=["synthetic"],
    )
    requester_identity = build_signer_identity(
        SignerIdentityKind.INDIVIDUAL_DECLARED,
        "Synthetic Requester",
        role="requester",
        namespace="synthetic",
    )
    approver_identity = build_signer_identity(
        SignerIdentityKind.INDIVIDUAL_DECLARED,
        "Synthetic Approver",
        role="approver",
        namespace="synthetic",
    )
    requester_binding = build_binding(requester_identity, requester_key)
    approver_binding = build_binding(approver_identity, approver_key)
    trust_policy = build_policy(
        "team_release",
        object_types=object_types,
        purposes=purposes,
        namespaces=["synthetic"],
    )
    trust_bundle = build_trust_bundle(
        [build_trust_root(requester_key), build_trust_root(approver_key)],
        [requester_key, approver_key],
        identities=[requester_identity, approver_identity],
        bindings=[requester_binding, approver_binding],
    )
    requester_actor = ApprovalActorReference(
        signer_identity_id=requester_identity.signer_identity_id,
        key_id=requester_key.key_id,
        trust_root_id=trust_bundle.trust_roots[1].trust_root_id,
        organization_id="synthetic-request-team",
        identity_trust=IdentityTrust.TRUSTED_BY_POLICY,
    )
    approver_actor = ApprovalActorReference(
        signer_identity_id=approver_identity.signer_identity_id,
        key_id=approver_key.key_id,
        trust_root_id=trust_bundle.trust_roots[0].trust_root_id,
        organization_id="synthetic-review-team",
        identity_trust=IdentityTrust.TRUSTED_BY_POLICY,
    )
    request = build_approval_request(
        decisions["intake"],
        policies["intake"],
        requested_action=ApprovalAction.APPROVE_ARTIFACT_INTAKE,
        requester_role=GovernanceRole.REQUESTER,
        requester=requester_actor,
        requested_scope="team artifact intake under the named policy",
        evidence_ids=[item.evidence_id for item in supplied],
    )
    approval = build_approval_record(
        request,
        approver_role=GovernanceRole.APPROVER,
        approver=approver_actor,
        outcome=ApprovalOutcome.APPROVED_WITH_CONDITIONS,
        scope="team artifact intake under the named policy",
        conditions=["Security remains not checked."],
    )
    request_input = ApprovalRequestCreateInput(
        requested_action=ApprovalAction.APPROVE_ARTIFACT_INTAKE,
        requested_target_id=None,
        requested_scope="team artifact intake under the named policy",
        requester_role=GovernanceRole.REQUESTER,
        requester=requester_actor,
        evidence_ids=sorted(item.evidence_id for item in supplied),
    )
    approval_input = ApprovalCreateInput(
        approver_role=GovernanceRole.APPROVER,
        approver=approver_actor,
        outcome=ApprovalOutcome.APPROVED_WITH_CONDITIONS,
        scope="team artifact intake under the named policy",
        conditions=["Security remains not checked."],
        evidence_ids=[],
        validity_not_after=None,
    )
    self_approval = build_approval_record(
        request,
        approver_role=GovernanceRole.APPROVER,
        approver=requester_actor,
        outcome=ApprovalOutcome.APPROVED,
        scope="team artifact intake under the named policy",
    )
    rejection = build_rejection_record(
        request,
        rejecting_role=GovernanceRole.APPROVER,
        rejecting_actor=approver_actor,
        scope="team artifact intake under the named policy",
        reasons=["Required security review has not been supplied."],
    )
    roles = [
        _assignment(requester_actor, GovernanceRole.REQUESTER, policies["intake"].policy_id),
        _assignment(approver_actor, GovernanceRole.APPROVER, policies["intake"].policy_id),
    ]

    decision_descriptor = build_descriptor(
        decisions["intake"].model_dump(mode="json", by_alias=True),
        SignedObjectType.POLICY_DECISION,
        SignaturePurpose.POLICY_DECISION_ISSUANCE,
        policy_id=trust_policy.policy_id,
        namespace="synthetic",
    )
    decision_signature = build_signature_record(
        decision_descriptor,
        requester_private,
        requester_key,
        binding_id=requester_binding.binding_id,
    )
    decision_envelope = build_signed_envelope(
        decisions["intake"].model_dump(mode="json", by_alias=True),
        SignedObjectType.POLICY_DECISION,
        [decision_signature],
        keys=[requester_key],
    )
    decision_trust_report = verify_envelope(decision_envelope, trust_bundle, trust_policy)
    signed_decision = decision_linkage(decision_envelope, decision_trust_report)

    approval_descriptor = build_descriptor(
        approval.model_dump(mode="json", by_alias=True),
        SignedObjectType.APPROVAL_RECORD,
        SignaturePurpose.APPROVAL_RECORD_ISSUANCE,
        policy_id=trust_policy.policy_id,
        namespace="synthetic",
    )
    approval_signature = build_signature_record(
        approval_descriptor, approver_private, approver_key, binding_id=approver_binding.binding_id
    )
    approval_envelope = build_signed_envelope(
        approval.model_dump(mode="json", by_alias=True),
        SignedObjectType.APPROVAL_RECORD,
        [approval_signature],
        keys=[approver_key],
    )
    approval_trust_report = verify_envelope(approval_envelope, trust_bundle, trust_policy)
    signed_approval = approval_linkage(approval_envelope, approval_trust_report)
    quorum = evaluate_quorum(
        intake_approval,
        [approval],
        signed_linkages={approval.approval_id: signed_approval},
        request=request,
        role_assignments=roles,
    )
    separation_result = evaluate_separation_of_duties(separation, request, [approval], roles)
    self_separation = evaluate_separation_of_duties(separation, request, [self_approval], roles)
    rejected_quorum = evaluate_quorum(
        intake_approval,
        [approval],
        [rejection],
        signed_linkages={approval.approval_id: signed_approval},
        request=request,
        role_assignments=roles,
    )
    target = build_promotion_target(
        PromotionTargetType.TEAM_ARTIFACT_REGISTRY,
        logical_namespace="synthetic/team-approved",
        environment_class="TEAM_REVIEWED",
        target_policy_id=policies["intake"].policy_id,
        accepted_formats=all_formats,
        required_decision_outcomes=[DecisionOutcome.ALLOW_WITH_LIMITATIONS],
        required_approval_policy_id=intake_approval.approval_policy_id,
    )
    enterprise_target = build_promotion_target(
        PromotionTargetType.ENTERPRISE_RELEASE_REGISTRY,
        logical_namespace="synthetic/enterprise-candidates",
        environment_class="ENTERPRISE_RELEASE",
        target_policy_id=policies["enterprise"].policy_id,
        accepted_formats=all_formats,
        required_decision_outcomes=[DecisionOutcome.ALLOW],
        required_approval_policy_id=release_approval.approval_policy_id,
    )
    gate = build_promotion_gate_policy(
        permitted_target_types=[PromotionTargetType.TEAM_ARTIFACT_REGISTRY],
        accepted_decision_outcomes=[DecisionOutcome.ALLOW_WITH_LIMITATIONS],
        require_quorum=True,
        require_separation_of_duties=True,
        require_trusted_decision_signature=True,
        require_security_evidence=False,
        require_revocation_evaluation=False,
        require_expiration_evaluation=False,
        allow_conditions=True,
    )
    enterprise_gate = build_promotion_gate_policy(
        permitted_target_types=[PromotionTargetType.ENTERPRISE_RELEASE_REGISTRY],
        accepted_decision_outcomes=[DecisionOutcome.ALLOW],
        require_quorum=True,
        require_separation_of_duties=True,
        require_trusted_decision_signature=True,
        require_security_evidence=True,
        require_revocation_evaluation=True,
        require_expiration_evaluation=True,
        allow_conditions=False,
    )
    candidate = build_release_candidate(
        subject,
        decisions["intake"],
        target,
        evidence=supplied,
        approval_request=request,
        approvals=[approval],
    )
    enterprise_candidate = build_release_candidate(
        subject,
        decisions["enterprise"],
        enterprise_target,
        evidence=supplied,
        approval_request=None,
        approvals=[],
    )
    promotion = build_promotion_decision(
        candidate,
        target,
        gate,
        decisions["intake"],
        quorum=quorum,
        separation=separation_result,
        trusted_decision_signature=(signed_decision.trust_status == "TRUSTED_BY_POLICY"),
    )
    enterprise_promotion = build_promotion_decision(
        enterprise_candidate,
        enterprise_target,
        enterprise_gate,
        decisions["enterprise"],
        quorum=None,
        separation=None,
        trusted_decision_signature=False,
    )

    def sign_governance_object(
        value: Any,
        object_type: SignedObjectType,
        purpose: SignaturePurpose,
        private_key: Ed25519PrivateKey,
        key: Any,
        binding_id: str,
    ) -> tuple[Any, Any]:
        descriptor = build_descriptor(
            value.model_dump(mode="json", by_alias=True),
            object_type,
            purpose,
            policy_id=trust_policy.policy_id,
            namespace="synthetic",
        )
        signature_record = build_signature_record(
            descriptor, private_key, key, binding_id=binding_id
        )
        envelope = build_signed_envelope(
            value.model_dump(mode="json", by_alias=True),
            object_type,
            [signature_record],
            keys=[key],
        )
        return envelope, verify_envelope(envelope, trust_bundle, trust_policy)

    rejection_envelope, rejection_trust_report = sign_governance_object(
        rejection,
        SignedObjectType.REJECTION_RECORD,
        SignaturePurpose.REJECTION_RECORD_ISSUANCE,
        approver_private,
        approver_key,
        approver_binding.binding_id,
    )
    candidate_envelope, candidate_trust_report = sign_governance_object(
        candidate,
        SignedObjectType.RELEASE_CANDIDATE,
        SignaturePurpose.RELEASE_CANDIDATE_ISSUANCE,
        requester_private,
        requester_key,
        requester_binding.binding_id,
    )
    promotion_envelope, promotion_trust_report = sign_governance_object(
        promotion,
        SignedObjectType.PROMOTION_DECISION,
        SignaturePurpose.PROMOTION_DECISION_ISSUANCE,
        requester_private,
        requester_key,
        requester_binding.binding_id,
    )
    reports = {
        name: build_governance_report(decisions[name])
        for name in ("personal", "release", "enterprise", "regulated")
    }
    reports["intake"] = build_governance_report(
        decisions["intake"],
        approval_request=request,
        approvals=[approval],
        quorum=quorum,
        separation=separation_result,
        target=target,
        promotion=promotion,
    )
    synthetic_passport = {
        "passport_id": "mp_" + canonical_sha256({"passport": "synthetic"})[:32],
    }
    synthetic_passport["passport_digest"] = canonical_sha256(synthetic_passport)
    passport_summary = build_passport_summary(
        synthetic_passport,
        decisions["intake"],
        approval_scope="team artifact intake under the named policy",
        quorum=quorum,
        separation=separation_result,
        target=target,
        promotion=promotion,
        signed_decision_status=signed_decision.trust_status,
        signed_approval_status=signed_approval.trust_status,
    )
    synthetic_ledger = {"chain_id": "mcoc_" + canonical_sha256({"ledger": "synthetic"})[:32]}
    synthetic_ledger["ledger_digest"] = canonical_sha256(synthetic_ledger)
    custody_linkage = build_custody_linkage(
        synthetic_ledger,
        event_type="PROMOTION_AUTHORIZED",
        governance_object_id=promotion.promotion_decision_id,
        governance_object_digest=promotion.promotion_decision_digest,
    )
    artifacts: dict[str, object | str] = {}
    for name, value in requirements.items():
        artifacts[f"governance/examples/{name}.requirement-set.json"] = value
    for name, value in policies.items():
        artifacts[f"governance/examples/{name}.governance-policy.json"] = value
        artifacts[f"governance/examples/{name}.policy-evaluation-input.json"] = inputs[name]
        artifacts[f"governance/examples/{name}.policy-decision.json"] = decisions[name]
        artifacts[f"reports/governance/{name}.governance-report.json"] = reports[name]
        artifacts[f"reports/governance/{name}.governance-report.md"] = render_markdown(
            reports[name]
        )
    artifacts.update(
        {
            "governance/examples/intake.approval-policy.json": intake_approval,
            "governance/examples/release.approval-policy.json": release_approval,
            "governance/examples/separation-of-duties-policy.json": separation,
            "governance/examples/team-intake.approval-request.json": request,
            "governance/examples/team-intake.approval-request-input.json": request_input,
            "governance/examples/team-intake.approval-record.json": approval,
            "governance/examples/team-intake.approval-input.json": approval_input,
            "governance/examples/team-intake.self-approval-record.json": self_approval,
            "governance/examples/team-intake.rejection-record.json": rejection,
            "governance/examples/team-intake.quorum-result.json": quorum,
            "governance/examples/team-intake.rejection-quorum-result.json": rejected_quorum,
            "governance/examples/team-intake.separation-result.json": separation_result,
            "governance/examples/team-intake.self-approval-separation-result.json": self_separation,
            "governance/examples/team.promotion-target.json": target,
            "governance/examples/enterprise.promotion-target.json": enterprise_target,
            "governance/examples/team.promotion-gate-policy.json": gate,
            "governance/examples/enterprise.promotion-gate-policy.json": enterprise_gate,
            "governance/examples/team.release-candidate.json": candidate,
            "governance/examples/enterprise.release-candidate.json": enterprise_candidate,
            "governance/examples/team.promotion-decision.json": promotion,
            "governance/examples/enterprise.promotion-decision.json": enterprise_promotion,
            "governance/examples/team.passport-governance-summary.json": passport_summary,
            "governance/examples/team.custody-governance-linkage.json": custody_linkage,
            "governance/examples/governance-trust-policy.json": trust_policy,
            "governance/examples/governance-trust-bundle.json": trust_bundle,
        }
    )
    artifacts["governance/examples/signed-team-intake-decision.signed-envelope.json"] = (
        decision_envelope
    )
    artifacts["governance/examples/signed-team-intake-approval.signed-envelope.json"] = (
        approval_envelope
    )
    artifacts["reports/governance/signed-team-intake-decision.signature-report.json"] = (
        decision_trust_report
    )
    artifacts["reports/governance/signed-team-intake-decision.signature-report.md"] = (
        render_trust_markdown(decision_trust_report)
    )
    artifacts["reports/governance/signed-team-intake-approval.signature-report.json"] = (
        approval_trust_report
    )
    artifacts["reports/governance/signed-team-intake-approval.signature-report.md"] = (
        render_trust_markdown(approval_trust_report)
    )
    for name, envelope, report in (
        ("team-intake-rejection", rejection_envelope, rejection_trust_report),
        ("team-release-candidate", candidate_envelope, candidate_trust_report),
        ("team-promotion-decision", promotion_envelope, promotion_trust_report),
    ):
        artifacts[f"governance/examples/signed-{name}.signed-envelope.json"] = envelope
        artifacts[f"reports/governance/signed-{name}.signature-report.json"] = report
        artifacts[f"reports/governance/signed-{name}.signature-report.md"] = render_trust_markdown(
            report
        )
    return artifacts
