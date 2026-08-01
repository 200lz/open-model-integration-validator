"""Phase 5E policy decisions, approvals, separation, quorum, and promotion tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.governance.evaluation import (
    build_approval_record,
    build_approval_request,
    build_evaluation_context,
    build_evaluation_input,
    build_governance_report,
    build_policy_decision,
    build_quorum,
    build_requirement,
    build_requirement_set,
    build_separation_policy,
    build_subject,
    evaluate_policy,
    evaluate_quorum,
    evaluate_separation_of_duties,
    verify_governance_report,
    verify_policy_decision,
)
from omiv.governance.examples import RFC8032_VECTOR_1, RFC8032_VECTOR_2
from omiv.governance.models import (
    ApprovalAction,
    ApprovalActorReference,
    ApprovalOutcome,
    ApprovalRecord,
    ApprovalRequest,
    DecisionOutcome,
    EvidenceCategory,
    EvidenceReference,
    GovernancePolicy,
    GovernanceRole,
    IdentityTrust,
    IndependenceDimension,
    PolicyEvaluationInput,
    QuorumOutcome,
    ReferenceAvailability,
    RejectionRecord,
    RequirementOutcome,
    RoleAssignment,
    SeparationOutcome,
    SignedApprovalLinkage,
    VerificationMode,
)
from omiv.governance.reporting import render_markdown
from omiv.trust.models import SignatureIntegrity, SignedObjectType
from omiv.trust.verification import load_envelope, load_report
from tools.generate_governance_examples import generate

ROOT = Path(__file__).parents[1]


def _raw(relative: str) -> dict[str, object]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _policy(name: str = "intake") -> GovernancePolicy:
    return GovernancePolicy.model_validate(
        _raw(f"governance/examples/{name}.governance-policy.json")
    )


def _input(name: str = "intake") -> PolicyEvaluationInput:
    return PolicyEvaluationInput.model_validate(
        _raw(f"governance/examples/{name}.policy-evaluation-input.json")
    )


def _actor(name: str, key: str, root: str) -> ApprovalActorReference:
    return ApprovalActorReference(
        signer_identity_id=name,
        key_id=key,
        trust_root_id=root,
        organization_id=f"org-{name}",
        identity_trust=IdentityTrust.TRUSTED_BY_POLICY,
    )


def _unsigned_policy() -> object:
    policy = _policy().approval_policy
    assert policy is not None
    return policy.model_copy(update={"require_signed_approval": False})


def _assignment(
    actor: ApprovalActorReference,
    role: GovernanceRole,
    policy_id: str,
    action: ApprovalAction = ApprovalAction.APPROVE_ARTIFACT_INTAKE,
) -> RoleAssignment:
    body = {
        "actor": actor.model_dump(mode="json"),
        "role": role.value,
        "allowed_actions": [action.value],
        "subject_scope": "models/synthetic-*",
        "policy_id": policy_id,
        "limitations": ["Policy-declared test role."],
    }
    return RoleAssignment.model_validate(
        {"assignment_id": "role_" + canonical_sha256(body)[:32], **body}
    )


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("personal", DecisionOutcome.ALLOW_WITH_LIMITATIONS),
        ("intake", DecisionOutcome.ALLOW_WITH_LIMITATIONS),
        ("release", DecisionOutcome.DENY),
        ("enterprise", DecisionOutcome.DENY),
        ("regulated", DecisionOutcome.DENY),
    ],
)
def test_policy_profile_outcomes(name: str, expected: DecisionOutcome) -> None:
    assert evaluate_policy(_input(name), _policy(name)).outcome == expected


def test_decision_precedence_is_fail_closed() -> None:
    result = evaluate_policy(_input("regulated"), _policy("regulated"))
    assert result.outcome == DecisionOutcome.DENY
    categories = {item.category for item in result.missing_evidence.items if item.blocking}
    assert EvidenceCategory.SECURITY_INSPECTION in categories
    assert EvidenceCategory.PAYLOAD_INTEGRITY in categories
    assert EvidenceCategory.RUNTIME_OBSERVATION in categories


def test_same_evidence_different_policy_changes_outcome() -> None:
    personal = _input("personal")
    release_policy = _policy("release")
    changed = personal.model_copy(
        update={
            "policy_id": release_policy.policy_id,
            "policy_digest": release_policy.policy_digest,
            "evaluation_context": None,
        }
    )
    assert (
        evaluate_policy(personal, _policy("personal")).outcome
        == DecisionOutcome.ALLOW_WITH_LIMITATIONS
    )
    assert evaluate_policy(changed, release_policy).outcome == DecisionOutcome.DENY


def test_caller_cannot_supply_final_outcome() -> None:
    raw = _raw("governance/examples/intake.policy-evaluation-input.json")
    raw["outcome"] = "ALLOW"
    with pytest.raises(ValidationError):
        PolicyEvaluationInput.model_validate(raw)


def test_unknown_fields_and_bad_digest_rejected() -> None:
    policy = _raw("governance/examples/intake.governance-policy.json")
    policy["unexpected"] = True
    with pytest.raises(ValidationError):
        GovernancePolicy.model_validate(policy)
    requirement = _raw("governance/examples/intake.requirement-set.json")
    requirement["requirement_set_digest"] = "0" * 64
    with pytest.raises(ValidationError):
        from omiv.governance.models import EvidenceRequirementSet

        EvidenceRequirementSet.model_validate(requirement)


@pytest.mark.parametrize(
    "value",
    ["/tmp/secret", "C:\\Users\\person", "https://example.invalid/a?token=value"],
)
def test_unsafe_portable_values_rejected(value: str) -> None:
    raw = _raw("governance/examples/personal.policy-evaluation-input.json")
    raw["subject"]["logical_locator"] = value  # type: ignore[index]
    with pytest.raises(ValidationError):
        PolicyEvaluationInput.model_validate(raw)


def test_missing_is_not_inferred_not_applicable() -> None:
    policy = _policy("release")
    result = evaluate_policy(_input("release"), policy)
    security = next(
        item
        for item in result.requirement_results
        if item.category == EvidenceCategory.SECURITY_INSPECTION
    )
    assert security.outcome == RequirementOutcome.MISSING


def test_limited_satisfaction_is_not_mislabeled_missing() -> None:
    result = evaluate_policy(_input("personal"), _policy("personal"))
    missing = {item.category for item in result.missing_evidence.items}
    assert EvidenceCategory.STRUCTURAL_VALIDATION not in missing
    assert EvidenceCategory.SECURITY_INSPECTION in missing


def test_future_security_reference_cannot_be_fabricated_or_approved_around() -> None:
    value = _input("release")
    source = value.evidence[0]
    fake = source.model_copy(
        update={
            "evidence_id": "evidence_fake_security",
            "category": EvidenceCategory.SECURITY_INSPECTION,
            "schema_id": "omiv.artifact-security-evidence.v1",
            "object_id": "security_passed_declaration",
            "digest": canonical_sha256({"security": "passed"}),
            "source_phase": "5F",
            "trust_status": "TRUSTED_BY_POLICY",
            "limitations": [],
        }
    )
    supplied = sorted([*value.evidence, fake], key=lambda item: item.evidence_id)
    changed = value.model_copy(
        update={
            "evidence": supplied,
            "approval_record_ids": ["approval_fake_security_override"],
        }
    )
    result = evaluate_policy(changed, _policy("release"))
    security = next(
        item
        for item in result.requirement_results
        if item.category == EvidenceCategory.SECURITY_INSPECTION
    )
    assert security.outcome == RequirementOutcome.UNAVAILABLE
    assert result.outcome == DecisionOutcome.DENY


def test_evidence_bound_to_different_subject_is_rejected() -> None:
    value = _input("personal")
    wrong = value.evidence[0].model_copy(update={"subject_id": "subject_" + "0" * 32})
    with pytest.raises(OmivInputError):
        build_evaluation_input(value.subject, _policy("personal"), [wrong])


def test_not_applicable_requires_explicit_policy_evidence() -> None:
    evidence = EvidenceReference(
        evidence_id="evidence_explicit_na",
        category=EvidenceCategory.SECURITY_INSPECTION,
        schema="omiv.not-applicable-evidence.v1",
        object_id="policy_evidence_security_na",
        digest=canonical_sha256({"na": "security"}),
        subject_id=_input("personal").subject.subject_id,
        governance_policy_id=None,
        availability=ReferenceAvailability.INCLUDED,
        verification_mode=VerificationMode.FULL,
        source_phase="5E",
        observed_at=None,
        valid_until=None,
        trust_status=None,
        signer_roles=[],
        provenance_strength=None,
        custody_status=None,
        lifecycle_events=[],
        limitations=[],
    )
    requirement = build_requirement(
        EvidenceCategory.SECURITY_INSPECTION,
        accepted_schemas=["omiv.artifact-security-evidence.v1"],
        not_applicable_policy_evidence=[evidence.object_id],
    )
    requirement_set = build_requirement_set([requirement])
    from omiv.governance.evaluation import build_governance_policy

    policy = build_governance_policy(
        "personal_local_use",
        requirement_set,
        accepted_formats=["SYNTHETIC"],
        accepted_origin_types=["local"],
    )
    evidence = evidence.model_copy(update={"governance_policy_id": policy.policy_id})
    subject = build_subject(
        artifact_digest="1" * 64,
        artifact_format="SYNTHETIC",
        origin_type="local",
        logical_locator="synthetic/object",
        variant="test",
    )
    evidence = evidence.model_copy(update={"subject_id": subject.subject_id})
    value = build_evaluation_input(subject, policy, [evidence])
    assert (
        evaluate_policy(value, policy).requirement_results[0].outcome
        == RequirementOutcome.NOT_APPLICABLE
    )


def test_freshness_requires_explicit_context() -> None:
    requirement = build_requirement(
        EvidenceCategory.ARTIFACT_IDENTITY,
        accepted_schemas=["omiv.synthetic-artifact-identity.v1"],
        minimum_freshness_seconds=60,
    )
    base = _input("personal")
    from omiv.governance.evaluation import build_governance_policy

    policy = build_governance_policy(
        "personal_local_use",
        build_requirement_set([requirement]),
        accepted_formats=[base.subject.artifact_format],
        accepted_origin_types=[base.subject.origin_type],
    )
    value = build_evaluation_input(base.subject, policy, [base.evidence[0]])
    assert evaluate_policy(value, policy).outcome == DecisionOutcome.DENY
    result = evaluate_policy(value, policy).requirement_results[0]
    assert result.outcome == RequirementOutcome.NOT_EVALUATED


def test_stale_evidence_is_distinct() -> None:
    requirement = build_requirement(
        EvidenceCategory.ARTIFACT_IDENTITY,
        accepted_schemas=["omiv.synthetic-artifact-identity.v1"],
        minimum_freshness_seconds=1,
    )
    base = _input("personal")
    evidence = base.evidence[0].model_copy(update={"observed_at": "2026-08-01T00:00:00Z"})
    from omiv.governance.evaluation import build_governance_policy

    policy = build_governance_policy(
        "personal_local_use",
        build_requirement_set([requirement]),
        accepted_formats=[base.subject.artifact_format],
        accepted_origin_types=[base.subject.origin_type],
    )
    context = build_evaluation_context(
        policy.policy_id, policy.policy_digest, "2026-08-02T00:00:00Z"
    )
    value = build_evaluation_input(base.subject, policy, [evidence], context=context)
    assert evaluate_policy(value, policy).requirement_results[0].outcome == RequirementOutcome.STALE


def test_broken_evidence_has_highest_evidence_precedence() -> None:
    value = _input("intake")
    evidence = [
        item.model_copy(update={"trust_status": "BROKEN"})
        if item.category == EvidenceCategory.SIGNATURE_TRUST
        else item
        for item in value.evidence
    ]
    changed = value.model_copy(update={"evidence": evidence})
    assert evaluate_policy(changed, _policy("intake")).outcome == DecisionOutcome.EVIDENCE_BROKEN


def test_decision_is_deterministic_and_reconstructed() -> None:
    first = build_policy_decision(_input(), _policy())
    second = build_policy_decision(_input(), _policy())
    assert first == second
    assert verify_policy_decision(first, _input(), _policy()) == first


def test_rehashed_false_decision_rejected() -> None:
    decision = build_policy_decision(_input(), _policy())
    raw = decision.model_dump(mode="json", by_alias=True)
    raw["decision_outcome"] = "ALLOW"
    raw.pop("decision_id")
    raw.pop("decision_digest")
    raw["decision_id"] = "decision_" + canonical_sha256(raw)[:32]
    raw["decision_digest"] = canonical_sha256(raw)
    altered = type(decision).model_validate(raw)
    with pytest.raises(OmivInputError):
        verify_policy_decision(altered, _input(), _policy())


def test_later_approval_cannot_be_inserted_into_initial_decision() -> None:
    raw = _raw("governance/examples/intake.policy-decision.json")
    raw["approval_record_ids"] = ["approval_later"]
    with pytest.raises(ValidationError):
        from omiv.governance.models import PolicyDecisionRecord

        PolicyDecisionRecord.model_validate(raw)


def test_reserved_approval_actions_fail_closed() -> None:
    decision = build_policy_decision(_input(), _policy())
    actor = _actor("signer_requester", "key_requester", "root_requester")
    with pytest.raises(OmivInputError):
        build_approval_request(
            decision,
            _policy(),
            requested_action=ApprovalAction.APPROVE_DEPLOYMENT_RESERVED,
            requester_role=GovernanceRole.REQUESTER,
            requester=actor,
            requested_scope="test scope",
        )


def test_approval_request_does_not_imply_approval() -> None:
    request = _raw("governance/examples/team-intake.approval-request.json")
    assert "approval_outcome" not in request
    assert request["limitations"]


@pytest.mark.parametrize(
    "outcome",
    [
        ApprovalOutcome.APPROVED,
        ApprovalOutcome.APPROVED_WITH_CONDITIONS,
        ApprovalOutcome.ABSTAINED,
        ApprovalOutcome.WITHDRAWN,
        ApprovalOutcome.EXPIRED,
        ApprovalOutcome.UNVERIFIED,
    ],
)
def test_approval_outcomes_are_strict(outcome: ApprovalOutcome) -> None:
    request = _raw("governance/examples/team-intake.approval-request.json")
    from omiv.governance.models import ApprovalRequest

    parsed = ApprovalRequest.model_validate(request)
    approval = build_approval_record(
        parsed,
        approver_role=GovernanceRole.APPROVER,
        approver=_actor("signer_approver", "key_approver", "root_approver"),
        outcome=outcome,
        scope="team artifact intake under policy",
    )
    assert approval.outcome == outcome
    assert "deployment" in " ".join(approval.limitations).lower()


@pytest.mark.parametrize(
    "purpose",
    [
        "ATTESTATION_ISSUANCE",
        "PASSPORT_ISSUANCE",
        "POLICY_DECISION_ISSUANCE",
    ],
)
def test_generic_signature_purpose_cannot_form_approval_linkage(purpose: str) -> None:
    with pytest.raises(ValidationError):
        SignedApprovalLinkage(
            envelope_id="soe_example",
            envelope_digest="1" * 64,
            signature_id="sig_example",
            signature_digest="2" * 64,
            signature_integrity="VALID",
            trust_status="TRUSTED_BY_POLICY",
            binding_status="VERIFIED_BY_TRUST_BUNDLE",
            purpose=purpose,  # type: ignore[arg-type]
        )


def test_rejection_signature_is_not_approval() -> None:
    policy = _unsigned_policy()
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    signed = SignedApprovalLinkage(
        envelope_id="soe_example",
        envelope_digest="1" * 64,
        signature_id="sig_example",
        signature_digest="2" * 64,
        signature_integrity="VALID",
        trust_status="TRUSTED_BY_POLICY",
        binding_status="VERIFIED_BY_TRUST_BUNDLE",
        purpose="REJECTION_RECORD_ISSUANCE",
    )
    strict = policy.model_copy(update={"require_signed_approval": True})
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    result = evaluate_quorum(
        strict,
        [approval],
        signed_linkages={approval.approval_id: signed},
        request=request,
        role_assignments=[
            _assignment(approval.approver, approval.approver_role, request.policy_id)
        ],
    )
    assert result.outcome == QuorumOutcome.NOT_SATISFIED


def test_signed_trusted_approval_counts() -> None:
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    envelope = load_envelope(
        ROOT / "governance/examples/signed-team-intake-approval.signed-envelope.json"
    )
    report = load_report(
        ROOT / "reports/governance/signed-team-intake-approval.signature-report.json"
    )
    from omiv.governance.signing import approval_linkage

    linkage = approval_linkage(envelope, report)
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    result = evaluate_quorum(
        _policy().approval_policy,  # type: ignore[arg-type]
        [approval],
        signed_linkages={approval.approval_id: linkage},
        request=request,
        role_assignments=[
            _assignment(approval.approver, approval.approver_role, request.policy_id)
        ],
    )
    assert result.outcome == QuorumOutcome.SATISFIED


def test_quorum_reconstructs_request_scope() -> None:
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    mismatched = approval.model_copy(update={"approval_request_id": "approval_request_wrong"})
    result = evaluate_quorum(
        _unsigned_policy(),
        [mismatched],
        request=request,
        role_assignments=[
            _assignment(approval.approver, approval.approver_role, request.policy_id)
        ],
    )
    assert result.outcome == QuorumOutcome.NOT_SATISFIED
    assert result.counted_approval_ids == []


def test_role_label_without_assignment_does_not_count() -> None:
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    result = evaluate_quorum(_unsigned_policy(), [approval], request=request)
    assert result.outcome == QuorumOutcome.NOT_EVALUATED
    assert result.counted_approval_ids == []


def test_approval_with_different_scope_does_not_count() -> None:
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    wrong_scope = approval.model_copy(update={"scope": "enterprise registry promotion"})
    result = evaluate_quorum(
        _unsigned_policy(),
        [wrong_scope],
        request=request,
        role_assignments=[
            _assignment(approval.approver, approval.approver_role, request.policy_id)
        ],
    )
    assert result.outcome == QuorumOutcome.NOT_SATISFIED


def test_unrelated_rejection_cannot_block_request() -> None:
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    rejection = RejectionRecord.model_validate(
        _raw("governance/examples/team-intake.rejection-record.json")
    )
    unrelated = rejection.model_copy(update={"approval_request_id": "approval_request_wrong"})
    result = evaluate_quorum(
        _unsigned_policy(),
        [],
        [unrelated],
        request=request,
        role_assignments=[
            _assignment(rejection.rejecting_actor, rejection.rejecting_role, request.policy_id)
        ],
    )
    assert result.outcome == QuorumOutcome.NOT_SATISFIED
    assert result.rejected_record_ids == []


def test_untrusted_or_revoked_approver_does_not_count() -> None:
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    revoked = approval.model_copy(
        update={
            "approver": approval.approver.model_copy(
                update={"identity_trust": IdentityTrust.REVOKED}
            )
        }
    )
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    result = evaluate_quorum(
        _policy().approval_policy,  # type: ignore[arg-type]
        [revoked],
        request=request,
        role_assignments=[_assignment(revoked.approver, revoked.approver_role, request.policy_id)],
    )
    assert result.outcome == QuorumOutcome.NOT_SATISFIED


def test_duplicate_approval_does_not_inflate_quorum() -> None:
    approval = ApprovalRecord.model_validate(
        _raw("governance/examples/team-intake.approval-record.json")
    )
    policy = _unsigned_policy()
    policy = policy.model_copy(
        update={"quorum": build_quorum(minimum_count=2, minimum_distinct_signers=2)}
    )
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    result = evaluate_quorum(
        policy,
        [approval, approval],
        request=request,
        role_assignments=[
            _assignment(approval.approver, approval.approver_role, request.policy_id)
        ],
    )
    assert result.outcome == QuorumOutcome.PARTIAL
    assert len(result.counted_approval_ids) == 1


def test_rejection_blocks_quorum_without_revocation() -> None:
    result = _raw("governance/examples/team-intake.rejection-quorum-result.json")
    assert result["outcome"] == "BLOCKED_BY_REJECTION"
    rejection = _raw("governance/examples/team-intake.rejection-record.json")
    assert "revocation" not in json.dumps(rejection).lower()


def test_self_approval_and_same_key_are_violations() -> None:
    result = _raw("governance/examples/team-intake.self-approval-separation-result.json")
    assert result["outcome"] == "VIOLATED"
    assert "REQUESTER_KEY_IS_APPROVER_KEY" in result["violations"]


@pytest.mark.parametrize(
    ("dimension", "field"),
    [
        (IndependenceDimension.DISTINCT_SIGNER_IDENTITY, "signer_identity_id"),
        (IndependenceDimension.DISTINCT_KEY, "key_id"),
        (IndependenceDimension.DISTINCT_TRUST_ROOT, "trust_root_id"),
        (IndependenceDimension.DISTINCT_ORGANIZATION, "organization_id"),
    ],
)
def test_independence_dimensions_detect_shared_identity(
    dimension: IndependenceDimension, field: str
) -> None:
    from omiv.governance.models import ApprovalRequest

    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    actor = _actor("same", "same-key", "same-root")
    actor2 = actor.model_copy(update={field: getattr(actor, field)})
    approvals = [
        build_approval_record(
            request,
            approver_role=GovernanceRole.APPROVER,
            approver=item,
            outcome=ApprovalOutcome.APPROVED,
            scope="test",
        )
        for item in (actor, actor2)
    ]
    policy = build_separation_policy(required_independence=[dimension])
    assert (
        evaluate_separation_of_duties(policy, request, approvals).outcome
        == SeparationOutcome.VIOLATED
    )


def test_unknown_identity_is_insufficient() -> None:
    from omiv.governance.models import ApprovalRequest

    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    unknown = ApprovalActorReference(identity_trust=IdentityTrust.UNAVAILABLE)
    approval = build_approval_record(
        request,
        approver_role=GovernanceRole.APPROVER,
        approver=unknown,
        outcome=ApprovalOutcome.APPROVED,
        scope="test",
    )
    policy = build_separation_policy()
    result = evaluate_separation_of_duties(policy, request, [approval])
    assert result.outcome == SeparationOutcome.INSUFFICIENT_IDENTITY_EVIDENCE


def test_declared_identity_is_insufficient_and_distinct_trusted_actors_pass() -> None:
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    declared = _actor("declared", "declared-key", "declared-root").model_copy(
        update={"identity_trust": IdentityTrust.DECLARED}
    )
    approval = build_approval_record(
        request,
        approver_role=GovernanceRole.APPROVER,
        approver=declared,
        outcome=ApprovalOutcome.APPROVED,
        scope=request.requested_scope,
    )
    assert (
        evaluate_separation_of_duties(build_separation_policy(), request, [approval]).outcome
        == SeparationOutcome.INSUFFICIENT_IDENTITY_EVIDENCE
    )
    generated = _raw("governance/examples/team-intake.separation-result.json")
    assert generated["outcome"] == "SATISFIED"


def test_conflicting_transformer_approver_role_assignment_is_violated() -> None:
    request = ApprovalRequest.model_validate(
        _raw("governance/examples/team-intake.approval-request.json")
    )
    actor = _actor("conflicted", "conflicted-key", "conflicted-root")
    approval = build_approval_record(
        request,
        approver_role=GovernanceRole.APPROVER,
        approver=actor,
        outcome=ApprovalOutcome.APPROVED,
        scope=request.requested_scope,
    )
    assignments = [
        _assignment(actor, GovernanceRole.APPROVER, request.policy_id),
        _assignment(actor, GovernanceRole.TRANSFORMER, request.policy_id),
    ]
    result = evaluate_separation_of_duties(
        build_separation_policy(), request, [approval], assignments
    )
    assert result.outcome == SeparationOutcome.VIOLATED
    assert "TRANSFORMER_IS_APPROVER" in result.violations


def test_promotion_outcomes_and_security_fail_closed() -> None:
    team = _raw("governance/examples/team.promotion-decision.json")
    enterprise = _raw("governance/examples/enterprise.promotion-decision.json")
    assert team["gate_result"]["outcome"] == "PROMOTION_ALLOWED_WITH_CONDITIONS"
    assert enterprise["gate_result"]["outcome"] == "PROMOTION_DENIED"
    assert "ARTIFACT_SECURITY_EVIDENCE_MISSING" in enterprise["blockers"]
    assert "REVOCATION_EVALUATION_MISSING" in enterprise["blockers"]
    assert "EXPIRATION_EVALUATION_MISSING" in enterprise["blockers"]


def test_promotion_has_no_external_side_effect_fields() -> None:
    text = (ROOT / "governance/examples/team.promotion-decision.json").read_text()
    for forbidden in ("upload_url", "registry_endpoint", "credential", "deployment_id"):
        assert forbidden not in text
    assert '"promotion_performed": "NO"' in text


def test_target_types_are_generic() -> None:
    subject = _input().subject
    assert subject.origin_type == "internal_registry"
    for origin in ("local", "s3", "oci", "internal_registry", "air_gapped", "other"):
        assert (
            build_subject(
                artifact_digest=subject.artifact_digest,
                artifact_format="GGUF",
                origin_type=origin,
                logical_locator=f"generic/{origin}/artifact",
                variant="Q4",
            ).origin_type
            == origin
        )


def test_governance_core_has_no_model_pack_or_kimi_dependency() -> None:
    for path in (ROOT / "src/omiv/governance").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "omiv.model_packs" not in text
        assert "kimi_k3" not in text.lower()


def test_signed_governance_object_uses_phase5d_domain_separation() -> None:
    envelope = load_envelope(
        ROOT / "governance/examples/signed-team-intake-decision.signed-envelope.json"
    )
    report = load_report(
        ROOT / "reports/governance/signed-team-intake-decision.signature-report.json"
    )
    assert envelope.signed_object_type == SignedObjectType.POLICY_DECISION
    assert envelope.signatures[0].payload.domain == "OMIV-SIGNED-OBJECT-V1"
    assert report.signature_results[0].signature_integrity == SignatureIntegrity.VALID
    assert report.content_independently_proven is False
    assert report.security_status == "NOT_CHECKED"
    assert report.approval_status == "NOT_AVAILABLE"


@pytest.mark.parametrize(
    ("name", "object_type", "purpose"),
    [
        (
            "team-intake-rejection",
            SignedObjectType.REJECTION_RECORD,
            "REJECTION_RECORD_ISSUANCE",
        ),
        (
            "team-release-candidate",
            SignedObjectType.RELEASE_CANDIDATE,
            "RELEASE_CANDIDATE_ISSUANCE",
        ),
        (
            "team-promotion-decision",
            SignedObjectType.PROMOTION_DECISION,
            "PROMOTION_DECISION_ISSUANCE",
        ),
    ],
)
def test_additional_signed_governance_objects_verify(
    name: str, object_type: SignedObjectType, purpose: str
) -> None:
    envelope = load_envelope(ROOT / f"governance/examples/signed-{name}.signed-envelope.json")
    report = load_report(ROOT / f"reports/governance/signed-{name}.signature-report.json")
    assert envelope.signed_object_type == object_type
    assert envelope.signatures[0].purpose.value == purpose
    assert report.signature_results[0].signature_integrity == SignatureIntegrity.VALID
    assert report.overall_status == "TRUSTED_SIGNATURE_WITH_LIMITATIONS"


def test_signing_did_not_modify_governance_object() -> None:
    decision = _raw("governance/examples/intake.policy-decision.json")
    envelope = _raw("governance/examples/signed-team-intake-decision.signed-envelope.json")
    assert canonical_json_bytes(decision) == canonical_json_bytes(envelope["signed_object"])


def test_passport_summary_is_separate_and_qualified() -> None:
    summary = _raw("governance/examples/team.passport-governance-summary.json")
    assert summary["security_status"] == "NOT_CHECKED"
    assert summary["deployment_status"] == "NOT_PERFORMED"
    assert summary["runtime_status"] == "NOT_CHECKED"
    assert "team artifact intake" in summary["approval_scope"]


def test_custody_linkage_does_not_claim_actual_promotion() -> None:
    linkage = _raw("governance/examples/team.custody-governance-linkage.json")
    assert linkage["event_type"] == "PROMOTION_AUTHORIZED"
    assert linkage["lifecycle_completeness"] == "UNCHANGED_INCOMPLETE"
    assert "ARTIFACT_PROMOTED" not in json.dumps(linkage)
    assert "DEPLOYMENT_RECORDED" not in json.dumps(linkage)


def test_report_is_deterministic_and_qualified() -> None:
    decision = build_policy_decision(_input(), _policy())
    first = build_governance_report(decision)
    second = build_governance_report(decision)
    assert first == second
    markdown = render_markdown(first)
    assert first.security_status == "NOT_CHECKED"
    assert "Registry write: **NOT_PERFORMED**" in markdown
    assert "Promotion performed: **NO**" in markdown
    assert "Deployment performed: **NOT_PERFORMED**" in markdown
    assert "Runtime observation: **NOT_CHECKED**" in markdown
    assert "does not independently prove underlying claims" in markdown


def test_rehashed_false_report_rejected() -> None:
    decision = build_policy_decision(_input("personal"), _policy("personal"))
    report = build_governance_report(decision)
    raw = report.model_dump(mode="json", by_alias=True)
    raw["decision_outcome"] = "ALLOW"
    raw.pop("report_id")
    raw.pop("report_digest")
    raw["report_id"] = "governance_report_" + canonical_sha256(raw)[:32]
    raw["report_digest"] = canonical_sha256(raw)
    altered = type(report).model_validate(raw)
    with pytest.raises(OmivInputError):
        verify_governance_report(altered, decision)


def test_generated_examples_reproduce_byte_for_byte(tmp_path: Path) -> None:
    paths = generate(ROOT, tmp_path)
    assert len(paths) == 71
    assert sum(path.suffix == ".json" for path in paths) == 61
    assert sum(path.suffix == ".md" for path in paths) == 10
    for path in paths:
        relative = path.relative_to(tmp_path)
        assert path.read_bytes() == (ROOT / relative).read_bytes()


def test_artifact_index_reconstructs_generated_files() -> None:
    import hashlib

    index = _raw("governance/artifact-index.json")
    assert len(index["artifacts"]) == 70
    for entry in index["artifacts"]:  # type: ignore[union-attr]
        path = ROOT / entry["relative_path"]
        content = path.read_bytes()
        assert len(content) == entry["size_bytes"]
        assert hashlib.sha256(content).hexdigest() == entry["sha256"]


def test_generated_artifacts_exclude_test_seeds_and_private_keys() -> None:
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (ROOT / "governance", ROOT / "reports/governance")
        for path in root.rglob("*")
        if path.is_file()
    )
    assert RFC8032_VECTOR_1 not in text
    assert RFC8032_VECTOR_2 not in text
    assert "BEGIN PRIVATE KEY" not in text


def test_no_kimi_approval_or_promotion_fixture() -> None:
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (ROOT / "governance", ROOT / "reports/governance")
        for path in root.rglob("*")
        if path.is_file()
    ).lower()
    assert "kimi" not in text
    assert "moonshot" not in text
    assert "unsloth" not in text


def test_cli_evaluate_decision_show_and_verify(tmp_path: Path) -> None:
    runner = CliRunner()
    decision = tmp_path / "decision.json"
    report = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "governance",
            "evaluate",
            "--input",
            str(ROOT / "governance/examples/personal.policy-evaluation-input.json"),
            "--policy",
            str(ROOT / "governance/examples/personal.governance-policy.json"),
            "--output",
            str(decision),
            "--report-output",
            str(report),
            "--markdown-output",
            str(markdown),
        ],
    )
    assert result.exit_code == 1
    shown = runner.invoke(app, ["governance", "decision-show", "--input", str(decision)])
    assert shown.exit_code == 0
    assert "Approval: NOT_INFERRED" in shown.output
    verified = runner.invoke(
        app,
        [
            "governance",
            "decision-verify",
            "--decision",
            str(decision),
            "--input",
            str(ROOT / "governance/examples/personal.policy-evaluation-input.json"),
            "--policy",
            str(ROOT / "governance/examples/personal.governance-policy.json"),
        ],
    )
    assert verified.exit_code == 0
    report_verified = runner.invoke(
        app,
        [
            "governance",
            "report-verify",
            "--report",
            str(report),
            "--decision",
            str(decision),
        ],
    )
    assert report_verified.exit_code == 0


def test_cli_approval_commands_and_unsigned_exit(tmp_path: Path) -> None:
    runner = CliRunner()
    shown = runner.invoke(
        app,
        [
            "governance",
            "approval-show",
            "--input",
            str(ROOT / "governance/examples/team-intake.approval-record.json"),
        ],
    )
    assert shown.exit_code == 0
    assert "Deployment: NOT_PERFORMED" in shown.output
    verified = runner.invoke(
        app,
        [
            "governance",
            "approval-verify",
            "--input",
            str(ROOT / "governance/examples/team-intake.approval-record.json"),
            "--request",
            str(ROOT / "governance/examples/team-intake.approval-request.json"),
            "--policy",
            str(ROOT / "governance/examples/intake.governance-policy.json"),
        ],
    )
    assert verified.exit_code == 1
    assert "signature_trusted=NOT_EVALUATED" in verified.output
    signed_verified = runner.invoke(
        app,
        [
            "governance",
            "approval-verify",
            "--input",
            str(ROOT / "governance/examples/team-intake.approval-record.json"),
            "--request",
            str(ROOT / "governance/examples/team-intake.approval-request.json"),
            "--policy",
            str(ROOT / "governance/examples/intake.governance-policy.json"),
            "--envelope",
            str(ROOT / "governance/examples/signed-team-intake-approval.signed-envelope.json"),
            "--trust-bundle",
            str(ROOT / "governance/examples/governance-trust-bundle.json"),
            "--trust-policy",
            str(ROOT / "governance/examples/governance-trust-policy.json"),
        ],
    )
    assert signed_verified.exit_code == 0
    assert "signature_trusted=YES" in signed_verified.output

    request = tmp_path / "request.json"
    created_request = runner.invoke(
        app,
        [
            "governance",
            "approval-request-create",
            "--input",
            str(ROOT / "governance/examples/team-intake.approval-request-input.json"),
            "--decision",
            str(ROOT / "governance/examples/intake.policy-decision.json"),
            "--policy",
            str(ROOT / "governance/examples/intake.governance-policy.json"),
            "--output",
            str(request),
        ],
    )
    assert created_request.exit_code == 0
    approval = tmp_path / "approval.json"
    created_approval = runner.invoke(
        app,
        [
            "governance",
            "approval-create",
            "--request",
            str(request),
            "--input",
            str(ROOT / "governance/examples/team-intake.approval-input.json"),
            "--output",
            str(approval),
        ],
    )
    assert created_approval.exit_code == 0
    assert (
        approval.read_bytes()
        == (ROOT / "governance/examples/team-intake.approval-record.json").read_bytes()
    )


def test_cli_promotion_denial_has_no_side_effect(tmp_path: Path) -> None:
    output = tmp_path / "promotion.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "governance",
            "promotion-evaluate",
            "--candidate",
            str(ROOT / "governance/examples/enterprise.release-candidate.json"),
            "--target",
            str(ROOT / "governance/examples/enterprise.promotion-target.json"),
            "--policy",
            str(ROOT / "governance/examples/enterprise.promotion-gate-policy.json"),
            "--decision",
            str(ROOT / "governance/examples/enterprise.policy-decision.json"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert "registry_write=NOT_PERFORMED" in result.output
    assert json.loads(output.read_text())["gate_result"]["outcome"] == "PROMOTION_DENIED"
    verified = runner.invoke(
        app,
        [
            "governance",
            "promotion-verify",
            "--input",
            str(output),
            "--candidate",
            str(ROOT / "governance/examples/enterprise.release-candidate.json"),
            "--target",
            str(ROOT / "governance/examples/enterprise.promotion-target.json"),
            "--policy",
            str(ROOT / "governance/examples/enterprise.promotion-gate-policy.json"),
            "--decision",
            str(ROOT / "governance/examples/enterprise.policy-decision.json"),
        ],
    )
    assert verified.exit_code == 0
    assert "action_performed=NO" in verified.output


def test_cli_reconstructs_enriched_governance_report() -> None:
    result = CliRunner().invoke(
        app,
        [
            "governance",
            "report-verify",
            "--report",
            str(ROOT / "reports/governance/intake.governance-report.json"),
            "--decision",
            str(ROOT / "governance/examples/intake.policy-decision.json"),
            "--approval-request",
            str(ROOT / "governance/examples/team-intake.approval-request.json"),
            "--approval",
            str(ROOT / "governance/examples/team-intake.approval-record.json"),
            "--quorum",
            str(ROOT / "governance/examples/team-intake.quorum-result.json"),
            "--separation",
            str(ROOT / "governance/examples/team-intake.separation-result.json"),
            "--target",
            str(ROOT / "governance/examples/team.promotion-target.json"),
            "--promotion",
            str(ROOT / "governance/examples/team.promotion-decision.json"),
        ],
    )
    assert result.exit_code == 0


def test_no_network_or_registry_implementation_in_governance_core() -> None:
    text = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "src/omiv/governance").glob("*.py")
    )
    for forbidden in (
        "requests.",
        "httpx.",
        "urllib.request",
        "boto3",
        "kubectl",
        "docker push",
        "webhook",
    ):
        assert forbidden not in text
