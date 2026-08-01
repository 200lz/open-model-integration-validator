"""Separate Passport and custody governance linkages; source artifacts stay immutable."""

from __future__ import annotations

from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.governance.models import (
    ApprovalQuorumResult,
    CustodyGovernanceLinkage,
    EvidenceCategory,
    PassportGovernanceSummary,
    PolicyDecisionRecord,
    PromotionDecisionRecord,
    PromotionTarget,
    SeparationOfDutiesResult,
)


def build_passport_summary(
    passport: dict[str, Any],
    decision: PolicyDecisionRecord,
    *,
    approval_scope: str,
    quorum: ApprovalQuorumResult | None = None,
    separation: SeparationOfDutiesResult | None = None,
    target: PromotionTarget | None = None,
    promotion: PromotionDecisionRecord | None = None,
    signed_decision_status: str = "NOT_EVALUATED",
    signed_approval_status: str = "NOT_EVALUATED",
) -> PassportGovernanceSummary:
    passport_id = passport.get("passport_id")
    passport_digest = passport.get("passport_digest")
    if not isinstance(passport_id, str) or not isinstance(passport_digest, str):
        raise OmivInputError("Passport governance summary requires canonical Passport identity")
    blockers = sorted({*decision.blocking_findings, *(promotion.blockers if promotion else [])})
    missing_categories = sorted(
        {item.category for item in decision.missing_evidence.items}, key=lambda item: item.value
    )
    security_result = next(
        (
            item
            for item in decision.requirement_results
            if item.category == EvidenceCategory.SECURITY_INSPECTION
        ),
        None,
    )
    body: dict[str, Any] = {
        "schema": "omiv.passport-governance-summary.v1",
        "passport_id": passport_id,
        "passport_digest": passport_digest,
        "decision_id": decision.decision_id,
        "decision_outcome": decision.decision_outcome.value,
        "policy_id": decision.policy_id,
        "policy_digest": decision.policy_digest,
        "approval_scope": approval_scope,
        "quorum_status": quorum.outcome.value if quorum else None,
        "separation_status": separation.outcome.value if separation else None,
        "promotion_eligibility": (
            promotion.gate_result.outcome.value if promotion else "NOT_EVALUATED"
        ),
        "target_id": target.target_id if target else None,
        "blockers": blockers,
        "missing_evidence": [item.value for item in missing_categories],
        "signed_decision_status": signed_decision_status,
        "signed_approval_status": signed_approval_status,
        "security_status": (
            "MISSING"
            if security_result is not None
            and security_result.outcome.value
            not in {
                "NOT_CHECKED",
                "NOT_APPLICABLE",
                "SATISFIED",
                "SATISFIED_WITH_LIMITATIONS",
            }
            else "NOT_CHECKED"
        ),
        "deployment_status": "NOT_PERFORMED",
        "runtime_status": "NOT_CHECKED",
        "limitations": [
            "This separate summary does not modify the Passport or upgrade its evidence.",
            "Approval and promotion are policy-scoped and do not prove security or deployment.",
        ],
    }
    return PassportGovernanceSummary.model_validate(
        {**body, "summary_digest": canonical_sha256(body)}
    )


def build_custody_linkage(
    ledger: dict[str, Any],
    *,
    event_type: str,
    governance_object_id: str,
    governance_object_digest: str,
) -> CustodyGovernanceLinkage:
    ledger_id = ledger.get("chain_id")
    ledger_digest = ledger.get("ledger_digest")
    if not isinstance(ledger_id, str) or not isinstance(ledger_digest, str):
        raise OmivInputError("custody linkage requires canonical ledger identity")
    body = {
        "schema": "omiv.custody-governance-linkage.v1",
        "custody_ledger_id": ledger_id,
        "custody_ledger_digest": ledger_digest,
        "event_type": event_type,
        "governance_object_id": governance_object_id,
        "governance_object_digest": governance_object_digest,
        "lifecycle_completeness": "UNCHANGED_INCOMPLETE",
        "limitations": [
            "Governance linkage records authorization only; no artifact movement, deployment, "
            "or runtime event occurred."
        ],
    }
    identified = {
        **body,
        "linkage_id": "custody_governance_" + canonical_sha256(body)[:32],
    }
    return CustodyGovernanceLinkage.model_validate(
        {**identified, "linkage_digest": canonical_sha256(identified)}
    )
