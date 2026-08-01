"""Phase 5D signing bridge for governance objects and external trust linkages."""

from __future__ import annotations

from omiv.errors import OmivInputError
from omiv.governance.models import SignedApprovalLinkage, SignedDecisionLinkage
from omiv.trust.models import (
    SignatureIntegrity,
    SignatureReport,
    SignedObjectEnvelope,
    SignedObjectType,
    TrustPolicyStatus,
)


def _trusted_result(report: SignatureReport) -> object:
    if len(report.signature_results) != 1:
        raise OmivInputError(
            "governance linkage requires exactly one independently evaluated signature"
        )
    result = report.signature_results[0]
    if result.signature_integrity != SignatureIntegrity.VALID:
        raise OmivInputError("governance object signature integrity is not valid")
    return result


def decision_linkage(
    envelope: SignedObjectEnvelope, report: SignatureReport
) -> SignedDecisionLinkage:
    if envelope.signed_object_type not in {
        SignedObjectType.POLICY_DECISION,
        SignedObjectType.PROMOTION_DECISION,
    }:
        raise OmivInputError("signed object is not a policy or promotion decision")
    if (
        report.envelope_id != envelope.envelope_id
        or report.envelope_digest != envelope.envelope_digest
    ):
        raise OmivInputError("signature report does not reference the supplied envelope")
    result = _trusted_result(report)
    record = envelope.signatures[0]
    return SignedDecisionLinkage.model_validate(
        {
            "envelope_id": envelope.envelope_id,
            "envelope_digest": envelope.envelope_digest,
            "signature_id": record.signature_id,
            "signature_digest": record.signature_digest,
            "signature_integrity": result.signature_integrity.value,  # type: ignore[attr-defined]
            "trust_status": result.trust_policy_status.value,  # type: ignore[attr-defined]
            "purpose": record.purpose.value,
        }
    )


def approval_linkage(
    envelope: SignedObjectEnvelope, report: SignatureReport
) -> SignedApprovalLinkage:
    if envelope.signed_object_type not in {
        SignedObjectType.APPROVAL_RECORD,
        SignedObjectType.REJECTION_RECORD,
    }:
        raise OmivInputError("signed object is not an approval or rejection record")
    if (
        report.envelope_id != envelope.envelope_id
        or report.envelope_digest != envelope.envelope_digest
    ):
        raise OmivInputError("signature report does not reference the supplied envelope")
    result = _trusted_result(report)
    record = envelope.signatures[0]
    trust_status = result.trust_policy_status.value  # type: ignore[attr-defined]
    if result.trust_policy_status != TrustPolicyStatus.TRUSTED_BY_POLICY:  # type: ignore[attr-defined]
        trust_status = "UNTRUSTED_BY_POLICY"
    return SignedApprovalLinkage.model_validate(
        {
            "envelope_id": envelope.envelope_id,
            "envelope_digest": envelope.envelope_digest,
            "signature_id": record.signature_id,
            "signature_digest": record.signature_digest,
            "signature_integrity": result.signature_integrity.value,  # type: ignore[attr-defined]
            "trust_status": trust_status,
            "binding_status": (result.signer_binding_status or result.signer_binding).value,  # type: ignore[attr-defined]
            "purpose": record.purpose.value,
        }
    )
