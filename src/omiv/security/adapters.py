"""Strict external-result, governance, Passport, and custody adapters."""

from __future__ import annotations

from typing import Any

from omiv.errors import OmivInputError
from omiv.governance.models import (
    EvidenceCategory,
    EvidenceReference,
    GovernanceSubject,
    ReferenceAvailability,
    RequirementOutcome,
    VerificationMode,
)
from omiv.security.building import identified
from omiv.security.evaluation import verify_security_evaluation
from omiv.security.models import (
    CoverageResult,
    CustodySecurityLinkage,
    FindingSeverity,
    GovernanceSecurityEvidenceAdapter,
    PassportSecuritySummary,
    ScannerTrust,
    SecurityEvaluationResult,
    SecurityEvidenceBundle,
    SecurityEvidencePolicy,
    SecurityVerdict,
)
from omiv.trust.models import SignatureReport


def import_external_result(value: dict[str, Any]) -> SecurityEvidenceBundle:
    """Import only a complete normalized local result, never a scanner PASS string."""
    if value.get("schema") != "omiv.security-evidence-bundle.v1":
        raise OmivInputError("unknown external scanner-result schema")
    if any(key in value for key in ("pass", "passed", "safe", "malware_free")):
        raise OmivInputError("arbitrary scanner summary cannot replace findings and coverage")
    try:
        return SecurityEvidenceBundle.model_validate(value)
    except ValueError as exc:
        raise OmivInputError(f"invalid normalized external scanner result: {exc}") from exc


def adapt_governance_security_evidence(
    subject: GovernanceSubject,
    bundle: SecurityEvidenceBundle,
    evaluation: SecurityEvaluationResult,
    policy: SecurityEvidencePolicy,
    *,
    signature_report: SignatureReport | None = None,
) -> tuple[GovernanceSecurityEvidenceAdapter, EvidenceReference]:
    verify_security_evaluation(
        evaluation,
        bundle,
        policy,
        signature_report=signature_report,
    )
    if evaluation.bundle_digest != bundle.bundle_digest:
        raise OmivInputError("governance adapter bundle digest mismatch")
    if evaluation.subject_identity_digest != bundle.subject.identity_digest:
        raise OmivInputError("governance adapter security subject mismatch")
    subject_digests = {bundle.subject.content_digest, bundle.subject.artifact_set_digest}
    if subject.artifact_digest not in subject_digests:
        raise OmivInputError("governance subject does not match inspected artifact")
    valid_pass = (
        evaluation.verdict == SecurityVerdict.PASS
        and evaluation.coverage_result == CoverageResult.COMPLETE
        and evaluation.scanner_trust == ScannerTrust.TRUSTED_BY_POLICY
        and not evaluation.blocking_finding_ids
        and not evaluation.unresolved_error_count
    )
    limited_pass = (
        evaluation.verdict == SecurityVerdict.PASS_WITH_LIMITATIONS
        and policy.governance_allow_limitations
        and evaluation.coverage_result in {CoverageResult.COMPLETE, CoverageResult.PARTIAL}
        and evaluation.scanner_trust == ScannerTrust.TRUSTED_BY_POLICY
        and not evaluation.blocking_finding_ids
        and not evaluation.unresolved_error_count
    )
    if valid_pass:
        outcome = RequirementOutcome.SATISFIED
    elif limited_pass:
        outcome = RequirementOutcome.SATISFIED_WITH_LIMITATIONS
    elif evaluation.verdict == SecurityVerdict.EVIDENCE_BROKEN:
        outcome = RequirementOutcome.BROKEN
    elif evaluation.verdict == SecurityVerdict.COVERAGE_INCOMPLETE:
        outcome = RequirementOutcome.NOT_CHECKED
    elif evaluation.verdict == SecurityVerdict.NOT_EVALUATED:
        outcome = RequirementOutcome.NOT_EVALUATED
    else:
        outcome = RequirementOutcome.INVALID
    evidence_id = "security_evidence_" + evaluation.evaluation_digest[:32]
    body = {
        "schema": "omiv.governance-security-evidence-adapter.v1",
        "subject_id": subject.subject_id,
        "subject_identity_digest": bundle.subject.identity_digest,
        "evaluation_id": evaluation.evaluation_id,
        "evaluation_digest": evaluation.evaluation_digest,
        "policy_id": evaluation.policy_id,
        "policy_digest": evaluation.policy_digest,
        "requirement_outcome": outcome.value,
        "evidence_reference_id": evidence_id,
        "verdict": evaluation.verdict.value,
        "coverage_result": evaluation.coverage_result.value,
        "scanner_trust": evaluation.scanner_trust.value,
        "signature_trust": evaluation.signature_trust,
        "blocking_findings": len(evaluation.blocking_finding_ids),
        "unresolved_errors": evaluation.unresolved_error_count,
        "limitations": sorted(set(evaluation.limitations)),
    }
    adapter = GovernanceSecurityEvidenceAdapter.model_validate(
        identified(body, "adapter_id", "governance_security_", "adapter_digest")
    )
    satisfied = outcome in {
        RequirementOutcome.SATISFIED,
        RequirementOutcome.SATISFIED_WITH_LIMITATIONS,
    }
    reference = EvidenceReference(
        evidence_id=evidence_id,
        category=EvidenceCategory.SECURITY_INSPECTION,
        schema="omiv.artifact-security-evidence.v1",
        object_id=evaluation.evaluation_id,
        digest=evaluation.evaluation_digest,
        subject_id=subject.subject_id,
        governance_policy_id=evaluation.policy_id,
        availability=ReferenceAvailability.AVAILABLE
        if satisfied
        else ReferenceAvailability.UNAVAILABLE,
        verification_mode=VerificationMode.FULL if satisfied else VerificationMode.NOT_VERIFIED,
        source_phase="5F",
        trust_status=evaluation.scanner_trust.value,
        limitations=adapter.limitations,
    )
    return adapter, reference


def build_passport_security_summary(
    passport: dict[str, Any],
    bundle: SecurityEvidenceBundle,
    evaluation: SecurityEvaluationResult,
) -> PassportSecuritySummary:
    passport_id, passport_digest = passport.get("passport_id"), passport.get("passport_digest")
    if not isinstance(passport_id, str) or not isinstance(passport_digest, str):
        raise OmivInputError("Passport security summary requires canonical Passport identity")
    counts = {
        severity: sum(x.severity == severity for x in bundle.findings)
        for severity in FindingSeverity
    }
    body = {
        "schema": "omiv.passport-security-summary.v1",
        "passport_id": passport_id,
        "passport_digest": passport_digest,
        "subject_identity_digest": bundle.subject.identity_digest,
        "evidence_availability": "AVAILABLE",
        "policy_id": evaluation.policy_id,
        "policy_digest": evaluation.policy_digest,
        "inspection_methods": sorted(
            {m.value for r in bundle.execution_records for m in r.methods_executed}
        ),
        "scanner_ids": sorted(x.scanner_id for x in bundle.scanner_identities),
        "scanner_trust": evaluation.scanner_trust.value,
        "coverage_result": evaluation.coverage_result.value,
        "finding_counts": {x.value: counts[x] for x in FindingSeverity},
        "blocking_finding_count": len(evaluation.blocking_finding_ids),
        "verdict": evaluation.verdict.value,
        "signed_evidence_status": evaluation.signature_trust,
        "freshness_status": "NOT_EVALUATED",
        "payload_integrity": "NOT_VERIFIED",
        "runtime_safety": "NOT_VERIFIED",
        "approval_status": "SEPARATE",
        "deployment_status": "NOT_PERFORMED",
        "limitations": sorted(set(evaluation.limitations)),
        "uninspected_scope": evaluation.uninspected_scope,
        "next_required_evidence": ["payload_integrity", "runtime_verification"],
    }
    return PassportSecuritySummary.model_validate(
        identified(body, "summary_id", "passport_security_", "summary_digest")
    )


def build_custody_security_linkage(
    ledger: dict[str, Any],
    bundle: SecurityEvidenceBundle,
    evaluation: SecurityEvaluationResult | None = None,
) -> CustodySecurityLinkage:
    ledger_id, ledger_digest = ledger.get("chain_id"), ledger.get("ledger_digest")
    if not isinstance(ledger_id, str) or not isinstance(ledger_digest, str):
        raise OmivInputError("custody security linkage requires canonical ledger identity")
    event = "SECURITY_EVALUATION_RECORDED" if evaluation else "SECURITY_INSPECTION_RECORDED"
    body = {
        "schema": "omiv.custody-security-linkage.v1",
        "custody_ledger_id": ledger_id,
        "custody_ledger_digest": ledger_digest,
        "event_type": event,
        "bundle_id": bundle.bundle_id,
        "bundle_digest": bundle.bundle_digest,
        "evaluation_id": evaluation.evaluation_id if evaluation else None,
        "evaluation_digest": evaluation.evaluation_digest if evaluation else None,
        "scanner_ids": sorted(x.scanner_id for x in bundle.scanner_identities),
        "coverage_result": evaluation.coverage_result.value
        if evaluation
        else CoverageResult.NOT_EVALUATED.value,
        "verdict": evaluation.verdict.value if evaluation else SecurityVerdict.NOT_EVALUATED.value,
        "signature_trust_summary": evaluation.signature_trust if evaluation else "NOT_EVALUATED",
        "lifecycle_completeness": "UNCHANGED_INCOMPLETE",
        "limitations": [
            "Security linkage records evidence only; approval, promotion, deployment, "
            "and runtime remain separate."
        ],
    }
    return CustodySecurityLinkage.model_validate(
        identified(body, "linkage_id", "custody_security_", "linkage_digest")
    )
