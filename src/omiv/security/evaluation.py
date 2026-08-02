"""Fail-closed reconstruction of layered Phase 5F security verdicts."""

from __future__ import annotations

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.security.building import identified
from omiv.security.models import (
    CoverageResult,
    CoverageStatus,
    FindingConfidence,
    FindingResult,
    FindingSeverity,
    FindingStatus,
    InspectionIntegrity,
    ScannerTrust,
    SecurityEvaluationResult,
    SecurityEvidenceBundle,
    SecurityEvidencePolicy,
    SecurityRequirementProfile,
    SecurityVerdict,
)
from omiv.trust.models import OverallSignedObjectStatus, SignatureReport, SignedObjectType

CONFIDENCE_RANK = {
    FindingConfidence.UNKNOWN: 0,
    FindingConfidence.HEURISTIC: 1,
    FindingConfidence.LOW: 2,
    FindingConfidence.MEDIUM: 3,
    FindingConfidence.HIGH: 4,
    FindingConfidence.CONFIRMED: 5,
}


def evaluate_security_bundle(
    bundle: SecurityEvidenceBundle,
    policy: SecurityEvidencePolicy,
    *,
    signature_report: SignatureReport | None = None,
    evaluation_context_digest: str | None = None,
) -> SecurityEvaluationResult:
    """Reconstruct a scope-limited verdict; callers cannot supply the verdict."""
    try:
        bundle = SecurityEvidenceBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        policy = SecurityEvidencePolicy.model_validate(
            policy.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise OmivInputError(f"security evidence is broken: {exc}") from exc
    signature_trust = "NOT_EVALUATED"
    if signature_report is not None:
        if (
            signature_report.signed_object_type != SignedObjectType.SECURITY_EVIDENCE_BUNDLE
            or signature_report.signed_object_id != bundle.bundle_id
            or signature_report.signed_object_digest
            != canonical_sha256(bundle.model_dump(mode="json", by_alias=True))
        ):
            raise OmivInputError("signature report does not cover the supplied security bundle")
        signature_trust = (
            "TRUSTED_BY_POLICY"
            if signature_report.overall_status
            == OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS
            else "UNTRUSTED_BY_POLICY"
        )
    scanners = bundle.scanner_identities
    scanner_ids_accepted = bool(scanners) and all(
        not policy.accepted_scanner_ids or scanner.scanner_id in policy.accepted_scanner_ids
        for scanner in scanners
    )
    candidate_scanner_trust = (
        ScannerTrust.TRUSTED_BY_POLICY if scanner_ids_accepted else ScannerTrust.UNTRUSTED_BY_POLICY
    )
    accepted = candidate_scanner_trust in policy.accepted_scanner_trust_levels
    scanner_trust = ScannerTrust.TRUSTED_BY_POLICY if accepted else ScannerTrust.UNTRUSTED_BY_POLICY
    executed = {method for record in bundle.execution_records for method in record.methods_executed}
    methods_ok = set(policy.required_methods).issubset(executed)
    coverage_map = {
        CoverageStatus.COMPLETE_FOR_DECLARED_SCOPE: CoverageResult.COMPLETE,
        CoverageStatus.PARTIAL: CoverageResult.PARTIAL,
        CoverageStatus.INCOMPLETE: CoverageResult.INCOMPLETE,
        CoverageStatus.UNSUPPORTED: CoverageResult.UNSUPPORTED,
        CoverageStatus.FAILED: CoverageResult.FAILED,
        CoverageStatus.NOT_ASSESSED: CoverageResult.NOT_EVALUATED,
    }
    coverage = coverage_map[bundle.coverage.status]
    if any(record.status.value == "LIMIT_EXCEEDED" for record in bundle.execution_records):
        coverage = CoverageResult.INCOMPLETE
    elif any(record.status.value == "FAILED" for record in bundle.execution_records):
        coverage = CoverageResult.FAILED
    strict_complete = policy.required_coverage == CoverageStatus.COMPLETE_FOR_DECLARED_SCOPE
    coverage_ok = (
        coverage == CoverageResult.COMPLETE
        if strict_complete
        else coverage in {CoverageResult.COMPLETE, CoverageResult.PARTIAL}
    )
    coverage_problem = (
        not coverage_ok or len(bundle.unsupported_items) > policy.allowed_unsupported_items
    )
    coverage_limitation_permitted = (
        coverage_problem and policy.incomplete_coverage_behavior == "ALLOW_WITH_LIMITATIONS"
    )
    active_findings = [
        item
        for item in bundle.findings
        if item.status
        not in {FindingStatus.FALSE_POSITIVE, FindingStatus.MITIGATED, FindingStatus.NOT_APPLICABLE}
    ]
    blocking = []
    for finding in active_findings:
        confidence_ok = (
            CONFIDENCE_RANK[finding.confidence]
            >= CONFIDENCE_RANK[policy.minimum_blocking_confidence]
        )
        blocks = (
            finding.category in policy.blocking_categories
            or finding.severity in policy.blocking_severities
            or finding.exploitability in policy.blocking_exploitability
        ) and confidence_ok
        if blocks:
            blocking.append(finding.finding_id)
    unknown = any(
        item.severity == FindingSeverity.UNKNOWN or item.confidence == FindingConfidence.UNKNOWN
        for item in active_findings
    )
    accepted_risk = any(item.status == FindingStatus.ACCEPTED_RISK for item in active_findings)
    if blocking:
        finding_result = FindingResult.BLOCKING_FINDINGS_PRESENT
    elif unknown:
        finding_result = FindingResult.UNKNOWN_FINDINGS_PRESENT
    elif active_findings:
        finding_result = FindingResult.NON_BLOCKING_FINDINGS_PRESENT
    else:
        finding_result = FindingResult.NO_BLOCKING_FINDINGS
    errors = len(bundle.scan_errors)
    blockers: list[str] = []
    limitations = sorted({*bundle.limitations, *policy.limitations})
    uninspected = sorted(
        item.logical_path
        for item in bundle.coverage.items
        if item.status.value != "INSPECTED" or item.inspected_bytes < item.declared_bytes
    )
    if policy.fail_closed_reserved:
        verdict = SecurityVerdict.FAIL
        blockers.append("regulated profile is reserved and fails closed in Phase 5F")
    elif blocking:
        verdict = SecurityVerdict.FAIL
        blockers.append("blocking security findings are present")
    elif errors > policy.maximum_scanner_errors:
        verdict = SecurityVerdict.FAIL
        blockers.append("scanner errors exceed policy maximum")
    elif not accepted:
        verdict = SecurityVerdict.SCANNER_UNTRUSTED
        blockers.append("required scanner is not accepted by policy")
    elif policy.signed_evidence_required and signature_trust != "TRUSTED_BY_POLICY":
        verdict = SecurityVerdict.SCANNER_UNTRUSTED
        blockers.append("trusted signed security evidence is required")
    elif policy.freshness_seconds is not None:
        verdict = SecurityVerdict.NOT_EVALUATED
        blockers.append(
            "freshness cannot be established without an explicit typed temporal context"
        )
    elif coverage_problem and not coverage_limitation_permitted:
        if policy.incomplete_coverage_behavior == "REVIEW":
            verdict = SecurityVerdict.REVIEW_REQUIRED
            blockers.append("incomplete or unsupported coverage requires review")
        else:
            verdict = SecurityVerdict.COVERAGE_INCOMPLETE
            blockers.append("mandatory coverage is incomplete or unsupported")
    elif not methods_ok:
        verdict = SecurityVerdict.NOT_EVALUATED
        blockers.append("required inspection methods were not executed")
    elif unknown:
        if policy.unknown_finding_behavior == "ALLOW_WITH_LIMITATIONS":
            verdict = SecurityVerdict.PASS_WITH_LIMITATIONS
            limitations.append("Policy permits unknown findings with explicit limitations.")
        elif policy.unknown_finding_behavior == "REVIEW":
            verdict = SecurityVerdict.REVIEW_REQUIRED
            blockers.append("unknown findings require review")
        else:
            verdict = SecurityVerdict.FAIL
            blockers.append("unknown findings fail the selected policy")
    elif accepted_risk:
        if policy.accepted_risk_behavior == "ALLOW_WITH_LIMITATIONS":
            verdict = SecurityVerdict.PASS_WITH_LIMITATIONS
            limitations.append("Policy permits governed accepted risk with limitations.")
        elif policy.accepted_risk_behavior == "REVIEW":
            verdict = SecurityVerdict.REVIEW_REQUIRED
            blockers.append("accepted-risk findings require review")
        else:
            verdict = SecurityVerdict.FAIL
            blockers.append("accepted-risk findings fail the selected policy")
    elif active_findings:
        verdict = SecurityVerdict.REVIEW_REQUIRED
        blockers.append("non-blocking findings require review")
    elif coverage_limitation_permitted:
        verdict = SecurityVerdict.PASS_WITH_LIMITATIONS
        limitations.append("Policy permits incomplete coverage with explicit limitations.")
    elif (
        bundle.coverage.status != CoverageStatus.COMPLETE_FOR_DECLARED_SCOPE
        or policy.profile == SecurityRequirementProfile.PERSONAL_LOCAL_SECURITY_REVIEW
    ):
        verdict = SecurityVerdict.PASS_WITH_LIMITATIONS
        limitations.append("Policy permits a scope-limited result with explicit limitations.")
    else:
        verdict = SecurityVerdict.PASS
    body = {
        "schema": "omiv.security-evaluation.v1",
        "subject_identity_digest": bundle.subject.identity_digest,
        "bundle_id": bundle.bundle_id,
        "bundle_digest": bundle.bundle_digest,
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest,
        "evaluation_context_digest": evaluation_context_digest,
        "inspection_integrity": InspectionIntegrity.VALID.value,
        "scanner_identity_status": "KNOWN",
        "scan_execution_integrity": InspectionIntegrity.VALID.value,
        "scanner_trust": scanner_trust.value,
        "signature_trust": signature_trust,
        "scanner_correctness_independently_proven": "NOT_ESTABLISHED",
        "coverage_result": coverage.value,
        "finding_result": finding_result.value,
        "required_methods_satisfied": methods_ok,
        "unresolved_error_count": errors,
        "blocking_finding_ids": sorted(blocking),
        "verdict": verdict.value,
        "blockers": sorted(blockers),
        "limitations": sorted(set(limitations)),
        "uninspected_scope": uninspected,
    }
    return SecurityEvaluationResult.model_validate(
        identified(body, "evaluation_id", "security_eval_", "evaluation_digest")
    )


def verify_security_evaluation(
    observed: SecurityEvaluationResult,
    bundle: SecurityEvidenceBundle,
    policy: SecurityEvidencePolicy,
    *,
    signature_report: SignatureReport | None = None,
) -> SecurityEvaluationResult:
    expected = evaluate_security_bundle(
        bundle,
        policy,
        signature_report=signature_report,
        evaluation_context_digest=observed.evaluation_context_digest,
    )
    if expected != observed:
        raise OmivInputError("security evaluation does not match deterministic reconstruction")
    return observed
