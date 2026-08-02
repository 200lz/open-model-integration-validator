"""Static trusted Phase 5F security-policy registry."""

from __future__ import annotations

from omiv.canonical import canonical_sha256
from omiv.security.building import builtin_scanner_identity
from omiv.security.models import (
    CoverageStatus,
    FindingClassification,
    FindingConfidence,
    FindingExploitability,
    FindingSeverity,
    InspectionMethod,
    ScannerTrust,
    SecurityEvidencePolicy,
    SecurityRequirementProfile,
    SecurityVerdict,
)

PRECEDENCE = [
    SecurityVerdict.EVIDENCE_BROKEN,
    SecurityVerdict.FAIL,
    SecurityVerdict.SCANNER_UNTRUSTED,
    SecurityVerdict.COVERAGE_INCOMPLETE,
    SecurityVerdict.NOT_EVALUATED,
    SecurityVerdict.REVIEW_REQUIRED,
    SecurityVerdict.PASS_WITH_LIMITATIONS,
    SecurityVerdict.PASS,
]


def build_security_policy(
    profile: SecurityRequirementProfile | str,
    *,
    accepted_scanner_ids: list[str] | None = None,
) -> SecurityEvidencePolicy:
    profile = SecurityRequirementProfile(profile)
    personal = profile == SecurityRequirementProfile.PERSONAL_LOCAL_SECURITY_REVIEW
    intake = profile == SecurityRequirementProfile.TEAM_ARTIFACT_SECURITY_INTAKE
    strict = profile in {
        SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE,
        SecurityRequirementProfile.ENTERPRISE_ARTIFACT_SECURITY_GATE,
        SecurityRequirementProfile.REGULATED_ARTIFACT_SECURITY_GATE,
    }
    enterprise = profile in {
        SecurityRequirementProfile.ENTERPRISE_ARTIFACT_SECURITY_GATE,
        SecurityRequirementProfile.REGULATED_ARTIFACT_SECURITY_GATE,
    }
    required = [
        InspectionMethod.METADATA_INSPECTION,
        InspectionMethod.FILE_TYPE_POLICY_CHECK,
        InspectionMethod.MAGIC_BYTE_INSPECTION,
        InspectionMethod.STATIC_PATTERN_INSPECTION,
        InspectionMethod.SERIALIZATION_FORMAT_INSPECTION,
    ]
    if strict:
        required.extend(
            [
                InspectionMethod.FORMAT_STRUCTURE_INSPECTION,
                InspectionMethod.SCRIPT_CONTENT_INSPECTION,
                InspectionMethod.EXECUTABLE_CONTENT_INSPECTION,
            ]
        )
    blocking_categories = [
        FindingClassification.UNSAFE_SERIALIZATION_FORMAT,
        FindingClassification.EXECUTABLE_CODE_PRESENT,
        FindingClassification.NATIVE_BINARY_PRESENT,
        FindingClassification.PRIVATE_KEY_MATERIAL_PATTERN,
        FindingClassification.PATH_TRAVERSAL_ENTRY,
        FindingClassification.DEVICE_OR_SPECIAL_FILE,
        FindingClassification.MALFORMED_CONTAINER,
        FindingClassification.SCANNER_ERROR,
    ]
    if strict:
        blocking_categories.extend(
            [
                FindingClassification.SCRIPT_CONTENT_PRESENT,
                FindingClassification.SIGNED_URL_PATTERN,
                FindingClassification.SHELL_EXECUTION_PATTERN,
                FindingClassification.DESERIALIZATION_EXECUTION_PATTERN,
            ]
        )
    policy_id = f"omiv.security-policy.{profile.value}.v1"
    body = {
        "schema": "omiv.security-evidence-policy.v1",
        "policy_id": policy_id,
        "version": 1,
        "profile": profile.value,
        "accepted_scanner_ids": sorted(
            accepted_scanner_ids
            if accepted_scanner_ids is not None
            else [builtin_scanner_identity().scanner_id]
        ),
        "accepted_scanner_trust_levels": [ScannerTrust.TRUSTED_BY_POLICY.value],
        "required_methods": sorted({x.value for x in required}),
        "required_coverage": (
            CoverageStatus.PARTIAL.value
            if personal
            else CoverageStatus.COMPLETE_FOR_DECLARED_SCOPE.value
        ),
        "allowed_unsupported_items": 1 if personal else 0,
        "blocking_severities": [FindingSeverity.CRITICAL.value, FindingSeverity.HIGH.value]
        + ([FindingSeverity.MEDIUM.value] if strict else []),
        "blocking_categories": sorted({x.value for x in blocking_categories}),
        "minimum_blocking_confidence": FindingConfidence.LOW.value,
        "blocking_exploitability": sorted(
            x.value
            for x in FindingExploitability
            if x
            not in {
                FindingExploitability.NOT_APPLICABLE,
            }
        ),
        "maximum_scanner_errors": 0,
        "unknown_finding_behavior": "REVIEW" if personal else "FAIL",
        "incomplete_coverage_behavior": "ALLOW_WITH_LIMITATIONS" if personal else "FAIL",
        "accepted_risk_behavior": "REVIEW",
        "freshness_seconds": None,
        "signed_evidence_required": enterprise,
        "fail_closed_reserved": profile
        == SecurityRequirementProfile.REGULATED_ARTIFACT_SECURITY_GATE,
        "decision_precedence": [x.value for x in PRECEDENCE],
        "governance_allow_limitations": personal or intake,
        "limitations": [
            "A policy PASS is scoped to supplied verified evidence and declared methods.",
            "Policy evaluation does not establish payload integrity, runtime safety, approval, "
            "or deployment.",
        ],
    }
    return SecurityEvidencePolicy.model_validate({**body, "policy_digest": canonical_sha256(body)})


def built_in_policies(
    *, accepted_scanner_ids: list[str] | None = None
) -> dict[str, SecurityEvidencePolicy]:
    policies = [
        build_security_policy(item, accepted_scanner_ids=accepted_scanner_ids)
        for item in SecurityRequirementProfile
    ]
    return {item.policy_id: item for item in policies}


def get_security_policy(
    value: str, *, accepted_scanner_ids: list[str] | None = None
) -> SecurityEvidencePolicy:
    policies = built_in_policies(accepted_scanner_ids=accepted_scanner_ids)
    if value in policies:
        return policies[value]
    try:
        return build_security_policy(value, accepted_scanner_ids=accepted_scanner_ids)
    except ValueError as exc:
        raise ValueError(f"unknown security policy {value!r}") from exc
