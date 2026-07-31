"""Trusted deterministic trust-summary and usage-profile policy."""

from __future__ import annotations

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.passport.models import (
    CustodyStatus,
    PassportPolicy,
    PassportPolicyProfile,
    PassportStageName,
    PassportStageStatus,
    SecuritySummary,
    SummaryStatus,
    TrustOutcome,
    TrustSummary,
    UsageOutcome,
    UsageProfileResult,
)

STRUCTURAL_STAGES = [
    PassportStageName.REPOSITORY_LAYOUT,
    PassportStageName.FORMAT_STRUCTURE,
    PassportStageName.HEADER_INTEGRITY,
    PassportStageName.SPLIT_CONTAINER,
    PassportStageName.PAYLOAD_SPAN_BOUNDS,
    PassportStageName.TARGET_ONTOLOGY,
    PassportStageName.SEMANTIC_MAPPING,
]


def passport_policy() -> PassportPolicy:
    profiles = [
        PassportPolicyProfile(
            name="enterprise_structural_review",
            required_stages=[
                PassportStageName.ARTIFACT_IDENTITY,
                PassportStageName.FORMAT_STRUCTURE,
                PassportStageName.TARGET_ONTOLOGY,
                PassportStageName.SEMANTIC_MAPPING,
            ],
            review_stages=[
                PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE,
                PassportStageName.PAYLOAD_INTEGRITY,
                PassportStageName.SECURITY_INSPECTION,
                PassportStageName.CUSTODY_CHAIN,
                PassportStageName.RUNTIME_PARITY,
            ],
            missing_requirement_outcome=UsageOutcome.REVIEW_REQUIRED,
        ),
        PassportPolicyProfile(
            name="local_experimentation",
            required_stages=[
                PassportStageName.ARTIFACT_IDENTITY,
                PassportStageName.FORMAT_STRUCTURE,
            ],
            review_stages=[
                PassportStageName.PAYLOAD_INTEGRITY,
                PassportStageName.SECURITY_INSPECTION,
                PassportStageName.RUNTIME_PARITY,
            ],
            missing_requirement_outcome=UsageOutcome.NOT_SUITABLE,
        ),
        PassportPolicyProfile(
            name="regulated_production",
            required_stages=[
                PassportStageName.ARTIFACT_IDENTITY,
                PassportStageName.FORMAT_STRUCTURE,
                PassportStageName.TARGET_ONTOLOGY,
                PassportStageName.SEMANTIC_MAPPING,
                PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE,
                PassportStageName.PAYLOAD_INTEGRITY,
                PassportStageName.QUANTIZATION_FIDELITY,
                PassportStageName.TOKENIZER_PARITY,
                PassportStageName.SECURITY_INSPECTION,
                PassportStageName.CUSTODY_CHAIN,
                PassportStageName.APPROVAL,
                PassportStageName.DEPLOYMENT_OBSERVATION,
                PassportStageName.RUNTIME_PARITY,
            ],
            review_stages=[],
            missing_requirement_outcome=UsageOutcome.NOT_SUITABLE,
        ),
        PassportPolicyProfile(
            name="team_structural_intake",
            required_stages=[
                PassportStageName.ARTIFACT_IDENTITY,
                PassportStageName.FORMAT_STRUCTURE,
                PassportStageName.TARGET_ONTOLOGY,
                PassportStageName.SEMANTIC_MAPPING,
            ],
            review_stages=[PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE],
            missing_requirement_outcome=UsageOutcome.NOT_SUITABLE,
        ),
    ]
    body = {
        "schema": "omiv.model-passport-policy.v1",
        "profiles": [item.model_dump(mode="json", by_alias=True) for item in profiles],
        "structural_stages": [item.value for item in STRUCTURAL_STAGES],
    }
    return PassportPolicy(
        profiles=profiles,
        structural_stages=STRUCTURAL_STAGES,
        policy_digest=canonical_sha256(body),
    )


def profile_policy_digest(policy: PassportPolicy) -> str:
    return canonical_sha256(
        {
            "profiles": [
                item.model_dump(mode="json", by_alias=True) for item in policy.profiles
            ]
        }
    )


def _is_pass(status: PassportStageStatus) -> bool:
    return status == PassportStageStatus.PASS


def reconstruct_trust_summary(
    statuses: dict[PassportStageName, PassportStageStatus],
    custody_status: CustodyStatus,
    security: SecuritySummary,
) -> TrustSummary:
    identity = statuses[PassportStageName.ARTIFACT_IDENTITY]
    structural = [statuses[name] for name in STRUCTURAL_STAGES]
    structural_status = (
        TrustOutcome.STRUCTURAL_VALIDATION_FAILED
        if PassportStageStatus.FAIL in structural
        else TrustOutcome.STRUCTURALLY_VALIDATED_WITH_LIMITATIONS
        if all(_is_pass(item) for item in structural)
        else TrustOutcome.EVIDENCE_INCOMPLETE
    )
    provenance = statuses[PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE]
    payload = statuses[PassportStageName.PAYLOAD_INTEGRITY]
    runtime = statuses[PassportStageName.RUNTIME_PARITY]
    return TrustSummary(
        identity_status=(
            TrustOutcome.IDENTITY_VERIFIED
            if identity == PassportStageStatus.PASS
            else TrustOutcome.TRUST_CHAIN_BROKEN
            if identity == PassportStageStatus.FAIL
            else TrustOutcome.NOT_ASSESSED
        ),
        structural_status=structural_status,
        provenance_status=(
            TrustOutcome.IDENTITY_VERIFIED
            if provenance == PassportStageStatus.PASS
            else TrustOutcome.TRUST_CHAIN_BROKEN
            if provenance == PassportStageStatus.FAIL
            else TrustOutcome.EVIDENCE_INCOMPLETE
        ),
        payload_status=(
            TrustOutcome.IDENTITY_VERIFIED
            if payload == PassportStageStatus.PASS
            else TrustOutcome.TRUST_CHAIN_BROKEN
            if payload == PassportStageStatus.FAIL
            else TrustOutcome.NOT_ASSESSED
        ),
        security_status=(
            TrustOutcome.IDENTITY_VERIFIED
            if security.status == SummaryStatus.PASS
            else TrustOutcome.TRUST_CHAIN_BROKEN
            if security.status == SummaryStatus.FAIL
            else TrustOutcome.NOT_ASSESSED
        ),
        custody_status=(
            TrustOutcome.IDENTITY_VERIFIED
            if custody_status == CustodyStatus.VERIFIED
            else TrustOutcome.TRUST_CHAIN_BROKEN
            if custody_status == CustodyStatus.AVAILABLE_UNVERIFIED
            and statuses[PassportStageName.CUSTODY_CHAIN] == PassportStageStatus.FAIL
            else TrustOutcome.TRUST_CHAIN_INCOMPLETE
        ),
        runtime_status=(
            TrustOutcome.IDENTITY_VERIFIED
            if runtime == PassportStageStatus.PASS
            else TrustOutcome.TRUST_CHAIN_BROKEN
            if runtime == PassportStageStatus.FAIL
            else TrustOutcome.NOT_ASSESSED
        ),
    )


def evaluate_usage_profiles(
    statuses: dict[PassportStageName, PassportStageStatus],
    policy: PassportPolicy,
) -> list[UsageProfileResult]:
    results: list[UsageProfileResult] = []
    for profile in policy.profiles:
        unmet = sorted(
            (stage for stage in profile.required_stages if not _is_pass(statuses[stage])),
            key=lambda item: item.value,
        )
        review = sorted(
            (stage for stage in profile.review_stages if not _is_pass(statuses[stage])),
            key=lambda item: item.value,
        )
        if unmet:
            outcome = profile.missing_requirement_outcome
        elif profile.name == "enterprise_structural_review" and review:
            outcome = UsageOutcome.REVIEW_REQUIRED
        else:
            outcome = UsageOutcome.SUITABLE_WITH_LIMITATIONS
        guidance = {
            UsageOutcome.SUITABLE_WITH_LIMITATIONS: (
                "Suitable within the recorded structural scope; payload, security, and runtime "
                "limitations remain visible."
            ),
            UsageOutcome.REVIEW_REQUIRED: (
                "Structural evidence is available, but additional review evidence is required."
            ),
            UsageOutcome.NOT_SUITABLE: (
                "Required evidence is missing or failed; this profile is not satisfied."
            ),
            UsageOutcome.NOT_ASSESSED: "This profile was not assessed.",
        }[outcome]
        results.append(
            UsageProfileResult(
                profile=profile.name,
                outcome=outcome,
                guidance=guidance,
                unmet_stages=unmet,
                review_requirements=[stage.value for stage in review],
            )
        )
    return sorted(results, key=lambda item: item.profile)


def selected_profile_result(
    profiles: list[UsageProfileResult], profile_name: str
) -> UsageProfileResult:
    matches = [item for item in profiles if item.profile == profile_name]
    if len(matches) != 1:
        raise OmivInputError(f"unknown passport usage profile: {profile_name}")
    return matches[0]
