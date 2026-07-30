"""Static trusted acceptance profiles and their deterministic evaluation."""

from omiv.canonical import canonical_sha256
from omiv.validation.models import (
    AcceptanceProfile,
    AcceptanceProfilePolicy,
    EvidenceStageName,
    EvidenceStageResult,
    EvidenceStatus,
    ProfileOutcome,
    ProfileRequirement,
    ProfileResult,
    ProfileStageDecision,
)

STRUCTURAL_STAGES = (
    EvidenceStageName.REPOSITORY_IDENTITY,
    EvidenceStageName.REPOSITORY_LAYOUT,
    EvidenceStageName.RANGE_SEMANTICS,
    EvidenceStageName.FILE_PREFIX,
    EvidenceStageName.COMPLETE_HEADER,
    EvidenceStageName.SPLIT_CONTAINER,
    EvidenceStageName.PAYLOAD_SPAN_BOUNDS,
    EvidenceStageName.TARGET_ONTOLOGY,
    EvidenceStageName.STRUCTURAL_SEMANTIC_MAPPING,
    EvidenceStageName.DETERMINISTIC_VERIFICATION,
)
LATE_STAGES = (
    EvidenceStageName.ARTIFACT_SPECIFIC_PROVENANCE,
    EvidenceStageName.PAYLOAD_INTEGRITY,
    EvidenceStageName.QUANTIZATION_FIDELITY,
    EvidenceStageName.TOKENIZER_PARITY,
    EvidenceStageName.RUNTIME_PARITY,
)


def _requirements(default: ProfileRequirement) -> dict[EvidenceStageName, ProfileRequirement]:
    return {stage: default for stage in EvidenceStageName}


def profile_policy() -> AcceptanceProfilePolicy:
    community = _requirements(ProfileRequirement.NOT_REQUIRED)
    for stage in STRUCTURAL_STAGES:
        community[stage] = ProfileRequirement.REQUIRED_PASS
    community[EvidenceStageName.CONVERTER_RULE_SUPPORT] = ProfileRequirement.REQUIRED_CHECKED
    community[EvidenceStageName.ARTIFACT_SPECIFIC_PROVENANCE] = ProfileRequirement.NOT_REQUIRED

    vendor = dict(community)
    vendor[EvidenceStageName.ARTIFACT_SPECIFIC_PROVENANCE] = ProfileRequirement.ALLOWED_UNAVAILABLE
    vendor[EvidenceStageName.PAYLOAD_INTEGRITY] = ProfileRequirement.ALLOWED_WARN

    enterprise = dict(vendor)
    for stage in STRUCTURAL_STAGES:
        enterprise[stage] = ProfileRequirement.REQUIRED_PASS
    enterprise[EvidenceStageName.PAYLOAD_INTEGRITY] = ProfileRequirement.ALLOWED_WARN
    enterprise[EvidenceStageName.QUANTIZATION_FIDELITY] = ProfileRequirement.ALLOWED_WARN
    enterprise[EvidenceStageName.TOKENIZER_PARITY] = ProfileRequirement.ALLOWED_WARN
    enterprise[EvidenceStageName.RUNTIME_PARITY] = ProfileRequirement.ALLOWED_WARN

    regulated = _requirements(ProfileRequirement.REQUIRED_PASS)
    regulated[EvidenceStageName.CONVERTER_RULE_SUPPORT] = ProfileRequirement.REQUIRED_CHECKED
    for stage in LATE_STAGES:
        regulated[stage] = ProfileRequirement.REQUIRED_CHECKED

    profiles = [
        AcceptanceProfile(
            name="community_structural",
            description="Structural integration acceptance with explicit downstream limitations.",
            requirements=community,
        ),
        AcceptanceProfile(
            name="vendor_release_structural",
            description=(
                "Vendor structural release review; missing provenance and payload evidence warn."
            ),
            requirements=vendor,
        ),
        AcceptanceProfile(
            name="enterprise_offline_structural",
            description=(
                "Deterministic offline structural review; full deployment equivalence is excluded."
            ),
            requirements=enterprise,
        ),
        AcceptanceProfile(
            name="regulated_deployment_full",
            description=(
                "Full deployment evidence including provenance, payload, numerical, "
                "and runtime checks."
            ),
            requirements=regulated,
        ),
    ]
    body = {
        "schema_id": "omiv.validation-acceptance-profile-policy.v1",
        "profiles": [profile.model_dump(mode="json") for profile in profiles],
    }
    return AcceptanceProfilePolicy(profiles=profiles, policy_digest=canonical_sha256(body))


def _decision(stage: EvidenceStageResult, requirement: ProfileRequirement) -> ProfileStageDecision:
    status = stage.status
    satisfied = True
    warning = False
    if requirement == ProfileRequirement.REQUIRED_PASS:
        satisfied = status == EvidenceStatus.PASS
    elif requirement == ProfileRequirement.REQUIRED_CHECKED:
        satisfied = status in {EvidenceStatus.PASS, EvidenceStatus.AVAILABLE}
    elif requirement == ProfileRequirement.ALLOWED_UNAVAILABLE:
        satisfied = status in {
            EvidenceStatus.PASS,
            EvidenceStatus.AVAILABLE,
            EvidenceStatus.WARN,
            EvidenceStatus.UNAVAILABLE,
        }
        warning = status in {EvidenceStatus.WARN, EvidenceStatus.UNAVAILABLE}
    elif requirement == ProfileRequirement.ALLOWED_WARN:
        satisfied = status not in {EvidenceStatus.FAIL}
        warning = status in {
            EvidenceStatus.WARN,
            EvidenceStatus.UNAVAILABLE,
            EvidenceStatus.NOT_CHECKED,
        }
    reason = f"{stage.stage.value} observed {status.value} under {requirement.value}"
    return ProfileStageDecision(
        stage=stage.stage,
        requirement=requirement,
        observed_status=status,
        satisfied=satisfied,
        warning=warning,
        reason=reason,
    )


def evaluate_profiles(
    stages: list[EvidenceStageResult], policy: AcceptanceProfilePolicy
) -> list[ProfileResult]:
    by_stage = {stage.stage: stage for stage in stages}
    results: list[ProfileResult] = []
    for profile in policy.profiles:
        decisions = [
            _decision(by_stage[stage], requirement)
            for stage, requirement in sorted(
                profile.requirements.items(), key=lambda item: item[0].value
            )
        ]
        failed = sum(not decision.satisfied for decision in decisions)
        warnings = sum(decision.warning for decision in decisions)
        outcome = (
            ProfileOutcome.NOT_SATISFIED
            if failed
            else ProfileOutcome.SATISFIED_WITH_WARNINGS
            if warnings
            else ProfileOutcome.SATISFIED
        )
        results.append(
            ProfileResult(
                profile_name=profile.name,
                outcome=outcome,
                satisfied=failed == 0,
                warning_count=warnings,
                failed_requirement_count=failed,
                decisions=decisions,
            )
        )
    return results
