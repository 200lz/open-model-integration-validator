"""Trusted custody event and lifecycle-completeness policy."""

from __future__ import annotations

from omiv.canonical import canonical_sha256
from omiv.custody.models import (
    CustodyEventType,
    CustodyPolicy,
    CustodyPolicyProfile,
    LifecycleCompleteness,
    MissingEventAnalysis,
    ProfileCompleteness,
)
from omiv.errors import OmivInputError

GENERATED_EVENT_TYPES = [
    CustodyEventType.SOURCE_LOCATOR_RECORDED,
    CustodyEventType.IMMUTABLE_IDENTITY_ESTABLISHED,
    CustodyEventType.REMOTE_INSPECTION_RECORDED,
    CustodyEventType.FORMAT_INSPECTION_COMPLETED,
    CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
    CustodyEventType.PASSPORT_ISSUED,
]

MISSING_LIFECYCLE_EVENT_TYPES = [
    CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
    CustodyEventType.TRANSFORMATION_RECORDED,
    CustodyEventType.QUANTIZATION_RECORDED,
    CustodyEventType.SECURITY_INSPECTION_COMPLETED,
    CustodyEventType.APPROVAL_RECORDED,
    CustodyEventType.REGISTRY_PROMOTION_RECORDED,
    CustodyEventType.DEPLOYMENT_RECORDED,
    CustodyEventType.RUNTIME_OBSERVATION_RECORDED,
]


def custody_policy() -> CustodyPolicy:
    profiles = [
        CustodyPolicyProfile(
            name="enterprise_deployment",
            required_event_types=[
                CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
                CustodyEventType.TRANSFORMATION_RECORDED,
                CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
                CustodyEventType.SECURITY_INSPECTION_COMPLETED,
                CustodyEventType.APPROVAL_RECORDED,
                CustodyEventType.REGISTRY_PROMOTION_RECORDED,
                CustodyEventType.DEPLOYMENT_RECORDED,
            ],
            any_of_event_types=[],
            required_evidence_concepts=[],
        ),
        CustodyPolicyProfile(
            name="evidence_segment",
            required_event_types=[
                CustodyEventType.IMMUTABLE_IDENTITY_ESTABLISHED,
                CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
                CustodyEventType.PASSPORT_ISSUED,
            ],
            any_of_event_types=[
                CustodyEventType.REMOTE_INSPECTION_RECORDED,
                CustodyEventType.FORMAT_INSPECTION_COMPLETED,
            ],
            required_evidence_concepts=[],
        ),
        CustodyPolicyProfile(
            name="local_model_intake",
            required_event_types=[
                CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
                CustodyEventType.IMMUTABLE_IDENTITY_ESTABLISHED,
                CustodyEventType.FORMAT_INSPECTION_COMPLETED,
                CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
                CustodyEventType.SECURITY_INSPECTION_COMPLETED,
                CustodyEventType.PASSPORT_ISSUED,
            ],
            any_of_event_types=[],
            required_evidence_concepts=[],
        ),
        CustodyPolicyProfile(
            name="regulated_runtime",
            required_event_types=[
                CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
                CustodyEventType.TRANSFORMATION_RECORDED,
                CustodyEventType.QUANTIZATION_RECORDED,
                CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
                CustodyEventType.SECURITY_INSPECTION_COMPLETED,
                CustodyEventType.APPROVAL_RECORDED,
                CustodyEventType.REGISTRY_PROMOTION_RECORDED,
                CustodyEventType.DEPLOYMENT_RECORDED,
                CustodyEventType.RUNTIME_OBSERVATION_RECORDED,
            ],
            any_of_event_types=[],
            required_evidence_concepts=[
                "payload_integrity",
                "tokenizer_parity",
                "revocation_check",
                "expiration_check",
            ],
        ),
        CustodyPolicyProfile(
            name="team_release",
            required_event_types=[
                CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
                CustodyEventType.TRANSFORMATION_RECORDED,
                CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
                CustodyEventType.SECURITY_INSPECTION_COMPLETED,
                CustodyEventType.APPROVAL_RECORDED,
                CustodyEventType.PASSPORT_ISSUED,
            ],
            any_of_event_types=[],
            required_evidence_concepts=[],
        ),
    ]
    body = {
        "schema": "omiv.custody-policy.v1",
        "allowed_event_types": [item.value for item in CustodyEventType],
        "generated_event_types": [item.value for item in GENERATED_EVENT_TYPES],
        "lifecycle_event_types": [item.value for item in MISSING_LIFECYCLE_EVENT_TYPES],
        "profiles": [item.model_dump(mode="json") for item in profiles],
    }
    return CustodyPolicy(
        allowed_event_types=list(CustodyEventType),
        generated_event_types=GENERATED_EVENT_TYPES,
        lifecycle_event_types=MISSING_LIFECYCLE_EVENT_TYPES,
        profiles=profiles,
        policy_digest=canonical_sha256(body),
    )


def evaluate_completeness(
    event_types: list[CustodyEventType],
    selected_profile: str,
    *,
    available_evidence_concepts: set[str] | None = None,
    not_applicable_event_types: dict[CustodyEventType, str] | None = None,
    not_applicable_policy_digests: set[str] | None = None,
) -> MissingEventAnalysis:
    policy = custody_policy()
    known = {profile.name for profile in policy.profiles}
    if selected_profile not in known:
        raise OmivInputError(f"unknown custody profile: {selected_profile}")
    observed = set(event_types)
    concepts = available_evidence_concepts or set()
    not_applicable = not_applicable_event_types or {}
    applicable_digests = not_applicable_policy_digests or set()
    if any(digest not in applicable_digests for digest in not_applicable.values()):
        raise OmivInputError("NOT_APPLICABLE custody events require explicit policy evidence")
    results: list[ProfileCompleteness] = []
    for profile in policy.profiles:
        missing = sorted(
            (
                item
                for item in profile.required_event_types
                if item not in observed and item not in not_applicable
            ),
            key=lambda item: item.value,
        )
        if profile.any_of_event_types and not observed.intersection(profile.any_of_event_types):
            missing.extend(sorted(profile.any_of_event_types, key=lambda item: item.value))
        missing_concepts = sorted(set(profile.required_evidence_concepts) - concepts)
        status = (
            LifecycleCompleteness.COMPLETE
            if not missing and not missing_concepts
            else LifecycleCompleteness.INCOMPLETE
        )
        results.append(
            ProfileCompleteness(
                profile=profile.name,
                status=status,
                missing_event_types=missing,
                missing_evidence_concepts=missing_concepts,
            )
        )
    lifecycle_missing = sorted(
        (
            item
            for item in policy.lifecycle_event_types
            if item not in observed and item not in not_applicable
        ),
        key=lambda item: item.value,
    )
    regulated = next(item for item in results if item.profile == "regulated_runtime")
    return MissingEventAnalysis(
        selected_profile=selected_profile,
        profile_results=sorted(results, key=lambda item: item.profile),
        missing_event_types=lifecycle_missing,
        missing_evidence_concepts=regulated.missing_evidence_concepts,
    )


def selected_profile_result(analysis: MissingEventAnalysis) -> ProfileCompleteness:
    matches = [
        item for item in analysis.profile_results if item.profile == analysis.selected_profile
    ]
    if len(matches) != 1:
        raise OmivInputError(f"unknown custody profile: {analysis.selected_profile}")
    return matches[0]
