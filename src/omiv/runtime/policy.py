"""Static trusted Phase 5G continuity-policy registry."""

from __future__ import annotations

from omiv.canonical import canonical_sha256
from omiv.runtime.models import (
    ContinuityPolicy,
    ContinuityPolicyProfile,
    ContinuityVerdict,
    EvidenceStrength,
    ObservationDimension,
    ProductSubjectClass,
)

PRECEDENCE = [
    ContinuityVerdict.EVIDENCE_BROKEN,
    ContinuityVerdict.REPLAY_REJECTED,
    ContinuityVerdict.MISMATCH,
    ContinuityVerdict.DRIFT_DETECTED,
    ContinuityVerdict.OBSERVER_UNAUTHORIZED,
    ContinuityVerdict.OBSERVER_UNTRUSTED,
    ContinuityVerdict.DEPLOYMENT_UNVERIFIED,
    ContinuityVerdict.COVERAGE_INCOMPLETE,
    ContinuityVerdict.STALE,
    ContinuityVerdict.NOT_OBSERVED,
    ContinuityVerdict.NOT_EVALUATED,
    ContinuityVerdict.IDENTITY_PROXY_MATCH,
    ContinuityVerdict.PARTIAL_CONTINUITY,
    ContinuityVerdict.PASS_WITH_LIMITATIONS,
    ContinuityVerdict.PASS,
]

BASE_DIMENSIONS = [
    ObservationDimension.PRIMARY_ARTIFACT_DIGEST,
    ObservationDimension.ARTIFACT_SET_DIGEST,
    ObservationDimension.RUNTIME_CONFIG_DIGEST,
    ObservationDimension.ENGINE_VERSION_REVISION,
    ObservationDimension.TARGET_IDENTITY,
]
STRICT_DIMENSIONS = BASE_DIMENSIONS + [
    ObservationDimension.COMPANION_ARTIFACT_DIGESTS,
    ObservationDimension.ENGINE_BINARY_DIGEST,
    ObservationDimension.ENVIRONMENT_IDENTITY,
]


def build_continuity_policy(profile: ContinuityPolicyProfile) -> ContinuityPolicy:
    local = profile == ContinuityPolicyProfile.LOCAL_RUNTIME_CONTINUITY
    team = profile == ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY
    air = profile == ContinuityPolicyProfile.AIR_GAPPED_RUNTIME_CONTINUITY
    regulated = profile == ContinuityPolicyProfile.REGULATED_RUNTIME_CONTINUITY
    strict = profile == ContinuityPolicyProfile.ENTERPRISE_DEPLOYMENT_CONTINUITY or regulated
    body = {
        "schema": "omiv.continuity-policy.v1",
        "policy_id": f"omiv.continuity-policy.{profile.value}.v1",
        "profile": profile.value,
        "accepted_subject_classes": sorted(x.value for x in ProductSubjectClass),
        "accepted_deployment_strengths": sorted(
            x.value
            for x in (
                [
                    EvidenceStrength.SYSTEM_OBSERVED,
                    EvidenceStrength.SIGNED,
                    EvidenceStrength.SIGNED_AND_TRUSTED,
                    EvidenceStrength.INDEPENDENTLY_CORROBORATED,
                ]
                if not local
                else list(EvidenceStrength)
            )
        ),
        "accepted_observation_strengths": sorted(
            x.value
            for x in (
                [EvidenceStrength.SIGNED_AND_TRUSTED, EvidenceStrength.INDEPENDENTLY_CORROBORATED]
                if strict or team or air
                else [
                    EvidenceStrength.SYSTEM_OBSERVED,
                    EvidenceStrength.SIGNED,
                    EvidenceStrength.SIGNED_AND_TRUSTED,
                    EvidenceStrength.INDEPENDENTLY_CORROBORATED,
                ]
            )
        ),
        "required_dimensions": sorted(
            x.value for x in (STRICT_DIMENSIONS if strict or team or air else BASE_DIMENSIONS)
        ),
        "require_direct_artifact_identity": not local,
        "require_signed_deployment": team or strict or air,
        "require_signed_observation": team or strict or air,
        "require_trusted_observer": team or strict or air,
        "require_independent_observer": team or strict or air,
        "require_distinct_signer": team or strict or air,
        "require_distinct_key": team or strict or air,
        "require_distinct_trust_root": strict,
        "require_corroboration": strict,
        "allow_limited_security_evidence": local or team or air,
        "maximum_age_sequences": 5,
        "offline_trust_requires_limitation": air,
        "fail_closed_reserved": regulated,
        "decision_precedence": [x.value for x in PRECEDENCE],
        "limitations": [
            "Continuity PASS is policy- and snapshot-scoped; behavior, safety, and "
            "continuous continuity remain unverified."
        ],
    }
    return ContinuityPolicy.model_validate({**body, "policy_digest": canonical_sha256(body)})


def get_continuity_policy(value: str) -> ContinuityPolicy:
    return build_continuity_policy(ContinuityPolicyProfile(value))
