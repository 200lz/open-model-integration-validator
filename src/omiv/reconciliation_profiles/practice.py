"""Offline target contracts; these import the core and are never imported by it."""

from __future__ import annotations

from omiv.reconciliation.models import ObjectReference, ProviderKind
from omiv.reconciliation_profiles.models import (
    PracticeProfile,
    PracticeStatus,
    build_practice_profile,
)


def kimi_profile(prior_evidence: tuple[ObjectReference, ...]) -> PracticeProfile:
    return build_practice_profile(
        "Kimi/Moonshot",
        provider_kinds=(ProviderKind.HUGGING_FACE,),
        declared_public_targets=("pinned prior remote evidence",),
        status=PracticeStatus.COMPATIBILITY_EVIDENCE_AVAILABLE_WITH_LIMITATIONS,
        prior_evidence=prior_evidence,
        limitations=(
            "Prior header-only evidence remains header-only.",
            "Prior metadata-only and payload NOT_CHECKED states remain unchanged.",
            "Remote evidence is not local payload-byte observation.",
        ),
    )


def deepseek_profile() -> PracticeProfile:
    return build_practice_profile(
        "DeepSeek",
        provider_kinds=(ProviderKind.HUGGING_FACE, ProviderKind.GIT_REPOSITORY),
        declared_public_targets=("caller-supplied pinned snapshot",),
        status=PracticeStatus.PINNED_REMOTE_SNAPSHOT_NOT_SUPPLIED,
        limitations=(
            "DEEPSEEK_PINNED_REMOTE_SNAPSHOT_NOT_SUPPLIED",
            "Readiness contract is not operational evidence.",
            "No revision, member, size, digest, or publisher authority was invented.",
        ),
    )


def xai_profile(prior_evidence: tuple[ObjectReference, ...] = ()) -> PracticeProfile:
    if prior_evidence:
        status = PracticeStatus.PUBLIC_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD
        evidence_limitation = (
            "Pinned public-provider metadata evidence is revision-specific, metadata-only, "
            "and not publisher authorization."
        )
    else:
        status = PracticeStatus.PINNED_REMOTE_SNAPSHOT_NOT_YET_COLLECTED
        evidence_limitation = "XAI_PINNED_REMOTE_SNAPSHOT_NOT_YET_COLLECTED"
    return build_practice_profile(
        "xAI",
        provider_kinds=(ProviderKind.HUGGING_FACE, ProviderKind.GIT_REPOSITORY),
        declared_public_targets=(
            "xai-org/grok-1",
            "xai-org/grok-2",
            "xai-org/grok-prompts",
            "xai-org/xai-cookbook",
            "xai-org/xai-proto",
            "xai-org/xai-sdk-python",
        ),
        status=status,
        prior_evidence=prior_evidence,
        limitations=(
            evidence_limitation,
            "No xAI endorsement, model authenticity, safety, freshness, runtime identity, or "
            "payload verification is asserted.",
            "Namespace identity cannot create publisher authority.",
        ),
    )
