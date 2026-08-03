"""Deterministic readiness contracts for practice and validation targets."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.reconciliation.models import ObjectReference, ProviderKind


class PracticeStatus(StrEnum):
    COMPATIBILITY_EVIDENCE_AVAILABLE_WITH_LIMITATIONS = (
        "COMPATIBILITY_EVIDENCE_AVAILABLE_WITH_LIMITATIONS"
    )
    PINNED_REMOTE_SNAPSHOT_NOT_SUPPLIED = "PINNED_REMOTE_SNAPSHOT_NOT_SUPPLIED"
    PINNED_REMOTE_SNAPSHOT_NOT_YET_COLLECTED = "PINNED_REMOTE_SNAPSHOT_NOT_YET_COLLECTED"
    PUBLIC_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD = (
        "PUBLIC_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD"
    )


class PracticeProfile(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_id: Literal["omiv.reconciliation-practice-profile.v1"] = Field(
        default="omiv.reconciliation-practice-profile.v1", alias="schema"
    )
    profile_id: str = Field(pattern=r"^reconciliation_profile_[0-9a-f]{32}$")
    family: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ./_-]{0,127}$")
    provider_kinds: tuple[ProviderKind, ...]
    declared_public_targets: tuple[str, ...]
    status: PracticeStatus
    prior_evidence: tuple[ObjectReference, ...]
    operational_evidence: Literal[False] = False
    payload_verified: Literal[False] = False
    authority_inferred_from_namespace: Literal[False] = False
    limitations: tuple[str, ...]
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity(self) -> PracticeProfile:
        body: dict[str, Any] = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("profile_digest")
        identity = body.pop("profile_id")
        expected_id = "reconciliation_profile_" + canonical_sha256(body)[:32]
        if identity != expected_id or digest != canonical_sha256(
            {**body, "profile_id": expected_id}
        ):
            raise ValueError("practice profile identity or digest mismatch")
        return self


def build_practice_profile(
    family: str,
    *,
    provider_kinds: Iterable[ProviderKind],
    declared_public_targets: Iterable[str],
    status: PracticeStatus,
    prior_evidence: Iterable[ObjectReference] = (),
    limitations: Iterable[str] = (),
) -> PracticeProfile:
    body = {
        "schema": "omiv.reconciliation-practice-profile.v1",
        "family": family,
        "provider_kinds": sorted({kind.value for kind in provider_kinds}),
        "declared_public_targets": sorted(set(declared_public_targets)),
        "status": status.value,
        "prior_evidence": [
            item.model_dump(mode="json")
            for item in sorted(prior_evidence, key=lambda item: item.object_id)
        ],
        "operational_evidence": False,
        "payload_verified": False,
        "authority_inferred_from_namespace": False,
        "limitations": list(limitations),
    }
    profile_id = "reconciliation_profile_" + canonical_sha256(body)[:32]
    return PracticeProfile.model_validate(
        {
            **body,
            "profile_id": profile_id,
            "profile_digest": canonical_sha256({**body, "profile_id": profile_id}),
        }
    )
