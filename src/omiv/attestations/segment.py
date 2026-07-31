"""Portable generic custody segments backed by one canonical attestation."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from omiv.attestations.custody import attestation_to_custody_event_input
from omiv.attestations.models import ArtifactAttestation
from omiv.attestations.verification import verify_attestation
from omiv.canonical import canonical_sha256, load_json_value
from omiv.custody.builder import build_event
from omiv.custody.models import (
    ArtifactReference,
    AttestationStatus,
    CustodyEvent,
    EvidenceLinkageStatus,
    IntegrityStatus,
    LifecycleCompleteness,
    OverallCustodyStatus,
    SubjectContinuityStatus,
)
from omiv.custody.policy import custody_policy, evaluate_completeness
from omiv.errors import OmivInputError
from omiv.models import StrictModel
from omiv.safe_write import atomic_write_text

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class AttestationLedgerPolicyIdentity(StrictModel):
    custody_policy_digest: str = Field(pattern=SHA256_PATTERN)
    attestation_policy_digest: str = Field(pattern=SHA256_PATTERN)


class AttestationLedgerReference(StrictModel):
    schema_id: Literal["omiv.artifact-attestation.v1"] = Field(alias="schema")
    attestation_id: str
    digest: str = Field(pattern=SHA256_PATTERN)
    relative_path: str

    @model_validator(mode="after")
    def safe_path(self) -> AttestationLedgerReference:
        path = PurePosixPath(self.relative_path)
        if path.is_absolute() or ".." in path.parts or "\\" in self.relative_path:
            raise ValueError("attestation ledger reference must be repository-relative")
        return self


class AttestationCustodyLedger(StrictModel):
    schema_id: Literal["omiv.custody-ledger.v2"] = Field(
        default="omiv.custody-ledger.v2", alias="schema"
    )
    chain_id: str = Field(pattern=r"^mcoc_[0-9a-f]{32}$")
    subject: ArtifactReference
    policy_identity: AttestationLedgerPolicyIdentity
    attestation_reference: AttestationLedgerReference
    genesis_semantics: Literal["PORTABLE_SEGMENT_BEGINNING"]
    selected_profile: str
    events: list[CustodyEvent]
    event_count: int = Field(ge=1)
    genesis_event_digest: str = Field(pattern=SHA256_PATTERN)
    latest_event_digest: str = Field(pattern=SHA256_PATTERN)
    ledger_integrity: IntegrityStatus
    subject_continuity: SubjectContinuityStatus
    evidence_linkage: EvidenceLinkageStatus
    signed_event_count: int = Field(ge=0)
    unattested_event_count: int = Field(ge=0)
    lifecycle_completeness: LifecycleCompleteness
    missing_event_types: list[str]
    overall_custody_status: OverallCustodyStatus
    ledger_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> AttestationCustodyLedger:
        if self.event_count != len(self.events) or self.event_count != 1:
            raise ValueError("v2 attestation segment contains exactly one genesis event")
        event = self.events[0]
        if event.sequence != 0 or event.previous_event_digest is not None:
            raise ValueError("attestation segment genesis is invalid")
        if event.chain_id != self.chain_id:
            raise ValueError("attestation segment event chain mismatch")
        if self.genesis_event_digest != event.event_digest:
            raise ValueError("attestation segment genesis digest mismatch")
        if self.latest_event_digest != event.event_digest:
            raise ValueError("attestation segment latest digest mismatch")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("ledger_digest")
        if digest != canonical_sha256(body):
            raise ValueError("attestation custody ledger digest mismatch")
        return self


def _chain_id(subject: ArtifactReference, attestation: ArtifactAttestation) -> str:
    return (
        "mcoc_"
        + canonical_sha256(
            {
                "schema": "omiv.custody-ledger.v2",
                "subject_identity_digest": subject.identity_digest,
                "custody_policy_digest": custody_policy().policy_digest,
                "attestation_policy_digest": attestation.policy_identity.policy_digest,
                "attestation_id": attestation.attestation_id,
            }
        )[:32]
    )


def build_attestation_custody_segment(
    attestation: ArtifactAttestation,
    *,
    attestation_reference: str,
    selected_profile: str = "evidence_segment",
) -> AttestationCustodyLedger:
    event_input = attestation_to_custody_event_input(
        attestation, attestation_reference=attestation_reference
    )
    subject = event_input.subject
    chain_id = _chain_id(subject, attestation)
    event = build_event(event_input, chain_id=chain_id, sequence=0, previous_event_digest=None)
    analysis = evaluate_completeness([event.event_type], selected_profile)
    lifecycle = (
        LifecycleCompleteness.COMPLETE
        if not analysis.missing_event_types and not analysis.missing_evidence_concepts
        else LifecycleCompleteness.INCOMPLETE
    )
    body = {
        "schema": "omiv.custody-ledger.v2",
        "chain_id": chain_id,
        "subject": subject.model_dump(mode="json"),
        "policy_identity": {
            "custody_policy_digest": custody_policy().policy_digest,
            "attestation_policy_digest": attestation.policy_identity.policy_digest,
        },
        "attestation_reference": {
            "schema": attestation.schema_id,
            "attestation_id": attestation.attestation_id,
            "digest": attestation.attestation_digest,
            "relative_path": attestation_reference,
        },
        "genesis_semantics": "PORTABLE_SEGMENT_BEGINNING",
        "selected_profile": selected_profile,
        "events": [event.model_dump(mode="json", by_alias=True)],
        "event_count": 1,
        "genesis_event_digest": event.event_digest,
        "latest_event_digest": event.event_digest,
        "ledger_integrity": "INTACT",
        "subject_continuity": "CONSISTENT",
        "evidence_linkage": (
            "VERIFIED"
            if attestation.verification_summary.evidence_linkage.value == "FULLY_VERIFIED"
            else "PARTIAL"
        ),
        "signed_event_count": 0,
        "unattested_event_count": int(event.attestation_status == AttestationStatus.UNATTESTED),
        "lifecycle_completeness": lifecycle.value,
        "missing_event_types": sorted(item.value for item in analysis.missing_event_types),
        "overall_custody_status": (
            OverallCustodyStatus.INTACT.value
            if lifecycle == LifecycleCompleteness.COMPLETE
            else OverallCustodyStatus.INCOMPLETE.value
        ),
    }
    return AttestationCustodyLedger.model_validate(
        {**body, "ledger_digest": canonical_sha256(body)}
    )


def pretty_segment_json(value: AttestationCustodyLedger) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def write_attestation_custody_segment(value: AttestationCustodyLedger, output: Path) -> None:
    atomic_write_text(output, pretty_segment_json(value))


def verify_attestation_custody_segment(path: Path, root: Path) -> AttestationCustodyLedger:
    try:
        stored = AttestationCustodyLedger.model_validate(
            load_json_value(path.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise OmivInputError(f"invalid attestation custody segment: {exc}") from exc
    attestation = verify_attestation(root / stored.attestation_reference.relative_path)
    expected = build_attestation_custody_segment(
        attestation,
        attestation_reference=stored.attestation_reference.relative_path,
        selected_profile=stored.selected_profile,
    )
    if stored != expected:
        raise OmivInputError("attestation custody segment does not reconstruct")
    return stored
