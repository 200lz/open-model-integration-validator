"""Backward-compatible attestation summaries for future Passport schema evolution."""

from __future__ import annotations

from enum import StrEnum

from omiv.attestations.models import (
    ArtifactAttestation,
    AttestationKind,
    Authenticity,
    ProvenanceStrength,
)
from omiv.custody.models import ArtifactReference
from omiv.errors import OmivInputError
from omiv.models import StrictModel


class PassportAttestationState(StrEnum):
    UNAVAILABLE = "UNAVAILABLE"
    DECLARED = "DECLARED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    EXECUTION_VERIFIED = "EXECUTION_VERIFIED"


class PassportAttestationSummary(StrictModel):
    acquisition_attestation: PassportAttestationState
    transfer_attestation: PassportAttestationState
    transformation_attestation: PassportAttestationState
    quantization_attestation: PassportAttestationState
    provenance_strength: ProvenanceStrength
    attestation_authenticity: list[Authenticity]
    attestation_ids: list[str]
    payload_status: str
    security_status: str
    runtime_status: str
    approval_status: str
    signature_status: str
    issuer_authentication: str
    actor_authenticity: str
    limitation: str


def _state(values: list[ArtifactAttestation]) -> PassportAttestationState:
    if not values:
        return PassportAttestationState.UNAVAILABLE
    authenticity = {item.authenticity for item in values}
    if Authenticity.EXECUTION_VERIFIED in authenticity:
        return PassportAttestationState.EXECUTION_VERIFIED
    if Authenticity.EVIDENCE_LINKED in authenticity:
        return PassportAttestationState.EVIDENCE_LINKED
    return PassportAttestationState.DECLARED


def summarize_attestations(
    subject: ArtifactReference, attestations: list[ArtifactAttestation]
) -> PassportAttestationSummary:
    """Build a typed summary without mutating Passport v1 or v2 semantics."""
    relevant = [
        item for item in attestations if item.subject.identity_digest == subject.identity_digest
    ]
    if len(relevant) != len(attestations):
        raise OmivInputError("attestation subject does not match Passport artifact")
    by_kind = {
        kind: [item for item in relevant if item.attestation_kind == kind]
        for kind in AttestationKind
    }
    provenance_order = list(ProvenanceStrength)
    provenance = max(
        (item.verification_summary.provenance_strength for item in relevant),
        key=provenance_order.index,
        default=ProvenanceStrength.NO_PROVENANCE,
    )
    return PassportAttestationSummary(
        acquisition_attestation=_state(by_kind[AttestationKind.ACQUISITION]),
        transfer_attestation=_state(by_kind[AttestationKind.TRANSFER]),
        transformation_attestation=_state(by_kind[AttestationKind.TRANSFORMATION]),
        quantization_attestation=_state(by_kind[AttestationKind.QUANTIZATION]),
        provenance_strength=provenance,
        attestation_authenticity=sorted(
            {item.authenticity for item in relevant}, key=lambda item: item.value
        ),
        attestation_ids=sorted(item.attestation_id for item in relevant),
        payload_status="NOT_CHECKED",
        security_status="NOT_CHECKED",
        runtime_status="NOT_CHECKED",
        approval_status="NOT_CHECKED",
        signature_status="NOT_AVAILABLE",
        issuer_authentication="UNVERIFIED",
        actor_authenticity="UNVERIFIED",
        limitation=(
            "Attestation summaries do not establish payload, security, runtime, approval, "
            "or signed authenticity status."
        ),
    )
