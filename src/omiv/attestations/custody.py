"""Deterministic adapter from verified attestations to custody events."""

from __future__ import annotations

from pathlib import Path

from pydantic import JsonValue

from omiv.attestations.models import (
    ArtifactAttestation,
    AttestationAssertionOrigin,
    AttestationKind,
    Authenticity,
    MaterializationEligibility,
)
from omiv.attestations.verification import verify_attestation
from omiv.custody.append import append_evidence_event
from omiv.custody.models import (
    ActorReference,
    AssertionOrigin,
    CustodyEventInput,
    CustodyEventType,
    CustodyEvidenceReference,
    CustodyLedger,
    CustodyPolicyReference,
    EnvironmentReference,
    EvidenceLinkageStatus,
    ReferenceStatus,
    ToolReference,
)
from omiv.custody.policy import custody_policy
from omiv.custody.reporting import pretty_json as pretty_custody_json
from omiv.custody.verification import verify_custody_ledger
from omiv.errors import OmivInputError
from omiv.passport.models import EvidenceAvailability
from omiv.safe_write import atomic_write_text


def _event_type(kind: AttestationKind) -> CustodyEventType:
    return {
        AttestationKind.ACQUISITION: CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
        AttestationKind.TRANSFER: CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
        AttestationKind.TRANSFORMATION: CustodyEventType.TRANSFORMATION_RECORDED,
        AttestationKind.QUANTIZATION: CustodyEventType.QUANTIZATION_RECORDED,
    }[kind]


def _origin(value: ArtifactAttestation) -> AssertionOrigin:
    if value.authenticity == Authenticity.DECLARED:
        return AssertionOrigin.USER_DECLARED
    if value.assertion_origin == AttestationAssertionOrigin.SYSTEM_OBSERVED:
        return AssertionOrigin.SYSTEM_OBSERVED
    if value.assertion_origin == AttestationAssertionOrigin.IMPORTED_ATTESTATION:
        return AssertionOrigin.IMPORTED_ATTESTATION
    return AssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE


def attestation_to_custody_event_input(
    value: ArtifactAttestation, *, attestation_reference: str
) -> CustodyEventInput:
    path = Path(attestation_reference)
    if path.is_absolute() or ".." in path.parts:
        raise OmivInputError("attestation custody reference must be repository-relative")
    if (
        value.verification_summary.materialization_eligibility
        != MaterializationEligibility.ELIGIBLE
    ):
        raise OmivInputError("attestation is not eligible for custody-event materialization")
    is_transform = value.attestation_kind in {
        AttestationKind.TRANSFORMATION,
        AttestationKind.QUANTIZATION,
    }
    subject = value.inputs[0] if is_transform else value.subject
    inputs = value.inputs if is_transform else []
    outputs = value.outputs if is_transform else []
    tool = None
    if value.tool_identity is not None:
        tool = ToolReference(
            status=ReferenceStatus.SYSTEM_DERIVED,
            tool_name=value.tool_identity.tool_name,
            tool_version=value.tool_identity.tool_version,
            tool_revision=value.tool_identity.tool_revision,
            tool_identity_digest=value.tool_identity.tool_identity_digest,
            evidence_status=EvidenceLinkageStatus.VERIFIED,
        )
    environment = EnvironmentReference(status=ReferenceStatus.UNAVAILABLE)
    if value.environment_identity.status.value != "UNAVAILABLE":
        environment = EnvironmentReference(
            status=ReferenceStatus.SYSTEM_DERIVED,
            environment_digest=value.environment_identity.environment_digest,
            runtime_identity=value.environment_identity.runtime_identity,
            container_identity=value.environment_identity.container_image_digest,
            evidence_reference=None,
        )
    claims: dict[str, JsonValue] = {
        "artifact_attestation_id": value.attestation_id,
        "artifact_attestation_digest": value.attestation_digest,
        "attestation_kind": value.attestation_kind.value,
        "claim_type": value.claim_type.value,
        "attestation_assertion_origin": value.assertion_origin.value,
        "attestation_authenticity": value.authenticity.value,
        "evidence_linkage": value.verification_summary.evidence_linkage.value,
        "execution_verification": value.verification_summary.execution_verification.value,
        "provenance_strength": value.verification_summary.provenance_strength.value,
        "materialization_eligibility": (
            value.verification_summary.materialization_eligibility.value
        ),
        "declared_input_identities": [item.identity_digest for item in value.inputs],
        "declared_output_identities": [item.identity_digest for item in value.outputs],
    }
    policy = custody_policy()
    action = f"Record canonical {value.attestation_kind.value.lower()} attestation."
    if value.authenticity == Authenticity.DECLARED:
        action = "Record a user-declared acquisition claim; acquisition is not verified."
    return CustodyEventInput(
        event_type=_event_type(value.attestation_kind),
        subject=subject,
        input_artifacts=inputs,
        output_artifacts=outputs,
        action=action,
        assertion_origin=_origin(value),
        actor_reference=ActorReference(status=ReferenceStatus.UNAVAILABLE),
        tool_reference=tool,
        environment_reference=environment,
        policy_references=[
            CustodyPolicyReference(policy_id="custody_policy", policy_digest=policy.policy_digest),
            CustodyPolicyReference(
                policy_id="artifact_attestation_policy",
                policy_digest=value.policy_identity.policy_digest,
            ),
        ],
        evidence_references=[
            CustodyEvidenceReference(
                role="artifact_attestation",
                schema=value.schema_id,
                digest=value.attestation_digest,
                availability=EvidenceAvailability.PRIVATE,
                verification_mode="full_verification",
                finding_ids=[],
                policy_digests=[value.policy_identity.policy_digest],
                source_phase="5C",
                relative_path=attestation_reference,
            )
        ],
        event_claims=claims,
        limitations=sorted(
            set(
                value.limitations
                + [
                    "The custody event is unattested and not cryptographically signed.",
                    "Attestation integrity does not prove real-world action occurrence.",
                ]
            )
        ),
    )


def append_attestation_to_ledger(
    *,
    attestation_path: Path,
    ledger_path: Path,
    output_path: Path,
    root: Path,
) -> CustodyLedger:
    if output_path.resolve() in {attestation_path.resolve(), ledger_path.resolve()}:
        raise OmivInputError("attestation custody append cannot overwrite an input")
    ledger = verify_custody_ledger(ledger_path, root)
    attestation = verify_attestation(attestation_path)
    try:
        reference = attestation_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise OmivInputError("attestation must be beneath the verification root") from exc
    event_input = attestation_to_custody_event_input(attestation, attestation_reference=reference)
    updated = append_evidence_event(ledger, event_input)
    atomic_write_text(
        output_path,
        pretty_custody_json(updated),
        forbidden_inputs=(attestation_path, ledger_path),
    )
    return updated
