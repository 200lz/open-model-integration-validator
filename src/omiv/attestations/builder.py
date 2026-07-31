"""Normalize and build deterministic canonical artifact attestations."""

from __future__ import annotations

from typing import Any

from omiv.attestations.models import (
    AcquisitionOutcome,
    ArtifactAttestation,
    ArtifactAttestationInput,
    ArtifactContinuity,
    AttestationAssertionOrigin,
    AttestationKind,
    Authenticity,
    CommandIdentity,
    ConfigurationIdentity,
    EvidenceLinkage,
    ExecutionResult,
    ExecutionVerification,
    IdentityStatus,
    MaterializationEligibility,
    ProvenanceStrength,
    ToolExecutionRecord,
    ToolExecutionRecordInput,
    ToolIdentity,
)
from omiv.attestations.policy import attestation_policy
from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.errors import OmivInputError
from omiv.passport.models import EvidenceAvailability, ReferenceVerificationMode


def build_tool_identity(
    tool_name: str, *, tool_version: str | None = None, tool_revision: str | None = None
) -> ToolIdentity:
    body = {
        "tool_name": tool_name,
        "tool_version": tool_version,
        "tool_revision": tool_revision,
    }
    return ToolIdentity.model_validate({**body, "tool_identity_digest": canonical_sha256(body)})


def build_command_identity(
    program: str,
    normalized_arguments: list[str],
    *,
    argument_digests: list[str] | None = None,
    redacted_fields: list[str] | None = None,
) -> CommandIdentity:
    body = {
        "program": program,
        "normalized_arguments": normalized_arguments,
        "argument_digests": sorted(argument_digests or []),
        "redacted_fields": sorted(redacted_fields or []),
        "working_directory_status": "UNAVAILABLE",
    }
    return CommandIdentity.model_validate({**body, "command_digest": canonical_sha256(body)})


def build_configuration_identity(
    configuration_schema: str,
    normalized_parameters: dict[str, Any],
    *,
    redacted_parameter_names: list[str] | None = None,
    source_reference: str | None = None,
    availability: EvidenceAvailability = EvidenceAvailability.INCLUDED,
    verification_mode: ReferenceVerificationMode = (ReferenceVerificationMode.FULL_VERIFICATION),
) -> ConfigurationIdentity:
    body = {
        "configuration_schema": configuration_schema,
        "normalized_parameters": normalized_parameters,
        "redacted_parameter_names": sorted(redacted_parameter_names or []),
        "source_reference": source_reference,
        "availability": availability.value,
        "verification_mode": verification_mode.value,
    }
    return ConfigurationIdentity.model_validate(
        {**body, "configuration_digest": canonical_sha256(body)}
    )


def build_execution_record(value: ToolExecutionRecordInput) -> ToolExecutionRecord:
    raw = value.model_dump(mode="json", by_alias=True)
    raw["schema"] = "omiv.tool-execution-record.v1"
    identity = dict(raw)
    record_id = "exec_" + canonical_sha256(identity)[:32]
    raw["execution_record_id"] = record_id
    raw["execution_record_digest"] = canonical_sha256(raw)
    return ToolExecutionRecord.model_validate(raw)


def _evidence_linkage(value: ArtifactAttestationInput) -> EvidenceLinkage:
    references = value.evidence_references
    if not references:
        return EvidenceLinkage.UNAVAILABLE
    modes = {item.verification_mode for item in references}
    if all(
        item.verification_mode == ReferenceVerificationMode.FULL_VERIFICATION
        and item.availability == EvidenceAvailability.INCLUDED
        and item.included_payload is not None
        for item in references
    ):
        return EvidenceLinkage.FULLY_VERIFIED
    if modes == {ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION}:
        return EvidenceLinkage.DIGEST_LINKED
    if ReferenceVerificationMode.UNVERIFIABLE_REFERENCE in modes:
        return EvidenceLinkage.PARTIAL
    return EvidenceLinkage.PARTIAL


def _same_artifact(left: ArtifactReference, right: ArtifactReference) -> bool:
    return left.identity_digest == right.identity_digest


def _continuity(value: ArtifactAttestationInput) -> ArtifactContinuity:
    if value.attestation_kind == AttestationKind.TRANSFER:
        return (
            ArtifactContinuity.VALID
            if len(value.inputs) == len(value.outputs)
            and all(_same_artifact(a, b) for a, b in zip(value.inputs, value.outputs, strict=True))
            else ArtifactContinuity.DIVERGED
        )
    if value.attestation_kind == AttestationKind.ACQUISITION:
        if len(value.inputs) != 1 or len(value.outputs) != 1:
            return ArtifactContinuity.INVALID
        source, destination = value.inputs[0], value.outputs[0]
        stable = (
            source.content_digest and source.content_digest == destination.content_digest
        ) or (
            source.artifact_set_digest
            and source.artifact_set_digest == destination.artifact_set_digest
        )
        return ArtifactContinuity.VALID if stable else ArtifactContinuity.INCOMPLETE
    if not value.inputs or not value.outputs:
        return ArtifactContinuity.INVALID
    if value.subject.identity_digest != value.outputs[0].identity_digest:
        return ArtifactContinuity.DIVERGED
    if any(item.identity_digest == value.subject.identity_digest for item in value.inputs):
        return ArtifactContinuity.DIVERGED
    return ArtifactContinuity.VALID


def _execution_verification(
    value: ArtifactAttestationInput, linkage: EvidenceLinkage
) -> ExecutionVerification:
    if value.assertion_origin != AttestationAssertionOrigin.VERIFIED_EXECUTION_RECORD:
        return ExecutionVerification.NOT_APPLICABLE
    record = value.execution_record
    if record is None:
        raise OmivInputError("verified execution origin requires an execution record")
    if record.execution_result != ExecutionResult.SUCCEEDED:
        return ExecutionVerification.FAILED
    if linkage != EvidenceLinkage.FULLY_VERIFIED:
        raise OmivInputError("verified execution requires fully verified evidence")
    if [item.identity_digest for item in record.input_artifacts] != [
        item.identity_digest for item in value.inputs
    ] or [item.identity_digest for item in record.output_artifacts] != [
        item.identity_digest for item in value.outputs
    ]:
        raise OmivInputError("execution record artifact relationship mismatch")
    if value.tool_identity != record.tool_identity:
        raise OmivInputError("execution record tool identity mismatch")
    if value.configuration_identity != record.configuration_identity:
        raise OmivInputError("execution record configuration identity mismatch")
    if value.command_identity != record.command_identity:
        raise OmivInputError("execution record command identity mismatch")
    if value.environment_identity != record.environment_identity:
        raise OmivInputError("execution record environment identity mismatch")
    if not record.evidence_references or any(
        item.verification_mode != ReferenceVerificationMode.FULL_VERIFICATION
        or item.availability != EvidenceAvailability.INCLUDED
        or item.included_payload is None
        for item in record.evidence_references
    ):
        raise OmivInputError("execution record evidence is not fully reconstructable")
    attestation_evidence = {item.digest for item in value.evidence_references}
    if not {item.digest for item in record.evidence_references}.issubset(attestation_evidence):
        raise OmivInputError("execution record evidence is not linked by the attestation")
    environment = value.environment_identity
    if environment.status != IdentityStatus.UNAVAILABLE and (
        not environment.evidence_references
        or any(
            item.verification_mode != ReferenceVerificationMode.FULL_VERIFICATION
            or item.availability != EvidenceAvailability.INCLUDED
            or item.included_payload is None
            for item in environment.evidence_references
        )
    ):
        raise OmivInputError("execution environment identity is not reconstructable")
    return ExecutionVerification.VERIFIED


def _authenticity(
    value: ArtifactAttestationInput,
    linkage: EvidenceLinkage,
    execution: ExecutionVerification,
) -> Authenticity:
    origin = value.assertion_origin
    if origin == AttestationAssertionOrigin.USER_DECLARED:
        return Authenticity.DECLARED
    if origin == AttestationAssertionOrigin.SYSTEM_OBSERVED:
        if not any(
            ref.role == "system_observation"
            and ref.verification_mode == ReferenceVerificationMode.FULL_VERIFICATION
            for ref in value.evidence_references
        ):
            raise OmivInputError("system-observed origin requires observation evidence")
        return Authenticity.SYSTEM_OBSERVED
    if origin == AttestationAssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE:
        if linkage != EvidenceLinkage.FULLY_VERIFIED:
            raise OmivInputError("evidence-derived origin requires fully verified evidence")
        return Authenticity.EVIDENCE_LINKED
    if origin == AttestationAssertionOrigin.VERIFIED_EXECUTION_RECORD:
        if execution != ExecutionVerification.VERIFIED:
            raise OmivInputError("execution origin requires a verified execution record")
        return Authenticity.EXECUTION_VERIFIED
    if origin == AttestationAssertionOrigin.IMPORTED_ATTESTATION:
        return (
            Authenticity.EVIDENCE_LINKED
            if linkage == EvidenceLinkage.FULLY_VERIFIED
            else Authenticity.UNVERIFIED
        )
    raise OmivInputError("signed attestations are reserved for Phase 5D")


def _acquisition_outcome(
    value: ArtifactAttestationInput, linkage: EvidenceLinkage
) -> AcquisitionOutcome | None:
    if value.attestation_kind not in {AttestationKind.ACQUISITION, AttestationKind.TRANSFER}:
        return None
    if not value.inputs:
        return AcquisitionOutcome.INCOMPLETE
    if not value.outputs:
        return AcquisitionOutcome.INCOMPLETE
    exact = bool(
        value.inputs[0].content_digest
        and value.inputs[0].content_digest == value.outputs[0].content_digest
    )
    if exact and linkage == EvidenceLinkage.FULLY_VERIFIED:
        return AcquisitionOutcome.REMOTE_LOCAL_MATCH_VERIFIED
    if linkage == EvidenceLinkage.FULLY_VERIFIED:
        return AcquisitionOutcome.TRANSFER_EVIDENCE_LINKED
    if value.assertion_origin == AttestationAssertionOrigin.USER_DECLARED:
        return AcquisitionOutcome.DECLARED_ONLY
    return AcquisitionOutcome.SOURCE_AND_DESTINATION_IDENTIFIED


def _provenance(
    value: ArtifactAttestationInput,
    authenticity: Authenticity,
    execution: ExecutionVerification,
    continuity: ArtifactContinuity,
) -> ProvenanceStrength:
    if continuity in {ArtifactContinuity.DIVERGED, ArtifactContinuity.INVALID}:
        return ProvenanceStrength.BROKEN_PROVENANCE
    if authenticity == Authenticity.DECLARED:
        return ProvenanceStrength.DECLARED_PROVENANCE
    if authenticity == Authenticity.EVIDENCE_LINKED:
        return ProvenanceStrength.EVIDENCE_LINKED_PROVENANCE
    if execution == ExecutionVerification.VERIFIED:
        if continuity == ArtifactContinuity.VALID and value.outputs:
            return ProvenanceStrength.ARTIFACT_SPECIFIC_PROVENANCE
        return ProvenanceStrength.EXECUTION_LINKED_PROVENANCE
    if value.source_location is not None:
        return ProvenanceStrength.LOCATOR_PROVENANCE
    return ProvenanceStrength.NO_PROVENANCE


def _materialization(
    value: ArtifactAttestationInput,
    linkage: EvidenceLinkage,
    continuity: ArtifactContinuity,
) -> MaterializationEligibility:
    if continuity != ArtifactContinuity.VALID:
        return MaterializationEligibility.NOT_ELIGIBLE
    if value.attestation_kind != AttestationKind.TRANSFER:
        return MaterializationEligibility.ELIGIBLE
    boundary_evidence = any(
        item.role == "custody_boundary_entry"
        and item.verification_mode == ReferenceVerificationMode.FULL_VERIFICATION
        and item.availability == EvidenceAvailability.INCLUDED
        and item.included_payload is not None
        for item in value.evidence_references
    )
    claims = value.claim_details
    if not (
        claims.get("new_custody_boundary_entry") is True
        and claims.get("destination_identity_status") == "VERIFIED"
        and claims.get("acquisition_event_requirements") == "SATISFIED"
        and linkage == EvidenceLinkage.FULLY_VERIFIED
        and boundary_evidence
    ):
        return MaterializationEligibility.NOT_ELIGIBLE
    return MaterializationEligibility.ELIGIBLE


def build_attestation(value: ArtifactAttestationInput) -> ArtifactAttestation:
    """Reconstruct every trust-relevant field from input, evidence, and policy."""
    policy = attestation_policy()
    linkage = _evidence_linkage(value)
    continuity = _continuity(value)
    if continuity in {ArtifactContinuity.DIVERGED, ArtifactContinuity.INVALID}:
        raise OmivInputError("artifact continuity is invalid or diverged")
    execution = _execution_verification(value, linkage)
    authenticity = _authenticity(value, linkage, execution)
    provenance = _provenance(value, authenticity, execution, continuity)
    materialization = _materialization(value, linkage, continuity)
    raw = value.model_dump(mode="json", by_alias=True)
    raw["schema"] = "omiv.artifact-attestation.v1"
    raw.update(
        {
            "authenticity": authenticity.value,
            "acquisition_outcome": (
                outcome.value
                if (outcome := _acquisition_outcome(value, linkage)) is not None
                else None
            ),
            "verification_summary": {
                "integrity": "VALID",
                "evidence_linkage": linkage.value,
                "execution_verification": execution.value,
                "artifact_continuity": continuity.value,
                "provenance_strength": provenance.value,
                "materialization_eligibility": materialization.value,
                "execution_record_integrity": (
                    "VERIFIED" if execution == ExecutionVerification.VERIFIED else "NOT_AVAILABLE"
                ),
                "cryptographic_signature": "NOT_AVAILABLE",
                "issuer_authentication": "UNVERIFIED",
                "actor_authenticity": "UNVERIFIED",
                "attestation_signature_boundary": "UNSIGNED",
                "payload_status": "NOT_CHECKED",
                "numerical_fidelity_status": "NOT_CHECKED",
                "security_status": "NOT_CHECKED",
                "runtime_status": "NOT_CHECKED",
            },
            "policy_identity": {
                "policy_schema": policy.schema_id,
                "policy_digest": policy.policy_digest,
            },
        }
    )
    identity = dict(raw)
    attestation_id = "att_" + canonical_sha256(identity)[:32]
    raw["attestation_id"] = attestation_id
    raw["attestation_digest"] = canonical_sha256(raw)
    return ArtifactAttestation.model_validate(raw)
