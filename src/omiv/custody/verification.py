"""Schema, hash-link, evidence, and reconstruction verification for custody ledgers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import load_json_value
from omiv.custody.builder import (
    artifact_reference_from_passport,
    build_evidence_custody_ledger,
    chain_id_for,
    ledger_digest,
)
from omiv.custody.models import (
    AttestationStatus,
    CustodyEvent,
    CustodyEventType,
    CustodyLedger,
    EventAuthenticity,
    EventAuthenticitySummary,
    EvidenceLinkageStatus,
    ExpirationStatus,
    IntegrityStatus,
    LifecycleCompleteness,
    OverallCustodyStatus,
    RevocationStatus,
    SubjectContinuityStatus,
)
from omiv.custody.policy import custody_policy, evaluate_completeness
from omiv.errors import OmivInputError
from omiv.external_artifacts import ExternalArtifactUnavailable
from omiv.passport.verification import load_passport, verify_passport
from omiv.validation.reporting import verify_validation_inventory_with_availability

MAX_CUSTODY_BYTES = 8 * 1024 * 1024


def _load(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_CUSTODY_BYTES:
            raise OmivInputError(f"custody ledger exceeds {MAX_CUSTODY_BYTES} bytes")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot load custody ledger: {exc}") from exc


def reconstruct_subject_continuity(
    ledger: CustodyLedger,
) -> SubjectContinuityStatus:
    current = ledger.subject
    for event in ledger.events:
        if event.subject.identity_digest != current.identity_digest:
            return SubjectContinuityStatus.DIVERGED
        if event.event_type in {
            CustodyEventType.TRANSFORMATION_RECORDED,
            CustodyEventType.QUANTIZATION_RECORDED,
        }:
            if len(event.input_artifacts) != 1 or len(event.output_artifacts) != 1:
                return SubjectContinuityStatus.DIVERGED
            if event.input_artifacts[0].identity_digest != current.identity_digest:
                return SubjectContinuityStatus.DIVERGED
            if event.output_artifacts[0].identity_digest == current.identity_digest:
                return SubjectContinuityStatus.DIVERGED
            current = event.output_artifacts[0]
        else:
            referenced = [*event.input_artifacts, *event.output_artifacts]
            if any(item.identity_digest != current.identity_digest for item in referenced):
                return SubjectContinuityStatus.DIVERGED
            if event.output_artifacts:
                return SubjectContinuityStatus.DIVERGED
    return SubjectContinuityStatus.CONSISTENT


def _authenticity(events: list[CustodyEvent]) -> EventAuthenticitySummary:
    return EventAuthenticitySummary(
        statuses=sorted({item.authenticity for item in events}, key=lambda item: item.value),
        unattested_event_count=sum(
            item.attestation_status == AttestationStatus.UNATTESTED for item in events
        ),
        signed_event_count=0,
        limitation=(
            "Hash linking protects recorded event integrity but does not authenticate an actor "
            "or prove that a real-world action occurred."
        ),
    )


def _verify_internal(ledger: CustodyLedger) -> None:
    policy = custody_policy()
    if ledger.policy_identity.custody_policy_digest != policy.policy_digest:
        raise OmivInputError("custody-policy digest mismatch")
    if ledger.chain_id != chain_id_for(ledger.subject, policy.policy_digest):
        raise OmivInputError("custody chain identity mismatch")
    if ledger.ledger_digest != ledger_digest(ledger):
        raise OmivInputError("custody ledger digest mismatch")
    if any(event.chain_id != ledger.chain_id for event in ledger.events):
        raise OmivInputError("custody event chain identity mismatch")
    if any(event.event_type not in policy.allowed_event_types for event in ledger.events):
        raise OmivInputError("custody ledger contains a policy-disallowed event")
    continuity = reconstruct_subject_continuity(ledger)
    if ledger.subject_continuity != continuity:
        raise OmivInputError("custody subject-continuity reconstruction mismatch")
    expected_analysis = evaluate_completeness(
        [event.event_type for event in ledger.events], ledger.selected_profile
    )
    if ledger.missing_event_analysis != expected_analysis:
        raise OmivInputError("custody missing-event reconstruction mismatch")
    lifecycle = (
        LifecycleCompleteness.INCOMPLETE
        if expected_analysis.missing_event_types or expected_analysis.missing_evidence_concepts
        else LifecycleCompleteness.COMPLETE
    )
    if ledger.lifecycle_completeness != lifecycle:
        raise OmivInputError("custody lifecycle-completeness reconstruction mismatch")
    if ledger.event_authenticity_summary != _authenticity(ledger.events):
        raise OmivInputError("custody authenticity reconstruction mismatch")
    if any(
        event.authenticity == EventAuthenticity.SIGNED_ATTESTATION_RESERVED
        for event in ledger.events
    ):
        raise OmivInputError("signed custody attestations are reserved")
    if ledger.revocation_status != RevocationStatus.NOT_ASSESSED:
        raise OmivInputError("Phase 5B revocation status must remain NOT_ASSESSED")
    if ledger.expiration_status != ExpirationStatus.NOT_ASSESSED:
        raise OmivInputError("Phase 5B expiration status must remain NOT_ASSESSED")
    expected_overall = (
        OverallCustodyStatus.DIVERGED
        if continuity == SubjectContinuityStatus.DIVERGED
        else OverallCustodyStatus.INCOMPLETE
        if lifecycle == LifecycleCompleteness.INCOMPLETE
        else OverallCustodyStatus.INTACT
    )
    if ledger.overall_custody_status != expected_overall:
        raise OmivInputError("overall custody verdict reconstruction mismatch")
    if any(
        status != IntegrityStatus.INTACT
        for status in (
            ledger.ledger_integrity,
            ledger.event_digest_integrity,
            ledger.parent_link_integrity,
        )
    ):
        raise OmivInputError("stored custody integrity status is not INTACT")


def load_custody_ledger(path: Path) -> CustodyLedger:
    try:
        ledger = CustodyLedger.model_validate(_load(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid custody ledger: {exc}") from exc
    _verify_internal(ledger)
    return ledger


def _verify_event_evidence(
    ledger: CustodyLedger,
    *,
    root: Path,
    passport_digest: str,
    validation_digest: str,
    finding_ids: set[str],
    policy_digests: set[str],
) -> EvidenceLinkageStatus:
    modes: list[str] = []
    unavailable_event = False
    for event in ledger.events:
        if event.assertion_origin.value == "DERIVED_FROM_VERIFIED_EVIDENCE" and not (
            event.evidence_references
        ):
            raise OmivInputError("evidence-derived custody event has no evidence reference")
        if not event.evidence_references:
            unavailable_event = True
        for reference in event.evidence_references:
            modes.append(reference.verification_mode)
            if reference.role == "model_passport":
                if reference.digest != passport_digest:
                    raise OmivInputError("custody event passport evidence digest mismatch")
            elif reference.role == "validation_inventory":
                if reference.digest != validation_digest:
                    raise OmivInputError("custody event validation evidence digest mismatch")
                if not set(reference.finding_ids).issubset(finding_ids):
                    raise OmivInputError("custody evidence references an unknown finding")
                if not set(reference.policy_digests).issubset(policy_digests):
                    raise OmivInputError("custody evidence references an unknown policy")
            elif reference.role == "artifact_attestation":
                if reference.relative_path is None:
                    raise OmivInputError("attestation evidence requires a relative path")
                from omiv.attestations.verification import verify_attestation

                attestation = verify_attestation(root / reference.relative_path)
                if attestation.attestation_digest != reference.digest:
                    raise OmivInputError("custody attestation evidence digest mismatch")
            elif reference.verification_mode == "full_verification":
                raise OmivInputError("unknown evidence cannot claim full verification")
    if not modes:
        return EvidenceLinkageStatus.UNAVAILABLE
    if unavailable_event:
        return EvidenceLinkageStatus.PARTIAL
    if all(mode == "full_verification" for mode in modes):
        return EvidenceLinkageStatus.VERIFIED
    if any(mode == "unverifiable_reference" for mode in modes):
        return EvidenceLinkageStatus.PARTIAL
    return EvidenceLinkageStatus.PARTIAL


def verify_custody_ledger(path: Path, root: Path) -> CustodyLedger:
    ledger = load_custody_ledger(path)
    root = root.resolve()
    passport_path = root / ledger.passport_reference.relative_path
    validation_path = root / ledger.validation_reference.relative_path
    verification = verify_validation_inventory_with_availability(validation_path, root)
    if not verification.external_artifacts_available:
        unavailable = next(item for item in verification.external_artifacts if not item.available)
        raise ExternalArtifactUnavailable(unavailable.expected)
    passport_result = verify_passport(passport_path, root=root)
    if passport_result.mode.value != "full_verification":
        raise OmivInputError("custody passport dependency was not fully verified")
    passport = load_passport(passport_path)
    validation = verification.inventory
    if ledger.passport_reference.digest != passport.passport_digest:
        raise OmivInputError("custody passport linkage mismatch")
    if ledger.validation_reference.digest != validation.inventory_digest:
        raise OmivInputError("custody validation linkage mismatch")
    if ledger.subject != artifact_reference_from_passport(passport):
        raise OmivInputError("custody subject does not match the Model Passport")
    identity = ledger.policy_identity
    if identity.passport_policy_digest != passport.policy_identity.passport_policy_digest:
        raise OmivInputError("custody passport-policy linkage mismatch")
    if identity.validation_profile_policy_digest != validation.profile_policy.policy_digest:
        raise OmivInputError("custody validation-policy linkage mismatch")
    if identity.ontology_policy_digest != validation.model_pack_identity.ontology_policy_digest:
        raise OmivInputError("custody ontology-policy linkage mismatch")
    if identity.mapping_policy_digest != validation.model_pack_identity.mapping_policy_digest:
        raise OmivInputError("custody mapping-policy linkage mismatch")
    linkage = _verify_event_evidence(
        ledger,
        root=root,
        passport_digest=passport.passport_digest,
        validation_digest=validation.inventory_digest,
        finding_ids={item.finding_id for item in validation.findings},
        policy_digests={
            validation.profile_policy.policy_digest,
            validation.model_pack_identity.ontology_policy_digest,
            validation.model_pack_identity.mapping_policy_digest,
            passport.policy_identity.passport_policy_digest,
        },
    )
    if ledger.evidence_linkage != linkage:
        raise OmivInputError("custody evidence-linkage reconstruction mismatch")
    expected = build_evidence_custody_ledger(
        passport,
        validation,
        passport_reference=ledger.passport_reference.relative_path,
        validation_reference=ledger.validation_reference.relative_path,
        selected_profile=ledger.selected_profile,
    )
    generated_count = len(expected.events)
    if ledger.events[:generated_count] != expected.events:
        raise OmivInputError("evidence-derived custody segment does not reconstruct")
    if len(ledger.events) == generated_count and ledger != expected:
        raise OmivInputError("custody ledger does not reconstruct from canonical evidence")
    return ledger
