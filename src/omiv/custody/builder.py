"""Build evidence-derived linear custody ledgers."""

from __future__ import annotations

from typing import Any

from omiv.canonical import canonical_sha256
from omiv.custody.models import (
    ActorReference,
    ArtifactReference,
    AssertionOrigin,
    AttestationStatus,
    CustodyEvent,
    CustodyEventInput,
    CustodyEventType,
    CustodyEvidenceReference,
    CustodyLedger,
    CustodyPolicyReference,
    EnvironmentReference,
    EventAuthenticity,
    EventAuthenticitySummary,
    EvidenceLinkageStatus,
    ExpirationStatus,
    IntegrityStatus,
    LedgerArtifactReference,
    LedgerPolicyIdentity,
    LifecycleCompleteness,
    OverallCustodyStatus,
    ReferenceStatus,
    RevocationStatus,
    SubjectContinuityStatus,
)
from omiv.custody.policy import custody_policy, evaluate_completeness
from omiv.errors import OmivInputError
from omiv.passport.models import EvidenceAvailability, ModelPassport
from omiv.validation.models import ValidationInventory


def artifact_reference_from_passport(passport: ModelPassport) -> ArtifactReference:
    artifact = passport.artifact_identity
    origin = artifact.origin
    content = artifact.content_identity
    data: dict[str, Any] = {
        "origin_type": origin.origin_type,
        "provider": origin.provider,
        "repository": origin.repository,
        "repository_type": origin.repository_type,
        "resolved_revision": origin.resolved_revision,
        "selection": artifact.variant_identity.selection,
        "artifact_set_digest": content.artifact_set_digest,
        "content_digest": None,
        "format": artifact.format_identity.format,
        "architecture": artifact.format_identity.architecture,
        "variant": artifact.variant_identity.variant,
        "file_count": content.file_count,
        "total_declared_bytes": content.total_declared_bytes,
        "passport_id": passport.passport_id,
        "passport_digest": passport.passport_digest,
        "validation_inventory_digest": (
            passport.evidence_identity.validation_inventory_digest
        ),
    }
    identity = dict(data)
    identity.pop("passport_id")
    identity.pop("passport_digest")
    identity.pop("validation_inventory_digest")
    data["identity_digest"] = canonical_sha256(identity)
    return ArtifactReference.model_validate(data)


def chain_id_for(subject: ArtifactReference, policy_digest: str) -> str:
    return "mcoc_" + canonical_sha256(
        {
            "schema": "omiv.custody-ledger.v1",
            "subject_identity_digest": subject.identity_digest,
            "genesis_policy": "evidence-derived-linear-custody-v1",
            "custody_policy_digest": policy_digest,
        }
    )[:32]


def _authenticity(origin: AssertionOrigin) -> EventAuthenticity:
    return {
        AssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE: (
            EventAuthenticity.EVIDENCE_DERIVED
        ),
        AssertionOrigin.SYSTEM_OBSERVED: EventAuthenticity.SYSTEM_OBSERVED,
        AssertionOrigin.USER_DECLARED: EventAuthenticity.USER_DECLARED,
        AssertionOrigin.IMPORTED_ATTESTATION: EventAuthenticity.UNVERIFIED,
        AssertionOrigin.SIGNED_ATTESTATION_RESERVED: (
            EventAuthenticity.SIGNED_ATTESTATION_RESERVED
        ),
    }[origin]


def build_event(
    event_input: CustodyEventInput,
    *,
    chain_id: str,
    sequence: int,
    previous_event_digest: str | None,
) -> CustodyEvent:
    raw = event_input.model_dump(mode="json", by_alias=True)
    raw["schema"] = "omiv.custody-event.v1"
    raw.update(
        {
            "sequence": sequence,
            "chain_id": chain_id,
            "previous_event_digest": previous_event_digest,
            "authenticity": _authenticity(event_input.assertion_origin).value,
            "attestation_status": AttestationStatus.UNATTESTED.value,
        }
    )
    event_id = "ce_" + canonical_sha256(raw)[:32]
    raw["event_id"] = event_id
    raw["event_digest"] = canonical_sha256(raw)
    return CustodyEvent.model_validate(raw)


def _policy_identity(
    passport: ModelPassport, validation: ValidationInventory
) -> LedgerPolicyIdentity:
    return LedgerPolicyIdentity(
        custody_policy_digest=custody_policy().policy_digest,
        passport_policy_digest=passport.policy_identity.passport_policy_digest,
        validation_profile_policy_digest=validation.profile_policy.policy_digest,
        ontology_policy_digest=validation.model_pack_identity.ontology_policy_digest,
        mapping_policy_digest=validation.model_pack_identity.mapping_policy_digest,
    )


def _policy_references(
    passport: ModelPassport, validation: ValidationInventory
) -> list[CustodyPolicyReference]:
    identity = _policy_identity(passport, validation)
    values = {
        "custody_policy": identity.custody_policy_digest,
        "mapping_policy": identity.mapping_policy_digest,
        "ontology_policy": identity.ontology_policy_digest,
        "passport_policy": identity.passport_policy_digest,
        "validation_profile_policy": identity.validation_profile_policy_digest,
    }
    return [
        CustodyPolicyReference(policy_id=name, policy_digest=digest)
        for name, digest in sorted(values.items())
    ]


def _validation_evidence(
    validation: ValidationInventory,
    validation_reference: str,
    *,
    finding_ids: list[str],
) -> CustodyEvidenceReference:
    return CustodyEvidenceReference(
        role="validation_inventory",
        schema=validation.schema_id,
        digest=validation.inventory_digest,
        availability=EvidenceAvailability.PRIVATE,
        verification_mode="full_verification",
        finding_ids=sorted(finding_ids),
        policy_digests=sorted(
            {
                validation.profile_policy.policy_digest,
                validation.model_pack_identity.ontology_policy_digest,
                validation.model_pack_identity.mapping_policy_digest,
            }
        ),
        source_phase="4F-6",
        relative_path=validation_reference,
    )


def _passport_evidence(
    passport: ModelPassport, passport_reference: str
) -> CustodyEvidenceReference:
    return CustodyEvidenceReference(
        role="model_passport",
        schema=passport.schema_id,
        digest=passport.passport_digest,
        availability=EvidenceAvailability.PRIVATE,
        verification_mode="full_verification",
        finding_ids=[],
        policy_digests=[passport.policy_identity.passport_policy_digest],
        source_phase="5A",
        relative_path=passport_reference,
    )


def _unavailable_actor() -> ActorReference:
    return ActorReference(status=ReferenceStatus.UNAVAILABLE)


def _unavailable_environment() -> EnvironmentReference:
    return EnvironmentReference(status=ReferenceStatus.UNAVAILABLE)


def _event_input(
    *,
    event_type: CustodyEventType,
    subject: ArtifactReference,
    action: str,
    evidence: list[CustodyEvidenceReference],
    policies: list[CustodyPolicyReference],
    claims: dict[str, Any],
    limitations: list[str],
) -> CustodyEventInput:
    return CustodyEventInput(
        event_type=event_type,
        subject=subject,
        input_artifacts=[],
        output_artifacts=[],
        action=action,
        assertion_origin=AssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE,
        actor_reference=_unavailable_actor(),
        tool_reference=None,
        environment_reference=_unavailable_environment(),
        policy_references=policies,
        evidence_references=evidence,
        event_claims=claims,
        limitations=limitations,
    )


def _finding_ids(validation: ValidationInventory, stage_names: set[str]) -> list[str]:
    return sorted(
        {
            finding_id
            for stage in validation.evidence_stages
            if stage.stage.value in stage_names
            for finding_id in stage.finding_ids
        }
    )


def _evidence_event_inputs(
    passport: ModelPassport,
    validation: ValidationInventory,
    subject: ArtifactReference,
    passport_reference: str,
    validation_reference: str,
) -> list[CustodyEventInput]:
    policies = _policy_references(passport, validation)

    def evidence(*stages: str) -> list[CustodyEvidenceReference]:
        return [
            _validation_evidence(
                validation,
                validation_reference,
                finding_ids=_finding_ids(validation, set(stages)),
            )
        ]

    immutable = validation.repository_identity.resolved_revision
    artifact_digest = subject.artifact_set_digest
    return [
        _event_input(
            event_type=CustodyEventType.SOURCE_LOCATOR_RECORDED,
            subject=subject,
            action="Record the source repository locator as context for the immutable subject.",
            evidence=evidence("repository_identity"),
            policies=policies,
            claims={
                "provider": validation.repository_identity.provider,
                "repository": validation.repository_identity.repository,
                "selection": validation.repository_identity.selection,
            },
            limitations=[
                "A repository locator is not evidence that artifact acquisition occurred."
            ],
        ),
        _event_input(
            event_type=CustodyEventType.IMMUTABLE_IDENTITY_ESTABLISHED,
            subject=subject,
            action="Establish immutable repository and artifact-set identity.",
            evidence=evidence("repository_identity", "repository_layout"),
            policies=policies,
            claims={
                "resolved_revision": immutable,
                "artifact_set_digest": artifact_digest,
            },
            limitations=[
                "Immutable metadata identity does not establish payload-byte integrity."
            ],
        ),
        _event_input(
            event_type=CustodyEventType.REMOTE_INSPECTION_RECORDED,
            subject=subject,
            action="Record verified bounded remote inspection evidence.",
            evidence=evidence("range_semantics", "file_prefix", "repository_layout"),
            policies=policies,
            claims={
                "evidence_graph_digest": validation.evidence_graph_digest,
                "artifact_index_digest": validation.artifact_index.index_digest,
                "tensor_payload_bytes_accepted": 0,
            },
            limitations=[
                "Remote header inspection is not artifact acquisition or payload validation."
            ],
        ),
        _event_input(
            event_type=CustodyEventType.FORMAT_INSPECTION_COMPLETED,
            subject=subject,
            action="Record verified GGUF header and split-container inspection.",
            evidence=evidence("complete_header", "split_container", "payload_span_bounds"),
            policies=policies,
            claims={
                "format": subject.format,
                "file_count": subject.file_count,
                "artifact_set_digest": artifact_digest,
            },
            limitations=[
                "Format inspection does not prove payload values or runtime compatibility."
            ],
        ),
        _event_input(
            event_type=CustodyEventType.STRUCTURAL_VALIDATION_COMPLETED,
            subject=subject,
            action="Record independently verified structural validation evidence.",
            evidence=evidence(
                "target_ontology",
                "structural_semantic_mapping",
                "deterministic_verification",
            ),
            policies=policies,
            claims={
                "validation_inventory_digest": validation.inventory_digest,
                "evidence_graph_digest": validation.evidence_graph_digest,
                "result": validation.structural_validation_result.value,
            },
            limitations=list(validation.limitations),
        ),
        _event_input(
            event_type=CustodyEventType.PASSPORT_ISSUED,
            subject=subject,
            action="Record issuance of the integrity-linked Model Passport.",
            evidence=[_passport_evidence(passport, passport_reference)],
            policies=policies,
            claims={
                "passport_id": passport.passport_id,
                "passport_digest": passport.passport_digest,
            },
            limitations=[
                "Passport issuance summarizes evidence; it is not an approval or signature."
            ],
        ),
    ]


def _authenticity_summary(events: list[CustodyEvent]) -> EventAuthenticitySummary:
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


def ledger_digest(ledger: CustodyLedger) -> str:
    data = ledger.model_dump(mode="json", by_alias=True)
    data.pop("ledger_digest")
    return canonical_sha256(data)


def assemble_ledger(
    *,
    subject: ArtifactReference,
    policy_identity: LedgerPolicyIdentity,
    passport_reference: LedgerArtifactReference,
    validation_reference: LedgerArtifactReference,
    events: list[CustodyEvent],
    selected_profile: str,
    evidence_linkage: EvidenceLinkageStatus,
    subject_continuity: SubjectContinuityStatus = SubjectContinuityStatus.CONSISTENT,
) -> CustodyLedger:
    analysis = evaluate_completeness(
        [event.event_type for event in events], selected_profile
    )
    lifecycle = (
        LifecycleCompleteness.INCOMPLETE
        if analysis.missing_event_types or analysis.missing_evidence_concepts
        else LifecycleCompleteness.COMPLETE
    )
    overall = (
        OverallCustodyStatus.DIVERGED
        if subject_continuity == SubjectContinuityStatus.DIVERGED
        else OverallCustodyStatus.INCOMPLETE
        if lifecycle == LifecycleCompleteness.INCOMPLETE
        else OverallCustodyStatus.INTACT
    )
    data: dict[str, Any] = {
        "chain_id": events[0].chain_id,
        "subject": subject,
        "policy_identity": policy_identity,
        "passport_reference": passport_reference,
        "validation_reference": validation_reference,
        "selected_profile": selected_profile,
        "events": events,
        "event_count": len(events),
        "genesis_event_digest": events[0].event_digest,
        "latest_event_digest": events[-1].event_digest,
        "ledger_integrity": IntegrityStatus.INTACT,
        "event_digest_integrity": IntegrityStatus.INTACT,
        "parent_link_integrity": IntegrityStatus.INTACT,
        "subject_continuity": subject_continuity,
        "evidence_linkage": evidence_linkage,
        "event_authenticity_summary": _authenticity_summary(events),
        "lifecycle_completeness": lifecycle,
        "missing_event_analysis": analysis,
        "revocation_status": RevocationStatus.NOT_ASSESSED,
        "expiration_status": ExpirationStatus.NOT_ASSESSED,
        "overall_custody_status": overall,
        "ledger_digest": "0" * 64,
    }
    draft = CustodyLedger.model_validate(data)
    data["ledger_digest"] = ledger_digest(draft)
    return CustodyLedger.model_validate(data)


def build_evidence_custody_ledger(
    passport: ModelPassport,
    validation: ValidationInventory,
    *,
    passport_reference: str,
    validation_reference: str,
    selected_profile: str,
) -> CustodyLedger:
    if passport.evidence_identity.validation_inventory_digest != validation.inventory_digest:
        raise OmivInputError("passport and validation inventory identity mismatch")
    subject = artifact_reference_from_passport(passport)
    policy = custody_policy()
    chain_id = chain_id_for(subject, policy.policy_digest)
    event_inputs = _evidence_event_inputs(
        passport,
        validation,
        subject,
        passport_reference,
        validation_reference,
    )
    events: list[CustodyEvent] = []
    previous: str | None = None
    for sequence, event_input in enumerate(event_inputs):
        event = build_event(
            event_input,
            chain_id=chain_id,
            sequence=sequence,
            previous_event_digest=previous,
        )
        events.append(event)
        previous = event.event_digest
    return assemble_ledger(
        subject=subject,
        policy_identity=_policy_identity(passport, validation),
        passport_reference=LedgerArtifactReference(
            role="model_passport",
            schema=passport.schema_id,
            digest=passport.passport_digest,
            relative_path=passport_reference,
        ),
        validation_reference=LedgerArtifactReference(
            role="validation_inventory",
            schema=validation.schema_id,
            digest=validation.inventory_digest,
            relative_path=validation_reference,
        ),
        events=events,
        selected_profile=selected_profile,
        evidence_linkage=EvidenceLinkageStatus.VERIFIED,
    )
