"""Explicit, deterministic append workflow for custody ledgers."""

from __future__ import annotations

from omiv.canonical import canonical_sha256
from omiv.custody.builder import assemble_ledger, build_event
from omiv.custody.models import (
    AssertionOrigin,
    CustodyEventInput,
    CustodyEventType,
    CustodyLedger,
    EvidenceLinkageStatus,
)
from omiv.custody.policy import custody_policy
from omiv.errors import OmivInputError


def _claim_identity(event_input: CustodyEventInput) -> str:
    data = event_input.model_dump(mode="json", by_alias=True)
    data.pop("schema", None)
    return canonical_sha256(data)


def _append_event(
    ledger: CustodyLedger,
    event_input: CustodyEventInput,
    *,
    allowed_origins: set[AssertionOrigin],
) -> CustodyLedger:
    if event_input.assertion_origin not in allowed_origins:
        allowed = ", ".join(sorted(item.value for item in allowed_origins))
        raise OmivInputError(f"appended event origin must be one of: {allowed}")
    policy = custody_policy()
    if event_input.event_type not in policy.allowed_event_types or event_input.event_type in {
        CustodyEventType.REVOCATION_RECORDED_RESERVED,
        CustodyEventType.EXPIRATION_RECORDED_RESERVED,
    }:
        raise OmivInputError(f"custody policy disallows append event {event_input.event_type}")
    new_claim = _claim_identity(event_input)
    for existing in ledger.events:
        raw = existing.model_dump(mode="json", by_alias=True)
        for field in (
            "event_id",
            "sequence",
            "chain_id",
            "previous_event_digest",
            "event_digest",
            "authenticity",
            "attestation_status",
        ):
            raw.pop(field)
        raw["schema"] = "omiv.custody-event-input.v1"
        comparable = CustodyEventInput.model_validate(raw)
        if _claim_identity(comparable) == new_claim:
            raise OmivInputError("duplicate custody event claim")
    last = ledger.events[-1]
    current_subject = (
        last.output_artifacts[0]
        if last.event_type
        in {
            CustodyEventType.TRANSFORMATION_RECORDED,
            CustodyEventType.QUANTIZATION_RECORDED,
        }
        and len(last.output_artifacts) == 1
        else last.subject
    )
    if event_input.event_type in {
        CustodyEventType.TRANSFORMATION_RECORDED,
        CustodyEventType.QUANTIZATION_RECORDED,
    }:
        if event_input.subject.identity_digest != current_subject.identity_digest:
            raise OmivInputError("transformation input does not match current subject")
        if len(event_input.input_artifacts) != 1 or len(event_input.output_artifacts) != 1:
            raise OmivInputError("transformation requires exactly one input and one output")
        if event_input.input_artifacts[0].identity_digest != current_subject.identity_digest:
            raise OmivInputError("transformation relation has the wrong input artifact")
    elif event_input.subject.identity_digest != current_subject.identity_digest:
        raise OmivInputError("custody subject divergence")
    event = build_event(
        event_input,
        chain_id=ledger.chain_id,
        sequence=len(ledger.events),
        previous_event_digest=ledger.latest_event_digest,
    )
    linkage = ledger.evidence_linkage
    if not event.evidence_references:
        linkage = (
            EvidenceLinkageStatus.PARTIAL if ledger.events else EvidenceLinkageStatus.UNAVAILABLE
        )
    elif any(
        reference.verification_mode != "full_verification"
        for reference in event.evidence_references
    ):
        linkage = EvidenceLinkageStatus.PARTIAL
    return assemble_ledger(
        subject=ledger.subject,
        policy_identity=ledger.policy_identity,
        passport_reference=ledger.passport_reference,
        validation_reference=ledger.validation_reference,
        events=[*ledger.events, event],
        selected_profile=ledger.selected_profile,
        evidence_linkage=linkage,
    )


def append_event(ledger: CustodyLedger, event_input: CustodyEventInput) -> CustodyLedger:
    """Append a strict user declaration without trust escalation."""
    if event_input.assertion_origin != AssertionOrigin.USER_DECLARED:
        raise OmivInputError("appended event inputs must remain USER_DECLARED")
    return _append_event(ledger, event_input, allowed_origins={AssertionOrigin.USER_DECLARED})


def append_evidence_event(ledger: CustodyLedger, event_input: CustodyEventInput) -> CustodyLedger:
    """Append an already verified attestation-derived event."""
    return _append_event(
        ledger,
        event_input,
        allowed_origins={
            AssertionOrigin.USER_DECLARED,
            AssertionOrigin.SYSTEM_OBSERVED,
            AssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE,
            AssertionOrigin.IMPORTED_ATTESTATION,
        },
    )
