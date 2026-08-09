"""Resolution-continuity and runtime-binding evaluation without live resolution."""

from __future__ import annotations

import re
from collections.abc import Sequence

from omiv.runtime_resolution.building import build_continuity_assessment
from omiv.runtime_resolution.models import (
    ContinuityOutcome,
    HistoricalCutoffOutcome,
    IdentifierKind,
    RegistryResolutionReceipt,
    RequestedModelIdentifier,
    ResolutionContinuityAssessment,
    ResolutionStatus,
    object_reference,
)


def assess_resolution_continuity(
    requested: RequestedModelIdentifier,
    receipts: Sequence[RegistryResolutionReceipt],
) -> ResolutionContinuityAssessment:
    """Compare only the supplied receipts; no interval is inferred between them."""
    if len(receipts) < 2:
        return build_continuity_assessment(
            requested.subject,
            requested,
            receipts,
            outcome=ContinuityOutcome.INSUFFICIENT_OBSERVATIONS,
            findings=("AT_LEAST_TWO_COMPARABLE_RECEIPTS_REQUIRED",),
        )
    expected_ref = object_reference(requested)
    if any(receipt.requested_identifier != expected_ref for receipt in receipts):
        return build_continuity_assessment(
            requested.subject,
            requested,
            receipts,
            outcome=ContinuityOutcome.REQUESTED_IDENTIFIER_CHANGED,
            findings=("REQUESTED_IDENTIFIER_REFERENCE_MISMATCH",),
        )
    if any(receipt.resolved_identifier is None for receipt in receipts):
        return build_continuity_assessment(
            requested.subject,
            requested,
            receipts,
            outcome=ContinuityOutcome.RESOLVED_IDENTITY_NOT_DISCLOSED,
            findings=("RESOLVED_IDENTITY_NOT_DISCLOSED",),
        )
    first = receipts[0]
    if any(
        (
            receipt.provider,
            receipt.namespace,
            receipt.api_surface,
            receipt.purpose,
            receipt.observation_level,
            receipt.resolution_mechanism,
            receipt.resolved_identity_kind,
        )
        != (
            first.provider,
            first.namespace,
            first.api_surface,
            first.purpose,
            first.observation_level,
            first.resolution_mechanism,
            first.resolved_identity_kind,
        )
        for receipt in receipts[1:]
    ):
        return build_continuity_assessment(
            requested.subject,
            requested,
            receipts,
            outcome=ContinuityOutcome.OBSERVATION_WINDOWS_NOT_COMPARABLE,
            findings=("RESOLUTION_METHOD_OR_IDENTITY_SEMANTICS_NOT_COMPARABLE",),
        )
    resolved = tuple(receipt.resolved_identifier for receipt in receipts)
    if len(set(resolved)) == 1:
        outcome = ContinuityOutcome.SAME_RESOLVED_IDENTITY_FOR_SUPPLIED_OBSERVATIONS
        findings = ("SAME_DISCLOSED_IDENTITY_AT_SUPPLIED_OBSERVATIONS",)
    elif any(
        receipt.status == ResolutionStatus.REDIRECTED_TO_DISCLOSED_IDENTIFIER
        or receipt.resolved_identity_kind == IdentifierKind.REDIRECTED_IDENTIFIER
        for receipt in receipts
    ):
        outcome = ContinuityOutcome.REDIRECT_TARGET_CHANGED_FOR_SUPPLIED_OBSERVATIONS
        findings = ("REDIRECT_TARGET_CHANGED",)
    else:
        outcome = ContinuityOutcome.ALIAS_REBOUND_FOR_SUPPLIED_OBSERVATIONS
        findings = ("MUTABLE_ALIAS_REBOUND",)
    return build_continuity_assessment(
        requested.subject,
        requested,
        receipts,
        outcome=outcome,
        findings=findings,
    )


def known_as_of_cutoff(
    *, available_at: str, effective_at: str, cutoff: str
) -> HistoricalCutoffOutcome:
    """Evaluate explicit supplied times without deriving or consulting host time."""
    if available_at == "NOT_RECORDED":
        return HistoricalCutoffOutcome.AVAILABILITY_NOT_RECORDED
    if effective_at == "NOT_RECORDED":
        return HistoricalCutoffOutcome.INVALID

    pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    if not all(re.fullmatch(pattern, value) for value in (available_at, effective_at, cutoff)):
        return HistoricalCutoffOutcome.INVALID
    if available_at > cutoff:
        return HistoricalCutoffOutcome.NOT_KNOWN_AS_OF_CUTOFF
    if effective_at > cutoff:
        return HistoricalCutoffOutcome.KNOWN_FUTURE_EFFECTIVE_AS_OF_CUTOFF
    return HistoricalCutoffOutcome.KNOWN_EFFECTIVE_AS_OF_CUTOFF
