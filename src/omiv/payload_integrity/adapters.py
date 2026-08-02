"""Narrow Phase 5 integration mappings that cannot upgrade payload evidence."""

from omiv.payload_integrity.building import build_integration
from omiv.payload_integrity.models import EvidenceOutcome, IntegrationLink, PayloadIntegrityEvidence


def passport_summary(evidence: PayloadIntegrityEvidence) -> IntegrationLink:
    return build_integration(
        "PASSPORT", evidence, accepted=True, source_status=evidence.outcome.value
    )


def custody_linkage(evidence: PayloadIntegrityEvidence) -> IntegrationLink:
    return build_integration(
        "CUSTODY", evidence, accepted=True, source_status="APPEND_ONLY_RECORDED"
    )


def governance_adapter(evidence: PayloadIntegrityEvidence) -> IntegrationLink:
    accepted = evidence.policy_satisfied is True
    return build_integration(
        "GOVERNANCE", evidence, accepted=accepted, source_status=evidence.outcome.value
    )


def bind_security(
    evidence: PayloadIntegrityEvidence,
    *,
    security_subject_id: str,
    security_payload_digest: str,
    security_evidence_id: str,
    security_evidence_digest: str,
    security_scope_digest: str,
    complete_coverage: bool,
    security_limitations: tuple[str, ...] = (),
) -> IntegrationLink:
    accepted = (
        evidence.subject_id == security_subject_id
        and evidence.artifact_set_payload_digest == security_payload_digest
        and evidence.subject_scope_digest == security_scope_digest
        and complete_coverage
    )
    return build_integration(
        "SECURITY",
        evidence,
        accepted=accepted,
        source_status="EXACT_PAYLOAD_BINDING" if accepted else "PAYLOAD_BINDING_REJECTED",
        source_object_id=security_evidence_id,
        source_object_digest=security_evidence_digest,
        source_scope_digest=security_scope_digest,
        coverage_status="COMPLETE" if complete_coverage else "PARTIAL",
        source_limitations=security_limitations,
    )


def runtime_expected_identity(evidence: PayloadIntegrityEvidence) -> IntegrationLink:
    return build_integration(
        "RUNTIME",
        evidence,
        accepted=evidence.outcome
        in {
            EvidenceOutcome.MATCHES_COMPLETE_EXPECTATION,
            EvidenceOutcome.MATCHES_AUTHORIZED_COMPLETE_EXPECTATION,
        },
        source_status="EXPECTED_RUNTIME_IDENTITY_ONLY;OBSERVED_RUNTIME_IDENTITY_NOT_CREATED",
        expected_runtime_payload_digest=evidence.artifact_set_payload_digest,
        runtime_boundary=True,
    )


def historical_reference(evidence: PayloadIntegrityEvidence) -> IntegrationLink:
    accepted = evidence.available_at != "NOT_RECORDED"
    return build_integration(
        "HISTORICAL",
        evidence,
        accepted=accepted,
        source_status="KNOWN_AVAILABILITY" if accepted else "AVAILABILITY_NOT_RECORDED",
        temporal=True,
    )
