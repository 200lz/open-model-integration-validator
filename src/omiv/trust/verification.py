"""Offline reconstruction of signature integrity and layered policy trust."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.attestations.models import ArtifactAttestation, ToolExecutionRecord
from omiv.attestations.segment import AttestationCustodyLedger
from omiv.canonical import canonical_sha256, load_json_value
from omiv.continuous_trust.models import (
    AuditBundleManifest,
    AuditBundleVerificationResult,
    HistoricalEvaluationResult,
    TrustSnapshot,
    TrustTimeline,
)
from omiv.custody.models import CustodyEvent, CustodyLinkedPassport
from omiv.errors import OmivInputError
from omiv.governance.models import (
    ApprovalRecord,
    PolicyDecisionRecord,
    PromotionDecisionRecord,
    RejectionRecord,
    ReleaseCandidate,
)
from omiv.passport.models import ModelPassport
from omiv.payload_integrity.models import (
    ObservedPayloadManifest,
    PayloadExpectation,
    PayloadIntegrityEvidence,
)
from omiv.quantization.models import (
    QuantizationFidelityEvidence,
    QuantizationRelationshipDeclaration,
    RepresentationObservation,
)
from omiv.reconciliation.models import (
    RemoteLocalReconciliationEvidence,
    RemoteSnapshotExpectation,
    RemoteSnapshotManifest,
)
from omiv.runtime.models import (
    ContinuityEvaluation,
    DeploymentIntent,
    DeploymentManifest,
    DeploymentRecord,
    RuntimeObservation,
)
from omiv.security.models import (
    SecurityEvaluationResult,
    SecurityEvidenceBundle,
    SecurityScanExecutionRecord,
)
from omiv.trust.algorithms import public_key_from_raw, verify
from omiv.trust.domain import delegation_bytes, signed_object_bytes
from omiv.trust.models import (
    BindingStatus,
    DelegationRecord,
    DelegationStatus,
    EvaluationContext,
    ExpirationStatus,
    KeyIdentity,
    KeyStatus,
    KeyUsage,
    OverallSignedObjectStatus,
    RevocationAuthority,
    RevocationEvaluationResult,
    RevocationReason,
    RevocationRecord,
    RevocationScope,
    RevocationStatus,
    SignatureIntegrity,
    SignatureRecord,
    SignatureReport,
    SignatureVerificationResult,
    SignedObjectEnvelope,
    SignedObjectType,
    SignerBindingResult,
    SignerIdentityStatus,
    SignerIdentityVerification,
    SignerKeyBinding,
    TrustBundle,
    TrustFinding,
    TrustPolicy,
    TrustPolicyStatus,
    TrustRoot,
    ValidityWindow,
)
from omiv.trust.signing import (
    EXPECTED_PURPOSE,
    delegation_authorization_payload,
    object_metadata,
)

MAX_TRUST_INPUT_BYTES = 8 * 1024 * 1024


def _read(path: Path) -> Any:
    try:
        if path.is_symlink() or not path.is_file():
            raise OmivInputError("trust input must be a regular non-symlink file")
        if path.stat().st_size > MAX_TRUST_INPUT_BYTES:
            raise OmivInputError("trust input exceeds the bounded input limit")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot read trust input: {exc}") from exc


def load_envelope(path: Path) -> SignedObjectEnvelope:
    try:
        return SignedObjectEnvelope.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid signed-object envelope: {exc}") from exc


def load_bundle(path: Path) -> TrustBundle:
    try:
        return TrustBundle.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid trust bundle: {exc}") from exc


def load_policy(path: Path) -> TrustPolicy:
    try:
        return TrustPolicy.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid trust policy: {exc}") from exc


def load_context(path: Path) -> EvaluationContext:
    try:
        return EvaluationContext.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid evaluation context: {exc}") from exc


def load_delegation(path: Path) -> DelegationRecord:
    try:
        return DelegationRecord.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid delegation record: {exc}") from exc


def load_revocation(path: Path) -> RevocationRecord:
    try:
        return RevocationRecord.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid revocation record: {exc}") from exc


def _bounded_by(child: list[Any], parent: list[Any]) -> bool:
    """Return whether child constraints grant no authority outside parent constraints."""
    return not parent or (bool(child) and set(child).issubset(parent))


def _window_within(child: ValidityWindow | None, parent: ValidityWindow | None) -> bool:
    if parent is None:
        return True
    if child is None:
        return False
    if parent.not_before is not None and (
        child.not_before is None or child.not_before < parent.not_before
    ):
        return False
    return not (
        parent.not_after is not None
        and (child.not_after is None or child.not_after > parent.not_after)
    )


def _delegation_constraints_within(
    child: DelegationRecord, parent: DelegationRecord | TrustRoot
) -> bool:
    return all(
        _bounded_by(granted, allowed)
        for granted, allowed in (
            (child.allowed_purposes, parent.allowed_purposes),
            (child.allowed_object_types, parent.allowed_object_types),
            (child.namespaces, parent.namespaces),
            (child.provider_artifact_scopes, parent.provider_artifact_scopes),
        )
    )


def verify_delegation_record(delegation: DelegationRecord, bundle: TrustBundle) -> None:
    """Verify one delegation's authorization signature and bounded authority."""
    keys = {item.key_id: item for item in bundle.keys}
    delegator = keys.get(delegation.delegator_key_id)
    delegate = keys.get(delegation.delegate_key_id)
    if delegator is None or delegate is None:
        raise OmivInputError("delegation references a key absent from the trust bundle")
    if KeyUsage.DELEGATE_SIGNING not in delegator.allowed_key_usages:
        raise OmivInputError("delegator key lacks DELEGATE_SIGNING usage")
    payload = delegation_authorization_payload(delegation.model_dump(mode="json", by_alias=True))
    if not verify(
        public_key_from_raw(bytes.fromhex(delegator.public_key)),
        bytes.fromhex(delegation.authorization_signature),
        delegation_bytes(payload),
    ):
        raise OmivInputError("delegation authorization signature is invalid")
    constraints = (
        (delegation.allowed_purposes, delegator.allowed_purposes, "purpose"),
        (delegation.allowed_object_types, delegator.allowed_object_types, "object type"),
        (delegation.namespaces, delegator.namespaces, "namespace"),
        (
            delegation.provider_artifact_scopes,
            delegator.provider_artifact_scopes,
            "provider/artifact scope",
        ),
    )
    for granted, allowed, label in constraints:
        if not _bounded_by(granted, allowed):
            raise OmivInputError(f"delegation exceeds delegator {label} constraints")
    if not _window_within(delegation.validity, delegator.validity):
        raise OmivInputError("delegation validity exceeds delegator key validity")


def verify_bundle(bundle: TrustBundle) -> None:
    """Verify static references, constraints, and every delegation signature."""
    keys = {item.key_id: item for item in bundle.keys}
    identities = {item.signer_identity_id for item in bundle.signer_identities}
    for root in bundle.trust_roots:
        root_key = keys[root.key_id]
        if root_key.status != "ACTIVE":
            raise OmivInputError("active trust root references a disabled key")
        if root.delegation_allowed and KeyUsage.DELEGATE_SIGNING not in root_key.allowed_key_usages:
            raise OmivInputError("delegating trust root key lacks DELEGATE_SIGNING usage")
        root_constraints: tuple[tuple[list[Any], list[Any], str], ...] = (
            (root.allowed_purposes, root_key.allowed_purposes, "purpose"),
            (root.allowed_object_types, root_key.allowed_object_types, "object type"),
            (root.namespaces, root_key.namespaces, "namespace"),
            (
                root.provider_artifact_scopes,
                root_key.provider_artifact_scopes,
                "provider/artifact scope",
            ),
        )
        for granted, allowed, label in root_constraints:
            if not _bounded_by(granted, allowed):
                raise OmivInputError(f"trust root exceeds key {label} constraints")
    for binding in bundle.signer_key_bindings:
        bound_key = keys.get(binding.key_id)
        if bound_key is None or binding.signer_identity_id not in identities:
            raise OmivInputError("signer/key binding contains an unresolved reference")
        binding_constraints: tuple[tuple[list[Any], list[Any], str], ...] = (
            (binding.allowed_usages, bound_key.allowed_key_usages, "usage"),
            (binding.allowed_object_types, bound_key.allowed_object_types, "object type"),
            (binding.namespaces, bound_key.namespaces, "namespace"),
        )
        for granted, allowed, label in binding_constraints:
            if not _bounded_by(granted, allowed):
                raise OmivInputError(f"signer/key binding exceeds key {label} constraints")
    for delegation in bundle.delegations:
        verify_delegation_record(delegation, bundle)
    roots_by_key = {item.key_id: item for item in bundle.trust_roots}
    delegations_by_delegate: dict[str, list[DelegationRecord]] = {}
    for item in bundle.delegations:
        delegations_by_delegate.setdefault(item.delegate_key_id, []).append(item)
    graph = {item.delegate_key_id: item.delegator_key_id for item in bundle.delegations}
    for start in graph:
        current = start
        visited: set[str] = set()
        while current in graph:
            if current in visited:
                raise OmivInputError("delegation cycle detected")
            visited.add(current)
            current = graph[current]
    for delegation in bundle.delegations:
        authorities: list[tuple[ValidityWindow | None, int, DelegationRecord | TrustRoot]] = []
        authority_root = roots_by_key.get(delegation.delegator_key_id)
        if authority_root is not None and authority_root.delegation_allowed:
            authorities.append(
                (
                    authority_root.validity,
                    authority_root.maximum_delegation_depth,
                    authority_root,
                )
            )
        authorities.extend(
            (parent.validity, parent.maximum_subordinate_depth, parent)
            for parent in delegations_by_delegate.get(delegation.delegator_key_id, [])
        )
        if authorities and not any(
            depth >= 1
            and delegation.maximum_subordinate_depth <= depth - 1
            and _window_within(delegation.validity, validity)
            and _delegation_constraints_within(delegation, parent)
            for validity, depth, parent in authorities
        ):
            raise OmivInputError("delegation broadens parent authority")


def _validate_source_object(envelope: SignedObjectEnvelope) -> None:
    value = envelope.signed_object
    model: type[Any]
    if envelope.signed_object_type == SignedObjectType.ARTIFACT_ATTESTATION:
        model = ArtifactAttestation
    elif envelope.signed_object_type == SignedObjectType.TOOL_EXECUTION_RECORD:
        model = ToolExecutionRecord
    elif envelope.signed_object_type == SignedObjectType.CUSTODY_EVENT:
        model = CustodyEvent
    elif envelope.signed_object_type == SignedObjectType.CUSTODY_SEGMENT:
        model = AttestationCustodyLedger
    elif envelope.signed_object_type == SignedObjectType.POLICY_DECISION:
        model = PolicyDecisionRecord
    elif envelope.signed_object_type == SignedObjectType.APPROVAL_RECORD:
        model = ApprovalRecord
    elif envelope.signed_object_type == SignedObjectType.REJECTION_RECORD:
        model = RejectionRecord
    elif envelope.signed_object_type == SignedObjectType.RELEASE_CANDIDATE:
        model = ReleaseCandidate
    elif envelope.signed_object_type == SignedObjectType.PROMOTION_DECISION:
        model = PromotionDecisionRecord
    elif envelope.signed_object_type == SignedObjectType.SECURITY_SCAN_EXECUTION_RECORD:
        model = SecurityScanExecutionRecord
    elif envelope.signed_object_type == SignedObjectType.SECURITY_EVIDENCE_BUNDLE:
        model = SecurityEvidenceBundle
    elif envelope.signed_object_type == SignedObjectType.SECURITY_EVALUATION:
        model = SecurityEvaluationResult
    elif envelope.signed_object_type == SignedObjectType.DEPLOYMENT_INTENT:
        model = DeploymentIntent
    elif envelope.signed_object_type == SignedObjectType.DEPLOYMENT_MANIFEST:
        model = DeploymentManifest
    elif envelope.signed_object_type == SignedObjectType.DEPLOYMENT_RECORD:
        model = DeploymentRecord
    elif envelope.signed_object_type == SignedObjectType.RUNTIME_OBSERVATION:
        model = RuntimeObservation
    elif envelope.signed_object_type == SignedObjectType.CONTINUITY_EVALUATION:
        model = ContinuityEvaluation
    elif envelope.signed_object_type == SignedObjectType.TRUST_SNAPSHOT:
        model = TrustSnapshot
    elif envelope.signed_object_type == SignedObjectType.TRUST_TIMELINE:
        model = TrustTimeline
    elif envelope.signed_object_type == SignedObjectType.HISTORICAL_EVALUATION_RESULT:
        model = HistoricalEvaluationResult
    elif envelope.signed_object_type == SignedObjectType.AUDIT_BUNDLE_MANIFEST:
        model = AuditBundleManifest
    elif envelope.signed_object_type == SignedObjectType.AUDIT_BUNDLE_VERIFICATION_RESULT:
        model = AuditBundleVerificationResult
    elif envelope.signed_object_type == SignedObjectType.PAYLOAD_EXPECTATION:
        model = PayloadExpectation
    elif envelope.signed_object_type == SignedObjectType.OBSERVED_PAYLOAD_MANIFEST:
        model = ObservedPayloadManifest
    elif envelope.signed_object_type == SignedObjectType.PAYLOAD_INTEGRITY_EVIDENCE:
        model = PayloadIntegrityEvidence
    elif envelope.signed_object_type == SignedObjectType.REMOTE_SNAPSHOT_MANIFEST:
        model = RemoteSnapshotManifest
    elif envelope.signed_object_type == SignedObjectType.REMOTE_SNAPSHOT_EXPECTATION:
        model = RemoteSnapshotExpectation
    elif envelope.signed_object_type == SignedObjectType.REMOTE_LOCAL_RECONCILIATION_EVIDENCE:
        model = RemoteLocalReconciliationEvidence
    elif envelope.signed_object_type == SignedObjectType.QUANTIZATION_RELATIONSHIP_DECLARATION:
        model = QuantizationRelationshipDeclaration
    elif envelope.signed_object_type == SignedObjectType.REPRESENTATION_OBSERVATION:
        model = RepresentationObservation
    elif envelope.signed_object_type == SignedObjectType.QUANTIZATION_FIDELITY_EVIDENCE:
        model = QuantizationFidelityEvidence
    elif envelope.signed_object_schema == "omiv.model-passport.v1":
        model = ModelPassport
    else:
        model = CustodyLinkedPassport
    try:
        parsed = model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid canonical signed object: {exc}") from exc
    raw = parsed.model_dump(mode="json", by_alias=True)
    _, object_id, object_digest = object_metadata(raw, envelope.signed_object_type)
    digest_body = dict(raw)
    digest_field = {
        SignedObjectType.ARTIFACT_ATTESTATION: "attestation_digest",
        SignedObjectType.TOOL_EXECUTION_RECORD: "execution_record_digest",
        SignedObjectType.CUSTODY_EVENT: "event_digest",
        SignedObjectType.CUSTODY_SEGMENT: "ledger_digest",
        SignedObjectType.MODEL_PASSPORT: "passport_digest",
        SignedObjectType.POLICY_DECISION: "decision_digest",
        SignedObjectType.APPROVAL_RECORD: "approval_digest",
        SignedObjectType.REJECTION_RECORD: "rejection_digest",
        SignedObjectType.RELEASE_CANDIDATE: "candidate_digest",
        SignedObjectType.PROMOTION_DECISION: "promotion_decision_digest",
        SignedObjectType.SECURITY_SCAN_EXECUTION_RECORD: "execution_digest",
        SignedObjectType.SECURITY_EVIDENCE_BUNDLE: "bundle_digest",
        SignedObjectType.SECURITY_EVALUATION: "evaluation_digest",
        SignedObjectType.DEPLOYMENT_INTENT: "intent_digest",
        SignedObjectType.DEPLOYMENT_MANIFEST: "manifest_digest",
        SignedObjectType.DEPLOYMENT_RECORD: "record_digest",
        SignedObjectType.RUNTIME_OBSERVATION: "observation_digest",
        SignedObjectType.CONTINUITY_EVALUATION: "evaluation_digest",
        SignedObjectType.TRUST_SNAPSHOT: "snapshot_digest",
        SignedObjectType.TRUST_TIMELINE: "timeline_digest",
        SignedObjectType.HISTORICAL_EVALUATION_RESULT: "result_digest",
        SignedObjectType.AUDIT_BUNDLE_MANIFEST: "manifest_digest",
        SignedObjectType.AUDIT_BUNDLE_VERIFICATION_RESULT: "verification_digest",
        SignedObjectType.PAYLOAD_EXPECTATION: "expectation_digest",
        SignedObjectType.OBSERVED_PAYLOAD_MANIFEST: "manifest_digest",
        SignedObjectType.PAYLOAD_INTEGRITY_EVIDENCE: "evidence_digest",
        SignedObjectType.REMOTE_SNAPSHOT_MANIFEST: "manifest_digest",
        SignedObjectType.REMOTE_SNAPSHOT_EXPECTATION: "expectation_digest",
        SignedObjectType.REMOTE_LOCAL_RECONCILIATION_EVIDENCE: "evidence_digest",
        SignedObjectType.QUANTIZATION_RELATIONSHIP_DECLARATION: "declaration_digest",
        SignedObjectType.REPRESENTATION_OBSERVATION: "observation_digest",
        SignedObjectType.QUANTIZATION_FIDELITY_EVIDENCE: "evidence_digest",
    }[envelope.signed_object_type]
    digest_body.pop(digest_field)
    if object_digest != canonical_sha256(digest_body):
        raise OmivInputError("canonical signed object stored digest mismatch")
    if envelope.signed_object_type == SignedObjectType.MODEL_PASSPORT:
        if envelope.signed_object_schema == "omiv.model-passport.v1":
            passport_identity = {
                "schema": raw["schema"],
                "subject": raw["subject"],
                "artifact_identity": raw["artifact_identity"],
                "source_evidence_bundle_digest": raw["evidence_identity"][
                    "validation_inventory_digest"
                ],
                "passport_policy_digest": raw["policy_identity"]["passport_policy_digest"],
            }
        else:
            passport_identity = {
                "schema": raw["schema"],
                "base_passport_id": raw["base_passport_id"],
                "base_passport_digest": raw["base_passport_digest"],
                "subject": raw["subject"],
                "artifact_identity": raw["artifact_identity"],
                "custody_ledger_digest": raw["custody_summary"]["ledger_digest"],
                "passport_policy_digest": raw["policy_identity"]["passport_policy_digest"],
            }
        if object_id != "mp_" + canonical_sha256(passport_identity)[:32]:
            raise OmivInputError("canonical signed Passport identity mismatch")
    if object_id != envelope.signed_object_id:
        raise OmivInputError("signed object identity mismatch")
    if canonical_sha256(raw) != envelope.signed_object_digest:
        raise OmivInputError("signed object canonical-byte digest mismatch")


def _expiration(
    window: ValidityWindow | None, context: EvaluationContext | None
) -> ExpirationStatus:
    if window is None:
        return ExpirationStatus.UNAVAILABLE
    if context is None or context.evaluation_time is None:
        return ExpirationStatus.NOT_EVALUATED
    value = context.evaluation_time
    if window.not_before is not None and value < window.not_before:
        return ExpirationStatus.NOT_YET_VALID
    if window.not_after is not None and value > window.not_after:
        return ExpirationStatus.EXPIRED
    return ExpirationStatus.VALID


def _revocation(
    bundle: TrustBundle,
    targets: list[tuple[RevocationScope, str]],
    policy: TrustPolicy,
    context: EvaluationContext | None,
) -> tuple[RevocationStatus, list[RevocationEvaluationResult]]:
    applicable: list[RevocationRecord] = []
    evaluations: list[RevocationEvaluationResult] = []
    for record in bundle.revocations:
        if (record.scope, record.target_id) not in targets:
            continue
        authority = (
            RevocationAuthority.AUTHORIZED_BY_LOCAL_POLICY
            if policy.accept_local_declarative_revocation
            else RevocationAuthority.REJECTED_BY_POLICY
        )
        if authority == RevocationAuthority.REJECTED_BY_POLICY:
            evaluations.append(
                RevocationEvaluationResult(
                    revocation_id=record.revocation_id,
                    revocation_digest=record.revocation_digest,
                    authority=authority,
                    scope=record.scope,
                    target_id=record.target_id,
                    effective_status=RevocationStatus.NOT_APPLICABLE,
                    reason=record.reason,
                    replacement_reference=record.replacement_reference,
                )
            )
            continue
        effective_status = RevocationStatus.REVOKED
        if record.effective_at is not None:
            if context is None or context.evaluation_time is None:
                effective_status = RevocationStatus.NOT_EVALUATED
            elif context.evaluation_time < record.effective_at:
                effective_status = RevocationStatus.NOT_REVOKED
        if effective_status == RevocationStatus.REVOKED:
            effective_status = {
                RevocationReason.SUPERSEDED: RevocationStatus.SUPERSEDED,
                RevocationReason.WITHDRAWN: RevocationStatus.WITHDRAWN,
            }.get(record.reason, RevocationStatus.REVOKED)
        evaluations.append(
            RevocationEvaluationResult(
                revocation_id=record.revocation_id,
                revocation_digest=record.revocation_digest,
                authority=authority,
                scope=record.scope,
                target_id=record.target_id,
                effective_status=effective_status,
                reason=record.reason,
                replacement_reference=record.replacement_reference,
            )
        )
        if effective_status not in {
            RevocationStatus.NOT_REVOKED,
            RevocationStatus.NOT_APPLICABLE,
        }:
            applicable.append(record)
    if not applicable:
        return RevocationStatus.NOT_REVOKED, evaluations
    if any(item.effective_status == RevocationStatus.NOT_EVALUATED for item in evaluations):
        return RevocationStatus.NOT_EVALUATED, evaluations
    reasons = {item.reason for item in applicable}
    if RevocationReason.SUPERSEDED in reasons:
        return RevocationStatus.SUPERSEDED, evaluations
    if RevocationReason.WITHDRAWN in reasons:
        return RevocationStatus.WITHDRAWN, evaluations
    return RevocationStatus.REVOKED, evaluations


def _binding_result(
    record: SignatureRecord,
    bundle: TrustBundle,
    context: EvaluationContext | None,
) -> tuple[SignerBindingResult, str | None, SignerKeyBinding | None]:
    if record.binding_id is None:
        return SignerBindingResult.UNAVAILABLE, None, None
    binding = next(
        (item for item in bundle.signer_key_bindings if item.binding_id == record.binding_id), None
    )
    if binding is None or binding.key_id != record.key_id:
        return SignerBindingResult.BROKEN, None, binding
    if not any(
        item.signer_identity_id == binding.signer_identity_id for item in bundle.signer_identities
    ):
        return SignerBindingResult.BROKEN, None, binding
    expiration = _expiration(binding.validity, context)
    if expiration == ExpirationStatus.EXPIRED:
        return SignerBindingResult.EXPIRED, binding.signer_identity_id, binding
    if expiration == ExpirationStatus.NOT_YET_VALID:
        return SignerBindingResult.BROKEN, binding.signer_identity_id, binding
    status = {
        BindingStatus.VERIFIED_BY_TRUST_BUNDLE: SignerBindingResult.VERIFIED,
        BindingStatus.EVIDENCE_LINKED: SignerBindingResult.EVIDENCE_LINKED,
        BindingStatus.DECLARED: SignerBindingResult.DECLARED,
        BindingStatus.PARTIAL: SignerBindingResult.PARTIAL,
        BindingStatus.UNAVAILABLE: SignerBindingResult.UNAVAILABLE,
        BindingStatus.BROKEN: SignerBindingResult.BROKEN,
        BindingStatus.REVOKED: SignerBindingResult.REVOKED,
        BindingStatus.EXPIRED: SignerBindingResult.EXPIRED,
    }[binding.verification_status]
    return status, binding.signer_identity_id, binding


def _identity_status(signer_id: str | None, bundle: TrustBundle) -> SignerIdentityStatus:
    identity = next(
        (item for item in bundle.signer_identities if item.signer_identity_id == signer_id), None
    )
    if identity is None:
        return SignerIdentityStatus.UNAVAILABLE
    return {
        "DECLARED": SignerIdentityStatus.DECLARED,
        "EVIDENCE_LINKED": SignerIdentityStatus.EVIDENCE_LINKED,
        "UNAVAILABLE": SignerIdentityStatus.UNAVAILABLE,
    }[identity.verification_status]


def _binding_meets_minimum(result: SignerBindingResult, required: BindingStatus | None) -> bool:
    if required is None:
        return True
    acceptable = {
        BindingStatus.VERIFIED_BY_TRUST_BUNDLE: {SignerBindingResult.VERIFIED},
        BindingStatus.EVIDENCE_LINKED: {
            SignerBindingResult.VERIFIED,
            SignerBindingResult.EVIDENCE_LINKED,
        },
        BindingStatus.DECLARED: {
            SignerBindingResult.VERIFIED,
            SignerBindingResult.EVIDENCE_LINKED,
            SignerBindingResult.DECLARED,
        },
        BindingStatus.PARTIAL: {
            SignerBindingResult.VERIFIED,
            SignerBindingResult.EVIDENCE_LINKED,
            SignerBindingResult.DECLARED,
            SignerBindingResult.PARTIAL,
        },
        BindingStatus.UNAVAILABLE: set(SignerBindingResult),
        BindingStatus.BROKEN: {SignerBindingResult.BROKEN},
        BindingStatus.REVOKED: {SignerBindingResult.REVOKED},
        BindingStatus.EXPIRED: {SignerBindingResult.EXPIRED},
    }[required]
    return result in acceptable


def _combined_expiration(
    windows: list[ValidityWindow | None], context: EvaluationContext | None
) -> ExpirationStatus:
    statuses = [_expiration(window, context) for window in windows if window is not None]
    if not statuses:
        return ExpirationStatus.UNAVAILABLE
    for status in (
        ExpirationStatus.INVALID,
        ExpirationStatus.EXPIRED,
        ExpirationStatus.NOT_YET_VALID,
        ExpirationStatus.NOT_EVALUATED,
    ):
        if status in statuses:
            return status
    return ExpirationStatus.VALID


def _constraints_allow(values: list[Any], required: Any) -> bool:
    return not values or required in values


def _delegation_valid(
    delegation: DelegationRecord,
    keys: dict[str, KeyIdentity],
    record: SignatureRecord,
) -> bool:
    delegator = keys.get(delegation.delegator_key_id)
    if (
        delegator is None
        or delegation.status != "ACTIVE"
        or delegator.status != "ACTIVE"
        or KeyUsage.DELEGATE_SIGNING not in delegator.allowed_key_usages
    ):
        return False
    payload = delegation_authorization_payload(delegation.model_dump(mode="json", by_alias=True))
    if not verify(
        public_key_from_raw(bytes.fromhex(delegator.public_key)),
        bytes.fromhex(delegation.authorization_signature),
        delegation_bytes(payload),
    ):
        return False
    descriptor = record.payload
    if not _constraints_allow(delegation.allowed_purposes, record.purpose):
        return False
    if not _constraints_allow(delegation.allowed_object_types, descriptor.signed_object_type):
        return False
    if not _constraints_allow(delegator.allowed_purposes, record.purpose):
        return False
    if not _constraints_allow(delegator.allowed_object_types, descriptor.signed_object_type):
        return False
    if delegation.namespaces and descriptor.namespace not in delegation.namespaces:
        return False
    if delegator.namespaces and descriptor.namespace not in delegator.namespaces:
        return False
    if (
        delegation.provider_artifact_scopes
        and descriptor.provider_artifact_scope not in delegation.provider_artifact_scopes
    ):
        return False
    return not (
        delegator.provider_artifact_scopes
        and descriptor.provider_artifact_scope not in delegator.provider_artifact_scopes
    )


def _trust_path(
    key: KeyIdentity,
    record: SignatureRecord,
    bundle: TrustBundle,
    policy: TrustPolicy,
) -> tuple[DelegationStatus, str | None, list[str]]:
    roots = {item.key_id: item for item in bundle.trust_roots if item.status == "ACTIVE"}
    direct = roots.get(key.key_id)
    if direct is not None:
        if (
            record.purpose not in direct.allowed_purposes
            or record.payload.signed_object_type not in direct.allowed_object_types
        ):
            return DelegationStatus.INVALID_DELEGATION, direct.trust_root_id, []
        if direct.namespaces and record.payload.namespace not in direct.namespaces:
            return DelegationStatus.INVALID_DELEGATION, direct.trust_root_id, []
        if (
            direct.provider_artifact_scopes
            and record.payload.provider_artifact_scope not in direct.provider_artifact_scopes
        ):
            return DelegationStatus.INVALID_DELEGATION, direct.trust_root_id, []
        return DelegationStatus.DIRECT_ROOT, direct.trust_root_id, []
    if not policy.allow_delegation:
        return DelegationStatus.NOT_APPLICABLE, None, []
    keys = {item.key_id: item for item in bundle.keys}
    frontier: list[tuple[str, list[str], frozenset[str]]] = [
        (key.key_id, [], frozenset({key.key_id}))
    ]
    saw_cycle = False
    saw_depth = False
    while frontier:
        current, path, visited = frontier.pop(0)
        depth = len(path) + 1
        if depth > policy.maximum_delegation_depth:
            saw_depth = True
            continue
        candidates = [
            item
            for item in bundle.delegations
            if item.delegate_key_id == current
            and len(path) <= item.maximum_subordinate_depth
            and _delegation_valid(item, keys, record)
        ]
        for delegation in candidates:
            if delegation.delegator_key_id in visited:
                saw_cycle = True
                continue
            next_path = [delegation.delegation_id, *path]
            root = roots.get(delegation.delegator_key_id)
            if root is not None:
                if not root.delegation_allowed or depth > root.maximum_delegation_depth:
                    saw_depth = True
                    continue
                if (
                    record.purpose not in root.allowed_purposes
                    or record.payload.signed_object_type not in root.allowed_object_types
                    or (root.namespaces and record.payload.namespace not in root.namespaces)
                    or (
                        root.provider_artifact_scopes
                        and record.payload.provider_artifact_scope
                        not in root.provider_artifact_scopes
                    )
                ):
                    continue
                return DelegationStatus.VALID_DELEGATION, root.trust_root_id, next_path
            frontier.append(
                (
                    delegation.delegator_key_id,
                    next_path,
                    visited | {delegation.delegator_key_id},
                )
            )
    if saw_cycle:
        return DelegationStatus.CYCLE_DETECTED, None, []
    if saw_depth:
        return DelegationStatus.DEPTH_EXCEEDED, None, []
    return DelegationStatus.INVALID_DELEGATION, None, []


def _claim_summary(envelope: SignedObjectEnvelope) -> tuple[dict[str, Any], str]:
    value: Any = envelope.signed_object
    if envelope.signed_object_type in {
        SignedObjectType.QUANTIZATION_RELATIONSHIP_DECLARATION,
        SignedObjectType.REPRESENTATION_OBSERVATION,
        SignedObjectType.QUANTIZATION_FIDELITY_EVIDENCE,
    }:
        return {
            "quantization_relationship": value.get("relationship_mode", "NOT_APPLICABLE"),
            "structural_status": value.get("structural_status", "NOT_EVALUATED"),
            "numerical_status": value.get("numerical_status", "NOT_EVALUATED"),
            "publisher_authority_created_by_signature": False,
            "transformation_authority_created_by_signature": False,
            "behavioral_parity_proven": False,
        }, "INCOMPLETE"
    if envelope.signed_object_type == SignedObjectType.ARTIFACT_ATTESTATION:
        summary = value.get("verification_summary", {})
        return {
            "assertion_origin": value.get("assertion_origin"),
            "authenticity": value.get("authenticity"),
            "provenance_strength": summary.get("provenance_strength"),
            "evidence_linkage": summary.get("evidence_linkage"),
            "execution_verification": summary.get("execution_verification"),
        }, "NOT_APPLICABLE"
    if envelope.signed_object_type == SignedObjectType.CUSTODY_EVENT:
        return {
            "assertion_origin": value.get("assertion_origin"),
            "authenticity": value.get("authenticity"),
            "attestation_status": value.get("attestation_status"),
        }, "NOT_ASSESSED"
    if envelope.signed_object_type == SignedObjectType.CUSTODY_SEGMENT:
        return {
            "event_authenticity": value.get("events", [{}])[0].get("authenticity"),
            "genesis_semantics": value.get("genesis_semantics"),
        }, str(value.get("lifecycle_completeness", "NOT_ASSESSED"))
    if envelope.signed_object_type == SignedObjectType.MODEL_PASSPORT:
        trust = value.get("trust_summary", {})
        custody = value.get("custody_summary", {})
        lifecycle = (
            custody.get("lifecycle_completeness")
            or trust.get("custody_status")
            or custody.get("status", "NOT_ASSESSED")
        )
        return {"passport_trust_summary": trust}, str(lifecycle)
    if envelope.signed_object_type == SignedObjectType.POLICY_DECISION:
        return {
            "decision_outcome": value.get("decision_outcome"),
            "policy_id": value.get("policy_id"),
            "claim_truth_independently_proven": False,
        }, "NOT_APPLICABLE"
    if envelope.signed_object_type in {
        SignedObjectType.APPROVAL_RECORD,
        SignedObjectType.REJECTION_RECORD,
    }:
        return {
            "approval_outcome": value.get("outcome", "REJECTED"),
            "scope": value.get("scope"),
            "approval_is_deployment": False,
        }, "NOT_APPLICABLE"
    if envelope.signed_object_type == SignedObjectType.RELEASE_CANDIDATE:
        return {
            "candidate_status": "GOVERNANCE_OBJECT_ONLY",
            "release_occurred": False,
        }, "INCOMPLETE"
    if envelope.signed_object_type == SignedObjectType.PROMOTION_DECISION:
        return {
            "promotion_outcome": value.get("gate_result", {}).get("outcome"),
            "promotion_performed": False,
            "deployment_performed": False,
        }, "INCOMPLETE"
    if envelope.signed_object_type in {
        SignedObjectType.SECURITY_SCAN_EXECUTION_RECORD,
        SignedObjectType.SECURITY_EVIDENCE_BUNDLE,
        SignedObjectType.SECURITY_EVALUATION,
    }:
        return {
            "security_verdict": value.get("verdict", "NOT_APPLICABLE"),
            "coverage_status": value.get(
                "coverage_result", value.get("coverage", {}).get("status")
            ),
            "signed_record_proves_scanner_correctness": False,
            "signed_record_upgrades_coverage": False,
        }, "INCOMPLETE"
    if envelope.signed_object_type in {
        SignedObjectType.DEPLOYMENT_INTENT,
        SignedObjectType.DEPLOYMENT_MANIFEST,
        SignedObjectType.DEPLOYMENT_RECORD,
        SignedObjectType.RUNTIME_OBSERVATION,
        SignedObjectType.CONTINUITY_EVALUATION,
    }:
        assertion = value.get("assertion", {})
        return {
            "deployment_status": value.get("status", "NOT_APPLICABLE"),
            "continuity_verdict": value.get("verdict", "NOT_APPLICABLE"),
            "evidence_origin": assertion.get("origin", "NOT_APPLICABLE"),
            "signed_record_upgrades_origin": False,
            "signed_record_upgrades_authority": False,
            "signed_record_upgrades_coverage": False,
            "signed_record_proves_runtime_behavior": False,
        }, "INCOMPLETE"
    return {
        "execution_result": value.get("execution_result"),
        "environment_status": value.get("environment_identity", {}).get("status"),
    }, "NOT_APPLICABLE"


def verify_envelope(
    envelope: SignedObjectEnvelope,
    bundle: TrustBundle,
    policy: TrustPolicy,
    context: EvaluationContext | None = None,
) -> SignatureReport:
    """Reconstruct all results; stored summaries are neither accepted nor used."""
    _validate_source_object(envelope)
    verify_bundle(bundle)
    if context is not None and context.policy_id != policy.policy_id:
        raise OmivInputError("evaluation context references a different policy")
    if envelope.trust_policy_id is not None and envelope.trust_policy_id != policy.policy_id:
        raise OmivInputError("signed envelope references a different trust policy")
    keys = {item.key_id: item for item in bundle.keys}
    embedded = {item.key_id: item for item in envelope.key_records}
    for key_id in set(keys).intersection(embedded):
        if keys[key_id] != embedded[key_id]:
            raise OmivInputError("conflicting embedded and trust-bundle key record")
    results: list[SignatureVerificationResult] = []
    findings: list[TrustFinding] = [
        TrustFinding(
            finding_id="TRUST-001", status="PASS", summary="Signed-envelope schema is valid."
        ),
        TrustFinding(
            finding_id="TRUST-002", status="PASS", summary="Canonical object digest is valid."
        ),
        TrustFinding(
            finding_id="TRUST-003",
            status="PASS",
            summary="Domain-separated bytes were reconstructed.",
        ),
    ]
    for record in envelope.signatures:
        descriptor = record.payload
        expected_descriptor = descriptor.model_copy(
            update={
                "signed_object_schema": envelope.signed_object_schema,
                "signed_object_type": envelope.signed_object_type,
                "signed_object_id": envelope.signed_object_id,
                "signed_object_digest": envelope.signed_object_digest,
            }
        )
        descriptor_ok = (
            descriptor == expected_descriptor
            and record.purpose == EXPECTED_PURPOSE[envelope.signed_object_type]
        )
        bundle_key = keys.get(record.key_id)
        key = bundle_key or embedded.get(record.key_id)
        integrity = SignatureIntegrity.UNVERIFIED
        if key is None:
            key_status = KeyStatus.UNKNOWN
            integrity = SignatureIntegrity.UNVERIFIED
        else:
            key_status = KeyStatus.KNOWN if bundle_key is not None else KeyStatus.UNKNOWN
            integrity = (
                SignatureIntegrity.VALID
                if descriptor_ok
                and verify(
                    public_key_from_raw(bytes.fromhex(key.public_key)),
                    bytes.fromhex(record.detached_signature),
                    signed_object_bytes(descriptor),
                )
                else SignatureIntegrity.INVALID
            )
        binding_result, signer_id, binding = _binding_result(record, bundle, context)
        identity_status = _identity_status(signer_id, bundle)
        if binding is not None and not all(
            (
                policy.required_key_usage in binding.allowed_usages,
                envelope.signed_object_type in binding.allowed_object_types,
                not binding.namespaces or descriptor.namespace in binding.namespaces,
            )
        ):
            binding_result = SignerBindingResult.BROKEN
        delegation, root_id, path = (
            _trust_path(key, record, bundle, policy)
            if key is not None
            else (DelegationStatus.UNVERIFIED, None, [])
        )
        targets = [
            (RevocationScope.SIGNATURE, record.signature_id),
            (RevocationScope.SIGNED_OBJECT, envelope.signed_object_id),
        ]
        if key is not None:
            targets.append((RevocationScope.KEY, key.key_id))
        if binding is not None:
            targets.append((RevocationScope.SIGNER_KEY_BINDING, binding.binding_id))
        if root_id is not None:
            targets.append((RevocationScope.TRUST_ROOT, root_id))
        targets.extend((RevocationScope.DELEGATION, item) for item in path)
        delegated_records = [item for item in bundle.delegations if item.delegation_id in set(path)]
        targets.extend((RevocationScope.KEY, item.delegator_key_id) for item in delegated_records)
        revocation, revocation_records = _revocation(bundle, targets, policy, context)
        root = next((item for item in bundle.trust_roots if item.trust_root_id == root_id), None)
        path_keys = {
            item.key_id: item
            for item in bundle.keys
            if any(
                item.key_id in {record.delegator_key_id, record.delegate_key_id}
                for record in delegated_records
            )
        }
        expiration = (
            _combined_expiration(
                [
                    key.validity,
                    binding.validity if binding else None,
                    root.validity if root else None,
                    bundle.validity,
                    *(item.validity for item in delegated_records),
                    *(item.validity for item in path_keys.values()),
                ],
                context,
            )
            if key
            else ExpirationStatus.UNAVAILABLE
        )
        if (
            revocation
            in {
                RevocationStatus.REVOKED,
                RevocationStatus.SUPERSEDED,
                RevocationStatus.WITHDRAWN,
            }
            and key is not None
            and any(
                item.scope == RevocationScope.KEY
                and item.target_id == key.key_id
                and item.effective_status
                in {
                    RevocationStatus.REVOKED,
                    RevocationStatus.SUPERSEDED,
                    RevocationStatus.WITHDRAWN,
                }
                for item in revocation_records
            )
        ):
            key_status = KeyStatus.REVOKED
        elif expiration == ExpirationStatus.EXPIRED:
            key_status = KeyStatus.EXPIRED
        elif expiration == ExpirationStatus.NOT_YET_VALID:
            key_status = KeyStatus.NOT_YET_VALID
        if binding is not None and any(
            item.scope == RevocationScope.SIGNER_KEY_BINDING
            and item.target_id == binding.binding_id
            and item.effective_status
            in {
                RevocationStatus.REVOKED,
                RevocationStatus.SUPERSEDED,
                RevocationStatus.WITHDRAWN,
            }
            for item in revocation_records
        ):
            binding_result = SignerBindingResult.REVOKED
        purpose_allowed = record.purpose in policy.allowed_signature_purposes
        algorithm_allowed = record.algorithm in policy.supported_algorithms
        object_allowed = envelope.signed_object_type in policy.allowed_object_types
        policy_scope_allowed = (
            not policy.namespaces or descriptor.namespace in policy.namespaces
        ) and (
            not policy.provider_artifact_scopes
            or descriptor.provider_artifact_scope in policy.provider_artifact_scopes
        )
        key_allowed = key is not None and (
            record.purpose in key.allowed_purposes
            and envelope.signed_object_type in key.allowed_object_types
            and policy.required_key_usage in key.allowed_key_usages
            and (not key.namespaces or descriptor.namespace in key.namespaces)
            and (
                not key.provider_artifact_scopes
                or descriptor.provider_artifact_scope in key.provider_artifact_scopes
            )
        )
        path_trusted = delegation in {
            DelegationStatus.DIRECT_ROOT,
            DelegationStatus.VALID_DELEGATION,
        }
        binding_acceptable = _binding_meets_minimum(binding_result, policy.minimum_binding_status)
        identity_verification = (
            SignerIdentityVerification.UNAVAILABLE
            if identity_status == SignerIdentityStatus.UNAVAILABLE
            else (
                SignerIdentityVerification.VERIFIED_BY_POLICY
                if identity_status == SignerIdentityStatus.EVIDENCE_LINKED and binding_acceptable
                else SignerIdentityVerification.UNVERIFIED
            )
        )
        identity_acceptable = (
            identity_status != SignerIdentityStatus.UNAVAILABLE
            or policy.unknown_identity_behavior == "ALLOW"
        )
        fatal_revocation = revocation in {
            RevocationStatus.REVOKED,
            RevocationStatus.SUPERSEDED,
            RevocationStatus.WITHDRAWN,
        }
        revocation_ok = not fatal_revocation and not (
            policy.require_revocation_evaluation and revocation == RevocationStatus.NOT_EVALUATED
        )
        expiration_ok = expiration not in {
            ExpirationStatus.EXPIRED,
            ExpirationStatus.NOT_YET_VALID,
            ExpirationStatus.INVALID,
        }
        if policy.require_expiration_evaluation and expiration in {
            ExpirationStatus.NOT_EVALUATED,
            ExpirationStatus.UNAVAILABLE,
        }:
            expiration_ok = False
        trusted = all(
            (
                integrity == SignatureIntegrity.VALID,
                algorithm_allowed,
                purpose_allowed,
                object_allowed,
                policy_scope_allowed,
                key_allowed,
                path_trusted,
                binding_acceptable,
                identity_acceptable,
                revocation_ok,
                expiration_ok,
            )
        )
        if trusted:
            policy_status = TrustPolicyStatus.TRUSTED_BY_POLICY
        elif (
            integrity == SignatureIntegrity.VALID
            and key is not None
            and (path_trusted or binding_acceptable)
        ):
            policy_status = TrustPolicyStatus.PARTIALLY_TRUSTED
        else:
            policy_status = TrustPolicyStatus.UNTRUSTED_BY_POLICY
        limitations = ["A valid signature does not independently prove claim content."]
        if signer_id is None:
            limitations.append("Signer identity is unavailable or unverified.")
        results.append(
            SignatureVerificationResult(
                signature_id=record.signature_id,
                signature_integrity=integrity,
                key_id=record.key_id,
                key_status=key_status,
                signer_identity_id=signer_id,
                signer_identity_status=identity_status,
                signer_identity_verification=identity_verification,
                signer_binding=binding_result,
                signer_binding_status=(binding.verification_status if binding else None),
                trust_root_id=root_id,
                delegation_status=delegation,
                delegation_path=path,
                revocation_status=revocation,
                revocation_records=revocation_records,
                expiration_status=expiration,
                trust_policy_status=policy_status,
                limitations=limitations,
            )
        )
    accepted = sum(
        item.trust_policy_status == TrustPolicyStatus.TRUSTED_BY_POLICY for item in results
    )
    invalid = any(item.signature_integrity == SignatureIntegrity.INVALID for item in results)
    revoked = any(
        item.revocation_status
        in {RevocationStatus.REVOKED, RevocationStatus.SUPERSEDED, RevocationStatus.WITHDRAWN}
        for item in results
    )
    expired = any(item.expiration_status == ExpirationStatus.EXPIRED for item in results)
    not_yet_valid = any(
        item.expiration_status == ExpirationStatus.NOT_YET_VALID for item in results
    )
    expiration_not_evaluated = any(
        item.expiration_status in {ExpirationStatus.NOT_EVALUATED, ExpirationStatus.UNAVAILABLE}
        for item in results
    )
    revocation_not_evaluated = any(
        item.revocation_status == RevocationStatus.NOT_EVALUATED for item in results
    )
    unknown_key = any(item.key_status == KeyStatus.UNKNOWN for item in results)
    unknown_identity = any(
        item.signer_binding == SignerBindingResult.UNAVAILABLE for item in results
    )
    if invalid:
        overall = OverallSignedObjectStatus.INVALID_SIGNATURE
    elif revoked:
        overall = OverallSignedObjectStatus.REVOKED
    elif expired and policy.require_expiration_evaluation:
        overall = OverallSignedObjectStatus.EXPIRED
    elif not_yet_valid and policy.require_expiration_evaluation:
        overall = OverallSignedObjectStatus.NOT_YET_VALID
    elif expiration_not_evaluated and policy.require_expiration_evaluation:
        overall = OverallSignedObjectStatus.EXPIRATION_NOT_EVALUATED
    elif revocation_not_evaluated and policy.require_revocation_evaluation:
        overall = OverallSignedObjectStatus.REVOCATION_NOT_EVALUATED
    elif accepted >= policy.minimum_signature_count:
        overall = OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS
    elif unknown_key:
        overall = OverallSignedObjectStatus.VALID_SIGNATURE_UNTRUSTED_KEY
    elif unknown_identity:
        overall = OverallSignedObjectStatus.VALID_SIGNATURE_UNKNOWN_IDENTITY
    else:
        overall = OverallSignedObjectStatus.PARTIALLY_TRUSTED
    findings.extend(
        [
            TrustFinding(
                finding_id="TRUST-005",
                status="PASS" if not invalid else "FAIL",
                summary="Detached Ed25519 signature verification was reconstructed.",
                limitation="Signature validity does not prove claim truth.",
            ),
            TrustFinding(
                finding_id="TRUST-014",
                status="PASS",
                summary="Static revocation records were evaluated.",
            ),
            TrustFinding(
                finding_id="TRUST-015",
                status="PASS" if context and context.evaluation_time else "WARN",
                summary="Expiration was evaluated under the explicit context."
                if context and context.evaluation_time
                else "Expiration was not evaluated because no explicit time was supplied.",
            ),
            TrustFinding(
                finding_id="TRUST-016",
                status="PASS" if accepted >= policy.minimum_signature_count else "WARN",
                summary="Selected trust policy was evaluated.",
                limitation=(
                    "Policy acceptance does not prove safety, approval, deployment, or runtime."
                ),
            ),
            TrustFinding(
                finding_id="TRUST-017",
                status="PASS",
                summary="Underlying claim strength was preserved.",
            ),
            TrustFinding(
                finding_id="TRUST-018",
                status="PASS",
                summary="Signing produced no forbidden trust escalation.",
            ),
            TrustFinding(
                finding_id="TRUST-020",
                status="PASS",
                summary="Trust schemas contain public material only.",
            ),
            TrustFinding(
                finding_id="TRUST-021",
                status="PASS",
                summary="Object type and purpose domain separation were enforced.",
            ),
            TrustFinding(
                finding_id="TRUST-024",
                status="PASS",
                summary="Trust and claim limitations are explicit.",
            ),
        ]
    )
    underlying, lifecycle = _claim_summary(envelope)
    body: dict[str, Any] = {
        "schema": "omiv.signature-report.v1",
        "envelope_id": envelope.envelope_id,
        "envelope_digest": envelope.envelope_digest,
        "signed_object_schema": envelope.signed_object_schema,
        "signed_object_type": envelope.signed_object_type.value,
        "signed_object_id": envelope.signed_object_id,
        "signed_object_digest": envelope.signed_object_digest,
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest,
        "trust_bundle_id": bundle.bundle_id,
        "trust_bundle_digest": bundle.bundle_digest,
        "evaluation_context_id": context.evaluation_context_id if context else None,
        "signature_results": [item.model_dump(mode="json") for item in results],
        "accepted_signature_count": accepted,
        "underlying_claim": underlying,
        "content_independently_proven": False,
        "payload_status": "NOT_CHECKED",
        "numerical_fidelity_status": "NOT_CHECKED",
        "security_status": "NOT_CHECKED",
        "runtime_status": "NOT_CHECKED",
        "approval_status": "NOT_AVAILABLE",
        "lifecycle_completeness": lifecycle,
        "overall_status": overall.value,
        "findings": [item.model_dump(mode="json") for item in findings],
        "missing_evidence": ["Independent evidence proving the real-world claim content."],
        "limitations": [
            "A valid signature proves that the corresponding private-key holder signed "
            "this canonical object; it does not prove the underlying claim is true.",
            "No payload, fidelity, security, runtime, approval, deployment, or "
            "complete-custody claim is created by signing.",
        ],
    }
    report_id = "trust_report_" + canonical_sha256(body)[:32]
    with_id = {**body, "report_id": report_id}
    return SignatureReport.model_validate({**with_id, "report_digest": canonical_sha256(with_id)})


def load_report(path: Path) -> SignatureReport:
    try:
        return SignatureReport.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid signature report: {exc}") from exc


def verify_report(
    path: Path,
    envelope: SignedObjectEnvelope,
    bundle: TrustBundle,
    policy: TrustPolicy,
    context: EvaluationContext | None = None,
) -> SignatureReport:
    stored = load_report(path)
    expected = verify_envelope(envelope, bundle, policy, context)
    if stored != expected:
        raise OmivInputError("signature report does not reconstruct")
    return stored


def pretty_json(value: Any) -> str:
    raw = value.model_dump(mode="json", by_alias=True) if hasattr(value, "model_dump") else value
    return json.dumps(raw, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"
