"""Deterministic key identities, records, envelopes, and delegation builders."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.trust.algorithms import raw_public_key, sign
from omiv.trust.domain import delegation_bytes, signed_object_bytes
from omiv.trust.models import (
    ACTIVE_PURPOSES,
    BindingOrigin,
    BindingStatus,
    DelegationRecord,
    EvaluationContext,
    KeyIdentity,
    KeyUsage,
    RevocationReason,
    RevocationRecord,
    RevocationScope,
    SignaturePayloadDescriptor,
    SignaturePurpose,
    SignatureRecord,
    SignedObjectEnvelope,
    SignedObjectType,
    SignerIdentity,
    SignerIdentityKind,
    SignerKeyBinding,
    TrustBundle,
    TrustPolicy,
    TrustRoot,
    ValidityWindow,
)

OBJECT_METADATA: dict[SignedObjectType, tuple[set[str], str, str]] = {
    SignedObjectType.ARTIFACT_ATTESTATION: (
        {"omiv.artifact-attestation.v1"},
        "attestation_id",
        "attestation_digest",
    ),
    SignedObjectType.TOOL_EXECUTION_RECORD: (
        {"omiv.tool-execution-record.v1"},
        "execution_record_id",
        "execution_record_digest",
    ),
    SignedObjectType.CUSTODY_EVENT: ({"omiv.custody-event.v1"}, "event_id", "event_digest"),
    SignedObjectType.CUSTODY_SEGMENT: ({"omiv.custody-ledger.v2"}, "chain_id", "ledger_digest"),
    SignedObjectType.MODEL_PASSPORT: (
        {"omiv.model-passport.v1", "omiv.model-passport.v2"},
        "passport_id",
        "passport_digest",
    ),
}
EXPECTED_PURPOSE = {
    SignedObjectType.ARTIFACT_ATTESTATION: SignaturePurpose.ATTESTATION_ISSUANCE,
    SignedObjectType.TOOL_EXECUTION_RECORD: SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
    SignedObjectType.CUSTODY_EVENT: SignaturePurpose.CUSTODY_EVENT_ISSUANCE,
    SignedObjectType.CUSTODY_SEGMENT: SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
    SignedObjectType.MODEL_PASSPORT: SignaturePurpose.PASSPORT_ISSUANCE,
}


def object_metadata(value: dict[str, Any], object_type: SignedObjectType) -> tuple[str, str, str]:
    schemas, id_field, digest_field = OBJECT_METADATA[object_type]
    schema = value.get("schema")
    object_id = value.get(id_field)
    object_digest = value.get(digest_field)
    if (
        schema not in schemas
        or not isinstance(object_id, str)
        or not isinstance(object_digest, str)
    ):
        raise OmivInputError(f"canonical object does not match {object_type.value}")
    if len(object_digest) != 64:
        raise OmivInputError("canonical object digest is malformed")
    return schema, object_id, object_digest


def build_key_identity(
    private_key: Ed25519PrivateKey,
    *,
    allowed_object_types: list[SignedObjectType],
    allowed_purposes: list[SignaturePurpose],
    allowed_key_usages: list[KeyUsage] | None = None,
    namespaces: list[str] | None = None,
    provider_artifact_scopes: list[str] | None = None,
    validity: ValidityWindow | None = None,
    limitations: list[str] | None = None,
) -> KeyIdentity:
    return build_key_identity_from_public(
        private_key.public_key(),
        allowed_object_types=allowed_object_types,
        allowed_purposes=allowed_purposes,
        allowed_key_usages=allowed_key_usages,
        namespaces=namespaces,
        provider_artifact_scopes=provider_artifact_scopes,
        validity=validity,
        limitations=limitations,
    )


def build_key_identity_from_public(
    public_key: Ed25519PublicKey,
    *,
    allowed_object_types: list[SignedObjectType],
    allowed_purposes: list[SignaturePurpose],
    allowed_key_usages: list[KeyUsage] | None = None,
    namespaces: list[str] | None = None,
    provider_artifact_scopes: list[str] | None = None,
    validity: ValidityWindow | None = None,
    limitations: list[str] | None = None,
) -> KeyIdentity:
    public_hex = raw_public_key(public_key).hex()
    identity = {
        "schema": "omiv.key-identity.v1",
        "algorithm": "ED25519",
        "public_key_encoding": "RAW_HEX",
        "public_key": public_hex,
    }
    public_digest = canonical_sha256(identity)
    body: dict[str, Any] = {
        **identity,
        "key_id": "key_" + public_digest[:32],
        "public_key_digest": public_digest,
        "allowed_key_usages": sorted(
            item.value for item in (allowed_key_usages or [KeyUsage.SIGN_OMIV_OBJECT])
        ),
        "allowed_object_types": sorted(item.value for item in allowed_object_types),
        "allowed_purposes": sorted(item.value for item in allowed_purposes),
        "namespaces": sorted(namespaces or []),
        "provider_artifact_scopes": sorted(provider_artifact_scopes or []),
        "validity": validity.model_dump(mode="json") if validity else None,
        "status": "ACTIVE",
        "limitations": sorted(
            limitations or ["Public-key identity does not establish signer identity."]
        ),
    }
    return KeyIdentity.model_validate({**body, "key_digest": canonical_sha256(body)})


def build_signer_identity(
    kind: SignerIdentityKind,
    label: str,
    *,
    role: str | None = None,
    namespace: str | None = None,
    evidence: list[str] | None = None,
    verification_status: str = "DECLARED",
    limitations: list[str] | None = None,
) -> SignerIdentity:
    body: dict[str, Any] = {
        "schema": "omiv.signer-identity.v1",
        "identity_kind": kind.value,
        "display_label": label,
        "organization_id": None,
        "role": role,
        "namespace": namespace,
        "identity_evidence": sorted(evidence or []),
        "verification_status": verification_status,
        "limitations": sorted(
            limitations or ["Synthetic declared identity; no external identity proof."]
        ),
    }
    signer_id = "signer_" + canonical_sha256(body)[:32]
    with_id = {**body, "signer_identity_id": signer_id}
    return SignerIdentity.model_validate({**with_id, "identity_digest": canonical_sha256(with_id)})


def build_binding(
    signer: SignerIdentity,
    key: KeyIdentity,
    *,
    origin: BindingOrigin = BindingOrigin.TRUST_BUNDLE_DECLARED,
    status: BindingStatus = BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    validity: ValidityWindow | None = None,
) -> SignerKeyBinding:
    body: dict[str, Any] = {
        "schema": "omiv.signer-key-binding.v1",
        "signer_identity_id": signer.signer_identity_id,
        "key_id": key.key_id,
        "binding_origin": origin.value,
        "evidence_references": [],
        "allowed_roles": sorted([signer.role] if signer.role else []),
        "allowed_usages": sorted(item.value for item in key.allowed_key_usages),
        "namespaces": list(key.namespaces),
        "allowed_object_types": sorted(item.value for item in key.allowed_object_types),
        "validity": validity.model_dump(mode="json") if validity else None,
        "verification_status": status.value,
        "limitations": ["Binding validity does not prove the underlying signed claim."],
    }
    binding_id = "binding_" + canonical_sha256(body)[:32]
    with_id = {**body, "binding_id": binding_id}
    return SignerKeyBinding.model_validate({**with_id, "binding_digest": canonical_sha256(with_id)})


def build_trust_root(
    key: KeyIdentity,
    *,
    delegation_allowed: bool = False,
    maximum_delegation_depth: int = 0,
    validity: ValidityWindow | None = None,
) -> TrustRoot:
    body: dict[str, Any] = {
        "schema": "omiv.trust-root.v1",
        "key_id": key.key_id,
        "allowed_purposes": sorted(item.value for item in key.allowed_purposes),
        "allowed_object_types": sorted(item.value for item in key.allowed_object_types),
        "namespaces": list(key.namespaces),
        "provider_artifact_scopes": list(key.provider_artifact_scopes),
        "delegation_allowed": delegation_allowed,
        "maximum_delegation_depth": maximum_delegation_depth,
        "validity": validity.model_dump(mode="json") if validity else None,
        "status": "ACTIVE",
        "limitations": ["Trust applies only under a selected policy and recorded constraints."],
    }
    root_id = "root_" + canonical_sha256(body)[:32]
    with_id = {**body, "trust_root_id": root_id}
    return TrustRoot.model_validate({**with_id, "root_digest": canonical_sha256(with_id)})


def build_policy(
    profile: str,
    *,
    object_types: list[SignedObjectType],
    purposes: list[SignaturePurpose],
    namespaces: list[str] | None = None,
    provider_artifact_scopes: list[str] | None = None,
    require_binding: bool = True,
    minimum_binding_status: BindingStatus | None = None,
    allow_delegation: bool = False,
    maximum_delegation_depth: int = 0,
    require_expiration: bool = False,
    accept_local_declarative_revocation: bool = True,
    minimum_signature_count: int = 1,
    unknown_identity_behavior: str = "PARTIAL",
) -> TrustPolicy:
    if any(item not in ACTIVE_PURPOSES for item in purposes):
        raise OmivInputError("reserved purpose cannot be used by Phase 5D")
    policy_id = f"omiv.trust-policy.{profile}.v1"
    body: dict[str, Any] = {
        "schema": "omiv.trust-policy.v1",
        "policy_id": policy_id,
        "profile": profile,
        "supported_algorithms": ["ED25519"],
        "allowed_object_types": sorted(item.value for item in object_types),
        "allowed_signature_purposes": sorted(item.value for item in purposes),
        "required_key_usage": "SIGN_OMIV_OBJECT",
        "namespaces": sorted(namespaces or []),
        "provider_artifact_scopes": sorted(provider_artifact_scopes or []),
        "minimum_binding_status": (
            (minimum_binding_status or BindingStatus.DECLARED).value if require_binding else None
        ),
        "allow_delegation": allow_delegation,
        "maximum_delegation_depth": maximum_delegation_depth,
        "require_revocation_evaluation": True,
        "accept_local_declarative_revocation": accept_local_declarative_revocation,
        "require_expiration_evaluation": require_expiration,
        "minimum_signature_count": minimum_signature_count,
        "unknown_key_behavior": "UNTRUSTED",
        "unknown_identity_behavior": unknown_identity_behavior,
        "digest_only_behavior": "PARTIAL",
        "claim_strength_preservation": True,
        "forbidden_trust_escalations": [
            "DECLARED_PROVENANCE_TO_ARTIFACT_SPECIFIC_PROVENANCE",
            "NOT_CHECKED_TO_PASS",
            "UNATTESTED_TO_EXECUTION_VERIFIED",
            "INCOMPLETE_TO_COMPLETE",
        ],
        "limitations": [
            "Policy trust does not prove claim content, safety, approval, deployment, or runtime."
        ],
    }
    return TrustPolicy.model_validate({**body, "policy_digest": canonical_sha256(body)})


def build_trust_bundle(
    roots: list[TrustRoot],
    keys: list[KeyIdentity],
    *,
    identities: list[SignerIdentity] | None = None,
    bindings: list[SignerKeyBinding] | None = None,
    delegations: list[DelegationRecord] | None = None,
    revocations: list[RevocationRecord] | None = None,
) -> TrustBundle:
    body: dict[str, Any] = {
        "schema": "omiv.trust-bundle.v1",
        "trust_roots": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(roots, key=lambda x: x.trust_root_id)
        ],
        "keys": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(keys, key=lambda x: x.key_id)
        ],
        "signer_identities": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(identities or [], key=lambda x: x.signer_identity_id)
        ],
        "signer_key_bindings": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(bindings or [], key=lambda x: x.binding_id)
        ],
        "delegations": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(delegations or [], key=lambda x: x.delegation_id)
        ],
        "revocations": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(revocations or [], key=lambda x: x.revocation_id)
        ],
        "validity": None,
        "limitations": ["Static offline bundle; no online discovery or continuous reevaluation."],
    }
    bundle_id = "tb_" + canonical_sha256(body)[:32]
    with_id = {**body, "bundle_id": bundle_id}
    return TrustBundle.model_validate({**with_id, "bundle_digest": canonical_sha256(with_id)})


def build_evaluation_context(
    policy: TrustPolicy, *, evaluation_time: str | None, historical: bool = False
) -> EvaluationContext:
    body = {
        "schema": "omiv.evaluation-context.v1",
        "evaluation_time": evaluation_time,
        "purpose": "HISTORICAL" if historical else "CURRENT",
        "policy_id": policy.policy_id,
        "limitations": ["Evaluation time is caller supplied; no trusted timestamp authority."],
    }
    context_id = "eval_" + canonical_sha256(body)[:32]
    with_id = {**body, "evaluation_context_id": context_id}
    return EvaluationContext.model_validate(
        {**with_id, "context_digest": canonical_sha256(with_id)}
    )


def build_descriptor(
    value: dict[str, Any],
    object_type: SignedObjectType,
    purpose: SignaturePurpose,
    *,
    policy_id: str | None = None,
    namespace: str | None = None,
    provider_artifact_scope: str | None = None,
) -> SignaturePayloadDescriptor:
    schema, object_id, _ = object_metadata(value, object_type)
    if purpose != EXPECTED_PURPOSE[object_type]:
        raise OmivInputError("signature purpose is incompatible with object type")
    return SignaturePayloadDescriptor(
        signed_object_schema=schema,
        signed_object_type=object_type,
        signed_object_id=object_id,
        signed_object_digest=canonical_sha256(value),
        signature_purpose=purpose,
        trust_policy_id=policy_id,
        namespace=namespace,
        provider_artifact_scope=provider_artifact_scope,
    )


def build_signature_record(
    descriptor: SignaturePayloadDescriptor,
    private_key: Ed25519PrivateKey,
    key: KeyIdentity,
    *,
    binding_id: str | None = None,
) -> SignatureRecord:
    if raw_public_key(private_key.public_key()).hex() != key.public_key:
        raise OmivInputError("private key does not correspond to supplied key identity")
    signature = sign(private_key, signed_object_bytes(descriptor)).hex()
    body: dict[str, Any] = {
        "schema": "omiv.signature-record.v1",
        "algorithm": "ED25519",
        "key_id": key.key_id,
        "purpose": descriptor.signature_purpose.value,
        "payload": descriptor.model_dump(mode="json", by_alias=True),
        "detached_signature": signature,
        "signature_encoding": "RAW_HEX",
        "binding_id": binding_id,
        "trust_policy_id": descriptor.trust_policy_id,
        "limitations": ["Signature integrity does not prove the underlying claim is true."],
    }
    signature_id = "sig_" + canonical_sha256(body)[:32]
    with_id = {**body, "signature_id": signature_id}
    return SignatureRecord.model_validate(
        {**with_id, "signature_digest": canonical_sha256(with_id)}
    )


def build_signed_envelope(
    value: dict[str, Any],
    object_type: SignedObjectType,
    signatures: list[SignatureRecord],
    *,
    keys: list[KeyIdentity] | None = None,
) -> SignedObjectEnvelope:
    schema, object_id, _ = object_metadata(value, object_type)
    digest = canonical_sha256(value)
    for record in signatures:
        descriptor = record.payload
        if (
            descriptor.signed_object_type != object_type
            or descriptor.signed_object_schema != schema
            or descriptor.signed_object_id != object_id
            or descriptor.signed_object_digest != digest
        ):
            raise OmivInputError("signature does not cover the supplied canonical object")
    body: dict[str, Any] = {
        "schema": "omiv.signed-object-envelope.v1",
        "signed_object_schema": schema,
        "signed_object_type": object_type.value,
        "signed_object_id": object_id,
        "signed_object_digest": digest,
        "signed_object": value,
        "signatures": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(signatures, key=lambda x: x.signature_id)
        ],
        "key_records": [
            item.model_dump(mode="json", by_alias=True)
            for item in sorted(keys or [], key=lambda x: x.key_id)
        ],
        "trust_policy_id": signatures[0].trust_policy_id if signatures else None,
        "limitations": [
            "The canonical source object is unchanged; trust is reconstructed externally."
        ],
    }
    envelope_id = "soe_" + canonical_sha256(body)[:32]
    with_id = {**body, "envelope_id": envelope_id}
    return SignedObjectEnvelope.model_validate(
        {**with_id, "envelope_digest": canonical_sha256(with_id)}
    )


def _delegation_payload(body: dict[str, Any]) -> dict[str, object]:
    return {
        key: value
        for key, value in body.items()
        if key not in {"authorization_signature", "delegation_id", "delegation_digest"}
    }


def build_delegation(
    delegator_private_key: Ed25519PrivateKey,
    delegator: KeyIdentity,
    delegate: KeyIdentity,
    *,
    purposes: list[SignaturePurpose],
    object_types: list[SignedObjectType],
    namespaces: list[str] | None = None,
    provider_artifact_scopes: list[str] | None = None,
    maximum_subordinate_depth: int = 0,
    validity: ValidityWindow | None = None,
) -> DelegationRecord:
    if raw_public_key(delegator_private_key.public_key()).hex() != delegator.public_key:
        raise OmivInputError("delegation private key does not match delegator")
    if KeyUsage.DELEGATE_SIGNING not in delegator.allowed_key_usages:
        raise OmivInputError("delegator key is not authorized for delegation")
    body: dict[str, Any] = {
        "schema": "omiv.delegation-record.v1",
        "delegator_key_id": delegator.key_id,
        "delegate_key_id": delegate.key_id,
        "allowed_purposes": sorted(x.value for x in purposes),
        "allowed_object_types": sorted(x.value for x in object_types),
        "namespaces": sorted(namespaces or []),
        "provider_artifact_scopes": sorted(provider_artifact_scopes or []),
        "maximum_subordinate_depth": maximum_subordinate_depth,
        "validity": validity.model_dump(mode="json") if validity else None,
        "authorization_algorithm": "ED25519",
        "status": "ACTIVE",
        "limitations": ["Delegation grants only the explicitly bounded signing authority."],
    }
    body["authorization_signature"] = sign(delegator_private_key, delegation_bytes(body)).hex()
    delegation_id = "delegation_" + canonical_sha256(body)[:32]
    with_id = {**body, "delegation_id": delegation_id}
    return DelegationRecord.model_validate(
        {**with_id, "delegation_digest": canonical_sha256(with_id)}
    )


def build_revocation(
    scope: RevocationScope,
    target_id: str,
    reason: RevocationReason,
    *,
    effective_at: str | None = None,
    replacement_reference: str | None = None,
) -> RevocationRecord:
    body = {
        "schema": "omiv.revocation-record.v1",
        "scope": scope.value,
        "target_id": target_id,
        "reason": reason.value,
        "effective_at": effective_at,
        "authoritative_basis": "LOCAL_POLICY",
        "replacement_reference": replacement_reference,
        "evidence": [],
        "limitations": ["Static local revocation applies only when accepted by selected policy."],
    }
    record_id = "revocation_" + canonical_sha256(body)[:32]
    with_id = {**body, "revocation_id": record_id}
    return RevocationRecord.model_validate(
        {**with_id, "revocation_digest": canonical_sha256(with_id)}
    )


delegation_authorization_payload = _delegation_payload
