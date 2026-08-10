"""Phase 5D Ed25519, domain separation, trust, and integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from typer._click._compat import strip_ansi
from typer.testing import CliRunner

from omiv.attestations.models import ArtifactAttestation
from omiv.attestations.segment import build_attestation_custody_segment
from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.trust.algorithms import public_key_from_raw, verify
from omiv.trust.domain import signed_object_bytes
from omiv.trust.models import (
    BindingStatus,
    DelegationStatus,
    ExpirationStatus,
    KeyIdentity,
    KeyStatus,
    KeyUsage,
    OverallSignedObjectStatus,
    RevocationAuthority,
    RevocationReason,
    RevocationScope,
    RevocationStatus,
    SignatureIntegrity,
    SignaturePayloadDescriptor,
    SignaturePurpose,
    SignatureRecord,
    SignedObjectType,
    SignerBindingResult,
    SignerIdentityKind,
    SignerIdentityVerification,
    TrustPolicyStatus,
    ValidityWindow,
)
from omiv.trust.reporting import render_markdown
from omiv.trust.signing import (
    build_binding,
    build_delegation,
    build_descriptor,
    build_evaluation_context,
    build_key_identity,
    build_policy,
    build_revocation,
    build_signature_record,
    build_signed_envelope,
    build_signer_identity,
    build_trust_bundle,
    build_trust_root,
)
from omiv.trust.verification import (
    load_bundle,
    load_context,
    load_envelope,
    load_policy,
    verify_bundle,
    verify_envelope,
    verify_report,
)
from tools.generate_trust_examples import generate

ROOT = Path(__file__).parents[1]
ATTESTATION = ROOT / "attestations/examples/synthetic_transformation.attestation.json"
ACQUISITION = ROOT / "attestations/examples/synthetic_local_acquisition.attestation.json"
LEDGER = ROOT / "custody/examples/synthetic_transformation.custody-ledger.json"
PASSPORT_V1_SOURCE = ROOT / "passports/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.passport.json"
PASSPORT_V2_SOURCE = ROOT / "passports/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.passport-with-custody.json"

# TEST-ONLY RFC 8032 vector seeds. They are publicly known and have no security value.
RFC8032_VECTOR_1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8032_VECTOR_2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"


def _private(vector: str = RFC8032_VECTOR_1) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector))


def _object(path: Path = ATTESTATION) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _synthetic_passport(path: Path) -> dict[str, object]:
    """Derive a non-publisher synthetic schema fixture, then reconstruct its identity."""
    raw_text = path.read_text(encoding="utf-8")
    replacements = {
        "Kimi K3": "Synthetic Transformer",
        "kimi-k3": "synthetic-transformer",
        "Kimi-K3": "Synthetic-Transformer",
        "unsloth": "synthetic-project",
        "Unsloth": "Synthetic Project",
        "huggingface": "internal_registry",
        "UD-Q4_K_XL": "SYNTHETIC-F16",
    }
    for old, new in replacements.items():
        raw_text = raw_text.replace(old, new)
    value = json.loads(raw_text)
    assert isinstance(value, dict)
    assert not any(term in json.dumps(value).lower() for term in ("kimi", "unsloth", "moonshot"))
    if value["schema"] == "omiv.model-passport.v1":
        identity = {
            "schema": value["schema"],
            "subject": value["subject"],
            "artifact_identity": value["artifact_identity"],
            "source_evidence_bundle_digest": value["evidence_identity"][
                "validation_inventory_digest"
            ],
            "passport_policy_digest": value["policy_identity"]["passport_policy_digest"],
        }
    else:
        identity = {
            "schema": value["schema"],
            "base_passport_id": value["base_passport_id"],
            "base_passport_digest": value["base_passport_digest"],
            "subject": value["subject"],
            "artifact_identity": value["artifact_identity"],
            "custody_ledger_digest": value["custody_summary"]["ledger_digest"],
            "passport_policy_digest": value["policy_identity"]["passport_policy_digest"],
        }
    value["passport_id"] = "mp_" + canonical_sha256(identity)[:32]
    value.pop("passport_digest")
    value["passport_digest"] = canonical_sha256(value)
    return value


def _trusted(
    value: dict[str, object] | None = None,
    *,
    object_type: SignedObjectType = SignedObjectType.ARTIFACT_ATTESTATION,
    purpose: SignaturePurpose = SignaturePurpose.ATTESTATION_ISSUANCE,
    validity: ValidityWindow | None = None,
    require_expiration: bool = False,
) -> tuple[object, ...]:
    value = value or _object()
    private = _private()
    key = build_key_identity(
        private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        namespaces=["synthetic"],
        validity=validity,
    )
    signer = build_signer_identity(
        SignerIdentityKind.PROJECT_MAINTAINER_DECLARED,
        "Synthetic Project Maintainer",
        role="maintainer",
        namespace="synthetic",
    )
    binding = build_binding(signer, key)
    root = build_trust_root(key, validity=validity)
    policy = build_policy(
        "project_maintainer_release",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["synthetic"],
        require_expiration=require_expiration,
    )
    bundle = build_trust_bundle([root], [key], identities=[signer], bindings=[binding])
    descriptor = build_descriptor(
        value,
        object_type,
        purpose,
        policy_id=policy.policy_id,
        namespace="synthetic",
    )
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(value, object_type, [signature], keys=[key])
    return private, key, signer, binding, root, policy, bundle, signature, envelope


def _delegated(
    *,
    delegation_validity: ValidityWindow | None = None,
    parent_validity: ValidityWindow | None = None,
    require_expiration: bool = False,
) -> tuple[object, ...]:
    value = _object()
    root_private = _private()
    delegate_private = _private(RFC8032_VECTOR_2)
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    root_key = build_key_identity(
        root_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING],
        namespaces=["synthetic"],
        validity=parent_validity,
    )
    delegate_key = build_key_identity(
        delegate_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        namespaces=["synthetic"],
    )
    root = build_trust_root(
        root_key,
        delegation_allowed=True,
        maximum_delegation_depth=1,
        validity=parent_validity,
    )
    delegation = build_delegation(
        root_private,
        root_key,
        delegate_key,
        purposes=[purpose],
        object_types=[object_type],
        namespaces=["synthetic"],
        validity=delegation_validity,
    )
    signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Synthetic Delegate")
    binding = build_binding(signer, delegate_key)
    policy = build_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["synthetic"],
        allow_delegation=True,
        maximum_delegation_depth=1,
        require_expiration=require_expiration,
    )
    descriptor = build_descriptor(
        value, object_type, purpose, policy_id=policy.policy_id, namespace="synthetic"
    )
    signature = build_signature_record(
        descriptor, delegate_private, delegate_key, binding_id=binding.binding_id
    )
    envelope = build_signed_envelope(value, object_type, [signature], keys=[delegate_key])
    bundle = build_trust_bundle(
        [root],
        [root_key, delegate_key],
        identities=[signer],
        bindings=[binding],
        delegations=[delegation],
    )
    return (
        root_key,
        delegate_key,
        root,
        delegation,
        signer,
        binding,
        policy,
        bundle,
        envelope,
    )


def test_rfc8032_vector_and_deterministic_signature() -> None:
    private = _private()
    public = private.public_key()
    assert private.sign(b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert verify(public, private.sign(b"message"), b"message")
    assert not verify(public, private.sign(b"message"), b"modified")
    assert not verify(_private(RFC8032_VECTOR_2).public_key(), private.sign(b"message"), b"message")


@pytest.mark.parametrize("size", [0, 31, 33])
def test_malformed_public_key_rejected(size: int) -> None:
    with pytest.raises(Exception, match="malformed Ed25519 public key"):
        public_key_from_raw(b"x" * size)


def test_truncated_signature_is_invalid() -> None:
    private, *_ = _trusted()
    assert not verify(private.public_key(), b"x" * 63, b"message")


def test_key_identity_is_deterministic_and_public_only() -> None:
    _, key, *_ = _trusted()
    _, same, *_ = _trusted()
    assert key == same
    assert key.key_id == "key_ed39d828050734934fcf309c611f5d9b"
    assert "private" not in json.dumps(key.model_dump(mode="json")).lower()
    raw = key.model_dump(mode="json", by_alias=True)
    raw["private_key"] = "forbidden"
    with pytest.raises(ValidationError):
        KeyIdentity.model_validate(raw)


def test_changed_key_changes_identity() -> None:
    _, key, *_ = _trusted()
    other = build_key_identity(
        _private(RFC8032_VECTOR_2),
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
    )
    assert other.key_id != key.key_id
    assert other.public_key_digest != key.public_key_digest


def test_unsupported_algorithm_and_local_path_fail_closed() -> None:
    _, key, *_ = _trusted()
    raw = key.model_dump(mode="json", by_alias=True)
    raw["algorithm"] = "ECDSA_P256_RESERVED"
    with pytest.raises(ValidationError, match="only ED25519"):
        KeyIdentity.model_validate(raw)
    raw = key.model_dump(mode="json", by_alias=True)
    raw["limitations"] = ["/home/synthetic/private-location"]
    raw["key_digest"] = canonical_sha256(
        {name: value for name, value in raw.items() if name != "key_digest"}
    )
    with pytest.raises(ValidationError, match="local path"):
        KeyIdentity.model_validate(raw)


def test_timestamps_are_fixed_width_utc() -> None:
    with pytest.raises(ValidationError):
        ValidityWindow(not_after="2026-07-31T00:00:00+00:00")
    with pytest.raises(ValidationError):
        ValidityWindow(not_after="not-a-time")
    with pytest.raises(ValidationError, match="valid fixed-width UTC"):
        ValidityWindow(not_after="2026-99-31T00:00:00Z")


def test_trusted_signature_preserves_transformation_claim() -> None:
    *_, policy, bundle, signature, envelope = _trusted()
    report = verify_envelope(envelope, bundle, policy)
    result = report.signature_results[0]
    assert signature.signature_id == result.signature_id
    assert result.signature_integrity == SignatureIntegrity.VALID
    assert result.key_status == KeyStatus.KNOWN
    assert result.signer_binding == SignerBindingResult.VERIFIED
    assert result.delegation_status == DelegationStatus.DIRECT_ROOT
    assert result.trust_policy_status == TrustPolicyStatus.TRUSTED_BY_POLICY
    assert report.overall_status == OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS
    assert report.underlying_claim["authenticity"] == "EXECUTION_VERIFIED"
    assert report.underlying_claim["provenance_strength"] == "ARTIFACT_SPECIFIC_PROVENANCE"
    assert report.payload_status == "NOT_CHECKED"
    assert report.numerical_fidelity_status == "NOT_CHECKED"
    assert report.security_status == "NOT_CHECKED"
    assert report.runtime_status == "NOT_CHECKED"
    assert report.approval_status == "NOT_AVAILABLE"


def test_signed_declared_acquisition_stays_declared() -> None:
    *_, policy, bundle, _, envelope = _trusted(_object(ACQUISITION))
    report = verify_envelope(envelope, bundle, policy)
    assert report.underlying_claim["authenticity"] == "DECLARED"
    assert report.underlying_claim["provenance_strength"] == "DECLARED_PROVENANCE"
    assert report.content_independently_proven is False


def _record_with_descriptor(
    signature: SignatureRecord, descriptor: SignaturePayloadDescriptor
) -> SignatureRecord:
    body = signature.model_dump(mode="json", by_alias=True)
    body.pop("signature_id")
    body.pop("signature_digest")
    body["payload"] = descriptor.model_dump(mode="json", by_alias=True)
    body["purpose"] = descriptor.signature_purpose.value
    signature_id = "sig_" + canonical_sha256(body)[:32]
    body["signature_id"] = signature_id
    body["signature_digest"] = canonical_sha256(body)
    return SignatureRecord.model_validate(body)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signed_object_type", SignedObjectType.MODEL_PASSPORT),
        ("signed_object_schema", "omiv.model-passport.v1"),
        ("signed_object_id", "mp_" + "0" * 32),
        ("canonicalization_version", "omiv-json-v2"),
        ("namespace", "different"),
    ],
)
def test_domain_descriptor_changes_invalidate_signature(field: str, value: object) -> None:
    *_, signature, _ = _trusted()
    raw = signature.payload.model_dump(mode="json", by_alias=True)
    raw[field] = value.value if hasattr(value, "value") else value
    if field == "canonicalization_version":
        with pytest.raises(ValidationError):
            SignaturePayloadDescriptor.model_validate(raw)
        return
    changed = SignaturePayloadDescriptor.model_validate(raw)
    assert not verify(
        _private().public_key(),
        bytes.fromhex(signature.detached_signature),
        signed_object_bytes(changed),
    )


def test_signature_policy_identity_must_match_signed_descriptor() -> None:
    *_, signature, _ = _trusted()
    raw = signature.model_dump(mode="json", by_alias=True)
    raw["trust_policy_id"] = "omiv.trust-policy.other.v1"
    raw.pop("signature_id")
    raw.pop("signature_digest")
    raw["signature_id"] = "sig_" + canonical_sha256(raw)[:32]
    raw["signature_digest"] = canonical_sha256(raw)
    with pytest.raises(ValidationError, match="trust policy does not match"):
        SignatureRecord.model_validate(raw)


def test_reserved_purpose_rejected() -> None:
    raw = build_descriptor(
        _object(),
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
    ).model_dump(mode="json", by_alias=True)
    raw["signature_purpose"] = "APPROVAL_RESERVED"
    with pytest.raises(ValidationError, match="reserved signature purpose"):
        SignaturePayloadDescriptor.model_validate(raw)


def test_unknown_key_signature_is_valid_but_untrusted() -> None:
    *_, policy, _, _, envelope = _trusted()
    empty = build_trust_bundle([], [])
    report = verify_envelope(envelope, empty, policy)
    result = report.signature_results[0]
    assert result.signature_integrity == SignatureIntegrity.VALID
    assert result.key_status == KeyStatus.UNKNOWN
    assert result.signer_identity_verification == SignerIdentityVerification.UNAVAILABLE
    assert result.trust_policy_status == TrustPolicyStatus.UNTRUSTED_BY_POLICY
    assert report.overall_status == OverallSignedObjectStatus.VALID_SIGNATURE_UNTRUSTED_KEY


def test_identity_is_not_inferred_when_binding_missing() -> None:
    private, key, signer, _, root, policy, _, _, _ = _trusted()
    descriptor = build_descriptor(
        _object(),
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
        policy_id=policy.policy_id,
        namespace="synthetic",
    )
    signature = build_signature_record(descriptor, private, key)
    envelope = build_signed_envelope(_object(), SignedObjectType.ARTIFACT_ATTESTATION, [signature])
    bundle = build_trust_bundle([root], [key], identities=[signer])
    report = verify_envelope(envelope, bundle, policy)
    assert report.signature_results[0].signer_binding == SignerBindingResult.UNAVAILABLE
    assert report.overall_status == OverallSignedObjectStatus.VALID_SIGNATURE_UNKNOWN_IDENTITY


def test_static_authoritative_key_revocation() -> None:
    _, key, signer, binding, root, policy, _, _, envelope = _trusted()
    revocation = build_revocation(RevocationScope.KEY, key.key_id, RevocationReason.KEY_COMPROMISE)
    bundle = build_trust_bundle(
        [root], [key], identities=[signer], bindings=[binding], revocations=[revocation]
    )
    report = verify_envelope(envelope, bundle, policy)
    assert report.overall_status == OverallSignedObjectStatus.REVOKED
    assert report.signature_results[0].key_status == KeyStatus.REVOKED


def test_expiration_requires_explicit_context() -> None:
    validity = ValidityWindow(not_before="2025-01-01T00:00:00Z", not_after="2025-12-31T23:59:59Z")
    *_, policy, bundle, _, envelope = _trusted(validity=validity, require_expiration=True)
    no_time = verify_envelope(envelope, bundle, policy)
    assert no_time.signature_results[0].expiration_status == ExpirationStatus.NOT_EVALUATED
    assert no_time.overall_status == OverallSignedObjectStatus.EXPIRATION_NOT_EVALUATED
    context = build_evaluation_context(policy, evaluation_time="2026-07-31T00:00:00Z")
    expired = verify_envelope(envelope, bundle, policy, context)
    assert expired.overall_status == OverallSignedObjectStatus.EXPIRED
    historical = build_evaluation_context(
        policy, evaluation_time="2025-07-31T00:00:00Z", historical=True
    )
    assert (
        verify_envelope(envelope, bundle, policy, historical).overall_status
        == OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS
    )


def test_validity_boundaries_are_inclusive_and_not_yet_is_distinct() -> None:
    validity = ValidityWindow(not_before="2025-01-01T00:00:00Z", not_after="2025-12-31T23:59:59Z")
    *_, policy, bundle, _, envelope = _trusted(validity=validity, require_expiration=True)
    at_start = build_evaluation_context(policy, evaluation_time=validity.not_before)
    at_end = build_evaluation_context(policy, evaluation_time=validity.not_after)
    before = build_evaluation_context(policy, evaluation_time="2024-12-31T23:59:59Z")
    assert (
        verify_envelope(envelope, bundle, policy, at_start).signature_results[0].expiration_status
        == ExpirationStatus.VALID
    )
    assert (
        verify_envelope(envelope, bundle, policy, at_end).signature_results[0].expiration_status
        == ExpirationStatus.VALID
    )
    not_yet = verify_envelope(envelope, bundle, policy, before)
    assert not_yet.signature_results[0].expiration_status == ExpirationStatus.NOT_YET_VALID
    assert not_yet.overall_status == OverallSignedObjectStatus.NOT_YET_VALID
    with pytest.raises(ValidationError, match="inverted"):
        ValidityWindow(
            not_before="2025-12-31T23:59:59Z",
            not_after="2025-01-01T00:00:00Z",
        )


def test_binding_validity_is_evaluated_independently() -> None:
    private, key, signer, _, root, _, _, _, _ = _trusted()
    validity = ValidityWindow(not_before="2025-01-01T00:00:00Z", not_after="2025-12-31T23:59:59Z")
    binding = build_binding(signer, key, validity=validity)
    policy = build_policy(
        "project_maintainer_release",
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        namespaces=["synthetic"],
        require_expiration=True,
    )
    descriptor = build_descriptor(
        _object(),
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
        policy_id=policy.policy_id,
        namespace="synthetic",
    )
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(_object(), SignedObjectType.ARTIFACT_ATTESTATION, [signature])
    bundle = build_trust_bundle([root], [key], identities=[signer], bindings=[binding])
    context = build_evaluation_context(policy, evaluation_time="2026-01-01T00:00:00Z")
    report = verify_envelope(envelope, bundle, policy, context)
    result = report.signature_results[0]
    assert result.signer_binding == SignerBindingResult.EXPIRED
    assert result.expiration_status == ExpirationStatus.EXPIRED
    assert report.overall_status == OverallSignedObjectStatus.EXPIRED


def test_valid_bounded_delegation() -> None:
    value = _object()
    root_private = _private()
    delegate_private = _private(RFC8032_VECTOR_2)
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    root_key = build_key_identity(
        root_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING, KeyUsage.SIGN_OMIV_OBJECT],
    )
    delegate_key = build_key_identity(
        delegate_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        namespaces=["synthetic"],
    )
    root = build_trust_root(root_key, delegation_allowed=True, maximum_delegation_depth=1)
    delegation = build_delegation(
        root_private,
        root_key,
        delegate_key,
        purposes=[purpose],
        object_types=[object_type],
        namespaces=["synthetic"],
    )
    signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Synthetic Release Team")
    binding = build_binding(signer, delegate_key)
    policy = build_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["synthetic"],
        allow_delegation=True,
        maximum_delegation_depth=1,
    )
    bundle = build_trust_bundle(
        [root],
        [root_key, delegate_key],
        identities=[signer],
        bindings=[binding],
        delegations=[delegation],
    )
    descriptor = build_descriptor(
        value,
        object_type,
        purpose,
        policy_id=policy.policy_id,
        namespace="synthetic",
    )
    signature = build_signature_record(
        descriptor, delegate_private, delegate_key, binding_id=binding.binding_id
    )
    envelope = build_signed_envelope(value, object_type, [signature])
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.delegation_status == DelegationStatus.VALID_DELEGATION
    assert result.delegation_path == [delegation.delegation_id]
    assert result.trust_policy_status == TrustPolicyStatus.TRUSTED_BY_POLICY


def test_self_delegation_rejected() -> None:
    private = _private()
    key = build_key_identity(
        private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING, KeyUsage.SIGN_OMIV_OBJECT],
    )
    with pytest.raises(ValidationError, match="self-delegation"):
        build_delegation(
            private,
            key,
            key,
            purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
            object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        )


def test_delegation_requires_explicit_key_usage() -> None:
    private, key, *_ = _trusted()
    delegate_key = build_key_identity(
        _private(RFC8032_VECTOR_2),
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
    )
    with pytest.raises(OmivInputError, match="not authorized for delegation"):
        build_delegation(
            private,
            key,
            delegate_key,
            purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
            object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        )


def test_multi_hop_delegation_enforces_subordinate_depth() -> None:
    value = _object()
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    root_private = _private()
    intermediate_private = _private(RFC8032_VECTOR_2)
    leaf_private = _private("01" * 32)
    delegation_usages = [KeyUsage.DELEGATE_SIGNING, KeyUsage.SIGN_OMIV_OBJECT]
    root_key = build_key_identity(
        root_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        allowed_key_usages=delegation_usages,
    )
    intermediate_key = build_key_identity(
        intermediate_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        allowed_key_usages=delegation_usages,
    )
    leaf_key = build_key_identity(
        leaf_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
    )
    root = build_trust_root(root_key, delegation_allowed=True, maximum_delegation_depth=2)
    outer = build_delegation(
        root_private,
        root_key,
        intermediate_key,
        purposes=[purpose],
        object_types=[object_type],
        maximum_subordinate_depth=0,
    )
    inner = build_delegation(
        intermediate_private,
        intermediate_key,
        leaf_key,
        purposes=[purpose],
        object_types=[object_type],
    )
    signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Synthetic Leaf")
    binding = build_binding(signer, leaf_key)
    policy = build_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        allow_delegation=True,
        maximum_delegation_depth=2,
    )
    descriptor = build_descriptor(value, object_type, purpose, policy_id=policy.policy_id)
    signature = build_signature_record(
        descriptor, leaf_private, leaf_key, binding_id=binding.binding_id
    )
    envelope = build_signed_envelope(value, object_type, [signature])
    bundle = build_trust_bundle(
        [root],
        [root_key, intermediate_key, leaf_key],
        identities=[signer],
        bindings=[binding],
        delegations=[outer, inner],
    )
    with pytest.raises(OmivInputError, match="broadens parent authority"):
        verify_envelope(envelope, bundle, policy)

    allowed_outer = build_delegation(
        root_private,
        root_key,
        intermediate_key,
        purposes=[purpose],
        object_types=[object_type],
        maximum_subordinate_depth=1,
    )
    allowed_bundle = build_trust_bundle(
        [root],
        [root_key, intermediate_key, leaf_key],
        identities=[signer],
        bindings=[binding],
        delegations=[allowed_outer, inner],
    )
    allowed = verify_envelope(envelope, allowed_bundle, policy).signature_results[0]
    assert allowed.delegation_status == DelegationStatus.VALID_DELEGATION
    assert allowed.delegation_path == [allowed_outer.delegation_id, inner.delegation_id]


@pytest.mark.parametrize(
    ("purposes", "object_types", "namespaces", "provider_scopes", "message"),
    [
        (
            [SignaturePurpose.PASSPORT_ISSUANCE],
            [SignedObjectType.ARTIFACT_ATTESTATION],
            ["synthetic"],
            ["synthetic/artifact"],
            "purpose",
        ),
        (
            [SignaturePurpose.ATTESTATION_ISSUANCE],
            [SignedObjectType.MODEL_PASSPORT],
            ["synthetic"],
            ["synthetic/artifact"],
            "object type",
        ),
        (
            [SignaturePurpose.ATTESTATION_ISSUANCE],
            [SignedObjectType.ARTIFACT_ATTESTATION],
            [],
            ["synthetic/artifact"],
            "namespace",
        ),
        (
            [SignaturePurpose.ATTESTATION_ISSUANCE],
            [SignedObjectType.ARTIFACT_ATTESTATION],
            ["synthetic"],
            [],
            "provider/artifact scope",
        ),
    ],
)
def test_delegation_cannot_broaden_constraints(
    purposes: list[SignaturePurpose],
    object_types: list[SignedObjectType],
    namespaces: list[str],
    provider_scopes: list[str],
    message: str,
) -> None:
    root_private = _private()
    root_key = build_key_identity(
        root_private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING],
        namespaces=["synthetic"],
        provider_artifact_scopes=["synthetic/artifact"],
    )
    delegate_key = build_key_identity(
        _private(RFC8032_VECTOR_2),
        allowed_object_types=list(SignedObjectType),
        allowed_purposes=[
            SignaturePurpose.ATTESTATION_ISSUANCE,
            SignaturePurpose.PASSPORT_ISSUANCE,
        ],
    )
    delegation = build_delegation(
        root_private,
        root_key,
        delegate_key,
        purposes=purposes,
        object_types=object_types,
        namespaces=namespaces,
        provider_artifact_scopes=provider_scopes,
    )
    bundle = build_trust_bundle(
        [build_trust_root(root_key, delegation_allowed=True, maximum_delegation_depth=1)],
        [root_key, delegate_key],
        delegations=[delegation],
    )
    with pytest.raises(OmivInputError, match=message):
        verify_bundle(bundle)


def test_delegation_validity_must_be_within_parent() -> None:
    parent_validity = ValidityWindow(
        not_before="2025-01-01T00:00:00Z", not_after="2025-12-31T23:59:59Z"
    )
    root_private = _private()
    root_key = build_key_identity(
        root_private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING],
        validity=parent_validity,
    )
    delegate_key = build_key_identity(
        _private(RFC8032_VECTOR_2),
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
    )
    delegation = build_delegation(
        root_private,
        root_key,
        delegate_key,
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        validity=ValidityWindow(
            not_before="2024-01-01T00:00:00Z", not_after="2026-12-31T23:59:59Z"
        ),
    )
    bundle = build_trust_bundle(
        [
            build_trust_root(
                root_key,
                delegation_allowed=True,
                maximum_delegation_depth=1,
                validity=parent_validity,
            )
        ],
        [root_key, delegate_key],
        delegations=[delegation],
    )
    with pytest.raises(OmivInputError, match="validity exceeds"):
        verify_bundle(bundle)


def test_delegate_cannot_create_authority_absent_from_root() -> None:
    root_private = _private()
    root_key = build_key_identity(
        root_private,
        allowed_object_types=[
            SignedObjectType.ARTIFACT_ATTESTATION,
            SignedObjectType.MODEL_PASSPORT,
        ],
        allowed_purposes=[
            SignaturePurpose.ATTESTATION_ISSUANCE,
            SignaturePurpose.PASSPORT_ISSUANCE,
        ],
        allowed_key_usages=[KeyUsage.DELEGATE_SIGNING],
    )
    root = build_trust_root(root_key, delegation_allowed=True, maximum_delegation_depth=1)
    root_raw = root.model_dump(mode="json", by_alias=True)
    root_raw["allowed_object_types"] = ["ARTIFACT_ATTESTATION"]
    root_raw["allowed_purposes"] = ["ATTESTATION_ISSUANCE"]
    root_raw.pop("trust_root_id")
    root_raw.pop("root_digest")
    root_raw["trust_root_id"] = "root_" + canonical_sha256(root_raw)[:32]
    root_raw["root_digest"] = canonical_sha256(root_raw)
    root = type(root).model_validate(root_raw)
    delegate_key = build_key_identity(
        _private(RFC8032_VECTOR_2),
        allowed_object_types=[SignedObjectType.MODEL_PASSPORT],
        allowed_purposes=[SignaturePurpose.PASSPORT_ISSUANCE],
    )
    delegation = build_delegation(
        root_private,
        root_key,
        delegate_key,
        purposes=[SignaturePurpose.PASSPORT_ISSUANCE],
        object_types=[SignedObjectType.MODEL_PASSPORT],
    )
    bundle = build_trust_bundle([root], [root_key, delegate_key], delegations=[delegation])
    with pytest.raises(OmivInputError, match="broadens parent authority"):
        verify_bundle(bundle)


def test_duplicate_delegation_pair_and_cycle_fail_closed() -> None:
    first_private = _private()
    second_private = _private(RFC8032_VECTOR_2)
    usage = [KeyUsage.DELEGATE_SIGNING]
    first_key = build_key_identity(
        first_private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        allowed_key_usages=usage,
    )
    second_key = build_key_identity(
        second_private,
        allowed_object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        allowed_purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        allowed_key_usages=usage,
    )
    first_to_second = build_delegation(
        first_private,
        first_key,
        second_key,
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
    )
    duplicate = build_delegation(
        first_private,
        first_key,
        second_key,
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        maximum_subordinate_depth=1,
    )
    with pytest.raises(ValidationError, match="duplicate delegator/delegate"):
        build_trust_bundle([], [first_key, second_key], delegations=[first_to_second, duplicate])
    second_to_first = build_delegation(
        second_private,
        second_key,
        first_key,
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
    )
    cycle = build_trust_bundle(
        [], [first_key, second_key], delegations=[first_to_second, second_to_first]
    )
    with pytest.raises(OmivInputError, match="cycle"):
        verify_bundle(cycle)


def test_provider_artifact_scope_is_enforced_at_every_policy_layer() -> None:
    value = _object()
    private = _private()
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    key = build_key_identity(
        private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        provider_artifact_scopes=["synthetic/allowed"],
    )
    signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Synthetic Team")
    binding = build_binding(signer, key)
    root = build_trust_root(key)
    policy = build_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        provider_artifact_scopes=["synthetic/allowed"],
    )
    bundle = build_trust_bundle([root], [key], identities=[signer], bindings=[binding])
    descriptor = build_descriptor(
        value,
        object_type,
        purpose,
        policy_id=policy.policy_id,
        provider_artifact_scope="synthetic/other",
    )
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(value, object_type, [signature])
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.signature_integrity == SignatureIntegrity.VALID
    assert result.delegation_status == DelegationStatus.INVALID_DELEGATION
    assert result.trust_policy_status == TrustPolicyStatus.PARTIALLY_TRUSTED


def test_policy_minimum_binding_status_is_enforced() -> None:
    value = _object()
    private = _private()
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    key = build_key_identity(
        private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        namespaces=["synthetic"],
    )
    signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Synthetic Team")
    binding = build_binding(signer, key, status=BindingStatus.DECLARED)
    root = build_trust_root(key)
    policy = build_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["synthetic"],
    )
    policy_raw = policy.model_dump(mode="json", by_alias=True)
    policy_raw["minimum_binding_status"] = "VERIFIED_BY_TRUST_BUNDLE"
    policy_raw.pop("policy_digest")
    policy_raw["policy_digest"] = canonical_sha256(policy_raw)
    policy = type(policy).model_validate(policy_raw)
    bundle = build_trust_bundle([root], [key], identities=[signer], bindings=[binding])
    descriptor = build_descriptor(
        value,
        object_type,
        purpose,
        policy_id=policy.policy_id,
        namespace="synthetic",
    )
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(value, object_type, [signature])
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.signer_binding == SignerBindingResult.DECLARED
    assert result.signer_binding_status == BindingStatus.DECLARED
    assert result.signer_identity_verification == SignerIdentityVerification.UNVERIFIED
    assert result.trust_policy_status == TrustPolicyStatus.PARTIALLY_TRUSTED


def test_policy_algorithm_allowlist_is_independently_enforced() -> None:
    *_, policy, bundle, _, envelope = _trusted()
    raw = policy.model_dump(mode="json", by_alias=True)
    raw["supported_algorithms"] = []
    raw.pop("policy_digest")
    raw["policy_digest"] = canonical_sha256(raw)
    no_algorithms = type(policy).model_validate(raw)
    result = verify_envelope(envelope, bundle, no_algorithms).signature_results[0]
    assert result.signature_integrity == SignatureIntegrity.VALID
    assert result.trust_policy_status == TrustPolicyStatus.PARTIALLY_TRUSTED


def test_same_signature_has_policy_scoped_trust_outcomes() -> None:
    value = _object()
    private = _private()
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    key = build_key_identity(
        private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
        namespaces=["synthetic"],
    )
    signer = build_signer_identity(SignerIdentityKind.INDIVIDUAL_DECLARED, "Local User")
    binding = build_binding(signer, key)
    bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    descriptor = build_descriptor(value, object_type, purpose, namespace="synthetic")
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(value, object_type, [signature], keys=[key])
    personal = build_policy(
        "personal_local_trust",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["synthetic"],
    )
    project = build_policy(
        "project_maintainer_release",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["different"],
    )
    enterprise = build_policy(
        "enterprise_offline_release",
        object_types=[object_type],
        purposes=[purpose],
        namespaces=["synthetic"],
        require_expiration=True,
    )
    personal_result = verify_envelope(envelope, bundle, personal)
    project_result = verify_envelope(envelope, bundle, project)
    enterprise_result = verify_envelope(envelope, bundle, enterprise)
    assert personal_result.signature_results[0].trust_policy_status == (
        TrustPolicyStatus.TRUSTED_BY_POLICY
    )
    assert project_result.signature_results[0].trust_policy_status == (
        TrustPolicyStatus.PARTIALLY_TRUSTED
    )
    assert enterprise_result.signature_results[0].trust_policy_status == (
        TrustPolicyStatus.PARTIALLY_TRUSTED
    )
    assert enterprise_result.overall_status == (OverallSignedObjectStatus.EXPIRATION_NOT_EVALUATED)
    assert {
        item.signature_results[0].signature_id
        for item in (
            personal_result,
            project_result,
            enterprise_result,
        )
    } == {signature.signature_id}


def test_known_trusted_key_can_have_unavailable_signer_identity() -> None:
    value = _object()
    private = _private()
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    key = build_key_identity(
        private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
    )
    policy = build_policy(
        "personal_local_trust",
        object_types=[object_type],
        purposes=[purpose],
        require_binding=False,
        unknown_identity_behavior="ALLOW",
    )
    descriptor = build_descriptor(value, object_type, purpose)
    signature = build_signature_record(descriptor, private, key)
    envelope = build_signed_envelope(value, object_type, [signature], keys=[key])
    report = verify_envelope(envelope, build_trust_bundle([build_trust_root(key)], [key]), policy)
    result = report.signature_results[0]
    assert result.signature_integrity == SignatureIntegrity.VALID
    assert result.key_status == KeyStatus.KNOWN
    assert result.signer_identity_verification == SignerIdentityVerification.UNAVAILABLE
    assert result.trust_policy_status == TrustPolicyStatus.TRUSTED_BY_POLICY


def test_evidence_linked_identity_can_be_verified_only_by_selected_policy() -> None:
    private, key, _, _, root, policy, _, _, _ = _trusted()
    signer = build_signer_identity(
        SignerIdentityKind.INDIVIDUAL_DECLARED,
        "Evidence-linked Synthetic Signer",
        evidence=["synthetic-evidence-record"],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key)
    descriptor = build_descriptor(
        _object(),
        SignedObjectType.ARTIFACT_ATTESTATION,
        SignaturePurpose.ATTESTATION_ISSUANCE,
        policy_id=policy.policy_id,
        namespace="synthetic",
    )
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(_object(), SignedObjectType.ARTIFACT_ATTESTATION, [signature])
    bundle = build_trust_bundle([root], [key], identities=[signer], bindings=[binding])
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.signer_binding_status == BindingStatus.VERIFIED_BY_TRUST_BUNDLE
    assert result.signer_identity_verification == (SignerIdentityVerification.VERIFIED_BY_POLICY)


def test_effective_revocation_requires_explicit_evaluation_time() -> None:
    _, key, signer, binding, root, policy, _, _, envelope = _trusted()
    revocation = build_revocation(
        RevocationScope.KEY,
        key.key_id,
        RevocationReason.KEY_COMPROMISE,
        effective_at="2026-07-31T00:00:00Z",
    )
    bundle = build_trust_bundle(
        [root], [key], identities=[signer], bindings=[binding], revocations=[revocation]
    )
    report = verify_envelope(envelope, bundle, policy)
    assert report.signature_results[0].revocation_status.value == "NOT_EVALUATED"
    assert report.overall_status == OverallSignedObjectStatus.REVOCATION_NOT_EVALUATED
    before = build_evaluation_context(policy, evaluation_time="2026-07-30T23:59:59Z")
    effective = build_evaluation_context(policy, evaluation_time="2026-07-31T00:00:00Z")
    assert (
        verify_envelope(envelope, bundle, policy, before).signature_results[0].revocation_status
        == RevocationStatus.NOT_REVOKED
    )
    assert (
        verify_envelope(envelope, bundle, policy, effective).signature_results[0].revocation_status
        == RevocationStatus.REVOKED
    )


@pytest.mark.parametrize(
    "scope",
    [
        RevocationScope.KEY,
        RevocationScope.SIGNATURE,
        RevocationScope.SIGNER_KEY_BINDING,
        RevocationScope.TRUST_ROOT,
        RevocationScope.SIGNED_OBJECT,
    ],
)
def test_local_policy_revocation_scopes_are_independently_evaluated(
    scope: RevocationScope,
) -> None:
    _, key, signer, binding, root, policy, _, signature, envelope = _trusted()
    targets = {
        RevocationScope.KEY: key.key_id,
        RevocationScope.SIGNATURE: signature.signature_id,
        RevocationScope.SIGNER_KEY_BINDING: binding.binding_id,
        RevocationScope.TRUST_ROOT: root.trust_root_id,
        RevocationScope.SIGNED_OBJECT: envelope.signed_object_id,
    }
    revocation = build_revocation(scope, targets[scope], RevocationReason.KEY_COMPROMISE)
    bundle = build_trust_bundle(
        [root], [key], identities=[signer], bindings=[binding], revocations=[revocation]
    )
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.revocation_status == RevocationStatus.REVOKED
    assert result.revocation_records[0].authority == (
        RevocationAuthority.AUTHORIZED_BY_LOCAL_POLICY
    )
    assert result.revocation_records[0].scope == scope
    assert result.revocation_records[0].reason == RevocationReason.KEY_COMPROMISE
    markdown = render_markdown(verify_envelope(envelope, bundle, policy))
    for value in (
        "Revocation record",
        "Revocation authority: **AUTHORIZED_BY_LOCAL_POLICY**",
        f"Revocation scope/status: **{scope.value}** / **REVOKED**",
        "Revocation reason: **KEY_COMPROMISE**",
    ):
        assert value in markdown


@pytest.mark.parametrize(
    ("reason", "replacement", "status"),
    [
        (RevocationReason.SUPERSEDED, "replacement-key-record", RevocationStatus.SUPERSEDED),
        (RevocationReason.WITHDRAWN, None, RevocationStatus.WITHDRAWN),
        (RevocationReason.KEY_COMPROMISE, None, RevocationStatus.REVOKED),
    ],
)
def test_revocation_reason_and_replacement_are_not_collapsed(
    reason: RevocationReason, replacement: str | None, status: RevocationStatus
) -> None:
    _, key, signer, binding, root, policy, _, _, envelope = _trusted()
    revocation = build_revocation(
        RevocationScope.KEY,
        key.key_id,
        reason,
        replacement_reference=replacement,
    )
    bundle = build_trust_bundle(
        [root], [key], identities=[signer], bindings=[binding], revocations=[revocation]
    )
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.revocation_status == status
    assert result.revocation_records[0].reason == reason
    assert result.revocation_records[0].replacement_reference == replacement


def test_revocation_integrity_is_not_revocation_authority() -> None:
    _, key, signer, binding, root, _, _, _, envelope = _trusted()
    policy = build_policy(
        "project_maintainer_release",
        object_types=[SignedObjectType.ARTIFACT_ATTESTATION],
        purposes=[SignaturePurpose.ATTESTATION_ISSUANCE],
        namespaces=["synthetic"],
        accept_local_declarative_revocation=False,
    )
    revocation = build_revocation(RevocationScope.KEY, key.key_id, RevocationReason.KEY_COMPROMISE)
    bundle = build_trust_bundle(
        [root], [key], identities=[signer], bindings=[binding], revocations=[revocation]
    )
    result = verify_envelope(envelope, bundle, policy).signature_results[0]
    assert result.revocation_status == RevocationStatus.NOT_REVOKED
    assert result.revocation_records[0].authority == RevocationAuthority.REJECTED_BY_POLICY
    assert result.revocation_records[0].effective_status == RevocationStatus.NOT_APPLICABLE

    raw = revocation.model_dump(mode="json", by_alias=True)
    raw["authoritative_basis"] = "TRUST_ROOT_SIGNATURE"
    raw.pop("revocation_id")
    raw.pop("revocation_digest")
    raw["revocation_id"] = "revocation_" + canonical_sha256(raw)[:32]
    raw["revocation_digest"] = canonical_sha256(raw)
    with pytest.raises(ValidationError, match="reserved and unsupported"):
        type(revocation).model_validate(raw)


@pytest.mark.parametrize("target_kind", ["delegator", "delegate", "delegation"])
def test_delegated_path_revocations_cover_every_authority(
    target_kind: str,
) -> None:
    root_key, delegate_key, root, delegation, signer, binding, policy, _, envelope = _delegated()
    targets = {
        "delegator": (RevocationScope.KEY, root_key.key_id),
        "delegate": (RevocationScope.KEY, delegate_key.key_id),
        "delegation": (RevocationScope.DELEGATION, delegation.delegation_id),
    }
    scope, target = targets[target_kind]
    revocation = build_revocation(scope, target, RevocationReason.KEY_COMPROMISE)
    bundle = build_trust_bundle(
        [root],
        [root_key, delegate_key],
        identities=[signer],
        bindings=[binding],
        delegations=[delegation],
        revocations=[revocation],
    )
    report = verify_envelope(envelope, bundle, policy)
    assert report.overall_status == OverallSignedObjectStatus.REVOKED
    assert report.signature_results[0].revocation_status == RevocationStatus.REVOKED


def test_expired_delegation_is_reported_by_expiration_layer() -> None:
    parent = ValidityWindow(not_before="2024-01-01T00:00:00Z", not_after="2027-12-31T23:59:59Z")
    delegated = ValidityWindow(not_before="2025-01-01T00:00:00Z", not_after="2025-12-31T23:59:59Z")
    *_, policy, bundle, envelope = _delegated(
        delegation_validity=delegated,
        parent_validity=parent,
        require_expiration=True,
    )
    context = build_evaluation_context(policy, evaluation_time="2026-01-01T00:00:00Z")
    report = verify_envelope(envelope, bundle, policy, context)
    result = report.signature_results[0]
    assert result.delegation_status == DelegationStatus.VALID_DELEGATION
    assert result.expiration_status == ExpirationStatus.EXPIRED
    assert report.overall_status == OverallSignedObjectStatus.EXPIRED


def test_execution_record_signed_independently() -> None:
    attestation = _object()
    execution = attestation["execution_record"]
    assert isinstance(execution, dict)
    *_, policy, bundle, _, envelope = _trusted(
        execution,
        object_type=SignedObjectType.TOOL_EXECUTION_RECORD,
        purpose=SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
    )
    original = canonical_sha256(execution)
    report = verify_envelope(envelope, bundle, policy)
    assert canonical_sha256(execution) == original
    assert report.underlying_claim["execution_result"] == "SUCCEEDED"
    assert report.payload_status == "NOT_CHECKED"


def test_custody_event_and_segment_wrappers_preserve_sources() -> None:
    ledger = _object(LEDGER)
    event = ledger["events"][0]
    assert isinstance(event, dict)
    event_digest = event["event_digest"]
    *_, policy, bundle, _, envelope = _trusted(
        event,
        object_type=SignedObjectType.CUSTODY_EVENT,
        purpose=SignaturePurpose.CUSTODY_EVENT_ISSUANCE,
    )
    report = verify_envelope(envelope, bundle, policy)
    assert event["event_digest"] == event_digest
    assert report.content_independently_proven is False

    attestation = ArtifactAttestation.model_validate(_object())
    segment = build_attestation_custody_segment(
        attestation, attestation_reference="attestations/examples/synthetic.json"
    ).model_dump(mode="json", by_alias=True)
    ledger_digest = segment["ledger_digest"]
    *_, policy2, bundle2, _, envelope2 = _trusted(
        segment,
        object_type=SignedObjectType.CUSTODY_SEGMENT,
        purpose=SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
    )
    report2 = verify_envelope(envelope2, bundle2, policy2)
    assert segment["ledger_digest"] == ledger_digest
    assert report2.lifecycle_completeness == "INCOMPLETE"
    assert report2.underlying_claim["genesis_semantics"] == "PORTABLE_SEGMENT_BEGINNING"


@pytest.mark.parametrize("source", [PASSPORT_V1_SOURCE, PASSPORT_V2_SOURCE])
def test_generic_passport_v1_v2_signed_without_mutation(source: Path) -> None:
    passport = _synthetic_passport(source)
    original_id = passport["passport_id"]
    original_digest = passport["passport_digest"]
    *_, policy, bundle, _, envelope = _trusted(
        passport,
        object_type=SignedObjectType.MODEL_PASSPORT,
        purpose=SignaturePurpose.PASSPORT_ISSUANCE,
    )
    report = verify_envelope(envelope, bundle, policy)
    assert passport["passport_id"] == original_id
    assert passport["passport_digest"] == original_digest
    assert report.signed_object_schema in {
        "omiv.model-passport.v1",
        "omiv.model-passport.v2",
    }
    assert report.payload_status == "NOT_CHECKED"
    assert report.security_status == "NOT_CHECKED"
    assert report.runtime_status == "NOT_CHECKED"
    assert report.approval_status == "NOT_AVAILABLE"
    assert report.lifecycle_completeness in {"INCOMPLETE", "TRUST_CHAIN_INCOMPLETE"}


def test_markdown_never_collapses_signed_into_trusted() -> None:
    *_, policy, bundle, _, envelope = _trusted()
    markdown = render_markdown(verify_envelope(envelope, bundle, policy))
    for label in (
        "Signature integrity",
        "Trusted by selected policy: **YES**",
        "Key identity/status",
        "Signer identity",
        "Signer identity verification",
        "Signer/key binding",
        "Policy trust",
        "Claim content independently proven: **NO**",
        "Payload integrity: **NOT_CHECKED**",
        "Security: **NOT_CHECKED**",
        "Runtime: **NOT_CHECKED**",
        "Approval: **NOT_AVAILABLE**",
    ):
        assert label in markdown


def test_report_is_deterministic() -> None:
    *_, policy, bundle, _, envelope = _trusted()
    first = verify_envelope(envelope, bundle, policy)
    second = verify_envelope(envelope, bundle, policy)
    assert first == second
    assert first.report_digest == second.report_digest


def test_signature_envelope_report_dependency_order_is_acyclic() -> None:
    *_, policy, bundle, signature, envelope = _trusted()
    report = verify_envelope(envelope, bundle, policy)
    source_text = json.dumps(envelope.signed_object, sort_keys=True)
    envelope_text = json.dumps(envelope.model_dump(mode="json", by_alias=True), sort_keys=True)
    descriptor_text = json.dumps(signature.payload.model_dump(mode="json"), sort_keys=True)
    assert envelope.envelope_id not in source_text
    assert signature.signature_id not in descriptor_text
    assert report.report_id not in envelope_text
    assert report.report_digest not in envelope_text
    assert envelope.signed_object_digest == canonical_sha256(envelope.signed_object)


def test_report_verification_rejects_rehashed_false_summary(tmp_path: Path) -> None:
    *_, policy, bundle, _, envelope = _trusted()
    report = verify_envelope(envelope, bundle, policy)
    raw = report.model_dump(mode="json", by_alias=True)
    raw["payload_status"] = "PASS"
    raw.pop("report_id")
    raw.pop("report_digest")
    raw["report_id"] = "trust_report_" + canonical_sha256(raw)[:32]
    raw["report_digest"] = canonical_sha256(raw)
    path = tmp_path / "rehashed-false-report.json"
    path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    with pytest.raises(OmivInputError, match="does not reconstruct"):
        verify_report(path, envelope, bundle, policy)


def test_gap_report_cannot_be_signed_as_lifecycle_evidence() -> None:
    gap = _object(ROOT / "reports/attestations/kimi_k3_attestation_gap.report.json")
    with pytest.raises(OmivInputError, match="does not match ARTIFACT_ATTESTATION"):
        build_descriptor(
            gap,
            SignedObjectType.ARTIFACT_ATTESTATION,
            SignaturePurpose.ATTESTATION_ISSUANCE,
        )


def test_multiple_signatures_are_ordered_and_independently_evaluated() -> None:
    value = _object()
    object_type = SignedObjectType.ARTIFACT_ATTESTATION
    purpose = SignaturePurpose.ATTESTATION_ISSUANCE
    first_private = _private()
    second_private = _private(RFC8032_VECTOR_2)
    first_key = build_key_identity(
        first_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
    )
    second_key = build_key_identity(
        second_private,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
    )
    first_signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Signer One")
    second_signer = build_signer_identity(SignerIdentityKind.TEAM_DECLARED, "Signer Two")
    first_binding = build_binding(first_signer, first_key)
    second_binding = build_binding(second_signer, second_key)
    policy = build_policy(
        "regulated_multi_party_release",
        object_types=[object_type],
        purposes=[purpose],
        minimum_signature_count=2,
    )
    descriptor = build_descriptor(value, object_type, purpose, policy_id=policy.policy_id)
    first_signature = build_signature_record(
        descriptor, first_private, first_key, binding_id=first_binding.binding_id
    )
    second_signature = build_signature_record(
        descriptor, second_private, second_key, binding_id=second_binding.binding_id
    )
    envelope = build_signed_envelope(
        value,
        object_type,
        [second_signature, first_signature],
        keys=[second_key, first_key],
    )
    bundle = build_trust_bundle(
        [build_trust_root(first_key), build_trust_root(second_key)],
        [first_key, second_key],
        identities=[first_signer, second_signer],
        bindings=[first_binding, second_binding],
    )
    report = verify_envelope(envelope, bundle, policy)
    assert [item.signature_id for item in envelope.signatures] == sorted(
        [first_signature.signature_id, second_signature.signature_id]
    )
    assert report.accepted_signature_count == 2
    assert all(
        item.signature_integrity == SignatureIntegrity.VALID
        and item.trust_policy_status == TrustPolicyStatus.TRUSTED_BY_POLICY
        for item in report.signature_results
    )
    assert report.overall_status == OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS

    invalid_raw = second_signature.model_dump(mode="json", by_alias=True)
    invalid_raw["detached_signature"] = "00" + invalid_raw["detached_signature"][2:]
    invalid_raw.pop("signature_id")
    invalid_raw.pop("signature_digest")
    invalid_raw["signature_id"] = "sig_" + canonical_sha256(invalid_raw)[:32]
    invalid_raw["signature_digest"] = canonical_sha256(invalid_raw)
    invalid_signature = SignatureRecord.model_validate(invalid_raw)
    invalid_envelope = build_signed_envelope(
        value, object_type, [first_signature, invalid_signature]
    )
    invalid_report = verify_envelope(invalid_envelope, bundle, policy)
    assert invalid_report.overall_status == OverallSignedObjectStatus.INVALID_SIGNATURE
    assert {item.signature_integrity for item in invalid_report.signature_results} == {
        SignatureIntegrity.VALID,
        SignatureIntegrity.INVALID,
    }

    partial_bundle = build_trust_bundle(
        [build_trust_root(first_key)],
        [first_key],
        identities=[first_signer],
        bindings=[first_binding],
    )
    partial = verify_envelope(envelope, partial_bundle, policy)
    assert partial.accepted_signature_count == 1
    assert partial.overall_status == OverallSignedObjectStatus.VALID_SIGNATURE_UNTRUSTED_KEY

    with pytest.raises(ValidationError, match="signatures must be unique"):
        build_signed_envelope(value, object_type, [first_signature, first_signature])

    duplicate_raw = first_signature.model_dump(mode="json", by_alias=True)
    duplicate_raw["binding_id"] = None
    duplicate_raw.pop("signature_id")
    duplicate_raw.pop("signature_digest")
    duplicate_raw["signature_id"] = "sig_" + canonical_sha256(duplicate_raw)[:32]
    duplicate_raw["signature_digest"] = canonical_sha256(duplicate_raw)
    duplicate_pair = SignatureRecord.model_validate(duplicate_raw)
    with pytest.raises(ValidationError, match="duplicate key and purpose"):
        build_signed_envelope(value, object_type, [first_signature, duplicate_pair])


def test_trust_core_has_no_model_pack_or_kimi_dependency() -> None:
    for path in (ROOT / "src/omiv/trust").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "omiv.model_packs" not in text
        assert "kimi_k3" not in text.lower()


def test_generated_artifacts_reproduce_byte_for_byte(tmp_path: Path) -> None:
    generated = generate(ROOT, tmp_path)
    assert len(generated) == 61
    for candidate in generated:
        relative = candidate.relative_to(tmp_path)
        assert candidate.read_bytes() == (ROOT / relative).read_bytes()
        assert candidate.stat().st_size < 1024 * 1024
        text = candidate.read_text(encoding="utf-8")
        assert RFC8032_VECTOR_1 not in text
        assert RFC8032_VECTOR_2 not in text
        assert "BEGIN PRIVATE KEY" not in text
    complete_cases = {
        "trusted-transformation",
        "signed-declared-acquisition",
        "signed-evidence-linked-acquisition",
        "signed-quantization",
        "signed-execution-record",
        "signed-quantization-execution-record",
        "signed-custody-event",
        "signed-custody-segment",
        "signed-passport-v1",
        "signed-passport-v2",
    }
    for name in complete_cases:
        assert (tmp_path / f"trust/examples/{name}.signed-envelope.json").is_file()
        assert (tmp_path / f"reports/trust/{name}.signature-report.json").is_file()
        assert (tmp_path / f"reports/trust/{name}.signature-report.md").is_file()


def test_generated_wrappers_preserve_every_canonical_source_object() -> None:
    source_by_case = {
        "trusted-transformation": ATTESTATION,
        "signed-declared-acquisition": ACQUISITION,
        "signed-evidence-linked-acquisition": (
            ROOT / "attestations/examples/synthetic_evidence_linked_acquisition.attestation.json"
        ),
        "signed-quantization": (
            ROOT / "attestations/examples/synthetic_quantization.attestation.json"
        ),
    }
    for name, source in source_by_case.items():
        envelope = _object(ROOT / f"trust/examples/{name}.signed-envelope.json")
        assert canonical_json_bytes(envelope["signed_object"]) == canonical_json_bytes(
            _object(source)
        )
    execution_by_case = {
        "signed-execution-record": ATTESTATION,
        "signed-quantization-execution-record": (
            ROOT / "attestations/examples/synthetic_quantization.attestation.json"
        ),
    }
    for name, source in execution_by_case.items():
        envelope = _object(ROOT / f"trust/examples/{name}.signed-envelope.json")
        attestation = _object(source)
        assert canonical_json_bytes(envelope["signed_object"]) == canonical_json_bytes(
            attestation["execution_record"]
        )
    ledger = _object(LEDGER)
    event_envelope = _object(ROOT / "trust/examples/signed-custody-event.signed-envelope.json")
    assert canonical_json_bytes(event_envelope["signed_object"]) == canonical_json_bytes(
        ledger["events"][0]
    )
    segment = build_attestation_custody_segment(
        ArtifactAttestation.model_validate(_object()),
        attestation_reference="attestations/examples/synthetic_transformation.attestation.json",
    ).model_dump(mode="json", by_alias=True)
    segment_envelope = _object(ROOT / "trust/examples/signed-custody-segment.signed-envelope.json")
    assert canonical_json_bytes(segment_envelope["signed_object"]) == canonical_json_bytes(segment)
    for name, source in (
        ("signed-passport-v1", PASSPORT_V1_SOURCE),
        ("signed-passport-v2", PASSPORT_V2_SOURCE),
    ):
        envelope = _object(ROOT / f"trust/examples/{name}.signed-envelope.json")
        assert canonical_json_bytes(envelope["signed_object"]) == canonical_json_bytes(
            _synthetic_passport(source)
        )


@pytest.mark.parametrize(
    "name",
    [
        "trusted-transformation",
        "signed-declared-acquisition",
        "signed-evidence-linked-acquisition",
        "signed-quantization",
        "signed-execution-record",
        "signed-quantization-execution-record",
        "signed-custody-event",
        "signed-custody-segment",
        "signed-passport-v1",
        "signed-passport-v2",
    ],
)
def test_complete_generated_pipeline_reconstructs_json_and_markdown(name: str) -> None:
    envelope = load_envelope(ROOT / f"trust/examples/{name}.signed-envelope.json")
    bundle = load_bundle(ROOT / "trust/examples/project-trust-bundle.json")
    policy = load_policy(ROOT / "trust/examples/project-trust-policy.json")
    context = load_context(ROOT / "trust/examples/evaluation-context.json")
    report = verify_report(
        ROOT / f"reports/trust/{name}.signature-report.json",
        envelope,
        bundle,
        policy,
        context,
    )
    assert report.signed_object_id == envelope.signed_object_id
    assert report.signed_object_digest == envelope.signed_object_digest
    assert report.signature_results[0].signature_integrity == SignatureIntegrity.VALID
    assert (ROOT / f"reports/trust/{name}.signature-report.md").read_text(
        encoding="utf-8"
    ) == render_markdown(report)


@pytest.mark.parametrize(
    ("name", "bundle", "policy", "context", "exit_code"),
    [
        (
            "trusted-transformation",
            "project-trust-bundle.json",
            "project-trust-policy.json",
            "evaluation-context.json",
            0,
        ),
        (
            "unknown-key",
            "project-trust-bundle.json",
            "project-trust-policy.json",
            "evaluation-context.json",
            1,
        ),
        (
            "revoked-attestation",
            "revoked-project-trust-bundle.json",
            "project-trust-policy.json",
            "evaluation-context.json",
            2,
        ),
        (
            "expired-attestation",
            "expired-project-trust-bundle.json",
            "expiration-trust-policy.json",
            "expired-evaluation-context.json",
            2,
        ),
    ],
)
def test_cli_verify_exit_codes(
    name: str, bundle: str, policy: str, context: str, exit_code: int
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "trust",
            "verify",
            "--input",
            str(ROOT / f"trust/examples/{name}.signed-envelope.json"),
            "--trust-bundle",
            str(ROOT / f"trust/examples/{bundle}"),
            "--policy",
            str(ROOT / f"trust/examples/{policy}"),
            "--evaluation-context",
            str(ROOT / f"trust/examples/{context}"),
        ],
    )
    assert result.exit_code == exit_code, result.output
    if exit_code == 0:
        for boundary in (
            "signature_integrity=VALID",
            "trusted_by_selected_policy=YES",
            "key_status=KNOWN",
            "signer_identity=DECLARED",
            "signer_binding=VERIFIED_BY_TRUST_BUNDLE",
            "claim_independently_proven=NO",
            "payload_integrity=NOT_CHECKED",
            "numerical_fidelity=NOT_CHECKED",
            "security=NOT_CHECKED",
            "runtime=NOT_CHECKED",
            "approval=NOT_AVAILABLE",
        ):
            assert boundary in result.output


def test_cli_sign_key_inspect_show_and_report_verify(tmp_path: Path) -> None:
    private = _private()
    private_path = tmp_path / "runtime-signing-key.pem"
    public_path = tmp_path / "public-key.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    envelope = tmp_path / "signed.json"
    report = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    runner = CliRunner()
    inspected = runner.invoke(app, ["trust", "key-inspect", "--public-key", str(public_path)])
    assert inspected.exit_code == 0
    assert "key_ed39d828050734934fcf309c611f5d9b" in inspected.output
    binding = json.loads((ROOT / "trust/examples/project-maintainer.binding.json").read_text())[
        "binding_id"
    ]
    signed = runner.invoke(
        app,
        [
            "trust",
            "sign",
            "--input",
            str(ATTESTATION),
            "--object-type",
            "ARTIFACT_ATTESTATION",
            "--purpose",
            "ATTESTATION_ISSUANCE",
            "--private-key",
            str(private_path),
            "--public-key",
            str(public_path),
            "--output",
            str(envelope),
            "--trust-bundle",
            str(ROOT / "trust/examples/project-trust-bundle.json"),
            "--policy",
            str(ROOT / "trust/examples/project-trust-policy.json"),
            "--evaluation-context",
            str(ROOT / "trust/examples/evaluation-context.json"),
            "--binding-id",
            binding,
            "--namespace",
            "synthetic",
            "--report-output",
            str(report),
            "--markdown-output",
            str(markdown),
        ],
    )
    assert signed.exit_code == 0, signed.output
    assert RFC8032_VECTOR_1 not in signed.output
    assert str(private_path) not in signed.output
    shown = runner.invoke(app, ["trust", "show", "--input", str(envelope)])
    assert shown.exit_code == 0
    assert "Trust: NOT_EVALUATED" in shown.output
    verified = runner.invoke(
        app,
        [
            "trust",
            "report-verify",
            "--report",
            str(report),
            "--envelope",
            str(envelope),
            "--trust-bundle",
            str(ROOT / "trust/examples/project-trust-bundle.json"),
            "--policy",
            str(ROOT / "trust/examples/project-trust-policy.json"),
            "--evaluation-context",
            str(ROOT / "trust/examples/evaluation-context.json"),
        ],
    )
    assert verified.exit_code == 0, verified.output


def test_cli_sign_requires_explicit_private_key(tmp_path: Path) -> None:
    public_path = tmp_path / "public-key.pem"
    output_path = tmp_path / "must-not-exist.json"
    public_path.write_bytes(
        _private()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    result = CliRunner().invoke(
        app,
        [
            "trust",
            "sign",
            "--input",
            str(ATTESTATION),
            "--object-type",
            "ARTIFACT_ATTESTATION",
            "--purpose",
            "ATTESTATION_ISSUANCE",
            "--public-key",
            str(public_path),
            "--output",
            str(output_path),
        ],
        color=False,
        terminal_width=160,
    )
    assert result.exit_code == 2
    assert result.stdout == ""
    normalized_stderr = " ".join(strip_ansi(result.stderr).split())
    assert "Missing option '--private-key'." in normalized_stderr
    assert not output_path.exists()
    assert RFC8032_VECTOR_1 not in result.output


@pytest.mark.parametrize(
    ("command", "path"),
    [
        ("bundle-verify", "project-trust-bundle.json"),
        ("delegation-verify", "delegation-record.json"),
        ("revocation-verify", "project-key.revocation-record.json"),
    ],
)
def test_cli_static_record_verification(command: str, path: str) -> None:
    arguments = ["trust", command, "--input", str(ROOT / "trust/examples" / path)]
    if command == "delegation-verify":
        arguments.extend(
            [
                "--trust-bundle",
                str(ROOT / "trust/examples/delegated-trust-bundle.json"),
            ]
        )
    result = CliRunner().invoke(
        app,
        arguments,
    )
    assert result.exit_code == 0, result.output
