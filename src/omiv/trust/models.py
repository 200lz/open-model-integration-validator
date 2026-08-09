"""Strict Phase 5D schemas for offline signatures and trust evaluation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"
HEX32_PATTERN = r"^[0-9a-f]{64}$"
HEX64_PATTERN = r"^[0-9a-f]{128}$"
UTC_TIMESTAMP_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"


def _validate_utc_timestamp(value: str | None) -> None:
    if value is None:
        return
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("timestamp must be a valid fixed-width UTC value") from exc


def _unsafe_trust_value(value: object) -> bool:
    if isinstance(value, str):
        forbidden = (
            "Authorization",
            "Bearer ",
            "github_pat_",
            "ghp_",
            "hf_",
            "X-Amz-",
            "Signature=",
            "Key-Pair-Id=",
            "api_key=",
            "access_token=",
            "password=",
            "BEGIN PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
        )
        return (
            value.startswith(("/", "~/"))
            or (len(value) >= 3 and value[0].isalpha() and value[1:3] in {":/", ":\\"})
            or any(item in value for item in forbidden)
            or (value.startswith(("http://", "https://")) and "?" in value)
        )
    if isinstance(value, list):
        return any(_unsafe_trust_value(item) for item in value)
    if isinstance(value, dict):
        forbidden_fields = {
            "private_key",
            "private_key_path",
            "private_seed",
            "secret_scalar",
            "certificate_blob",
            "credentials",
        }
        return bool(forbidden_fields.intersection(value)) or any(
            _unsafe_trust_value(item) for item in value.values()
        )
    return False


class TrustModel(StrictModel):
    """Strict public-only trust model with shared path and secret rejection."""

    @model_validator(mode="after")
    def public_portable_values(self) -> TrustModel:
        if _unsafe_trust_value(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("trust object contains a local path, credential, or private material")
        return self


class SignatureAlgorithm(StrEnum):
    ED25519 = "ED25519"
    ECDSA_P256_RESERVED = "ECDSA_P256_RESERVED"
    RSA_PSS_SHA256_RESERVED = "RSA_PSS_SHA256_RESERVED"
    SIGSTORE_RESERVED = "SIGSTORE_RESERVED"


class SignedObjectType(StrEnum):
    ARTIFACT_ATTESTATION = "ARTIFACT_ATTESTATION"
    TOOL_EXECUTION_RECORD = "TOOL_EXECUTION_RECORD"
    CUSTODY_EVENT = "CUSTODY_EVENT"
    CUSTODY_SEGMENT = "CUSTODY_SEGMENT"
    MODEL_PASSPORT = "MODEL_PASSPORT"
    POLICY_DECISION = "POLICY_DECISION"
    APPROVAL_RECORD = "APPROVAL_RECORD"
    REJECTION_RECORD = "REJECTION_RECORD"
    RELEASE_CANDIDATE = "RELEASE_CANDIDATE"
    PROMOTION_DECISION = "PROMOTION_DECISION"
    SECURITY_SCAN_EXECUTION_RECORD = "SECURITY_SCAN_EXECUTION_RECORD"
    SECURITY_EVIDENCE_BUNDLE = "SECURITY_EVIDENCE_BUNDLE"
    SECURITY_EVALUATION = "SECURITY_EVALUATION"
    DEPLOYMENT_INTENT = "DEPLOYMENT_INTENT"
    DEPLOYMENT_MANIFEST = "DEPLOYMENT_MANIFEST"
    DEPLOYMENT_RECORD = "DEPLOYMENT_RECORD"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    CONTINUITY_EVALUATION = "CONTINUITY_EVALUATION"
    TRUST_SNAPSHOT = "TRUST_SNAPSHOT"
    TRUST_TIMELINE = "TRUST_TIMELINE"
    HISTORICAL_EVALUATION_RESULT = "HISTORICAL_EVALUATION_RESULT"
    AUDIT_BUNDLE_MANIFEST = "AUDIT_BUNDLE_MANIFEST"
    AUDIT_BUNDLE_VERIFICATION_RESULT = "AUDIT_BUNDLE_VERIFICATION_RESULT"
    PAYLOAD_EXPECTATION = "PAYLOAD_EXPECTATION"
    OBSERVED_PAYLOAD_MANIFEST = "OBSERVED_PAYLOAD_MANIFEST"
    PAYLOAD_INTEGRITY_EVIDENCE = "PAYLOAD_INTEGRITY_EVIDENCE"
    REMOTE_SNAPSHOT_MANIFEST = "REMOTE_SNAPSHOT_MANIFEST"
    REMOTE_SNAPSHOT_EXPECTATION = "REMOTE_SNAPSHOT_EXPECTATION"
    REMOTE_LOCAL_RECONCILIATION_EVIDENCE = "REMOTE_LOCAL_RECONCILIATION_EVIDENCE"
    QUANTIZATION_RELATIONSHIP_DECLARATION = "QUANTIZATION_RELATIONSHIP_DECLARATION"
    REPRESENTATION_OBSERVATION = "REPRESENTATION_OBSERVATION"
    QUANTIZATION_FIDELITY_EVIDENCE = "QUANTIZATION_FIDELITY_EVIDENCE"


class SignaturePurpose(StrEnum):
    ATTESTATION_ISSUANCE = "ATTESTATION_ISSUANCE"
    EXECUTION_RECORD_ISSUANCE = "EXECUTION_RECORD_ISSUANCE"
    CUSTODY_EVENT_ISSUANCE = "CUSTODY_EVENT_ISSUANCE"
    CUSTODY_SEGMENT_ISSUANCE = "CUSTODY_SEGMENT_ISSUANCE"
    PASSPORT_ISSUANCE = "PASSPORT_ISSUANCE"
    POLICY_DECISION_ISSUANCE = "POLICY_DECISION_ISSUANCE"
    APPROVAL_RECORD_ISSUANCE = "APPROVAL_RECORD_ISSUANCE"
    REJECTION_RECORD_ISSUANCE = "REJECTION_RECORD_ISSUANCE"
    RELEASE_CANDIDATE_ISSUANCE = "RELEASE_CANDIDATE_ISSUANCE"
    PROMOTION_DECISION_ISSUANCE = "PROMOTION_DECISION_ISSUANCE"
    SECURITY_SCAN_ISSUANCE = "SECURITY_SCAN_ISSUANCE"
    SECURITY_EVIDENCE_ISSUANCE = "SECURITY_EVIDENCE_ISSUANCE"
    SECURITY_EVALUATION_ISSUANCE = "SECURITY_EVALUATION_ISSUANCE"
    DEPLOYMENT_INTENT_ISSUANCE = "DEPLOYMENT_INTENT_ISSUANCE"
    DEPLOYMENT_MANIFEST_ISSUANCE = "DEPLOYMENT_MANIFEST_ISSUANCE"
    DEPLOYMENT_RECORD_ISSUANCE = "DEPLOYMENT_RECORD_ISSUANCE"
    RUNTIME_OBSERVATION_ISSUANCE = "RUNTIME_OBSERVATION_ISSUANCE"
    CONTINUITY_EVALUATION_ISSUANCE = "CONTINUITY_EVALUATION_ISSUANCE"
    TRUST_SNAPSHOT_ISSUANCE = "TRUST_SNAPSHOT_ISSUANCE"
    TRUST_TIMELINE_ISSUANCE = "TRUST_TIMELINE_ISSUANCE"
    HISTORICAL_EVALUATION_ISSUANCE = "HISTORICAL_EVALUATION_ISSUANCE"
    AUDIT_BUNDLE_ISSUANCE = "AUDIT_BUNDLE_ISSUANCE"
    AUDIT_BUNDLE_VERIFICATION_ISSUANCE = "AUDIT_BUNDLE_VERIFICATION_ISSUANCE"
    PAYLOAD_EXPECTATION_ISSUANCE = "PAYLOAD_EXPECTATION_ISSUANCE"
    OBSERVED_PAYLOAD_MANIFEST_ISSUANCE = "OBSERVED_PAYLOAD_MANIFEST_ISSUANCE"
    PAYLOAD_INTEGRITY_EVIDENCE_ISSUANCE = "PAYLOAD_INTEGRITY_EVIDENCE_ISSUANCE"
    REMOTE_SNAPSHOT_MANIFEST_ISSUANCE = "REMOTE_SNAPSHOT_MANIFEST_ISSUANCE"
    REMOTE_SNAPSHOT_EXPECTATION_ISSUANCE = "REMOTE_SNAPSHOT_EXPECTATION_ISSUANCE"
    REMOTE_LOCAL_RECONCILIATION_EVIDENCE_ISSUANCE = "REMOTE_LOCAL_RECONCILIATION_EVIDENCE_ISSUANCE"
    QUANTIZATION_RELATIONSHIP_DECLARATION_ISSUANCE = (
        "QUANTIZATION_RELATIONSHIP_DECLARATION_ISSUANCE"
    )
    REPRESENTATION_OBSERVATION_ISSUANCE = "REPRESENTATION_OBSERVATION_ISSUANCE"
    QUANTIZATION_FIDELITY_EVIDENCE_ISSUANCE = "QUANTIZATION_FIDELITY_EVIDENCE_ISSUANCE"
    SECURITY_REPORT_RESERVED = "SECURITY_REPORT_RESERVED"
    POLICY_DECISION_RESERVED = "POLICY_DECISION_RESERVED"
    APPROVAL_RESERVED = "APPROVAL_RESERVED"
    PROMOTION_RESERVED = "PROMOTION_RESERVED"
    DEPLOYMENT_RESERVED = "DEPLOYMENT_RESERVED"
    REVOCATION_RESERVED = "REVOCATION_RESERVED"


ACTIVE_PURPOSES = {
    SignaturePurpose.ATTESTATION_ISSUANCE,
    SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
    SignaturePurpose.CUSTODY_EVENT_ISSUANCE,
    SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
    SignaturePurpose.PASSPORT_ISSUANCE,
    SignaturePurpose.POLICY_DECISION_ISSUANCE,
    SignaturePurpose.APPROVAL_RECORD_ISSUANCE,
    SignaturePurpose.REJECTION_RECORD_ISSUANCE,
    SignaturePurpose.RELEASE_CANDIDATE_ISSUANCE,
    SignaturePurpose.PROMOTION_DECISION_ISSUANCE,
    SignaturePurpose.SECURITY_SCAN_ISSUANCE,
    SignaturePurpose.SECURITY_EVIDENCE_ISSUANCE,
    SignaturePurpose.SECURITY_EVALUATION_ISSUANCE,
    SignaturePurpose.DEPLOYMENT_INTENT_ISSUANCE,
    SignaturePurpose.DEPLOYMENT_MANIFEST_ISSUANCE,
    SignaturePurpose.DEPLOYMENT_RECORD_ISSUANCE,
    SignaturePurpose.RUNTIME_OBSERVATION_ISSUANCE,
    SignaturePurpose.CONTINUITY_EVALUATION_ISSUANCE,
    SignaturePurpose.TRUST_SNAPSHOT_ISSUANCE,
    SignaturePurpose.TRUST_TIMELINE_ISSUANCE,
    SignaturePurpose.HISTORICAL_EVALUATION_ISSUANCE,
    SignaturePurpose.AUDIT_BUNDLE_ISSUANCE,
    SignaturePurpose.AUDIT_BUNDLE_VERIFICATION_ISSUANCE,
    SignaturePurpose.PAYLOAD_EXPECTATION_ISSUANCE,
    SignaturePurpose.OBSERVED_PAYLOAD_MANIFEST_ISSUANCE,
    SignaturePurpose.PAYLOAD_INTEGRITY_EVIDENCE_ISSUANCE,
    SignaturePurpose.REMOTE_SNAPSHOT_MANIFEST_ISSUANCE,
    SignaturePurpose.REMOTE_SNAPSHOT_EXPECTATION_ISSUANCE,
    SignaturePurpose.REMOTE_LOCAL_RECONCILIATION_EVIDENCE_ISSUANCE,
    SignaturePurpose.QUANTIZATION_RELATIONSHIP_DECLARATION_ISSUANCE,
    SignaturePurpose.REPRESENTATION_OBSERVATION_ISSUANCE,
    SignaturePurpose.QUANTIZATION_FIDELITY_EVIDENCE_ISSUANCE,
}


class KeyUsage(StrEnum):
    SIGN_OMIV_OBJECT = "SIGN_OMIV_OBJECT"
    DELEGATE_SIGNING = "DELEGATE_SIGNING"


class SignerIdentityKind(StrEnum):
    INDIVIDUAL_DECLARED = "INDIVIDUAL_DECLARED"
    ORGANIZATION_DECLARED = "ORGANIZATION_DECLARED"
    TEAM_DECLARED = "TEAM_DECLARED"
    SERVICE_DECLARED = "SERVICE_DECLARED"
    PROJECT_MAINTAINER_DECLARED = "PROJECT_MAINTAINER_DECLARED"
    UNKNOWN = "UNKNOWN"


class BindingOrigin(StrEnum):
    USER_DECLARED = "USER_DECLARED"
    TRUST_BUNDLE_DECLARED = "TRUST_BUNDLE_DECLARED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    DELEGATED = "DELEGATED"
    CERTIFICATE_RESERVED = "CERTIFICATE_RESERVED"
    OIDC_RESERVED = "OIDC_RESERVED"


class BindingStatus(StrEnum):
    VERIFIED_BY_TRUST_BUNDLE = "VERIFIED_BY_TRUST_BUNDLE"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    DECLARED = "DECLARED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    BROKEN = "BROKEN"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class SignatureIntegrity(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    MISSING = "MISSING"
    UNSUPPORTED = "UNSUPPORTED"
    UNVERIFIED = "UNVERIFIED"


class KeyStatus(StrEnum):
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    UNVERIFIED = "UNVERIFIED"


class SignerBindingResult(StrEnum):
    VERIFIED = "VERIFIED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    DECLARED = "DECLARED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    BROKEN = "BROKEN"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class SignerIdentityStatus(StrEnum):
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    DECLARED = "DECLARED"
    UNAVAILABLE = "UNAVAILABLE"


class SignerIdentityVerification(StrEnum):
    VERIFIED_BY_POLICY = "VERIFIED_BY_POLICY"
    UNVERIFIED = "UNVERIFIED"
    UNAVAILABLE = "UNAVAILABLE"


class DelegationStatus(StrEnum):
    DIRECT_ROOT = "DIRECT_ROOT"
    VALID_DELEGATION = "VALID_DELEGATION"
    INVALID_DELEGATION = "INVALID_DELEGATION"
    DEPTH_EXCEEDED = "DEPTH_EXCEEDED"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"


class RevocationStatus(StrEnum):
    NOT_REVOKED = "NOT_REVOKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"
    WITHDRAWN = "WITHDRAWN"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNVERIFIED = "UNVERIFIED"


class RevocationAuthority(StrEnum):
    AUTHORIZED_BY_LOCAL_POLICY = "AUTHORIZED_BY_LOCAL_POLICY"
    REJECTED_BY_POLICY = "REJECTED_BY_POLICY"
    ROOT_SIGNATURE_RESERVED_UNSUPPORTED = "ROOT_SIGNATURE_RESERVED_UNSUPPORTED"


class ExpirationStatus(StrEnum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class TrustPolicyStatus(StrEnum):
    TRUSTED_BY_POLICY = "TRUSTED_BY_POLICY"
    UNTRUSTED_BY_POLICY = "UNTRUSTED_BY_POLICY"
    PARTIALLY_TRUSTED = "PARTIALLY_TRUSTED"
    NOT_EVALUATED = "NOT_EVALUATED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    POLICY_INVALID = "POLICY_INVALID"


class OverallSignedObjectStatus(StrEnum):
    TRUSTED_SIGNATURE_WITH_LIMITATIONS = "TRUSTED_SIGNATURE_WITH_LIMITATIONS"
    VALID_SIGNATURE_UNTRUSTED_KEY = "VALID_SIGNATURE_UNTRUSTED_KEY"
    VALID_SIGNATURE_UNKNOWN_IDENTITY = "VALID_SIGNATURE_UNKNOWN_IDENTITY"
    PARTIALLY_TRUSTED = "PARTIALLY_TRUSTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRATION_NOT_EVALUATED = "EXPIRATION_NOT_EVALUATED"
    REVOCATION_NOT_EVALUATED = "REVOCATION_NOT_EVALUATED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNSUPPORTED = "UNSUPPORTED"
    UNVERIFIED = "UNVERIFIED"


class RevocationScope(StrEnum):
    KEY = "KEY"
    SIGNATURE = "SIGNATURE"
    SIGNER_KEY_BINDING = "SIGNER_KEY_BINDING"
    DELEGATION = "DELEGATION"
    TRUST_ROOT = "TRUST_ROOT"
    SIGNED_OBJECT = "SIGNED_OBJECT"


class RevocationReason(StrEnum):
    KEY_COMPROMISE = "KEY_COMPROMISE"
    KEY_RETIRED = "KEY_RETIRED"
    SUPERSEDED = "SUPERSEDED"
    WITHDRAWN = "WITHDRAWN"
    MISISSUED = "MISISSUED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    UNKNOWN_REASON = "UNKNOWN_REASON"


class ValidityWindow(TrustModel):
    not_before: str | None = Field(default=None, pattern=UTC_TIMESTAMP_PATTERN)
    not_after: str | None = Field(default=None, pattern=UTC_TIMESTAMP_PATTERN)

    @model_validator(mode="after")
    def valid_interval(self) -> ValidityWindow:
        _validate_utc_timestamp(self.not_before)
        _validate_utc_timestamp(self.not_after)
        if self.not_before and self.not_after and self.not_before > self.not_after:
            raise ValueError("validity interval is inverted")
        return self


class KeyIdentity(TrustModel):
    schema_id: Literal["omiv.key-identity.v1"] = Field(
        default="omiv.key-identity.v1", alias="schema"
    )
    key_id: str = Field(pattern=r"^key_[0-9a-f]{32}$")
    algorithm: SignatureAlgorithm
    public_key_encoding: Literal["RAW_HEX"] = "RAW_HEX"
    public_key: str = Field(pattern=HEX32_PATTERN)
    public_key_digest: str = Field(pattern=SHA256_PATTERN)
    allowed_key_usages: list[KeyUsage]
    allowed_object_types: list[SignedObjectType]
    allowed_purposes: list[SignaturePurpose]
    namespaces: list[str] = Field(default_factory=list)
    provider_artifact_scopes: list[str] = Field(default_factory=list)
    validity: ValidityWindow | None = None
    status: Literal["ACTIVE", "DISABLED"] = "ACTIVE"
    limitations: list[str]
    key_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> KeyIdentity:
        if self.algorithm != SignatureAlgorithm.ED25519:
            raise ValueError("only ED25519 key identities are supported in Phase 5D")
        raw = bytes.fromhex(self.public_key)
        identity = {
            "schema": self.schema_id,
            "algorithm": self.algorithm.value,
            "public_key_encoding": self.public_key_encoding,
            "public_key": self.public_key,
        }
        if self.public_key_digest != canonical_sha256(identity):
            raise ValueError("public-key digest mismatch")
        if self.key_id != "key_" + self.public_key_digest[:32]:
            raise ValueError("key identity mismatch")
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must contain 32 bytes")
        body = self.model_dump(mode="json", by_alias=True)
        stored = body.pop("key_digest")
        if stored != canonical_sha256(body):
            raise ValueError("key record digest mismatch")
        for name in (
            "allowed_key_usages",
            "allowed_object_types",
            "allowed_purposes",
            "namespaces",
            "provider_artifact_scopes",
            "limitations",
        ):
            values = getattr(self, name)
            if values != sorted(set(values), key=str):
                raise ValueError(f"{name} must be unique and sorted")
        if any(purpose not in ACTIVE_PURPOSES for purpose in self.allowed_purposes):
            raise ValueError("reserved signature purposes cannot be activated")
        return self


class SignerIdentity(TrustModel):
    schema_id: Literal["omiv.signer-identity.v1"] = Field(
        default="omiv.signer-identity.v1", alias="schema"
    )
    signer_identity_id: str = Field(pattern=r"^signer_[0-9a-f]{32}$")
    identity_kind: SignerIdentityKind
    display_label: str
    organization_id: str | None = None
    role: str | None = None
    namespace: str | None = None
    identity_evidence: list[str] = Field(default_factory=list)
    verification_status: Literal["DECLARED", "EVIDENCE_LINKED", "UNAVAILABLE"]
    limitations: list[str]
    identity_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SignerIdentity:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("identity_digest")
        identity_id = body.pop("signer_identity_id")
        expected = canonical_sha256(body)
        if identity_id != "signer_" + expected[:32]:
            raise ValueError("signer identity mismatch")
        body["signer_identity_id"] = identity_id
        if digest != canonical_sha256(body):
            raise ValueError("signer identity digest mismatch")
        return self


class SignerKeyBinding(TrustModel):
    schema_id: Literal["omiv.signer-key-binding.v1"] = Field(
        default="omiv.signer-key-binding.v1", alias="schema"
    )
    binding_id: str = Field(pattern=r"^binding_[0-9a-f]{32}$")
    signer_identity_id: str
    key_id: str
    binding_origin: BindingOrigin
    evidence_references: list[str] = Field(default_factory=list)
    allowed_roles: list[str] = Field(default_factory=list)
    allowed_usages: list[KeyUsage]
    namespaces: list[str] = Field(default_factory=list)
    allowed_object_types: list[SignedObjectType]
    validity: ValidityWindow | None = None
    verification_status: BindingStatus
    limitations: list[str]
    binding_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SignerKeyBinding:
        if self.binding_origin in {BindingOrigin.CERTIFICATE_RESERVED, BindingOrigin.OIDC_RESERVED}:
            raise ValueError("reserved binding origins are unsupported")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("binding_digest")
        binding_id = body.pop("binding_id")
        expected = canonical_sha256(body)
        if binding_id != "binding_" + expected[:32]:
            raise ValueError("binding identity mismatch")
        body["binding_id"] = binding_id
        if digest != canonical_sha256(body):
            raise ValueError("binding digest mismatch")
        return self


class SignaturePayloadDescriptor(TrustModel):
    schema_id: Literal["omiv.signature-payload.v1"] = Field(
        default="omiv.signature-payload.v1", alias="schema"
    )
    domain: Literal["OMIV-SIGNED-OBJECT-V1"] = "OMIV-SIGNED-OBJECT-V1"
    canonicalization_version: Literal["omiv-json-v1"] = "omiv-json-v1"
    signed_object_schema: str
    signed_object_type: SignedObjectType
    signed_object_id: str
    signed_object_digest: str = Field(pattern=SHA256_PATTERN)
    digest_algorithm: Literal["SHA-256"] = "SHA-256"
    signature_purpose: SignaturePurpose
    trust_policy_id: str | None = None
    namespace: str | None = None
    provider_artifact_scope: str | None = None
    key_usage: KeyUsage = KeyUsage.SIGN_OMIV_OBJECT

    @model_validator(mode="after")
    def active_purpose(self) -> SignaturePayloadDescriptor:
        if self.signature_purpose not in ACTIVE_PURPOSES:
            raise ValueError("reserved signature purpose is unsupported")
        return self


class SignatureRecord(TrustModel):
    schema_id: Literal["omiv.signature-record.v1"] = Field(
        default="omiv.signature-record.v1", alias="schema"
    )
    signature_id: str = Field(pattern=r"^sig_[0-9a-f]{32}$")
    algorithm: SignatureAlgorithm
    key_id: str
    purpose: SignaturePurpose
    payload: SignaturePayloadDescriptor
    detached_signature: str = Field(pattern=HEX64_PATTERN)
    signature_encoding: Literal["RAW_HEX"] = "RAW_HEX"
    binding_id: str | None = None
    trust_policy_id: str | None = None
    limitations: list[str]
    signature_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SignatureRecord:
        if self.algorithm != SignatureAlgorithm.ED25519:
            raise ValueError("only ED25519 signatures are supported")
        if self.purpose != self.payload.signature_purpose:
            raise ValueError("signature purpose does not match payload")
        if self.trust_policy_id != self.payload.trust_policy_id:
            raise ValueError("signature trust policy does not match payload")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("signature_digest")
        signature_id = body.pop("signature_id")
        expected = canonical_sha256(body)
        if signature_id != "sig_" + expected[:32]:
            raise ValueError("signature identity mismatch")
        body["signature_id"] = signature_id
        if digest != canonical_sha256(body):
            raise ValueError("signature digest mismatch")
        return self


class SignedObjectEnvelope(TrustModel):
    schema_id: Literal["omiv.signed-object-envelope.v1"] = Field(
        default="omiv.signed-object-envelope.v1", alias="schema"
    )
    envelope_id: str = Field(pattern=r"^soe_[0-9a-f]{32}$")
    signed_object_schema: str
    signed_object_type: SignedObjectType
    signed_object_id: str
    signed_object_digest: str = Field(pattern=SHA256_PATTERN)
    signed_object: dict[str, JsonValue]
    signatures: list[SignatureRecord] = Field(min_length=1)
    key_records: list[KeyIdentity] = Field(default_factory=list)
    trust_policy_id: str | None = None
    limitations: list[str]
    envelope_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SignedObjectEnvelope:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("envelope_digest")
        envelope_id = body.pop("envelope_id")
        expected = canonical_sha256(body)
        if envelope_id != "soe_" + expected[:32]:
            raise ValueError("signed envelope identity mismatch")
        body["envelope_id"] = envelope_id
        if digest != canonical_sha256(body):
            raise ValueError("signed envelope digest mismatch")
        ids = [item.signature_id for item in self.signatures]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("signatures must be unique and sorted")
        pairs = [(item.key_id, item.purpose) for item in self.signatures]
        if len(pairs) != len(set(pairs)):
            raise ValueError("duplicate key and purpose signature")
        if any(item.trust_policy_id != self.trust_policy_id for item in self.signatures):
            raise ValueError("signature trust policies do not match envelope")
        return self


class TrustRoot(TrustModel):
    schema_id: Literal["omiv.trust-root.v1"] = Field(default="omiv.trust-root.v1", alias="schema")
    trust_root_id: str = Field(pattern=r"^root_[0-9a-f]{32}$")
    key_id: str
    allowed_purposes: list[SignaturePurpose]
    allowed_object_types: list[SignedObjectType]
    namespaces: list[str] = Field(default_factory=list)
    provider_artifact_scopes: list[str] = Field(default_factory=list)
    delegation_allowed: bool
    maximum_delegation_depth: int = Field(ge=0, le=8)
    validity: ValidityWindow | None = None
    status: Literal["ACTIVE", "DISABLED"] = "ACTIVE"
    limitations: list[str]
    root_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> TrustRoot:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("root_digest")
        root_id = body.pop("trust_root_id")
        expected = canonical_sha256(body)
        if root_id != "root_" + expected[:32]:
            raise ValueError("trust-root identity mismatch")
        body["trust_root_id"] = root_id
        if digest != canonical_sha256(body):
            raise ValueError("trust-root digest mismatch")
        return self


class DelegationRecord(TrustModel):
    schema_id: Literal["omiv.delegation-record.v1"] = Field(
        default="omiv.delegation-record.v1", alias="schema"
    )
    delegation_id: str = Field(pattern=r"^delegation_[0-9a-f]{32}$")
    delegator_key_id: str
    delegate_key_id: str
    allowed_purposes: list[SignaturePurpose]
    allowed_object_types: list[SignedObjectType]
    namespaces: list[str] = Field(default_factory=list)
    provider_artifact_scopes: list[str] = Field(default_factory=list)
    maximum_subordinate_depth: int = Field(ge=0, le=8)
    validity: ValidityWindow | None = None
    authorization_algorithm: Literal[SignatureAlgorithm.ED25519] = SignatureAlgorithm.ED25519
    authorization_signature: str = Field(pattern=HEX64_PATTERN)
    status: Literal["ACTIVE", "DISABLED"] = "ACTIVE"
    limitations: list[str]
    delegation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> DelegationRecord:
        if self.delegator_key_id == self.delegate_key_id:
            raise ValueError("self-delegation is forbidden")
        for name in (
            "allowed_purposes",
            "allowed_object_types",
            "namespaces",
            "provider_artifact_scopes",
            "limitations",
        ):
            values = getattr(self, name)
            if values != sorted(set(values), key=str):
                raise ValueError(f"{name} must be unique and sorted")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("delegation_digest")
        delegation_id = body.pop("delegation_id")
        expected = canonical_sha256(body)
        if delegation_id != "delegation_" + expected[:32]:
            raise ValueError("delegation identity mismatch")
        body["delegation_id"] = delegation_id
        if digest != canonical_sha256(body):
            raise ValueError("delegation digest mismatch")
        return self


class RevocationRecord(TrustModel):
    schema_id: Literal["omiv.revocation-record.v1"] = Field(
        default="omiv.revocation-record.v1", alias="schema"
    )
    revocation_id: str = Field(pattern=r"^revocation_[0-9a-f]{32}$")
    scope: RevocationScope
    target_id: str
    reason: RevocationReason
    effective_at: str | None = Field(default=None, pattern=UTC_TIMESTAMP_PATTERN)
    authoritative_basis: Literal["LOCAL_POLICY", "TRUST_ROOT_SIGNATURE"]
    replacement_reference: str | None = None
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str]
    revocation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> RevocationRecord:
        _validate_utc_timestamp(self.effective_at)
        if self.authoritative_basis == "TRUST_ROOT_SIGNATURE":
            raise ValueError("root-authorized revocation is reserved and unsupported")
        if self.reason == RevocationReason.SUPERSEDED and not self.replacement_reference:
            raise ValueError("SUPERSEDED revocation requires a replacement reference")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("revocation_digest")
        record_id = body.pop("revocation_id")
        expected = canonical_sha256(body)
        if record_id != "revocation_" + expected[:32]:
            raise ValueError("revocation identity mismatch")
        body["revocation_id"] = record_id
        if digest != canonical_sha256(body):
            raise ValueError("revocation digest mismatch")
        return self


class TrustBundle(TrustModel):
    schema_id: Literal["omiv.trust-bundle.v1"] = Field(
        default="omiv.trust-bundle.v1", alias="schema"
    )
    bundle_id: str = Field(pattern=r"^tb_[0-9a-f]{32}$")
    trust_roots: list[TrustRoot]
    keys: list[KeyIdentity]
    signer_identities: list[SignerIdentity] = Field(default_factory=list)
    signer_key_bindings: list[SignerKeyBinding] = Field(default_factory=list)
    delegations: list[DelegationRecord] = Field(default_factory=list)
    revocations: list[RevocationRecord] = Field(default_factory=list)
    validity: ValidityWindow | None = None
    limitations: list[str]
    bundle_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> TrustBundle:
        groups = (
            (self.trust_roots, "trust_root_id"),
            (self.keys, "key_id"),
            (self.signer_identities, "signer_identity_id"),
            (self.signer_key_bindings, "binding_id"),
            (self.delegations, "delegation_id"),
            (self.revocations, "revocation_id"),
        )
        for records, field in groups:
            ids = [str(getattr(item, field)) for item in records]
            if ids != sorted(ids) or len(ids) != len(set(ids)):
                raise ValueError(f"{field} records must be unique and sorted")
        delegation_pairs = [
            (item.delegator_key_id, item.delegate_key_id) for item in self.delegations
        ]
        if len(delegation_pairs) != len(set(delegation_pairs)):
            raise ValueError("duplicate delegator/delegate pair")
        key_ids = {item.key_id for item in self.keys}
        if any(root.key_id not in key_ids for root in self.trust_roots):
            raise ValueError("trust root references an unknown key")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("bundle_digest")
        bundle_id = body.pop("bundle_id")
        expected = canonical_sha256(body)
        if bundle_id != "tb_" + expected[:32]:
            raise ValueError("trust-bundle identity mismatch")
        body["bundle_id"] = bundle_id
        if digest != canonical_sha256(body):
            raise ValueError("trust-bundle digest mismatch")
        return self


class TrustPolicy(TrustModel):
    schema_id: Literal["omiv.trust-policy.v1"] = Field(
        default="omiv.trust-policy.v1", alias="schema"
    )
    policy_id: str
    profile: Literal[
        "personal_local_trust",
        "project_maintainer_release",
        "team_release",
        "enterprise_offline_release",
        "regulated_multi_party_release",
    ]
    supported_algorithms: list[Literal[SignatureAlgorithm.ED25519]]
    allowed_object_types: list[SignedObjectType]
    allowed_signature_purposes: list[SignaturePurpose]
    required_key_usage: KeyUsage
    namespaces: list[str] = Field(default_factory=list)
    provider_artifact_scopes: list[str] = Field(default_factory=list)
    minimum_binding_status: BindingStatus | None = None
    allow_delegation: bool
    maximum_delegation_depth: int = Field(ge=0, le=8)
    require_revocation_evaluation: bool
    accept_local_declarative_revocation: bool
    require_expiration_evaluation: bool
    minimum_signature_count: int = Field(ge=1, le=8)
    unknown_key_behavior: Literal["PARTIAL", "UNTRUSTED", "REJECT"]
    unknown_identity_behavior: Literal["PARTIAL", "UNTRUSTED", "ALLOW"]
    digest_only_behavior: Literal["PARTIAL", "REJECT"]
    claim_strength_preservation: Literal[True] = True
    forbidden_trust_escalations: list[str]
    limitations: list[str]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> TrustPolicy:
        if any(purpose not in ACTIVE_PURPOSES for purpose in self.allowed_signature_purposes):
            raise ValueError("reserved purposes cannot be enabled by a Phase 5D policy")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("policy_digest")
        if digest != canonical_sha256(body):
            raise ValueError("trust-policy digest mismatch")
        return self


class EvaluationContext(TrustModel):
    schema_id: Literal["omiv.evaluation-context.v1"] = Field(
        default="omiv.evaluation-context.v1", alias="schema"
    )
    evaluation_context_id: str = Field(pattern=r"^eval_[0-9a-f]{32}$")
    evaluation_time: str | None = Field(default=None, pattern=UTC_TIMESTAMP_PATTERN)
    purpose: Literal["CURRENT", "HISTORICAL"]
    policy_id: str
    limitations: list[str]
    context_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> EvaluationContext:
        _validate_utc_timestamp(self.evaluation_time)
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("context_digest")
        context_id = body.pop("evaluation_context_id")
        expected = canonical_sha256(body)
        if context_id != "eval_" + expected[:32]:
            raise ValueError("evaluation-context identity mismatch")
        body["evaluation_context_id"] = context_id
        if digest != canonical_sha256(body):
            raise ValueError("evaluation-context digest mismatch")
        return self


class TrustFinding(TrustModel):
    finding_id: str = Field(pattern=r"^TRUST-[0-9]{3}$")
    status: Literal["PASS", "FAIL", "WARN", "INFO"]
    summary: str
    limitation: str | None = None


class RevocationEvaluationResult(TrustModel):
    revocation_id: str
    revocation_digest: str = Field(pattern=SHA256_PATTERN)
    record_validity: Literal["VALID"] = "VALID"
    authority: RevocationAuthority
    scope: RevocationScope
    target_id: str
    effective_status: RevocationStatus
    reason: RevocationReason
    replacement_reference: str | None = None


class SignatureVerificationResult(TrustModel):
    signature_id: str
    signature_integrity: SignatureIntegrity
    key_id: str
    key_status: KeyStatus
    signer_identity_id: str | None = None
    signer_identity_status: SignerIdentityStatus
    signer_identity_verification: SignerIdentityVerification
    signer_binding: SignerBindingResult
    signer_binding_status: BindingStatus | None = None
    trust_root_id: str | None = None
    delegation_status: DelegationStatus
    delegation_path: list[str]
    revocation_status: RevocationStatus
    revocation_records: list[RevocationEvaluationResult]
    expiration_status: ExpirationStatus
    trust_policy_status: TrustPolicyStatus
    limitations: list[str]


class SignatureReport(TrustModel):
    schema_id: Literal["omiv.signature-report.v1"] = Field(
        default="omiv.signature-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^trust_report_[0-9a-f]{32}$")
    envelope_id: str
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    signed_object_schema: str
    signed_object_type: SignedObjectType
    signed_object_id: str
    signed_object_digest: str = Field(pattern=SHA256_PATTERN)
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    trust_bundle_id: str
    trust_bundle_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context_id: str | None
    signature_results: list[SignatureVerificationResult]
    accepted_signature_count: int = Field(ge=0)
    underlying_claim: dict[str, JsonValue]
    content_independently_proven: Literal[False] = False
    payload_status: str
    numerical_fidelity_status: str
    security_status: str
    runtime_status: str
    approval_status: Literal["NOT_AVAILABLE"] = "NOT_AVAILABLE"
    lifecycle_completeness: str
    overall_status: OverallSignedObjectStatus
    findings: list[TrustFinding]
    missing_evidence: list[str]
    limitations: list[str]
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SignatureReport:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("report_digest")
        report_id = body.pop("report_id")
        expected = canonical_sha256(body)
        if report_id != "trust_report_" + expected[:32]:
            raise ValueError("signature report identity mismatch")
        body["report_id"] = report_id
        if digest != canonical_sha256(body):
            raise ValueError("signature report digest mismatch")
        return self


JsonObject = dict[str, Any]
