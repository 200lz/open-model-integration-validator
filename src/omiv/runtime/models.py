"""Strict canonical Phase 5G deployment and runtime snapshot-evidence models."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.models import StrictModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
MAX_TEXT = 512


def _unsafe(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        forbidden = (
            "authorization:",
            "bearer ",
            "github_pat_",
            "ghp_",
            "x-amz-",
            "signature=",
            "key-pair-id=",
            "access_token=",
            "api_key=",
            "password=",
            "begin private key",
            "begin openssh private key",
            "kubeconfig",
        )
        return (
            value.startswith(("/", "~/", "git@"))
            or "\\" in value
            or "${" in value
            or bool(UUID_PATTERN.fullmatch(value))
            or bool(TIMESTAMP_PATTERN.match(value))
            or any(item in lowered for item in forbidden)
            or (value.startswith(("http://", "https://", "ssh://")) and "?" in value)
        )
    if isinstance(value, list):
        return any(_unsafe(item) for item in value)
    if isinstance(value, dict):
        forbidden_fields = {
            "secret",
            "secret_value",
            "credentials",
            "environment_variables",
            "raw_command",
            "process_id",
            "container_id",
            "hostname",
            "username",
        }
        return bool(forbidden_fields.intersection(value)) or any(_unsafe(v) for v in value.values())
    return False


def _unbounded(value: object) -> bool:
    if isinstance(value, str):
        return len(value) > MAX_TEXT
    if isinstance(value, list):
        return len(value) > 256 or any(_unbounded(item) for item in value)
    if isinstance(value, dict):
        return len(value) > 256 or any(_unbounded(item) for item in value.values())
    return False


def _check_identity(model: StrictModel, id_field: str, prefix: str, digest_field: str) -> None:
    data = model.model_dump(mode="json", by_alias=True)
    digest = data.pop(digest_field)
    if digest != canonical_sha256(data):
        raise ValueError(f"{digest_field} mismatch")
    object_id = data.pop(id_field)
    if object_id != prefix + canonical_sha256(data)[:32]:
        raise ValueError(f"{id_field} mismatch")


class RuntimeModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def portable(self) -> RuntimeModel:
        value = self.model_dump(mode="json", by_alias=True)
        if _unsafe(value):
            raise ValueError(
                "runtime record contains a local identity, path, credential, or secret"
            )
        if _unbounded(value):
            raise ValueError("runtime record contains an unbounded value")
        return self


class ProductSubjectClass(StrEnum):
    MODEL_WEIGHTS = "MODEL_WEIGHTS"
    TOKENIZER = "TOKENIZER"
    MODEL_CONFIG = "MODEL_CONFIG"
    ADAPTER = "ADAPTER"
    LORA_ADAPTER = "LORA_ADAPTER"
    PROMPT_TEMPLATE = "PROMPT_TEMPLATE"
    CHAT_TEMPLATE = "CHAT_TEMPLATE"
    RUNTIME_ENGINE = "RUNTIME_ENGINE"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    DEPLOYMENT_PACKAGE = "DEPLOYMENT_PACKAGE"
    TOOL_PACKAGE = "TOOL_PACKAGE"
    AGENT_PACKAGE = "AGENT_PACKAGE"
    EVALUATION_DATASET = "EVALUATION_DATASET"
    POLICY_BUNDLE = "POLICY_BUNDLE"
    SECURITY_EVIDENCE_BUNDLE = "SECURITY_EVIDENCE_BUNDLE"
    OTHER_DECLARED = "OTHER_DECLARED"


class ArtifactMemberRole(StrEnum):
    PRIMARY = "PRIMARY"
    MANDATORY_COMPANION = "MANDATORY_COMPANION"
    OPTIONAL_COMPANION = "OPTIONAL_COMPANION"
    RUNTIME_ENGINE = "RUNTIME_ENGINE"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    STARTUP_CONFIGURATION = "STARTUP_CONFIGURATION"
    EXTERNAL_DEPENDENCY = "EXTERNAL_DEPENDENCY"
    RUNTIME_GENERATED = "RUNTIME_GENERATED"


class EvidenceStrength(StrEnum):
    DECLARED = "DECLARED"
    IMPORTED_UNVERIFIED = "IMPORTED_UNVERIFIED"
    STRUCTURALLY_VERIFIED = "STRUCTURALLY_VERIFIED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    SIGNED = "SIGNED"
    SIGNED_AND_TRUSTED = "SIGNED_AND_TRUSTED"
    INDEPENDENTLY_CORROBORATED = "INDEPENDENTLY_CORROBORATED"


class EvidenceAcquisitionOrigin(StrEnum):
    DECLARED = "DECLARED"
    IMPORTED = "IMPORTED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"


class AssertionAuthorityStatus(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    PARTIALLY_AUTHORIZED = "PARTIALLY_AUTHORIZED"
    UNAUTHORIZED = "UNAUTHORIZED"
    NOT_EVALUATED = "NOT_EVALUATED"


class DeploymentTargetType(StrEnum):
    LOCAL_PROCESS = "LOCAL_PROCESS"
    LOCAL_CONTAINER = "LOCAL_CONTAINER"
    LOCAL_MODEL_SERVER = "LOCAL_MODEL_SERVER"
    TEAM_INFERENCE_SERVICE = "TEAM_INFERENCE_SERVICE"
    INTERNAL_CLUSTER = "INTERNAL_CLUSTER"
    KUBERNETES_WORKLOAD = "KUBERNETES_WORKLOAD"
    OCI_RUNTIME = "OCI_RUNTIME"
    CLOUD_MANAGED_ENDPOINT = "CLOUD_MANAGED_ENDPOINT"
    EDGE_DEVICE = "EDGE_DEVICE"
    AIR_GAPPED_APPLIANCE = "AIR_GAPPED_APPLIANCE"
    BATCH_INFERENCE_JOB = "BATCH_INFERENCE_JOB"
    SERVERLESS_INFERENCE = "SERVERLESS_INFERENCE"
    DESKTOP_RUNTIME = "DESKTOP_RUNTIME"
    MOBILE_RUNTIME_RESERVED = "MOBILE_RUNTIME_RESERVED"
    OTHER_DECLARED = "OTHER_DECLARED"


class RuntimeEngineFamily(StrEnum):
    LLAMA_CPP = "LLAMA_CPP"
    VLLM = "VLLM"
    TENSORRT_LLM = "TENSORRT_LLM"
    TRITON = "TRITON"
    MLX = "MLX"
    OLLAMA = "OLLAMA"
    LM_STUDIO = "LM_STUDIO"
    ONNX_RUNTIME = "ONNX_RUNTIME"
    TGI = "TGI"
    CUSTOM_INFERENCE_SERVER = "CUSTOM_INFERENCE_SERVER"
    DESKTOP_RUNTIME = "DESKTOP_RUNTIME"
    EDGE_RUNTIME = "EDGE_RUNTIME"
    UNKNOWN = "UNKNOWN"


class DeploymentStatus(StrEnum):
    REQUESTED = "REQUESTED"
    STARTED = "STARTED"
    COMPLETED_DECLARED = "COMPLETED_DECLARED"
    COMPLETED_OBSERVED = "COMPLETED_OBSERVED"
    COMPLETED_WITH_LIMITATIONS = "COMPLETED_WITH_LIMITATIONS"
    FAILED = "FAILED"
    ROLLED_BACK_DECLARED = "ROLLED_BACK_DECLARED"
    ROLLED_BACK_OBSERVED = "ROLLED_BACK_OBSERVED"
    UNKNOWN = "UNKNOWN"
    NOT_OBSERVED = "NOT_OBSERVED"


class ObserverCapability(StrEnum):
    ARTIFACT_IDENTITY_OBSERVATION = "ARTIFACT_IDENTITY_OBSERVATION"
    ARTIFACT_SET_OBSERVATION = "ARTIFACT_SET_OBSERVATION"
    CONFIGURATION_IDENTITY_OBSERVATION = "CONFIGURATION_IDENTITY_OBSERVATION"
    ENGINE_IDENTITY_OBSERVATION = "ENGINE_IDENTITY_OBSERVATION"
    ENGINE_BINARY_OBSERVATION = "ENGINE_BINARY_OBSERVATION"
    ENVIRONMENT_IDENTITY_OBSERVATION = "ENVIRONMENT_IDENTITY_OBSERVATION"
    CONTAINER_IMAGE_OBSERVATION = "CONTAINER_IMAGE_OBSERVATION"
    REGISTRY_REFERENCE_OBSERVATION = "REGISTRY_REFERENCE_OBSERVATION"
    STARTUP_MANIFEST_OBSERVATION = "STARTUP_MANIFEST_OBSERVATION"
    ENDPOINT_LOGICAL_IDENTITY_OBSERVATION = "ENDPOINT_LOGICAL_IDENTITY_OBSERVATION"
    PROCESS_LOGICAL_IDENTITY_OBSERVATION = "PROCESS_LOGICAL_IDENTITY_OBSERVATION"
    RUNTIME_HEALTH_OBSERVATION = "RUNTIME_HEALTH_OBSERVATION"
    BEHAVIORAL_OBSERVATION_RESERVED = "BEHAVIORAL_OBSERVATION_RESERVED"


class ObservationDimension(StrEnum):
    PRIMARY_ARTIFACT_DIGEST = "PRIMARY_ARTIFACT_DIGEST"
    COMPANION_ARTIFACT_DIGESTS = "COMPANION_ARTIFACT_DIGESTS"
    ARTIFACT_SET_DIGEST = "ARTIFACT_SET_DIGEST"
    TOKENIZER_DIGEST = "TOKENIZER_DIGEST"
    MODEL_CONFIG_DIGEST = "MODEL_CONFIG_DIGEST"
    CHAT_TEMPLATE_DIGEST = "CHAT_TEMPLATE_DIGEST"
    ADAPTER_DIGEST = "ADAPTER_DIGEST"
    CONTAINER_IMAGE_DIGEST = "CONTAINER_IMAGE_DIGEST"
    ENGINE_BINARY_DIGEST = "ENGINE_BINARY_DIGEST"
    ENGINE_VERSION_REVISION = "ENGINE_VERSION_REVISION"
    RUNTIME_CONFIG_DIGEST = "RUNTIME_CONFIG_DIGEST"
    ENVIRONMENT_IDENTITY = "ENVIRONMENT_IDENTITY"
    TARGET_IDENTITY = "TARGET_IDENTITY"


class ObservationCoverageStatus(StrEnum):
    COMPLETE_FOR_REQUIRED_DIMENSIONS = "COMPLETE_FOR_REQUIRED_DIMENSIONS"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"
    INACCESSIBLE = "INACCESSIBLE"
    FAILED = "FAILED"
    NOT_ASSESSED = "NOT_ASSESSED"


class ObservationStatus(StrEnum):
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_LIMITATIONS = "COMPLETED_WITH_LIMITATIONS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNSUPPORTED = "UNSUPPORTED"
    INACCESSIBLE = "INACCESSIBLE"


class IdentityObservationMethod(StrEnum):
    DIRECT_BYTE_IDENTITY = "DIRECT_BYTE_IDENTITY"
    DIRECT_ARTIFACT_SET_IDENTITY = "DIRECT_ARTIFACT_SET_IDENTITY"
    MANIFEST_IDENTITY = "MANIFEST_IDENTITY"
    REGISTRY_REFERENCE_IDENTITY = "REGISTRY_REFERENCE_IDENTITY"
    CONTAINER_IMAGE_PROXY = "CONTAINER_IMAGE_PROXY"
    CONFIGURATION_PROXY = "CONFIGURATION_PROXY"
    DECLARED_IDENTITY = "DECLARED_IDENTITY"
    UNOBSERVED = "UNOBSERVED"


class ContinuityLevel(StrEnum):
    FULL_CONTINUITY = "FULL_CONTINUITY"
    PARTIAL_CONTINUITY = "PARTIAL_CONTINUITY"
    IDENTITY_PROXY_MATCH = "IDENTITY_PROXY_MATCH"
    UNOBSERVED = "UNOBSERVED"
    MISMATCH = "MISMATCH"
    BROKEN = "BROKEN"


class RuntimeFreshness(StrEnum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class ContinuityVerdict(StrEnum):
    PASS = "PASS"
    PASS_WITH_LIMITATIONS = "PASS_WITH_LIMITATIONS"
    PARTIAL_CONTINUITY = "PARTIAL_CONTINUITY"
    IDENTITY_PROXY_MATCH = "IDENTITY_PROXY_MATCH"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    MISMATCH = "MISMATCH"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    STALE = "STALE"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_EVALUATED = "NOT_EVALUATED"
    EVIDENCE_BROKEN = "EVIDENCE_BROKEN"
    OBSERVER_UNTRUSTED = "OBSERVER_UNTRUSTED"
    OBSERVER_UNAUTHORIZED = "OBSERVER_UNAUTHORIZED"
    DEPLOYMENT_UNVERIFIED = "DEPLOYMENT_UNVERIFIED"
    COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"


class DriftCategory(StrEnum):
    PRIMARY_ARTIFACT_DIGEST_DRIFT = "PRIMARY_ARTIFACT_DIGEST_DRIFT"
    COMPANION_ARTIFACT_DRIFT = "COMPANION_ARTIFACT_DRIFT"
    ARTIFACT_SET_DRIFT = "ARTIFACT_SET_DRIFT"
    REVISION_DRIFT = "REVISION_DRIFT"
    VARIANT_DRIFT = "VARIANT_DRIFT"
    TOKENIZER_CONFIG_DRIFT = "TOKENIZER_CONFIG_DRIFT"
    MODEL_CONFIG_DRIFT = "MODEL_CONFIG_DRIFT"
    CHAT_TEMPLATE_DRIFT = "CHAT_TEMPLATE_DRIFT"
    ADAPTER_DRIFT = "ADAPTER_DRIFT"
    RUNTIME_CONFIGURATION_DRIFT = "RUNTIME_CONFIGURATION_DRIFT"
    RUNTIME_ENGINE_DRIFT = "RUNTIME_ENGINE_DRIFT"
    ENGINE_BINARY_DRIFT = "ENGINE_BINARY_DRIFT"
    CONTAINER_IMAGE_DRIFT = "CONTAINER_IMAGE_DRIFT"
    ENVIRONMENT_DRIFT = "ENVIRONMENT_DRIFT"
    TARGET_DRIFT = "TARGET_DRIFT"
    TENANT_SCOPE_DRIFT = "TENANT_SCOPE_DRIFT"
    TRUST_DOMAIN_DRIFT = "TRUST_DOMAIN_DRIFT"
    SECURITY_EVIDENCE_STALE = "SECURITY_EVIDENCE_STALE"
    GOVERNANCE_DECISION_STALE = "GOVERNANCE_DECISION_STALE"
    SIGNATURE_TRUST_DRIFT = "SIGNATURE_TRUST_DRIFT"
    OBSERVER_IDENTITY_DRIFT = "OBSERVER_IDENTITY_DRIFT"
    OBSERVER_AUTHORITY_DRIFT = "OBSERVER_AUTHORITY_DRIFT"
    REPLAYED_OBSERVATION = "REPLAYED_OBSERVATION"
    OBSERVATION_COVERAGE_GAP = "OBSERVATION_COVERAGE_GAP"
    UNKNOWN_RUNTIME_COMPONENT = "UNKNOWN_RUNTIME_COMPONENT"
    OTHER_RUNTIME_DRIFT = "OTHER_RUNTIME_DRIFT"


class ScopeContext(RuntimeModel):
    tenant_scope: str = Field(pattern=ID_PATTERN)
    organization_scope: str = Field(pattern=ID_PATTERN)
    project_scope: str = Field(pattern=ID_PATTERN)
    product_scope: str = Field(pattern=ID_PATTERN)
    trust_domain: str = Field(pattern=ID_PATTERN)
    environment_scope: str = Field(pattern=ID_PATTERN)
    target_scope: str = Field(pattern=ID_PATTERN)


class ProductSubject(RuntimeModel):
    schema_id: Literal["omiv.product-subject.v1"] = Field(
        default="omiv.product-subject.v1", alias="schema"
    )
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    subject_class: ProductSubjectClass
    logical_name: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    limitations: list[str]
    subject_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> ProductSubject:
        _check_identity(self, "subject_id", "product_subject_", "subject_digest")
        return self


class DeploymentArtifactMember(RuntimeModel):
    role: ArtifactMemberRole
    artifact_class: ProductSubjectClass
    logical_name: str = Field(pattern=ID_PATTERN)
    artifact: ArtifactReference
    required: bool
    expected_observation_method: IdentityObservationMethod
    continuity_required: bool
    generation_provenance_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    limitations: list[str]


class DeploymentArtifactSet(RuntimeModel):
    schema_id: Literal["omiv.deployment-artifact-set.v1"] = Field(
        default="omiv.deployment-artifact-set.v1", alias="schema"
    )
    artifact_set_id: str = Field(pattern=r"^deployment_artifact_set_[0-9a-f]{32}$")
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    scope: ScopeContext
    members: list[DeploymentArtifactMember] = Field(min_length=1, max_length=64)
    limitations: list[str]
    artifact_set_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> DeploymentArtifactSet:
        if sum(item.role == ArtifactMemberRole.PRIMARY for item in self.members) != 1:
            raise ValueError("deployment artifact set requires exactly one primary member")
        names = [item.logical_name for item in self.members]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("artifact-set members must be uniquely ordered")
        if any(
            item.role in {ArtifactMemberRole.PRIMARY, ArtifactMemberRole.MANDATORY_COMPANION}
            and (not item.required or not item.continuity_required)
            for item in self.members
        ):
            raise ValueError("primary and mandatory companion members require continuity")
        if any(
            item.role == ArtifactMemberRole.OPTIONAL_COMPANION and item.required
            for item in self.members
        ):
            raise ValueError("optional companion cannot be marked mandatory")
        if any(
            item.role == ArtifactMemberRole.RUNTIME_GENERATED
            and item.generation_provenance_digest is None
            for item in self.members
        ):
            raise ValueError("runtime-generated member requires parent provenance")
        _check_identity(self, "artifact_set_id", "deployment_artifact_set_", "artifact_set_digest")
        return self


class AssertionAuthorityScope(RuntimeModel):
    schema_id: Literal["omiv.assertion-authority-scope.v1"] = Field(
        default="omiv.assertion-authority-scope.v1", alias="schema"
    )
    authority_id: str = Field(pattern=r"^runtime_authority_[0-9a-f]{32}$")
    actor_id: str = Field(pattern=ID_PATTERN)
    object_types: list[str]
    assertion_types: list[str]
    artifact_classes: list[ProductSubjectClass]
    target_classes: list[DeploymentTargetType]
    scope: ScopeContext
    actions: list[str]
    valid_from_sequence: int = Field(ge=0)
    valid_through_sequence: int = Field(ge=0)
    delegated_by_authority_id: str | None = Field(
        default=None, pattern=r"^runtime_authority_[0-9a-f]{32}$"
    )
    maximum_delegation_depth: int = Field(ge=0, le=8)
    limitations: list[str]
    authority_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> AssertionAuthorityScope:
        if self.valid_through_sequence < self.valid_from_sequence:
            raise ValueError("authority validity interval is inverted")
        _check_identity(self, "authority_id", "runtime_authority_", "authority_digest")
        return self


class DeploymentTargetReference(RuntimeModel):
    target_id: str = Field(pattern=ID_PATTERN)
    target_type: DeploymentTargetType
    scope: ScopeContext
    namespace: str = Field(pattern=ID_PATTERN)
    region_classification: str = Field(pattern=ID_PATTERN)
    registry_class: str = Field(pattern=ID_PATTERN)
    runtime_policy_digest: str = Field(pattern=SHA256_PATTERN)
    observer_policy_digest: str = Field(pattern=SHA256_PATTERN)
    limitations: list[str]


class NormalizedConfigurationField(RuntimeModel):
    name: str = Field(pattern=ID_PATTERN)
    normalized_value: str
    source: Literal["EXPLICIT", "DEFAULT", "ALIAS_NORMALIZED"]


class SecretReference(RuntimeModel):
    logical_reference_id: str = Field(pattern=ID_PATTERN)
    provider_class: str = Field(pattern=ID_PATTERN)
    reference_digest: str = Field(pattern=SHA256_PATTERN)


class DeploymentConfigurationIdentity(RuntimeModel):
    schema_id: Literal["omiv.deployment-configuration-identity.v1"] = Field(
        default="omiv.deployment-configuration-identity.v1", alias="schema"
    )
    configuration_id: str = Field(pattern=r"^runtime_config_[0-9a-f]{32}$")
    normalized_fields: list[NormalizedConfigurationField]
    secret_references: list[SecretReference]
    normalization_policy_digest: str = Field(pattern=SHA256_PATTERN)
    unknown_fields: list[str]
    limitations: list[str]
    configuration_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> DeploymentConfigurationIdentity:
        names = [x.name for x in self.normalized_fields]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("configuration fields must be uniquely ordered")
        _check_identity(self, "configuration_id", "runtime_config_", "configuration_digest")
        return self


class RuntimeEngineIdentity(RuntimeModel):
    schema_id: Literal["omiv.runtime-engine-identity.v1"] = Field(
        default="omiv.runtime-engine-identity.v1", alias="schema"
    )
    engine_id: str = Field(pattern=r"^runtime_engine_[0-9a-f]{32}$")
    family: RuntimeEngineFamily
    name: str = Field(pattern=ID_PATTERN)
    display_version: str
    source_revision: str
    binary_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    container_image_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    build_configuration_digest: str = Field(pattern=SHA256_PATTERN)
    dependency_lock_digest: str = Field(pattern=SHA256_PATTERN)
    runtime_configuration_digest: str = Field(pattern=SHA256_PATTERN)
    runtime_configuration_schema: str = Field(pattern=ID_PATTERN)
    trust_references: list[str]
    limitations: list[str]
    engine_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RuntimeEngineIdentity:
        _check_identity(self, "engine_id", "runtime_engine_", "engine_digest")
        return self


class RuntimeEnvironmentIdentity(RuntimeModel):
    schema_id: Literal["omiv.runtime-environment-identity.v1"] = Field(
        default="omiv.runtime-environment-identity.v1", alias="schema"
    )
    environment_id: str = Field(pattern=r"^runtime_environment_[0-9a-f]{32}$")
    environment_class: str = Field(pattern=ID_PATTERN)
    operating_system_class: str = Field(pattern=ID_PATTERN)
    architecture: str = Field(pattern=ID_PATTERN)
    accelerator_class: str = Field(pattern=ID_PATTERN)
    container_vm_identity_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    dependency_lock_digest: str = Field(pattern=SHA256_PATTERN)
    runtime_policy_digest: str = Field(pattern=SHA256_PATTERN)
    network_policy_digest: str = Field(pattern=SHA256_PATTERN)
    filesystem_policy_digest: str = Field(pattern=SHA256_PATTERN)
    trust_domain: str = Field(pattern=ID_PATTERN)
    limitations: list[str]
    environment_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RuntimeEnvironmentIdentity:
        _check_identity(self, "environment_id", "runtime_environment_", "environment_digest")
        return self


class EvidenceAssertion(RuntimeModel):
    origin: EvidenceStrength
    acquisition_origin: EvidenceAcquisitionOrigin
    structurally_verified: bool
    directly_observed: bool
    signature_status: Literal["VALID", "INVALID", "NOT_PRESENT", "NOT_EVALUATED"]
    trust_status: Literal["TRUSTED_BY_POLICY", "UNTRUSTED_BY_POLICY", "NOT_EVALUATED"]
    authority_status: AssertionAuthorityStatus
    corroboration_status: Literal["INDEPENDENT", "SELF_CORROBORATED", "NOT_ESTABLISHED"]
    independently_corroborated: bool
    verification_mode: Literal["OFFLINE_NORMALIZED"] = "OFFLINE_NORMALIZED"
    limitations: list[str]

    @model_validator(mode="after")
    def preserve_dimensions(self) -> EvidenceAssertion:
        if self.signature_status == "VALID" and self.origin not in {
            EvidenceStrength.SIGNED,
            EvidenceStrength.SIGNED_AND_TRUSTED,
            EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        }:
            raise ValueError("valid signature conflicts with evidence origin")
        if self.trust_status == "TRUSTED_BY_POLICY" and self.signature_status != "VALID":
            raise ValueError("signature trust requires a valid signature")
        if self.independently_corroborated != (self.corroboration_status == "INDEPENDENT"):
            raise ValueError("corroboration dimensions conflict")
        return self


class DeploymentActorReference(RuntimeModel):
    actor_id: str = Field(pattern=ID_PATTERN)
    role: str = Field(pattern=ID_PATTERN)
    signer_identity_id: str | None = Field(default=None, pattern=ID_PATTERN)
    key_id: str | None = Field(default=None, pattern=ID_PATTERN)
    trust_root_id: str | None = Field(default=None, pattern=ID_PATTERN)
    authority_id: str = Field(pattern=r"^runtime_authority_[0-9a-f]{32}$")
    limitations: list[str]


class DeploymentIntent(RuntimeModel):
    schema_id: Literal["omiv.deployment-intent.v1"] = Field(
        default="omiv.deployment-intent.v1", alias="schema"
    )
    intent_id: str = Field(pattern=r"^deployment_intent_[0-9a-f]{32}$")
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    artifact_set_id: str = Field(pattern=r"^deployment_artifact_set_[0-9a-f]{32}$")
    artifact_set_digest: str = Field(pattern=SHA256_PATTERN)
    release_candidate_id: str = Field(pattern=ID_PATTERN)
    promotion_decision_id: str = Field(pattern=ID_PATTERN)
    promotion_decision_digest: str = Field(pattern=SHA256_PATTERN)
    promotion_outcome: Literal["PROMOTE"]
    promotion_authorization_status: Literal["VERIFIED"]
    governance_policy_id: str = Field(pattern=ID_PATTERN)
    governance_decision_digest: str = Field(pattern=SHA256_PATTERN)
    governance_decision_outcome: Literal["ALLOW", "ALLOW_WITH_LIMITATIONS"]
    approval_quorum_status: Literal["SATISFIED"]
    security_evaluation_id: str = Field(pattern=ID_PATTERN)
    security_evaluation_digest: str = Field(pattern=SHA256_PATTERN)
    security_verdict: Literal["PASS", "PASS_WITH_LIMITATIONS"]
    security_limitations: list[str]
    security_evaluation_freshness: Literal["CURRENT"]
    security_evaluation_trust_status: Literal["TRUSTED_BY_POLICY"]
    scope: ScopeContext
    target: DeploymentTargetReference
    expected_engine_id: str = Field(pattern=r"^runtime_engine_[0-9a-f]{32}$")
    expected_configuration_id: str = Field(pattern=r"^runtime_config_[0-9a-f]{32}$")
    requester: DeploymentActorReference
    authority: AssertionAuthorityScope
    evaluation_sequence: int = Field(ge=0)
    limitations: list[str]
    intent_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> DeploymentIntent:
        if self.scope != self.target.scope or self.scope != self.authority.scope:
            raise ValueError("deployment intent scope mismatch")
        _check_identity(self, "intent_id", "deployment_intent_", "intent_digest")
        return self


class DeploymentInstanceIdentity(RuntimeModel):
    schema_id: Literal["omiv.deployment-instance-identity.v1"] = Field(
        default="omiv.deployment-instance-identity.v1", alias="schema"
    )
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    intent_id: str = Field(pattern=r"^deployment_intent_[0-9a-f]{32}$")
    target_id: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    artifact_set_digest: str = Field(pattern=SHA256_PATTERN)
    configuration_digest: str = Field(pattern=SHA256_PATTERN)
    engine_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    generation: int = Field(ge=1)
    predecessor_instance_id: str | None = Field(
        default=None, pattern=r"^deployment_instance_[0-9a-f]{32}$"
    )
    instance_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> DeploymentInstanceIdentity:
        _check_identity(self, "instance_id", "deployment_instance_", "instance_digest")
        return self


class AdapterIdentity(RuntimeModel):
    schema_id: Literal["omiv.runtime-adapter-identity.v1"] = Field(
        default="omiv.runtime-adapter-identity.v1", alias="schema"
    )
    adapter_id: str = Field(pattern=r"^omiv\.adapter\.[a-z0-9-]+\.v1$")
    adapter_schema_version: str
    implementation_version: str
    source_revision: str
    implementation_digest: str = Field(pattern=SHA256_PATTERN)
    capabilities: list[str]
    supported_input_schemas: list[str]
    supported_output_schemas: list[str]
    supported_subject_classes: list[ProductSubjectClass]
    supported_target_classes: list[DeploymentTargetType]
    observation_strength_ceiling: EvidenceStrength
    accepted_evidence_origins: list[EvidenceStrength]
    normalization_policy_digest: str = Field(pattern=SHA256_PATTERN)
    scope: ScopeContext
    operational: bool
    limitations: list[str]
    adapter_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> AdapterIdentity:
        if len(self.accepted_evidence_origins) != len(set(self.accepted_evidence_origins)):
            raise ValueError("adapter evidence origins must be unique")
        data = self.model_dump(mode="json", by_alias=True)
        digest = data.pop("adapter_digest")
        if digest != canonical_sha256(data):
            raise ValueError("adapter digest mismatch")
        return self


class DeploymentManifest(RuntimeModel):
    schema_id: Literal["omiv.deployment-manifest.v1"] = Field(
        default="omiv.deployment-manifest.v1", alias="schema"
    )
    manifest_id: str = Field(pattern=r"^deployment_manifest_[0-9a-f]{32}$")
    intent_id: str = Field(pattern=r"^deployment_intent_[0-9a-f]{32}$")
    intent_digest: str = Field(pattern=SHA256_PATTERN)
    instance: DeploymentInstanceIdentity
    artifact_set: DeploymentArtifactSet
    passport_references: list[str]
    governance_decision_digest: str = Field(pattern=SHA256_PATTERN)
    security_evaluation_digest: str = Field(pattern=SHA256_PATTERN)
    security_verdict: Literal["PASS", "PASS_WITH_LIMITATIONS"]
    security_limitations: list[str]
    promotion_decision_digest: str = Field(pattern=SHA256_PATTERN)
    target: DeploymentTargetReference
    engine: RuntimeEngineIdentity
    configuration: DeploymentConfigurationIdentity
    expected_environment: RuntimeEnvironmentIdentity
    resource_profile_digest: str = Field(pattern=SHA256_PATTERN)
    startup_policy_digest: str = Field(pattern=SHA256_PATTERN)
    adapter: AdapterIdentity
    limitations: list[str]
    manifest_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> DeploymentManifest:
        if self.instance.intent_id != self.intent_id:
            raise ValueError("manifest deployment instance mismatch")
        if self.instance.artifact_set_digest != self.artifact_set.artifact_set_digest:
            raise ValueError("manifest artifact-set mismatch")
        if self.instance.configuration_digest != self.configuration.configuration_digest:
            raise ValueError("manifest configuration mismatch")
        if self.instance.engine_digest != self.engine.engine_digest:
            raise ValueError("manifest runtime engine mismatch")
        if self.instance.target_id != self.target.target_id:
            raise ValueError("manifest target mismatch")
        if self.target.scope != self.instance.scope:
            raise ValueError("manifest target scope mismatch")
        _check_identity(self, "manifest_id", "deployment_manifest_", "manifest_digest")
        return self


class DeploymentRecord(RuntimeModel):
    schema_id: Literal["omiv.deployment-record.v1"] = Field(
        default="omiv.deployment-record.v1", alias="schema"
    )
    record_id: str = Field(pattern=r"^deployment_record_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    manifest_id: str = Field(pattern=r"^deployment_manifest_[0-9a-f]{32}$")
    manifest_digest: str = Field(pattern=SHA256_PATTERN)
    target: DeploymentTargetReference
    deployed_artifact_set: DeploymentArtifactSet
    configuration: DeploymentConfigurationIdentity
    engine: RuntimeEngineIdentity
    actor: DeploymentActorReference
    actor_authority: AssertionAuthorityScope
    execution_reference_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    assertion: EvidenceAssertion
    status: DeploymentStatus
    evidence_references: list[str]
    limitations: list[str]
    record_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> DeploymentRecord:
        if self.actor.authority_id != self.actor_authority.authority_id:
            raise ValueError("deployment actor authority mismatch")
        if self.status == DeploymentStatus.COMPLETED_OBSERVED and self.assertion.origin in {
            EvidenceStrength.DECLARED,
            EvidenceStrength.IMPORTED_UNVERIFIED,
        }:
            raise ValueError("declared/imported deployment cannot claim observed completion")
        _check_identity(self, "record_id", "deployment_record_", "record_digest")
        return self


class RuntimeObserverIdentity(RuntimeModel):
    schema_id: Literal["omiv.runtime-observer-identity.v1"] = Field(
        default="omiv.runtime-observer-identity.v1", alias="schema"
    )
    observer_id: str = Field(pattern=r"^runtime_observer_[0-9a-f]{32}$")
    name: str = Field(pattern=ID_PATTERN)
    version: str
    revision: str
    implementation_digest: str = Field(pattern=SHA256_PATTERN)
    configuration_digest: str = Field(pattern=SHA256_PATTERN)
    capabilities: list[ObserverCapability]
    supported_target_types: list[DeploymentTargetType]
    supported_artifact_classes: list[ProductSubjectClass]
    observation_strength_ceiling: EvidenceStrength
    scope: ScopeContext
    authority: AssertionAuthorityScope
    signer_identity_id: str | None = Field(default=None, pattern=ID_PATTERN)
    key_id: str | None = Field(default=None, pattern=ID_PATTERN)
    trust_root_id: str | None = Field(default=None, pattern=ID_PATTERN)
    trust_references: list[str]
    limitations: list[str]
    observer_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RuntimeObserverIdentity:
        if ObserverCapability.BEHAVIORAL_OBSERVATION_RESERVED in self.capabilities:
            raise ValueError("reserved behavioral observation is non-operational in Phase 5G")
        if self.scope != self.authority.scope:
            raise ValueError("observer scope and authority mismatch")
        _check_identity(self, "observer_id", "runtime_observer_", "observer_digest")
        return self


class ReplayProtectionContext(RuntimeModel):
    schema_id: Literal["omiv.replay-protection-context.v1"] = Field(
        default="omiv.replay-protection-context.v1", alias="schema"
    )
    replay_id: str = Field(pattern=r"^runtime_replay_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    observer_id: str = Field(pattern=r"^runtime_observer_[0-9a-f]{32}$")
    scope: ScopeContext
    manifest_digest: str = Field(pattern=SHA256_PATTERN)
    target_id: str = Field(pattern=ID_PATTERN)
    artifact_set_digest: str = Field(pattern=SHA256_PATTERN)
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    sequence_namespace: str = Field(pattern=ID_PATTERN)
    epoch: int = Field(ge=1)
    expected_sequence: int = Field(ge=1)
    predecessor_observation_id: str | None = Field(
        default=None, pattern=r"^runtime_observation_[0-9a-f]{32}$"
    )
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    replay_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> ReplayProtectionContext:
        _check_identity(self, "replay_id", "runtime_replay_", "replay_digest")
        return self


class RuntimeObservationPlan(RuntimeModel):
    schema_id: Literal["omiv.runtime-observation-plan.v1"] = Field(
        default="omiv.runtime-observation-plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=r"^runtime_plan_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    manifest_id: str = Field(pattern=r"^deployment_manifest_[0-9a-f]{32}$")
    observer_id: str = Field(pattern=r"^runtime_observer_[0-9a-f]{32}$")
    required_capabilities: list[ObserverCapability]
    expected_artifact_set_digest: str = Field(pattern=SHA256_PATTERN)
    expected_configuration_digest: str = Field(pattern=SHA256_PATTERN)
    expected_engine_digest: str = Field(pattern=SHA256_PATTERN)
    expected_environment_digest: str = Field(pattern=SHA256_PATTERN)
    expected_target_id: str = Field(pattern=ID_PATTERN)
    required_dimensions: list[ObservationDimension]
    optional_dimensions: list[ObservationDimension]
    maximum_age_sequences: int = Field(ge=0)
    replay_context: ReplayProtectionContext
    maximum_evidence_references: int = Field(ge=1, le=256)
    limitations: list[str]
    plan_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> RuntimeObservationPlan:
        if self.replay_context.instance_id != self.instance_id:
            raise ValueError("observation plan replay instance mismatch")
        if self.replay_context.observer_id != self.observer_id:
            raise ValueError("observation plan replay observer mismatch")
        if set(self.required_dimensions).intersection(self.optional_dimensions):
            raise ValueError("required and optional observation dimensions overlap")
        _check_identity(self, "plan_id", "runtime_plan_", "plan_digest")
        return self


class ArtifactMemberObservation(RuntimeModel):
    logical_name: str = Field(pattern=ID_PATTERN)
    observed_identity_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    method: IdentityObservationMethod
    evidence_strength: EvidenceStrength
    generation_provenance_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    limitations: list[str]


class RuntimeArtifactSetObservation(RuntimeModel):
    artifact_set_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    members: list[ArtifactMemberObservation]
    limitations: list[str]


class ObservationCoverage(RuntimeModel):
    schema_id: Literal["omiv.observation-coverage.v1"] = Field(
        default="omiv.observation-coverage.v1", alias="schema"
    )
    coverage_id: str = Field(pattern=r"^runtime_coverage_[0-9a-f]{32}$")
    expected_dimensions: list[ObservationDimension]
    observed_dimensions: list[ObservationDimension]
    unsupported_dimensions: list[ObservationDimension]
    inaccessible_dimensions: list[ObservationDimension]
    errored_dimensions: list[ObservationDimension]
    stale_dimensions: list[ObservationDimension]
    proxy_only_dimensions: list[ObservationDimension]
    independently_corroborated_dimensions: list[ObservationDimension]
    status: ObservationCoverageStatus
    limitations: list[str]
    coverage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> ObservationCoverage:
        expected, observed = set(self.expected_dimensions), set(self.observed_dimensions)
        if not observed.issubset(expected):
            raise ValueError("observed dimensions exceed expected scope")
        classified = {
            "unsupported": set(self.unsupported_dimensions),
            "inaccessible": set(self.inaccessible_dimensions),
            "errored": set(self.errored_dimensions),
            "stale": set(self.stale_dimensions),
            "proxy": set(self.proxy_only_dimensions),
            "corroborated": set(self.independently_corroborated_dimensions),
        }
        if any(not values.issubset(expected) for values in classified.values()):
            raise ValueError("coverage classification exceeds expected dimensions")
        if not classified["corroborated"].issubset(observed):
            raise ValueError("corroborated dimensions must be observed")
        failure_groups = [
            classified["unsupported"],
            classified["inaccessible"],
            classified["errored"],
        ]
        if any(
            left.intersection(right)
            for i, left in enumerate(failure_groups)
            for right in failure_groups[i + 1 :]
        ):
            raise ValueError("coverage failure classifications overlap")
        problem = set().union(*failure_groups)
        if self.status == ObservationCoverageStatus.COMPLETE_FOR_REQUIRED_DIMENSIONS and (
            expected != observed or problem or classified["stale"]
        ):
            raise ValueError("false complete observation coverage")
        _check_identity(self, "coverage_id", "runtime_coverage_", "coverage_digest")
        return self


class RuntimeObservation(RuntimeModel):
    schema_id: Literal["omiv.runtime-observation.v1"] = Field(
        default="omiv.runtime-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^runtime_observation_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    plan_id: str = Field(pattern=r"^runtime_plan_[0-9a-f]{32}$")
    deployment_record_id: str = Field(pattern=r"^deployment_record_[0-9a-f]{32}$")
    observer_id: str = Field(pattern=r"^runtime_observer_[0-9a-f]{32}$")
    observer_authority: AssertionAuthorityScope
    observed_artifact_set: RuntimeArtifactSetObservation
    observed_configuration_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_engine_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_engine_binary_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_environment_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    observed_target_id: str | None = Field(default=None, pattern=ID_PATTERN)
    assertion: EvidenceAssertion
    coverage: ObservationCoverage
    sequence_namespace: str = Field(pattern=ID_PATTERN)
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=1)
    predecessor_observation_id: str | None = Field(
        default=None, pattern=r"^runtime_observation_[0-9a-f]{32}$"
    )
    evaluation_context_digest: str = Field(pattern=SHA256_PATTERN)
    status: ObservationStatus
    evidence_references: list[str]
    limitations: list[str]
    observation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RuntimeObservation:
        if len(self.evidence_references) > 256:
            raise ValueError("observation evidence reference bound exceeded")
        _check_identity(self, "observation_id", "runtime_observation_", "observation_digest")
        return self


class ContinuityPolicyProfile(StrEnum):
    LOCAL_RUNTIME_CONTINUITY = "local_runtime_continuity"
    TEAM_SERVICE_CONTINUITY = "team_service_continuity"
    ENTERPRISE_DEPLOYMENT_CONTINUITY = "enterprise_deployment_continuity"
    AIR_GAPPED_RUNTIME_CONTINUITY = "air_gapped_runtime_continuity"
    REGULATED_RUNTIME_CONTINUITY = "regulated_runtime_continuity"


class ContinuityPolicy(RuntimeModel):
    schema_id: Literal["omiv.continuity-policy.v1"] = Field(
        default="omiv.continuity-policy.v1", alias="schema"
    )
    policy_id: str = Field(pattern=r"^omiv\.continuity-policy\.[a-z0-9_.-]+\.v1$")
    profile: ContinuityPolicyProfile
    accepted_subject_classes: list[ProductSubjectClass]
    accepted_deployment_strengths: list[EvidenceStrength]
    accepted_observation_strengths: list[EvidenceStrength]
    required_dimensions: list[ObservationDimension]
    require_direct_artifact_identity: bool
    require_signed_deployment: bool
    require_signed_observation: bool
    require_trusted_observer: bool
    require_independent_observer: bool
    require_distinct_signer: bool
    require_distinct_key: bool
    require_distinct_trust_root: bool
    require_corroboration: bool
    allow_limited_security_evidence: bool
    maximum_age_sequences: int = Field(ge=0)
    offline_trust_requires_limitation: bool
    fail_closed_reserved: bool
    decision_precedence: list[ContinuityVerdict]
    limitations: list[str]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> ContinuityPolicy:
        data = self.model_dump(mode="json", by_alias=True)
        digest = data.pop("policy_digest")
        if digest != canonical_sha256(data):
            raise ValueError("continuity policy digest mismatch")
        return self


class DriftFinding(RuntimeModel):
    schema_id: Literal["omiv.drift-finding.v1"] = Field(
        default="omiv.drift-finding.v1", alias="schema"
    )
    drift_id: str = Field(pattern=r"^runtime_drift_[0-9a-f]{32}$")
    category: DriftCategory
    expected_reference: str
    observed_reference: str
    observation_method: IdentityObservationMethod
    evidence_strength: EvidenceStrength
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    confidence: Literal["CONFIRMED", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    policy_impact: str
    scope: ScopeContext
    limitations: list[str]
    remediation: str
    drift_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> DriftFinding:
        _check_identity(self, "drift_id", "runtime_drift_", "drift_digest")
        return self


class ArtifactMemberContinuity(RuntimeModel):
    logical_name: str = Field(pattern=ID_PATTERN)
    required: bool
    method: IdentityObservationMethod
    evidence_strength: EvidenceStrength
    result: ContinuityLevel
    limitations: list[str]


class ContinuityEvaluation(RuntimeModel):
    schema_id: Literal["omiv.continuity-evaluation.v1"] = Field(
        default="omiv.continuity-evaluation.v1", alias="schema"
    )
    evaluation_id: str = Field(pattern=r"^runtime_evaluation_[0-9a-f]{32}$")
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    artifact_set_id: str = Field(pattern=r"^deployment_artifact_set_[0-9a-f]{32}$")
    intent_digest: str = Field(pattern=SHA256_PATTERN)
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    manifest_digest: str = Field(pattern=SHA256_PATTERN)
    deployment_record_digest: str = Field(pattern=SHA256_PATTERN)
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    policy_id: str = Field(pattern=ID_PATTERN)
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    deployment_evidence: str
    observation_integrity: str
    observer_trust: str
    observer_authority: AssertionAuthorityStatus
    separation_of_duties: str
    replay_status: str
    freshness: RuntimeFreshness
    coverage_status: ObservationCoverageStatus
    artifact_members: list[ArtifactMemberContinuity]
    artifact_set_continuity: ContinuityLevel
    configuration_continuity: ContinuityLevel
    engine_continuity: ContinuityLevel
    environment_continuity: ContinuityLevel
    target_continuity: ContinuityLevel
    security_evidence_continuity: str
    governance_continuity: str
    drift_findings: list[DriftFinding]
    verdict: ContinuityVerdict
    blockers: list[str]
    limitations: list[str]
    unobserved_dimensions: list[ObservationDimension]
    snapshot_scope: Literal["SNAPSHOT_ONLY"] = "SNAPSHOT_ONLY"
    behavioral_parity: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    runtime_safety: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    continuous_continuity: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    trusted_timestamp_status: Literal["NOT_AVAILABLE"] = "NOT_AVAILABLE"
    revocation_status: Literal[
        "EVALUATED_NO_APPLICABLE_REVOCATION",
        "ONLINE_UNAVAILABLE",
        "NOT_EVALUATED",
    ]
    trust_bundle_freshness: Literal[
        "CURRENT_FOR_EXPLICIT_CONTEXT",
        "LIMITED_OFFLINE_SNAPSHOT",
        "NOT_EVALUATED",
    ]
    structured_gaps: list[str]
    evaluation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> ContinuityEvaluation:
        if self.verdict == ContinuityVerdict.PASS and (
            self.coverage_status != ObservationCoverageStatus.COMPLETE_FOR_REQUIRED_DIMENSIONS
            or self.observer_authority != AssertionAuthorityStatus.AUTHORIZED
            or self.drift_findings
        ):
            raise ValueError("PASS does not satisfy mandatory continuity conditions")
        _check_identity(self, "evaluation_id", "runtime_evaluation_", "evaluation_digest")
        return self


class DeploymentRuntimeReport(RuntimeModel):
    schema_id: Literal["omiv.deployment-runtime-report.v1"] = Field(
        default="omiv.deployment-runtime-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^runtime_report_[0-9a-f]{32}$")
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    artifact_set_id: str = Field(pattern=r"^deployment_artifact_set_[0-9a-f]{32}$")
    scope: ScopeContext
    intent_id: str = Field(pattern=r"^deployment_intent_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    manifest_id: str = Field(pattern=r"^deployment_manifest_[0-9a-f]{32}$")
    deployment_record_id: str = Field(pattern=r"^deployment_record_[0-9a-f]{32}$")
    deployment_status: DeploymentStatus
    deployment_evidence_origin: EvidenceStrength
    target_id: str = Field(pattern=ID_PATTERN)
    engine_id: str = Field(pattern=r"^runtime_engine_[0-9a-f]{32}$")
    environment_id: str = Field(pattern=r"^runtime_environment_[0-9a-f]{32}$")
    observer_id: str = Field(pattern=r"^runtime_observer_[0-9a-f]{32}$")
    observation_id: str = Field(pattern=r"^runtime_observation_[0-9a-f]{32}$")
    observation_strength: EvidenceStrength
    source_security_verdict: Literal["PASS", "PASS_WITH_LIMITATIONS"]
    source_security_limitations: list[str]
    coverage: ObservationCoverage
    coverage_remediation: list[str]
    evaluation: ContinuityEvaluation
    deployment_performed_by_omiv: Literal[False] = False
    limitations: list[str]
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> DeploymentRuntimeReport:
        _check_identity(self, "report_id", "runtime_report_", "report_digest")
        return self


class GovernanceRuntimeAdapter(RuntimeModel):
    schema_id: Literal["omiv.governance-runtime-adapter.v1"] = Field(
        default="omiv.governance-runtime-adapter.v1", alias="schema"
    )
    adapter_id: str = Field(pattern=r"^governance_runtime_[0-9a-f]{32}$")
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    continuity_evaluation_id: str = Field(pattern=r"^runtime_evaluation_[0-9a-f]{32}$")
    continuity_evaluation_digest: str = Field(pattern=SHA256_PATTERN)
    source_security_verdict: str
    source_security_limitations: list[str]
    deployment_evidence_outcome: str
    runtime_observation_outcome: str
    continuity_outcome: str
    limitations: list[str]
    adapter_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> GovernanceRuntimeAdapter:
        _check_identity(self, "adapter_id", "governance_runtime_", "adapter_digest")
        return self


class PassportRuntimeSummary(RuntimeModel):
    schema_id: Literal["omiv.passport-runtime-summary.v1"] = Field(
        default="omiv.passport-runtime-summary.v1", alias="schema"
    )
    summary_id: str = Field(pattern=r"^passport_runtime_[0-9a-f]{32}$")
    passport_id: str = Field(pattern=ID_PATTERN)
    passport_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    artifact_set_id: str = Field(pattern=r"^deployment_artifact_set_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    deployment_declared: bool
    deployment_observed: bool
    runtime_observed: bool
    observation_strength: EvidenceStrength
    observation_coverage: ObservationCoverageStatus
    artifact_set_continuity: ContinuityLevel
    configuration_continuity: ContinuityLevel
    engine_continuity: ContinuityLevel
    observer_trust: str
    observer_authority: AssertionAuthorityStatus
    freshness: RuntimeFreshness
    replay_status: str
    verdict: ContinuityVerdict
    limitations: list[str]
    behavioral_parity: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    runtime_safety: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    continuous_continuity: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    summary_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> PassportRuntimeSummary:
        _check_identity(self, "summary_id", "passport_runtime_", "summary_digest")
        return self


class CustodyRuntimeLinkage(RuntimeModel):
    schema_id: Literal["omiv.custody-runtime-linkage.v1"] = Field(
        default="omiv.custody-runtime-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=r"^custody_runtime_[0-9a-f]{32}$")
    chain_id: str = Field(pattern=ID_PATTERN)
    ledger_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    artifact_set_id: str = Field(pattern=r"^deployment_artifact_set_[0-9a-f]{32}$")
    instance_id: str = Field(pattern=r"^deployment_instance_[0-9a-f]{32}$")
    event_types: list[
        Literal[
            "DEPLOYMENT_INTENT_RECORDED",
            "DEPLOYMENT_RECORD_RECORDED",
            "RUNTIME_OBSERVATION_RECORDED",
            "RUNTIME_DRIFT_DETECTED",
            "RUNTIME_REPLAY_REJECTED",
        ]
    ]
    evidence_origin: EvidenceStrength
    observer_authority: AssertionAuthorityStatus
    observation_coverage: ObservationCoverageStatus
    verdict: ContinuityVerdict
    limitations: list[str]
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> CustodyRuntimeLinkage:
        _check_identity(self, "linkage_id", "custody_runtime_", "linkage_digest")
        return self


class SignedRuntimeLinkage(RuntimeModel):
    schema_id: Literal["omiv.signed-runtime-linkage.v1"] = Field(
        default="omiv.signed-runtime-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=r"^signed_runtime_[0-9a-f]{32}$")
    object_type: str
    object_id: str = Field(pattern=ID_PATTERN)
    object_digest: str = Field(pattern=SHA256_PATTERN)
    envelope_id: str = Field(pattern=ID_PATTERN)
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    signature_purposes: list[str]
    evidence_origin_preserved: bool
    authority_preserved: bool
    coverage_preserved: bool
    verdict_preserved: bool
    limitations: list[str]
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> SignedRuntimeLinkage:
        if not all(
            (
                self.evidence_origin_preserved,
                self.authority_preserved,
                self.coverage_preserved,
                self.verdict_preserved,
            )
        ):
            raise ValueError("signed runtime linkage must preserve claim boundaries")
        _check_identity(self, "linkage_id", "signed_runtime_", "linkage_digest")
        return self


class RuntimeArtifactIndexEntry(RuntimeModel):
    relative_path: str
    size: int = Field(ge=0, le=1024 * 1024)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str
    canonical_id: str = Field(pattern=ID_PATTERN)


class RuntimeArtifactIndex(RuntimeModel):
    schema_id: Literal["omiv.runtime-artifact-index.v1"] = Field(
        default="omiv.runtime-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^runtime_index_[0-9a-f]{32}$")
    entries: list[RuntimeArtifactIndexEntry] = Field(max_length=150)
    total_size: int = Field(ge=0)
    generated_json_count: int = Field(ge=0)
    generated_markdown_count: int = Field(ge=0)
    limitations: list[str]
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def valid(self) -> RuntimeArtifactIndex:
        paths = [x.relative_path for x in self.entries]
        ids = [x.canonical_id for x in self.entries]
        hashes = [x.sha256 for x in self.entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("runtime index paths must be uniquely ordered")
        if len(ids) != len(set(ids)) or len(hashes) != len(set(hashes)):
            raise ValueError("runtime index contains duplicate canonical IDs or content")
        if self.total_size != sum(x.size for x in self.entries):
            raise ValueError("runtime index total size mismatch")
        _check_identity(self, "index_id", "runtime_index_", "index_digest")
        return self
