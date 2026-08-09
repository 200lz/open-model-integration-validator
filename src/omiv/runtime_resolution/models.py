"""Strict canonical Phase 6E runtime-resolution and output-provenance models."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.quantization.models import parse_bounded_decimal
from omiv.runtime.models import ProductSubject

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
SCHEMA_PATTERN = r"^omiv\.[a-z0-9.-]+\.v[0-9]+$"
MAX_TEXT = 2048
MAX_COLLECTION = 4096
MAX_FINDINGS = 200_000
MAX_INDEX_ENTRIES = 180
ExplicitTime = Annotated[
    str,
    StringConstraints(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    ),
]


class IdentifierKind(StrEnum):
    IMMUTABLE_PINNED_IDENTIFIER = "IMMUTABLE_PINNED_IDENTIFIER"
    VERSIONED_IDENTIFIER = "VERSIONED_IDENTIFIER"
    MUTABLE_ALIAS = "MUTABLE_ALIAS"
    LATEST_ALIAS = "LATEST_ALIAS"
    DEPRECATED_RESOLVING_IDENTIFIER = "DEPRECATED_RESOLVING_IDENTIFIER"
    REDIRECTED_IDENTIFIER = "REDIRECTED_IDENTIFIER"
    PROVIDER_OPAQUE_IDENTIFIER = "PROVIDER_OPAQUE_IDENTIFIER"
    USER_DEFINED_ALIAS = "USER_DEFINED_ALIAS"
    UNKNOWN_IDENTIFIER_KIND = "UNKNOWN_IDENTIFIER_KIND"
    INVALID_IDENTIFIER = "INVALID_IDENTIFIER"


class ObservationLevel(StrEnum):
    CALLER_DECLARED = "CALLER_DECLARED"
    PROVIDER_DOCUMENTED_POLICY = "PROVIDER_DOCUMENTED_POLICY"
    CONTROL_PLANE_RESPONSE = "CONTROL_PLANE_RESPONSE"
    API_RESPONSE_FIELD = "API_RESPONSE_FIELD"
    RUNTIME_SELF_REPORT = "RUNTIME_SELF_REPORT"
    DIRECT_RUNTIME_OBSERVATION = "DIRECT_RUNTIME_OBSERVATION"
    CRYPTOGRAPHICALLY_ATTESTED = "CRYPTOGRAPHICALLY_ATTESTED"
    NOT_OBSERVED = "NOT_OBSERVED"


class ResolutionMechanism(StrEnum):
    HTTP_REDIRECT = "HTTP_REDIRECT"
    PROVIDER_SEMANTIC_ROUTING = "PROVIDER_SEMANTIC_ROUTING"
    MODEL_ALIAS_RESOLUTION = "MODEL_ALIAS_RESOLUTION"
    DEPRECATION_COMPATIBILITY_ROUTING = "DEPRECATION_COMPATIBILITY_ROUTING"
    REGISTRY_LOOKUP = "REGISTRY_LOOKUP"
    CALLER_SUPPLIED = "CALLER_SUPPLIED"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class ResolutionStatus(StrEnum):
    RESOLVED_TO_DISCLOSED_IDENTIFIER = "RESOLVED_TO_DISCLOSED_IDENTIFIER"
    REDIRECTED_TO_DISCLOSED_IDENTIFIER = "REDIRECTED_TO_DISCLOSED_IDENTIFIER"
    RESOLVED_IDENTITY_NOT_DISCLOSED = "RESOLVED_IDENTITY_NOT_DISCLOSED"
    MUTABLE_ALIAS_RESOLUTION = "MUTABLE_ALIAS_RESOLUTION"
    DEPRECATED_IDENTIFIER_CONTINUES_TO_RESOLVE = "DEPRECATED_IDENTIFIER_CONTINUES_TO_RESOLVE"
    RESOLUTION_NOT_OBSERVED = "RESOLUTION_NOT_OBSERVED"
    RESOLUTION_INVALID = "RESOLUTION_INVALID"


class ContinuityOutcome(StrEnum):
    SAME_RESOLVED_IDENTITY_FOR_SUPPLIED_OBSERVATIONS = (
        "SAME_RESOLVED_IDENTITY_FOR_SUPPLIED_OBSERVATIONS"
    )
    ALIAS_REBOUND_FOR_SUPPLIED_OBSERVATIONS = "ALIAS_REBOUND_FOR_SUPPLIED_OBSERVATIONS"
    REDIRECT_TARGET_CHANGED_FOR_SUPPLIED_OBSERVATIONS = (
        "REDIRECT_TARGET_CHANGED_FOR_SUPPLIED_OBSERVATIONS"
    )
    ROUTING_RULE_CHANGED_FOR_SUPPLIED_OBSERVATIONS = (
        "ROUTING_RULE_CHANGED_FOR_SUPPLIED_OBSERVATIONS"
    )
    REQUESTED_IDENTIFIER_CHANGED = "REQUESTED_IDENTIFIER_CHANGED"
    RESOLVED_IDENTITY_NOT_DISCLOSED = "RESOLVED_IDENTITY_NOT_DISCLOSED"
    INSUFFICIENT_OBSERVATIONS = "INSUFFICIENT_OBSERVATIONS"
    OBSERVATION_WINDOWS_NOT_COMPARABLE = "OBSERVATION_WINDOWS_NOT_COMPARABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class HistoricalCutoffOutcome(StrEnum):
    KNOWN_EFFECTIVE_AS_OF_CUTOFF = "KNOWN_EFFECTIVE_AS_OF_CUTOFF"
    KNOWN_FUTURE_EFFECTIVE_AS_OF_CUTOFF = "KNOWN_FUTURE_EFFECTIVE_AS_OF_CUTOFF"
    NOT_KNOWN_AS_OF_CUTOFF = "NOT_KNOWN_AS_OF_CUTOFF"
    AVAILABILITY_NOT_RECORDED = "AVAILABILITY_NOT_RECORDED"
    INVALID = "INVALID"


class ObservationStrength(StrEnum):
    DECLARATION_ONLY = "DECLARATION_ONLY"
    CONTROL_PLANE_CONFIGURATION = "CONTROL_PLANE_CONFIGURATION"
    ORCHESTRATOR_STATE = "ORCHESTRATOR_STATE"
    PROCESS_ARGUMENTS = "PROCESS_ARGUMENTS"
    ENVIRONMENT_CONFIGURATION = "ENVIRONMENT_CONFIGURATION"
    FILESYSTEM_ARTIFACT_OBSERVATION = "FILESYSTEM_ARTIFACT_OBSERVATION"
    FILE_DESCRIPTOR_OBSERVATION = "FILE_DESCRIPTOR_OBSERVATION"
    MEMORY_MAPPING_OBSERVATION = "MEMORY_MAPPING_OBSERVATION"
    RUNTIME_SELF_REPORT = "RUNTIME_SELF_REPORT"
    HARDWARE_ATTESTATION_REFERENCE = "HARDWARE_ATTESTATION_REFERENCE"
    TEE_ATTESTATION_REFERENCE = "TEE_ATTESTATION_REFERENCE"
    CRYPTOGRAPHIC_RUNTIME_ATTESTATION = "CRYPTOGRAPHIC_RUNTIME_ATTESTATION"
    PROVABLE_INFERENCE_REFERENCE = "PROVABLE_INFERENCE_REFERENCE"
    NOT_OBSERVED = "NOT_OBSERVED"


class RuntimeBindingOutcome(StrEnum):
    EXPECTED_IDENTITY_ONLY = "EXPECTED_IDENTITY_ONLY"
    DEPLOYMENT_DECLARED_NOT_OBSERVED = "DEPLOYMENT_DECLARED_NOT_OBSERVED"
    CONTROL_PLANE_IDENTITY_OBSERVED = "CONTROL_PLANE_IDENTITY_OBSERVED"
    PROCESS_CONFIGURATION_OBSERVED = "PROCESS_CONFIGURATION_OBSERVED"
    LOCAL_ARTIFACT_BINDING_OBSERVED = "LOCAL_ARTIFACT_BINDING_OBSERVED"
    RUNTIME_SELF_REPORTED = "RUNTIME_SELF_REPORTED"
    RUNTIME_IDENTITY_BOUND_FOR_DECLARED_SCOPE = "RUNTIME_IDENTITY_BOUND_FOR_DECLARED_SCOPE"
    RUNTIME_IDENTITY_MISMATCH = "RUNTIME_IDENTITY_MISMATCH"
    INSUFFICIENT_OBSERVATION = "INSUFFICIENT_OBSERVATION"
    NOT_OBSERVED = "NOT_OBSERVED"
    INVALID = "INVALID"


class ExecutionMode(StrEnum):
    DECLARED_DETERMINISTIC = "DECLARED_DETERMINISTIC"
    DECLARED_STOCHASTIC = "DECLARED_STOCHASTIC"
    UNKNOWN_DETERMINISM = "UNKNOWN_DETERMINISM"


class ResultDimension(StrEnum):
    FINAL_OUTPUT_BYTES = "FINAL_OUTPUT_BYTES"
    FINAL_TEXT = "FINAL_TEXT"
    TOKEN_ID_SEQUENCE = "TOKEN_ID_SEQUENCE"
    STRUCTURED_JSON = "STRUCTURED_JSON"
    TOOL_CALL_STRUCTURE = "TOOL_CALL_STRUCTURE"
    FINISH_REASON = "FINISH_REASON"
    SELECTED_LOGIT_SAMPLES = "SELECTED_LOGIT_SAMPLES"
    ERROR_CLASS = "ERROR_CLASS"
    STREAM_FINAL_AGGREGATE = "STREAM_FINAL_AGGREGATE"
    STREAM_CHUNK_BOUNDARIES = "STREAM_CHUNK_BOUNDARIES"


class BackendComparisonStatus(StrEnum):
    EXACT_FOR_DECLARED_PROBES = "EXACT_FOR_DECLARED_PROBES"
    WITHIN_EXPLICIT_NUMERICAL_POLICY_FOR_DECLARED_PROBES = (
        "WITHIN_EXPLICIT_NUMERICAL_POLICY_FOR_DECLARED_PROBES"
    )
    MISMATCH_FOR_DECLARED_PROBES = "MISMATCH_FOR_DECLARED_PROBES"
    DIFFERENT_BUT_NOT_POLICY_FAILURE = "DIFFERENT_BUT_NOT_POLICY_FAILURE"
    STOCHASTIC_RESULTS_NOT_DIRECTLY_COMPARABLE = "STOCHASTIC_RESULTS_NOT_DIRECTLY_COMPARABLE"
    PARTIAL_BACKEND_PARITY = "PARTIAL_BACKEND_PARITY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class ContentAvailability(StrEnum):
    INLINE_SYNTHETIC = "INLINE_SYNTHETIC"
    DIGEST_ONLY = "DIGEST_ONLY"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class ReproducibilityState(StrEnum):
    INLINE_SYNTHETIC_REPRODUCIBLE = "INLINE_SYNTHETIC_REPRODUCIBLE"
    DIGEST_ONLY_NOT_INDEPENDENTLY_REPRODUCIBLE = "DIGEST_ONLY_NOT_INDEPENDENTLY_REPRODUCIBLE"
    CONTENT_UNAVAILABLE = "CONTENT_UNAVAILABLE"
    INVALID = "INVALID"


class AttestationMethod(StrEnum):
    UNSIGNED_CLAIM = "UNSIGNED_CLAIM"
    SERVICE_SIGNATURE = "SERVICE_SIGNATURE"
    PROVIDER_ATTESTATION_REFERENCE = "PROVIDER_ATTESTATION_REFERENCE"
    HARDWARE_ATTESTATION_REFERENCE = "HARDWARE_ATTESTATION_REFERENCE"
    TEE_ATTESTATION_REFERENCE = "TEE_ATTESTATION_REFERENCE"
    CRYPTOGRAPHIC_RUNTIME_ATTESTATION_REFERENCE = "CRYPTOGRAPHIC_RUNTIME_ATTESTATION_REFERENCE"
    PROVABLE_INFERENCE_PROOF_REFERENCE = "PROVABLE_INFERENCE_PROOF_REFERENCE"
    METHOD_UNAVAILABLE = "METHOD_UNAVAILABLE"


class ProofAvailability(StrEnum):
    PROOF_OBJECT_AVAILABLE = "PROOF_OBJECT_AVAILABLE"
    PROOF_REFERENCE_ONLY = "PROOF_REFERENCE_ONLY"
    PROOF_UNAVAILABLE = "PROOF_UNAVAILABLE"
    PROOF_FORMAT_UNKNOWN = "PROOF_FORMAT_UNKNOWN"
    PROOF_INVALID = "PROOF_INVALID"


class ProvenanceVerificationStatus(StrEnum):
    SERVICE_SIGNATURE_VERIFIED = "SERVICE_SIGNATURE_VERIFIED"
    PROVIDER_ATTESTATION_RECORDED_NOT_INDEPENDENTLY_VERIFIED = (
        "PROVIDER_ATTESTATION_RECORDED_NOT_INDEPENDENTLY_VERIFIED"
    )
    HARDWARE_ATTESTATION_NOT_EVALUATED = "HARDWARE_ATTESTATION_NOT_EVALUATED"
    TEE_ATTESTATION_NOT_EVALUATED = "TEE_ATTESTATION_NOT_EVALUATED"
    PROVABLE_INFERENCE_NOT_IMPLEMENTED = "PROVABLE_INFERENCE_NOT_IMPLEMENTED"
    PROVABLE_INFERENCE_FORMAT_UNAVAILABLE = "PROVABLE_INFERENCE_FORMAT_UNAVAILABLE"
    WEIGHT_ATTRIBUTION_NOT_ESTABLISHED = "WEIGHT_ATTRIBUTION_NOT_ESTABLISHED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    INVALID = "INVALID"


class AssumptionStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    ACTIVE = "ACTIVE"
    WEAKENED = "WEAKENED"
    INVALIDATED = "INVALIDATED"
    UNRESOLVED = "UNRESOLVED"
    SUPERSEDED = "SUPERSEDED"
    NOT_EVALUATED = "NOT_EVALUATED"


class RequirementStatus(StrEnum):
    SATISFIED = "POLICY_REQUIREMENT_SATISFIED"
    FAILED = "POLICY_REQUIREMENT_FAILED"
    NOT_EVALUATED = "POLICY_REQUIREMENT_NOT_EVALUATED"
    NOT_APPLICABLE = "POLICY_REQUIREMENT_NOT_APPLICABLE"
    INVALID = "POLICY_REQUIREMENT_INVALID"


class AuthorityStatus(StrEnum):
    ESTABLISHED = "ESTABLISHED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    NOT_EVALUATED = "NOT_EVALUATED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    INVALID = "INVALID"


class EvidenceStatus(StrEnum):
    SATISFACTORY_FOR_DECLARED_SCOPE = "SATISFACTORY_FOR_DECLARED_SCOPE"
    MISMATCH_FOR_DECLARED_SCOPE = "MISMATCH_FOR_DECLARED_SCOPE"
    PARTIAL_FOR_DECLARED_SCOPE = "PARTIAL_FOR_DECLARED_SCOPE"
    INDETERMINATE = "INDETERMINATE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class DenominatorAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class RuntimeResolutionLimits(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_identifiers: int = Field(default=10_000, ge=1, le=100_000)
    maximum_receipts: int = Field(default=10_000, ge=1, le=100_000)
    maximum_redirect_depth: int = Field(default=3, ge=0, le=16)
    maximum_continuity_observations: int = Field(default=1_000, ge=2, le=100_000)
    maximum_deployment_observations: int = Field(default=10_000, ge=1, le=100_000)
    maximum_runtime_observations: int = Field(default=10_000, ge=1, le=100_000)
    maximum_backend_descriptors: int = Field(default=256, ge=1, le=4096)
    maximum_probes: int = Field(default=4096, ge=1, le=100_000)
    maximum_executions: int = Field(default=4096, ge=1, le=100_000)
    maximum_result_bytes: int = Field(default=8 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    maximum_token_ids: int = Field(default=100_000, ge=1, le=1_000_000)
    maximum_structured_json_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    maximum_logit_samples: int = Field(default=100_000, ge=1, le=1_000_000)
    maximum_findings: int = Field(default=MAX_FINDINGS, ge=1, le=1_000_000)
    maximum_inference_identities: int = Field(default=10_000, ge=1, le=100_000)
    maximum_attestations: int = Field(default=10_000, ge=1, le=100_000)
    maximum_proof_references: int = Field(default=10_000, ge=1, le=100_000)
    maximum_dependency_nodes: int = Field(default=10_000, ge=32, le=100_000)
    maximum_dependency_edges: int = Field(default=100_000, ge=32, le=1_000_000)
    maximum_dependency_depth: int = Field(default=64, ge=4, le=512)
    maximum_report_nodes: int = Field(default=10_000, ge=1, le=100_000)
    maximum_generated_files: int = Field(default=125, ge=1, le=180)
    maximum_generated_bytes: int = Field(default=5 * 1024 * 1024, ge=1024)
    maximum_public_document_requests: int = Field(default=6, ge=0, le=6)
    maximum_public_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    maximum_public_total_bytes: int = Field(default=6 * 1024 * 1024, ge=1024)


IDENTITY_SPECS: dict[str, tuple[str, str, str]] = {
    "omiv.requested-model-identifier.v1": (
        "identifier_id",
        "identifier_digest",
        "requested_model_",
    ),
    "omiv.identifier-classification.v1": (
        "classification_id",
        "classification_digest",
        "identifier_classification_",
    ),
    "omiv.resolution-plan.v1": ("plan_id", "plan_digest", "resolution_plan_"),
    "omiv.resolution-execution-record.v1": (
        "execution_id",
        "execution_digest",
        "resolution_execution_",
    ),
    "omiv.provider-routing-statement.v1": (
        "statement_id",
        "statement_digest",
        "routing_statement_",
    ),
    "omiv.registry-resolution-receipt.v1": ("receipt_id", "receipt_digest", "resolution_receipt_"),
    "omiv.resolution-continuity-assessment.v1": (
        "assessment_id",
        "assessment_digest",
        "resolution_continuity_",
    ),
    "omiv.runtime-artifact-expectation.v1": (
        "expectation_id",
        "expectation_digest",
        "runtime_artifact_expectation_",
    ),
    "omiv.deployment-declaration.v1": (
        "declaration_id",
        "declaration_digest",
        "deployment_declaration_",
    ),
    "omiv.deployment-observation.v1": (
        "observation_id",
        "observation_digest",
        "deployment_observation_",
    ),
    "omiv.runtime-identity-expectation.v1": (
        "expectation_id",
        "expectation_digest",
        "runtime_identity_expectation_",
    ),
    "omiv.runtime-identity-observation.v1": (
        "observation_id",
        "observation_digest",
        "runtime_identity_observation_",
    ),
    "omiv.model-runtime-binding.v1": ("binding_id", "binding_digest", "model_runtime_binding_"),
    "omiv.backend-descriptor.v1": ("backend_id", "backend_digest", "backend_descriptor_"),
    "omiv.cross-backend-probe-set.v1": ("probe_set_id", "probe_set_digest", "backend_probe_set_"),
    "omiv.backend-execution-plan.v1": ("plan_id", "plan_digest", "backend_plan_"),
    "omiv.backend-execution-record.v1": ("execution_id", "execution_digest", "backend_execution_"),
    "omiv.backend-result-observation.v1": (
        "observation_id",
        "observation_digest",
        "backend_result_",
    ),
    "omiv.cross-backend-comparison.v1": (
        "comparison_id",
        "comparison_digest",
        "backend_comparison_",
    ),
    "omiv.inference-identity.v1": ("inference_id", "inference_digest", "inference_identity_"),
    "omiv.inference-attestation.v1": (
        "attestation_id",
        "attestation_digest",
        "inference_attestation_",
    ),
    "omiv.output-provenance-evidence.v1": (
        "provenance_id",
        "provenance_digest",
        "output_provenance_",
    ),
    "omiv.runtime-resolution-policy.v1": (
        "policy_id",
        "policy_digest",
        "runtime_resolution_policy_",
    ),
    "omiv.runtime-resolution-policy-evaluation.v1": (
        "evaluation_id",
        "evaluation_digest",
        "runtime_policy_evaluation_",
    ),
    "omiv.runtime-resolution-authority-evaluation.v1": (
        "evaluation_id",
        "evaluation_digest",
        "runtime_authority_evaluation_",
    ),
    "omiv.runtime-resolution-parity-evidence.v1": (
        "evidence_id",
        "evidence_digest",
        "runtime_resolution_evidence_",
    ),
    "omiv.runtime-resolution-integration-summary.v1": (
        "integration_id",
        "integration_digest",
        "runtime_integration_",
    ),
    "omiv.assumption-register-entry.v1": ("assumption_id", "assumption_digest", "assumption_"),
    "omiv.runtime-resolution-report.v1": (
        "report_id",
        "report_digest",
        "runtime_resolution_report_",
    ),
    "omiv.runtime-resolution-scenario-result.v1": (
        "result_id",
        "result_digest",
        "runtime_scenario_",
    ),
    "omiv.runtime-resolution-scenario-catalog.v1": (
        "catalog_id",
        "catalog_digest",
        "runtime_catalog_",
    ),
    "omiv.runtime-resolution-artifact-index.v1": ("index_id", "index_digest", "runtime_index_"),
}


class ResolutionModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def canonical_identity(self) -> ResolutionModel:
        body = self.model_dump(mode="json", by_alias=True)
        schema = body.get("schema")
        if not isinstance(schema, str) or schema not in IDENTITY_SPECS:
            return self
        id_field, digest_field, prefix = IDENTITY_SPECS[schema]
        digest = body.pop(digest_field)
        identity = body.pop(id_field)
        expected_id = prefix + canonical_sha256(body)[:32]
        expected_digest = canonical_sha256({**body, id_field: expected_id})
        if identity != expected_id or digest != expected_digest:
            raise ValueError("canonical identity or digest mismatch")
        return self


class ObjectReference(ResolutionModel):
    schema_id: str = Field(pattern=SCHEMA_PATTERN)
    object_id: str = Field(min_length=3, max_length=192)
    object_digest: str = Field(pattern=SHA256_PATTERN)


class CoverageDimension(ResolutionModel):
    dimension: str = Field(pattern=ID_PATTERN)
    numerator: int = Field(ge=0)
    denominator: int | None = Field(default=None, ge=0)
    denominator_availability: DenominatorAvailability
    selected_scope: str = Field(pattern=ID_PATTERN)
    incomplete_reason: str | None = Field(default=None, max_length=MAX_TEXT)

    @model_validator(mode="after")
    def valid_denominator(self) -> CoverageDimension:
        if (self.denominator is None) != (
            self.denominator_availability == DenominatorAvailability.UNAVAILABLE
        ):
            raise ValueError("coverage denominator availability mismatch")
        if self.denominator is not None and self.numerator > self.denominator:
            raise ValueError("coverage numerator exceeds denominator")
        return self


class TypedParameter(ResolutionModel):
    name: str = Field(pattern=ID_PATTERN)
    value_type: Literal["BOOLEAN", "INTEGER", "DECIMAL", "STRING", "DIGEST", "EXPLICIT_NULL"]
    value: str | None = Field(default=None, max_length=MAX_TEXT)

    @model_validator(mode="after")
    def valid_value(self) -> TypedParameter:
        if self.value_type == "EXPLICIT_NULL":
            if self.value is not None:
                raise ValueError("explicit null parameter cannot carry a value")
        elif self.value is None:
            raise ValueError("typed parameter requires a value")
        if self.value_type == "DECIMAL" and self.value is not None:
            parse_bounded_decimal(self.value)
        if (
            self.value_type == "INTEGER"
            and self.value is not None
            and not re.fullmatch(r"-?(?:0|[1-9][0-9]{0,127})", self.value)
        ):
            raise ValueError("invalid bounded integer parameter")
        if (
            self.value_type == "DIGEST"
            and self.value is not None
            and not re.fullmatch(SHA256_PATTERN, self.value)
        ):
            raise ValueError("invalid typed digest")
        return self


class ContentIdentity(ResolutionModel):
    availability: ContentAvailability
    canonicalization_mode: str = Field(pattern=ID_PATTERN)
    media_type: str = Field(pattern=r"^[a-z0-9.+-]+/[a-z0-9.+-]+$")
    encoding: str = Field(pattern=ID_PATTERN)
    length: int | None = Field(default=None, ge=0, le=64 * 1024 * 1024)
    digest_algorithm: Literal["SHA256"]
    digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    inline_synthetic: str | None = Field(default=None, max_length=MAX_TEXT)
    streaming_aggregate_semantics: str = Field(pattern=ID_PATTERN)
    scope: str = Field(pattern=ID_PATTERN)
    coverage: Literal["COMPLETE_CONTENT", "DIGEST_IDENTITY_ONLY", "CONTENT_UNAVAILABLE"]
    reproducibility: ReproducibilityState

    @model_validator(mode="after")
    def availability_matches_content(self) -> ContentIdentity:
        if self.availability == ContentAvailability.INLINE_SYNTHETIC:
            if self.inline_synthetic is None or self.digest is None or self.length is None:
                raise ValueError("inline synthetic content requires value, length, and digest")
            raw = self.inline_synthetic.encode(self.encoding)
            expected_digest = canonical_sha256(
                {
                    "domain": "omiv.content-identity.v1",
                    "canonicalization_mode": self.canonicalization_mode,
                    "media_type": self.media_type,
                    "encoding": self.encoding,
                    "raw_hex": raw.hex(),
                    "streaming_aggregate_semantics": self.streaming_aggregate_semantics,
                }
            )
            if len(raw) != self.length or expected_digest != self.digest:
                raise ValueError("inline content identity mismatch")
        elif self.availability == ContentAvailability.DIGEST_ONLY:
            if self.inline_synthetic is not None or self.digest is None:
                raise ValueError("digest-only content requires digest without plaintext")
        elif self.availability in {
            ContentAvailability.UNAVAILABLE,
            ContentAvailability.INVALID,
        } and any(value is not None for value in (self.inline_synthetic, self.digest, self.length)):
            raise ValueError("unavailable content cannot carry content identity")
        expected_state = {
            ContentAvailability.INLINE_SYNTHETIC: (
                "COMPLETE_CONTENT",
                ReproducibilityState.INLINE_SYNTHETIC_REPRODUCIBLE,
            ),
            ContentAvailability.DIGEST_ONLY: (
                "DIGEST_IDENTITY_ONLY",
                ReproducibilityState.DIGEST_ONLY_NOT_INDEPENDENTLY_REPRODUCIBLE,
            ),
            ContentAvailability.UNAVAILABLE: (
                "CONTENT_UNAVAILABLE",
                ReproducibilityState.CONTENT_UNAVAILABLE,
            ),
            ContentAvailability.INVALID: ("CONTENT_UNAVAILABLE", ReproducibilityState.INVALID),
        }[self.availability]
        if (self.coverage, self.reproducibility) != expected_state:
            raise ValueError("content availability, coverage, and reproducibility mismatch")
        return self


class RequestedModelIdentifier(ResolutionModel):
    schema_id: Literal["omiv.requested-model-identifier.v1"] = Field(
        default="omiv.requested-model-identifier.v1", alias="schema"
    )
    identifier_id: str
    identifier_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    provider: str = Field(pattern=ID_PATTERN)
    namespace: str = Field(pattern=ID_PATTERN)
    api_surface: str = Field(pattern=ID_PATTERN)
    purpose: str = Field(pattern=ID_PATTERN)
    requested_identifier: str = Field(min_length=1, max_length=256)
    requested_kind: IdentifierKind
    provenance: str = Field(pattern=ID_PATTERN)
    requested_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class IdentifierClassification(ResolutionModel):
    schema_id: Literal["omiv.identifier-classification.v1"] = Field(
        default="omiv.identifier-classification.v1", alias="schema"
    )
    classification_id: str
    classification_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    requested_identifier: ObjectReference
    kind: IdentifierKind
    provenance: ObservationLevel
    authority: AuthorityStatus
    effective_from: ExplicitTime
    effective_until: ExplicitTime
    mutability_evidence: tuple[ObjectReference, ...] = Field(max_length=64)
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class ResolutionPlan(ResolutionModel):
    schema_id: Literal["omiv.resolution-plan.v1"] = Field(
        default="omiv.resolution-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    requested_identifier: ObjectReference
    classification: ObjectReference
    lookup_kind: str = Field(pattern=ID_PATTERN)
    permitted_sources: tuple[ObservationLevel, ...] = Field(min_length=1, max_length=16)
    limits: RuntimeResolutionLimits
    planned_at: ExplicitTime
    network_policy: Literal["OFFLINE", "BOUNDED_PUBLIC_DOCUMENTS_ONLY"]
    limitations: tuple[str, ...] = Field(max_length=32)


class ResolutionExecutionRecord(ResolutionModel):
    schema_id: Literal["omiv.resolution-execution-record.v1"] = Field(
        default="omiv.resolution-execution-record.v1", alias="schema"
    )
    execution_id: str
    execution_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    plan: ObjectReference
    supplied_inputs: tuple[ObjectReference, ...] = Field(max_length=256)
    tool_identity: str = Field(pattern=ID_PATTERN)
    status: Literal["COMPLETED", "NOT_EXECUTED", "LIMIT_EXCEEDED", "INVALID"]
    request_count: int = Field(ge=0, le=6)
    context: str = Field(pattern=ID_PATTERN)
    executed_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class RoutingRule(ResolutionModel):
    requested_identifier: str = Field(min_length=1, max_length=256)
    documented_target: str = Field(min_length=1, max_length=256)
    mechanism: ResolutionMechanism
    api_surface: str = Field(pattern=ID_PATTERN)
    reasoning_setting: str | None = Field(default=None, max_length=64)
    effective_at: ExplicitTime


class ProviderRoutingStatement(ResolutionModel):
    schema_id: Literal["omiv.provider-routing-statement.v1"] = Field(
        default="omiv.provider-routing-statement.v1", alias="schema"
    )
    statement_id: str
    statement_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    provider: str = Field(pattern=ID_PATTERN)
    api_surface: str = Field(pattern=ID_PATTERN)
    source_fixture_digest: str = Field(pattern=SHA256_PATTERN)
    source_url: str = Field(pattern=r"^https://[a-z0-9.-]+/[^?#]+$")
    statement_kind: Literal[
        "PROVIDER_DOCUMENTED_ROUTING_POLICY", "PROVIDER_RESEARCH_ROADMAP_STATEMENT"
    ]
    rules: tuple[RoutingRule, ...] = Field(max_length=64)
    authority: AuthorityStatus
    document_published_at: ExplicitTime
    document_updated_at: ExplicitTime
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    supplied_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class RedirectHop(ResolutionModel):
    ordinal: int = Field(ge=0, le=16)
    source_identifier: str = Field(min_length=1, max_length=256)
    target_identifier: str = Field(min_length=1, max_length=256)
    mechanism: ResolutionMechanism
    evidence: ObjectReference | None = None


class RegistryResolutionReceipt(ResolutionModel):
    schema_id: Literal["omiv.registry-resolution-receipt.v1"] = Field(
        default="omiv.registry-resolution-receipt.v1", alias="schema"
    )
    receipt_id: str
    receipt_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    execution: ObjectReference
    provider: str = Field(pattern=ID_PATTERN)
    namespace: str = Field(pattern=ID_PATTERN)
    api_surface: str = Field(pattern=ID_PATTERN)
    purpose: str = Field(pattern=ID_PATTERN)
    requested_identifier: ObjectReference
    lookup_kind: str = Field(pattern=ID_PATTERN)
    resolution_source: str = Field(pattern=ID_PATTERN)
    resolution_mechanism: ResolutionMechanism
    resolved_identifier: str | None = Field(default=None, max_length=256)
    resolved_identity_kind: IdentifierKind
    status: ResolutionStatus
    evidence: ObjectReference
    observation_level: ObservationLevel
    redirect_chain: tuple[RedirectHop, ...] = Field(max_length=16)
    provider_response_field: str | None = Field(default=None, max_length=128)
    endpoint_context: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    resolved_at: ExplicitTime
    effective_at: ExplicitTime
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    supplied_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def disclosed_status_matches_identifier(self) -> RegistryResolutionReceipt:
        disclosed = self.status in {
            ResolutionStatus.RESOLVED_TO_DISCLOSED_IDENTIFIER,
            ResolutionStatus.REDIRECTED_TO_DISCLOSED_IDENTIFIER,
            ResolutionStatus.MUTABLE_ALIAS_RESOLUTION,
            ResolutionStatus.DEPRECATED_IDENTIFIER_CONTINUES_TO_RESOLVE,
        }
        if disclosed != (self.resolved_identifier is not None):
            raise ValueError("resolution disclosure status mismatch")
        if tuple(h.ordinal for h in self.redirect_chain) != tuple(range(len(self.redirect_chain))):
            raise ValueError("redirect hops must be canonically ordered")
        return self


class ResolutionContinuityAssessment(ResolutionModel):
    schema_id: Literal["omiv.resolution-continuity-assessment.v1"] = Field(
        default="omiv.resolution-continuity-assessment.v1", alias="schema"
    )
    assessment_id: str
    assessment_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    requested_identifier: ObjectReference
    receipts: tuple[ObjectReference, ...] = Field(max_length=1000)
    outcome: ContinuityOutcome
    observation_count: int = Field(ge=0, le=1000)
    evaluated_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=16)
    findings: tuple[str, ...] = Field(max_length=128)
    limitations: tuple[str, ...] = Field(max_length=32)


class RuntimeArtifactExpectation(ResolutionModel):
    schema_id: Literal["omiv.runtime-artifact-expectation.v1"] = Field(
        default="omiv.runtime-artifact-expectation.v1", alias="schema"
    )
    expectation_id: str
    expectation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    artifact_identity: ObjectReference
    payload_identity: ObjectReference | None = None
    tokenizer_configuration_identity: ObjectReference | None = None
    quantization_identity: ObjectReference | None = None
    availability: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    available_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class DeploymentDeclaration(ResolutionModel):
    schema_id: Literal["omiv.deployment-declaration.v1"] = Field(
        default="omiv.deployment-declaration.v1", alias="schema"
    )
    declaration_id: str
    declaration_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    artifact_expectation: ObjectReference
    environment: str = Field(pattern=ID_PATTERN)
    tenant: str = Field(pattern=ID_PATTERN)
    project: str = Field(pattern=ID_PATTERN)
    trust_domain: str = Field(pattern=ID_PATTERN)
    declared_by: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    declared_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class DeploymentObservation(ResolutionModel):
    schema_id: Literal["omiv.deployment-observation.v1"] = Field(
        default="omiv.deployment-observation.v1", alias="schema"
    )
    observation_id: str
    observation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    declaration: ObjectReference
    execution: ObjectReference
    expected_artifact: ObjectReference
    observed_control_plane_identity: str | None = Field(default=None, max_length=256)
    observed_local_artifact: ObjectReference | None = None
    strength: ObservationStrength
    authority: AuthorityStatus
    observed_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    findings: tuple[str, ...] = Field(max_length=128)
    limitations: tuple[str, ...] = Field(max_length=32)


class RuntimeIdentityExpectation(ResolutionModel):
    schema_id: Literal["omiv.runtime-identity-expectation.v1"] = Field(
        default="omiv.runtime-identity-expectation.v1", alias="schema"
    )
    expectation_id: str
    expectation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    deployment_declaration: ObjectReference
    artifact_expectation: ObjectReference
    minimum_strength: ObservationStrength
    authority: AuthorityStatus
    available_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class RuntimeIdentityObservation(ResolutionModel):
    schema_id: Literal["omiv.runtime-identity-observation.v1"] = Field(
        default="omiv.runtime-identity-observation.v1", alias="schema"
    )
    observation_id: str
    observation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    deployment_observation: ObjectReference
    expected_identity: ObjectReference
    observed_identity: ObjectReference | None = None
    strength: ObservationStrength
    observation_source: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    observed_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    findings: tuple[str, ...] = Field(max_length=128)
    limitations: tuple[str, ...] = Field(max_length=32)


class ModelRuntimeBinding(ResolutionModel):
    schema_id: Literal["omiv.model-runtime-binding.v1"] = Field(
        default="omiv.model-runtime-binding.v1", alias="schema"
    )
    binding_id: str
    binding_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    artifact_expectation: ObjectReference
    deployment_declaration: ObjectReference
    deployment_observation: ObjectReference | None = None
    runtime_expectation: ObjectReference
    runtime_observation: ObjectReference | None = None
    selected_policy: ObjectReference
    accepted_strength: ObservationStrength
    outcome: RuntimeBindingOutcome
    authority: AuthorityStatus
    evaluated_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)


class BackendDescriptor(ResolutionModel):
    schema_id: Literal["omiv.backend-descriptor.v1"] = Field(
        default="omiv.backend-descriptor.v1", alias="schema"
    )
    backend_id: str
    backend_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    name: str = Field(pattern=ID_PATTERN)
    version: str = Field(min_length=1, max_length=128)
    build_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    hardware_class: str | None = Field(default=None, max_length=128)
    device_identity_availability: ContentAvailability
    precision: str = Field(pattern=ID_PATTERN)
    quantization_mode: str = Field(pattern=ID_PATTERN)
    declarations: tuple[TypedParameter, ...] = Field(max_length=256)
    runtime_binding: ObjectReference
    tokenizer_configuration_binding: ObjectReference | None = None
    execution_context: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    limitations: tuple[str, ...] = Field(max_length=32)


class BackendProbeDefinition(ResolutionModel):
    probe_id: str = Field(pattern=r"^backend_probe_[0-9a-f]{32}$")
    kind: str = Field(pattern=ID_PATTERN)
    input_identity: ContentIdentity
    request_digest: str = Field(pattern=SHA256_PATTERN)
    runtime_binding: ObjectReference
    tokenizer_configuration_identity: ObjectReference | None = None
    decoding_configuration: tuple[TypedParameter, ...] = Field(max_length=128)
    tool_configuration_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    execution_mode: ExecutionMode
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    dimensions: tuple[ResultDimension, ...] = Field(min_length=1, max_length=16)


class CrossBackendProbeSet(ResolutionModel):
    schema_id: Literal["omiv.cross-backend-probe-set.v1"] = Field(
        default="omiv.cross-backend-probe-set.v1", alias="schema"
    )
    probe_set_id: str
    probe_set_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    probes: tuple[BackendProbeDefinition, ...] = Field(min_length=1, max_length=4096)
    created_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class BackendExecutionPlan(ResolutionModel):
    schema_id: Literal["omiv.backend-execution-plan.v1"] = Field(
        default="omiv.backend-execution-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    probe_set: ObjectReference
    backend: ObjectReference
    runtime_binding: ObjectReference
    selected_probe_ids: tuple[str, ...] = Field(min_length=1, max_length=4096)
    limits: RuntimeResolutionLimits
    planned_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class BackendExecutionRecord(ResolutionModel):
    schema_id: Literal["omiv.backend-execution-record.v1"] = Field(
        default="omiv.backend-execution-record.v1", alias="schema"
    )
    execution_id: str
    execution_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    plan: ObjectReference
    backend: ObjectReference
    runtime_binding: ObjectReference
    probe_set: ObjectReference
    tool_identity: str = Field(pattern=ID_PATTERN)
    context: str = Field(pattern=ID_PATTERN)
    status: Literal[
        "SUPPLIED_RESULT_EXECUTION_RECORDED", "NOT_EXECUTED", "LIMIT_EXCEEDED", "INVALID"
    ]
    executed_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class LogitSample(ResolutionModel):
    position: int = Field(ge=0, le=1_000_000)
    token_id: int = Field(ge=0, le=2**31 - 1)
    value: str = Field(max_length=768)
    rank: int | None = Field(default=None, ge=1, le=1_000_000)

    @field_validator("value")
    @classmethod
    def finite_decimal(cls, value: str) -> str:
        parse_bounded_decimal(value)
        return value


class ToolCallRecord(ResolutionModel):
    ordinal: int = Field(ge=0, le=4095)
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
    arguments: ContentIdentity


class BackendErrorDetail(ResolutionModel):
    error_class: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
    detail: ContentIdentity | None = None


class BackendResult(ResolutionModel):
    probe_id: str = Field(pattern=r"^backend_probe_[0-9a-f]{32}$")
    output: ContentIdentity
    token_ids: tuple[int, ...] = Field(max_length=100_000)
    structured_json_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    tool_call_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    tool_calls: tuple[ToolCallRecord, ...] = Field(default=(), max_length=4096)
    finish_reason: str | None = Field(default=None, max_length=128)
    selected_logits: tuple[LogitSample, ...] = Field(max_length=100_000)
    error_class: str | None = Field(default=None, max_length=128)
    error: BackendErrorDetail | None = None
    stream_final_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    stream_chunk_digests: tuple[str, ...] = Field(max_length=4096)

    @model_validator(mode="after")
    def structured_result_consistency(self) -> BackendResult:
        if tuple(call.ordinal for call in self.tool_calls) != tuple(range(len(self.tool_calls))):
            raise ValueError("tool-call order must use contiguous explicit ordinals")
        if self.tool_calls and self.tool_call_digest is not None:
            raise ValueError("inline tool calls and digest-only tool calls are mutually exclusive")
        if self.error is not None and self.error_class != self.error.error_class:
            raise ValueError("error class and structured error detail disagree")
        return self


class BackendResultObservation(ResolutionModel):
    schema_id: Literal["omiv.backend-result-observation.v1"] = Field(
        default="omiv.backend-result-observation.v1", alias="schema"
    )
    observation_id: str
    observation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    execution: ObjectReference
    backend: ObjectReference
    runtime_binding: ObjectReference
    probe_set: ObjectReference
    results: tuple[BackendResult, ...] = Field(max_length=4096)
    provenance: ObservationLevel
    authority: AuthorityStatus
    observed_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)


class ComparisonFinding(ResolutionModel):
    dimension: ResultDimension
    probe_id: str = Field(pattern=r"^backend_probe_[0-9a-f]{32}$")
    status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    reference_value_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    candidate_value_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    metric: str | None = Field(default=None, pattern=ID_PATTERN)
    metric_value: str | None = Field(default=None, max_length=768)
    threshold: str | None = Field(default=None, max_length=768)
    limitation: str = Field(max_length=MAX_TEXT)

    @model_validator(mode="after")
    def numeric_fields_are_bounded(self) -> ComparisonFinding:
        for value in (self.metric_value, self.threshold):
            if value is not None:
                parse_bounded_decimal(value)
        return self


class CrossBackendComparison(ResolutionModel):
    schema_id: Literal["omiv.cross-backend-comparison.v1"] = Field(
        default="omiv.cross-backend-comparison.v1", alias="schema"
    )
    comparison_id: str
    comparison_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    probe_set: ObjectReference
    runtime_bindings: tuple[ObjectReference, ...] = Field(min_length=2, max_length=256)
    result_observations: tuple[ObjectReference, ...] = Field(min_length=2, max_length=256)
    policy: ObjectReference | None = None
    status: BackendComparisonStatus
    findings: tuple[ComparisonFinding, ...] = Field(max_length=MAX_FINDINGS)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)


class InferenceIdentity(ResolutionModel):
    schema_id: Literal["omiv.inference-identity.v1"] = Field(
        default="omiv.inference-identity.v1", alias="schema"
    )
    inference_id: str
    inference_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    provider_context: str = Field(pattern=ID_PATTERN)
    requested_identifier: ObjectReference
    resolution_receipt: ObjectReference | None = None
    resolved_identifier: str | None = Field(default=None, max_length=256)
    runtime_binding: ObjectReference
    backend_execution: ObjectReference
    request: ContentIdentity
    tokenizer_configuration_identity: ObjectReference | None = None
    decoding_tool_configuration_digest: str = Field(pattern=SHA256_PATTERN)
    result_observation: ObjectReference
    output: ContentIdentity
    observed_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)


class InferenceAttestation(ResolutionModel):
    schema_id: Literal["omiv.inference-attestation.v1"] = Field(
        default="omiv.inference-attestation.v1", alias="schema"
    )
    attestation_id: str
    attestation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    issuer: str = Field(pattern=ID_PATTERN)
    signer_key_reference: str | None = Field(default=None, max_length=192)
    signature_report: ObjectReference | None = None
    purpose: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    inference_identity: ObjectReference
    runtime_binding: ObjectReference
    output_digest: str = Field(pattern=SHA256_PATTERN)
    method: AttestationMethod
    issued_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def signature_method_requires_signature_evidence(self) -> InferenceAttestation:
        signed = self.method == AttestationMethod.SERVICE_SIGNATURE
        supplied = self.signer_key_reference is not None and self.signature_report is not None
        if signed != supplied:
            raise ValueError("service-signature attestation requires key and signature report")
        return self


class ProofReference(ResolutionModel):
    scheme_identifier: str = Field(pattern=ID_PATTERN)
    scheme_version: str = Field(min_length=1, max_length=128)
    reference_digest: str = Field(pattern=SHA256_PATTERN)
    request_digest: str = Field(pattern=SHA256_PATTERN)
    output_digest: str = Field(pattern=SHA256_PATTERN)
    runtime_binding: ObjectReference
    verifier_identity: str | None = Field(default=None, max_length=192)
    verifier_version: str | None = Field(default=None, max_length=128)
    challenge_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    freshness_state: Literal["RECORDED", "UNAVAILABLE", "INVALID"]
    replay_state: Literal["RECORDED", "UNAVAILABLE", "INVALID"]
    authority: AuthorityStatus


class OutputProvenanceEvidence(ResolutionModel):
    schema_id: Literal["omiv.output-provenance-evidence.v1"] = Field(
        default="omiv.output-provenance-evidence.v1", alias="schema"
    )
    provenance_id: str
    provenance_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    output: ContentIdentity
    request_digest: str = Field(pattern=SHA256_PATTERN)
    inference_identity: ObjectReference
    inference_attestation: ObjectReference
    runtime_binding: ObjectReference
    claimed_weight_artifact_identity: ObjectReference | None = None
    proof_method: AttestationMethod
    proof_availability: ProofAvailability
    proof_reference: ProofReference | None = None
    verifier_availability: Literal["AVAILABLE", "NOT_AVAILABLE", "FORMAT_UNKNOWN"]
    verification_status: ProvenanceVerificationStatus
    verification_policy: ObjectReference
    authority_evaluation: ObjectReference
    authority: AuthorityStatus
    evaluated_at: ExplicitTime
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def no_fake_proof_substitution(self) -> OutputProvenanceEvidence:
        if (
            self.proof_method == AttestationMethod.SERVICE_SIGNATURE
            and self.verification_status
            in {
                ProvenanceVerificationStatus.PROVABLE_INFERENCE_NOT_IMPLEMENTED,
                ProvenanceVerificationStatus.PROVABLE_INFERENCE_FORMAT_UNAVAILABLE,
            }
        ):
            raise ValueError("service signature cannot be labeled as provable inference")
        if self.proof_availability == ProofAvailability.PROOF_OBJECT_AVAILABLE:
            raise ValueError("Phase 6E does not accept or simulate proof objects")
        if (
            self.verification_status == ProvenanceVerificationStatus.SERVICE_SIGNATURE_VERIFIED
            and self.proof_method != AttestationMethod.SERVICE_SIGNATURE
        ):
            raise ValueError("service-signature verification requires service-signature method")
        if self.verifier_availability == "AVAILABLE" and (
            self.proof_reference is None
            or self.proof_reference.verifier_identity is None
            or self.proof_reference.verifier_version is None
        ):
            raise ValueError("available verifier requires exact identity and version")
        if self.proof_availability == ProofAvailability.PROOF_REFERENCE_ONLY:
            if self.proof_reference is None:
                raise ValueError("proof-reference-only evidence requires a typed reference")
            if (
                self.proof_reference.request_digest != self.request_digest
                or self.proof_reference.output_digest != self.output.digest
                or self.proof_reference.runtime_binding != self.runtime_binding
            ):
                raise ValueError("proof reference does not bind exact request, output, and runtime")
        elif self.proof_reference is not None:
            raise ValueError("proof reference is only valid for reference-only availability")
        return self


class PolicyRequirement(ResolutionModel):
    requirement: str = Field(pattern=ID_PATTERN)
    status: RequirementStatus
    finding: str = Field(max_length=MAX_TEXT)


class RuntimeResolutionPolicy(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-policy.v1"] = Field(
        default="omiv.runtime-resolution-policy.v1", alias="schema"
    )
    policy_id: str
    policy_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    accepted_identifier_kinds: tuple[IdentifierKind, ...] = Field(min_length=1, max_length=16)
    pinned_identifier_required: bool
    mutable_alias_behavior: str = Field(pattern=ID_PATTERN)
    redirect_behavior: str = Field(pattern=ID_PATTERN)
    continuity_required: bool
    minimum_resolution_level: ObservationLevel
    maximum_resolution_age_seconds: int | None = Field(default=None, ge=0)
    minimum_runtime_strength: ObservationStrength
    exact_artifact_binding_required: bool
    tokenizer_configuration_required: bool
    quantization_required: bool
    required_dimensions: tuple[ResultDimension, ...] = Field(max_length=16)
    numerical_tolerance: str | None = Field(default=None, max_length=768)
    stochastic_behavior: str = Field(pattern=ID_PATTERN)
    minimum_probe_coverage: str = Field(max_length=768)
    required_request_availability: tuple[ContentAvailability, ...] = Field(
        min_length=1, max_length=4
    )
    required_output_availability: tuple[ContentAvailability, ...] = Field(
        min_length=1, max_length=4
    )
    output_provenance_required: bool
    accepted_attestation_methods: tuple[AttestationMethod, ...] = Field(max_length=16)
    accepted_verification_statuses: tuple[ProvenanceVerificationStatus, ...] = Field(max_length=16)
    freshness_behavior: str = Field(pattern=ID_PATTERN)
    replay_behavior: str = Field(pattern=ID_PATTERN)
    authority_required: bool
    historical_mode: Literal["KNOWN_AS_OF_CUTOFF"]
    missing_input_behavior: str = Field(pattern=ID_PATTERN)
    unsupported_method_behavior: str = Field(pattern=ID_PATTERN)
    evaluation_context: str = Field(pattern=ID_PATTERN)
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def canonical_decimals(self) -> RuntimeResolutionPolicy:
        parse_bounded_decimal(self.minimum_probe_coverage)
        if self.numerical_tolerance is not None:
            parse_bounded_decimal(self.numerical_tolerance)
        return self


class RuntimeResolutionPolicyEvaluation(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-policy-evaluation.v1"] = Field(
        default="omiv.runtime-resolution-policy-evaluation.v1", alias="schema"
    )
    evaluation_id: str
    evaluation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    policy: ObjectReference
    comparison: ObjectReference | None = None
    runtime_binding: ObjectReference
    output_provenance: ObjectReference | None = None
    requirements: tuple[PolicyRequirement, ...] = Field(min_length=1, max_length=1024)
    overall_status: RequirementStatus
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def conservative_overall_policy_state(self) -> RuntimeResolutionPolicyEvaluation:
        states = {requirement.status for requirement in self.requirements}
        expected = (
            RequirementStatus.INVALID
            if RequirementStatus.INVALID in states
            else RequirementStatus.FAILED
            if RequirementStatus.FAILED in states
            else RequirementStatus.NOT_EVALUATED
            if RequirementStatus.NOT_EVALUATED in states
            else RequirementStatus.SATISFIED
            if states == {RequirementStatus.SATISFIED}
            else RequirementStatus.NOT_APPLICABLE
        )
        if self.overall_status != expected:
            raise ValueError("policy overall state does not preserve all requirement states")
        return self


class AuthorityDimension(ResolutionModel):
    purpose: str = Field(pattern=ID_PATTERN)
    signer_trusted: bool
    authorized: bool
    status: AuthorityStatus
    subject_scope: str = Field(pattern=ID_PATTERN)
    authorized_subject_id: str = Field(min_length=3, max_length=192)
    evaluated_subject_id: str = Field(min_length=3, max_length=192)
    tenant: str = Field(pattern=ID_PATTERN)
    project: str = Field(pattern=ID_PATTERN)
    provider: str = Field(pattern=ID_PATTERN)
    namespace: str = Field(pattern=ID_PATTERN)
    trust_domain: str = Field(pattern=ID_PATTERN)
    context: str = Field(pattern=ID_PATTERN)
    finding: str = Field(max_length=MAX_TEXT)

    @model_validator(mode="after")
    def authority_state_matches_scope(self) -> AuthorityDimension:
        same_subject = self.authorized_subject_id == self.evaluated_subject_id
        if not same_subject and self.status not in {
            AuthorityStatus.SCOPE_MISMATCH,
            AuthorityStatus.NOT_ESTABLISHED,
        }:
            raise ValueError("cross-subject authority must remain a scope mismatch")
        if self.status == AuthorityStatus.ESTABLISHED and not (
            self.signer_trusted and self.authorized and same_subject
        ):
            raise ValueError("established authority requires trust, purpose, and exact subject")
        return self


class RuntimeResolutionAuthorityEvaluation(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-authority-evaluation.v1"] = Field(
        default="omiv.runtime-resolution-authority-evaluation.v1", alias="schema"
    )
    evaluation_id: str
    evaluation_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    policy: ObjectReference
    purposes: tuple[AuthorityDimension, ...] = Field(max_length=64)
    overall_status: AuthorityStatus
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def conservative_overall_authority_state(self) -> RuntimeResolutionAuthorityEvaluation:
        states = {purpose.status for purpose in self.purposes}
        expected = (
            AuthorityStatus.INVALID
            if AuthorityStatus.INVALID in states
            else AuthorityStatus.SCOPE_MISMATCH
            if AuthorityStatus.SCOPE_MISMATCH in states
            else AuthorityStatus.NOT_ESTABLISHED
            if AuthorityStatus.NOT_ESTABLISHED in states
            else AuthorityStatus.NOT_EVALUATED
            if not states or AuthorityStatus.NOT_EVALUATED in states
            else AuthorityStatus.ESTABLISHED
        )
        if self.overall_status != expected:
            raise ValueError("authority overall state does not preserve all purpose states")
        return self


class RuntimeResolutionParityEvidence(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-parity-evidence.v1"] = Field(
        default="omiv.runtime-resolution-parity-evidence.v1", alias="schema"
    )
    evidence_id: str
    evidence_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    continuity: ObjectReference
    runtime_binding: ObjectReference
    comparison: ObjectReference
    output_provenance: ObjectReference
    policy_evaluation: ObjectReference
    authority_evaluation: ObjectReference
    status: EvidenceStatus
    coverage: tuple[CoverageDimension, ...] = Field(max_length=64)
    limitations: tuple[str, ...] = Field(max_length=64)


class RuntimeResolutionIntegrationSummary(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-integration-summary.v1"] = Field(
        default="omiv.runtime-resolution-integration-summary.v1", alias="schema"
    )
    integration_id: str
    integration_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    phase: str = Field(pattern=ID_PATTERN)
    evidence: ObjectReference
    upstream: ObjectReference | None = None
    state: str = Field(pattern=ID_PATTERN)
    authority: AuthorityStatus
    limitations: tuple[str, ...] = Field(max_length=32)


class AssumptionRegisterEntry(ResolutionModel):
    schema_id: Literal["omiv.assumption-register-entry.v1"] = Field(
        default="omiv.assumption-register-entry.v1", alias="schema"
    )
    assumption_id: str
    assumption_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    statement: str = Field(min_length=1, max_length=MAX_TEXT)
    prior_status: AssumptionStatus
    status: AssumptionStatus
    evidence_references: tuple[ObjectReference, ...] = Field(max_length=64)
    evidence_strength: ObservationLevel
    affected_trust_boundary: str = Field(pattern=ID_PATTERN)
    affected_schemas: tuple[str, ...] = Field(max_length=64)
    affected_policies: tuple[ObjectReference, ...] = Field(max_length=64)
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    supplied_at: ExplicitTime
    supersession: ObjectReference | None = None
    basis: str = Field(min_length=1, max_length=MAX_TEXT)
    consequence: str = Field(min_length=1, max_length=MAX_TEXT)
    remediation: str = Field(min_length=1, max_length=MAX_TEXT)
    authority: AuthorityStatus
    limitations: tuple[str, ...] = Field(max_length=32)


class RuntimeResolutionReport(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-report.v1"] = Field(
        default="omiv.runtime-resolution-report.v1", alias="schema"
    )
    report_id: str
    report_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    evidence: ObjectReference
    title: str = Field(min_length=1, max_length=256)
    status: EvidenceStatus
    total_findings: int = Field(ge=0)
    included_findings: int = Field(ge=0)
    omitted_findings: int = Field(ge=0)
    inclusion_rule: str = Field(pattern=ID_PATTERN)
    truncation_status: Literal["NOT_TRUNCATED", "DETERMINISTICALLY_TRUNCATED"]
    findings: tuple[str, ...] = Field(max_length=4096)
    limitations: tuple[str, ...] = Field(max_length=32)


class RuntimeResolutionScenarioResult(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-scenario-result.v1"] = Field(
        default="omiv.runtime-resolution-scenario-result.v1", alias="schema"
    )
    result_id: str
    result_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    case_id: str = Field(pattern=ID_PATTERN)
    exercised_invariant: str = Field(min_length=1, max_length=MAX_TEXT)
    outcome: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    findings: tuple[str, ...] = Field(max_length=64)
    upstream_objects: tuple[ObjectReference, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)


class RuntimeResolutionScenarioCatalog(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-scenario-catalog.v1"] = Field(
        default="omiv.runtime-resolution-scenario-catalog.v1", alias="schema"
    )
    catalog_id: str
    catalog_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    classification: Literal[
        "COMPLETE_AS_PROVIDER_NEUTRAL_RUNTIME_RESOLUTION_DEPLOYMENT_BINDING_AND_CROSS_BACKEND_PARITY_EVIDENCE_FOUNDATION_WITH_EXPLICIT_OBSERVATION_AND_PROVABLE_INFERENCE_LIMITATIONS"
    ]
    scenarios: tuple[ObjectReference, ...] = Field(min_length=42, max_length=64)
    limitations: tuple[str, ...] = Field(max_length=64)


class RuntimeResolutionArtifactIndexEntry(ResolutionModel):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str = Field(pattern=SCHEMA_PATTERN)
    canonical_id: str = Field(min_length=3, max_length=192)

    @field_validator("path")
    @classmethod
    def portable_path(cls, value: str) -> str:
        return validate_portable_path(value)


class RuntimeResolutionArtifactIndex(ResolutionModel):
    schema_id: Literal["omiv.runtime-resolution-artifact-index.v1"] = Field(
        default="omiv.runtime-resolution-artifact-index.v1", alias="schema"
    )
    index_id: str
    index_digest: str
    subject: ProductSubject
    scope: str = Field(pattern=ID_PATTERN)
    entries: tuple[RuntimeResolutionArtifactIndexEntry, ...] = Field(max_length=MAX_INDEX_ENTRIES)
    total_size: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def external_unique_index(self) -> RuntimeResolutionArtifactIndex:
        paths = tuple(entry.path for entry in self.entries)
        validate_path_set(paths)
        if "runtime-resolution-parity/artifact-index.json" in paths:
            raise ValueError("external runtime-resolution index must exclude itself")
        if len({entry.canonical_id for entry in self.entries}) != len(self.entries):
            raise ValueError("duplicate canonical identity in artifact index")
        if sum(entry.size for entry in self.entries) != self.total_size:
            raise ValueError("artifact index total size mismatch")
        return self


def finalize_identity(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    value = _json_compatible(body)
    if not isinstance(value, dict):
        raise TypeError("canonical body must be an object")
    object_id = prefix + canonical_sha256(value)[:32]
    with_id = {**value, id_field: object_id}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def object_reference(value: BaseModel) -> ObjectReference:
    body = value.model_dump(mode="json", by_alias=True)
    schema = str(body["schema"])
    spec = IDENTITY_SPECS.get(schema)
    if spec is None:
        id_fields = [key for key in body if key.endswith("_id")]
        digest_fields = [key for key in body if key.endswith("_digest")]
        if len(id_fields) != 1 or len(digest_fields) != 1:
            raise ValueError("canonical object does not expose one identity pair")
        id_field, digest_field = id_fields[0], digest_fields[0]
    else:
        id_field, digest_field, _prefix = spec
    return ObjectReference(
        schema_id=schema,
        object_id=str(body[id_field]),
        object_digest=str(body[digest_field]),
    )


def verify_object_reference(reference: ObjectReference, value: BaseModel) -> None:
    if reference != object_reference(value):
        raise ValueError("canonical object reference does not match supplied object")


def content_identity(
    value: str | None,
    *,
    availability: ContentAvailability,
    canonicalization_mode: str,
    media_type: str,
    encoding: str = "utf-8",
    digest: str | None = None,
    length: int | None = None,
    streaming: str = "final.aggregate",
    scope: str = "declared.content",
) -> ContentIdentity:
    if availability == ContentAvailability.INLINE_SYNTHETIC:
        if value is None:
            raise ValueError("inline synthetic content is required")
        raw = value.encode(encoding)
        digest = canonical_sha256(
            {
                "domain": "omiv.content-identity.v1",
                "canonicalization_mode": canonicalization_mode,
                "media_type": media_type,
                "encoding": encoding,
                "raw_hex": raw.hex(),
                "streaming_aggregate_semantics": streaming,
            }
        )
        length = len(raw)
    return ContentIdentity(
        availability=availability,
        canonicalization_mode=canonicalization_mode,
        media_type=media_type,
        encoding=encoding,
        length=length,
        digest_algorithm="SHA256",
        digest=digest,
        inline_synthetic=value,
        streaming_aggregate_semantics=streaming,
        scope=scope,
        coverage=(
            "COMPLETE_CONTENT"
            if availability == ContentAvailability.INLINE_SYNTHETIC
            else "DIGEST_IDENTITY_ONLY"
            if availability == ContentAvailability.DIGEST_ONLY
            else "CONTENT_UNAVAILABLE"
        ),
        reproducibility=(
            ReproducibilityState.INLINE_SYNTHETIC_REPRODUCIBLE
            if availability == ContentAvailability.INLINE_SYNTHETIC
            else ReproducibilityState.DIGEST_ONLY_NOT_INDEPENDENTLY_REPRODUCIBLE
            if availability == ContentAvailability.DIGEST_ONLY
            else ReproducibilityState.CONTENT_UNAVAILABLE
            if availability == ContentAvailability.UNAVAILABLE
            else ReproducibilityState.INVALID
        ),
    )


def canonical_probe_id(body: dict[str, Any]) -> str:
    return (
        "backend_probe_"
        + canonical_sha256(
            {"domain": "omiv.backend-probe-definition.v1", "definition": _json_compatible(body)}
        )[:32]
    )


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return {str(key): _json_compatible(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_compatible(child) for child in value]
    return value
