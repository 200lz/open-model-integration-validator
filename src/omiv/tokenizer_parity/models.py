"""Strict canonical models for Phase 6D tokenizer/configuration parity evidence."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
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
from omiv.runtime.models import ProductSubject, ScopeContext

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,159}$"
HEX_PATTERN = r"^(?:[0-9a-f]{2})*$"
MAX_TEXT = 8192
MAX_FINDINGS = 250_000
MAX_INDEX_ENTRIES = 160
MAX_DECIMAL_DIGITS = 100
MAX_DECIMAL_EXPONENT = 308
ExplicitTime = Annotated[
    str,
    StringConstraints(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    ),
]


class ExpectationMode(StrEnum):
    EMBEDDED_EXPECTATION = "EMBEDDED_EXPECTATION"
    REFERENCED_EXPECTATION = "REFERENCED_EXPECTATION"


class ExpectationAvailability(StrEnum):
    FULL_EXPECTATION_AVAILABLE = "FULL_EXPECTATION_AVAILABLE"
    DIGEST_REFERENCE_ONLY = "DIGEST_REFERENCE_ONLY"
    EXPECTATION_UNAVAILABLE = "EXPECTATION_UNAVAILABLE"
    EXPECTATION_INVALID = "EXPECTATION_INVALID"


class ArtifactAvailability(StrEnum):
    EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE = "EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE"
    REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE = "REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE"
    REMOTE_NON_PAYLOAD_IDENTITY_ONLY = "REMOTE_NON_PAYLOAD_IDENTITY_ONLY"
    METADATA_IDENTITY_ONLY = "METADATA_IDENTITY_ONLY"
    DIGEST_REFERENCE_ONLY = "DIGEST_REFERENCE_ONLY"
    ARTIFACT_NOT_SUPPLIED = "ARTIFACT_NOT_SUPPLIED"
    IDENTITY_UNAVAILABLE = "IDENTITY_UNAVAILABLE"
    IDENTITY_INVALID = "IDENTITY_INVALID"


class AssetRole(StrEnum):
    REFERENCE = "REFERENCE"
    CANDIDATE = "CANDIDATE"


class AssetKind(StrEnum):
    MODEL_CONFIG = "MODEL_CONFIG"
    GENERATION_CONFIG = "GENERATION_CONFIG"
    TOKENIZER_CONFIG = "TOKENIZER_CONFIG"
    SPECIAL_TOKENS_MAP = "SPECIAL_TOKENS_MAP"
    ADDED_TOKENS = "ADDED_TOKENS"
    VOCABULARY = "VOCABULARY"
    MERGE_TABLE = "MERGE_TABLE"
    TOKENIZER_PIPELINE = "TOKENIZER_PIPELINE"
    CHAT_TEMPLATE = "CHAT_TEMPLATE"
    OTHER_DECLARED = "OTHER_DECLARED"


class PresenceState(StrEnum):
    EXPLICIT_VALUE = "EXPLICIT_VALUE"
    EXPLICIT_NULL = "EXPLICIT_NULL"
    ABSENT = "ABSENT"
    DEFAULTED_BY_EXPLICIT_POLICY = "DEFAULTED_BY_EXPLICIT_POLICY"
    INFERRED_NON_AUTHORITATIVELY = "INFERRED_NON_AUTHORITATIVELY"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class CanonicalValueType(StrEnum):
    BOOLEAN = "BOOLEAN"
    INTEGER = "INTEGER"
    DECIMAL = "DECIMAL"
    STRING = "STRING"
    INTEGER_LIST = "INTEGER_LIST"
    STRING_LIST = "STRING_LIST"
    TYPED_OBJECT_DIGEST = "TYPED_OBJECT_DIGEST"
    EXPLICIT_NULL = "EXPLICIT_NULL"


class TokenContentEncoding(StrEnum):
    UNICODE_TEXT = "UNICODE_TEXT"
    BYTE_SEQUENCE = "BYTE_SEQUENCE"


class TokenClassification(StrEnum):
    REGULAR = "REGULAR"
    ADDED = "ADDED"
    SPECIAL = "SPECIAL"
    NOT_DECLARED = "NOT_DECLARED"


class SpecialTokenRole(StrEnum):
    BOS = "BOS"
    EOS = "EOS"
    PAD = "PAD"
    UNK = "UNK"
    MASK = "MASK"
    SEP = "SEP"
    CLS = "CLS"
    ADDITIONAL_SPECIAL = "ADDITIONAL_SPECIAL"
    MODEL_DEFINED = "MODEL_DEFINED"
    ABSENT_ROLE = "ABSENT_ROLE"


class PipelineComponentKind(StrEnum):
    NORMALIZER = "NORMALIZER"
    PRE_TOKENIZER = "PRE_TOKENIZER"
    MODEL = "MODEL"
    POST_PROCESSOR = "POST_PROCESSOR"
    DECODER = "DECODER"
    CLEANUP = "CLEANUP"
    UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"


class ComponentSupportState(StrEnum):
    STRUCTURALLY_OBSERVED = "STRUCTURALLY_OBSERVED"
    PARAMETERS_PARTIALLY_OBSERVED = "PARAMETERS_PARTIALLY_OBSERVED"
    OPAQUE_COMPONENT = "OPAQUE_COMPONENT"
    UNSUPPORTED_COMPONENT = "UNSUPPORTED_COMPONENT"
    NOT_OBSERVED = "NOT_OBSERVED"
    INVALID = "INVALID"


class ProbeKind(StrEnum):
    ENCODE_TEXT_TO_TOKEN_IDS = "ENCODE_TEXT_TO_TOKEN_IDS"
    DECODE_TOKEN_IDS_TO_TEXT = "DECODE_TOKEN_IDS_TO_TEXT"
    CHAT_TEMPLATE_RENDER = "CHAT_TEMPLATE_RENDER"
    SPECIAL_TOKEN_INSERTION = "SPECIAL_TOKEN_INSERTION"
    ROUND_TRIP = "ROUND_TRIP"
    NORMALIZATION_BOUNDARY = "NORMALIZATION_BOUNDARY"


class ProbeInputAvailability(StrEnum):
    INLINE_SYNTHETIC_INPUT = "INLINE_SYNTHETIC_INPUT"
    DIGEST_ONLY_INPUT = "DIGEST_ONLY_INPUT"
    INPUT_UNAVAILABLE = "INPUT_UNAVAILABLE"


class ProbeOutputAvailability(StrEnum):
    INLINE_SYNTHETIC_OUTPUT = "INLINE_SYNTHETIC_OUTPUT"
    DIGEST_ONLY_OUTPUT = "DIGEST_ONLY_OUTPUT"
    OUTPUT_UNAVAILABLE = "OUTPUT_UNAVAILABLE"


class VocabularyCardinalityBasis(StrEnum):
    RECORD_COUNT = "RECORD_COUNT"
    DISTINCT_TOKEN_COUNT = "DISTINCT_TOKEN_COUNT"
    DISTINCT_ID_COUNT = "DISTINCT_ID_COUNT"
    MAX_ID_PLUS_ONE = "MAX_ID_PLUS_ONE"
    BASE_VOCABULARY_COUNT = "BASE_VOCABULARY_COUNT"
    TOTAL_WITH_ADDED_TOKENS = "TOTAL_WITH_ADDED_TOKENS"


class ProbeComparisonStatus(StrEnum):
    EXACT_FOR_DECLARED_PROBES = "EXACT_FOR_DECLARED_PROBES"
    MISMATCH_FOR_DECLARED_PROBES = "MISMATCH_FOR_DECLARED_PROBES"
    PARTIAL_PROBE_PARITY = "PARTIAL_PROBE_PARITY"
    DIGEST_ONLY_NOT_REPRODUCIBLE = "DIGEST_ONLY_NOT_REPRODUCIBLE"
    PROBE_RESULT_UNAVAILABLE = "PROBE_RESULT_UNAVAILABLE"
    PROBE_NOT_COMPARABLE = "PROBE_NOT_COMPARABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class ParityScope(StrEnum):
    COMPLETE_DECLARED_TOKENIZER_ASSET_SET = "COMPLETE_DECLARED_TOKENIZER_ASSET_SET"
    COMPLETE_DECLARED_CONFIGURATION = "COMPLETE_DECLARED_CONFIGURATION"
    SELECTED_REQUIRED_ASSETS = "SELECTED_REQUIRED_ASSETS"
    SELECTED_REQUIRED_FIELDS = "SELECTED_REQUIRED_FIELDS"
    SELECTED_REQUIRED_FIELD_GROUPS = "SELECTED_REQUIRED_FIELD_GROUPS"
    SELECTED_REQUIRED_SPECIAL_TOKENS = "SELECTED_REQUIRED_SPECIAL_TOKENS"
    SELECTED_REQUIRED_PROBES = "SELECTED_REQUIRED_PROBES"
    PARTIAL_REFERENCE_SET = "PARTIAL_REFERENCE_SET"


class ConfigurationStatus(StrEnum):
    EXACT_RAW_BYTES_FOR_SCOPE = "EXACT_RAW_BYTES_FOR_SCOPE"
    CANONICAL_JSON_EQUAL_FOR_SCOPE = "CANONICAL_JSON_EQUAL_FOR_SCOPE"
    FIELD_PARITY_FOR_DECLARED_SCOPE = "FIELD_PARITY_FOR_DECLARED_SCOPE"
    FIELD_MISMATCH = "FIELD_MISMATCH"
    INCOMPLETE_CONFIGURATION_EVIDENCE = "INCOMPLETE_CONFIGURATION_EVIDENCE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class OverallParityStatus(StrEnum):
    PARITY_ESTABLISHED_FOR_DECLARED_SCOPE = "PARITY_ESTABLISHED_FOR_DECLARED_SCOPE"
    MISMATCH_FOR_DECLARED_SCOPE = "MISMATCH_FOR_DECLARED_SCOPE"
    PARTIAL_PARITY = "PARTIAL_PARITY"
    INDETERMINATE = "INDETERMINATE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class RequirementStatus(StrEnum):
    POLICY_REQUIREMENT_SATISFIED = "POLICY_REQUIREMENT_SATISFIED"
    POLICY_REQUIREMENT_FAILED = "POLICY_REQUIREMENT_FAILED"
    POLICY_REQUIREMENT_NOT_EVALUATED = "POLICY_REQUIREMENT_NOT_EVALUATED"
    POLICY_REQUIREMENT_NOT_APPLICABLE = "POLICY_REQUIREMENT_NOT_APPLICABLE"
    POLICY_REQUIREMENT_INVALID = "POLICY_REQUIREMENT_INVALID"


class AuthorityStatus(StrEnum):
    ESTABLISHED = "ESTABLISHED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    NOT_EVALUATED = "NOT_EVALUATED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    INVALID = "INVALID"


class DenominatorState(StrEnum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class FindingStatus(StrEnum):
    OBSERVED = "OBSERVED"
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    ALLOWED_DIFFERENCE = "ALLOWED_DIFFERENCE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INVALID = "INVALID"


class ParityDimension(StrEnum):
    ASSET_SET = "ASSET_SET"
    RAW_BYTES = "RAW_BYTES"
    CANONICAL_JSON = "CANONICAL_JSON"
    CONFIGURATION_FIELDS = "CONFIGURATION_FIELDS"
    VOCABULARY_TOKEN_TO_ID = "VOCABULARY_TOKEN_TO_ID"
    VOCABULARY_ID_TO_TOKEN = "VOCABULARY_ID_TO_TOKEN"
    MERGE_ORDER = "MERGE_ORDER"
    ADDED_TOKEN_PROPERTIES = "ADDED_TOKEN_PROPERTIES"
    SPECIAL_TOKEN_ROLES = "SPECIAL_TOKEN_ROLES"
    TOKENIZER_PIPELINE = "TOKENIZER_PIPELINE"
    CHAT_TEMPLATE = "CHAT_TEMPLATE"
    ENCODE_PROBES = "ENCODE_PROBES"
    DECODE_PROBES = "DECODE_PROBES"
    TEMPLATE_RENDER_PROBES = "TEMPLATE_RENDER_PROBES"
    CROSS_ASSET_CONSISTENCY = "CROSS_ASSET_CONSISTENCY"
    AUTHORITY = "AUTHORITY"
    COVERAGE = "COVERAGE"


class CrossAssetStatus(StrEnum):
    CONSISTENT_FOR_DECLARED_RULE = "CONSISTENT_FOR_DECLARED_RULE"
    INCONSISTENT_FOR_DECLARED_RULE = "INCONSISTENT_FOR_DECLARED_RULE"
    REQUIRED_INPUT_MISSING = "REQUIRED_INPUT_MISSING"
    RULE_NOT_APPLICABLE = "RULE_NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


IDENTITY_SPECS: dict[str, tuple[str, str, str]] = {
    "omiv.tokenizer-configuration-expectation.v1": (
        "expectation_id",
        "expectation_digest",
        "tokenizer_expectation_",
    ),
    "omiv.tokenizer-configuration-parity-declaration.v1": (
        "declaration_id",
        "declaration_digest",
        "tokenizer_declaration_",
    ),
    "omiv.tokenizer-configuration-inspection-plan.v1": (
        "plan_id",
        "plan_digest",
        "tokenizer_plan_",
    ),
    "omiv.tokenizer-configuration-execution-record.v1": (
        "execution_id",
        "execution_digest",
        "tokenizer_execution_",
    ),
    "omiv.configuration-observation.v1": (
        "observation_id",
        "observation_digest",
        "config_observation_",
    ),
    "omiv.tokenizer-asset-observation.v1": (
        "observation_id",
        "observation_digest",
        "tokenizer_asset_",
    ),
    "omiv.vocabulary-observation.v1": (
        "observation_id",
        "observation_digest",
        "vocabulary_observation_",
    ),
    "omiv.merge-table-observation.v1": (
        "observation_id",
        "observation_digest",
        "merge_observation_",
    ),
    "omiv.added-token-observation.v1": (
        "observation_id",
        "observation_digest",
        "added_token_observation_",
    ),
    "omiv.special-token-observation.v1": (
        "observation_id",
        "observation_digest",
        "special_token_observation_",
    ),
    "omiv.tokenizer-pipeline-observation.v1": (
        "observation_id",
        "observation_digest",
        "pipeline_observation_",
    ),
    "omiv.chat-template-observation.v1": (
        "observation_id",
        "observation_digest",
        "template_observation_",
    ),
    "omiv.tokenizer-probe-set-definition.v1": (
        "probe_set_id",
        "probe_set_digest",
        "tokenizer_probe_set_",
    ),
    "omiv.tokenizer-probe-execution-record.v1": (
        "execution_id",
        "execution_digest",
        "tokenizer_probe_execution_",
    ),
    "omiv.tokenizer-probe-result-observation.v1": (
        "observation_id",
        "observation_digest",
        "tokenizer_probe_results_",
    ),
    "omiv.tokenizer-configuration-comparison.v1": (
        "comparison_id",
        "comparison_digest",
        "tokenizer_comparison_",
    ),
    "omiv.tokenizer-configuration-policy.v1": ("policy_id", "policy_digest", "tokenizer_policy_"),
    "omiv.tokenizer-configuration-policy-evaluation.v1": (
        "evaluation_id",
        "evaluation_digest",
        "tokenizer_policy_evaluation_",
    ),
    "omiv.tokenizer-configuration-authority-evaluation.v1": (
        "authority_evaluation_id",
        "authority_evaluation_digest",
        "tokenizer_authority_",
    ),
    "omiv.tokenizer-configuration-parity-evidence.v1": (
        "evidence_id",
        "evidence_digest",
        "tokenizer_evidence_",
    ),
    "omiv.tokenizer-configuration-integration-summary.v1": (
        "integration_id",
        "integration_digest",
        "tokenizer_integration_",
    ),
    "omiv.tokenizer-configuration-report.v1": ("report_id", "report_digest", "tokenizer_report_"),
    "omiv.tokenizer-configuration-scenario-result.v1": (
        "result_id",
        "result_digest",
        "tokenizer_scenario_",
    ),
    "omiv.tokenizer-configuration-scenario-catalog.v1": (
        "catalog_id",
        "catalog_digest",
        "tokenizer_catalog_",
    ),
    "omiv.tokenizer-configuration-artifact-index.v1": (
        "index_id",
        "index_digest",
        "tokenizer_index_",
    ),
}


class ParityModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def canonical_identity(self) -> ParityModel:
        body = self.model_dump(mode="json", by_alias=True)
        schema = body.get("schema")
        if not isinstance(schema, str):
            return self
        spec = IDENTITY_SPECS.get(schema)
        if spec is None:
            return self
        id_field, digest_field, prefix = spec
        digest = body.pop(digest_field)
        object_id = body.pop(id_field)
        expected = prefix + canonical_sha256(body)[:32]
        if object_id != expected or digest != canonical_sha256({**body, id_field: expected}):
            raise ValueError("canonical identity or digest mismatch")
        return self


class ObjectReference(ParityModel):
    schema_id: str = Field(pattern=r"^omiv\.[a-z0-9.-]+\.v[0-9]+$")
    object_id: str = Field(min_length=3, max_length=192)
    object_digest: str = Field(pattern=SHA256_PATTERN)


class CanonicalValue(ParityModel):
    value_type: CanonicalValueType
    boolean_value: bool | None = None
    integer_value: int | None = None
    decimal_value: str | None = Field(default=None, max_length=256)
    string_value: str | None = Field(default=None, max_length=MAX_TEXT)
    integer_list: tuple[int, ...] | None = Field(default=None, max_length=4096)
    string_list: tuple[str, ...] | None = Field(default=None, max_length=4096)
    object_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def exactly_one_typed_value(self) -> CanonicalValue:
        populated = {
            "boolean": self.boolean_value is not None,
            "integer": self.integer_value is not None,
            "decimal": self.decimal_value is not None,
            "string": self.string_value is not None,
            "integer_list": self.integer_list is not None,
            "string_list": self.string_list is not None,
            "object_digest": self.object_digest is not None,
        }
        expected = {
            CanonicalValueType.BOOLEAN: "boolean",
            CanonicalValueType.INTEGER: "integer",
            CanonicalValueType.DECIMAL: "decimal",
            CanonicalValueType.STRING: "string",
            CanonicalValueType.INTEGER_LIST: "integer_list",
            CanonicalValueType.STRING_LIST: "string_list",
            CanonicalValueType.TYPED_OBJECT_DIGEST: "object_digest",
        }.get(self.value_type)
        if self.value_type == CanonicalValueType.EXPLICIT_NULL:
            if any(populated.values()):
                raise ValueError("explicit null cannot carry a value")
        elif expected is None or not populated[expected] or sum(populated.values()) != 1:
            raise ValueError("canonical configuration value does not match its declared type")
        if self.decimal_value is not None:
            _validate_decimal(self.decimal_value)
        return self

    @field_validator("integer_value", mode="before")
    @classmethod
    def bounded_integer(cls, value: Any) -> Any:
        if value is not None and (
            type(value) is not int or len(str(abs(value))) > MAX_DECIMAL_DIGITS
        ):
            raise ValueError("LIMIT_EXCEEDED:INTEGER_DIGITS")
        return value

    @field_validator("integer_list", mode="before")
    @classmethod
    def bounded_integer_list(cls, value: Any) -> Any:
        if value is not None and any(
            type(item) is not int or len(str(abs(item))) > MAX_DECIMAL_DIGITS for item in value
        ):
            raise ValueError("invalid or excessive integer-list value")
        return value


class TokenContent(ParityModel):
    encoding: TokenContentEncoding
    unicode_text: str | None = Field(default=None, max_length=4096)
    bytes_hex: str | None = Field(default=None, pattern=HEX_PATTERN, max_length=8192)

    @model_validator(mode="after")
    def exact_encoding(self) -> TokenContent:
        if self.encoding == TokenContentEncoding.UNICODE_TEXT:
            if self.unicode_text is None or self.bytes_hex is not None:
                raise ValueError("Unicode token requires only unicode_text")
            _validate_unicode_scalars(self.unicode_text)
        elif self.bytes_hex is None or self.unicode_text is not None:
            raise ValueError("byte token requires only canonical lowercase hex")
        return self


class ArtifactBinding(ParityModel):
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    role: AssetRole
    asset_kind: AssetKind
    provider: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=256)
    requested_revision: str | None = Field(default=None, max_length=512)
    resolved_revision: str | None = Field(default=None, max_length=512)
    phase6a_manifest: ObjectReference | None = None
    phase6b_snapshot: ObjectReference | None = None
    phase6c_evidence: ObjectReference | None = None
    artifact_set_identity: str | None = Field(default=None, pattern=SHA256_PATTERN)
    logical_root: str = Field(pattern=ID_PATTERN)
    asset_path: str
    file_size: int | None = Field(default=None, ge=0)
    payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    coverage: str = Field(pattern=ID_PATTERN)
    availability: ArtifactAvailability
    limitations: tuple[str, ...] = Field(max_length=64)

    @field_validator("asset_path")
    @classmethod
    def portable_asset_path(cls, value: str) -> str:
        return validate_portable_path(value)

    @model_validator(mode="after")
    def exact_binding_requirements(self) -> ArtifactBinding:
        if self.availability == ArtifactAvailability.EXACT_LOCAL_PAYLOAD_IDENTITY_AVAILABLE and any(
            value is None
            for value in (
                self.phase6a_manifest,
                self.artifact_set_identity,
                self.file_size,
                self.payload_sha256,
            )
        ):
            raise ValueError("exact local asset identity requires Phase 6A and payload identity")
        if (
            self.availability == ArtifactAvailability.REMOTE_PAYLOAD_COMPARABLE_IDENTITY_AVAILABLE
            and (self.phase6b_snapshot is None or self.payload_sha256 is None)
        ):
            raise ValueError(
                "remote payload-comparable identity requires established payload digest"
            )
        if (
            self.availability == ArtifactAvailability.REMOTE_NON_PAYLOAD_IDENTITY_ONLY
            and self.payload_sha256 is not None
        ):
            raise ValueError("non-payload remote identity cannot carry payload SHA-256")
        return self


class ExpectationReference(ParityModel):
    reference: ObjectReference | None = None
    object_supplied_and_verified: bool
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    provider: str | None = Field(default=None, max_length=128)
    namespace: str | None = Field(default=None, max_length=256)
    scope: ParityScope
    authority_status: AuthorityStatus
    availability: ExpectationAvailability
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def availability_binding(self) -> ExpectationReference:
        if self.availability == ExpectationAvailability.FULL_EXPECTATION_AVAILABLE and (
            self.reference is None or not self.object_supplied_and_verified
        ):
            raise ValueError(
                "full expectation availability requires supplied canonical expectation"
            )
        if self.availability == ExpectationAvailability.DIGEST_REFERENCE_ONLY and (
            self.reference is None or self.object_supplied_and_verified
        ):
            raise ValueError(
                "digest-only expectation requires an identity reference without a supplied object"
            )
        if (
            self.availability
            in {
                ExpectationAvailability.EXPECTATION_UNAVAILABLE,
                ExpectationAvailability.EXPECTATION_INVALID,
            }
            and self.object_supplied_and_verified
        ):
            raise ValueError("unavailable or invalid expectation cannot be verified as supplied")
        return self


class TokenizerConfigurationLimits(ParityModel):
    maximum_asset_files: int = Field(default=256, ge=1, le=4096)
    maximum_bytes_per_asset: int = Field(default=64 * 1024 * 1024, ge=1024)
    maximum_total_asset_bytes: int = Field(default=256 * 1024 * 1024, ge=1024)
    maximum_json_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    maximum_json_nesting: int = Field(default=64, ge=1, le=128)
    maximum_json_members: int = Field(default=500_000, ge=1, le=1_000_000)
    maximum_string_length: int = Field(default=MAX_TEXT, ge=64, le=65536)
    maximum_numeric_digits: int = Field(default=MAX_DECIMAL_DIGITS, ge=1, le=1000)
    maximum_numeric_exponent: int = Field(default=MAX_DECIMAL_EXPONENT, ge=1, le=10000)
    maximum_configuration_fields: int = Field(default=10_000, ge=1, le=100_000)
    maximum_field_path_length: int = Field(default=512, ge=16, le=4096)
    maximum_vocabulary_entries: int = Field(default=250_000, ge=1, le=1_000_000)
    maximum_token_id: int = Field(default=2_147_483_647, ge=0)
    maximum_token_content_units: int = Field(default=4096, ge=1, le=65536)
    maximum_merge_records: int = Field(default=250_000, ge=1, le=1_000_000)
    maximum_merge_operand_size: int = Field(default=4096, ge=1, le=65536)
    maximum_added_tokens: int = Field(default=100_000, ge=1, le=250_000)
    maximum_special_tokens: int = Field(default=4096, ge=1, le=65536)
    maximum_pipeline_components: int = Field(default=256, ge=1, le=4096)
    maximum_component_parameters: int = Field(default=4096, ge=1, le=65536)
    maximum_chat_template_bytes: int = Field(default=1024 * 1024, ge=1)
    maximum_probe_definitions: int = Field(default=10_000, ge=1, le=100_000)
    maximum_probe_input_bytes: int = Field(default=1024 * 1024, ge=1)
    maximum_token_ids_per_probe: int = Field(default=100_000, ge=1, le=1_000_000)
    maximum_total_probe_token_ids: int = Field(default=1_000_000, ge=1)
    maximum_probe_output_bytes: int = Field(default=4 * 1024 * 1024, ge=1)
    maximum_findings: int = Field(default=MAX_FINDINGS, ge=1, le=MAX_FINDINGS)
    maximum_report_nodes: int = Field(default=250_000, ge=1)
    maximum_dependency_nodes: int = Field(default=250_000, ge=1)
    maximum_dependency_edges: int = Field(default=1_000_000, ge=1)
    maximum_dependency_depth: int = Field(default=128, ge=1, le=1024)
    maximum_generated_files: int = Field(default=160, ge=1, le=160)
    maximum_generated_metadata_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)


class CoverageDimension(ParityModel):
    dimension: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,95}$")
    numerator: int = Field(ge=0)
    denominator: int | None = Field(default=None, ge=0)
    denominator_state: DenominatorState
    selected_scope: ParityScope
    incomplete_reason: str | None = Field(default=None, max_length=MAX_TEXT)

    @model_validator(mode="after")
    def denominator_semantics(self) -> CoverageDimension:
        if self.denominator_state == DenominatorState.UNAVAILABLE and self.denominator is not None:
            raise ValueError("unavailable denominator must remain unknown")
        if self.denominator_state == DenominatorState.AVAILABLE and self.denominator is None:
            raise ValueError("available denominator requires exact count")
        if self.denominator is not None and self.numerator > self.denominator:
            raise ValueError("coverage numerator exceeds denominator")
        if self.denominator == 0 and self.incomplete_reason is None:
            raise ValueError("zero denominator cannot imply vacuous completeness")
        return self


class ConfigurationFieldObservation(ParityModel):
    field_path: str = Field(min_length=1, max_length=512)
    presence: PresenceState
    value: CanonicalValue | None = None
    provenance: str = Field(pattern=ID_PATTERN)
    semantic_role: str = Field(pattern=ID_PATTERN)
    scope: ParityScope
    source_asset: ObjectReference

    @field_validator("field_path")
    @classmethod
    def canonical_field_path(cls, value: str) -> str:
        if value.startswith(("/", ".")) or ".." in value.split(".") or "\\" in value:
            raise ValueError("invalid canonical configuration field path")
        return value

    @model_validator(mode="after")
    def presence_value(self) -> ConfigurationFieldObservation:
        has = self.value is not None
        if (
            self.presence
            in {
                PresenceState.EXPLICIT_VALUE,
                PresenceState.DEFAULTED_BY_EXPLICIT_POLICY,
                PresenceState.INFERRED_NON_AUTHORITATIVELY,
            }
            and not has
        ):
            raise ValueError("presence state requires an explicit typed value")
        if self.presence == PresenceState.EXPLICIT_NULL and (
            self.value is None or self.value.value_type != CanonicalValueType.EXPLICIT_NULL
        ):
            raise ValueError("explicit null requires explicit-null typed value")
        if (
            self.presence
            in {PresenceState.ABSENT, PresenceState.UNAVAILABLE, PresenceState.INVALID}
            and has
        ):
            raise ValueError("non-value presence state cannot carry a value")
        return self


class VocabularyEntry(ParityModel):
    token: TokenContent
    token_id: int = Field(ge=0, le=2_147_483_647)
    source_order: int = Field(ge=0)
    provenance: str = Field(pattern=ID_PATTERN)
    classification: TokenClassification
    source_asset: ObjectReference


class MergeRecord(ParityModel):
    left: TokenContent
    right: TokenContent
    rank: int = Field(ge=0)
    source_order: int = Field(ge=0)
    provenance: str = Field(pattern=ID_PATTERN)


class AddedTokenRecord(ParityModel):
    content: TokenContent
    token_id: int | None = Field(default=None, ge=0, le=2_147_483_647)
    token_id_presence: PresenceState
    special: bool | None = None
    single_word: bool | None = None
    lstrip: bool | None = None
    rstrip: bool | None = None
    normalized: bool | None = None
    property_presence: tuple[str, ...] = Field(max_length=16)
    source_order: int = Field(ge=0)
    provenance: str = Field(pattern=ID_PATTERN)

    @model_validator(mode="after")
    def presence_semantics(self) -> AddedTokenRecord:
        value_states = {
            PresenceState.EXPLICIT_VALUE,
            PresenceState.DEFAULTED_BY_EXPLICIT_POLICY,
            PresenceState.INFERRED_NON_AUTHORITATIVELY,
        }
        if (self.token_id_presence in value_states) != (self.token_id is not None):
            raise ValueError("added-token ID presence does not match supplied token ID")
        declared = {
            name
            for name in ("special", "single_word", "lstrip", "rstrip", "normalized")
            if getattr(self, name) is not None
        }
        if set(self.property_presence) != declared:
            raise ValueError("added-token property presence does not match supplied properties")
        return self


class SpecialTokenRecord(ParityModel):
    role: SpecialTokenRole
    content: TokenContent | None = None
    content_presence: PresenceState
    token_id: int | None = Field(default=None, ge=0, le=2_147_483_647)
    token_id_presence: PresenceState
    added_properties: AddedTokenRecord | None = None
    provenance: str = Field(pattern=ID_PATTERN)
    source_asset: ObjectReference
    declared_behavior: str = Field(pattern=ID_PATTERN)
    availability: ArtifactAvailability

    @model_validator(mode="after")
    def presence_semantics(self) -> SpecialTokenRecord:
        value_states = {
            PresenceState.EXPLICIT_VALUE,
            PresenceState.DEFAULTED_BY_EXPLICIT_POLICY,
            PresenceState.INFERRED_NON_AUTHORITATIVELY,
        }
        if (self.content_presence in value_states) != (self.content is not None):
            raise ValueError("special-token content presence mismatch")
        if (self.token_id_presence in value_states) != (self.token_id is not None):
            raise ValueError("special-token ID presence mismatch")
        if self.role == SpecialTokenRole.ABSENT_ROLE and (
            self.content is not None or self.token_id is not None
        ):
            raise ValueError("ABSENT_ROLE cannot carry token content or ID")
        if self.role == SpecialTokenRole.ABSENT_ROLE and self.declared_behavior != "absent.role":
            raise ValueError("ABSENT_ROLE cannot carry declared token behavior")
        return self


class TokenizerPipelineComponent(ParityModel):
    component_kind: PipelineComponentKind
    position: int = Field(ge=0)
    type_identifier: str = Field(min_length=1, max_length=256)
    parameter_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    parameter_count: int = Field(ge=0)
    implementation_identifier: str | None = Field(default=None, max_length=256)
    provenance: str = Field(pattern=ID_PATTERN)
    source_asset: ObjectReference
    support_state: ComponentSupportState
    unknown_fields: tuple[str, ...] = Field(max_length=4096)


class TokenizerProbeDefinition(ParityModel):
    probe_id: str = Field(pattern=r"^tokenizer_probe_[0-9a-f]{32}$")
    probe_kind: ProbeKind
    subject_id: str = Field(pattern=r"^product_subject_[0-9a-f]{32}$")
    scope: ParityScope
    input_availability: ProbeInputAvailability
    input_digest: str = Field(pattern=SHA256_PATTERN)
    inline_input: TokenContent | tuple[int, ...] | None = None
    expected_output_form: str = Field(pattern=ID_PATTERN)
    tokenizer_identities: tuple[ObjectReference, ...] = Field(max_length=32)
    execution_context: str = Field(pattern=ID_PATTERN)
    limitations: tuple[str, ...] = Field(max_length=32)

    @field_validator("inline_input", mode="before")
    @classmethod
    def strict_inline_token_ids(cls, value: Any) -> Any:
        if isinstance(value, (tuple, list)) and any(
            type(item) is not int or item < 0 or item > 2_147_483_647 for item in value
        ):
            raise ValueError("invalid inline probe token ID")
        return value

    @model_validator(mode="after")
    def inline_availability(self) -> TokenizerProbeDefinition:
        if (
            self.input_availability == ProbeInputAvailability.INLINE_SYNTHETIC_INPUT
            and self.inline_input is None
        ):
            raise ValueError("inline probe requires harmless synthetic input")
        if (
            self.input_availability != ProbeInputAvailability.INLINE_SYNTHETIC_INPUT
            and self.inline_input is not None
        ):
            raise ValueError("non-inline probe cannot serialize input")
        if self.input_availability == ProbeInputAvailability.INLINE_SYNTHETIC_INPUT:
            inline = _json_compatible(self.inline_input)
            expected_digest = canonical_sha256({"domain": "probe.input.v1", "value": inline})
            if self.input_digest != expected_digest:
                raise ValueError("inline probe input digest mismatch")
        body = self.model_dump(mode="json")
        claimed = body.pop("probe_id")
        expected_id = (
            "tokenizer_probe_"
            + canonical_sha256(
                {"domain": "omiv.tokenizer-probe-definition.v1", "definition": body}
            )[:32]
        )
        if claimed != expected_id:
            raise ValueError("canonical probe identity mismatch")
        return self


class TokenizerProbeResult(ParityModel):
    probe_id: str = Field(pattern=r"^tokenizer_probe_[0-9a-f]{32}$")
    probe_kind: ProbeKind
    output_availability: ProbeOutputAvailability
    output_interpretation: str = Field(pattern=ID_PATTERN)
    output_length: int | None = Field(default=None, ge=0)
    token_ids: tuple[int, ...] | None = Field(default=None, max_length=100_000)
    token_contents: tuple[TokenContent, ...] | None = Field(default=None, max_length=100_000)
    output_text: TokenContent | None = None
    output_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    offsets: tuple[tuple[int, int], ...] | None = Field(default=None, max_length=100_000)
    special_token_mask: tuple[int, ...] | None = Field(default=None, max_length=100_000)
    attention_mask: tuple[int, ...] | None = Field(default=None, max_length=100_000)
    status: ProbeComparisonStatus
    limitations: tuple[str, ...] = Field(max_length=32)

    @field_validator("token_ids", mode="before")
    @classmethod
    def strict_token_ids(cls, value: Any) -> Any:
        if value is not None and any(
            type(item) is not int or item < 0 or item > 2_147_483_647 for item in value
        ):
            raise ValueError("invalid supplied probe token ID")
        return value

    @field_validator("special_token_mask", "attention_mask", mode="before")
    @classmethod
    def binary_masks(cls, value: Any) -> Any:
        if value is not None and any(type(item) is not int or item not in {0, 1} for item in value):
            raise ValueError("probe mask values must be exact integers zero or one")
        return value

    @field_validator("offsets", mode="before")
    @classmethod
    def valid_offsets(cls, value: Any) -> Any:
        if value is not None and any(
            not isinstance(pair, (tuple, list))
            or len(pair) != 2
            or any(type(item) is not int or item < 0 for item in pair)
            or pair[0] > pair[1]
            for pair in value
        ):
            raise ValueError("probe offsets must be ordered non-negative integer pairs")
        return value

    @model_validator(mode="after")
    def output_semantics(self) -> TokenizerProbeResult:
        inline = any(
            value is not None
            for value in (
                self.token_ids,
                self.token_contents,
                self.output_text,
                self.offsets,
                self.special_token_mask,
                self.attention_mask,
            )
        )
        if self.output_availability == ProbeOutputAvailability.INLINE_SYNTHETIC_OUTPUT:
            if not inline or self.output_digest is None or self.output_length is None:
                raise ValueError("inline output requires content, digest, and explicit length")
        elif self.output_availability == ProbeOutputAvailability.DIGEST_ONLY_OUTPUT:
            if inline or self.output_digest is None or self.output_length is None:
                raise ValueError("digest-only output cannot serialize plaintext output")
        elif inline or self.output_digest is not None or self.output_length is not None:
            raise ValueError("unavailable output cannot carry output content or identity")
        if (
            self.output_availability == ProbeOutputAvailability.DIGEST_ONLY_OUTPUT
            and self.status != ProbeComparisonStatus.DIGEST_ONLY_NOT_REPRODUCIBLE
        ):
            raise ValueError("digest-only output must retain non-reproducible status")
        if (
            self.output_availability == ProbeOutputAvailability.OUTPUT_UNAVAILABLE
            and self.status != ProbeComparisonStatus.PROBE_RESULT_UNAVAILABLE
        ):
            raise ValueError("unavailable output must retain unavailable status")
        if self.output_availability == ProbeOutputAvailability.INLINE_SYNTHETIC_OUTPUT:
            if self.probe_kind == ProbeKind.ENCODE_TEXT_TO_TOKEN_IDS and self.token_ids is None:
                raise ValueError("encode probe output requires token IDs")
            if (
                self.probe_kind
                in {
                    ProbeKind.DECODE_TOKEN_IDS_TO_TEXT,
                    ProbeKind.CHAT_TEMPLATE_RENDER,
                }
                and self.output_text is None
            ):
                raise ValueError("text-output probe requires explicit output text")
        for mask in (self.special_token_mask, self.attention_mask):
            if mask is not None and (self.token_ids is None or len(mask) != len(self.token_ids)):
                raise ValueError("probe mask length must match token-ID sequence")
        if self.offsets is not None and (
            self.token_ids is None or len(self.offsets) != len(self.token_ids)
        ):
            raise ValueError("probe offset count must match token-ID sequence")
        actual_length = _probe_output_length(self)
        if self.output_availability == ProbeOutputAvailability.INLINE_SYNTHETIC_OUTPUT:
            if self.output_length != actual_length:
                raise ValueError("inline probe output length mismatch")
            expected = canonical_sha256(
                {
                    "domain": "probe.output.v1",
                    "value": _json_compatible(_probe_output_value(self)),
                }
            )
            if self.output_digest != expected:
                raise ValueError("inline probe output digest mismatch")
        return self


class ParityFinding(ParityModel):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,127}$")
    dimension: ParityDimension
    status: FindingStatus
    subject: str = Field(min_length=1, max_length=512)
    detail: str = Field(min_length=1, max_length=MAX_TEXT)


class DimensionResult(ParityModel):
    dimension: ParityDimension
    status: FindingStatus
    compared_count: int = Field(ge=0)
    mismatch_count: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(max_length=32)


class CrossAssetConsistencyResult(ParityModel):
    rule_id: str = Field(pattern=ID_PATTERN)
    status: CrossAssetStatus
    inputs: tuple[ObjectReference, ...] = Field(max_length=16)
    detail: str = Field(min_length=1, max_length=MAX_TEXT)


class TokenizerConfigurationExpectation(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-expectation.v1"] = Field(
        default="omiv.tokenizer-configuration-expectation.v1", alias="schema"
    )
    expectation_id: str = Field(pattern=r"^tokenizer_expectation_[0-9a-f]{32}$")
    expectation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    scope: ParityScope
    required_assets: tuple[AssetKind, ...] = Field(max_length=256)
    required_fields: tuple[str, ...] = Field(max_length=10_000)
    required_special_roles: tuple[SpecialTokenRole, ...] = Field(max_length=4096)
    required_probe_kinds: tuple[ProbeKind, ...] = Field(max_length=1024)
    publisher: str | None = Field(default=None, max_length=256)
    authority_status: AuthorityStatus
    available_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def nonempty_expectation(self) -> TokenizerConfigurationExpectation:
        if not any(
            (
                self.required_assets,
                self.required_fields,
                self.required_special_roles,
                self.required_probe_kinds,
            )
        ):
            raise ValueError("empty expectation cannot pass by vacuous truth")
        return self


class TokenizerConfigurationParityDeclaration(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-parity-declaration.v1"] = Field(
        default="omiv.tokenizer-configuration-parity-declaration.v1", alias="schema"
    )
    declaration_id: str = Field(pattern=r"^tokenizer_declaration_[0-9a-f]{32}$")
    declaration_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    scope: ScopeContext
    expectation_mode: ExpectationMode
    expectation: ExpectationReference
    reference_artifacts: tuple[ArtifactBinding, ...] = Field(max_length=256)
    candidate_artifacts: tuple[ArtifactBinding, ...] = Field(max_length=256)
    provenance: str = Field(pattern=ID_PATTERN)
    declared_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def subject_binding(self) -> TokenizerConfigurationParityDeclaration:
        if self.expectation.subject_id != self.subject.subject_id:
            raise ValueError("expectation subject differs from declaration subject")
        if any(
            a.subject_id != self.subject.subject_id
            for a in (*self.reference_artifacts, *self.candidate_artifacts)
        ):
            raise ValueError("artifact subject differs from declaration subject")
        return self


class TokenizerConfigurationInspectionPlan(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-inspection-plan.v1"] = Field(
        default="omiv.tokenizer-configuration-inspection-plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=r"^tokenizer_plan_[0-9a-f]{32}$")
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    declaration: ObjectReference
    expectation: ObjectReference | None = None
    supplied_inputs: tuple[ObjectReference, ...] = Field(max_length=512)
    selected_scopes: tuple[ParityScope, ...] = Field(max_length=16)
    selected_asset_paths: tuple[str, ...] = Field(max_length=256)
    limits: TokenizerConfigurationLimits = TokenizerConfigurationLimits()
    network_use: Literal["NONE"] = "NONE"
    tokenizer_execution: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    template_execution: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    requested_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)

    @field_validator("selected_asset_paths")
    @classmethod
    def paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return validate_path_set(value)


class TokenizerConfigurationExecutionRecord(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-execution-record.v1"] = Field(
        default="omiv.tokenizer-configuration-execution-record.v1", alias="schema"
    )
    execution_id: str = Field(pattern=r"^tokenizer_execution_[0-9a-f]{32}$")
    execution_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    plan: ObjectReference
    supplied_inputs: tuple[ObjectReference, ...] = Field(max_length=512)
    tool_identity: str = Field(pattern=ID_PATTERN)
    completion_status: Literal[
        "COMPLETED", "COMPLETED_WITH_LIMITATIONS", "FAILED", "LIMIT_EXCEEDED"
    ]
    counters: tuple[tuple[str, int], ...] = Field(max_length=64)
    failure_class: str | None = Field(default=None, pattern=ID_PATTERN)
    time_context: ExplicitTime
    network_requests: Literal[0] = 0
    executed_tokenizers: Literal[0] = 0
    rendered_templates: Literal[0] = 0
    limitations: tuple[str, ...] = Field(max_length=64)


class ConfigurationObservation(ParityModel):
    schema_id: Literal["omiv.configuration-observation.v1"] = Field(
        default="omiv.configuration-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^config_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    artifact: ArtifactBinding
    raw_sha256: str = Field(pattern=SHA256_PATTERN)
    canonical_json_sha256: str = Field(pattern=SHA256_PATTERN)
    projection_sha256: str = Field(pattern=SHA256_PATTERN)
    fields: tuple[ConfigurationFieldObservation, ...] = Field(max_length=10_000)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=64)
    race_findings: tuple[str, ...] = Field(max_length=8)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerAssetObservation(ParityModel):
    schema_id: Literal["omiv.tokenizer-asset-observation.v1"] = Field(
        default="omiv.tokenizer-asset-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^tokenizer_asset_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    artifact: ArtifactBinding
    raw_sha256: str = Field(pattern=SHA256_PATTERN)
    raw_size: int = Field(ge=0)
    format_identifier: str = Field(pattern=ID_PATTERN)
    format_supported: bool
    content_executed: Literal[False] = False
    race_findings: tuple[str, ...] = Field(max_length=8)
    limitations: tuple[str, ...] = Field(max_length=64)


class VocabularyObservation(ParityModel):
    schema_id: Literal["omiv.vocabulary-observation.v1"] = Field(
        default="omiv.vocabulary-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^vocabulary_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    asset_observation: ObjectReference
    entries: tuple[VocabularyEntry, ...] = Field(max_length=250_000)
    record_count: int = Field(ge=0)
    distinct_token_count: int = Field(ge=0)
    distinct_id_count: int = Field(ge=0)
    maximum_token_id: int | None = Field(default=None, ge=0)
    max_id_plus_one: int | None = Field(default=None, ge=1)
    base_vocabulary_count: int | None = Field(default=None, ge=0)
    added_token_count: int | None = Field(default=None, ge=0)
    duplicate_token_count: int = Field(ge=0)
    duplicate_id_count: int = Field(ge=0)
    sparse_ids_observed: bool
    comparable: bool
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def cardinalities_match_records(self) -> VocabularyObservation:
        token_count = len({entry.token.model_dump_json() for entry in self.entries})
        id_count = len({entry.token_id for entry in self.entries})
        maximum = max((entry.token_id for entry in self.entries), default=None)
        if (
            self.record_count != len(self.entries)
            or self.distinct_token_count != token_count
            or self.distinct_id_count != id_count
            or self.maximum_token_id != maximum
            or self.max_id_plus_one != (maximum + 1 if maximum is not None else None)
        ):
            raise ValueError("vocabulary cardinality summary does not match records")
        return self


class MergeTableObservation(ParityModel):
    schema_id: Literal["omiv.merge-table-observation.v1"] = Field(
        default="omiv.merge-table-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^merge_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    asset_observation: ObjectReference
    format_identifier: str = Field(pattern=ID_PATTERN)
    header: str | None = Field(default=None, max_length=256)
    records: tuple[MergeRecord, ...] = Field(max_length=250_000)
    duplicate_count: int = Field(ge=0)
    malformed_count: int = Field(ge=0)
    comparable: bool
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)


class AddedTokenObservation(ParityModel):
    schema_id: Literal["omiv.added-token-observation.v1"] = Field(
        default="omiv.added-token-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^added_token_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    asset_observation: ObjectReference
    records: tuple[AddedTokenRecord, ...] = Field(max_length=100_000)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)


class SpecialTokenObservation(ParityModel):
    schema_id: Literal["omiv.special-token-observation.v1"] = Field(
        default="omiv.special-token-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^special_token_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    source_assets: tuple[ObjectReference, ...] = Field(max_length=16)
    records: tuple[SpecialTokenRecord, ...] = Field(max_length=4096)
    consistency_findings: tuple[ParityFinding, ...] = Field(max_length=MAX_FINDINGS)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerPipelineObservation(ParityModel):
    schema_id: Literal["omiv.tokenizer-pipeline-observation.v1"] = Field(
        default="omiv.tokenizer-pipeline-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^pipeline_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    asset_observation: ObjectReference
    components: tuple[TokenizerPipelineComponent, ...] = Field(max_length=256)
    behavior_evaluated: Literal[False] = False
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)


class ChatTemplateObservation(ParityModel):
    schema_id: Literal["omiv.chat-template-observation.v1"] = Field(
        default="omiv.chat-template-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^template_observation_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    asset_observation: ObjectReference
    content_encoding: TokenContentEncoding
    content_digest: str = Field(pattern=SHA256_PATTERN)
    template_language: str | None = Field(default=None, max_length=128)
    template_name: str | None = Field(default=None, max_length=256)
    availability: ArtifactAvailability
    template_executed: Literal[False] = False
    content_size: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerProbeSetDefinition(ParityModel):
    schema_id: Literal["omiv.tokenizer-probe-set-definition.v1"] = Field(
        default="omiv.tokenizer-probe-set-definition.v1", alias="schema"
    )
    probe_set_id: str = Field(pattern=r"^tokenizer_probe_set_[0-9a-f]{32}$")
    probe_set_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    scope: ParityScope
    probes: tuple[TokenizerProbeDefinition, ...] = Field(max_length=10_000)
    limits: TokenizerConfigurationLimits = TokenizerConfigurationLimits()
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def unique_nonempty_probes(self) -> TokenizerProbeSetDefinition:
        ids = [p.probe_id for p in self.probes]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("probe set must be nonempty with unique probe identities")
        return self


class TokenizerProbeExecutionRecord(ParityModel):
    schema_id: Literal["omiv.tokenizer-probe-execution-record.v1"] = Field(
        default="omiv.tokenizer-probe-execution-record.v1", alias="schema"
    )
    execution_id: str = Field(pattern=r"^tokenizer_probe_execution_[0-9a-f]{32}$")
    execution_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    inspection_plan: ObjectReference
    probe_set: ObjectReference
    tokenizer_identities: tuple[ObjectReference, ...] = Field(max_length=32)
    tool_identity: str = Field(pattern=ID_PATTERN)
    completion_status: Literal[
        "COMPLETED", "COMPLETED_WITH_LIMITATIONS", "NOT_PERFORMED", "LIMIT_EXCEEDED"
    ]
    time_context: ExplicitTime
    execution_context: str = Field(pattern=ID_PATTERN)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerProbeResultObservation(ParityModel):
    schema_id: Literal["omiv.tokenizer-probe-result-observation.v1"] = Field(
        default="omiv.tokenizer-probe-result-observation.v1", alias="schema"
    )
    observation_id: str = Field(pattern=r"^tokenizer_probe_results_[0-9a-f]{32}$")
    observation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    execution: ObjectReference
    probe_set: ObjectReference
    results: tuple[TokenizerProbeResult, ...] = Field(max_length=10_000)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerConfigurationComparison(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-comparison.v1"] = Field(
        default="omiv.tokenizer-configuration-comparison.v1", alias="schema"
    )
    comparison_id: str = Field(pattern=r"^tokenizer_comparison_[0-9a-f]{32}$")
    comparison_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    declaration: ObjectReference
    expectation: ObjectReference | None
    observations: tuple[ObjectReference, ...] = Field(max_length=1024)
    probe_results: tuple[ObjectReference, ...] = Field(max_length=16)
    scope: ParityScope
    configuration_status: ConfigurationStatus
    probe_status: ProbeComparisonStatus
    dimension_results: tuple[DimensionResult, ...] = Field(max_length=64)
    cross_asset_results: tuple[CrossAssetConsistencyResult, ...] = Field(max_length=256)
    findings: tuple[ParityFinding, ...] = Field(max_length=MAX_FINDINGS)
    coverage: tuple[CoverageDimension, ...] = Field(max_length=64)
    raw_status: OverallParityStatus
    limitations: tuple[str, ...] = Field(max_length=64)


class ExplicitAliasRule(ParityModel):
    rule_id: str = Field(pattern=ID_PATTERN)
    version: str = Field(pattern=ID_PATTERN)
    reference_field: str = Field(min_length=1, max_length=512)
    candidate_field: str = Field(min_length=1, max_length=512)
    scope: ParityScope


class TransformationDifferenceRule(ParityModel):
    rule_id: str = Field(pattern=ID_PATTERN)
    version: str = Field(pattern=ID_PATTERN)
    field_path: str = Field(min_length=1, max_length=512)
    allowed_reference_value_digest: str = Field(pattern=SHA256_PATTERN)
    allowed_candidate_value_digest: str = Field(pattern=SHA256_PATTERN)
    scope: ParityScope


class TokenizerConfigurationPolicy(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-policy.v1"] = Field(
        default="omiv.tokenizer-configuration-policy.v1", alias="schema"
    )
    policy_id: str = Field(pattern=r"^tokenizer_policy_[0-9a-f]{32}$")
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    scope: ParityScope
    required_identity: ArtifactAvailability
    required_assets: tuple[AssetKind, ...] = Field(max_length=256)
    required_fields: tuple[str, ...] = Field(max_length=10_000)
    required_special_roles: tuple[SpecialTokenRole, ...] = Field(max_length=4096)
    required_pipeline_components: tuple[PipelineComponentKind, ...] = Field(max_length=256)
    required_probe_kinds: tuple[ProbeKind, ...] = Field(max_length=1024)
    alias_rules: tuple[ExplicitAliasRule, ...] = Field(max_length=1024)
    transformation_rules: tuple[TransformationDifferenceRule, ...] = Field(max_length=1024)
    minimum_vocabulary_coverage: str
    minimum_probe_coverage: str
    allow_duplicate_token: bool
    allow_duplicate_id: bool
    require_merge_order: bool
    opaque_component_behavior: Literal["FAIL", "NOT_EVALUATED", "ALLOW_WITH_LIMITATION"]
    require_chat_template: bool
    digest_only_probes_acceptable: bool
    require_authority: bool
    missing_input_behavior: Literal["FAIL", "NOT_EVALUATED"]
    unsupported_format_behavior: Literal["FAIL", "NOT_EVALUATED"]
    evaluation_context: ScopeContext
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def bounded_ratios(self) -> TokenizerConfigurationPolicy:
        for value in (self.minimum_vocabulary_coverage, self.minimum_probe_coverage):
            parsed = _validate_decimal(value)
            if parsed < 0 or parsed > 1:
                raise ValueError("coverage policy ratio must be in [0,1]")
        return self


class PolicyRequirementResult(ParityModel):
    requirement: str = Field(pattern=ID_PATTERN)
    status: RequirementStatus
    observed: str | None = Field(default=None, max_length=MAX_TEXT)
    required: str | None = Field(default=None, max_length=MAX_TEXT)
    detail: str = Field(min_length=1, max_length=MAX_TEXT)


class TokenizerConfigurationPolicyEvaluation(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-policy-evaluation.v1"] = Field(
        default="omiv.tokenizer-configuration-policy-evaluation.v1", alias="schema"
    )
    evaluation_id: str = Field(pattern=r"^tokenizer_policy_evaluation_[0-9a-f]{32}$")
    evaluation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    comparison: ObjectReference
    policy: ObjectReference
    authority: ObjectReference | None
    requirements: tuple[PolicyRequirementResult, ...] = Field(max_length=MAX_FINDINGS)
    result: RequirementStatus
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)


class AuthorityDimension(ParityModel):
    purpose: str = Field(pattern=ID_PATTERN)
    signature_state: str = Field(pattern=ID_PATTERN)
    signer_trust: AuthorityStatus
    purpose_authority: AuthorityStatus
    subject_scope: AuthorityStatus
    detail: str = Field(min_length=1, max_length=MAX_TEXT)


class TokenizerConfigurationAuthorityEvaluation(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-authority-evaluation.v1"] = Field(
        default="omiv.tokenizer-configuration-authority-evaluation.v1", alias="schema"
    )
    authority_evaluation_id: str = Field(pattern=r"^tokenizer_authority_[0-9a-f]{32}$")
    authority_evaluation_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    scope: ScopeContext
    reference_expectation_authority: AuthorityStatus
    source_publisher_authority: AuthorityStatus
    candidate_publisher_authority: AuthorityStatus
    transformation_authority: AuthorityStatus
    observation_signer_authority: AuthorityStatus
    probe_executor_authority: AuthorityStatus
    policy_authority: AuthorityStatus
    dimensions: tuple[AuthorityDimension, ...] = Field(max_length=64)
    overall_status: AuthorityStatus
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerConfigurationParityEvidence(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-parity-evidence.v1"] = Field(
        default="omiv.tokenizer-configuration-parity-evidence.v1", alias="schema"
    )
    evidence_id: str = Field(pattern=r"^tokenizer_evidence_[0-9a-f]{32}$")
    evidence_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    scope: ParityScope
    comparison: ObjectReference
    policy_evaluation: ObjectReference
    authority_evaluation: ObjectReference
    overall_status: OverallParityStatus
    coverage: tuple[CoverageDimension, ...] = Field(max_length=64)
    authority_status: AuthorityStatus
    behavioral_equivalence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    runtime_compatibility: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    security_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    authenticity: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def no_authority_upgrade(self) -> TokenizerConfigurationParityEvidence:
        if self.overall_status == OverallParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE and any(
            c.denominator in {None, 0} or c.numerator != c.denominator for c in self.coverage
        ):
            raise ValueError("parity cannot be established with incomplete or empty coverage")
        return self


class TokenizerConfigurationIntegrationSummary(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-integration-summary.v1"] = Field(
        default="omiv.tokenizer-configuration-integration-summary.v1", alias="schema"
    )
    integration_id: str = Field(pattern=r"^tokenizer_integration_[0-9a-f]{32}$")
    integration_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    evidence: ObjectReference
    integration_kind: Literal[
        "PASSPORT",
        "CUSTODY",
        "ATTESTATION",
        "GOVERNANCE",
        "SECURITY",
        "RUNTIME",
        "HISTORICAL",
        "PAYLOAD_INTEGRITY",
        "RECONCILIATION",
        "QUANTIZATION",
    ]
    linked_object: ObjectReference | None
    identity_match: bool
    derived_state: str = Field(pattern=ID_PATTERN)
    creates_approval: Literal[False] = False
    creates_security_pass: Literal[False] = False
    creates_runtime_observation: Literal[False] = False
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerConfigurationReport(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-report.v1"] = Field(
        default="omiv.tokenizer-configuration-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^tokenizer_report_[0-9a-f]{32}$")
    report_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    evidence: ObjectReference
    title: str = Field(min_length=1, max_length=256)
    overall_status: OverallParityStatus
    total_findings: int = Field(ge=0)
    included_findings: int = Field(ge=0)
    omitted_findings: int = Field(ge=0)
    inclusion_rule: str = Field(pattern=ID_PATTERN)
    truncation_status: Literal["NOT_TRUNCATED", "DETERMINISTICALLY_TRUNCATED"]
    findings: tuple[ParityFinding, ...] = Field(max_length=4096)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerConfigurationScenarioResult(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-scenario-result.v1"] = Field(
        default="omiv.tokenizer-configuration-scenario-result.v1", alias="schema"
    )
    result_id: str = Field(pattern=r"^tokenizer_scenario_[0-9a-f]{32}$")
    result_digest: str = Field(pattern=SHA256_PATTERN)
    case_id: str = Field(pattern=ID_PATTERN)
    exercised_invariant: str = Field(min_length=1, max_length=MAX_TEXT)
    outcome: str = Field(pattern=ID_PATTERN)
    findings: tuple[str, ...] = Field(max_length=64)
    upstream_objects: tuple[ObjectReference, ...] = Field(max_length=32)
    limitations: tuple[str, ...] = Field(max_length=32)


class TokenizerConfigurationScenarioCatalog(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-scenario-catalog.v1"] = Field(
        default="omiv.tokenizer-configuration-scenario-catalog.v1", alias="schema"
    )
    catalog_id: str = Field(pattern=r"^tokenizer_catalog_[0-9a-f]{32}$")
    catalog_digest: str = Field(pattern=SHA256_PATTERN)
    classification: Literal[
        "COMPLETE_AS_PROVIDER_NEUTRAL_TOKENIZER_AND_CONFIGURATION_PARITY_EVIDENCE_FOUNDATION_WITH_EXPLICIT_FORMAT_PROBE_AND_RUNTIME_LIMITATIONS"
    ]
    scenarios: tuple[ObjectReference, ...] = Field(min_length=36, max_length=36)
    limitations: tuple[str, ...] = Field(max_length=64)


class TokenizerConfigurationArtifactIndexEntry(ParityModel):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str = Field(pattern=r"^omiv\.[a-z0-9.-]+\.v[0-9]+$")
    canonical_id: str = Field(min_length=3, max_length=192)

    @field_validator("path")
    @classmethod
    def path_is_portable(cls, value: str) -> str:
        return validate_portable_path(value)


class TokenizerConfigurationArtifactIndex(ParityModel):
    schema_id: Literal["omiv.tokenizer-configuration-artifact-index.v1"] = Field(
        default="omiv.tokenizer-configuration-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^tokenizer_index_[0-9a-f]{32}$")
    index_digest: str = Field(pattern=SHA256_PATTERN)
    entries: tuple[TokenizerConfigurationArtifactIndexEntry, ...] = Field(
        max_length=MAX_INDEX_ENTRIES
    )
    total_size: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def unique_external_entries(self) -> TokenizerConfigurationArtifactIndex:
        paths = tuple(e.path for e in self.entries)
        validate_path_set(paths)
        if "tokenizer-configuration-parity/artifact-index.json" in paths:
            raise ValueError("external tokenizer/config index must exclude itself")
        if len({e.canonical_id for e in self.entries}) != len(self.entries):
            raise ValueError("duplicate canonical identity in artifact index")
        if sum(e.size for e in self.entries) != self.total_size:
            raise ValueError("artifact index total size mismatch")
        return self


def finalize_identity(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    """Add the canonical identity pair using the repository OMIV JSON profile."""
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
        id_fields = [k for k in body if k.endswith("_id")]
        digest_fields = [k for k in body if k.endswith("_digest")]
        if len(id_fields) != 1 or len(digest_fields) != 1:
            raise ValueError("canonical object does not expose one identity pair")
        id_field, digest_field = id_fields[0], digest_fields[0]
    else:
        id_field, digest_field, _prefix = spec
    return ObjectReference(
        schema_id=schema, object_id=str(body[id_field]), object_digest=str(body[digest_field])
    )


def verify_object_reference(reference: ObjectReference, value: BaseModel) -> None:
    if reference != object_reference(value):
        raise ValueError("canonical object reference does not match supplied object")


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return {str(k): _json_compatible(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_compatible(v) for v in value]
    return value


def _validate_unicode_scalars(value: str) -> None:
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF or (code & 0xFFFF) in {0xFFFE, 0xFFFF}:
            raise ValueError("token text contains surrogate or Unicode noncharacter")


def _validate_decimal(value: str) -> Decimal:
    if not isinstance(value, str) or not re.fullmatch(
        r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:E-?[0-9]+)?", value
    ):
        raise ValueError("invalid canonical decimal")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("invalid canonical decimal") from exc
    if not parsed.is_finite() or len(parsed.as_tuple().digits) > MAX_DECIMAL_DIGITS:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_DIGITS")
    if parsed != 0 and abs(parsed.adjusted()) > MAX_DECIMAL_EXPONENT:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_EXPONENT")
    if parsed == 0 and value != "0":
        raise ValueError("canonical zero has one representation")
    return parsed


def _probe_output_value(value: TokenizerProbeResult) -> dict[str, Any]:
    return {
        "probe_kind": value.probe_kind,
        "token_ids": value.token_ids,
        "token_contents": value.token_contents,
        "output_text": value.output_text,
        "offsets": value.offsets,
        "special_token_mask": value.special_token_mask,
        "attention_mask": value.attention_mask,
        "interpretation": value.output_interpretation,
    }


def _probe_output_length(value: TokenizerProbeResult) -> int:
    if value.token_ids is not None:
        return len(value.token_ids)
    if value.token_contents is not None:
        return len(value.token_contents)
    if value.output_text is not None:
        if value.output_text.unicode_text is not None:
            return len(value.output_text.unicode_text.encode("utf-8"))
        return len(value.output_text.bytes_hex or "") // 2
    return 0


def canonical_probe_definition_id(body: dict[str, Any]) -> str:
    value = _json_compatible(body)
    if not isinstance(value, dict):
        raise TypeError("probe definition body must be an object")
    value.pop("probe_id", None)
    return (
        "tokenizer_probe_"
        + canonical_sha256({"domain": "omiv.tokenizer-probe-definition.v1", "definition": value})[
            :32
        ]
    )


def canonical_text_token(value: str) -> TokenContent:
    return TokenContent(encoding=TokenContentEncoding.UNICODE_TEXT, unicode_text=value)


def canonical_byte_token(value: bytes) -> TokenContent:
    return TokenContent(encoding=TokenContentEncoding.BYTE_SEQUENCE, bytes_hex=value.hex())
