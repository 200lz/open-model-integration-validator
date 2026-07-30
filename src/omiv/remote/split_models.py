"""Strict schemas and reproducible policies for split GGUF aggregation."""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.remote.header_models import HeaderParserPolicy
from omiv.remote.models import (
    SHA256_PATTERN,
    Integrity,
    RemoteFinding,
    RemoteResult,
    ReportExecution,
    RepositoryIdentity,
    SnapshotSelection,
)

SPLIT_INVENTORY_SCHEMA: Final = "omiv.remote-split-gguf-inventory.v1"
SPLIT_REPORT_SCHEMA: Final = "omiv.remote-split-gguf-report.v1"


class MetadataConsistencyClass(StrEnum):
    REQUIRED_EQUAL = "required_equal"
    REQUIRED_PRESENT_ALL = "required_present_all"
    ALLOWED_PRIMARY_ONLY = "allowed_primary_only"
    ALLOWED_SUBSET = "allowed_subset"
    ALLOWED_SHARD_SPECIFIC = "allowed_shard_specific"
    IGNORED_FOR_CONSISTENCY = "ignored_for_consistency"
    DERIVED_SPLIT_IDENTITY = "derived_split_identity"


class SplitAggregationLimits(StrictModel):
    policy_schema: Literal["omiv.remote-split-gguf-aggregation-policy.v1"] = (
        "omiv.remote-split-gguf-aggregation-policy.v1"
    )
    policy_id: Literal["omiv.split-gguf.structural.v1"] = (
        "omiv.split-gguf.structural.v1"
    )
    max_shard_count: int = Field(default=256, ge=1)
    max_total_header_bytes: int = Field(default=1024 * 1024 * 1024, ge=24)
    max_total_request_count: int = Field(default=65536, ge=1)
    max_total_metadata_records: int = Field(default=2_000_000, ge=1)
    max_total_tensor_descriptors: int = Field(default=5_000_000, ge=1)
    max_serialized_inventory_bytes: int = Field(default=1024 * 1024 * 1024, ge=1024)
    max_duplicate_details: int = Field(default=1000, ge=0)
    max_metadata_summaries: int = Field(default=10000, ge=0)
    max_representative_tensors: int = Field(default=100, ge=0)

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class MetadataPolicyRule(StrictModel):
    selector: str
    match: Literal["exact", "prefix"]
    consistency: MetadataConsistencyClass


class SplitMetadataPolicy(StrictModel):
    policy_schema: Literal["omiv.remote-split-gguf-metadata-policy.v1"] = (
        "omiv.remote-split-gguf-metadata-policy.v1"
    )
    policy_id: Literal["omiv.gguf-split-metadata.conservative.v1"] = (
        "omiv.gguf-split-metadata.conservative.v1"
    )
    rules: list[MetadataPolicyRule] = Field(
        default_factory=lambda: [
            MetadataPolicyRule(
                selector="split.",
                match="prefix",
                consistency=MetadataConsistencyClass.DERIVED_SPLIT_IDENTITY,
            ),
            MetadataPolicyRule(
                selector="general.alignment",
                match="exact",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="general.architecture",
                match="exact",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="general.name",
                match="exact",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="tokenizer.",
                match="prefix",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="quantize.",
                match="prefix",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="general.quant",
                match="prefix",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="general.repo_url",
                match="exact",
                consistency=MetadataConsistencyClass.IGNORED_FOR_CONSISTENCY,
            ),
            MetadataPolicyRule(
                selector="general.base_model.",
                match="prefix",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
            MetadataPolicyRule(
                selector="general.",
                match="prefix",
                consistency=MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY,
            ),
        ]
    )
    default_consistency: MetadataConsistencyClass = (
        MetadataConsistencyClass.ALLOWED_PRIMARY_ONLY
    )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    def classify(self, key: str) -> MetadataConsistencyClass:
        exact = [rule for rule in self.rules if rule.match == "exact" and rule.selector == key]
        if exact:
            return exact[0].consistency
        prefixes = [
            rule for rule in self.rules if rule.match == "prefix" and key.startswith(rule.selector)
        ]
        if prefixes:
            return max(prefixes, key=lambda item: len(item.selector)).consistency
        return self.default_consistency


class GGMLTypeTrait(StrictModel):
    type_code: int = Field(ge=0)
    type_name: str
    block_elements: int = Field(ge=1)
    block_bytes: int = Field(ge=1)


class GGMLTypePolicy(StrictModel):
    policy_schema: Literal["omiv.ggml-type-size-policy.v1"] = (
        "omiv.ggml-type-size-policy.v1"
    )
    source_identity: Literal["llama.cpp-cf67f0d24511864d-ggml-type-traits"] = (
        "llama.cpp-cf67f0d24511864d-ggml-type-traits"
    )
    traits: list[GGMLTypeTrait]

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class SplitIdentity(StrictModel):
    filename_ordinal: int = Field(ge=1)
    filename_declared_count: int = Field(ge=1)
    header_split_index: int = Field(ge=0)
    normalized_header_ordinal: int = Field(ge=1)
    header_split_count: int = Field(ge=1)
    global_tensor_count: int = Field(ge=0)
    agrees: bool


class PayloadSpan(StrictModel):
    status: Literal["bounded", "unsupported", "invalid"]
    absolute_start: int = Field(ge=0)
    absolute_end: int | None = Field(default=None, ge=0)
    encoded_byte_length: int | None = Field(default=None, ge=1)
    reason: str | None = None


class GlobalTensorDescriptor(StrictModel):
    name: str
    shard_path: str
    filename_ordinal: int = Field(ge=1)
    header_split_index: int = Field(ge=0)
    descriptor_index: int = Field(ge=0)
    dimensions: list[int]
    ggml_type_code: int = Field(ge=0)
    ggml_type_name: str
    relative_data_offset: int = Field(ge=0)
    descriptor_sha256: str = Field(pattern=SHA256_PATTERN)
    payload_span: PayloadSpan


class SplitShardSummary(StrictModel):
    path: str
    filename_ordinal: int = Field(ge=1)
    header_split_index: int = Field(ge=0)
    declared_split_count: int = Field(ge=1)
    file_size: int = Field(ge=0)
    gguf_version: Literal[3]
    metadata_count: int = Field(ge=0)
    tensor_count: int = Field(ge=0)
    payload_start: int = Field(ge=24)
    accepted_header_bytes: int = Field(ge=1)
    request_count: int = Field(ge=1)
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    metadata_role: Literal["broadest_metadata", "metadata_subset", "metadata_equal"]
    payload_span_result: Literal["bounded", "unsupported", "invalid", "no_tensors"]


class MetadataConsistencySummary(StrictModel):
    broadest_metadata_shard: str
    replicated_all_keys: list[str]
    primary_only_keys: list[str]
    required_equal_checked: int = Field(ge=0)
    required_equal_failures: list[str]
    policy_class_counts: dict[str, int]


class DuplicateSummary(StrictModel):
    exact_duplicate_count: int = Field(ge=0)
    conflict_count: int = Field(ge=0)
    exact_duplicate_names: list[str]
    conflicting_names: list[str]
    detail_digest: str = Field(pattern=SHA256_PATTERN)


class PayloadSpanSummary(StrictModel):
    computable_count: int = Field(ge=0)
    bounded_count: int = Field(ge=0)
    unsupported_count: int = Field(ge=0)
    invalid_count: int = Field(ge=0)
    overlap_count: int = Field(ge=0)
    supported_type_counts: dict[str, int]
    unsupported_type_counts: dict[str, int]


class SplitGGUFInventory(StrictModel):
    inventory_schema: Literal["omiv.remote-split-gguf-inventory.v1"] = (
        SPLIT_INVENTORY_SCHEMA
    )
    provider: Literal["huggingface"]
    repository: RepositoryIdentity
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    selection: SnapshotSelection
    filename_candidate_stem: str
    header_parser_policy: HeaderParserPolicy
    header_parser_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    aggregation_policy: SplitAggregationLimits
    aggregation_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    metadata_policy: SplitMetadataPolicy
    metadata_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    ggml_type_policy: GGMLTypePolicy
    ggml_type_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    shard_count: int = Field(ge=1)
    declared_split_count: int = Field(ge=1)
    global_tensor_count_metadata: int = Field(ge=0)
    aggregated_tensor_count: int = Field(ge=0)
    total_repository_bytes: int = Field(ge=0)
    total_header_bytes_accepted: int = Field(ge=1)
    total_request_count: int = Field(ge=1)
    reused_inventory_count: int = Field(ge=0)
    remotely_parsed_inventory_count: int = Field(ge=0)
    shard_summaries: list[SplitShardSummary]
    split_identities: list[SplitIdentity]
    metadata_consistency: MetadataConsistencySummary
    tensors: list[GlobalTensorDescriptor]
    representative_tensors: list[GlobalTensorDescriptor]
    duplicate_summary: DuplicateSummary
    payload_span_summary: PayloadSpanSummary
    findings: list[RemoteFinding]

    @model_validator(mode="after")
    def consistent(self) -> SplitGGUFInventory:
        if self.header_parser_policy_sha256 != self.header_parser_policy.digest:
            raise ValueError("header parser policy digest mismatch")
        if self.aggregation_policy_sha256 != self.aggregation_policy.digest:
            raise ValueError("aggregation policy digest mismatch")
        if self.metadata_policy_sha256 != self.metadata_policy.digest:
            raise ValueError("metadata policy digest mismatch")
        if self.ggml_type_policy_sha256 != self.ggml_type_policy.digest:
            raise ValueError("GGML type policy digest mismatch")
        if self.shard_count != len(self.shard_summaries):
            raise ValueError("shard count mismatch")
        if self.aggregated_tensor_count != len(self.tensors):
            raise ValueError("aggregated tensor count mismatch")
        if self.reused_inventory_count + self.remotely_parsed_inventory_count != self.shard_count:
            raise ValueError("inventory source counts mismatch")
        expected_statuses = [
            RemoteResult.PASS,
            RemoteResult.PASS
            if sorted(item.header_split_index for item in self.split_identities)
            == list(range(self.shard_count))
            else RemoteResult.FAIL,
            RemoteResult.PASS
            if all(item.agrees for item in self.split_identities)
            else RemoteResult.FAIL,
            RemoteResult.PASS
            if self.declared_split_count == self.shard_count
            and all(
                item.header_split_count == self.declared_split_count
                and item.filename_declared_count == self.declared_split_count
                for item in self.split_identities
            )
            else RemoteResult.FAIL,
            RemoteResult.PASS
            if not self.metadata_consistency.required_equal_failures
            else RemoteResult.FAIL,
            RemoteResult.PASS
            if not self.metadata_consistency.required_equal_failures
            else RemoteResult.FAIL,
            RemoteResult.PASS
            if self.global_tensor_count_metadata == self.aggregated_tensor_count
            and all(
                item.global_tensor_count == self.global_tensor_count_metadata
                for item in self.split_identities
            )
            else RemoteResult.FAIL,
            RemoteResult.PASS
            if not self.duplicate_summary.exact_duplicate_count
            and not self.duplicate_summary.conflict_count
            else RemoteResult.FAIL,
            RemoteResult.FAIL
            if self.payload_span_summary.invalid_count
            else RemoteResult.WARN
            if self.payload_span_summary.unsupported_count
            else RemoteResult.PASS,
            RemoteResult.FAIL
            if self.payload_span_summary.overlap_count
            else RemoteResult.WARN
            if self.payload_span_summary.unsupported_count
            else RemoteResult.PASS,
            RemoteResult.PASS,
            RemoteResult.PASS,
        ]
        if [item.rule_id for item in self.findings] != [
            f"SPLIT-{index:03d}" for index in range(1, 13)
        ]:
            raise ValueError("split finding identifiers do not reconstruct")
        if [item.status for item in self.findings] != expected_statuses:
            raise ValueError("split finding statuses do not reconstruct")
        return self


class SplitInventoryEnvelope(StrictModel):
    inventory: SplitGGUFInventory
    integrity: Integrity


class SplitGGUFReport(StrictModel):
    report_schema: Literal["omiv.remote-split-gguf-report.v1"] = SPLIT_REPORT_SCHEMA
    execution: ReportExecution
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    inventory: SplitGGUFInventory
    findings: list[RemoteFinding]
    limitations: list[str]

    @model_validator(mode="after")
    def consistent(self) -> SplitGGUFReport:
        if self.inventory_sha256 != canonical_sha256(self.inventory.model_dump(mode="json")):
            raise ValueError("split report inventory digest mismatch")
        if self.findings != self.inventory.findings:
            raise ValueError("split report findings do not reconstruct")
        result = (
            RemoteResult.FAIL
            if any(item.status == RemoteResult.FAIL for item in self.findings)
            else RemoteResult.WARN
            if any(item.status == RemoteResult.WARN for item in self.findings)
            else RemoteResult.PASS
        )
        if self.execution != ReportExecution(
            result=result, exit_code=1 if result == RemoteResult.FAIL else 0
        ):
            raise ValueError("split report execution mismatch")
        return self


class SplitReportEnvelope(StrictModel):
    report: SplitGGUFReport
    integrity: Integrity
