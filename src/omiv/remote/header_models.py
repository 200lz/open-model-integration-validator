"""Strict schemas for bounded remote GGUF header inventories."""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import Final, Literal

from pydantic import Field, JsonValue, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.remote.models import (
    SHA256_PATTERN,
    Integrity,
    RemoteFile,
    RemoteFinding,
    RemoteResult,
    RemoteSeverity,
    ReportExecution,
    RepositoryIdentity,
)

HEADER_INVENTORY_SCHEMA: Final = "omiv.remote-gguf-header-inventory.v1"
HEADER_REPORT_SCHEMA: Final = "omiv.remote-gguf-header-report.v1"
HEADER_POLICY_SCHEMA: Final = "omiv.remote-gguf-header-policy.v1"


class HeaderParserPolicy(StrictModel):
    policy_schema: Literal["omiv.remote-gguf-header-policy.v1"] = HEADER_POLICY_SCHEMA
    policy_id: Literal["omiv.gguf-v3.bounded-header.v1"] = (
        "omiv.gguf-v3.bounded-header.v1"
    )
    max_total_header_bytes: int = Field(default=64 * 1024 * 1024, ge=24)
    max_request_bytes: int = Field(default=256 * 1024, ge=24)
    read_ahead_bytes: int = Field(default=256 * 1024, ge=0)
    max_metadata_count: int = Field(default=1_000_000, ge=0)
    max_tensor_count: int = Field(default=1_000_000, ge=0)
    max_string_bytes: int = Field(default=16 * 1024 * 1024, ge=0)
    max_metadata_key_bytes: int = Field(default=1024, ge=1)
    max_array_elements: int = Field(default=10_000_000, ge=0)
    max_tensor_name_bytes: int = Field(default=4096, ge=1)
    max_tensor_dimensions: int = Field(default=4, ge=1, le=64)
    max_alignment: int = Field(default=4096, ge=1)
    max_request_count: int = Field(default=4096, ge=1)
    max_preview_bytes: int = Field(default=256, ge=0, le=65536)

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class RequestedInterval(StrictModel):
    """A half-open accepted HTTP range interval ``[start, end)``."""

    start: int = Field(ge=0)
    end: int = Field(ge=1)
    byte_count: int = Field(ge=1)

    @model_validator(mode="after")
    def consistent(self) -> RequestedInterval:
        if self.end <= self.start or self.byte_count != self.end - self.start:
            raise ValueError("requested interval is not a valid half-open interval")
        return self


class MetadataValueType(StrEnum):
    UINT8 = "UINT8"
    INT8 = "INT8"
    UINT16 = "UINT16"
    INT16 = "INT16"
    UINT32 = "UINT32"
    INT32 = "INT32"
    FLOAT32 = "FLOAT32"
    BOOL = "BOOL"
    STRING = "STRING"
    ARRAY = "ARRAY"
    UINT64 = "UINT64"
    INT64 = "INT64"
    FLOAT64 = "FLOAT64"


class RemoteMetadataEntry(StrictModel):
    key: str
    value_type: MetadataValueType
    array_element_type: MetadataValueType | None = None
    element_count: int | None = Field(default=None, ge=0)
    encoded_start: int = Field(ge=0)
    encoded_end: int = Field(ge=1)
    encoded_byte_length: int = Field(ge=1)
    encoded_sha256: str = Field(pattern=SHA256_PATTERN)
    summary_value: JsonValue = None
    string_preview: str | None = None
    preview: list[JsonValue] = Field(default_factory=list)
    preview_truncated: bool

    @model_validator(mode="after")
    def consistent(self) -> RemoteMetadataEntry:
        if self.encoded_end - self.encoded_start != self.encoded_byte_length:
            raise ValueError("metadata encoded span length mismatch")
        if self.value_type == MetadataValueType.ARRAY:
            if self.array_element_type is None or self.element_count is None:
                raise ValueError("array metadata requires element type and count")
        elif self.array_element_type is not None or self.element_count is not None:
            raise ValueError("scalar metadata cannot have array fields")
        return self


class RemoteTensorDescriptor(StrictModel):
    name: str
    dimensions: list[int]
    ggml_type_code: int = Field(ge=0)
    ggml_type_name: str
    data_offset: int = Field(ge=0)
    logical_element_count: int = Field(ge=1)
    encoded_start: int = Field(ge=0)
    encoded_end: int = Field(ge=1)
    encoded_byte_length: int = Field(ge=1)
    encoded_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def consistent(self) -> RemoteTensorDescriptor:
        if self.encoded_end - self.encoded_start != self.encoded_byte_length:
            raise ValueError("tensor descriptor encoded span length mismatch")
        return self


class LargestMetadataEntry(StrictModel):
    key: str
    encoded_byte_length: int = Field(ge=1)
    value_type: MetadataValueType


class HeaderInventorySummary(StrictModel):
    metadata_type_counts: dict[str, int]
    tensor_type_counts: dict[str, int]
    largest_metadata_entries: list[LargestMetadataEntry]
    representative_tensor_names: list[str]
    payload_relation: Literal["payload_before_eof", "payload_at_eof"]


class RemoteGGUFHeaderInventory(StrictModel):
    inventory_schema: Literal["omiv.remote-gguf-header-inventory.v1"] = (
        HEADER_INVENTORY_SCHEMA
    )
    provider: Literal["huggingface"]
    repository: RepositoryIdentity
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    file: RemoteFile
    gguf_version: Literal[3]
    tensor_count: int = Field(ge=0)
    metadata_count: int = Field(ge=0)
    alignment: int = Field(ge=1)
    metadata_and_descriptor_end: int = Field(ge=24)
    header_end_offset: int = Field(ge=24)
    padding_length: int = Field(ge=0)
    payload_start_offset: int = Field(ge=24)
    header_encoded_byte_length: int = Field(ge=24)
    highest_requested_offset: int = Field(ge=0)
    highest_accepted_offset: int = Field(ge=0)
    total_remote_bytes_accepted: int = Field(ge=1)
    request_count: int = Field(ge=1)
    requested_intervals: list[RequestedInterval]
    metadata: list[RemoteMetadataEntry]
    tensors: list[RemoteTensorDescriptor]
    summary: HeaderInventorySummary
    parser_policy: HeaderParserPolicy
    parser_policy_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def consistent(self) -> RemoteGGUFHeaderInventory:
        if self.metadata_count != len(self.metadata):
            raise ValueError("metadata count does not match inventory")
        if self.tensor_count != len(self.tensors):
            raise ValueError("tensor count does not match inventory")
        if [item.key for item in self.metadata] != sorted(item.key for item in self.metadata):
            raise ValueError("metadata entries must be sorted by key")
        if len({item.key for item in self.metadata}) != len(self.metadata):
            raise ValueError("metadata keys must be unique")
        if [item.name for item in self.tensors] != sorted(item.name for item in self.tensors):
            raise ValueError("tensor descriptors must be sorted by name")
        if len({item.name for item in self.tensors}) != len(self.tensors):
            raise ValueError("tensor names must be unique within the file")
        if self.metadata_and_descriptor_end + self.padding_length != self.payload_start_offset:
            raise ValueError("padding does not lead to payload start")
        if self.header_end_offset != self.payload_start_offset:
            raise ValueError("header end must equal payload start")
        if self.header_encoded_byte_length != self.payload_start_offset:
            raise ValueError("header encoded length must equal payload start")
        if self.payload_start_offset > self.file.byte_size:
            raise ValueError("payload start exceeds repository file size")
        if self.highest_accepted_offset >= self.payload_start_offset:
            raise ValueError("accepted bytes crossed into tensor payload")
        if self.highest_requested_offset >= self.payload_start_offset:
            raise ValueError("requested bytes crossed into tensor payload")
        if self.request_count != len(self.requested_intervals):
            raise ValueError("request count does not match intervals")
        if sum(item.byte_count for item in self.requested_intervals) != (
            self.total_remote_bytes_accepted
        ):
            raise ValueError("accepted byte count does not match intervals")
        if self.parser_policy_sha256 != self.parser_policy.digest:
            raise ValueError("parser policy digest mismatch")
        if self.metadata_count > self.parser_policy.max_metadata_count:
            raise ValueError("metadata count exceeds recorded parser policy")
        if self.tensor_count > self.parser_policy.max_tensor_count:
            raise ValueError("tensor count exceeds recorded parser policy")
        if (
            self.alignment > self.parser_policy.max_alignment
            or self.alignment & (self.alignment - 1)
        ):
            raise ValueError("alignment violates recorded parser policy")
        if self.total_remote_bytes_accepted > self.parser_policy.max_total_header_bytes:
            raise ValueError("accepted bytes exceed recorded parser policy")
        if self.request_count > self.parser_policy.max_request_count:
            raise ValueError("request count exceeds recorded parser policy")
        previous_end = 0
        for interval in self.requested_intervals:
            if interval.start != previous_end:
                raise ValueError("requested intervals must be contiguous and non-overlapping")
            if interval.byte_count > self.parser_policy.max_request_bytes:
                raise ValueError("requested interval exceeds recorded parser policy")
            previous_end = interval.end
        if self.highest_requested_offset != previous_end - 1:
            raise ValueError("highest requested offset does not match intervals")
        if self.highest_accepted_offset != previous_end - 1:
            raise ValueError("highest accepted offset does not match intervals")
        for entry in self.metadata:
            if entry.encoded_end > self.metadata_and_descriptor_end:
                raise ValueError("metadata span exceeds descriptor boundary")
            if len(entry.key.encode("utf-8")) > self.parser_policy.max_metadata_key_bytes:
                raise ValueError("metadata key exceeds recorded parser policy")
            if any(ord(character) < 32 or ord(character) == 127 for character in entry.key):
                raise ValueError("metadata key contains a control character")
            if (
                entry.element_count is not None
                and entry.element_count > self.parser_policy.max_array_elements
            ):
                raise ValueError("metadata array exceeds recorded parser policy")
            if len(entry.preview) > self.parser_policy.max_preview_bytes:
                raise ValueError("metadata preview exceeds recorded parser policy")
            if (
                entry.string_preview is not None
                and len(entry.string_preview.encode("utf-8"))
                > self.parser_policy.max_preview_bytes
            ):
                raise ValueError("string preview exceeds recorded parser policy")
        for tensor in self.tensors:
            if tensor.encoded_end > self.metadata_and_descriptor_end:
                raise ValueError("tensor descriptor span exceeds descriptor boundary")
            if len(tensor.name.encode("utf-8")) > self.parser_policy.max_tensor_name_bytes:
                raise ValueError("tensor name exceeds recorded parser policy")
            if any(ord(character) < 32 or ord(character) == 127 for character in tensor.name):
                raise ValueError("tensor name contains a control character")
            if not 1 <= len(tensor.dimensions) <= self.parser_policy.max_tensor_dimensions:
                raise ValueError("tensor dimensions exceed recorded parser policy")
            element_count = 1
            for dimension in tensor.dimensions:
                if dimension < 1 or element_count > ((1 << 64) - 1) // dimension:
                    raise ValueError("tensor logical element count is invalid")
                element_count *= dimension
            if tensor.logical_element_count != element_count:
                raise ValueError("tensor logical element count mismatch")
            if tensor.data_offset % self.alignment:
                raise ValueError("tensor relative offset is not aligned")
            if tensor.data_offset > self.file.byte_size - self.payload_start_offset:
                raise ValueError("tensor relative offset exceeds file boundary")
        expected_relation = (
            "payload_at_eof"
            if self.payload_start_offset == self.file.byte_size
            else "payload_before_eof"
        )
        if self.summary.payload_relation != expected_relation:
            raise ValueError("payload relation does not match file boundary")
        if self.summary.metadata_type_counts != dict(
            sorted(Counter(item.value_type.value for item in self.metadata).items())
        ):
            raise ValueError("metadata type summary mismatch")
        if self.summary.tensor_type_counts != dict(
            sorted(Counter(item.ggml_type_name for item in self.tensors).items())
        ):
            raise ValueError("tensor type summary mismatch")
        expected_largest = [
            LargestMetadataEntry(
                key=item.key,
                encoded_byte_length=item.encoded_byte_length,
                value_type=item.value_type,
            )
            for item in sorted(
                self.metadata,
                key=lambda item: (-item.encoded_byte_length, item.key),
            )[:10]
        ]
        if self.summary.largest_metadata_entries != expected_largest:
            raise ValueError("largest metadata summary mismatch")
        if self.summary.representative_tensor_names != [
            item.name for item in self.tensors[:10]
        ]:
            raise ValueError("representative tensor summary mismatch")
        return self


class HeaderInventoryEnvelope(StrictModel):
    inventory: RemoteGGUFHeaderInventory
    integrity: Integrity


class RemoteGGUFHeaderReport(StrictModel):
    report_schema: Literal["omiv.remote-gguf-header-report.v1"] = HEADER_REPORT_SCHEMA
    execution: ReportExecution
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    inventory: RemoteGGUFHeaderInventory
    findings: list[RemoteFinding]
    limitations: list[str]

    @model_validator(mode="after")
    def consistent(self) -> RemoteGGUFHeaderReport:
        if self.inventory_sha256 != canonical_sha256(
            self.inventory.model_dump(mode="json")
        ):
            raise ValueError("report inventory digest mismatch")
        expected = build_header_findings(self.inventory)
        if self.findings != expected:
            raise ValueError("header findings do not reconstruct from inventory")
        if self.execution != ReportExecution(result=RemoteResult.PASS, exit_code=0):
            raise ValueError("successful header inventory must produce PASS execution")
        return self


class HeaderReportEnvelope(StrictModel):
    report: RemoteGGUFHeaderReport
    integrity: Integrity


def build_header_findings(
    inventory: RemoteGGUFHeaderInventory,
) -> list[RemoteFinding]:
    messages = [
        "GGUF v3 fixed prefix and little-endian fields are valid.",
        "Metadata and tensor counts are within the recorded parser policy.",
        "All metadata binary encodings were fully parsed within configured bounds.",
        "All per-file tensor descriptors were syntactically parsed and uniquely named.",
        "Tensor relative offsets fit within the repository-declared file boundary.",
        "GGUF alignment is valid and bounded by policy.",
        "The exact half-open header boundary was derived from parsed descriptors.",
        "No accepted or requested byte reached the tensor payload boundary.",
        "Every HTTP Content-Range total agreed with repository file size.",
        "The header inventory and parser policy use deterministic canonical hashing.",
    ]
    evidence: list[dict[str, JsonValue]] = [
        {"gguf_version": inventory.gguf_version},
        {
            "metadata_count": inventory.metadata_count,
            "tensor_count": inventory.tensor_count,
        },
        {"metadata_entry_count": len(inventory.metadata)},
        {"tensor_descriptor_count": len(inventory.tensors)},
        {"repository_declared_file_size": inventory.file.byte_size},
        {"alignment": inventory.alignment},
        {
            "metadata_and_descriptor_end": inventory.metadata_and_descriptor_end,
            "payload_start_offset": inventory.payload_start_offset,
        },
        {
            "highest_accepted_offset": inventory.highest_accepted_offset,
            "payload_start_offset": inventory.payload_start_offset,
        },
        {"repository_declared_file_size": inventory.file.byte_size},
        {"parser_policy_sha256": inventory.parser_policy_sha256},
    ]
    return [
        RemoteFinding(
            rule_id=f"HEADER-{index:03d}",
            severity=RemoteSeverity.INFO,
            status=RemoteResult.PASS,
            message=message,
            evidence=item_evidence,
        )
        for index, (message, item_evidence) in enumerate(
            zip(messages, evidence, strict=True), start=1
        )
    ]
