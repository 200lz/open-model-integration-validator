"""Typed canonical GGUF inventories and comparison policies."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, JsonValue


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GGUFArtifactKind(StrEnum):
    MONOLITHIC = "monolithic"


class GGUFComparisonStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class GGUFComparisonSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class GGUFShardSummary(StrictModel):
    index: int = Field(ge=0)
    count: int = Field(ge=1)
    file_name: str
    byte_size: int = Field(ge=0)
    sha256: str


class GGUFArtifactSummary(StrictModel):
    kind: Literal["monolithic"]
    byte_size: int = Field(ge=0)
    sha256: str
    shards: list[GGUFShardSummary]


class GGUFHeaderSummary(StrictModel):
    version: int = Field(ge=1)
    endianness: Literal["little", "big", "unknown"]
    alignment: int = Field(ge=1)
    metadata_kv_count: int = Field(ge=0)
    tensor_count: int = Field(ge=0)


class GGUFIdentity(StrictModel):
    architecture: str | None
    model_name: str | None


class GGUFMetadataEntry(StrictModel):
    key: str
    value_type: str
    value: JsonValue = None
    array_element_type: str | None = None
    array_length: int | None = Field(default=None, ge=0)
    value_sha256: str | None = None


class GGUFTensorDescriptor(StrictModel):
    """Shape is GGUF on-disk order from ReaderTensor.shape, never tensor.data."""

    name: str
    shape: list[int]
    ggml_type: str


class GGUFSummary(StrictModel):
    tensor_type_counts: dict[str, int]
    observed_layer_ids: list[int]
    duplicate_tensor_name_count: int = Field(ge=0)
    tensor_shape_order: Literal["gguf_on_disk_reader_tensor_shape"]


class GGUFInventory(StrictModel):
    schema_version: Literal[1]
    artifact: GGUFArtifactSummary
    header: GGUFHeaderSummary
    identity: GGUFIdentity
    metadata: list[GGUFMetadataEntry]
    tensors: list[GGUFTensorDescriptor]
    summary: GGUFSummary


class TypeTransitionRule(StrictModel):
    source_type: str
    target_type: str
    selector: str = "*"


class MetadataDifferenceRule(StrictModel):
    key: str
    action: Literal["ignore", "allow", "warn", "require_equal"]


class GGUFComparisonPolicy(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    policy_schema_version: Literal[1] = Field(
        validation_alias=AliasChoices("policy_schema_version", "schema_version")
    )
    policy_id: str = Field(
        min_length=1,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        validation_alias=AliasChoices("policy_id", "name"),
    )
    description: str | None = None
    require_same_architecture: bool
    require_same_tensor_names: bool
    require_same_tensor_shapes: bool
    type_transition_rules: list[TypeTransitionRule]
    metadata_rules: list[MetadataDifferenceRule]
    unknown_metadata_drift: Literal["warn", "fail", "ignore"]
    evidence_example_cap: int = Field(default=10, ge=1, le=100)

    @property
    def schema_version(self) -> int:
        """Phase 3A compatibility alias."""
        return self.policy_schema_version

    @property
    def name(self) -> str:
        """Phase 3A compatibility alias."""
        return self.policy_id


class GGUFComparisonFinding(StrictModel):
    rule_id: str
    severity: GGUFComparisonSeverity
    status: GGUFComparisonStatus
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class GGUFComparisonReport(StrictModel):
    findings: list[GGUFComparisonFinding]

    @property
    def passed(self) -> bool:
        return not any(
            finding.status == GGUFComparisonStatus.FAIL for finding in self.findings
        )
