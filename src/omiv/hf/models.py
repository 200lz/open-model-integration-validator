"""Typed canonical local-HF checkpoint inventory models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class HFSmallFileSummary(StrictModel):
    file_name: str
    byte_size: int = Field(ge=0)
    sha256: str


class HFShardSummary(StrictModel):
    index: int = Field(ge=0)
    count: int = Field(ge=1)
    file_name: str
    byte_size: int = Field(ge=0)
    header_length: int = Field(ge=0)
    payload_length: int = Field(ge=0)


class HFArtifactSummary(StrictModel):
    kind: Literal["monolithic", "sharded"]
    config_file: HFSmallFileSummary
    index_file: HFSmallFileSummary | None
    shards: list[HFShardSummary]


class HFConfigSummary(StrictModel):
    architectures: list[str]
    model_type: str
    torch_dtype: str
    tie_word_embeddings: bool
    hidden_size: int = Field(gt=0)
    layer_count: int = Field(gt=0)
    attention_head_count: int = Field(gt=0)
    key_value_head_count: int = Field(gt=0)
    intermediate_size: int = Field(gt=0)
    vocabulary_size: int = Field(gt=0)


class CanonicalTensorIdentity(StrictModel):
    identity: str
    scope: Literal["model", "layer"]
    layer_id: int | None = Field(default=None, ge=0)
    module: str
    component: str
    parameter: Literal["weight", "bias"]


class HFTensorDescriptor(StrictModel):
    source_name: str
    canonical: CanonicalTensorIdentity | None
    classification: Literal["classified", "unclassified"]
    dtype: str
    shape: list[int]
    shape_order: Literal["huggingface_safetensors"]
    shard_file: str
    data_offsets: tuple[int, int]
    payload_byte_length: int = Field(ge=0)


class LogicalTensorTie(StrictModel):
    logical_identity: str
    physical_source_identity: str
    materialized: bool
    evidence: dict[str, JsonValue]


class HFDiagnostic(StrictModel):
    code: str
    severity: Literal["info", "warning"]
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class HFProvenance(StrictModel):
    available: bool
    repository: str | None = None
    revision: str | None = None
    source: str | None = None
    purpose: str | None = None


class HFSummary(StrictModel):
    physical_tensor_count: int = Field(ge=0)
    logical_tie_count: int = Field(ge=0)
    dtype_counts: dict[str, int]
    observed_layer_ids: list[int]
    classified_tensor_count: int = Field(ge=0)
    unclassified_tensor_count: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    overlap_count: int = Field(ge=0)


class HFInventory(StrictModel):
    schema_id: Literal["omiv.hf-inventory.v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    canonicalization: Literal["omiv-json-v1"]
    canonical_sha256: str
    artifact: HFArtifactSummary
    provenance: HFProvenance
    config: HFConfigSummary
    tensors: list[HFTensorDescriptor]
    logical_ties: list[LogicalTensorTie]
    summary: HFSummary
    diagnostics: list[HFDiagnostic]
