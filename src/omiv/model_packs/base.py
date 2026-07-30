"""Typed, capability-gated model-pack interface."""

from __future__ import annotations

from abc import ABC
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.models import (
    CanonicalTensorIdentity,
    HFConfigSummary,
    HFDiagnostic,
    HFTensorDescriptor,
    LogicalTensorTie,
)
from omiv.models import ModelInventory, ValidationReport

if TYPE_CHECKING:
    from omiv.mapping.models import MappingManifest, RealizationEvidence


class ModelPackCapability(StrEnum):
    HF_ONTOLOGY = "hf_ontology"
    GGUF_ONTOLOGY = "gguf_ontology"
    CHECKPOINT_SCHEMA = "checkpoint_schema"
    CHECKPOINT_ONTOLOGY = "checkpoint_ontology"
    SEMANTIC_MAPPING = "semantic_mapping"
    MOE_STRUCTURE = "moe_structure"
    MULTIMODAL_STRUCTURE = "multimodal_structure"


class TensorClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical: CanonicalTensorIdentity | None
    layer_component: str | None = None


class ModelConstraints(BaseModel):
    """Declarative identities used by generic validation rules."""

    model_config = ConfigDict(extra="forbid")

    logical_tie_required: bool = False


class ModelPackMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_schema: Literal["omiv.model-pack.v1"] = "omiv.model-pack.v1"
    pack_id: str
    pack_schema_version: int
    pack_version: int
    model_family: str
    description: str
    capabilities: list[ModelPackCapability]
    supported_formats: list[str]
    supported_source_formats: list[str]
    supported_target_formats: list[str]
    production_supported: bool
    test_only: bool

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))


class ModelPack(ABC):
    """Safe built-in extension point with explicit capability checks."""

    pack_id: str
    pack_schema_version: int = 1
    pack_version: int
    model_family: str
    description: str
    capabilities: frozenset[ModelPackCapability]
    supported_source_formats: frozenset[str]
    supported_target_formats: frozenset[str]
    production_supported: bool = True
    test_only: bool = False

    @property
    def metadata(self) -> ModelPackMetadata:
        return ModelPackMetadata(
            pack_id=self.pack_id,
            pack_schema_version=self.pack_schema_version,
            pack_version=self.pack_version,
            model_family=self.model_family,
            description=self.description,
            capabilities=sorted(self.capabilities, key=str),
            supported_formats=sorted(
                self.supported_source_formats | self.supported_target_formats
            ),
            supported_source_formats=sorted(self.supported_source_formats),
            supported_target_formats=sorted(self.supported_target_formats),
            production_supported=self.production_supported,
            test_only=self.test_only,
        )

    def require(self, capability: ModelPackCapability) -> None:
        if capability not in self.capabilities:
            raise OmivInputError(
                f"model pack {self.pack_id!r} does not support capability {capability.value!r}"
            )

    def classify_hf_tensor(self, name: str) -> TensorClassification:
        self.require(ModelPackCapability.HF_ONTOLOGY)
        raise OmivInputError(f"model pack {self.pack_id!r} has no HF classifier")

    def classify_gguf_tensor(self, name: str) -> TensorClassification:
        self.require(ModelPackCapability.GGUF_ONTOLOGY)
        raise OmivInputError(f"model pack {self.pack_id!r} has no GGUF classifier")

    def validate_hf_config(self, raw: dict[str, Any]) -> HFConfigSummary:
        self.require(ModelPackCapability.HF_ONTOLOGY)
        raise OmivInputError(f"model pack {self.pack_id!r} has no HF config policy")

    def validate_hf_structure(
        self,
        tensors: list[HFTensorDescriptor],
        config: HFConfigSummary,
    ) -> tuple[list[LogicalTensorTie], list[HFDiagnostic]]:
        self.require(ModelPackCapability.HF_ONTOLOGY)
        raise OmivInputError(f"model pack {self.pack_id!r} has no HF structure policy")

    def normalize_checkpoint(self, path: Path) -> ModelInventory:
        self.require(ModelPackCapability.CHECKPOINT_ONTOLOGY)
        raise OmivInputError(f"model pack {self.pack_id!r} has no checkpoint ontology")

    def validate_checkpoint(self, inventory: ModelInventory, schema: object) -> ValidationReport:
        self.require(ModelPackCapability.CHECKPOINT_SCHEMA)
        raise OmivInputError(f"model pack {self.pack_id!r} has no checkpoint schema")

    def load_default_mapping_manifest(self) -> MappingManifest:
        self.require(ModelPackCapability.SEMANTIC_MAPPING)
        raise OmivInputError(f"model pack {self.pack_id!r} has no default mapping manifest")

    def provide_model_constraints(self) -> ModelConstraints:
        return ModelConstraints()

    def provide_realization_evidence(self) -> tuple[RealizationEvidence, ...]:
        """Return immutable, built-in evidence owned by this model pack."""
        return ()
