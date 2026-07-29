"""Built-in Qwen2 model pack."""

from __future__ import annotations

from typing import Any

from omiv.hf.models import (
    HFConfigSummary,
    HFDiagnostic,
    HFTensorDescriptor,
    LogicalTensorTie,
)
from omiv.model_packs.base import (
    ModelConstraints,
    ModelPack,
    ModelPackCapability,
    TensorClassification,
)
from omiv.model_packs.qwen2.config import validate_config, validate_structure
from omiv.model_packs.qwen2.gguf_ontology import classify_gguf_tensor
from omiv.model_packs.qwen2.hf_ontology import classify_hf_tensor


class Qwen2ModelPack(ModelPack):
    pack_id = "qwen2"
    pack_version = 1
    model_family = "qwen2"
    description = "Production Qwen2 HF and GGUF semantic ontology."
    capabilities = frozenset(
        {
            ModelPackCapability.HF_ONTOLOGY,
            ModelPackCapability.GGUF_ONTOLOGY,
            ModelPackCapability.SEMANTIC_MAPPING,
        }
    )
    supported_source_formats = frozenset({"huggingface-safetensors"})
    supported_target_formats = frozenset({"gguf"})

    def classify_hf_tensor(self, name: str) -> TensorClassification:
        return classify_hf_tensor(name)

    def classify_gguf_tensor(self, name: str) -> TensorClassification:
        return classify_gguf_tensor(name)

    def validate_hf_config(self, raw: dict[str, Any]) -> HFConfigSummary:
        return validate_config(raw)

    def validate_hf_structure(
        self,
        tensors: list[HFTensorDescriptor],
        config: HFConfigSummary,
    ) -> tuple[list[LogicalTensorTie], list[HFDiagnostic]]:
        return validate_structure(tensors, config)

    def provide_model_constraints(self) -> ModelConstraints:
        return ModelConstraints(logical_tie_required=True)
