"""Compatibility names for the Qwen2 pack's former HF ontology API."""

from omiv.model_packs.base import TensorClassification as QwenTensorClassification
from omiv.model_packs.qwen2.hf_ontology import (
    LAYER_COMPONENTS,
    LAYER_RE,
)
from omiv.model_packs.qwen2.hf_ontology import (
    classify_hf_tensor as classify_qwen2_tensor,
)

__all__ = [
    "LAYER_COMPONENTS",
    "LAYER_RE",
    "QwenTensorClassification",
    "classify_qwen2_tensor",
]
