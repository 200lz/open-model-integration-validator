"""Versioned built-in model-pack interfaces and registry."""

from omiv.model_packs.base import (
    ModelConstraints,
    ModelPack,
    ModelPackCapability,
    ModelPackMetadata,
    TensorClassification,
)
from omiv.model_packs.registry import (
    detect_model_pack,
    get_model_pack,
    list_model_packs,
)

__all__ = [
    "ModelConstraints",
    "ModelPack",
    "ModelPackCapability",
    "ModelPackMetadata",
    "TensorClassification",
    "detect_model_pack",
    "get_model_pack",
    "list_model_packs",
]
