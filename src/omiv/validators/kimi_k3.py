"""Compatibility facade for the built-in Kimi K3 validator."""

from omiv.model_packs.kimi_k3.validator import (
    DENSE_SIGNATURE,
    validate_attn_001,
    validate_attn_002,
    validate_attnres_001,
    validate_attnres_002,
    validate_inventory,
    validate_layer_001,
    validate_layer_002,
    validate_moe_001,
    validate_moe_002,
    validate_tensor_001,
    validate_tensor_002,
)

__all__ = [
    "DENSE_SIGNATURE",
    "validate_attn_001",
    "validate_attn_002",
    "validate_attnres_001",
    "validate_attnres_002",
    "validate_inventory",
    "validate_layer_001",
    "validate_layer_002",
    "validate_moe_001",
    "validate_moe_002",
    "validate_tensor_001",
    "validate_tensor_002",
]
