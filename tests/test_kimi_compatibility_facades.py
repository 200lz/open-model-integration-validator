"""Compatibility covers module-owned symbols, not historical import side effects."""

from __future__ import annotations

import importlib

import pytest

MODULE_SYMBOLS = {
    ("omiv.contracts", "omiv.model_packs.kimi_k3.contracts"): (
        "ExpertSetPolicy",
        "UnclassifiedTensorPolicy",
        "DuplicateTensorPolicy",
        "DescriptorConsistencyPolicy",
        "ExpertComponent",
        "PHASE1_EXPERT_COMPONENTS",
        "PHASE1_EXPERT_COMPONENT_SET",
        "SharedExpertComponent",
        "SHARED_EXPERT_COMPONENTS",
        "SHARED_EXPERT_COMPONENT_SET",
        "AttentionResidualComponent",
        "ATTENTION_RESIDUAL_COMPONENTS",
        "ATTENTION_RESIDUAL_COMPONENT_SET",
        "ModelAttentionResidualComponent",
        "MODEL_ATTENTION_RESIDUAL_COMPONENTS",
        "MODEL_ATTENTION_RESIDUAL_COMPONENT_SET",
    ),
    ("omiv.normalizer", "omiv.model_packs.kimi_k3.checkpoint"): (
        "LAYER_RE",
        "EXPERT_RE",
        "DENSE_RE",
        "SHARED_RE",
        "SELF_ATTN_RE",
        "LAYER_RESIDUAL_RE",
        "MODEL_RESIDUAL_RE",
        "MOE_NAMESPACE_RE",
        "KDA_MARKERS",
        "MLA_MARKERS",
        "DENSE_COMPONENTS",
        "DESCRIPTOR_ENTITY_EXAMPLE_CAP",
        "UNCLASSIFIED_GROUP_CAP",
        "UNCLASSIFIED_EXAMPLES_PER_GROUP_CAP",
        "iter_raw_records",
        "normalize_inventory",
        "write_inventory",
    ),
    ("omiv.schema.loader", "omiv.model_packs.kimi_k3.schema"): (
        "KimiK3Schema",
        "load_schema",
    ),
    ("omiv.validators.kimi_k3", "omiv.model_packs.kimi_k3.validator"): (
        "DENSE_SIGNATURE",
        "validate_layer_001",
        "validate_layer_002",
        "validate_attn_001",
        "validate_attn_002",
        "validate_moe_001",
        "validate_moe_002",
        "validate_attnres_001",
        "validate_attnres_002",
        "validate_tensor_001",
        "validate_tensor_002",
        "validate_inventory",
    ),
}

SYMBOL_CASES = [
    (legacy_module, model_pack_module, symbol)
    for (legacy_module, model_pack_module), symbols in MODULE_SYMBOLS.items()
    for symbol in symbols
]


def test_compatibility_surface_covers_all_module_owned_symbols() -> None:
    assert len(SYMBOL_CASES) == 47


@pytest.mark.parametrize(
    ("legacy_module_name", "model_pack_module_name", "symbol"),
    SYMBOL_CASES,
)
def test_legacy_symbol_is_model_pack_symbol(
    legacy_module_name: str,
    model_pack_module_name: str,
    symbol: str,
) -> None:
    legacy_module = importlib.import_module(legacy_module_name)
    model_pack_module = importlib.import_module(model_pack_module_name)

    assert getattr(legacy_module, symbol) is getattr(model_pack_module, symbol)


@pytest.mark.parametrize(
    ("legacy_module_name", "expected_symbols"),
    [
        (legacy_module_name, symbols)
        for (legacy_module_name, _), symbols in MODULE_SYMBOLS.items()
        if legacy_module_name != "omiv.contracts"
    ],
)
def test_explicit_all_contains_module_owned_symbols(
    legacy_module_name: str,
    expected_symbols: tuple[str, ...],
) -> None:
    legacy_module = importlib.import_module(legacy_module_name)

    assert set(legacy_module.__all__) == set(expected_symbols)
