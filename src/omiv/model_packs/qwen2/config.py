"""Qwen2 config interpretation and structural expectations."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from omiv.errors import OmivInputError
from omiv.hf.models import (
    HFConfigSummary,
    HFDiagnostic,
    HFTensorDescriptor,
    LogicalTensorTie,
)
from omiv.model_packs.qwen2.hf_ontology import (
    LAYER_COMPONENTS,
    classify_hf_tensor,
)

TORCH_TO_SAFETENSORS_DTYPE = {
    "bfloat16": "BF16",
    "float16": "F16",
    "float32": "F32",
}


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise OmivInputError(f"config {key} must be a non-empty string")
    return value


def _required_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise OmivInputError(f"config {key} must be a positive integer")
    return value


def validate_config(raw: dict[str, Any]) -> HFConfigSummary:
    architectures = raw.get("architectures")
    if (
        not isinstance(architectures, list)
        or not architectures
        or not all(isinstance(value, str) and value for value in architectures)
    ):
        raise OmivInputError("config architectures must be a non-empty string list")
    tie = raw.get("tie_word_embeddings")
    if not isinstance(tie, bool):
        raise OmivInputError("config tie_word_embeddings must be a boolean")
    config = HFConfigSummary(
        architectures=architectures,
        model_type=_required_string(raw, "model_type"),
        torch_dtype=_required_string(raw, "torch_dtype"),
        tie_word_embeddings=tie,
        hidden_size=_required_int(raw, "hidden_size"),
        layer_count=_required_int(raw, "num_hidden_layers"),
        attention_head_count=_required_int(raw, "num_attention_heads"),
        key_value_head_count=_required_int(raw, "num_key_value_heads"),
        intermediate_size=_required_int(raw, "intermediate_size"),
        vocabulary_size=_required_int(raw, "vocab_size"),
    )
    if config.model_type != "qwen2" or "Qwen2ForCausalLM" not in config.architectures:
        raise OmivInputError("selected model pack requires Qwen2ForCausalLM")
    if config.hidden_size % config.attention_head_count:
        raise OmivInputError("hidden_size must be divisible by num_attention_heads")
    return config


def _expected_shapes(config: HFConfigSummary) -> dict[str, list[int]]:
    hidden = config.hidden_size
    kv_width = hidden // config.attention_head_count * config.key_value_head_count
    intermediate = config.intermediate_size
    return {
        "input_layernorm.weight": [hidden],
        "self_attn.q_proj.weight": [hidden, hidden],
        "self_attn.q_proj.bias": [hidden],
        "self_attn.k_proj.weight": [kv_width, hidden],
        "self_attn.k_proj.bias": [kv_width],
        "self_attn.v_proj.weight": [kv_width, hidden],
        "self_attn.v_proj.bias": [kv_width],
        "self_attn.o_proj.weight": [hidden, hidden],
        "post_attention_layernorm.weight": [hidden],
        "mlp.gate_proj.weight": [intermediate, hidden],
        "mlp.up_proj.weight": [intermediate, hidden],
        "mlp.down_proj.weight": [hidden, intermediate],
    }


def validate_structure(
    tensors: list[HFTensorDescriptor],
    config: HFConfigSummary,
) -> tuple[list[LogicalTensorTie], list[HFDiagnostic]]:
    by_name = {tensor.source_name: tensor for tensor in tensors}
    layer_components: dict[int, set[str]] = defaultdict(set)
    for tensor in tensors:
        classification = classify_hf_tensor(tensor.source_name)
        canonical = classification.canonical
        if (
            canonical is not None
            and canonical.layer_id is not None
            and classification.layer_component is not None
        ):
            layer_components[canonical.layer_id].add(classification.layer_component)
    expected_layers = set(range(config.layer_count))
    observed_layers = set(layer_components)
    if observed_layers != expected_layers:
        raise OmivInputError(
            "observed Qwen2 layer IDs contradict config: "
            f"missing={sorted(expected_layers - observed_layers)}, "
            f"unexpected={sorted(observed_layers - expected_layers)}"
        )
    required = set(LAYER_COMPONENTS)
    shapes = _expected_shapes(config)
    for layer_id in sorted(expected_layers):
        observed = layer_components[layer_id]
        if observed != required:
            raise OmivInputError(
                f"layer {layer_id} component coverage mismatch: "
                f"missing={sorted(required - observed)}, "
                f"unexpected={sorted(observed - required)}"
            )
        for component, expected_shape in shapes.items():
            name = f"model.layers.{layer_id}.{component}"
            if by_name[name].shape != expected_shape:
                raise OmivInputError(
                    f"tensor {name!r} shape {by_name[name].shape} "
                    f"does not match expected {expected_shape}"
                )
    embedding = by_name.get("model.embed_tokens.weight")
    output_norm = by_name.get("model.norm.weight")
    lm_head = by_name.get("lm_head.weight")
    if embedding is None or embedding.shape != [
        config.vocabulary_size,
        config.hidden_size,
    ]:
        raise OmivInputError("token embedding is missing or has an incompatible shape")
    if output_norm is None or output_norm.shape != [config.hidden_size]:
        raise OmivInputError("output norm is missing or has an incompatible shape")
    if lm_head is not None and lm_head.shape != [
        config.vocabulary_size,
        config.hidden_size,
    ]:
        raise OmivInputError("physical lm_head.weight has an incompatible shape")

    expected_dtype = TORCH_TO_SAFETENSORS_DTYPE.get(config.torch_dtype)
    if expected_dtype is not None:
        mismatch = sorted(
            tensor.source_name for tensor in tensors if tensor.dtype != expected_dtype
        )
        if mismatch:
            raise OmivInputError(
                f"checkpoint dtype contradicts torch_dtype; examples={mismatch[:10]}"
            )

    diagnostics: list[HFDiagnostic] = []
    ties: list[LogicalTensorTie] = []
    if config.tie_word_embeddings:
        ties.append(
            LogicalTensorTie(
                logical_identity="qwen2.output_projection.weight",
                physical_source_identity="qwen2.token_embedding.weight",
                materialized=lm_head is not None,
                evidence={
                    "config_tie_word_embeddings": True,
                    "physical_lm_head_present": lm_head is not None,
                    "token_embedding_present": True,
                },
            )
        )
        if lm_head is not None:
            diagnostics.append(
                HFDiagnostic(
                    code="TIED_WEIGHT_PAYLOAD_EQUALITY_UNVERIFIED",
                    severity="warning",
                    message=(
                        "Both tied physical tensors are materialized; payload equality "
                        "was not checked"
                    ),
                    evidence={"logical_identity": "qwen2.output_projection.weight"},
                )
            )
    elif lm_head is None:
        raise OmivInputError("tie_word_embeddings is false but physical lm_head.weight is absent")
    return ties, diagnostics
