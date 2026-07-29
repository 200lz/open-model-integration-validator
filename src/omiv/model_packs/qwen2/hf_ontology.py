"""Qwen2 Hugging Face tensor ontology."""

from __future__ import annotations

import re

from omiv.hf.models import CanonicalTensorIdentity
from omiv.model_packs.base import TensorClassification

LAYER_RE = re.compile(r"^model\.layers\.(\d+)\.(.+)$")

LAYER_COMPONENTS = {
    "input_layernorm.weight": ("attention.input_norm.weight", "attention", "input_norm", "weight"),
    "self_attn.q_proj.weight": ("attention.query.weight", "attention", "query", "weight"),
    "self_attn.q_proj.bias": ("attention.query.bias", "attention", "query", "bias"),
    "self_attn.k_proj.weight": ("attention.key.weight", "attention", "key", "weight"),
    "self_attn.k_proj.bias": ("attention.key.bias", "attention", "key", "bias"),
    "self_attn.v_proj.weight": ("attention.value.weight", "attention", "value", "weight"),
    "self_attn.v_proj.bias": ("attention.value.bias", "attention", "value", "bias"),
    "self_attn.o_proj.weight": ("attention.output.weight", "attention", "output", "weight"),
    "post_attention_layernorm.weight": (
        "ffn.post_attention_norm.weight",
        "ffn",
        "post_attention_norm",
        "weight",
    ),
    "mlp.gate_proj.weight": ("ffn.gate.weight", "ffn", "gate", "weight"),
    "mlp.up_proj.weight": ("ffn.up.weight", "ffn", "up", "weight"),
    "mlp.down_proj.weight": ("ffn.down.weight", "ffn", "down", "weight"),
}


def classify_hf_tensor(name: str) -> TensorClassification:
    model_tensors = {
        "model.embed_tokens.weight": (
            "qwen2.token_embedding.weight",
            "embedding",
            "token_embedding",
            "weight",
        ),
        "model.norm.weight": ("qwen2.output_norm.weight", "normalization", "output_norm", "weight"),
        "lm_head.weight": (
            "qwen2.output_projection.weight",
            "output",
            "output_projection",
            "weight",
        ),
    }
    detail = model_tensors.get(name)
    if detail is not None:
        identity, module, component, parameter = detail
        return TensorClassification(
            canonical=CanonicalTensorIdentity(
                identity=identity,
                scope="model",
                module=module,
                component=component,
                parameter=parameter,  # type: ignore[arg-type]
            )
        )
    match = LAYER_RE.match(name)
    if not match:
        return TensorClassification(canonical=None)
    layer_id, suffix = int(match.group(1)), match.group(2)
    detail = LAYER_COMPONENTS.get(suffix)
    if detail is None:
        return TensorClassification(canonical=None)
    identity_suffix, module, component, parameter = detail
    return TensorClassification(
        canonical=CanonicalTensorIdentity(
            identity=f"qwen2.layer.{layer_id}.{identity_suffix}",
            scope="layer",
            layer_id=layer_id,
            module=module,
            component=component,
            parameter=parameter,  # type: ignore[arg-type]
        ),
        layer_component=suffix,
    )
