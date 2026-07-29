"""Exact measured Qwen2 physical tensor ontology."""

from __future__ import annotations

import re

from omiv.gguf.models import StrictModel
from omiv.hf.models import CanonicalTensorIdentity

LAYER_RE = re.compile(r"^model\.layers\.(\d+)\.(.+)$")

LAYER_COMPONENTS = {
    "input_layernorm.weight": (
        "attention.input_norm.weight",
        "attention",
        "input_norm",
        "weight",
    ),
    "self_attn.q_proj.weight": (
        "attention.query.weight",
        "attention",
        "query",
        "weight",
    ),
    "self_attn.q_proj.bias": (
        "attention.query.bias",
        "attention",
        "query",
        "bias",
    ),
    "self_attn.k_proj.weight": (
        "attention.key.weight",
        "attention",
        "key",
        "weight",
    ),
    "self_attn.k_proj.bias": (
        "attention.key.bias",
        "attention",
        "key",
        "bias",
    ),
    "self_attn.v_proj.weight": (
        "attention.value.weight",
        "attention",
        "value",
        "weight",
    ),
    "self_attn.v_proj.bias": (
        "attention.value.bias",
        "attention",
        "value",
        "bias",
    ),
    "self_attn.o_proj.weight": (
        "attention.output.weight",
        "attention",
        "output",
        "weight",
    ),
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


class QwenTensorClassification(StrictModel):
    canonical: CanonicalTensorIdentity | None
    layer_component: str | None


def classify_qwen2_tensor(name: str) -> QwenTensorClassification:
    if name == "model.embed_tokens.weight":
        return QwenTensorClassification(
            canonical=CanonicalTensorIdentity(
                identity="qwen2.token_embedding.weight",
                scope="model",
                module="embedding",
                component="token_embedding",
                parameter="weight",
            ),
            layer_component=None,
        )
    if name == "model.norm.weight":
        return QwenTensorClassification(
            canonical=CanonicalTensorIdentity(
                identity="qwen2.output_norm.weight",
                scope="model",
                module="normalization",
                component="output_norm",
                parameter="weight",
            ),
            layer_component=None,
        )
    if name == "lm_head.weight":
        return QwenTensorClassification(
            canonical=CanonicalTensorIdentity(
                identity="qwen2.output_projection.weight",
                scope="model",
                module="output",
                component="output_projection",
                parameter="weight",
            ),
            layer_component=None,
        )
    match = LAYER_RE.match(name)
    if not match:
        return QwenTensorClassification(canonical=None, layer_component=None)
    layer_id, suffix = int(match.group(1)), match.group(2)
    detail = LAYER_COMPONENTS.get(suffix)
    if detail is None:
        return QwenTensorClassification(canonical=None, layer_component=None)
    identity_suffix, module, component, parameter = detail
    return QwenTensorClassification(
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
