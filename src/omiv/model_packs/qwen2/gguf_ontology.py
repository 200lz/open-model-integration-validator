"""Qwen2 GGUF tensor ontology."""

from __future__ import annotations

import re

from omiv.hf.models import CanonicalTensorIdentity
from omiv.model_packs.base import TensorClassification

_GGUF_LAYER_RE = re.compile(r"^blk\.(\d+)\.([a-z0-9_]+)\.(weight|bias)$")
_MODEL_TENSORS = {
    "token_embd.weight": ("qwen2.token_embedding.weight", "embedding", "token_embedding", "weight"),
    "output_norm.weight": ("qwen2.output_norm.weight", "normalization", "output_norm", "weight"),
    "output.weight": ("qwen2.output_projection.weight", "output", "output_projection", "weight"),
}
_LAYER_TENSORS = {
    ("attn_norm", "weight"): ("attention.input_norm.weight", "attention", "input_norm", "weight"),
    ("attn_q", "weight"): ("attention.query.weight", "attention", "query", "weight"),
    ("attn_q", "bias"): ("attention.query.bias", "attention", "query", "bias"),
    ("attn_k", "weight"): ("attention.key.weight", "attention", "key", "weight"),
    ("attn_k", "bias"): ("attention.key.bias", "attention", "key", "bias"),
    ("attn_v", "weight"): ("attention.value.weight", "attention", "value", "weight"),
    ("attn_v", "bias"): ("attention.value.bias", "attention", "value", "bias"),
    ("attn_output", "weight"): ("attention.output.weight", "attention", "output", "weight"),
    ("ffn_norm", "weight"): (
        "ffn.post_attention_norm.weight",
        "ffn",
        "post_attention_norm",
        "weight",
    ),
    ("ffn_gate", "weight"): ("ffn.gate.weight", "ffn", "gate", "weight"),
    ("ffn_up", "weight"): ("ffn.up.weight", "ffn", "up", "weight"),
    ("ffn_down", "weight"): ("ffn.down.weight", "ffn", "down", "weight"),
}


def classify_gguf_tensor(name: str) -> TensorClassification:
    detail = _MODEL_TENSORS.get(name)
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
    match = _GGUF_LAYER_RE.fullmatch(name)
    if match is None:
        return TensorClassification(canonical=None)
    layer_id = int(match.group(1))
    detail = _LAYER_TENSORS.get((match.group(2), match.group(3)))
    if detail is None:
        return TensorClassification(canonical=None)
    suffix, module, component, parameter = detail
    return TensorClassification(
        canonical=CanonicalTensorIdentity(
            identity=f"qwen2.layer.{layer_id}.{suffix}",
            scope="layer",
            layer_id=layer_id,
            module=module,
            component=component,
            parameter=parameter,  # type: ignore[arg-type]
        )
    )
