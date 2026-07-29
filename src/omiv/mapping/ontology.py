"""Derived Qwen2 semantic views for HF and GGUF canonical inventories."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory, GGUFTensorDescriptor
from omiv.hf.models import CanonicalTensorIdentity, HFInventory
from omiv.mapping.models import SemanticTensorDescriptor, SourceKind

_GGUF_LAYER_RE = re.compile(r"^blk\.(\d+)\.([a-z0-9_]+)\.(weight|bias)$")

_MODEL_TENSORS = {
    "token_embd.weight": (
        "qwen2.token_embedding.weight",
        "embedding",
        "token_embedding",
        "weight",
    ),
    "output_norm.weight": (
        "qwen2.output_norm.weight",
        "normalization",
        "output_norm",
        "weight",
    ),
    "output.weight": (
        "qwen2.output_projection.weight",
        "output",
        "output_projection",
        "weight",
    ),
}

_LAYER_TENSORS = {
    ("attn_norm", "weight"): (
        "attention.input_norm.weight",
        "attention",
        "input_norm",
        "weight",
    ),
    ("attn_q", "weight"): (
        "attention.query.weight",
        "attention",
        "query",
        "weight",
    ),
    ("attn_q", "bias"): (
        "attention.query.bias",
        "attention",
        "query",
        "bias",
    ),
    ("attn_k", "weight"): (
        "attention.key.weight",
        "attention",
        "key",
        "weight",
    ),
    ("attn_k", "bias"): (
        "attention.key.bias",
        "attention",
        "key",
        "bias",
    ),
    ("attn_v", "weight"): (
        "attention.value.weight",
        "attention",
        "value",
        "weight",
    ),
    ("attn_v", "bias"): (
        "attention.value.bias",
        "attention",
        "value",
        "bias",
    ),
    ("attn_output", "weight"): (
        "attention.output.weight",
        "attention",
        "output",
        "weight",
    ),
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


class Qwen2GGUFClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical: CanonicalTensorIdentity | None


def classify_qwen2_gguf_name(name: str) -> Qwen2GGUFClassification:
    model_detail = _MODEL_TENSORS.get(name)
    if model_detail is not None:
        identity, module, component, parameter = model_detail
        return Qwen2GGUFClassification(
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
        return Qwen2GGUFClassification(canonical=None)
    layer_id = int(match.group(1))
    detail = _LAYER_TENSORS.get((match.group(2), match.group(3)))
    if detail is None:
        return Qwen2GGUFClassification(canonical=None)
    suffix, module, component, parameter = detail
    return Qwen2GGUFClassification(
        canonical=CanonicalTensorIdentity(
            identity=f"qwen2.layer.{layer_id}.{suffix}",
            scope="layer",
            layer_id=layer_id,
            module=module,
            component=component,
            parameter=parameter,  # type: ignore[arg-type]
        )
    )


def _target_descriptor(tensor: GGUFTensorDescriptor) -> SemanticTensorDescriptor:
    classification = classify_qwen2_gguf_name(tensor.name)
    canonical = classification.canonical
    return SemanticTensorDescriptor(
        exact_name=tensor.name,
        canonical_identity=None if canonical is None else canonical.identity,
        classification="unclassified" if canonical is None else "classified",
        scope=None if canonical is None else canonical.scope,
        layer_id=None if canonical is None else canonical.layer_id,
        module=None if canonical is None else canonical.module,
        component=None if canonical is None else canonical.component,
        parameter=None if canonical is None else canonical.parameter,
        source_kind=SourceKind.PHYSICAL,
        materialized=True,
        shape=tensor.shape,
        shape_order="gguf_on_disk_reader_tensor_shape",
        data_type=tensor.ggml_type,
    )


def qwen2_gguf_semantic_view(inventory: GGUFInventory) -> list[SemanticTensorDescriptor]:
    """Classify GGUF descriptors without depending on tensor file order."""
    descriptors = [_target_descriptor(tensor) for tensor in inventory.tensors]
    classified = [
        item.canonical_identity
        for item in descriptors
        if item.canonical_identity is not None
    ]
    duplicates = sorted(
        identity for identity in set(classified) if classified.count(identity) > 1
    )
    if duplicates:
        raise OmivInputError(
            "duplicate GGUF canonical identities: " + ", ".join(duplicates[:10])
        )
    return sorted(
        descriptors,
        key=lambda item: (
            item.canonical_identity is None,
            item.canonical_identity or "",
            item.exact_name,
        ),
    )


def hf_semantic_view(inventory: HFInventory) -> list[SemanticTensorDescriptor]:
    """Return physical and logical HF semantic entities in stable identity order."""
    descriptors: list[SemanticTensorDescriptor] = []
    physical_by_identity: dict[str, SemanticTensorDescriptor] = {}
    for tensor in inventory.tensors:
        canonical = tensor.canonical
        descriptor = SemanticTensorDescriptor(
            exact_name=tensor.source_name,
            canonical_identity=None if canonical is None else canonical.identity,
            classification=tensor.classification,
            scope=None if canonical is None else canonical.scope,
            layer_id=None if canonical is None else canonical.layer_id,
            module=None if canonical is None else canonical.module,
            component=None if canonical is None else canonical.component,
            parameter=None if canonical is None else canonical.parameter,
            source_kind=SourceKind.PHYSICAL,
            materialized=True,
            shape=tensor.shape,
            shape_order="huggingface_safetensors",
            data_type=tensor.dtype,
        )
        descriptors.append(descriptor)
        if descriptor.canonical_identity is not None:
            if descriptor.canonical_identity in physical_by_identity:
                raise OmivInputError(
                    "duplicate HF canonical identity: "
                    f"{descriptor.canonical_identity}"
                )
            physical_by_identity[descriptor.canonical_identity] = descriptor

    logical_seen: set[str] = set()
    for tie in inventory.logical_ties:
        if tie.logical_identity in logical_seen:
            raise OmivInputError(
                f"duplicate HF logical canonical identity: {tie.logical_identity}"
            )
        logical_seen.add(tie.logical_identity)
        physical = physical_by_identity.get(tie.physical_source_identity)
        descriptors.append(
            SemanticTensorDescriptor(
                exact_name=tie.logical_identity,
                canonical_identity=tie.logical_identity,
                classification="classified",
                scope="model",
                layer_id=None,
                module="output",
                component="output_projection",
                parameter="weight",
                source_kind=SourceKind.LOGICAL,
                materialized=tie.materialized,
                shape=[] if physical is None else physical.shape,
                shape_order="logical",
                data_type=None if physical is None else physical.data_type,
                physical_source_identity=tie.physical_source_identity,
            )
        )
    return sorted(
        descriptors,
        key=lambda item: (
            item.canonical_identity is None,
            item.canonical_identity or "",
            item.source_kind.value,
            item.exact_name,
        ),
    )
