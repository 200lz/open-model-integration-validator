from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

DTYPE_BYTES = {"BF16": 2, "F32": 4}


def qwen_config(
    *,
    layers: int = 2,
    tie: bool = True,
    torch_dtype: str = "bfloat16",
) -> dict[str, Any]:
    return {
        "architectures": ["Qwen2ForCausalLM"],
        "model_type": "qwen2",
        "torch_dtype": torch_dtype,
        "tie_word_embeddings": tie,
        "hidden_size": 8,
        "num_hidden_layers": layers,
        "num_attention_heads": 4,
        "num_key_value_heads": 2,
        "intermediate_size": 12,
        "vocab_size": 16,
    }


def qwen_shapes(layers: int = 2, *, lm_head: bool = False) -> dict[str, list[int]]:
    values: dict[str, list[int]] = {
        "model.embed_tokens.weight": [16, 8],
        "model.norm.weight": [8],
    }
    if lm_head:
        values["lm_head.weight"] = [16, 8]
    for layer in range(layers):
        prefix = f"model.layers.{layer}."
        values.update(
            {
                prefix + "input_layernorm.weight": [8],
                prefix + "self_attn.q_proj.weight": [8, 8],
                prefix + "self_attn.q_proj.bias": [8],
                prefix + "self_attn.k_proj.weight": [4, 8],
                prefix + "self_attn.k_proj.bias": [4],
                prefix + "self_attn.v_proj.weight": [4, 8],
                prefix + "self_attn.v_proj.bias": [4],
                prefix + "self_attn.o_proj.weight": [8, 8],
                prefix + "post_attention_layernorm.weight": [8],
                prefix + "mlp.gate_proj.weight": [12, 8],
                prefix + "mlp.up_proj.weight": [12, 8],
                prefix + "mlp.down_proj.weight": [8, 12],
            }
        )
    return values


def descriptors_from_shapes(
    shapes: dict[str, list[int]],
    *,
    dtype: str = "BF16",
    initial_gap: int = 0,
    gap_after: str | None = None,
    gap_bytes: int = 0,
) -> tuple[dict[str, dict[str, Any]], int]:
    offset = initial_gap
    descriptors: dict[str, dict[str, Any]] = {}
    for name in sorted(shapes):
        shape = shapes[name]
        elements = 1
        for dimension in shape:
            elements *= dimension
        length = elements * DTYPE_BYTES[dtype]
        descriptors[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [offset, offset + length],
        }
        offset += length
        if name == gap_after:
            offset += gap_bytes
    return descriptors, offset


def write_safetensors(
    path: Path,
    descriptors: dict[str, dict[str, Any]],
    *,
    metadata: dict[str, str] | None = None,
    payload_length: int | None = None,
    reverse_header_order: bool = False,
) -> None:
    items = list(descriptors.items())
    if reverse_header_order:
        items.reverse()
    header: dict[str, Any] = dict(items)
    if metadata is not None:
        header["__metadata__"] = metadata
    encoded = json.dumps(header, separators=(",", ":")).encode()
    maximum = max(
        (descriptor["data_offsets"][1] for descriptor in descriptors.values()),
        default=0,
    )
    payload_size = maximum if payload_length is None else payload_length
    path.write_bytes(
        struct.pack("<Q", len(encoded)) + encoded + b"\xa5" * payload_size
    )


def write_config(model_dir: Path, config: dict[str, Any]) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    (model_dir / "config.json").write_text(
        json.dumps(config, sort_keys=True), encoding="utf-8"
    )


def make_monolithic(
    model_dir: Path,
    *,
    layers: int = 2,
    tie: bool = True,
    lm_head: bool = False,
    dtype: str = "BF16",
    extra_shapes: dict[str, list[int]] | None = None,
) -> dict[str, dict[str, Any]]:
    write_config(
        model_dir,
        qwen_config(
            layers=layers,
            tie=tie,
            torch_dtype={"BF16": "bfloat16", "F32": "float32"}[dtype],
        ),
    )
    shapes = qwen_shapes(layers, lm_head=lm_head)
    shapes.update(extra_shapes or {})
    descriptors, _ = descriptors_from_shapes(shapes, dtype=dtype)
    write_safetensors(model_dir / "model.safetensors", descriptors)
    return descriptors


def write_index(
    model_dir: Path,
    weight_map: dict[str, str],
    *,
    total_size: int | None = None,
) -> None:
    metadata: dict[str, int] = {}
    if total_size is not None:
        metadata["total_size"] = total_size
    (model_dir / "model.safetensors.index.json").write_text(
        json.dumps(
            {"metadata": metadata, "weight_map": weight_map},
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def make_sharded(model_dir: Path, *, reverse_shards: bool = False) -> None:
    write_config(model_dir, qwen_config())
    shapes = qwen_shapes()
    names = sorted(shapes)
    split = len(names) // 2
    groups = [names[:split], names[split:]]
    shard_names = ["model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"]
    if reverse_shards:
        shard_names.reverse()
    weight_map: dict[str, str] = {}
    total = 0
    for shard_name, group in zip(shard_names, groups, strict=True):
        shard_shapes = {name: shapes[name] for name in group}
        descriptors, size = descriptors_from_shapes(shard_shapes)
        write_safetensors(model_dir / shard_name, descriptors)
        total += size
        weight_map.update({name: shard_name for name in group})
    write_index(model_dir, weight_map, total_size=total)


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
