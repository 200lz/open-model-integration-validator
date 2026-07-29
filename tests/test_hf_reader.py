from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from hf_helpers import (
    descriptors_from_shapes,
    make_monolithic,
    make_sharded,
    qwen_config,
    qwen_shapes,
    write_config,
    write_index,
    write_safetensors,
)

from omiv.errors import OmivInputError
from omiv.hf.ontology import LAYER_COMPONENTS, classify_qwen2_tensor
from omiv.hf.reader import read_hf_inventory
from omiv.hf.safetensors import parse_safetensors_header


def _rewrite(
    model_dir: Path,
    descriptors: dict[str, dict[str, object]],
) -> None:
    write_safetensors(model_dir / "model.safetensors", descriptors)


def test_valid_monolithic_qwen_inventory(tmp_path: Path) -> None:
    make_monolithic(tmp_path)
    inventory = read_hf_inventory(tmp_path)
    assert inventory.artifact.kind == "monolithic"
    assert inventory.summary.physical_tensor_count == 26
    assert inventory.summary.observed_layer_ids == [0, 1]
    assert inventory.summary.classified_tensor_count == 26
    assert inventory.summary.unclassified_tensor_count == 0


def test_all_qwen_canonical_identities() -> None:
    assert (
        classify_qwen2_tensor("model.embed_tokens.weight").canonical.identity
        == "qwen2.token_embedding.weight"
    )
    assert (
        classify_qwen2_tensor("model.norm.weight").canonical.identity
        == "qwen2.output_norm.weight"
    )
    assert (
        classify_qwen2_tensor("lm_head.weight").canonical.identity
        == "qwen2.output_projection.weight"
    )
    for suffix, detail in LAYER_COMPONENTS.items():
        result = classify_qwen2_tensor(f"model.layers.7.{suffix}")
        assert result.canonical is not None
        assert result.canonical.identity == f"qwen2.layer.7.{detail[0]}"


def test_missing_layer_component(tmp_path: Path) -> None:
    descriptors = make_monolithic(tmp_path)
    descriptors.pop("model.layers.1.self_attn.q_proj.bias")
    _rewrite(tmp_path, descriptors)
    with pytest.raises(OmivInputError, match="component coverage mismatch"):
        read_hf_inventory(tmp_path)


def test_unexpected_layer(tmp_path: Path) -> None:
    descriptors = make_monolithic(tmp_path)
    extra_shapes = {
        f"model.layers.2.{suffix}": shape
        for suffix, shape in {
            key: qwen_shapes(1)[f"model.layers.0.{key}"]
            for key in LAYER_COMPONENTS
        }.items()
    }
    offset = max(item["data_offsets"][1] for item in descriptors.values())
    extra, _ = descriptors_from_shapes(extra_shapes, initial_gap=offset)
    descriptors.update(extra)
    _rewrite(tmp_path, descriptors)
    with pytest.raises(OmivInputError, match="unexpected=\\[2\\]"):
        read_hf_inventory(tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        "model.layers.0.self_attn.q_proj.weight",
        "model.layers.0.self_attn.k_proj.weight",
        "model.layers.0.self_attn.v_proj.bias",
        "model.layers.0.mlp.down_proj.weight",
        "model.layers.0.input_layernorm.weight",
        "model.embed_tokens.weight",
    ],
)
def test_qwen_shape_mismatches(tmp_path: Path, name: str) -> None:
    shapes = qwen_shapes()
    shapes[name] = [1]
    write_config(tmp_path, qwen_config())
    descriptors, _ = descriptors_from_shapes(shapes)
    _rewrite(tmp_path, descriptors)
    with pytest.raises(OmivInputError, match="shape|embedding|norm"):
        read_hf_inventory(tmp_path)


def test_dtype_config_mismatch(tmp_path: Path) -> None:
    write_config(tmp_path, qwen_config(torch_dtype="bfloat16"))
    descriptors, _ = descriptors_from_shapes(qwen_shapes(), dtype="F32")
    _rewrite(tmp_path, descriptors)
    with pytest.raises(OmivInputError, match="dtype contradicts"):
        read_hf_inventory(tmp_path)


def test_unknown_tensor_is_retained(tmp_path: Path) -> None:
    make_monolithic(tmp_path, extra_shapes={"model.extra_probe.weight": [1]})
    inventory = read_hf_inventory(tmp_path)
    unknown = next(
        tensor for tensor in inventory.tensors if tensor.source_name == "model.extra_probe.weight"
    )
    assert unknown.classification == "unclassified"
    assert unknown.canonical is None
    assert inventory.summary.unclassified_tensor_count == 1


def test_tied_embedding_without_physical_head(tmp_path: Path) -> None:
    make_monolithic(tmp_path, tie=True, lm_head=False)
    inventory = read_hf_inventory(tmp_path)
    assert len(inventory.logical_ties) == 1
    assert not inventory.logical_ties[0].materialized
    assert not any(tensor.source_name == "lm_head.weight" for tensor in inventory.tensors)


def test_tied_embedding_with_physical_head(tmp_path: Path) -> None:
    make_monolithic(tmp_path, tie=True, lm_head=True)
    inventory = read_hf_inventory(tmp_path)
    assert inventory.logical_ties[0].materialized
    assert any(tensor.source_name == "lm_head.weight" for tensor in inventory.tensors)
    assert any(
        diagnostic.code == "TIED_WEIGHT_PAYLOAD_EQUALITY_UNVERIFIED"
        for diagnostic in inventory.diagnostics
    )


def test_untied_missing_physical_head_is_error(tmp_path: Path) -> None:
    make_monolithic(tmp_path, tie=False, lm_head=False)
    with pytest.raises(OmivInputError, match="physical lm_head.weight is absent"):
        read_hf_inventory(tmp_path)


def test_valid_sharded_checkpoint(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    inventory = read_hf_inventory(tmp_path)
    assert inventory.artifact.kind == "sharded"
    assert [shard.file_name for shard in inventory.artifact.shards] == [
        "model-00001-of-00002.safetensors",
        "model-00002-of-00002.safetensors",
    ]


def test_missing_shard(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    (tmp_path / "model-00002-of-00002.safetensors").unlink()
    with pytest.raises(OmivInputError, match="missing"):
        read_hf_inventory(tmp_path)


def test_undeclared_shard_tensor(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    index_path = tmp_path / "model.safetensors.index.json"
    index = json.loads(index_path.read_text())
    index["weight_map"].pop(next(iter(index["weight_map"])))
    index_path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(OmivInputError, match="undeclared"):
        read_hf_inventory(tmp_path)


def test_tensor_missing_from_declared_shard(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    index_path = tmp_path / "model.safetensors.index.json"
    index = json.loads(index_path.read_text())
    index["weight_map"]["ghost.weight"] = "model-00001-of-00002.safetensors"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(OmivInputError, match="missing"):
        read_hf_inventory(tmp_path)


def test_duplicate_tensor_across_shards(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    first = parse_safetensors_header(tmp_path / "model-00001-of-00002.safetensors")
    second = parse_safetensors_header(tmp_path / "model-00002-of-00002.safetensors")
    shapes = {tensor.name: tensor.shape for tensor in second.tensors}
    shapes[first.tensors[0].name] = first.tensors[0].shape
    descriptors, _ = descriptors_from_shapes(shapes)
    write_safetensors(tmp_path / second.file_name, descriptors)
    with pytest.raises(OmivInputError, match="duplicate tensor name across shards"):
        read_hf_inventory(tmp_path)


@pytest.mark.parametrize(
    "unsafe",
    ["/tmp/model.safetensors", "../model.safetensors", "dir/model.safetensors"],
)
def test_unsafe_index_shard_path(tmp_path: Path, unsafe: str) -> None:
    write_config(tmp_path, qwen_config())
    write_index(tmp_path, {"x": unsafe})
    with pytest.raises(OmivInputError, match="unsafe index shard"):
        read_hf_inventory(tmp_path)


def test_symlink_escape(tmp_path: Path) -> None:
    model_dir = tmp_path / "model"
    outside = tmp_path / "outside.safetensors"
    write_config(model_dir, qwen_config())
    descriptors, total = descriptors_from_shapes(qwen_shapes())
    write_safetensors(outside, descriptors)
    (model_dir / "shard.safetensors").symlink_to(outside)
    write_index(
        model_dir,
        {name: "shard.safetensors" for name in descriptors},
        total_size=total,
    )
    with pytest.raises(OmivInputError, match="outside model directory"):
        read_hf_inventory(model_dir)


def test_non_regular_shard(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    write_config(tmp_path, qwen_config())
    os.mkfifo(tmp_path / "shard.safetensors")
    write_index(tmp_path, {"x": "shard.safetensors"})
    with pytest.raises(OmivInputError, match="regular file"):
        read_hf_inventory(tmp_path)


def test_index_total_size_mismatch(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    index_path = tmp_path / "model.safetensors.index.json"
    index = json.loads(index_path.read_text())
    index["metadata"]["total_size"] += 1
    index_path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(OmivInputError, match="total_size mismatch"):
        read_hf_inventory(tmp_path)


def test_both_layouts_are_rejected(tmp_path: Path) -> None:
    make_monolithic(tmp_path)
    (tmp_path / "model.safetensors.index.json").write_text(
        '{"metadata":{},"weight_map":{}}', encoding="utf-8"
    )
    with pytest.raises(OmivInputError, match="both monolithic and indexed"):
        read_hf_inventory(tmp_path)


def test_deterministic_shard_and_header_order(tmp_path: Path) -> None:
    make_sharded(tmp_path)
    first = read_hf_inventory(tmp_path)
    index_path = tmp_path / "model.safetensors.index.json"
    index = json.loads(index_path.read_text())
    index_path.write_text(
        json.dumps(
            {
                "weight_map": dict(reversed(list(index["weight_map"].items()))),
                "metadata": index["metadata"],
            }
        ),
        encoding="utf-8",
    )
    for shard_path in sorted(tmp_path.glob("model-*.safetensors")):
        parsed = parse_safetensors_header(shard_path)
        descriptors = {
            tensor.name: {
                "dtype": tensor.dtype,
                "shape": tensor.shape,
                "data_offsets": list(tensor.data_offsets),
            }
            for tensor in parsed.tensors
        }
        write_safetensors(shard_path, descriptors, reverse_header_order=True)
    second = read_hf_inventory(tmp_path)
    assert first.model_dump(mode="json", by_alias=True) == second.model_dump(
        mode="json", by_alias=True
    )
