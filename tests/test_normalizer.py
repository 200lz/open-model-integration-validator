from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import normalize_records, record

from omiv.errors import OmivInputError
from omiv.models import AttentionKind, FfnKind
from omiv.normalizer import KDA_MARKERS, MLA_MARKERS, normalize_inventory, write_inventory


def test_valid_measured_style_inventory(valid_inventory: object) -> None:
    inventory = valid_inventory
    assert inventory.source.record_count > 0  # type: ignore[attr-defined]
    assert inventory.observed_layer_ids == list(range(93))  # type: ignore[attr-defined]
    assert len(inventory.layers) == 93  # type: ignore[attr-defined]


def test_layer_zero_classified_dense(valid_inventory: object) -> None:
    layer = valid_inventory.layers[0]  # type: ignore[attr-defined]
    assert layer.id == 0
    assert layer.ffn.kind == FfnKind.DENSE


def test_layer_zero_missing_dense_component(
    tmp_path: Path, raw_records: list[dict[str, object]]
) -> None:
    raw_records[:] = [
        item
        for item in raw_records
        if item["name"] != "language_model.model.layers.0.mlp.down_proj.weight"
    ]
    inventory = normalize_records(tmp_path, raw_records)
    assert inventory.layers[0].ffn.kind == FfnKind.UNKNOWN
    assert any(d.code == "PARTIAL_DENSE_SIGNATURE" for d in inventory.diagnostics)


def test_dense_and_moe_evidence_conflict(
    tmp_path: Path, raw_records: list[dict[str, object]]
) -> None:
    raw_records.append(
        record(
            "language_model.model.layers.0.block_sparse_moe."
            "experts.0.w1.weight_packed"
        )
    )
    inventory = normalize_records(tmp_path, raw_records)
    assert inventory.layers[0].ffn.kind == FfnKind.CONFLICT


def test_g_proj_alone_does_not_classify_mla(tmp_path: Path) -> None:
    inventory = normalize_records(
        tmp_path,
        [record("language_model.model.layers.0.self_attn.g_proj.weight")],
    )
    assert inventory.layers[0].attention.kind == AttentionKind.UNKNOWN
    assert inventory.layers[0].attention.g_proj_present


def test_kda_mla_conflicting_signatures(tmp_path: Path) -> None:
    records = [
        record(f"language_model.model.layers.0.self_attn.{marker}")
        for marker in KDA_MARKERS | MLA_MARKERS
    ]
    inventory = normalize_records(tmp_path, records)
    assert inventory.layers[0].attention.kind == AttentionKind.CONFLICT


def test_malformed_top_level_object(tmp_path: Path) -> None:
    path = tmp_path / "object.json"
    path.write_text('{"records": []}', encoding="utf-8")
    with pytest.raises(OmivInputError, match="top-level JSON array"):
        normalize_inventory(path)


@pytest.mark.parametrize(
    "bad_record",
    [
        {"name": "x"},
        {
            "name": "x",
            "dtype": "BF16",
            "shape": ["1"],
            "shard": "s",
            "header_len": 8,
            "offsets": [0, 1],
        },
        {
            "name": "x",
            "dtype": "BF16",
            "shape": [1],
            "shard": "s",
            "header_len": 8,
            "offsets": [2, 1],
        },
    ],
)
def test_malformed_record(tmp_path: Path, bad_record: dict[str, object]) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps([bad_record]), encoding="utf-8")
    with pytest.raises(OmivInputError, match="record 0"):
        normalize_inventory(path)


def test_deterministic_normalization(
    tmp_path: Path, raw_records: list[dict[str, object]]
) -> None:
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps(raw_records), encoding="utf-8")
    inventory = normalize_inventory(raw)
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    write_inventory(inventory, first)
    write_inventory(normalize_inventory(raw), second)
    assert first.read_bytes() == second.read_bytes()


def test_stable_canonical_ordering(tmp_path: Path) -> None:
    names = [
        "language_model.model.layers.10.mlp.up_proj.weight",
        "language_model.model.layers.2.mlp.up_proj.weight",
        "language_model.model.layers.2.mlp.gate_proj.weight",
    ]
    inventory = normalize_records(tmp_path, [record(name) for name in reversed(names)])
    assert inventory.observed_layer_ids == [2, 10]
    assert [layer.id for layer in inventory.layers] == [2, 10]
    assert inventory.layers[0].ffn.dense_components == [
        "gate_proj.weight",
        "up_proj.weight",
    ]
