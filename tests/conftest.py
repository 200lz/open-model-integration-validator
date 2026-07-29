from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from omiv.contracts import PHASE1_EXPERT_COMPONENT_SET
from omiv.models import ModelInventory
from omiv.normalizer import (
    KDA_MARKERS,
    MLA_MARKERS,
    normalize_inventory,
)
from omiv.schema.loader import KimiK3Schema, load_schema


def record(name: str, index: int = 0) -> dict[str, Any]:
    return {
        "name": name,
        "dtype": "BF16",
        "shape": [1],
        "shard": f"model-{index % 2:05d}.safetensors",
        "header_len": 8,
        "offsets": [index, index + 1],
    }


def measured_style_records(expert_ids: tuple[int, ...] = (0, 1)) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for layer_id in range(93):
        markers = MLA_MARKERS if layer_id in {91, 92} else KDA_MARKERS
        for marker in markers:
            records.append(
                record(f"language_model.model.layers.{layer_id}.self_attn.{marker}")
            )
        records.append(
            record(f"language_model.model.layers.{layer_id}.self_attn.g_proj.weight")
        )
        for component in (
            "self_attention_res_norm.weight",
            "self_attention_res_proj.weight",
            "mlp_res_norm.weight",
            "mlp_res_proj.weight",
        ):
            records.append(record(f"language_model.model.layers.{layer_id}.{component}"))
        if layer_id == 0:
            for projection in ("gate_proj", "up_proj", "down_proj"):
                records.append(
                    record(
                        f"language_model.model.layers.0.mlp.{projection}.weight"
                    )
                )
        else:
            for expert_id in expert_ids:
                for component in PHASE1_EXPERT_COMPONENT_SET:
                    projection, suffix = component.split(".", 1)
                    records.append(
                        record(
                            f"language_model.model.layers.{layer_id}."
                            f"block_sparse_moe.experts.{expert_id}.{projection}.{suffix}"
                        )
                    )
            for projection in ("gate_proj", "up_proj", "down_proj"):
                records.append(
                    record(
                        f"language_model.model.layers.{layer_id}."
                        f"block_sparse_moe.shared_experts.{projection}.weight"
                    )
                )
    records.extend(
        [
            record("language_model.model.output_attn_res_norm.weight"),
            record("language_model.model.output_attn_res_proj.weight"),
        ]
    )
    return records


def normalize_records(tmp_path: Path, records: list[dict[str, Any]]) -> ModelInventory:
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    return normalize_inventory(path)


@pytest.fixture
def schema() -> KimiK3Schema:
    return load_schema(Path("schemas/kimi_k3.yaml"))


@pytest.fixture
def raw_records() -> list[dict[str, Any]]:
    return measured_style_records()


@pytest.fixture
def valid_inventory(tmp_path: Path, raw_records: list[dict[str, Any]]) -> ModelInventory:
    return normalize_records(tmp_path, raw_records)
