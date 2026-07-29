from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import normalize_records, record
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.models import FindingStatus, ModelInventory
from omiv.schema.loader import KimiK3Schema, load_schema
from omiv.validators.kimi_k3 import validate_inventory

runner = CliRunner()


def _finding(inventory: ModelInventory, schema: KimiK3Schema, rule_id: str) -> Any:
    report = validate_inventory(inventory, schema)
    return next(item for item in report.findings if item.rule_id == rule_id)


def _remove(records: list[dict[str, Any]], name: str) -> None:
    records[:] = [item for item in records if item["name"] != name]


def _change_descriptor(
    records: list[dict[str, Any]],
    name: str,
    *,
    dtype: str | None = None,
    shape: list[int] | None = None,
) -> None:
    target = next(item for item in records if item["name"] == name)
    if dtype is not None:
        target["dtype"] = dtype
    if shape is not None:
        target["shape"] = shape


def test_complete_shared_expert_coverage(
    valid_inventory: ModelInventory, schema: KimiK3Schema
) -> None:
    assert _finding(valid_inventory, schema, "K3-MOE-002").status == FindingStatus.PASS


@pytest.mark.parametrize("layer_id", [1, 42])
def test_missing_shared_projection(
    tmp_path: Path,
    raw_records: list[dict[str, Any]],
    schema: KimiK3Schema,
    layer_id: int,
) -> None:
    _remove(
        raw_records,
        f"language_model.model.layers.{layer_id}.block_sparse_moe."
        "shared_experts.gate_proj.weight",
    )
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-MOE-002"
    )
    assert result.status == FindingStatus.FAIL
    assert result.evidence["missing_components_by_layer"][str(layer_id)] == [
        "gate_proj.weight"
    ]


def test_shared_expert_evidence_on_dense_layer(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    raw_records.append(
        record(
            "language_model.model.layers.0.block_sparse_moe."
            "shared_experts.gate_proj.weight"
        )
    )
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-MOE-002"
    )
    assert result.status == FindingStatus.FAIL
    assert result.evidence["non_moe_layer_evidence"]["0"] == ["gate_proj.weight"]


def test_unexpected_shared_expert_component(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    raw_records.append(
        record(
            "language_model.model.layers.1.block_sparse_moe."
            "shared_experts.extra_proj.weight"
        )
    )
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-MOE-002"
    )
    assert result.status == FindingStatus.FAIL
    assert result.evidence["unexpected_components_by_layer"]["1"] == [
        "extra_proj.weight"
    ]


def test_invalid_shared_component_vocabulary_is_configuration_error(
    tmp_path: Path, valid_inventory: ModelInventory
) -> None:
    data = yaml.safe_load(Path("schemas/kimi_k3.yaml").read_text(encoding="utf-8"))
    data["required_shared_expert_components"][0] = "gate_projection.weight"
    path = tmp_path / "schema.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid schema"):
        load_schema(path)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(valid_inventory.model_dump(mode="json")), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        [
            "validate",
            "--inventory",
            str(inventory_path),
            "--schema",
            str(path),
        ],
    )
    assert result.exit_code == 2


def test_complete_g_proj_coverage(
    valid_inventory: ModelInventory, schema: KimiK3Schema
) -> None:
    result = _finding(valid_inventory, schema, "K3-ATTN-002")
    assert result.status == FindingStatus.PASS
    assert result.evidence["descriptors"]["observation_count"] == 93


def test_missing_g_proj(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    _remove(raw_records, "language_model.model.layers.17.self_attn.g_proj.weight")
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-ATTN-002"
    )
    assert result.status == FindingStatus.FAIL
    assert result.evidence["missing_layer_ids"] == [17]


@pytest.mark.parametrize(
    ("field", "value"),
    [("shape", [2, 1]), ("dtype", "F32")],
)
def test_g_proj_descriptor_mismatch(
    tmp_path: Path,
    raw_records: list[dict[str, Any]],
    schema: KimiK3Schema,
    field: str,
    value: object,
) -> None:
    name = "language_model.model.layers.17.self_attn.g_proj.weight"
    if field == "shape":
        _change_descriptor(raw_records, name, shape=value)  # type: ignore[arg-type]
    else:
        _change_descriptor(raw_records, name, dtype=value)  # type: ignore[arg-type]
    inventory = normalize_records(tmp_path, raw_records)
    assert _finding(inventory, schema, "K3-ATTN-002").status == FindingStatus.FAIL
    tensor = _finding(inventory, schema, "K3-TENSOR-001")
    assert tensor.status == FindingStatus.FAIL
    assert len(
        tensor.evidence["inconsistent_groups"]["self_attn.g_proj"][
            "descriptor_groups"
        ]
    ) == 2


def test_kda_and_mla_layers_both_have_contextual_g_proj(
    valid_inventory: ModelInventory,
) -> None:
    by_id = {layer.id: layer for layer in valid_inventory.layers}
    assert by_id[0].attention.kind.value == "kda"
    assert by_id[91].attention.kind.value == "mla"
    assert by_id[0].attention.g_proj_observation_count == 1
    assert by_id[91].attention.g_proj_observation_count == 1


@pytest.mark.parametrize(
    "name",
    [
        (
            "language_model.model.layers.17.block_sparse_moe."
            "shared_experts.gate_proj.weight"
        ),
        (
            "language_model.model.layers.17.block_sparse_moe."
            "experts.1.w2.weight_scale"
        ),
    ],
)
def test_shared_and_routed_descriptor_mismatches_fail_tensor_rule(
    tmp_path: Path,
    raw_records: list[dict[str, Any]],
    schema: KimiK3Schema,
    name: str,
) -> None:
    _change_descriptor(raw_records, name, shape=[9])
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-TENSOR-001"
    )
    assert result.status == FindingStatus.FAIL


def test_complete_per_layer_attention_residual(
    valid_inventory: ModelInventory, schema: KimiK3Schema
) -> None:
    assert (
        _finding(valid_inventory, schema, "K3-ATTNRES-001").status
        == FindingStatus.PASS
    )


def test_missing_per_layer_attention_residual_component(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    _remove(
        raw_records,
        "language_model.model.layers.12.self_attention_res_norm.weight",
    )
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-ATTNRES-001"
    )
    assert result.status == FindingStatus.FAIL
    assert result.evidence["missing_components_by_layer"]["12"] == [
        "self_attention_res_norm.weight"
    ]


def test_unexpected_per_layer_attention_residual_component(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    raw_records.append(
        record("language_model.model.layers.12.self_attention_res_extra.weight")
    )
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-ATTNRES-001"
    )
    assert result.status == FindingStatus.FAIL
    assert result.evidence["unexpected_components_by_layer"]["12"] == [
        "self_attention_res_extra.weight"
    ]


@pytest.mark.parametrize(
    ("dtype", "shape"),
    [("F32", None), (None, [2, 1])],
)
def test_attention_residual_descriptor_mismatch(
    tmp_path: Path,
    raw_records: list[dict[str, Any]],
    schema: KimiK3Schema,
    dtype: str | None,
    shape: list[int] | None,
) -> None:
    _change_descriptor(
        raw_records,
        "language_model.model.layers.12.mlp_res_proj.weight",
        dtype=dtype,
        shape=shape,
    )
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-ATTNRES-001"
    )
    assert result.status == FindingStatus.FAIL


def test_complete_model_level_attention_residual(
    valid_inventory: ModelInventory, schema: KimiK3Schema
) -> None:
    assert (
        _finding(valid_inventory, schema, "K3-ATTNRES-002").status
        == FindingStatus.PASS
    )


@pytest.mark.parametrize(
    "component", ["output_attn_res_proj.weight", "output_attn_res_norm.weight"]
)
def test_missing_model_attention_residual_component(
    tmp_path: Path,
    raw_records: list[dict[str, Any]],
    schema: KimiK3Schema,
    component: str,
) -> None:
    _remove(raw_records, f"language_model.model.{component}")
    assert (
        _finding(
            normalize_records(tmp_path, raw_records), schema, "K3-ATTNRES-002"
        ).status
        == FindingStatus.FAIL
    )


@pytest.mark.parametrize(
    "name",
    [
        "language_model.model.layers.0.self_attn.g_proj.weight",
        "language_model.model.output_attn_res_proj.weight",
    ],
)
def test_duplicate_required_tensor_name_is_input_error(
    tmp_path: Path, raw_records: list[dict[str, Any]], name: str
) -> None:
    raw_records.append(next(item.copy() for item in raw_records if item["name"] == name))
    with pytest.raises(OmivInputError, match="duplicate exact tensor name"):
        normalize_records(tmp_path, raw_records)


def test_duplicate_exact_name_cli_exit_two(tmp_path: Path) -> None:
    item = record("language_model.model.layers.0.self_attn.g_proj.weight")
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps([item, item]), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "normalize",
            "--input",
            str(raw),
            "--output",
            str(tmp_path / "inventory.json"),
        ],
    )
    assert result.exit_code == 2
    assert "duplicate exact tensor name" in result.stderr


def test_unknown_layer_tensor_produces_warn(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    raw_records.append(record("language_model.model.layers.4.unknown_probe.weight"))
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-TENSOR-002"
    )
    assert result.status == FindingStatus.WARN
    assert result.evidence["unknown_layer_local"]["record_count"] == 1


def test_unknown_model_namespace_produces_warn(
    tmp_path: Path, raw_records: list[dict[str, Any]], schema: KimiK3Schema
) -> None:
    raw_records.append(record("mystery_tower.probe.weight"))
    result = _finding(
        normalize_records(tmp_path, raw_records), schema, "K3-TENSOR-002"
    )
    assert result.status == FindingStatus.WARN
    assert result.evidence["unknown_model_namespaces"]["groups"][0]["key"] == (
        "mystery_tower"
    )


def test_unclassified_examples_are_deterministic_and_bounded(tmp_path: Path) -> None:
    unknown = [
        record(f"language_model.model.layers.{layer}.unknown_probe.weight")
        for layer in range(6)
    ]
    first = normalize_records(tmp_path, unknown)
    first_group = first.tensor_classification.unknown_layer_local.groups[0]
    second_path = tmp_path / "second"
    second_path.mkdir()
    second = normalize_records(second_path, list(reversed(unknown)))
    second_group = second.tensor_classification.unknown_layer_local.groups[0]
    assert first_group.examples == second_group.examples
    assert len(first_group.examples) == 3
    assert first_group.record_count == 6


def test_warn_only_validation_exits_zero(
    tmp_path: Path, raw_records: list[dict[str, Any]]
) -> None:
    raw_records.append(record("mystery_tower.probe.weight"))
    inventory = normalize_records(tmp_path, raw_records)
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(inventory.model_dump(mode="json")), encoding="utf-8"
    )
    result = runner.invoke(
        app,
        [
            "validate",
            "--inventory",
            str(inventory_path),
            "--schema",
            "schemas/kimi_k3.yaml",
        ],
    )
    assert result.exit_code == 0
    assert "WARN K3-TENSOR-002" in result.stdout
