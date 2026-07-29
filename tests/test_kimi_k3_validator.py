from __future__ import annotations

from pathlib import Path

from conftest import normalize_records, record

from omiv.models import FindingStatus
from omiv.schema.loader import KimiK3Schema
from omiv.validators.kimi_k3 import validate_inventory


def finding(report: object, rule_id: str) -> object:
    return next(item for item in report.findings if item.rule_id == rule_id)  # type: ignore[attr-defined]


def test_valid_measured_style_inventory_passes(
    valid_inventory: object, schema: KimiK3Schema
) -> None:
    report = validate_inventory(valid_inventory, schema)  # type: ignore[arg-type]
    assert report.passed
    assert all(item.status == FindingStatus.PASS for item in report.findings)


def test_missing_moe_layer(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    raw_records[:] = [
        item
        for item in raw_records
        if not str(item["name"]).startswith("language_model.model.layers.50.")
    ]
    report = validate_inventory(normalize_records(tmp_path, raw_records), schema)
    result = finding(report, "K3-LAYER-002")
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert 50 in result.evidence["missing_layer_ids"]  # type: ignore[attr-defined]


def test_unexpected_layer(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    raw_records.append(record("language_model.model.layers.93.mlp.gate_proj.weight"))
    report = validate_inventory(normalize_records(tmp_path, raw_records), schema)
    result = finding(report, "K3-LAYER-002")
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert result.evidence["unexpected_layer_ids"] == [93]  # type: ignore[attr-defined]


def test_mla_layers_91_and_92_valid(
    valid_inventory: object, schema: KimiK3Schema
) -> None:
    result = finding(
        validate_inventory(valid_inventory, schema),  # type: ignore[arg-type]
        "K3-ATTN-001",
    )
    assert result.status == FindingStatus.PASS  # type: ignore[attr-defined]


def test_mla_layer_92_missing(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    raw_records[:] = [
        item
        for item in raw_records
        if not (
            str(item["name"]).startswith(
                "language_model.model.layers.92.self_attn."
            )
            and not str(item["name"]).endswith("g_proj.weight")
        )
    ]
    result = finding(
        validate_inventory(normalize_records(tmp_path, raw_records), schema),
        "K3-ATTN-001",
    )
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert result.evidence["problems"]["92"]["kind"] == "unknown"  # type: ignore[attr-defined]


def test_incomplete_routed_expert_component_set(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    target = (
        "language_model.model.layers.9.block_sparse_moe."
        "experts.1.w3.weight_scale"
    )
    raw_records[:] = [item for item in raw_records if item["name"] != target]
    result = finding(
        validate_inventory(normalize_records(tmp_path, raw_records), schema),
        "K3-MOE-001",
    )
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert result.evidence["incomplete_experts_by_layer"]["9"]["1"] == [  # type: ignore[attr-defined]
        "w3.weight_scale"
    ]


def _remove_expert(
    records: list[dict[str, object]], layer_id: int, expert_id: int
) -> None:
    prefix = (
        f"language_model.model.layers.{layer_id}.block_sparse_moe."
        f"experts.{expert_id}."
    )
    records[:] = [
        item for item in records if not str(item["name"]).startswith(prefix)
    ]


def test_missing_routed_expert(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    _remove_expert(raw_records, 7, 1)
    result = finding(
        validate_inventory(normalize_records(tmp_path, raw_records), schema),
        "K3-MOE-001",
    )
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert result.evidence["unanimous"] is False  # type: ignore[attr-defined]


def test_unexpected_routed_expert(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    for component in (
        "w1.weight_packed",
        "w1.weight_scale",
        "w2.weight_packed",
        "w2.weight_scale",
        "w3.weight_packed",
        "w3.weight_scale",
    ):
        projection, suffix = component.split(".", 1)
        raw_records.append(
            record(
                "language_model.model.layers.7.block_sparse_moe."
                f"experts.2.{projection}.{suffix}"
            )
        )
    result = finding(
        validate_inventory(normalize_records(tmp_path, raw_records), schema),
        "K3-MOE-001",
    )
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert result.evidence["unanimous"] is False  # type: ignore[attr-defined]


def test_non_contiguous_unanimous_expert_set(
    tmp_path: Path, schema: KimiK3Schema
) -> None:
    from conftest import measured_style_records

    inventory = normalize_records(tmp_path, measured_style_records((0, 2)))
    result = finding(validate_inventory(inventory, schema), "K3-MOE-001")
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert result.evidence["reference_set_contiguous"] is False  # type: ignore[attr-defined]


def test_disagreement_between_expert_sets_across_layers(
    tmp_path: Path, raw_records: list[dict[str, object]], schema: KimiK3Schema
) -> None:
    _remove_expert(raw_records, 7, 1)
    _remove_expert(raw_records, 8, 0)
    result = finding(
        validate_inventory(normalize_records(tmp_path, raw_records), schema),
        "K3-MOE-001",
    )
    assert result.status == FindingStatus.FAIL  # type: ignore[attr-defined]
    assert len(result.evidence["distinct_expert_sets"]) == 3  # type: ignore[attr-defined]
