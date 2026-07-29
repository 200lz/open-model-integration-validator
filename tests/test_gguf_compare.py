from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from typer.testing import CliRunner

from omiv.cli import app
from omiv.gguf.compare import compare_gguf_inventories
from omiv.gguf.models import (
    GGUFArtifactSummary,
    GGUFComparisonPolicy,
    GGUFComparisonStatus,
    GGUFHeaderSummary,
    GGUFIdentity,
    GGUFInventory,
    GGUFMetadataEntry,
    GGUFShardSummary,
    GGUFSummary,
    GGUFTensorDescriptor,
    MetadataDifferenceRule,
    TypeTransitionRule,
)

runner = CliRunner()


def _inventory(
    *,
    architecture: str = "qwen2",
    tensors: list[tuple[str, list[int], str]] | None = None,
    metadata: dict[str, int | str] | None = None,
) -> GGUFInventory:
    tensor_values = tensors or [
        ("blk.0.attn.weight", [4, 2], "F16"),
        ("blk.0.ffn_down.weight", [8, 4], "F16"),
        ("output_norm.weight", [4], "F32"),
    ]
    metadata_values = {
        "general.architecture": architecture,
        "general.file_type": 1,
        "qwen2.context_length": 8192,
        **(metadata or {}),
    }
    entries = [
        GGUFMetadataEntry(
            key=key,
            value_type="STRING" if isinstance(value, str) else "UINT32",
            value=value,
        )
        for key, value in sorted(metadata_values.items())
    ]
    descriptors = [
        GGUFTensorDescriptor(name=name, shape=shape, ggml_type=tensor_type)
        for name, shape, tensor_type in sorted(tensor_values)
    ]
    counts: dict[str, int] = {}
    for descriptor in descriptors:
        counts[descriptor.ggml_type] = counts.get(descriptor.ggml_type, 0) + 1
    return GGUFInventory(
        schema_version=1,
        artifact=GGUFArtifactSummary(
            kind="monolithic",
            byte_size=1,
            sha256="0" * 64,
            shards=[
                GGUFShardSummary(
                    index=0,
                    count=1,
                    file_name="model.gguf",
                    byte_size=1,
                    sha256="0" * 64,
                )
            ],
        ),
        header=GGUFHeaderSummary(
            version=3,
            endianness="little",
            alignment=32,
            metadata_kv_count=len(entries),
            tensor_count=len(descriptors),
        ),
        identity=GGUFIdentity(architecture=architecture, model_name="model"),
        metadata=entries,
        tensors=descriptors,
        summary=GGUFSummary(
            tensor_type_counts=dict(sorted(counts.items())),
            observed_layer_ids=[0],
            duplicate_tensor_name_count=0,
            tensor_shape_order="gguf_on_disk_reader_tensor_shape",
        ),
    )


def _policy(
    transitions: list[TypeTransitionRule] | None = None,
    metadata_rules: list[MetadataDifferenceRule] | None = None,
) -> GGUFComparisonPolicy:
    return GGUFComparisonPolicy(
        schema_version=1,
        name="test",
        require_same_architecture=True,
        require_same_tensor_names=True,
        require_same_tensor_shapes=True,
        type_transition_rules=transitions
        or [
            TypeTransitionRule(source_type="F16", target_type="Q8_0"),
            TypeTransitionRule(source_type="F32", target_type="F32"),
        ],
        metadata_rules=metadata_rules
        or [
            MetadataDifferenceRule(key="general.file_type", action="allow"),
            MetadataDifferenceRule(key="qwen2.context_length", action="warn"),
        ],
        unknown_metadata_drift="warn",
    )


def _finding(report: Any, rule_id: str) -> Any:
    return next(item for item in report.findings if item.rule_id == rule_id)


def test_matching_architecture() -> None:
    report = compare_gguf_inventories(_inventory(), _inventory(), _policy())
    assert _finding(report, "GGUF-DIFF-001").status == GGUFComparisonStatus.PASS


def test_architecture_mismatch() -> None:
    report = compare_gguf_inventories(
        _inventory(), _inventory(architecture="other"), _policy()
    )
    assert _finding(report, "GGUF-DIFF-001").status == GGUFComparisonStatus.FAIL


def test_missing_and_unexpected_tensor() -> None:
    source = _inventory()
    target = _inventory(
        tensors=[
            ("blk.0.attn.weight", [4, 2], "Q8_0"),
            ("blk.0.ffn_down.weight", [8, 4], "Q8_0"),
            ("extra.weight", [1], "F32"),
        ]
    )
    finding = _finding(
        compare_gguf_inventories(source, target, _policy()), "GGUF-DIFF-002"
    )
    assert finding.status == GGUFComparisonStatus.FAIL
    assert finding.evidence["missing_examples"] == ["output_norm.weight"]
    assert finding.evidence["unexpected_examples"] == ["extra.weight"]


def test_shape_mismatch() -> None:
    target = _inventory(
        tensors=[
            ("blk.0.attn.weight", [9, 2], "Q8_0"),
            ("blk.0.ffn_down.weight", [8, 4], "Q8_0"),
            ("output_norm.weight", [4], "F32"),
        ]
    )
    finding = _finding(
        compare_gguf_inventories(_inventory(), target, _policy()),
        "GGUF-DIFF-003",
    )
    assert finding.status == GGUFComparisonStatus.FAIL
    assert finding.evidence["shape_change_group_count"] == 1


def test_valid_f16_to_q8_transition() -> None:
    target = _inventory(
        tensors=[
            ("blk.0.attn.weight", [4, 2], "Q8_0"),
            ("blk.0.ffn_down.weight", [8, 4], "Q8_0"),
            ("output_norm.weight", [4], "F32"),
        ]
    )
    finding = _finding(
        compare_gguf_inventories(_inventory(), target, _policy()),
        "GGUF-DIFF-004",
    )
    assert finding.status == GGUFComparisonStatus.PASS


def test_invalid_type_transition() -> None:
    target = _inventory(
        tensors=[
            ("blk.0.attn.weight", [4, 2], "Q4_K"),
            ("blk.0.ffn_down.weight", [8, 4], "Q8_0"),
            ("output_norm.weight", [4], "F32"),
        ]
    )
    finding = _finding(
        compare_gguf_inventories(_inventory(), target, _policy()),
        "GGUF-DIFF-004",
    )
    assert finding.status == GGUFComparisonStatus.FAIL


def test_selector_specific_transition_accepted_and_rejected() -> None:
    policy = _policy(
        [
            TypeTransitionRule(
                source_type="F16",
                target_type="Q4_K",
                selector="*.ffn_down.weight",
            ),
            TypeTransitionRule(source_type="F16", target_type="Q5_0"),
            TypeTransitionRule(source_type="F32", target_type="F32"),
        ]
    )
    accepted = _inventory(
        tensors=[
            ("blk.0.attn.weight", [4, 2], "Q5_0"),
            ("blk.0.ffn_down.weight", [8, 4], "Q4_K"),
            ("output_norm.weight", [4], "F32"),
        ]
    )
    rejected = _inventory(
        tensors=[
            ("blk.0.attn.weight", [4, 2], "Q4_K"),
            ("blk.0.ffn_down.weight", [8, 4], "Q5_0"),
            ("output_norm.weight", [4], "F32"),
        ]
    )
    assert (
        _finding(
            compare_gguf_inventories(_inventory(), accepted, policy),
            "GGUF-DIFF-004",
        ).status
        == GGUFComparisonStatus.PASS
    )
    assert (
        _finding(
            compare_gguf_inventories(_inventory(), rejected, policy),
            "GGUF-DIFF-004",
        ).status
        == GGUFComparisonStatus.FAIL
    )


def test_allowed_and_unknown_metadata_drift() -> None:
    target = _inventory(
        metadata={
            "general.file_type": 7,
            "new.metadata": "changed",
        }
    )
    finding = _finding(
        compare_gguf_inventories(_inventory(), target, _policy()),
        "GGUF-DIFF-005",
    )
    assert finding.status == GGUFComparisonStatus.WARN
    assert [item["key"] for item in finding.evidence["allowed_differences"]] == [
        "general.file_type"
    ]
    assert [item["key"] for item in finding.evidence["warning_differences"]] == [
        "new.metadata"
    ]


def test_required_metadata_mismatch_fails() -> None:
    policy = _policy(
        metadata_rules=[
            MetadataDifferenceRule(
                key="qwen2.context_length", action="require_equal"
            )
        ]
    )
    target = _inventory(metadata={"qwen2.context_length": 32768})
    finding = _finding(
        compare_gguf_inventories(_inventory(), target, policy), "GGUF-DIFF-005"
    )
    assert finding.status == GGUFComparisonStatus.FAIL


def _write_cli_inputs(
    tmp_path: Path,
    source: GGUFInventory,
    target: GGUFInventory,
    policy: GGUFComparisonPolicy,
) -> tuple[Path, Path, Path]:
    source_path, target_path, policy_path = (
        tmp_path / "source.json",
        tmp_path / "target.json",
        tmp_path / "policy.yaml",
    )
    source_path.write_text(source.model_dump_json(), encoding="utf-8")
    target_path.write_text(target.model_dump_json(), encoding="utf-8")
    policy_path.write_text(
        yaml.safe_dump(policy.model_dump(mode="json")), encoding="utf-8"
    )
    return source_path, target_path, policy_path


def test_warn_only_cli_exit_zero_with_valid_transitions(tmp_path: Path) -> None:
    target = _inventory(
        tensors=[
            ("blk.0.attn.weight", [4, 2], "Q8_0"),
            ("blk.0.ffn_down.weight", [8, 4], "Q8_0"),
            ("output_norm.weight", [4], "F32"),
        ],
        metadata={"qwen2.context_length": 32768},
    )
    paths = _write_cli_inputs(tmp_path, _inventory(), target, _policy())
    result = runner.invoke(
        app,
        [
            "gguf-diff",
            "--source",
            str(paths[0]),
            "--target",
            str(paths[1]),
            "--policy",
            str(paths[2]),
        ],
    )
    assert result.exit_code == 0
    assert "WARN GGUF-DIFF-005" in result.stdout


def test_fail_cli_exit_one(tmp_path: Path) -> None:
    paths = _write_cli_inputs(
        tmp_path, _inventory(), _inventory(architecture="bad"), _policy()
    )
    result = runner.invoke(
        app,
        [
            "gguf-diff",
            "--source",
            str(paths[0]),
            "--target",
            str(paths[1]),
            "--policy",
            str(paths[2]),
        ],
    )
    assert result.exit_code == 1


def test_invalid_policy_cli_exit_two(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    target = tmp_path / "target.json"
    policy = tmp_path / "bad.yaml"
    source.write_text(json.dumps(_inventory().model_dump(mode="json")), encoding="utf-8")
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    policy.write_text("schema_version: 1\nname: incomplete\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "gguf-diff",
            "--source",
            str(source),
            "--target",
            str(target),
            "--policy",
            str(policy),
        ],
    )
    assert result.exit_code == 2
