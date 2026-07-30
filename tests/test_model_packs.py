from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.cli import app
from omiv.gguf.models import GGUFInventory
from omiv.hf.models import HFInventory
from omiv.mapping.manifest import load_mapping_manifest
from omiv.mapping.models import MappingStatus
from omiv.mapping.reporting import (
    build_mapping_report_envelope,
    mapping_report_integrity_matches,
)
from omiv.mapping.validator import validate_semantic_mapping
from omiv.model_packs import (
    ModelPackCapability,
    get_model_pack,
    list_model_packs,
)
from omiv.model_packs.qwen2 import Qwen2ModelPack
from omiv.model_packs.registry import ModelPackRegistry
from omiv.schema.loader import load_schema

runner = CliRunner()


def _synthetic_source() -> HFInventory:
    pack = get_model_pack("synthetic-dense")
    tensors = []
    for layer_id in range(2):
        name = f"layers.{layer_id}.linear.weight"
        tensors.append(
            {
                "source_name": name,
                "canonical": pack.classify_hf_tensor(name).canonical.model_dump(
                    mode="json"
                ),
                "classification": "classified",
                "dtype": "F16",
                "shape": [3, 2],
                "shape_order": "huggingface_safetensors",
                "shard_file": "model.safetensors",
                "data_offsets": [layer_id * 12, (layer_id + 1) * 12],
                "payload_byte_length": 12,
            }
        )
    raw: dict[str, Any] = {
        "schema": "omiv.hf-inventory.v1",
        "canonicalization": CANONICALIZATION_ID,
        "canonical_sha256": "",
        "artifact": {
            "kind": "monolithic",
            "config_file": {
                "file_name": "config.json",
                "byte_size": 2,
                "sha256": "a" * 64,
            },
            "index_file": None,
            "shards": [
                {
                    "index": 0,
                    "count": 1,
                    "file_name": "model.safetensors",
                    "byte_size": 32,
                    "header_length": 8,
                    "payload_length": 24,
                }
            ],
        },
        "provenance": {
            "available": False,
            "repository": None,
            "revision": None,
            "source": None,
            "purpose": None,
        },
        "config": {
            "architectures": ["SyntheticDense"],
            "model_type": "synthetic-dense",
            "torch_dtype": "float16",
            "tie_word_embeddings": False,
            "hidden_size": 2,
            "layer_count": 2,
            "attention_head_count": 1,
            "key_value_head_count": 1,
            "intermediate_size": 3,
            "vocabulary_size": 1,
        },
        "tensors": tensors,
        "logical_ties": [],
        "summary": {
            "physical_tensor_count": 2,
            "logical_tie_count": 0,
            "dtype_counts": {"F16": 2},
            "observed_layer_ids": [0, 1],
            "classified_tensor_count": 2,
            "unclassified_tensor_count": 0,
            "gap_count": 0,
            "overlap_count": 0,
        },
        "diagnostics": [],
    }
    payload = dict(raw)
    payload.pop("canonical_sha256")
    raw["canonical_sha256"] = canonical_sha256(payload)
    return HFInventory.model_validate(raw)


def _synthetic_target(
    *,
    missing_last: bool = False,
    bad_shape: bool = False,
) -> GGUFInventory:
    tensors = [
        {
            "name": f"blk.{layer_id}.linear.weight",
            "shape": [3, 3] if bad_shape and layer_id == 0 else [2, 3],
            "ggml_type": "F16",
        }
        for layer_id in range(1 if missing_last else 2)
    ]
    return GGUFInventory.model_validate(
        {
            "schema_version": 1,
            "artifact": {
                "kind": "monolithic",
                "byte_size": 100,
                "sha256": "b" * 64,
                "shards": [
                    {
                        "index": 0,
                        "count": 1,
                        "file_name": "model.gguf",
                        "byte_size": 100,
                        "sha256": "b" * 64,
                    }
                ],
            },
            "header": {
                "version": 3,
                "endianness": "little",
                "alignment": 32,
                "metadata_kv_count": 0,
                "tensor_count": len(tensors),
            },
            "identity": {
                "architecture": "synthetic-dense",
                "model_name": "test-only",
            },
            "metadata": [],
            "tensors": tensors,
            "summary": {
                "tensor_type_counts": {"F16": len(tensors)},
                "observed_layer_ids": list(range(len(tensors))),
                "duplicate_tensor_name_count": 0,
                "tensor_shape_order": "gguf_on_disk_reader_tensor_shape",
            },
        }
    )


def test_registry_is_static_deterministic_and_hides_test_pack() -> None:
    production = list_model_packs()
    assert [item.pack_id for item in production] == ["kimi-k3", "qwen2"]
    assert [item.pack_id for item in list_model_packs(include_test_packs=True)] == [
        "kimi-k3",
        "qwen2",
        "synthetic-dense",
    ]


def test_registry_rejects_duplicate_pack_id_and_version() -> None:
    with pytest.raises(RuntimeError, match="duplicate pack ID and version"):
        ModelPackRegistry((Qwen2ModelPack(), Qwen2ModelPack()))


def test_pack_capabilities_are_explicit() -> None:
    qwen = get_model_pack("qwen2")
    kimi = get_model_pack("kimi-k3")
    assert qwen.capabilities == {
        ModelPackCapability.HF_ONTOLOGY,
        ModelPackCapability.GGUF_ONTOLOGY,
        ModelPackCapability.SEMANTIC_MAPPING,
    }
    assert kimi.capabilities == {
        ModelPackCapability.CHECKPOINT_SCHEMA,
        ModelPackCapability.CHECKPOINT_ONTOLOGY,
        ModelPackCapability.GGUF_ONTOLOGY,
    }
    assert (
        kimi.classify_gguf_tensor("output.weight").canonical.identity
        == "kimi-k3.model.output_projection"
    )


def test_pack_metadata_digest_is_canonical_and_declarative() -> None:
    metadata = get_model_pack("qwen2").metadata
    first = metadata.digest
    reordered = dict(reversed(list(metadata.model_dump(mode="json").items())))
    assert type(metadata).model_validate(reordered).digest == first
    changed = metadata.model_copy(
        update={
            "capabilities": [
                *metadata.capabilities,
                ModelPackCapability.MULTIMODAL_STRUCTURE,
            ]
        }
    )
    assert changed.digest != first
    assert "timestamp" not in metadata.model_dump(mode="json")


def test_synthetic_pack_uses_generic_mapping_and_reporting() -> None:
    pack = get_model_pack("synthetic-dense")
    manifest = pack.load_default_mapping_manifest()
    source = _synthetic_source()
    target = _synthetic_target()
    validation = validate_semantic_mapping(source, target, manifest, model_pack=pack)
    assert validation.passed
    assert validation.coverage.physical_source_mapped == 2
    assert validation.coverage.target_explained == 2
    envelope = build_mapping_report_envelope(source, target, manifest, validation)
    assert mapping_report_integrity_matches(envelope)
    assert envelope.report.mapping.model_pack_id == "synthetic-dense"
    assert envelope.report.mapping.model_pack_version == 1
    assert envelope.report.mapping.model_pack_metadata_sha256 == pack.metadata.digest


@pytest.mark.parametrize(
    ("target", "rule_id"),
    [
        (_synthetic_target(missing_last=True), "MAP-001"),
        (_synthetic_target(bad_shape=True), "MAP-006"),
    ],
)
def test_synthetic_pack_failures_are_generic(
    target: GGUFInventory, rule_id: str
) -> None:
    pack = get_model_pack("synthetic-dense")
    validation = validate_semantic_mapping(
        _synthetic_source(),
        target,
        pack.load_default_mapping_manifest(),
        model_pack=pack,
    )
    assert not validation.passed
    finding = next(item for item in validation.findings if item.rule_id == rule_id)
    assert finding.status == MappingStatus.FAIL


def test_qwen_committed_mapping_is_unchanged_except_pack_provenance() -> None:
    source = HFInventory.model_validate(
        json.loads(
            Path("fixtures/hf/qwen2_5_0_5b_instruct.inventory.json").read_text()
        )
    )
    target = GGUFInventory.model_validate(
        json.loads(
            Path("fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json").read_text()
        )
    )
    manifest = load_mapping_manifest(
        Path("mappings/qwen2_5_0_5b_hf_to_gguf.yaml")
    )
    validation = validate_semantic_mapping(source, target, manifest)
    assert (
        validation.coverage.physical_source_mapped,
        validation.coverage.physical_source_total,
    ) == (290, 290)
    assert (
        validation.coverage.logical_source_mapped,
        validation.coverage.logical_source_total,
    ) == (1, 1)
    assert (
        validation.coverage.target_explained,
        validation.coverage.target_total,
    ) == (291, 291)
    assert [item.status for item in validation.findings] == [
        *([MappingStatus.PASS] * 8),
        MappingStatus.WARN,
    ]


def test_kimi_pack_preserves_measured_attention_partition() -> None:
    inventory = json.loads(Path("fixtures/kimi_k3_inventory.json").read_text())
    from omiv.models import AttentionKind, ModelInventory

    canonical = ModelInventory.model_validate(inventory)
    counts = {
        kind: sum(layer.attention.kind == kind for layer in canonical.layers)
        for kind in (AttentionKind.KDA, AttentionKind.MLA)
    }
    assert counts == {AttentionKind.KDA: 69, AttentionKind.MLA: 24}
    report = get_model_pack("kimi-k3").validate_checkpoint(
        canonical, load_schema(Path("schemas/kimi_k3.yaml"))
    )
    assert report.passed
    warning = next(item for item in report.findings if item.rule_id == "K3-TENSOR-002")
    assert warning.status.value == "warn"


def test_cli_pack_listing_show_and_unsupported_exit_two() -> None:
    listed = runner.invoke(app, ["model-packs", "list"])
    assert listed.exit_code == 0
    assert "qwen2" in listed.stdout
    assert "synthetic-dense" not in listed.stdout
    included = runner.invoke(
        app, ["model-packs", "list", "--include-test-packs"]
    )
    assert included.exit_code == 0
    assert "synthetic-dense" in included.stdout
    shown = runner.invoke(app, ["model-packs", "show", "--pack", "qwen2"])
    assert shown.exit_code == 0
    assert '"metadata_sha256"' in shown.stdout
    unsupported = runner.invoke(
        app, ["model-packs", "show", "--pack", "not-registered"]
    )
    assert unsupported.exit_code == 2
    mapping_unsupported = runner.invoke(
        app,
        [
            "mapping-validate",
            "--source",
            "fixtures/hf/qwen2_5_0_5b_instruct.inventory.json",
            "--target",
            "fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json",
            "--mapping",
            "mappings/qwen2_5_0_5b_hf_to_gguf.yaml",
            "--model-pack",
            "not-registered",
        ],
    )
    assert mapping_unsupported.exit_code == 2
    assert "unsupported model pack" in mapping_unsupported.stderr


def test_core_format_modules_have_no_model_specific_implementation() -> None:
    resolver = Path("src/omiv/mapping/resolver.py").read_text()
    validator = Path("src/omiv/mapping/validator.py").read_text()
    hf_reader = Path("src/omiv/hf/reader.py").read_text()
    gguf_reader = Path("src/omiv/gguf/reader.py").read_text()
    for content in (resolver, validator, hf_reader, gguf_reader):
        assert "model_family ==" not in content
        assert "kimi_k3" not in content
    assert "qwen2." not in resolver
    assert "qwen2." not in validator
    assert "qwen2." not in hf_reader
    assert "qwen2." not in gguf_reader
