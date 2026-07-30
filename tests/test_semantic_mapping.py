from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory
from omiv.hf.models import HFInventory
from omiv.mapping.manifest import MAX_MANIFEST_BYTES, load_mapping_manifest
from omiv.mapping.models import MappingManifest, MappingStatus
from omiv.mapping.ontology import (
    classify_qwen2_gguf_name,
    qwen2_gguf_semantic_view,
)
from omiv.mapping.reporting import (
    MAPPING_REPORT_SCHEMA_ID,
    build_mapping_report_envelope,
    load_mapping_report_envelope,
    mapping_report_integrity_matches,
    pretty_mapping_report_json,
    render_mapping_markdown,
)
from omiv.mapping.validator import validate_semantic_mapping

runner = CliRunner()


def _source() -> HFInventory:
    raw: dict[str, Any] = {
        "schema": "omiv.hf-inventory.v1",
        "canonicalization": CANONICALIZATION_ID,
        "canonical_sha256": "",
        "artifact": {
            "kind": "monolithic",
            "config_file": {"file_name": "config.json", "byte_size": 2, "sha256": "a" * 64},
            "index_file": None,
            "shards": [
                {
                    "index": 0,
                    "count": 1,
                    "file_name": "model.safetensors",
                    "byte_size": 20,
                    "header_length": 8,
                    "payload_length": 12,
                }
            ],
        },
        "provenance": {
            "available": True,
            "repository": "example/qwen",
            "revision": "revision",
            "source": "test",
            "purpose": "synthetic",
        },
        "config": {
            "architectures": ["Qwen2ForCausalLM"],
            "model_type": "qwen2",
            "torch_dtype": "float16",
            "tie_word_embeddings": True,
            "hidden_size": 3,
            "layer_count": 1,
            "attention_head_count": 1,
            "key_value_head_count": 1,
            "intermediate_size": 4,
            "vocabulary_size": 2,
        },
        "tensors": [
            {
                "source_name": "model.embed_tokens.weight",
                "canonical": {
                    "identity": "qwen2.token_embedding.weight",
                    "scope": "model",
                    "layer_id": None,
                    "module": "embedding",
                    "component": "token_embedding",
                    "parameter": "weight",
                },
                "classification": "classified",
                "dtype": "F16",
                "shape": [2, 3],
                "shape_order": "huggingface_safetensors",
                "shard_file": "model.safetensors",
                "data_offsets": [0, 12],
                "payload_byte_length": 12,
            }
        ],
        "logical_ties": [
            {
                "logical_identity": "qwen2.output_projection.weight",
                "physical_source_identity": "qwen2.token_embedding.weight",
                "materialized": False,
                "evidence": {
                    "config_tie_word_embeddings": True,
                    "physical_lm_head_present": False,
                },
            }
        ],
        "summary": {
            "physical_tensor_count": 1,
            "logical_tie_count": 1,
            "dtype_counts": {"F16": 1},
            "observed_layer_ids": [],
            "classified_tensor_count": 1,
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


def _target(
    *,
    tensors: list[dict[str, Any]] | None = None,
    lineage: bool = False,
) -> GGUFInventory:
    metadata = []
    if lineage:
        metadata = [
            {
                "key": "omiv.source.artifact_sha256",
                "value_type": "STRING",
                "value": "c" * 64,
            },
            {
                "key": "omiv.source.repository",
                "value_type": "STRING",
                "value": "example/qwen",
            },
            {
                "key": "omiv.source.revision",
                "value_type": "STRING",
                "value": "revision",
            },
            {
                "key": "omiv.converter.commit",
                "value_type": "STRING",
                "value": "converter-commit",
            },
            {
                "key": "omiv.conversion.command",
                "value_type": "STRING",
                "value": "convert command",
            },
        ]
    actual = tensors or [
        {"name": "token_embd.weight", "shape": [3, 2], "ggml_type": "F16"},
        {"name": "output.weight", "shape": [3, 2], "ggml_type": "F16"},
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
                "metadata_kv_count": len(metadata),
                "tensor_count": len(actual),
            },
            "identity": {"architecture": "qwen2", "model_name": "synthetic"},
            "metadata": metadata,
            "tensors": actual,
            "summary": {
                "tensor_type_counts": {"F16": len(actual)},
                "observed_layer_ids": [],
                "duplicate_tensor_name_count": 0,
                "tensor_shape_order": "gguf_on_disk_reader_tensor_shape",
            },
        }
    )


def _manifest() -> MappingManifest:
    return MappingManifest.model_validate(
        {
            "mapping_schema": "omiv.semantic-mapping.v1",
            "mapping_id": "synthetic-qwen",
            "model_family": "qwen2",
            "source_format": "huggingface-safetensors",
            "target_format": "gguf",
            "rules": [
                {
                    "rule_id": "embedding",
                    "source": {"canonical_identity": "qwen2.token_embedding.weight"},
                    "target": {
                        "canonical_identity": "qwen2.token_embedding.weight",
                        "tensor_name": "token_embd.weight",
                    },
                    "source_kind": "physical",
                    "cardinality": "one_to_one",
                    "shape_relation": "reverse_dimensions",
                    "payload_transform": "identity",
                    "parameter": "weight",
                },
                {
                    "rule_id": "output",
                    "source": {"canonical_identity": "qwen2.output_projection.weight"},
                    "target": {
                        "canonical_identity": "qwen2.output_projection.weight",
                        "tensor_name": "output.weight",
                    },
                    "source_kind": "logical",
                    "cardinality": "one_to_one",
                    "shape_relation": "reverse_dimensions",
                    "payload_transform": "identity",
                    "parameter": "weight",
                    "target_materialization": "required",
                    "physical_source": "qwen2.token_embedding.weight",
                    "payload_origin": "unverified",
                },
            ],
        }
    )


def _write_yaml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "mapping.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_manifest_loads_real_mapping_and_rejects_unsafe_inputs(tmp_path: Path) -> None:
    manifest = load_mapping_manifest(Path("mappings/qwen2_5_0_5b_hf_to_gguf.yaml"))
    assert manifest.mapping_id == "qwen2.5-0.5b-hf-to-gguf"
    assert len(manifest.rules) == 15

    base = Path("mappings/qwen2_5_0_5b_hf_to_gguf.yaml").read_text()
    duplicate = base.replace(
        "mapping_id: qwen2.5-0.5b-hf-to-gguf",
        "mapping_id: first\nmapping_id: second",
    )
    with pytest.raises(OmivInputError, match="duplicate mapping key"):
        load_mapping_manifest(_write_yaml(tmp_path, duplicate))

    alias = "mapping_schema: &schema omiv.semantic-mapping.v1\nmapping_id: *schema\n"
    with pytest.raises(OmivInputError, match="aliases/anchors"):
        load_mapping_manifest(_write_yaml(tmp_path, alias))

    oversized = tmp_path / "oversized.yaml"
    oversized.write_bytes(b"x" * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(OmivInputError, match="byte limit"):
        load_mapping_manifest(oversized)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mapping_schema", "omiv.semantic-mapping.v9"),
        ("payload_transform", "transpose"),
        ("source_kind", "maybe"),
        ("target_materialization", "optional"),
    ],
)
def test_manifest_strict_enum_rejection(field: str, value: str) -> None:
    raw = _manifest().model_dump(mode="json")
    if field == "mapping_schema":
        raw[field] = value
    else:
        raw["rules"][1][field] = value
    with pytest.raises(ValidationError):
        MappingManifest.model_validate(raw)


def test_manifest_rejects_duplicate_rules_unknown_fields_and_placeholders() -> None:
    raw = _manifest().model_dump(mode="json")
    raw["rules"].append(dict(raw["rules"][0]))
    with pytest.raises(ValidationError, match="duplicate rule IDs"):
        MappingManifest.model_validate(raw)
    raw = _manifest().model_dump(mode="json")
    raw["unknown"] = True
    with pytest.raises(ValidationError):
        MappingManifest.model_validate(raw)
    raw = _manifest().model_dump(mode="json")
    raw["rules"][0]["source"]["canonical_identity"] = "qwen2.layer.{other}.x"
    with pytest.raises(ValidationError, match="placeholder"):
        MappingManifest.model_validate(raw)


@pytest.mark.parametrize(
    ("name", "identity"),
    [
        ("token_embd.weight", "qwen2.token_embedding.weight"),
        ("output_norm.weight", "qwen2.output_norm.weight"),
        ("output.weight", "qwen2.output_projection.weight"),
        ("blk.12.attn_norm.weight", "qwen2.layer.12.attention.input_norm.weight"),
        ("blk.12.attn_q.weight", "qwen2.layer.12.attention.query.weight"),
        ("blk.12.attn_q.bias", "qwen2.layer.12.attention.query.bias"),
        ("blk.12.attn_k.weight", "qwen2.layer.12.attention.key.weight"),
        ("blk.12.attn_k.bias", "qwen2.layer.12.attention.key.bias"),
        ("blk.12.attn_v.weight", "qwen2.layer.12.attention.value.weight"),
        ("blk.12.attn_v.bias", "qwen2.layer.12.attention.value.bias"),
        ("blk.12.attn_output.weight", "qwen2.layer.12.attention.output.weight"),
        ("blk.12.ffn_norm.weight", "qwen2.layer.12.ffn.post_attention_norm.weight"),
        ("blk.12.ffn_gate.weight", "qwen2.layer.12.ffn.gate.weight"),
        ("blk.12.ffn_up.weight", "qwen2.layer.12.ffn.up.weight"),
        ("blk.12.ffn_down.weight", "qwen2.layer.12.ffn.down.weight"),
    ],
)
def test_qwen2_target_ontology(name: str, identity: str) -> None:
    result = classify_qwen2_gguf_name(name)
    assert result.canonical is not None
    assert result.canonical.identity == identity


def test_target_ontology_unknown_malformed_duplicate_and_deterministic() -> None:
    assert classify_qwen2_gguf_name("unknown.weight").canonical is None
    assert classify_qwen2_gguf_name("blk.bad.attn_q.weight").canonical is None
    first = qwen2_gguf_semantic_view(_target())
    reversed_target = _target(tensors=list(reversed([t.model_dump() for t in _target().tensors])))
    assert first == qwen2_gguf_semantic_view(reversed_target)
    first_tensor = _target().tensors[0]
    duplicate = _target().model_copy(
        update={
            "tensors": [
                first_tensor,
                first_tensor.model_copy(update={"name": "token_embd.weight"}),
            ]
        }
    )
    with pytest.raises(OmivInputError, match="duplicate GGUF canonical"):
        qwen2_gguf_semantic_view(duplicate)


def test_complete_resolution_shapes_logical_tie_and_provenance() -> None:
    report = validate_semantic_mapping(_source(), _target(), _manifest())
    assert len(report.resolutions) == 2
    assert [finding.status for finding in report.findings] == [
        *([MappingStatus.PASS] * 8),
        MappingStatus.WARN,
    ]
    assert report.coverage.model_dump() == {
        "physical_source_mapped": 1,
        "physical_source_total": 1,
        "logical_source_mapped": 1,
        "logical_source_total": 1,
        "target_explained": 2,
        "target_total": 2,
        "duplicate_source_count": 0,
        "duplicate_target_count": 0,
        "unmapped_source_count": 0,
        "unmapped_target_count": 0,
    }
    shape = report.findings[5]
    assert shape.evidence["payload_transpose_claimed"] is False
    tie = report.findings[7]
    assert tie.evidence["payload_equality_status"] == "not checked"
    assert tie.evidence["physical_lm_head_required"] is False


def test_target_metadata_without_validated_provenance_warns_map009() -> None:
    report = validate_semantic_mapping(_source(), _target(lineage=True), _manifest())
    assert report.findings[-1].status == MappingStatus.WARN


def test_zero_target_unclassified_shape_and_duplicate_destination_failures() -> None:
    missing = _target(
        tensors=[{"name": "token_embd.weight", "shape": [3, 2], "ggml_type": "F16"}]
    )
    report = validate_semantic_mapping(_source(), missing, _manifest())
    assert report.findings[1].status == MappingStatus.FAIL
    assert report.findings[7].status == MappingStatus.FAIL

    unknown = _target(
        tensors=[
            *[tensor.model_dump() for tensor in _target().tensors],
            {"name": "mystery.weight", "shape": [1], "ggml_type": "F32"},
        ]
    )
    assert validate_semantic_mapping(_source(), unknown, _manifest()).findings[
        1
    ].status == MappingStatus.FAIL

    bad_shape = _target(
        tensors=[
            {"name": "token_embd.weight", "shape": [2, 3], "ggml_type": "F16"},
            {"name": "output.weight", "shape": [3, 2], "ggml_type": "F16"},
        ]
    )
    assert validate_semantic_mapping(_source(), bad_shape, _manifest()).findings[
        5
    ].status == MappingStatus.FAIL

    raw = _manifest().model_dump(mode="json")
    duplicate_rule = dict(raw["rules"][0])
    duplicate_rule["rule_id"] = "embedding-again"
    raw["rules"].append(duplicate_rule)
    duplicate_report = validate_semantic_mapping(
        _source(), _target(), MappingManifest.model_validate(raw)
    )
    assert duplicate_report.findings[2].status == MappingStatus.FAIL
    assert duplicate_report.findings[3].status == MappingStatus.FAIL


def test_report_determinism_integrity_markdown_and_tamper(tmp_path: Path) -> None:
    validation = validate_semantic_mapping(_source(), _target(), _manifest())
    envelope = build_mapping_report_envelope(
        _source(), _target(), _manifest(), validation
    )
    assert pretty_mapping_report_json(envelope) == pretty_mapping_report_json(envelope)
    markdown = render_mapping_markdown(envelope)
    for section in (
        "# Open Model Integration Validator Mapping Report",
        "## Result",
        "## Source",
        "## Target",
        "## Mapping Manifest",
        "## Coverage",
        "## Findings",
        "## Integrity",
    ):
        assert section in markdown
    assert "Payload equality status: not checked" in markdown
    assert str(Path.cwd()) not in markdown
    assert "timestamp" not in pretty_mapping_report_json(envelope).lower()

    path = tmp_path / "report.json"
    path.write_text(pretty_mapping_report_json(envelope), encoding="utf-8")
    loaded = load_mapping_report_envelope(path)
    assert mapping_report_integrity_matches(loaded)
    raw = json.loads(path.read_text())
    raw["report"]["findings"][0]["message"] = "tampered"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert not mapping_report_integrity_matches(load_mapping_report_envelope(path))


def test_mapping_cli_exit_codes_and_report_verification(tmp_path: Path) -> None:
    source_path, target_path = tmp_path / "source.json", tmp_path / "target.json"
    mapping_path = tmp_path / "mapping.yaml"
    report_path, markdown_path = tmp_path / "report.json", tmp_path / "report.md"
    source_path.write_text(
        json.dumps(_source().model_dump(mode="json", by_alias=True)), encoding="utf-8"
    )
    target_path.write_text(
        json.dumps(_target().model_dump(mode="json")), encoding="utf-8"
    )
    mapping_path.write_text(
        Path("mappings/qwen2_5_0_5b_hf_to_gguf.yaml")
        .read_text()
        .replace("rules:", "rules:", 1),
        encoding="utf-8",
    )
    # Use compact manifest JSON, which is valid YAML.
    mapping_path.write_text(json.dumps(_manifest().model_dump(mode="json")), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "mapping-validate",
            "--source",
            str(source_path),
            "--target",
            str(target_path),
            "--mapping",
            str(mapping_path),
            "--json-output",
            str(report_path),
            "--markdown-output",
            str(markdown_path),
        ],
    )
    assert result.exit_code == 0
    assert "WARN MAP-009" in result.stdout
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 0
    assert MAPPING_REPORT_SCHEMA_ID in report_path.read_text()

    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("mapping_schema: [", encoding="utf-8")
    assert runner.invoke(
        app,
        [
            "mapping-validate",
            "--source",
            str(source_path),
            "--target",
            str(target_path),
            "--mapping",
            str(malformed),
        ],
    ).exit_code == 2

    bad_target = _target(
        tensors=[{"name": "token_embd.weight", "shape": [3, 2], "ggml_type": "F16"}]
    )
    target_path.write_text(bad_target.model_dump_json(), encoding="utf-8")
    assert runner.invoke(
        app,
        [
            "mapping-validate",
            "--source",
            str(source_path),
            "--target",
            str(target_path),
            "--mapping",
            str(mapping_path),
        ],
    ).exit_code == 1


@pytest.mark.integration
def test_opt_in_committed_mapping_integration() -> None:
    if os.environ.get("OMIV_RUN_MAPPING_INTEGRATION") != "1":
        pytest.skip("semantic mapping integration disabled")
    result = runner.invoke(
        app,
        [
            "mapping-validate",
            "--source",
            "fixtures/hf/qwen2_5_0_5b_instruct.inventory.json",
            "--target",
            "fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json",
            "--mapping",
            "mappings/qwen2_5_0_5b_hf_to_gguf.yaml",
        ],
    )
    assert result.exit_code == 0
    assert "PASS MAP-008" in result.stdout
    assert "WARN MAP-009" in result.stdout
