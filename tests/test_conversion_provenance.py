from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory
from omiv.hf.models import HFInventory
from omiv.mapping.models import MappingManifest, MappingStatus
from omiv.mapping.validator import _provenance
from omiv.model_packs.registry import get_model_pack
from omiv.provenance.adapters import inventory_evidence_from_value
from omiv.provenance.loading import load_provenance_envelope
from omiv.provenance.models import (
    ConversionProvenance,
    Invocation,
    ProvenanceStatus,
)
from omiv.provenance.reporting import (
    PROVENANCE_REPORT_SCHEMA_ID,
    build_provenance_envelope,
    build_provenance_report_envelope,
    load_provenance_report_envelope,
    pretty_provenance_json,
    pretty_provenance_report_json,
    provenance_integrity_matches,
    provenance_report_integrity_matches,
    render_provenance_markdown,
)
from omiv.provenance.validator import (
    ProvenanceValidationContext,
    validate_provenance,
)

runner = CliRunner()


def _source() -> HFInventory:
    raw = {
        "schema": "omiv.hf-inventory.v1",
        "canonicalization": "omiv-json-v1",
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
            "available": True,
            "repository": "example/qwen",
            "revision": "c" * 40,
            "source": "local",
            "purpose": "test",
        },
        "config": {
            "architectures": ["Qwen2ForCausalLM"],
            "model_type": "qwen2",
            "torch_dtype": "float16",
            "tie_word_embeddings": True,
            "hidden_size": 2,
            "layer_count": 1,
            "attention_head_count": 1,
            "key_value_head_count": 1,
            "intermediate_size": 3,
            "vocabulary_size": 3,
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
                "shape": [3, 2],
                "shape_order": "huggingface_safetensors",
                "shard_file": "model.safetensors",
                "data_offsets": [0, 12],
                "payload_byte_length": 12,
            }
        ],
        "logical_ties": [],
        "summary": {
            "physical_tensor_count": 1,
            "logical_tie_count": 0,
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


def _target() -> GGUFInventory:
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
                "metadata_kv_count": 2,
                "tensor_count": 1,
            },
            "identity": {"architecture": "qwen2", "model_name": "synthetic"},
            "metadata": [
                {
                    "key": "general.architecture",
                    "value_type": "STRING",
                    "value": "qwen2",
                },
                {
                    "key": "general.name",
                    "value_type": "STRING",
                    "value": "synthetic",
                },
            ],
            "tensors": [
                {"name": "token_embd.weight", "shape": [2, 3], "ggml_type": "F16"}
            ],
            "summary": {
                "tensor_type_counts": {"F16": 1},
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
            "mapping_id": "synthetic-qwen-provenance",
            "model_family": "qwen2",
            "model_pack": {
                "pack_id": "qwen2",
                "pack_schema_version": 1,
                "minimum_pack_version": 1,
            },
            "source_format": "huggingface-safetensors",
            "target_format": "gguf",
            "rules": [
                {
                    "rule_id": "embedding",
                    "source": {
                        "canonical_identity": "qwen2.token_embedding.weight"
                    },
                    "target": {
                        "canonical_identity": "qwen2.token_embedding.weight",
                        "tensor_name": "token_embd.weight",
                    },
                    "source_kind": "physical",
                    "cardinality": "one_to_one",
                    "shape_relation": "reverse_dimensions",
                    "payload_transform": "identity",
                    "parameter": "weight",
                }
            ],
        }
    )


def _provenance_payload() -> dict[str, object]:
    source = _source()
    target = _target()
    manifest = _manifest()
    pack = get_model_pack("qwen2")
    return {
        "provenance_schema": "omiv.conversion-provenance.v1",
        "provenance_id": "synthetic-qwen-conversion",
        "operation": "convert",
        "source": {
            "format": "huggingface-safetensors",
            "inventory_schema": "omiv.hf-inventory.v1",
            "inventory_sha256": source.canonical_sha256,
            "model_family": "qwen2",
            "model_pack": {
                "pack_id": "qwen2",
                "pack_version": pack.pack_version,
                "metadata_sha256": pack.metadata.digest,
            },
            "repository": "example/qwen",
            "revision": "c" * 40,
            "artifacts": [
                {
                    "role": "config",
                    "artifact_id": "config.json",
                    "byte_size": 2,
                    "sha256": "a" * 64,
                    "required": True,
                    "digest_evidence": "full_artifact",
                }
            ],
        },
        "interpretation": {
            "model_pack": {
                "pack_id": "qwen2",
                "pack_schema_version": 1,
                "pack_version": pack.pack_version,
                "metadata_sha256": pack.metadata.digest,
            },
            "mapping": {
                "mapping_schema": manifest.mapping_schema,
                "mapping_id": manifest.mapping_id,
                "canonical_sha256": canonical_sha256(
                    manifest.model_dump(mode="json")
                ),
            },
            "policies": [],
        },
        "process": {
            "operation": "convert",
            "tool": {
                "name": "synthetic-converter",
                "repository": "example/converter",
                "revision": "d" * 40,
                "revision_kind": "git_commit",
                "entrypoint": "convert.py",
            },
            "invocation": {
                "executable": "python",
                "arguments": [
                    "{source_model_dir}",
                    "--outfile",
                    "{target_output}",
                ],
                "working_tree_policy": "require_clean",
                "redacted_arguments": [],
            },
            "result": {"exit_code": 0, "success": True},
            "declared_outputs": ["model"],
            "tool_source": {
                "clean_worktree": True,
                "repository_head": "d" * 40,
                "source_tree_sha256": None,
            },
        },
        "target": {
            "format": "gguf",
            "inventory_schema": "omiv.gguf-inventory.v1",
            "inventory_sha256": canonical_sha256(
                target.model_dump(mode="json")
            ),
            "architecture": "qwen2",
            "artifact_type": None,
            "artifacts": [
                {
                    "role": "model",
                    "artifact_id": "model.gguf",
                    "sha256": "b" * 64,
                    "byte_size": 100,
                    "output_success": True,
                }
            ],
        },
        "capture": {
            "tool_name": "open-model-integration-validator",
            "omiv_version": "0.1.0",
            "capture_schema_version": 1,
            "redaction_count": 0,
            "offline": True,
            "payload_access": "descriptor_only",
            "artifact_hashing": "requested_full_sha256",
        },
    }


def _validation(
    provenance: ConversionProvenance | None = None,
    *,
    observed_tool_head: str | None = "d" * 40,
) -> tuple[ConversionProvenance, object]:
    value = provenance or ConversionProvenance.model_validate(_provenance_payload())
    source = _source()
    target = _target()
    report = validate_provenance(
        value,
        ProvenanceValidationContext(
            source_inventory=inventory_evidence_from_value(
                source.model_dump(mode="json", by_alias=True)
            ),
            target_inventory=inventory_evidence_from_value(
                target.model_dump(mode="json")
            ),
            mapping=_manifest(),
            model_pack=get_model_pack("qwen2"),
            observed_tool_head=observed_tool_head,
        ),
    )
    return value, report


def test_complete_provenance_has_ordered_findings_and_exact_lineage() -> None:
    _, report = _validation()
    assert [item.rule_id for item in report.findings] == [
        f"PROV-{number:03d}" for number in range(1, 13)
    ]
    assert report.passed
    assert report.exact_lineage_status == ProvenanceStatus.PASS
    assert report.findings[1].status == ProvenanceStatus.PASS


@pytest.mark.parametrize(
    "operation",
    ["convert", "quantize", "export", "compile", "pack", "merge", "shard"],
)
def test_schema_supports_all_phase4d_operations(operation: str) -> None:
    raw = _provenance_payload()
    raw["operation"] = operation
    raw["process"]["operation"] = operation  # type: ignore[index]
    assert ConversionProvenance.model_validate(raw).operation.value == operation


def test_incomplete_and_contradictory_lineage() -> None:
    incomplete = _provenance_payload()
    incomplete["source"]["repository"] = None  # type: ignore[index]
    incomplete["source"]["revision"] = None  # type: ignore[index]
    incomplete["source"]["artifacts"][0]["digest_evidence"] = "descriptor_only"  # type: ignore[index]
    _, incomplete_report = _validation(
        ConversionProvenance.model_validate(incomplete)
    )
    assert incomplete_report.findings[0].status == ProvenanceStatus.WARN
    assert incomplete_report.exact_lineage_status == ProvenanceStatus.WARN

    contradictory = _provenance_payload()
    contradictory["source"]["inventory_sha256"] = "f" * 64  # type: ignore[index]
    _, contradictory_report = _validation(
        ConversionProvenance.model_validate(contradictory)
    )
    assert contradictory_report.findings[2].status == ProvenanceStatus.FAIL
    assert contradictory_report.exact_lineage_status == ProvenanceStatus.FAIL


def test_source_and_target_artifact_file_mismatch(tmp_path: Path) -> None:
    provenance = ConversionProvenance.model_validate(_provenance_payload())
    wrong = tmp_path / "wrong.bin"
    wrong.write_bytes(b"wrong")
    source = _source()
    target = _target()
    report = validate_provenance(
        provenance,
        ProvenanceValidationContext(
            source_inventory=inventory_evidence_from_value(
                source.model_dump(mode="json", by_alias=True)
            ),
            target_inventory=inventory_evidence_from_value(
                target.model_dump(mode="json")
            ),
            mapping=_manifest(),
            model_pack=get_model_pack("qwen2"),
            source_artifacts={"config": wrong},
            target_artifacts={"model": wrong},
        ),
    )
    assert report.findings[1].status == ProvenanceStatus.FAIL
    assert report.findings[8].status == ProvenanceStatus.FAIL


def test_process_and_chain_contradictions_are_findings() -> None:
    raw = _provenance_payload()
    raw["process"]["result"] = {"exit_code": 7, "success": True}  # type: ignore[index]
    _, process_report = _validation(ConversionProvenance.model_validate(raw))
    assert process_report.findings[7].status == ProvenanceStatus.FAIL
    assert process_report.exact_lineage_status == ProvenanceStatus.FAIL

    raw = _provenance_payload()
    raw["process"]["operation"] = "quantize"  # type: ignore[index]
    _, chain_report = _validation(ConversionProvenance.model_validate(raw))
    assert chain_report.findings[10].status == ProvenanceStatus.FAIL


def test_mutable_tool_revision_warns_and_observed_head_conflict_fails() -> None:
    raw = _provenance_payload()
    raw["process"]["tool"]["revision"] = "main"  # type: ignore[index]
    mutable = ConversionProvenance.model_validate(raw)
    _, mutable_report = _validation(mutable, observed_tool_head=None)
    assert mutable_report.findings[5].status == ProvenanceStatus.WARN

    _, conflict_report = _validation(mutable)
    assert conflict_report.findings[5].status == ProvenanceStatus.FAIL


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provenance_schema", "unsupported"),
        ("operation", "copy"),
        ("provenance_id", ""),
        ("timestamp", "2026-01-01T00:00:00Z"),
    ],
)
def test_schema_rejects_unsupported_or_unknown_fields(
    field: str, value: str
) -> None:
    raw = _provenance_payload()
    raw[field] = value
    with pytest.raises(ValidationError):
        ConversionProvenance.model_validate(raw)


def test_absolute_paths_and_unredacted_secrets_are_rejected() -> None:
    raw = _provenance_payload()
    raw["process"]["tool"]["entrypoint"] = "/tmp/convert.py"  # type: ignore[index]
    with pytest.raises(ValidationError, match="absolute|relative"):
        ConversionProvenance.model_validate(raw)

    with pytest.raises(ValidationError, match="not redacted"):
        Invocation(
            executable="tool",
            arguments=["--token", "secret-value", "--output", "model.bin"],
            working_tree_policy="not_applicable",
            redacted_arguments=["--token"],
        )
    invocation = Invocation(
        executable="tool",
        arguments=["--token", "[REDACTED]", "--output", "model.bin"],
        working_tree_policy="not_applicable",
        redacted_arguments=["--token"],
    )
    assert "secret-value" not in invocation.model_dump_json()


def test_duplicate_json_and_yaml_keys_are_rejected(tmp_path: Path) -> None:
    duplicate_json = tmp_path / "duplicate.json"
    duplicate_json.write_text('{"provenance":{},"provenance":{}}')
    with pytest.raises(OmivInputError, match="duplicate"):
        load_provenance_envelope(duplicate_json)
    duplicate_yaml = tmp_path / "duplicate.yaml"
    duplicate_yaml.write_text("provenance: {}\nprovenance: {}\n")
    with pytest.raises(OmivInputError, match="duplicate"):
        load_provenance_envelope(duplicate_yaml)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(OmivInputError, match="byte limit"):
        load_provenance_envelope(oversized)


def test_provenance_and_report_are_deterministic_and_tamper_evident(
    tmp_path: Path,
) -> None:
    provenance, validation = _validation()
    first = build_provenance_envelope(provenance)
    second = build_provenance_envelope(provenance)
    assert pretty_provenance_json(first) == pretty_provenance_json(second)
    assert provenance_integrity_matches(first)

    report = build_provenance_report_envelope(provenance, validation)
    assert report.report.report_schema == PROVENANCE_REPORT_SCHEMA_ID
    assert provenance_report_integrity_matches(report)
    markdown = render_provenance_markdown(report)
    assert "## Lineage Findings" in markdown
    assert "## Limitations" in markdown
    assert "/home/" not in markdown
    assert "timestamp" not in pretty_provenance_report_json(report).lower()

    path = tmp_path / "report.json"
    path.write_text(pretty_provenance_report_json(report))
    loaded = load_provenance_report_envelope(path)
    assert provenance_report_integrity_matches(loaded)
    raw = json.loads(path.read_text())
    raw["report"]["findings"][0]["message"] = "tampered"
    path.write_text(json.dumps(raw))
    assert not provenance_report_integrity_matches(
        load_provenance_report_envelope(path)
    )


def test_provenance_cli_and_report_verify(tmp_path: Path) -> None:
    provenance, _ = _validation()
    provenance_path = tmp_path / "provenance.json"
    source_path = tmp_path / "source.json"
    target_path = tmp_path / "target.json"
    mapping_path = tmp_path / "mapping.yaml"
    report_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    provenance_path.write_text(
        pretty_provenance_json(build_provenance_envelope(provenance))
    )
    source_path.write_text(
        json.dumps(_source().model_dump(mode="json", by_alias=True))
    )
    target_path.write_text(json.dumps(_target().model_dump(mode="json")))
    mapping_path.write_text(
        json.dumps(_manifest().model_dump(mode="json"))
    )
    result = runner.invoke(
        app,
        [
            "provenance-validate",
            "--provenance",
            str(provenance_path),
            "--source-inventory",
            str(source_path),
            "--target-inventory",
            str(target_path),
            "--mapping",
            str(mapping_path),
            "--model-pack",
            "qwen2",
            "--json-output",
            str(report_path),
            "--markdown-output",
            str(markdown_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "PASS PROV-012" in result.stdout
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 0
    mapping_result = runner.invoke(
        app,
        [
            "mapping-validate",
            "--source",
            str(source_path),
            "--target",
            str(target_path),
            "--mapping",
            str(mapping_path),
            "--model-pack",
            "qwen2",
            "--provenance-report",
            str(report_path),
        ],
    )
    assert "PASS MAP-009" in mapping_result.stdout


def test_map009_consumes_validated_provenance_summary() -> None:
    source, target = _source(), _target()
    assert _provenance(source, target, None).status == MappingStatus.WARN
    provenance, complete = _validation()
    assert _provenance(source, target, complete).status == MappingStatus.PASS

    raw = provenance.model_dump(mode="json")
    raw["source"]["inventory_sha256"] = "f" * 64
    _, contradictory = _validation(ConversionProvenance.model_validate(raw))
    assert _provenance(source, target, contradictory).status == MappingStatus.FAIL

    raw = provenance.model_dump(mode="json")
    raw["source"]["repository"] = None
    raw["source"]["revision"] = None
    raw["source"]["artifacts"][0]["digest_evidence"] = "descriptor_only"
    _, incomplete = _validation(ConversionProvenance.model_validate(raw))
    assert _provenance(source, target, incomplete).status == MappingStatus.WARN
