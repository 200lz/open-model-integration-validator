from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from omiv.canonical import load_json_value
from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory
from omiv.hf.models import HFInventory
from omiv.mapping.manifest import load_mapping_manifest
from omiv.mapping.models import MappingManifest
from omiv.mapping.reporting import (
    build_mapping_report_envelope,
    mapping_report_integrity_matches,
    render_mapping_markdown,
)
from omiv.mapping.validator import validate_semantic_mapping
from omiv.provenance.models import ProvenanceValidationReport
from omiv.provenance.reporting import load_provenance_report_envelope

SOURCE = Path("fixtures/hf/qwen2_5_0_5b_instruct.inventory.json")
TARGET_290 = Path("fixtures/gguf/qwen2_5_0_5b_f16.generated.inventory.json")
TARGET_291 = Path("fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json")
MANIFEST = Path("mappings/qwen2_5_0_5b_hf_to_gguf_realizations.yaml")
PROVENANCE_REPORT = Path(
    "reports/provenance/qwen2_5_0_5b_hf_to_gguf_f16_realizations.report.json"
)


def _json(path: Path) -> Any:
    return load_json_value(path.read_text(encoding="utf-8"))


def _source() -> HFInventory:
    return HFInventory.model_validate(_json(SOURCE))


def _target(path: Path) -> GGUFInventory:
    return GGUFInventory.model_validate(_json(path))


def _manifest_raw() -> dict[str, Any]:
    return load_mapping_manifest(MANIFEST).model_dump(mode="json")


def _logical_rule(raw: dict[str, Any]) -> dict[str, Any]:
    return next(item for item in raw["rules"] if item["rule_id"] == "logical-output-projection")


def _provenance() -> tuple[Any, ProvenanceValidationReport]:
    envelope = load_provenance_report_envelope(PROVENANCE_REPORT)
    report = envelope.report
    return report.provenance, ProvenanceValidationReport(
        findings=report.findings,
        summary=report.summary,
    )


@pytest.mark.parametrize(
    "alternative",
    [
        {
            "realization_id": "materialized",
            "kind": "materialized",
            "tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
        },
        {
            "realization_id": "alias",
            "kind": "format_alias",
            "alias_tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
            "backing_tensor": {
                "canonical_identity": "qwen2.token_embedding.weight",
                "tensor_name": "token_embd.weight",
            },
            "format_contract": {
                "target_format": "gguf",
                "contract_id": "test-alias-v1",
                "metadata_key": "test.alias",
                "metadata_value": True,
            },
        },
        {
            "realization_id": "fallback",
            "kind": "backend_fallback",
            "omitted_tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
            "fallback_tensor": {
                "canonical_identity": "qwen2.token_embedding.weight",
                "tensor_name": "token_embd.weight",
            },
            "backend_policy": {
                "backend": "llama.cpp",
                "repository": "ggml-org/llama.cpp",
                "revision": "e3546c7948e3af463d0b401e6421d5a4c2faf565",
                "architecture": "qwen2",
                "policy_symbol": "llama_model_qwen2::load_arch_tensors",
                "evidence_id": "llama-qwen2-output-fallback-v1",
            },
        },
        {
            "realization_id": "synthesized",
            "kind": "synthesized",
            "tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
            "converter_policy": {
                "converter": "llama.cpp",
                "repository": "ggml-org/llama.cpp",
                "revision": "e3546c7948e3af463d0b401e6421d5a4c2faf565",
                "synthesis_rule_id": "test-synthesis-v1",
                "operation": "copy",
            },
        },
    ],
)
def test_schema_accepts_each_phase_4e_realization_kind(
    alternative: dict[str, Any],
) -> None:
    raw = _manifest_raw()
    _logical_rule(raw)["target"]["realization"]["alternatives"] = [alternative]
    assert MappingManifest.model_validate(raw)


def test_schema_rejects_duplicate_ids_zero_alternatives_and_unknown_values() -> None:
    raw = _manifest_raw()
    alternatives = _logical_rule(raw)["target"]["realization"]["alternatives"]
    alternatives.append(dict(alternatives[0]))
    with pytest.raises(ValidationError, match="duplicate realization IDs"):
        MappingManifest.model_validate(raw)

    raw = _manifest_raw()
    _logical_rule(raw)["target"]["realization"]["alternatives"] = []
    with pytest.raises(ValidationError):
        MappingManifest.model_validate(raw)

    raw = _manifest_raw()
    _logical_rule(raw)["target"]["realization"]["alternatives"][0]["kind"] = "packed"
    with pytest.raises(ValidationError):
        MappingManifest.model_validate(raw)

    raw = _manifest_raw()
    _logical_rule(raw)["target"]["payload_relation"]["status"] = "declared"
    with pytest.raises(ValidationError, match="Phase 4E"):
        MappingManifest.model_validate(raw)

    raw = _manifest_raw()
    _logical_rule(raw)["target"]["realization"]["alternatives"][0]["tensor"][
        "canonical_identity"
    ] = "qwen2.token_embedding.weight"
    with pytest.raises(ValidationError, match="identity does not match"):
        MappingManifest.model_validate(raw)


def test_legacy_materialization_manifest_remains_unchanged() -> None:
    manifest = load_mapping_manifest(Path("mappings/qwen2_5_0_5b_hf_to_gguf.yaml"))
    rule = next(item for item in manifest.rules if item.rule_id == "logical-output-projection")
    assert rule.target.realization is None
    report = validate_semantic_mapping(_source(), _target(TARGET_290), manifest)
    assert next(item for item in report.findings if item.rule_id == "MAP-008").status == "fail"
    assert report.realizations == []


def test_291_selects_materialized_and_keeps_payload_not_checked() -> None:
    report = validate_semantic_mapping(
        _source(), _target(TARGET_291), load_mapping_manifest(MANIFEST)
    )
    assert report.passed
    assert report.realizations[0].selected_realization_id == "separately-materialized"
    assert report.realizations[0].realization_kind == "materialized"
    assert report.realizations[0].payload_relation_status == "not_checked"
    assert next(item for item in report.findings if item.rule_id == "MAP-009").status == "warn"


def test_290_requires_provenance_then_selects_backend_fallback() -> None:
    manifest = load_mapping_manifest(MANIFEST)
    without = validate_semantic_mapping(_source(), _target(TARGET_290), manifest)
    assert not without.passed
    assert without.realizations[0].selected_realization_id is None
    provenance, provenance_validation = _provenance()
    report = validate_semantic_mapping(
        _source(),
        _target(TARGET_290),
        manifest,
        provenance_validation=provenance_validation,
        conversion_provenance=provenance,
    )
    selection = report.realizations[0]
    assert report.passed
    assert selection.selected_realization_id == "llama-qwen2-token-embedding-fallback"
    assert selection.realization_kind == "backend_fallback"
    assert selection.physical_tensor_present is False
    assert selection.backing_tensor == "token_embd.weight"
    assert selection.backing_tensor_present is True
    assert selection.evidence_digest is not None
    assert len(selection.evidence_digest) == 64
    assert selection.payload_relation_status == "not_checked"


def test_backend_revision_and_architecture_mismatches_fail() -> None:
    provenance, provenance_validation = _provenance()
    for field, value in (
        ("revision", "0" * 40),
        ("architecture", "other"),
    ):
        raw = _manifest_raw()
        fallback = _logical_rule(raw)["target"]["realization"]["alternatives"][1]
        fallback["backend_policy"][field] = value
        report = validate_semantic_mapping(
            _source(),
            _target(TARGET_290),
            MappingManifest.model_validate(raw),
            provenance_validation=provenance_validation,
            conversion_provenance=provenance,
        )
        assert not report.passed


def test_materialized_shape_mismatch_and_missing_tensor_fail() -> None:
    manifest = load_mapping_manifest(MANIFEST)
    target_raw = _json(TARGET_291)
    output = next(item for item in target_raw["tensors"] if item["name"] == "output.weight")
    output["shape"] = [1, 1]
    mismatch = validate_semantic_mapping(
        _source(), GGUFInventory.model_validate(target_raw), manifest
    )
    assert not mismatch.passed

    missing = validate_semantic_mapping(_source(), _target(TARGET_290), manifest)
    assert not missing.passed
    assert missing.realizations[0].matched_realization_ids == []


def test_format_alias_requires_explicit_metadata_and_backing() -> None:
    raw = _manifest_raw()
    logical = _logical_rule(raw)
    logical["target"]["realization"]["alternatives"] = [
        {
            "realization_id": "explicit-alias",
            "kind": "format_alias",
            "alias_tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
            "backing_tensor": {
                "canonical_identity": "qwen2.token_embedding.weight",
                "tensor_name": "token_embd.weight",
            },
            "format_contract": {
                "target_format": "gguf",
                "contract_id": "test-alias-v1",
                "metadata_key": "test.alias",
                "metadata_value": True,
            },
        }
    ]
    manifest = MappingManifest.model_validate(raw)
    no_metadata = validate_semantic_mapping(_source(), _target(TARGET_291), manifest)
    assert not no_metadata.passed

    target_raw = _json(TARGET_291)
    target_raw["metadata"].append(
        {"key": "test.alias", "value_type": "BOOL", "value": True}
    )
    target_raw["header"]["metadata_kv_count"] += 1
    explicit = validate_semantic_mapping(
        _source(), GGUFInventory.model_validate(target_raw), manifest
    )
    assert explicit.passed
    assert explicit.realizations[0].realization_kind == "format_alias"


def test_multiple_satisfied_alternatives_fail_in_deterministic_order() -> None:
    raw = _manifest_raw()
    logical = _logical_rule(raw)
    logical["target"]["realization"]["alternatives"].append(
        {
            "realization_id": "explicit-alias",
            "kind": "format_alias",
            "alias_tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
            "backing_tensor": {
                "canonical_identity": "qwen2.token_embedding.weight",
                "tensor_name": "token_embd.weight",
            },
            "format_contract": {
                "target_format": "gguf",
                "contract_id": "test-alias-v1",
                "metadata_key": "test.alias",
                "metadata_value": True,
            },
        }
    )
    target_raw = _json(TARGET_291)
    target_raw["metadata"].append(
        {"key": "test.alias", "value_type": "BOOL", "value": True}
    )
    target_raw["header"]["metadata_kv_count"] += 1
    report = validate_semantic_mapping(
        _source(),
        GGUFInventory.model_validate(target_raw),
        MappingManifest.model_validate(raw),
    )
    assert not report.passed
    assert report.realizations[0].selected_realization_id is None
    assert report.realizations[0].matched_realization_ids == [
        "explicit-alias",
        "separately-materialized",
    ]


def test_synthesized_requires_pinned_converter_and_never_upgrades_payload() -> None:
    raw = _manifest_raw()
    logical = _logical_rule(raw)
    logical["target"]["realization"]["alternatives"] = [
        {
            "realization_id": "converter-copy",
            "kind": "synthesized",
            "tensor": {
                "canonical_identity": "qwen2.output_projection.weight",
                "tensor_name": "output.weight",
            },
            "converter_policy": {
                "converter": "llama.cpp",
                "repository": "ggml-org/llama.cpp",
                "revision": "e3546c7948e3af463d0b401e6421d5a4c2faf565",
                "synthesis_rule_id": "test-copy-v1",
                "operation": "copy",
            },
        }
    ]
    manifest = MappingManifest.model_validate(raw)
    absent = validate_semantic_mapping(_source(), _target(TARGET_291), manifest)
    assert not absent.passed
    provenance, provenance_validation = _provenance()
    valid = validate_semantic_mapping(
        _source(),
        _target(TARGET_291),
        manifest,
        provenance_validation=provenance_validation,
        conversion_provenance=provenance,
    )
    assert valid.passed
    assert valid.realizations[0].realization_kind == "synthesized"
    assert valid.realizations[0].payload_relation_status == "not_checked"

    raw = manifest.model_dump(mode="json")
    _logical_rule(raw)["target"]["realization"]["alternatives"][0]["converter_policy"][
        "revision"
    ] = "0" * 40
    mismatch = validate_semantic_mapping(
        _source(),
        _target(TARGET_291),
        MappingManifest.model_validate(raw),
        provenance_validation=provenance_validation,
        conversion_provenance=provenance,
    )
    assert not mismatch.passed


def test_unsupported_evidence_id_is_invalid_cli_input(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unsupported.yaml"
    path.write_text(
        MANIFEST.read_text(encoding="utf-8").replace(
            "llama-qwen2-output-fallback-v1",
            "untrusted-user-claim",
        ),
        encoding="utf-8",
    )
    with pytest.raises(OmivInputError, match="unsupported realization evidence ID"):
        load_mapping_manifest(path)


def test_reports_preserve_realization_and_payload_status() -> None:
    validation = validate_semantic_mapping(
        _source(), _target(TARGET_291), load_mapping_manifest(MANIFEST)
    )
    envelope = build_mapping_report_envelope(
        _source(), _target(TARGET_291), load_mapping_manifest(MANIFEST), validation
    )
    assert mapping_report_integrity_matches(envelope)
    markdown = render_mapping_markdown(envelope)
    assert "Structural realization: PASS" in markdown
    assert "Selected realization: materialized" in markdown
    assert "Payload equality: NOT CHECKED" in markdown


def test_core_realization_validator_has_no_qwen_or_backend_literals() -> None:
    text = Path("src/omiv/mapping/realization.py").read_text(encoding="utf-8").lower()
    for literal in ("qwen", "llama.cpp", "output.weight", "token_embd.weight"):
        assert literal not in text
