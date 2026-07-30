from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.model_packs import ModelPackCapability, get_model_pack
from omiv.model_packs.kimi_k3.gguf_models import (
    KimiK3GGUFOntologyReportEnvelope,
)
from omiv.model_packs.kimi_k3.gguf_ontology import (
    KimiK3GGUFOntologyPolicy,
    parse_gguf_name,
)
from omiv.model_packs.kimi_k3.gguf_reporting import (
    build_ontology_inventory_envelope,
    build_ontology_report,
    load_ontology_inventory,
    load_ontology_report,
    ontology_inventory_integrity_matches,
    ontology_inventory_links_split,
    ontology_report_integrity_matches,
    pretty_ontology_json,
    render_ontology_markdown,
)
from omiv.model_packs.kimi_k3.gguf_validator import (
    build_kimi_k3_gguf_ontology,
    validate_metadata_inventory_linkage,
)
from omiv.remote.header_models import HeaderInventoryEnvelope
from omiv.remote.header_reporting import (
    build_header_inventory_envelope,
    load_header_inventory,
)
from omiv.remote.split_models import SplitInventoryEnvelope
from omiv.remote.split_reporting import (
    build_split_inventory_envelope,
    load_split_inventory,
)

ROOT = Path(__file__).resolve().parents[1]
SPLIT_PATH = ROOT / "inventories/remote" / "unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json"
METADATA_PATH = (
    ROOT
    / "inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M/shards"
    / "Kimi-K3-UD-IQ1_M-00001-of-00015.header.inventory.json"
)


@pytest.fixture(scope="module")
def split() -> SplitInventoryEnvelope:
    return load_split_inventory(SPLIT_PATH)


@pytest.fixture(scope="module")
def metadata() -> HeaderInventoryEnvelope:
    return load_header_inventory(METADATA_PATH)


@pytest.fixture(scope="module")
def ontology(split: SplitInventoryEnvelope, metadata: HeaderInventoryEnvelope):
    return build_kimi_k3_gguf_ontology(
        split,
        metadata,
        get_model_pack("kimi-k3"),
    )


@pytest.mark.parametrize(
    ("name", "layer_id", "family_id", "malformed"),
    [
        ("token_embd.weight", None, "model.token_embedding", False),
        ("blk.0.ffn_gate.weight", 0, "dense.gate", False),
        ("blk.92.attn_q_a.weight", 92, "mla.query_a", False),
        ("blk.12.ssm_g.weight", 12, "g_proj.kda", False),
        ("aux.12.weight", None, None, False),
        ("blk.01.attn_q.weight", None, None, True),
        ("blk.1foo.attn_q.weight", None, None, True),
    ],
)
def test_tensor_name_grammar_is_specific(
    name: str,
    layer_id: int | None,
    family_id: str | None,
    malformed: bool,
) -> None:
    parsed = parse_gguf_name(name)
    assert (parsed.layer_id, parsed.family_id, parsed.malformed) == (
        layer_id,
        family_id,
        malformed,
    )


def test_policy_schedule_and_digest_are_deterministic() -> None:
    policy = KimiK3GGUFOntologyPolicy()
    assert policy.digest == KimiK3GGUFOntologyPolicy().digest
    assert policy.expected_layer_ids == list(range(93))
    assert len(policy.expected_kda_layer_ids) == 69
    assert len(policy.expected_mla_layer_ids) == 24
    assert policy.expected_mla_layer_ids[-2:] == [91, 92]
    assert not set(policy.expected_kda_layer_ids) & set(policy.expected_mla_layer_ids)
    assert set(policy.expected_kda_layer_ids) | set(policy.expected_mla_layer_ids) == set(range(93))


def test_model_pack_exposes_target_gguf_capability() -> None:
    pack = get_model_pack("kimi-k3")
    assert pack.pack_version == 3
    assert ModelPackCapability.GGUF_ONTOLOGY in pack.capabilities
    assert ModelPackCapability.SEMANTIC_MAPPING in pack.capabilities
    assert pack.supported_target_formats == {"gguf"}
    classified = pack.classify_gguf_tensor("blk.7.attn_gate.weight")
    assert classified.canonical is not None
    assert classified.canonical.layer_id == 7
    assert classified.layer_component == "g_proj.mla"


def test_real_census_and_classification_accounting(ontology) -> None:
    assert ontology.split_tensor_count == 2573
    assert ontology.census.unique_tensor_count == 2573
    assert ontology.census.top_level_prefix_counts == {
        "blk": 2569,
        "output": 1,
        "output_norm": 1,
        "output_res_score": 1,
        "token_embd": 1,
    }
    assert ontology.census.observed_layer_ids == list(range(93))
    assert ontology.census.tensor_count_by_layer["0"] == 21
    assert ontology.census.tensor_count_by_layer["3"] == 24
    assert ontology.census.tensor_count_by_layer["4"] == 29
    assert ontology.census.tensor_count_by_ggml_type == {
        "F32": 1181,
        "IQ1_S": 209,
        "IQ2_XXS": 56,
        "IQ3_XXS": 11,
        "Q8_0": 1116,
    }
    assert ontology.classification.classified_count == 2573
    assert ontology.classification.intentionally_unclassified_count == 0
    assert ontology.classification.invalid_count == 0
    assert ontology.classification.duplicate_classification_count == 0
    assert not ontology.census.malformed_names


def test_architecture_metadata_is_direct_typed_and_linked(ontology) -> None:
    summary = ontology.architecture_metadata
    assert summary.architecture_identifier == "kimi-k3"
    assert summary.model_name == "Kimi-K3"
    assert not summary.required_failures
    items = {item.key: item for item in summary.items}
    assert items["kimi-k3.block_count"].summary_value == 93
    assert items["kimi-k3.embedding_length"].summary_value == 7168
    assert items["kimi-k3.expert_count"].summary_value == 896
    assert items["kimi-k3.attn_res.block_size"].summary_value == 12
    kv_schedule = items["kimi-k3.attention.head_count_kv"]
    assert kv_schedule.value_type == "ARRAY"
    assert kv_schedule.encoded_sha256 is not None
    assert kv_schedule.valid


def test_layer_attention_and_ffn_schedules_are_exact(ontology) -> None:
    schedule = ontology.schedule
    assert schedule.observed_layer_ids == list(range(93))
    assert schedule.kda_layer_ids == ontology.ontology_policy.expected_kda_layer_ids
    assert schedule.mla_layer_ids == ontology.ontology_policy.expected_mla_layer_ids
    assert schedule.dense_layer_ids == [0]
    assert schedule.moe_layer_ids == list(range(1, 93))
    assert not schedule.attention_overlap_layer_ids
    assert not schedule.missing_layer_ids
    assert all(
        not item.missing_family_ids and not item.unexpected_family_ids
        for item in ontology.layer_summaries
    )


def test_packed_shared_gproj_and_attention_residual_structures(ontology) -> None:
    assert ontology.packed_experts.family_ids == [
        "moe.packed_down",
        "moe.packed_gate",
        "moe.packed_up",
    ]
    assert ontology.packed_experts.structurally_encoded_expert_counts == [896]
    assert ontology.packed_experts.metadata_expert_count == 896
    assert ontology.packed_experts.layer_ids == list(range(1, 93))
    assert not ontology.packed_experts.missing_layer_ids
    assert ontology.shared_experts.layer_ids == list(range(1, 93))
    assert ontology.g_proj.kda_layer_ids == ontology.schedule.kda_layer_ids
    assert ontology.g_proj.mla_layer_ids == ontology.schedule.mla_layer_ids
    assert ontology.g_proj.combined_layer_ids == list(range(93))
    assert ontology.attention_residual.metadata_block_size == 12
    assert ontology.attention_residual.derived_checkpoint_layer_ids == [
        0,
        12,
        24,
        36,
        48,
        60,
        72,
        84,
    ]
    assert not ontology.attention_residual.missing_components


def test_family_shape_normalization_and_type_placement(ontology) -> None:
    families = {item.family_id: item for item in ontology.family_summaries}
    packed = families["moe.packed_gate"]
    assert packed.shape_summaries[0].physical_dimensions == [3584, 3072, 896]
    assert packed.shape_summaries[0].normalized_dimensions == [3584, 3072, 896]
    assert packed.ggml_type_counts == {"IQ1_S": 64, "IQ2_XXS": 28}
    assert packed.allowed_ggml_types == ["IQ1_S", "IQ2_XXS", "MXFP4"]
    assert packed.shape_valid and packed.type_valid and packed.coverage_valid
    norm = families["attention.input_norm"]
    assert norm.ggml_type_counts == {"F32": 93}
    assert families["g_proj.kda"].ggml_type_counts == {"Q8_0": 69}
    assert all(
        family.shape_valid and family.type_valid and family.coverage_valid
        for family in ontology.family_summaries
    )


def _changed_split(
    split: SplitInventoryEnvelope,
    *,
    tensor_name: str,
    dimensions: list[int] | None = None,
    ggml_type_name: str | None = None,
    new_name: str | None = None,
) -> SplitInventoryEnvelope:
    raw = split.inventory.model_dump(mode="json")
    tensor = next(item for item in raw["tensors"] if item["name"] == tensor_name)
    if dimensions is not None:
        tensor["dimensions"] = dimensions
    if ggml_type_name is not None:
        tensor["ggml_type_name"] = ggml_type_name
    if new_name is not None:
        tensor["name"] = new_name
        raw["tensors"].sort(
            key=lambda item: (
                item["name"],
                item["filename_ordinal"],
                item["descriptor_index"],
            )
        )
    changed = type(split.inventory).model_validate(raw)
    return build_split_inventory_envelope(changed)


@pytest.mark.parametrize(
    "tensor_name",
    [
        "blk.1.ffn_gate_exps.weight",
        "blk.1.ffn_up_exps.weight",
        "blk.1.ffn_down_exps.weight",
    ],
)
def test_mxfp4_is_narrowly_allowed_for_packed_experts(
    split: SplitInventoryEnvelope,
    metadata: HeaderInventoryEnvelope,
    tensor_name: str,
) -> None:
    changed = _changed_split(
        split,
        tensor_name=tensor_name,
        ggml_type_name="MXFP4",
    )
    result = build_kimi_k3_gguf_ontology(
        changed, metadata, get_model_pack("kimi-k3")
    )
    assert result.classification.invalid_count == 0


@pytest.mark.parametrize(
    "tensor_name",
    [
        "blk.1.attn_norm.weight",
        "blk.1.ffn_gate_inp.weight",
        "blk.1.attn_res_score.weight",
        "blk.0.ffn_gate.weight",
    ],
)
def test_mxfp4_is_rejected_outside_packed_experts(
    split: SplitInventoryEnvelope,
    metadata: HeaderInventoryEnvelope,
    tensor_name: str,
) -> None:
    changed = _changed_split(
        split,
        tensor_name=tensor_name,
        ggml_type_name="MXFP4",
    )
    result = build_kimi_k3_gguf_ontology(
        changed, metadata, get_model_pack("kimi-k3")
    )
    assert result.classification.invalid_count == 1
    assert result.classification.invalid_details[0].name == tensor_name


@pytest.mark.parametrize(
    ("change", "finding"),
    [
        (
            {
                "tensor_name": "blk.1.ffn_gate_exps.weight",
                "dimensions": [3584, 3072, 895],
            },
            "KIMIGGUF-007",
        ),
        (
            {
                "tensor_name": "blk.1.ffn_gate_exps.weight",
                "ggml_type_name": "F32",
            },
            "KIMIGGUF-012",
        ),
        (
            {
                "tensor_name": "blk.92.attn_q_a.weight",
                "new_name": "blk.93.attn_q_a.weight",
            },
            "KIMIGGUF-002",
        ),
        (
            {
                "tensor_name": "blk.1.ffn_gate_inp.weight",
                "new_name": "blk.1.unknown_42.weight",
            },
            "KIMIGGUF-013",
        ),
    ],
)
def test_structural_mutations_fail_recorded_findings(
    split: SplitInventoryEnvelope,
    metadata: HeaderInventoryEnvelope,
    change: dict[str, object],
    finding: str,
) -> None:
    changed = _changed_split(split, **change)  # type: ignore[arg-type]
    result = build_kimi_k3_gguf_ontology(changed, metadata, get_model_pack("kimi-k3"))
    statuses = {item.rule_id: item.status.value for item in result.findings}
    assert statuses[finding] == "fail"


def test_metadata_linkage_and_architecture_tamper_are_detected(
    split: SplitInventoryEnvelope,
    metadata: HeaderInventoryEnvelope,
) -> None:
    foreign_raw = metadata.model_dump(mode="json")
    foreign_raw["integrity"]["sha256"] = "f" * 64
    foreign = HeaderInventoryEnvelope.model_validate(foreign_raw)
    with pytest.raises(OmivInputError, match="integrity"):
        validate_metadata_inventory_linkage(split, foreign)

    header_raw = metadata.inventory.model_dump(mode="json")
    architecture = next(
        item for item in header_raw["metadata"] if item["key"] == "general.architecture"
    )
    architecture["summary_value"] = "not-kimi-k3"
    changed_header = type(metadata.inventory).model_validate(header_raw)
    changed_envelope = build_header_inventory_envelope(changed_header)
    changed_split_raw = split.inventory.model_dump(mode="json")
    primary = next(
        item
        for item in changed_split_raw["shard_summaries"]
        if item["path"] == changed_header.file.path
    )
    primary["inventory_sha256"] = changed_envelope.integrity.sha256
    changed_split = build_split_inventory_envelope(
        type(split.inventory).model_validate(changed_split_raw)
    )
    result = build_kimi_k3_gguf_ontology(changed_split, changed_envelope, get_model_pack("kimi-k3"))
    assert result.architecture_metadata.required_failures == ["general.architecture"]
    assert result.findings[0].status.value == "fail"


def test_inventory_report_verification_determinism_and_privacy(
    tmp_path: Path,
    split: SplitInventoryEnvelope,
    ontology,
) -> None:
    inventory = build_ontology_inventory_envelope(ontology)
    report = build_ontology_report(inventory)
    assert ontology_inventory_integrity_matches(inventory)
    assert ontology_inventory_links_split(inventory, split)
    assert ontology_report_integrity_matches(report)
    assert pretty_ontology_json(report) == pretty_ontology_json(build_ontology_report(inventory))
    markdown = render_ontology_markdown(report)
    assert "KIMIGGUF\\-006" in markdown
    encoded = pretty_ontology_json(report)
    for forbidden in (
        "https://",
        "Authorization",
        "Bearer ",
        "X-Amz-",
        "/home/",
        "timestamp",
        "tokenizer.ggml.tokens",
    ):
        assert forbidden not in encoded
    inventory_path = tmp_path / "ontology.inventory.json"
    report_path = tmp_path / "ontology.report.json"
    inventory_path.write_text(pretty_ontology_json(inventory), encoding="utf-8")
    report_path.write_text(encoded, encoding="utf-8")
    assert ontology_inventory_integrity_matches(load_ontology_inventory(inventory_path))
    assert ontology_report_integrity_matches(load_ontology_report(report_path))

    raw = json.loads(encoded)
    raw["report"]["findings"][0]["status"] = "warn"
    raw["integrity"]["sha256"] = canonical_sha256(raw["report"])
    report_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid"):
        load_ontology_report(report_path)


def test_cli_exit_codes_and_source_linkage(
    tmp_path: Path,
    split: SplitInventoryEnvelope,
) -> None:
    inventory_path = tmp_path / "ontology.inventory.json"
    report_path = tmp_path / "ontology.report.json"
    markdown_path = tmp_path / "ontology.report.md"
    runner = CliRunner()
    success = runner.invoke(
        app,
        [
            "kimi-k3-gguf-ontology",
            "--input",
            str(SPLIT_PATH),
            "--metadata-inventory",
            str(METADATA_PATH),
            "--output",
            str(inventory_path),
            "--report-output",
            str(report_path),
            "--markdown-output",
            str(markdown_path),
        ],
    )
    assert success.exit_code == 0, success.output
    assert (
        runner.invoke(
            app,
            [
                "kimi-k3-gguf-ontology-inventory-verify",
                "--input",
                str(inventory_path),
                "--source",
                str(SPLIT_PATH),
            ],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["report-verify", "--input", str(report_path)]).exit_code == 0

    wrong_pack = runner.invoke(
        app,
        [
            "kimi-k3-gguf-ontology",
            "--input",
            str(SPLIT_PATH),
            "--metadata-inventory",
            str(METADATA_PATH),
            "--model-pack",
            "qwen2",
            "--output",
            str(tmp_path / "bad.inventory.json"),
            "--report-output",
            str(tmp_path / "bad.report.json"),
            "--markdown-output",
            str(tmp_path / "bad.report.md"),
        ],
    )
    assert wrong_pack.exit_code == 2

    changed = _changed_split(
        split,
        tensor_name="blk.1.ffn_gate_exps.weight",
        dimensions=[3584, 3072, 895],
    )
    changed_path = tmp_path / "changed.split.inventory.json"
    changed_path.write_text(
        json.dumps(changed.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    failed = runner.invoke(
        app,
        [
            "kimi-k3-gguf-ontology",
            "--input",
            str(changed_path),
            "--metadata-inventory",
            str(METADATA_PATH),
            "--output",
            str(tmp_path / "failed.inventory.json"),
            "--report-output",
            str(tmp_path / "failed.report.json"),
            "--markdown-output",
            str(tmp_path / "failed.report.md"),
        ],
    )
    assert failed.exit_code == 1, failed.output


def test_report_schema_rejects_unknown_fields(ontology) -> None:
    report = build_ontology_report(build_ontology_inventory_envelope(ontology))
    raw = report.model_dump(mode="json")
    raw["report"]["unknown"] = True
    with pytest.raises(ValidationError):
        KimiK3GGUFOntologyReportEnvelope.model_validate(raw)


def test_full_real_findings_are_reconstructed_pass(ontology) -> None:
    assert [item.rule_id for item in ontology.findings] == [
        f"KIMIGGUF-{index:03d}" for index in range(1, 16)
    ]
    assert all(item.status.value == "pass" for item in ontology.findings)
    assert ontology.census.ordering.payload_gap_count == 0
    assert ontology.census.ordering.trailing_byte_count == 0
