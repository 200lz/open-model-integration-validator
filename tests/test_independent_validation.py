import json
from pathlib import Path, PurePosixPath

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.external_artifacts import (
    KIMI_K3_TENSOR_INVENTORY,
    ExternalArtifactStatus,
    observe_external_artifact,
)
from omiv.validation.builder import build_independent_validation
from omiv.validation.models import (
    EvidenceStatus,
    ProfileOutcome,
    ValidationInventory,
)
from omiv.validation.profiles import evaluate_profiles, profile_policy
from omiv.validation.reporting import (
    build_validation_report,
    load_validation_inventory,
    load_validation_report,
    pretty_json,
    render_validation_markdown,
    verify_validation_inventory,
    verify_validation_inventory_with_availability,
    verify_validation_report,
    write_validation_bundle,
)

ROOT = Path(__file__).parents[1]
SNAPSHOT = ROOT / "snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json"
SPLIT = ROOT / "inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json"
ONTOLOGY = ROOT / "inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.inventory.json"
MAPPING = ROOT / "inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.inventory.json"
VALIDATION = ROOT / "validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json"


@pytest.fixture(scope="module")
def validation_inventory() -> ValidationInventory:
    return load_validation_inventory(VALIDATION)


def test_complete_graph_and_deterministic_order(
    validation_inventory: ValidationInventory,
) -> None:
    node_ids = [node.node_id for node in validation_inventory.evidence_nodes]
    edge_keys = [
        (edge.parent_node_id, edge.child_node_id, edge.dependency_relation)
        for edge in validation_inventory.evidence_edges
    ]
    assert node_ids == sorted(node_ids)
    assert edge_keys == sorted(edge_keys)
    assert len(node_ids) == 26
    assert all(
        edge.linkage_status == EvidenceStatus.PASS for edge in validation_inventory.evidence_edges
    )


def test_graph_rejects_duplicate_node(
    validation_inventory: ValidationInventory,
) -> None:
    data = validation_inventory.model_dump(mode="json")
    data["evidence_nodes"].append(data["evidence_nodes"][0])
    with pytest.raises(ValidationError, match="duplicate evidence node"):
        ValidationInventory.model_validate(data)


def test_graph_rejects_missing_node_reference(
    validation_inventory: ValidationInventory,
) -> None:
    data = validation_inventory.model_dump(mode="json")
    data["evidence_edges"][0]["parent_node_id"] = "missing"
    with pytest.raises(ValidationError, match="unknown node"):
        ValidationInventory.model_validate(data)


def test_graph_rejects_cycle(validation_inventory: ValidationInventory) -> None:
    data = validation_inventory.model_dump(mode="json")
    first = data["evidence_nodes"][0]["node_id"]
    last = data["evidence_nodes"][-1]["node_id"]
    data["evidence_edges"].extend(
        [
            {
                "parent_node_id": first,
                "child_node_id": last,
                "dependency_relation": "test-forward",
                "expected_digest": "0" * 64,
                "observed_digest": "0" * 64,
                "linkage_status": "PASS",
                "mismatch_reason": None,
            },
            {
                "parent_node_id": last,
                "child_node_id": first,
                "dependency_relation": "test-backward",
                "expected_digest": "0" * 64,
                "observed_digest": "0" * 64,
                "linkage_status": "PASS",
                "mismatch_reason": None,
            },
        ]
    )
    with pytest.raises(ValidationError, match="cycle"):
        ValidationInventory.model_validate(data)


def test_graph_digest_and_inventory_tamper_detection(
    validation_inventory: ValidationInventory, tmp_path: Path
) -> None:
    data = validation_inventory.model_dump(mode="json")
    data["evidence_nodes"][0]["canonical_digest"] = "f" * 64
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(OmivInputError, match="inventory digest mismatch"):
        load_validation_inventory(path)


def test_unknown_field_is_rejected(
    validation_inventory: ValidationInventory,
) -> None:
    data = validation_inventory.model_dump(mode="json")
    data["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        ValidationInventory.model_validate(data)


def test_structural_stages_and_explicit_boundaries(
    validation_inventory: ValidationInventory,
) -> None:
    statuses = {stage.stage.value: stage.status for stage in validation_inventory.evidence_stages}
    assert statuses["repository_identity"] == EvidenceStatus.PASS
    assert statuses["structural_semantic_mapping"] == EvidenceStatus.PASS
    assert statuses["converter_rule_support"] == EvidenceStatus.AVAILABLE
    assert statuses["artifact_specific_provenance"] == EvidenceStatus.UNAVAILABLE
    for name in (
        "payload_integrity",
        "quantization_fidelity",
        "tokenizer_parity",
        "runtime_parity",
    ):
        assert statuses[name] == EvidenceStatus.NOT_CHECKED
    assert validation_inventory.unverified_stage_count == 4
    assert validation_inventory.unavailable_stage_count == 1
    assert validation_inventory.failed_stage_count == 0


def test_profiles_reconstruct_and_do_not_escalate(
    validation_inventory: ValidationInventory,
) -> None:
    results = {
        item.profile_name: item
        for item in evaluate_profiles(validation_inventory.evidence_stages, profile_policy())
    }
    assert results["community_structural"].outcome == ProfileOutcome.SATISFIED
    assert results["vendor_release_structural"].outcome == ProfileOutcome.SATISFIED_WITH_WARNINGS
    assert (
        results["enterprise_offline_structural"].outcome == ProfileOutcome.SATISFIED_WITH_WARNINGS
    )
    assert results["regulated_deployment_full"].outcome == ProfileOutcome.NOT_SATISFIED
    assert results["regulated_deployment_full"].failed_requirement_count == 5


def test_profile_policy_digest_is_stable() -> None:
    assert profile_policy() == profile_policy()
    assert (
        profile_policy().policy_digest
        == "ec745ebc9c7a7f1b51b115ab049a6507e76d5902aa98d8d7a27c70497886bdc7"
    )


def test_real_graph_and_artifact_index_digests_are_stable(
    validation_inventory: ValidationInventory,
) -> None:
    assert (
        validation_inventory.evidence_graph_digest
        == "ea08a66295a72ebb1331196e9cd3c94845fc21208b08240447828ae77b7db2eb"
    )
    assert (
        validation_inventory.artifact_index.index_digest
        == "6059d6a460f5d417173c4346f0c4e5d6c26a4887e488ea7c24d5e473ca6094a6"
    )


def test_unknown_profile_fails_closed() -> None:
    with pytest.raises(OmivInputError, match="unknown acceptance profile"):
        build_independent_validation(
            root=ROOT,
            subject="kimi-k3",
            variant="UD-IQ1_M",
            snapshot_path=SNAPSHOT,
            split_path=SPLIT,
            ontology_path=ONTOLOGY,
            mapping_path=MAPPING,
            selected_profile="unknown",
        )


def test_artifact_index_is_relative_complete_and_deterministic(
    validation_inventory: ValidationInventory,
) -> None:
    entries = validation_inventory.artifact_index.entries
    assert len(entries) == 26
    assert [(item.producer_phase, item.role) for item in entries] == sorted(
        (item.producer_phase, item.role) for item in entries
    )
    for entry in entries:
        path = PurePosixPath(entry.relative_path)
        assert not path.is_absolute()
        assert ".." not in path.parts
        if entry.relative_path == KIMI_K3_TENSOR_INVENTORY.relative_path:
            observation = observe_external_artifact(ROOT, KIMI_K3_TENSOR_INVENTORY)
            assert entry.size_bytes == KIMI_K3_TENSOR_INVENTORY.size_bytes
            assert entry.canonical_digest == KIMI_K3_TENSOR_INVENTORY.sha256
            assert observation.status in {
                ExternalArtifactStatus.PRESENT_AND_VERIFIED,
                ExternalArtifactStatus.NOT_AVAILABLE,
            }
        else:
            assert (ROOT / entry.relative_path).stat().st_size == entry.size_bytes
    assert {item.role for item in entries} >= {
        "repository_snapshot",
        "split_inventory",
        "target_ontology_inventory",
        "semantic_mapping_inventory",
        "source_checkpoint_inventory",
    }


def test_accounting_and_architecture_are_derived(
    validation_inventory: ValidationInventory,
) -> None:
    assert validation_inventory.source_accounting["physical_records"] == 497220
    assert validation_inventory.source_accounting["unresolved_records"] == 0
    assert validation_inventory.source_accounting["newly_classified_text_records"] == 282
    assert validation_inventory.source_accounting["source_only_auxiliary_records"] == 168
    assert validation_inventory.target_accounting["physical_records"] == 2573
    assert validation_inventory.target_accounting["unresolved_records"] == 0
    assert validation_inventory.architecture_summary["layers"] == 93
    assert validation_inventory.architecture_summary["kda_layers"] == 69
    assert validation_inventory.architecture_summary["mla_layers"] == 24


def test_repository_and_payload_span_summary(
    validation_inventory: ValidationInventory,
) -> None:
    summary = validation_inventory.repository_summary
    assert summary["selected_shard_count"] == 15
    assert summary["total_repository_bytes"] == 648872012448
    assert summary["global_declared_tensor_count"] == 2573
    assert summary["aggregated_tensor_count"] == 2573
    assert summary["payload_span_bounded_count"] == 2573
    assert summary["payload_span_overlap_count"] == 0
    assert summary["tensor_payload_bytes_accepted"] == 0


def test_report_is_deterministic_and_has_required_sections(
    validation_inventory: ValidationInventory,
) -> None:
    first = build_validation_report(validation_inventory)
    second = build_validation_report(validation_inventory)
    assert first == second
    markdown = render_validation_markdown(first)
    for heading in (
        "Executive Summary",
        "Engineering Summary",
        "Commercial Acceptance Controls",
        "Validation Stages",
        "Acceptance Profiles",
        "Verified",
        "Not Verified",
        "Unavailable Evidence",
        "Not-Checked Evidence",
        "Artifact Index",
    ):
        assert heading in markdown
    assert "tensor payload integrity" in markdown
    assert "runtime equivalence" in markdown


def test_report_and_inventory_offline_verification(
    validation_inventory: ValidationInventory, tmp_path: Path
) -> None:
    inventory_path = tmp_path / "validation.json"
    report_path = tmp_path / "report.json"
    inventory_path.write_text(pretty_json(validation_inventory), encoding="utf-8")
    report = build_validation_report(validation_inventory)
    report_path.write_text(pretty_json(report), encoding="utf-8")
    assert verify_validation_inventory(inventory_path, ROOT) == validation_inventory
    verification = verify_validation_inventory_with_availability(inventory_path, ROOT)
    assert verification.inventory == validation_inventory
    observation = verification.external_artifacts[0]
    assert observation.expected.identity_status == (
        ExternalArtifactStatus.EXPECTED_IDENTITY_RECORDED
    )
    assert observation.status in {
        ExternalArtifactStatus.PRESENT_AND_VERIFIED,
        ExternalArtifactStatus.NOT_AVAILABLE,
    }
    assert verify_validation_report(report_path, ROOT) == report
    assert load_validation_report(report_path) == report


def test_report_tamper_detection(validation_inventory: ValidationInventory, tmp_path: Path) -> None:
    report = build_validation_report(validation_inventory)
    data = report.model_dump(mode="json")
    data["report"]["executive_summary"]["numerical_or_runtime_equivalence"] = True
    path = tmp_path / "tampered-report.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(OmivInputError, match="integrity mismatch"):
        load_validation_report(path)


def test_bundle_writer_rejects_output_collision(
    validation_inventory: ValidationInventory, tmp_path: Path
) -> None:
    output = tmp_path / "same.json"
    with pytest.raises(OmivInputError, match="distinct paths"):
        write_validation_bundle(
            validation_inventory,
            output,
            output,
            tmp_path / "report.md",
        )


def test_cli_exit_zero_and_one(validation_inventory: ValidationInventory, tmp_path: Path) -> None:
    del validation_inventory
    runner = CliRunner()
    common = [
        "independent-validation",
        "--subject",
        "kimi-k3",
        "--variant",
        "UD-IQ1_M",
        "--snapshot",
        str(SNAPSHOT),
        "--split-inventory",
        str(SPLIT),
        "--ontology-inventory",
        str(ONTOLOGY),
        "--mapping-inventory",
        str(MAPPING),
        "--output",
        str(tmp_path / "validation.json"),
        "--report-output",
        str(tmp_path / "report.json"),
        "--markdown-output",
        str(tmp_path / "report.md"),
    ]
    community = runner.invoke(app, [*common, "--profile", "community_structural"])
    regulated = runner.invoke(app, [*common, "--profile", "regulated_deployment_full"])
    observation = observe_external_artifact(ROOT, KIMI_K3_TENSOR_INVENTORY)
    if observation.available:
        assert community.exit_code == 0, community.output
        assert regulated.exit_code == 1, regulated.output
    else:
        assert community.exit_code == 1, community.output
        assert regulated.exit_code == 1, regulated.output
        assert "NOT_AVAILABLE" in community.output
        assert KIMI_K3_TENSOR_INVENTORY.relative_path in community.output


def test_cli_exit_two_for_unknown_profile(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "independent-validation",
            "--subject",
            "kimi-k3",
            "--variant",
            "UD-IQ1_M",
            "--snapshot",
            str(SNAPSHOT),
            "--split-inventory",
            str(SPLIT),
            "--ontology-inventory",
            str(ONTOLOGY),
            "--mapping-inventory",
            str(MAPPING),
            "--profile",
            "unknown",
            "--output",
            str(tmp_path / "validation.json"),
            "--report-output",
            str(tmp_path / "report.json"),
            "--markdown-output",
            str(tmp_path / "report.md"),
        ],
    )
    assert result.exit_code == 2
