import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from omiv.mapping.grouped_engine import (
    AssignmentAudit,
    deterministic_groups,
    validate_many_to_one,
    validate_results_against_policy,
)
from omiv.mapping.grouped_models import (
    GroupRelation,
    MappingInventory,
    MappingPolicy,
    MappingRule,
    SourceAccountingState,
    TargetAccountingState,
)
from omiv.mapping.grouped_reporting import load_mapping_inventory, load_mapping_report
from omiv.model_packs.base import ModelPackCapability
from omiv.model_packs.kimi_k3.mapping_policy import kimi_mapping_policy
from omiv.model_packs.kimi_k3.pack import KimiK3ModelPack
from omiv.model_packs.kimi_k3.semantic_mapping import _Builder

ROOT = Path(__file__).parents[1]
MAPPING_INVENTORY = (
    ROOT / "inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.inventory.json"
)
MAPPING_REPORT = ROOT / "reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.report.json"
MAPPING_MARKDOWN = ROOT / "reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.report.md"


def test_grouped_engine_is_deterministic_and_bounded() -> None:
    groups = deterministic_groups([("b", 2), ("a", 1), ("b", 1)], lambda x: x[0], lambda x: x[1])
    assert list(groups) == ["a", "b"]
    assert groups["b"] == [("b", 1), ("b", 2)]
    assert validate_many_to_one(groups, {"a": object(), "b": object()}, 2) == [
        "a: cardinality 1 != 2"
    ]


def test_mapping_policy_digest_and_cardinality() -> None:
    policy = MappingPolicy(
        source_model_pack="s",
        target_model_pack="t",
        converter_revision="r",
        converter_evidence_role="test",
        rules=[
            MappingRule(
                rule_id="x",
                source_family="a",
                target_family="b",
                relation=GroupRelation.MANY_TO_ONE_PACKED,
                layer_scope="all",
                source_name_pattern="a",
                target_name_patterns=["b"],
                source_cardinality=2,
                target_cardinality=1,
                source_dtype="F16",
                allowed_target_types=["F16"],
                converter_operation="identity",
                evidence_source="test",
            )
        ],
    )
    assert len(policy.digest) == 64


def _rule(rule_id: str, source: str, target: str) -> MappingRule:
    return MappingRule(
        rule_id=rule_id,
        source_family=source,
        target_family=target,
        relation=GroupRelation.ONE_TO_ONE,
        layer_scope="all",
        source_name_pattern=source,
        target_name_patterns=[target],
        source_cardinality=1,
        target_cardinality=1,
        source_dtype="BF16",
        allowed_target_types=["Q8_0"],
        converter_operation="identity",
        evidence_source="pinned",
    )


def test_mapping_policy_rejects_overlapping_targets_and_sources() -> None:
    with pytest.raises(ValidationError, match="target pattern"):
        MappingPolicy(
            source_model_pack="s",
            target_model_pack="t",
            converter_revision="r",
            converter_evidence_role="test",
            rules=[_rule("a", "source-a", "target"), _rule("b", "source-b", "target")],
            exclusion_rules=[],
        )
    with pytest.raises(ValidationError, match="source pattern/scope"):
        MappingPolicy(
            source_model_pack="s",
            target_model_pack="t",
            converter_revision="r",
            converter_evidence_role="test",
            rules=[_rule("a", "source", "target-a"), _rule("b", "source", "target-b")],
            exclusion_rules=[],
        )


def test_assignment_audit_detects_duplicates_and_allows_one_to_many() -> None:
    split = AssignmentAudit()
    split.claim_source("kv_b", logical_identity="layer.3.kv_b")
    split.claim_target("k_b")
    split.claim_target("v_b")
    split.claim_result("split.layer.3")
    split.claim_group("split.layer.3")
    assert split.valid

    split.claim_source("kv_b", logical_identity="layer.3.kv_b")
    split.claim_target("k_b")
    split.claim_result("split.layer.3")
    split.claim_group("split.layer.3")
    summary = split.summary()
    assert summary["duplicate_source_physical"]["count"] == 1
    assert summary["duplicate_source_logical"]["count"] == 1
    assert summary["duplicate_target_physical"]["count"] == 1
    assert summary["duplicate_mapping_result"]["count"] == 1
    assert summary["duplicate_source_group"]["count"] == 1
    assert not split.valid


def _shared_gate_builder(
    *,
    source_dtype: str = "BF16",
    target_type: str = "Q8_0",
    source_shape: tuple[int, ...] = (6144, 7168),
    target_shape: tuple[int, ...] = (6144, 7168),
    include_source: bool = True,
    include_target: bool = True,
) -> _Builder:
    source_name = "language_model.model.layers.1.block_sparse_moe.shared_experts.gate_proj.weight"
    target_name = "blk.1.ffn_gate_shexp.weight"
    sources = (
        [{"name": source_name, "dtype": source_dtype, "shape": list(source_shape)}]
        if include_source
        else []
    )
    targets = (
        [{"name": target_name, "ggml_type_name": target_type, "dimensions": [7168, 6144]}]
        if include_target
        else []
    )
    builder = _Builder(
        sources,
        targets,
        {target_name: list(target_shape)} if include_target else {},
        kimi_mapping_policy(),
    )
    builder.add(
        rule_id="K3-SHARED-GATE",
        relation=GroupRelation.ONE_TO_ONE,
        key=[1, "shared-gate"],
        source_names=[source_name],
        target_names=[target_name],
        source_state=SourceAccountingState.DIRECTLY_MAPPED,
        target_state=TargetAccountingState.DIRECTLY_REALIZED,
        expected_source_shapes={(6144, 7168)},
        expected_target_shapes={(6144, 7168)},
        source_member_count=1,
        allowed_target_types=["Q8_0"],
        axis_relation="layer_and_component_preserved",
        shape_relation="normalized_identity",
        converter_operation="map_tensor_name_then_gguf_dimension_reversal",
    )
    return builder


@pytest.mark.parametrize(
    ("kwargs", "failure"),
    [
        ({"source_dtype": "F32"}, "type_failures"),
        ({"target_type": "F32"}, "type_failures"),
        ({"source_shape": (1, 1)}, "shape_failures"),
        ({"target_shape": (1, 1)}, "shape_failures"),
        ({"include_source": False}, "missing_sources"),
        ({"include_target": False}, "missing_targets"),
    ],
)
def test_shared_mapping_rejects_missing_shape_and_type_failures(
    kwargs: dict[str, object], failure: str
) -> None:
    builder = _shared_gate_builder(**kwargs)
    assert builder.results[0].status == "FAIL"
    assert getattr(builder, failure)


def test_shared_mapping_has_no_separate_routing_gate_rule() -> None:
    policy = kimi_mapping_policy()
    assert _shared_gate_builder().results[0].status == "PASS"
    assert not any(
        "shared" in rule.source_family and "routing" in rule.source_family for rule in policy.rules
    )


def test_kimi_pack_identity_is_canonical_and_versioned() -> None:
    pack = KimiK3ModelPack()
    old_digest = "2939affbf3ce86f0be1b7ebc48ef61291e1268ea06d4cf38f5ce6bc60bdd35ff"
    assert pack.pack_version == 3
    assert pack.metadata.digest == (
        "6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288"
    )
    assert pack.metadata.digest != old_digest
    assert ModelPackCapability.SEMANTIC_MAPPING in pack.capabilities
    assert {
        ModelPackCapability.CHECKPOINT_SCHEMA,
        ModelPackCapability.CHECKPOINT_ONTOLOGY,
        ModelPackCapability.GGUF_ONTOLOGY,
    } < pack.capabilities
    pack.require(ModelPackCapability.SEMANTIC_MAPPING)


def test_kimi_mapping_policy_is_complete_and_non_ambiguous() -> None:
    policy = kimi_mapping_policy()
    assert len(policy.rules) == 43
    assert len(policy.exclusion_rules) == 2
    assert all(rule.layer_scope for rule in policy.rules)
    assert all(rule.source_name_pattern for rule in policy.rules)
    assert all(rule.target_name_patterns for rule in policy.rules)
    assert all(rule.source_dtype in {"BF16", "F32", "U8"} for rule in policy.rules)
    assert all(rule.allowed_target_types for rule in policy.rules)
    assert all(rule.converter_operation for rule in policy.rules)
    assert all(rule.payload_status.value == "not_checked" for rule in policy.rules)
    relations = {rule.relation for rule in policy.rules}
    assert {
        GroupRelation.ONE_TO_ONE,
        GroupRelation.MANY_TO_ONE_PACKED,
        GroupRelation.ONE_TO_MANY_SPLIT,
        GroupRelation.FUSED_TARGET,
        GroupRelation.LOGICAL_REALIZATION,
    } <= relations


def test_real_mapping_accounting_and_domain_denominators() -> None:
    raw = json.loads(MAPPING_INVENTORY.read_text())
    inventory = MappingInventory.model_validate(raw)
    assert inventory.source_accounting["states"] == {
        "directly_mapped": 1693,
        "packed_group_member": 494592,
        "fused_mapping_member": 374,
        "logical_realization_source": 393,
        "source_only_auxiliary": 168,
        "intentionally_excluded": 0,
        "unsupported": 0,
        "invalid": 0,
        "unclassified": 0,
    }
    assert inventory.target_accounting["states"] == {
        "directly_realized": 1693,
        "packed_group_target": 276,
        "fused_target": 187,
        "logical_realization_target": 417,
        "target_only_auxiliary": 0,
        "unsupported": 0,
        "invalid": 0,
        "unclassified": 0,
    }
    assert inventory.source_accounting["newly_classified_text_records"] == 282
    assert inventory.source_accounting["source_only_auxiliary_records"] == 168
    assert not inventory.source_accounting["unresolved_family_breakdown"]
    assert not inventory.target_accounting["unresolved_family_breakdown"]
    coverage = inventory.coverage
    assert coverage["routed"]["complete_groups"] == 276
    assert coverage["routed"]["packed_targets"] == 276
    assert coverage["routed"]["source_expert_members"] == 247296
    assert coverage["routed"]["source_scale_records"] == 247296
    assert coverage["shared_experts"]["physical_target_mappings"] == 276
    assert coverage["shared_experts"]["metadata_shared_expert_count"] == 2
    assert coverage["shared_experts"]["shared_routing_mixing_gate"] == ("absent_not_applicable")
    assert coverage["router"] == {"router": 92, "router_bias": 92}
    assert coverage["latent_moe"] == {"down": 92, "norm": 92, "up": 92}
    assert coverage["kda"] == {"direct": 552, "logical": 276}
    assert coverage["mla"] == {
        "direct": 120,
        "split_sources": 24,
        "split_targets": 48,
    }
    assert coverage["fused"] == {"source_members": 374, "targets": 187}
    assert coverage["g_proj"] == {"kda": 69, "mla": 24, "total": 93}
    assert all(item["count"] == 0 for item in coverage["duplicates"].values())
    assert coverage["ambiguities"]["count"] == 0
    assert coverage["failures"] == {"shape": 0, "axis": 0, "type_transition": 0}
    assert len(inventory.mapping_results) == 2549
    assert all(result.status == "PASS" for result in inventory.mapping_results)
    assert all(result.payload_status.value == "not_checked" for result in inventory.mapping_results)
    split = next(
        result for result in inventory.mapping_results if result.rule_id == "K3-MLA-KV-B-SPLIT"
    )
    assert split.target_shapes == [[96, 128, 512], [96, 512, 128]]
    validate_results_against_policy(kimi_mapping_policy(), inventory.mapping_results)


def test_policy_linkage_rejects_tampered_source_dtype() -> None:
    inventory = load_mapping_inventory(MAPPING_INVENTORY)
    results = list(inventory.mapping_results)
    results[0] = results[0].model_copy(update={"source_dtypes": ["F32"]})
    with pytest.raises(ValueError, match="differs from canonical policy"):
        validate_results_against_policy(kimi_mapping_policy(), results)


def test_inventory_reconstructs_claims_from_emitted_results() -> None:
    raw = json.loads(MAPPING_INVENTORY.read_text())
    raw["mapping_results"].pop()
    with pytest.raises(ValidationError, match="not backed by mapping results"):
        MappingInventory.model_validate(raw)
    raw = json.loads(MAPPING_INVENTORY.read_text())
    raw["mapping_results"].append(raw["mapping_results"][0])
    with pytest.raises(ValidationError, match="duplicate result identity"):
        MappingInventory.model_validate(raw)


def test_mapping_report_carries_all_canonical_linkage() -> None:
    envelope = load_mapping_report(MAPPING_REPORT)
    report = envelope.report
    assert report.source["inventory_sha256"] == (
        "15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469"
    )
    assert report.target["split_inventory_sha256"]
    assert report.target["ontology_inventory_sha256"]
    assert report.model_pack["pack_version"] == 3
    assert "semantic_mapping" in report.model_pack["capabilities"]
    assert report.mapping_policy_digest == kimi_mapping_policy().digest
    assert report.converter_evidence_revision
    assert report.artifact_specific_provenance.value == "unavailable"
    assert report.payload_status.value == "not_checked"


def test_mapping_markdown_has_compact_family_and_type_summaries() -> None:
    markdown = MAPPING_MARKDOWN.read_text()
    assert "## Family coverage" in markdown
    assert "KDA direct / logical transform | 552 / 276" in markdown
    assert "MLA direct / split sources / split targets | 120 / 24 / 48" in markdown
    assert "## Type transitions and validation" in markdown
    assert "| `F32` | 1181 |" in markdown
    assert "Duplicate target physical assignments | 0" in markdown
    assert "Shared partition/order is NOT_CHECKED" in markdown


def test_mapping_inventory_rejects_incomplete_or_duplicate_accounting() -> None:
    raw = json.loads(MAPPING_INVENTORY.read_text())
    raw["source_accounting"]["states"]["unclassified"] = 1
    with pytest.raises(ValidationError, match="source accounting states"):
        MappingInventory.model_validate(raw)
    raw = json.loads(MAPPING_INVENTORY.read_text())
    raw["coverage"]["duplicates"]["duplicate_target_physical"]["count"] = 1
    with pytest.raises(ValidationError, match="duplicate assignments"):
        MappingInventory.model_validate(raw)
