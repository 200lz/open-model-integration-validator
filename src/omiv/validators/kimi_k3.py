"""Structured Phase 1 validators for the measured Kimi K3 checkpoint schema."""

from __future__ import annotations

from collections import defaultdict

from omiv.models import (
    AttentionKind,
    FfnKind,
    FindingStatus,
    ModelInventory,
    Severity,
    ValidationFinding,
    ValidationReport,
)
from omiv.schema.loader import KimiK3Schema

DENSE_SIGNATURE = {"gate_proj.weight", "up_proj.weight", "down_proj.weight"}


def _finding(
    rule_id: str,
    passed: bool,
    pass_message: str,
    fail_message: str,
    evidence: dict[str, object],
) -> ValidationFinding:
    return ValidationFinding(
        rule_id=rule_id,
        severity=Severity.INFO if passed else Severity.ERROR,
        status=FindingStatus.PASS if passed else FindingStatus.FAIL,
        message=pass_message if passed else fail_message,
        evidence=evidence,  # type: ignore[arg-type]
    )


def validate_layer_001(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    expected = schema.expected_dense_layer_ids
    problems: dict[str, object] = {}
    for layer_id in expected:
        layer = by_id.get(layer_id)
        if layer is None:
            problems[str(layer_id)] = {"problem": "missing_layer"}
            continue
        observed = set(layer.ffn.dense_components)
        if layer.ffn.kind != FfnKind.DENSE or observed != DENSE_SIGNATURE:
            problems[str(layer_id)] = {
                "kind": layer.ffn.kind.value,
                "observed_components": sorted(observed),
                "missing_components": sorted(DENSE_SIGNATURE - observed),
            }
    return _finding(
        "K3-LAYER-001",
        not problems,
        "Layer 0 is dense",
        "Expected dense layer classification or signature is missing/conflicting",
        {"expected_dense_layer_ids": expected, "problems": problems},
    )


def validate_layer_002(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    observed_ids = set(inventory.observed_layer_ids)
    expected_ids = set(schema.expected_layer_ids)
    expected_moe = set(schema.expected_moe_layer_ids)
    missing_layers = sorted(expected_ids - observed_ids)
    unexpected_layers = sorted(observed_ids - expected_ids)
    wrong: dict[str, str] = {}
    for layer_id in sorted(expected_moe & observed_ids):
        kind = by_id[layer_id].ffn.kind
        if kind != FfnKind.MOE:
            wrong[str(layer_id)] = kind.value
    passed = not missing_layers and not unexpected_layers and not wrong
    return _finding(
        "K3-LAYER-002",
        passed,
        "Layers 1-92 are MoE",
        "MoE layer partition has missing, unexpected, unknown, or conflicting layers",
        {
            "expected_moe_layer_ids": sorted(expected_moe),
            "missing_layer_ids": missing_layers,
            "unexpected_layer_ids": unexpected_layers,
            "incorrect_classifications": wrong,
        },
    )


def validate_attn_001(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    required = schema.required_mla_tail_layers
    problems: dict[str, object] = {}
    for layer_id in required:
        layer = by_id.get(layer_id)
        if layer is None:
            problems[str(layer_id)] = {"problem": "missing_layer"}
        elif layer.attention.kind != AttentionKind.MLA:
            problems[str(layer_id)] = {
                "kind": layer.attention.kind.value,
                "observed_markers": layer.attention.observed_markers,
                "g_proj_present": layer.attention.g_proj_present,
            }
    mla_layers = [
        layer.id for layer in inventory.layers if layer.attention.kind == AttentionKind.MLA
    ]
    kda_layers = [
        layer.id for layer in inventory.layers if layer.attention.kind == AttentionKind.KDA
    ]
    return _finding(
        "K3-ATTN-001",
        not problems,
        "MLA tail contains consecutive layers 91 and 92",
        "Required tail layers are not independently classified as MLA",
        {
            "required_mla_tail_layers": required,
            "problems": problems,
            "measured_mla_layer_ids": mla_layers,
            "measured_kda_layer_ids": kda_layers,
        },
    )


def _set_groups(layer_sets: dict[int, frozenset[int]]) -> list[dict[str, object]]:
    groups: dict[frozenset[int], list[int]] = defaultdict(list)
    for layer_id, expert_ids in layer_sets.items():
        groups[expert_ids].append(layer_id)
    return [
        {
            "layer_ids": sorted(layer_ids),
            "expert_count": len(expert_ids),
            "expert_ids": sorted(expert_ids),
        }
        for expert_ids, layer_ids in sorted(
            groups.items(), key=lambda item: (min(item[1]), sorted(item[0]))
        )
    ]


def validate_moe_001(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    layer_sets: dict[int, frozenset[int]] = {}
    absent: list[int] = []
    incomplete: dict[str, dict[str, list[str]]] = {}
    coverage_count_mismatches: dict[str, dict[str, int]] = {}
    required_components = set(schema.required_expert_components)

    for layer_id in schema.expected_moe_layer_ids:
        layer = by_id.get(layer_id)
        if layer is None:
            absent.append(layer_id)
            continue
        expert_ids = frozenset(layer.ffn.routed_expert_ids)
        layer_sets[layer_id] = expert_ids
        coverage = layer.ffn.expert_component_coverage
        missing_required = {
            expert_id: sorted(set(missing) & required_components)
            for expert_id, missing in coverage.incomplete_experts.items()
            if set(missing) & required_components
        }
        if missing_required:
            incomplete[str(layer_id)] = missing_required
        expected_complete = len(expert_ids) - len(missing_required)
        if coverage.complete_expert_count != expected_complete:
            coverage_count_mismatches[str(layer_id)] = {
                "reported": coverage.complete_expert_count,
                "expected": expected_complete,
            }

    distinct_sets = set(layer_sets.values())
    unanimous = len(distinct_sets) == 1 and bool(layer_sets) and not absent
    reference = next(iter(distinct_sets)) if unanimous else frozenset()
    contiguous = False
    if reference:
        contiguous = reference == frozenset(range(min(reference), max(reference) + 1))

    passed = (
        unanimous
        and contiguous
        and not incomplete
        and not coverage_count_mismatches
    )
    evidence: dict[str, object] = {
        "policy": schema.expert_set_policy,
        "missing_moe_layers": absent,
        "unanimous": unanimous,
        "distinct_expert_sets": _set_groups(layer_sets),
        "reference_expert_count": len(reference) if unanimous else None,
        "reference_expert_id_min": min(reference) if reference else None,
        "reference_expert_id_max": max(reference) if reference else None,
        "reference_set_contiguous": contiguous,
        "required_expert_components": schema.required_expert_components,
        "incomplete_experts_by_layer": incomplete,
        "coverage_count_mismatches": coverage_count_mismatches,
    }
    return _finding(
        "K3-MOE-001",
        passed,
        "Routed expert sets and components are complete",
        "Routed expert sets disagree, are non-contiguous, or have incomplete components",
        evidence,
    )


def validate_inventory(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationReport:
    """Run all required Phase 1 rules without printing."""
    return ValidationReport(
        findings=[
            validate_layer_001(inventory, schema),
            validate_layer_002(inventory, schema),
            validate_attn_001(inventory, schema),
            validate_moe_001(inventory, schema),
        ]
    )
