"""Structured Phase 1 validators for the measured Kimi K3 checkpoint schema."""

from __future__ import annotations

from collections import defaultdict

from omiv.models import (
    AttentionKind,
    DescriptorSummary,
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


def validate_moe_002(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    expected_moe = set(schema.expected_moe_layer_ids)
    required = set(schema.required_shared_expert_components)
    missing: dict[str, list[str]] = {}
    unexpected: dict[str, list[str]] = {}
    non_moe_evidence: dict[str, list[str]] = {}

    for layer_id in sorted(expected_moe):
        layer = by_id.get(layer_id)
        observed = set(layer.ffn.shared_expert_components) if layer else set()
        if required - observed:
            missing[str(layer_id)] = sorted(required - observed)
        if observed - required:
            unexpected[str(layer_id)] = sorted(observed - required)
    for layer in inventory.layers:
        observed = set(layer.ffn.shared_expert_components)
        if layer.id not in expected_moe and observed:
            non_moe_evidence[str(layer.id)] = sorted(observed)

    passed = not missing and not unexpected and not non_moe_evidence
    return _finding(
        "K3-MOE-002",
        passed,
        "Shared expert projection coverage is complete",
        "Shared expert coverage is missing, unexpected, or present on non-MoE layers",
        {
            "required_components": schema.required_shared_expert_components,
            "missing_components_by_layer": missing,
            "unexpected_components_by_layer": unexpected,
            "non_moe_layer_evidence": non_moe_evidence,
        },
    )


def _descriptor_is_unanimous(summary: DescriptorSummary | None) -> bool:
    return (
        summary is not None
        and summary.observation_count > 0
        and len(summary.descriptor_groups) == 1
    )


def _descriptor_evidence(summary: DescriptorSummary | None) -> object:
    if summary is None:
        return {"observation_count": 0, "descriptor_groups": []}
    return summary.model_dump(mode="json")


def validate_attn_002(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    expected = set(schema.expected_layer_ids)
    missing: list[int] = []
    duplicate: dict[str, int] = {}
    classifications: dict[str, str] = {}
    for layer_id in sorted(expected):
        layer = by_id.get(layer_id)
        count = layer.attention.g_proj_observation_count if layer else 0
        if count == 0:
            missing.append(layer_id)
        elif count != 1:
            duplicate[str(layer_id)] = count
        if layer:
            classifications[str(layer_id)] = layer.attention.kind.value
    unexpected_layers = sorted(
        layer.id
        for layer in inventory.layers
        if layer.id not in expected and layer.attention.g_proj_observation_count
    )
    descriptors = inventory.semantic_descriptors.g_proj
    unanimous = _descriptor_is_unanimous(descriptors)
    passed = (
        schema.require_g_proj
        and not missing
        and not duplicate
        and not unexpected_layers
        and unanimous
    )
    return _finding(
        "K3-ATTN-002",
        passed,
        "Contextual g_proj coverage and descriptors are complete",
        "g_proj coverage, uniqueness, or descriptor unanimity failed",
        {
            "missing_layer_ids": missing,
            "duplicate_observation_counts": duplicate,
            "unexpected_layer_ids": unexpected_layers,
            "attention_classifications": classifications,
            "descriptor_unanimous": unanimous,
            "descriptors": _descriptor_evidence(descriptors),
        },
    )


def validate_attnres_001(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    by_id = {layer.id: layer for layer in inventory.layers}
    expected_layers = set(schema.expected_layer_ids)
    required = set(schema.required_attention_residual_components)
    missing: dict[str, list[str]] = {}
    unexpected: dict[str, list[str]] = {}
    unexpected_layers: dict[str, list[str]] = {}
    for layer_id in sorted(expected_layers):
        layer = by_id.get(layer_id)
        observed = set(layer.attention_residual_components) if layer else set()
        if required - observed:
            missing[str(layer_id)] = sorted(required - observed)
        if observed - required:
            unexpected[str(layer_id)] = sorted(observed - required)
    for layer in inventory.layers:
        if layer.id not in expected_layers and layer.attention_residual_components:
            unexpected_layers[str(layer.id)] = layer.attention_residual_components

    descriptor_results: dict[str, object] = {}
    descriptors_ok = True
    for component in schema.required_attention_residual_components:
        summary = inventory.semantic_descriptors.attention_residual_components.get(
            component
        )
        unanimous = _descriptor_is_unanimous(summary)
        descriptors_ok = descriptors_ok and unanimous
        descriptor_results[component] = {
            "unanimous": unanimous,
            "summary": _descriptor_evidence(summary),
        }
    passed = (
        not missing
        and not unexpected
        and not unexpected_layers
        and descriptors_ok
    )
    return _finding(
        "K3-ATTNRES-001",
        passed,
        "Per-layer Attention Residual coverage and descriptors are complete",
        "Per-layer Attention Residual coverage or descriptor unanimity failed",
        {
            "missing_components_by_layer": missing,
            "unexpected_components_by_layer": unexpected,
            "unexpected_layer_evidence": unexpected_layers,
            "descriptor_results": descriptor_results,
        },
    )


def validate_attnres_002(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    required = set(schema.required_model_attention_residual_components)
    observed = set(inventory.model_attention_residual_components)
    missing = sorted(required - observed)
    unexpected = sorted(observed - required)
    descriptor_results: dict[str, object] = {}
    descriptors_ok = True
    for component in schema.required_model_attention_residual_components:
        summary = inventory.semantic_descriptors.model_attention_residual_components.get(
            component
        )
        unanimous = _descriptor_is_unanimous(summary)
        descriptors_ok = descriptors_ok and unanimous
        descriptor_results[component] = {
            "unanimous": unanimous,
            "summary": _descriptor_evidence(summary),
        }
    passed = not missing and not unexpected and descriptors_ok
    return _finding(
        "K3-ATTNRES-002",
        passed,
        "Model-level Attention Residual coverage is complete",
        "Model-level Attention Residual coverage or descriptors failed",
        {
            "missing_components": missing,
            "unexpected_components": unexpected,
            "descriptor_results": descriptor_results,
        },
    )


def validate_tensor_001(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    semantic = inventory.semantic_descriptors
    groups: dict[str, DescriptorSummary | None] = {
        "self_attn.g_proj": semantic.g_proj,
    }
    groups.update(
        {
            f"shared_expert.{component}": semantic.shared_expert_components.get(
                component
            )
            for component in schema.required_shared_expert_components
        }
    )
    groups.update(
        {
            f"attention_residual.{component}": (
                semantic.attention_residual_components.get(component)
            )
            for component in schema.required_attention_residual_components
        }
    )
    groups.update(
        {
            f"routed_expert.{component}": semantic.routed_expert_components.get(
                component
            )
            for component in schema.required_expert_components
        }
    )
    groups.update(
        {
            f"model_attention_residual.{component}": (
                semantic.model_attention_residual_components.get(component)
            )
            for component in schema.required_model_attention_residual_components
        }
    )
    inconsistent = {
        name: _descriptor_evidence(summary)
        for name, summary in sorted(groups.items())
        if not _descriptor_is_unanimous(summary)
    }
    summaries = {
        name: _descriptor_evidence(summary)
        for name, summary in sorted(groups.items())
    }
    return _finding(
        "K3-TENSOR-001",
        not inconsistent,
        "Supported semantic descriptor groups are unanimous",
        "One or more supported semantic descriptor groups are missing or disagree",
        {
            "policy": schema.descriptor_consistency_policy,
            "inconsistent_groups": inconsistent,
            "semantic_groups": summaries,
        },
    )


def validate_tensor_002(
    inventory: ModelInventory, schema: KimiK3Schema
) -> ValidationFinding:
    summary = inventory.tensor_classification
    evidence = summary.model_dump(mode="json")
    if summary.duplicate_exact_tensor_names:
        return ValidationFinding(
            rule_id="K3-TENSOR-002",
            severity=Severity.ERROR,
            status=FindingStatus.FAIL,
            message="Canonical inventory reports duplicate exact tensor names",
            evidence=evidence,
        )
    if summary.unclassified_records:
        return ValidationFinding(
            rule_id="K3-TENSOR-002",
            severity=Severity.WARNING,
            status=FindingStatus.WARN,
            message="Unclassified tensors are present; review the compact summary",
            evidence=evidence,
        )
    return ValidationFinding(
        rule_id="K3-TENSOR-002",
        severity=Severity.INFO,
        status=FindingStatus.PASS,
        message="All tensor records are semantically classified",
        evidence=evidence,
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
            validate_moe_002(inventory, schema),
            validate_attn_002(inventory, schema),
            validate_attnres_001(inventory, schema),
            validate_attnres_002(inventory, schema),
            validate_tensor_001(inventory, schema),
            validate_tensor_002(inventory, schema),
        ]
    )
