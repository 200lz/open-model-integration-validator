"""Exact structural comparison for canonical GGUF inventories."""

from __future__ import annotations

import fnmatch
import json
from collections import defaultdict
from typing import Any

from omiv.gguf.models import (
    GGUFComparisonFinding,
    GGUFComparisonPolicy,
    GGUFComparisonReport,
    GGUFComparisonSeverity,
    GGUFComparisonStatus,
    GGUFInventory,
    GGUFMetadataEntry,
)


def _finding(
    rule_id: str,
    status: GGUFComparisonStatus,
    message: str,
    evidence: dict[str, Any],
) -> GGUFComparisonFinding:
    severity = {
        GGUFComparisonStatus.PASS: GGUFComparisonSeverity.INFO,
        GGUFComparisonStatus.WARN: GGUFComparisonSeverity.WARNING,
        GGUFComparisonStatus.FAIL: GGUFComparisonSeverity.ERROR,
    }[status]
    return GGUFComparisonFinding(
        rule_id=rule_id,
        severity=severity,
        status=status,
        message=message,
        evidence=evidence,
    )


def _architecture(
    source: GGUFInventory, target: GGUFInventory, policy: GGUFComparisonPolicy
) -> GGUFComparisonFinding:
    matches = source.identity.architecture == target.identity.architecture
    passed = matches or not policy.require_same_architecture
    return _finding(
        "GGUF-DIFF-001",
        GGUFComparisonStatus.PASS if passed else GGUFComparisonStatus.FAIL,
        "Architecture identity is preserved"
        if passed
        else "Architecture identity differs",
        {
            "required": policy.require_same_architecture,
            "source_architecture": source.identity.architecture,
            "target_architecture": target.identity.architecture,
        },
    )


def _tensor_names(
    source: GGUFInventory, target: GGUFInventory, policy: GGUFComparisonPolicy
) -> GGUFComparisonFinding:
    source_names = {tensor.name for tensor in source.tensors}
    target_names = {tensor.name for tensor in target.tensors}
    missing = sorted(source_names - target_names)
    unexpected = sorted(target_names - source_names)
    failed = policy.require_same_tensor_names and bool(missing or unexpected)
    cap = policy.evidence_example_cap
    return _finding(
        "GGUF-DIFF-002",
        GGUFComparisonStatus.FAIL if failed else GGUFComparisonStatus.PASS,
        "Tensor-name coverage is identical"
        if not failed
        else "Tensor-name coverage differs",
        {
            "required": policy.require_same_tensor_names,
            "source_tensor_count": len(source_names),
            "target_tensor_count": len(target_names),
            "missing_count": len(missing),
            "missing_examples": missing[:cap],
            "unexpected_count": len(unexpected),
            "unexpected_examples": unexpected[:cap],
            "example_cap": cap,
        },
    )


def _tensor_shapes(
    source: GGUFInventory, target: GGUFInventory, policy: GGUFComparisonPolicy
) -> GGUFComparisonFinding:
    source_shapes = {tensor.name: tuple(tensor.shape) for tensor in source.tensors}
    target_shapes = {tensor.name: tuple(tensor.shape) for tensor in target.tensors}
    grouped: dict[tuple[tuple[int, ...], tuple[int, ...]], list[str]] = defaultdict(
        list
    )
    for name in sorted(source_shapes.keys() & target_shapes.keys()):
        if source_shapes[name] != target_shapes[name]:
            grouped[(source_shapes[name], target_shapes[name])].append(name)
    cap = policy.evidence_example_cap
    changes = [
        {
            "source_shape": list(source_shape),
            "target_shape": list(target_shape),
            "tensor_count": len(names),
            "tensor_examples": names[:cap],
        }
        for (source_shape, target_shape), names in sorted(grouped.items())
    ]
    failed = policy.require_same_tensor_shapes and bool(changes)
    return _finding(
        "GGUF-DIFF-003",
        GGUFComparisonStatus.FAIL if failed else GGUFComparisonStatus.PASS,
        "Tensor shapes are preserved" if not failed else "Tensor shapes differ",
        {
            "required": policy.require_same_tensor_shapes,
            "shape_change_group_count": len(changes),
            "shape_change_groups": changes,
            "shape_order": "gguf_on_disk_reader_tensor_shape",
        },
    )


def _type_transitions(
    source: GGUFInventory, target: GGUFInventory, policy: GGUFComparisonPolicy
) -> GGUFComparisonFinding:
    source_types = {tensor.name: tensor.ggml_type for tensor in source.tensors}
    target_types = {tensor.name: tensor.ggml_type for tensor in target.tensors}
    accepted: dict[tuple[str, str, tuple[str, ...]], list[str]] = defaultdict(list)
    rejected: dict[tuple[str, str], list[str]] = defaultdict(list)
    for name in sorted(source_types.keys() & target_types.keys()):
        source_type, target_type = source_types[name], target_types[name]
        matching = sorted(
            {
                rule.selector
                for rule in policy.type_transition_rules
                if rule.source_type == source_type
                and rule.target_type == target_type
                and fnmatch.fnmatchcase(name, rule.selector)
            }
        )
        if matching:
            accepted[(source_type, target_type, tuple(matching))].append(name)
        else:
            rejected[(source_type, target_type)].append(name)
    cap = policy.evidence_example_cap
    accepted_groups = [
        {
            "source_type": source_type,
            "target_type": target_type,
            "matched_selectors": list(selectors),
            "tensor_count": len(names),
            "tensor_examples": names[:cap],
        }
        for (source_type, target_type, selectors), names in sorted(accepted.items())
    ]
    rejected_groups = [
        {
            "source_type": source_type,
            "target_type": target_type,
            "tensor_count": len(names),
            "tensor_examples": names[:cap],
        }
        for (source_type, target_type), names in sorted(rejected.items())
    ]
    return _finding(
        "GGUF-DIFF-004",
        (
            GGUFComparisonStatus.FAIL
            if rejected_groups
            else GGUFComparisonStatus.PASS
        ),
        "All GGML type transitions satisfy policy"
        if not rejected_groups
        else "One or more GGML type transitions violate policy",
        {
            "accepted_transition_groups": accepted_groups,
            "rejected_transition_groups": rejected_groups,
            "checked_tensor_count": sum(map(len, accepted.values()))
            + sum(map(len, rejected.values())),
            "example_cap": cap,
        },
    )


def _metadata_value(entry: GGUFMetadataEntry | None) -> Any:
    return None if entry is None else entry.model_dump(mode="json")


def _metadata(
    source: GGUFInventory, target: GGUFInventory, policy: GGUFComparisonPolicy
) -> GGUFComparisonFinding:
    source_metadata = {entry.key: entry for entry in source.metadata}
    target_metadata = {entry.key: entry for entry in target.metadata}
    rules = {rule.key: rule.action for rule in policy.metadata_rules}
    allowed: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    ignored_count = 0

    for key in sorted(source_metadata.keys() | target_metadata.keys()):
        if key == "general.architecture":
            continue
        source_entry = source_metadata.get(key)
        target_entry = target_metadata.get(key)
        if source_entry == target_entry:
            continue
        difference = {
            "key": key,
            "source": _metadata_value(source_entry),
            "target": _metadata_value(target_entry),
        }
        action = rules.get(key)
        if action == "ignore":
            ignored_count += 1
        elif action == "allow":
            allowed.append(difference)
        elif action == "require_equal":
            failures.append(difference)
        elif action == "warn" or policy.unknown_metadata_drift == "warn":
            warnings.append(difference)
        elif policy.unknown_metadata_drift == "fail":
            failures.append(difference)
        else:
            ignored_count += 1

    if failures:
        status = GGUFComparisonStatus.FAIL
        message = "Required metadata equality failed"
    elif warnings:
        status = GGUFComparisonStatus.WARN
        message = "Metadata drift requires review"
    else:
        status = GGUFComparisonStatus.PASS
        message = "Metadata drift satisfies policy"
    return _finding(
        "GGUF-DIFF-005",
        status,
        message,
        {
            "allowed_differences": allowed,
            "warning_differences": warnings,
            "failed_differences": failures,
            "ignored_difference_count": ignored_count,
            "unknown_metadata_drift": policy.unknown_metadata_drift,
        },
    )


def compare_gguf_inventories(
    source: GGUFInventory,
    target: GGUFInventory,
    policy: GGUFComparisonPolicy,
) -> GGUFComparisonReport:
    return GGUFComparisonReport(
        findings=[
            _architecture(source, target, policy),
            _tensor_names(source, target, policy),
            _tensor_shapes(source, target, policy),
            _type_transitions(source, target, policy),
            _metadata(source, target, policy),
        ]
    )


def format_gguf_report(report: GGUFComparisonReport) -> str:
    lines: list[str] = []
    for finding in report.findings:
        lines.append(
            f"{finding.status.value.upper()} {finding.rule_id} {finding.message}"
        )
        if finding.status != GGUFComparisonStatus.PASS:
            lines.append(
                "  evidence: "
                + json.dumps(finding.evidence, sort_keys=True, separators=(",", ":"))
            )
    return "\n".join(lines)
