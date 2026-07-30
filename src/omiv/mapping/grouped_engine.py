"""Reusable deterministic grouped mapping and assignment primitives."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from omiv.mapping.grouped_models import MappingPolicy, MappingResult, PayloadStatus

T = TypeVar("T")


def deterministic_groups(
    records: Iterable[T], key: Callable[[T], str], order_key: Callable[[T], Any]
) -> dict[str, list[T]]:
    out: dict[str, list[T]] = defaultdict(list)
    for record in records:
        out[key(record)].append(record)
    return {k: sorted(v, key=order_key) for k, v in sorted(out.items())}


def validate_many_to_one(
    groups: Mapping[str, list[T]], targets: Mapping[str, T], expected_members: int
) -> list[str]:
    errors: list[str] = []
    for key, members in sorted(groups.items()):
        if len(members) != expected_members:
            errors.append(f"{key}: cardinality {len(members)} != {expected_members}")
        if key not in targets:
            errors.append(f"{key}: missing target")
    return errors


def validate_results_against_policy(
    policy: MappingPolicy, results: Iterable[MappingResult]
) -> None:
    """Require every emitted result to be an exact realization of one policy rule."""

    rules = {rule.rule_id: rule for rule in policy.rules}
    observed: set[str] = set()
    for result in results:
        rule = rules.get(result.rule_id)
        if rule is None:
            raise ValueError(f"mapping result uses unknown policy rule {result.rule_id!r}")
        observed.add(result.rule_id)
        expected = {
            "relation": rule.relation,
            "source_member_count": rule.source_cardinality,
            "target_count": rule.target_cardinality,
            "shape_relation": rule.shape_relation,
            "axis_relation": rule.axis_relation,
            "source_dtypes": [rule.source_dtype],
            "allowed_target_types": sorted(rule.allowed_target_types),
            "converter_operation": rule.converter_operation,
            "evidence_level": rule.evidence_level,
            "payload_status": PayloadStatus.NOT_CHECKED,
        }
        actual = {
            "relation": result.relation,
            "source_member_count": result.source_member_count,
            "target_count": result.target_count,
            "shape_relation": result.shape_relation,
            "axis_relation": result.axis_relation,
            "source_dtypes": result.source_dtypes,
            "allowed_target_types": sorted(result.allowed_target_types),
            "converter_operation": result.converter_operation,
            "evidence_level": result.evidence_level,
            "payload_status": result.payload_status,
        }
        if actual != expected:
            raise ValueError(f"mapping result {result.rule_id!r} differs from canonical policy")
    missing = sorted(set(rules) - observed)
    if missing:
        raise ValueError(f"mapping policy rules have no emitted results: {missing[:8]}")


@dataclass
class AssignmentAudit:
    """Track physical/logical assignments without retaining payload data."""

    example_limit: int = 8
    source_physical: Counter[str] = field(default_factory=Counter)
    source_logical: Counter[str] = field(default_factory=Counter)
    target_physical: Counter[str] = field(default_factory=Counter)
    result_identities: Counter[str] = field(default_factory=Counter)
    source_groups: Counter[str] = field(default_factory=Counter)

    def claim_source(self, name: str, *, logical_identity: str | None = None) -> None:
        self.source_physical[name] += 1
        if logical_identity is not None:
            self.source_logical[logical_identity] += 1

    def claim_target(self, name: str) -> None:
        self.target_physical[name] += 1

    def claim_result(self, identity: str) -> None:
        self.result_identities[identity] += 1

    def claim_group(self, identity: str) -> None:
        self.source_groups[identity] += 1

    @staticmethod
    def _duplicates(values: Counter[str], limit: int) -> tuple[int, list[str]]:
        duplicate_names = sorted(name for name, count in values.items() if count > 1)
        return len(duplicate_names), duplicate_names[:limit]

    def summary(self) -> dict[str, object]:
        checks = {
            "duplicate_source_physical": self._duplicates(self.source_physical, self.example_limit),
            "duplicate_source_logical": self._duplicates(self.source_logical, self.example_limit),
            "duplicate_target_physical": self._duplicates(self.target_physical, self.example_limit),
            "duplicate_mapping_result": self._duplicates(
                self.result_identities, self.example_limit
            ),
            "duplicate_source_group": self._duplicates(self.source_groups, self.example_limit),
        }
        return {key: {"count": value[0], "examples": value[1]} for key, value in checks.items()}

    @property
    def valid(self) -> bool:
        return all(item["count"] == 0 for item in self.summary().values() if isinstance(item, dict))
