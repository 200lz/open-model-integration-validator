"""Deterministic one-to-one manifest resolution."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from omiv.mapping.models import (
    MappingManifest,
    MappingResolution,
    MappingRule,
    SemanticTensorDescriptor,
)


@dataclass(frozen=True)
class ResolutionDiagnostics:
    resolutions: list[MappingResolution]
    zero_source_matches: list[str]
    zero_target_matches: list[str]
    multiple_source_matches: list[str]
    multiple_target_matches: list[str]
    source_kind_mismatches: list[str]
    source_match_counts: Counter[str]
    target_name_match_counts: Counter[str]
    target_identity_match_counts: Counter[str]


def _render(pattern: str, layer_id: int | None) -> str:
    if layer_id is None:
        return pattern
    return pattern.replace("{layer}", str(layer_id))


def _selector_matches(
    entity: SemanticTensorDescriptor,
    rule: MappingRule,
    *,
    source: bool,
    layer_id: int | None,
) -> bool:
    selector = rule.source if source else rule.target
    if entity.canonical_identity != _render(selector.canonical_identity, layer_id):
        return False
    return not (
        selector.tensor_name is not None
        and entity.exact_name != _render(selector.tensor_name, layer_id)
    )


def resolve_mapping_with_diagnostics(
    source_entities: list[SemanticTensorDescriptor],
    target_entities: list[SemanticTensorDescriptor],
    manifest: MappingManifest,
) -> ResolutionDiagnostics:
    resolutions: list[MappingResolution] = []
    zero_source: list[str] = []
    zero_target: list[str] = []
    multiple_source: list[str] = []
    multiple_target: list[str] = []
    kind_mismatch: list[str] = []
    source_counts: Counter[str] = Counter()
    target_name_counts: Counter[str] = Counter()
    target_identity_counts: Counter[str] = Counter()

    for rule in sorted(manifest.rules, key=lambda item: item.rule_id):
        bindings: list[int | None]
        if rule.layer_binding is None:
            bindings = [None]
        else:
            start, end = rule.layer_binding.range
            bindings = list(range(start, end + 1))
        for layer_id in bindings:
            binding_key = rule.rule_id if layer_id is None else f"{rule.rule_id}[{layer_id}]"
            source_without_kind = [
                entity
                for entity in source_entities
                if _selector_matches(entity, rule, source=True, layer_id=layer_id)
            ]
            source_matches = [
                entity
                for entity in source_without_kind
                if entity.source_kind == rule.source_kind
            ]
            target_matches = [
                entity
                for entity in target_entities
                if _selector_matches(entity, rule, source=False, layer_id=layer_id)
            ]
            if source_without_kind and not source_matches:
                kind_mismatch.append(binding_key)
            if not source_matches:
                zero_source.append(binding_key)
            elif len(source_matches) > 1:
                multiple_source.append(binding_key)
            if not target_matches:
                zero_target.append(binding_key)
            elif len(target_matches) > 1:
                multiple_target.append(binding_key)
            if len(source_matches) != 1 or len(target_matches) != 1:
                continue
            source_entity, target_entity = source_matches[0], target_matches[0]
            source_key = (
                f"{source_entity.source_kind.value}:"
                f"{source_entity.canonical_identity or source_entity.exact_name}"
            )
            source_counts[source_key] += 1
            target_name_counts[target_entity.exact_name] += 1
            if target_entity.canonical_identity is not None:
                target_identity_counts[target_entity.canonical_identity] += 1
            resolutions.append(
                MappingResolution(
                    rule_id=rule.rule_id,
                    layer_id=layer_id,
                    source=source_entity,
                    target=target_entity,
                    shape_relation=rule.shape_relation,
                    payload_transform=rule.payload_transform,
                    parameter=rule.parameter,
                )
            )

    resolutions.sort(
        key=lambda item: (
            item.source.canonical_identity or item.source.exact_name,
            -1 if item.layer_id is None else item.layer_id,
            item.rule_id,
            item.target.exact_name,
        )
    )
    return ResolutionDiagnostics(
        resolutions=resolutions,
        zero_source_matches=sorted(zero_source),
        zero_target_matches=sorted(zero_target),
        multiple_source_matches=sorted(multiple_source),
        multiple_target_matches=sorted(multiple_target),
        source_kind_mismatches=sorted(kind_mismatch),
        source_match_counts=source_counts,
        target_name_match_counts=target_name_counts,
        target_identity_match_counts=target_identity_counts,
    )


def resolve_mapping(
    source_entities: list[SemanticTensorDescriptor],
    target_entities: list[SemanticTensorDescriptor],
    manifest: MappingManifest,
) -> list[MappingResolution]:
    """Resolve the manifest in stable semantic order."""
    return resolve_mapping_with_diagnostics(
        source_entities, target_entities, manifest
    ).resolutions
