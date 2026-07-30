"""Generic, evidence-gated logical target realization validation."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from omiv.gguf.models import GGUFInventory
from omiv.hf.models import HFInventory
from omiv.mapping.models import (
    BackendFallbackRealization,
    FormatAliasRealization,
    MappingFinding,
    MappingManifest,
    MappingSeverity,
    MappingStatus,
    MaterializedRealization,
    PayloadRelationStatus,
    RealizationEvidence,
    RealizationKind,
    RealizationSelection,
    SemanticTensorDescriptor,
    ShapeRelation,
    SourceKind,
    SynthesizedRealization,
)
from omiv.model_packs.base import ModelPack
from omiv.provenance.models import (
    ConversionProvenance,
    ProvenanceStatus,
    ProvenanceValidationReport,
)


@dataclass(frozen=True)
class RealizationValidation:
    target_entities: list[SemanticTensorDescriptor]
    selections: list[RealizationSelection]
    findings: list[MappingFinding]


def _finding(rule_id: str, failed: bool, message: str, evidence: dict[str, Any]) -> MappingFinding:
    return MappingFinding(
        rule_id=rule_id,
        severity=MappingSeverity.ERROR if failed else MappingSeverity.INFO,
        status=MappingStatus.FAIL if failed else MappingStatus.PASS,
        message=message,
        evidence=evidence,
    )


def _shape_matches(
    source: SemanticTensorDescriptor,
    target: SemanticTensorDescriptor,
    relation: ShapeRelation,
) -> bool:
    expected = source.shape if relation == ShapeRelation.IDENTICAL else list(reversed(source.shape))
    return expected == target.shape


def _tensor_matches(
    entities: list[SemanticTensorDescriptor],
    name: str,
    identity: str,
) -> list[SemanticTensorDescriptor]:
    return [
        entity
        for entity in entities
        if entity.exact_name == name and entity.canonical_identity == identity
    ]


def _metadata_matches(target: GGUFInventory, key: str, value: object) -> bool:
    return sum(item.key == key and item.value == value for item in target.metadata) == 1


def _trusted_evidence(
    pack: ModelPack, evidence_id: str
) -> RealizationEvidence | None:
    records = {
        item.evidence_id: item
        for item in sorted(pack.provide_realization_evidence(), key=lambda item: item.evidence_id)
    }
    return records.get(evidence_id)


def _provenance_matches(
    provenance: ConversionProvenance | None,
    validation: ProvenanceValidationReport | None,
    *,
    repository: str,
    revision: str,
    tool_name: str | None = None,
) -> bool:
    return bool(
        provenance is not None
        and validation is not None
        and validation.exact_lineage_status == ProvenanceStatus.PASS
        and provenance.process.result.success
        and provenance.process.tool.repository == repository
        and provenance.process.tool.revision == revision
        and (tool_name is None or provenance.process.tool.name == tool_name)
    )


def _virtual_target(
    source: SemanticTensorDescriptor,
    backing: SemanticTensorDescriptor,
    *,
    exact_name: str,
) -> SemanticTensorDescriptor:
    return SemanticTensorDescriptor(
        exact_name=exact_name,
        canonical_identity=source.canonical_identity,
        classification="classified",
        scope=source.scope,
        layer_id=source.layer_id,
        module=source.module,
        component=source.component,
        parameter=source.parameter,
        source_kind=SourceKind.PHYSICAL,
        materialized=False,
        shape=backing.shape,
        shape_order=backing.shape_order,
        data_type=backing.data_type,
        physical_source_identity=backing.canonical_identity,
    )


def validate_realizations(
    source: HFInventory,
    target: GGUFInventory,
    source_entities: list[SemanticTensorDescriptor],
    target_entities: list[SemanticTensorDescriptor],
    manifest: MappingManifest,
    pack: ModelPack,
    provenance_validation: ProvenanceValidationReport | None,
    conversion_provenance: ConversionProvenance | None,
) -> RealizationValidation:
    del source  # Logical tie semantics remain MAP-008's responsibility.
    augmented = list(target_entities)
    selections: list[RealizationSelection] = []
    category_failures: dict[str, list[str]] = {
        f"REALIZE-{number:03d}": [] for number in range(1, 8)
    }
    rules = [
        rule for rule in manifest.rules if rule.target.realization is not None
    ]
    for rule in sorted(rules, key=lambda item: item.rule_id):
        realization = rule.target.realization
        assert realization is not None
        logical_sources = [
            entity
            for entity in source_entities
            if entity.source_kind == SourceKind.LOGICAL
            and entity.canonical_identity == rule.source.canonical_identity
        ]
        if len(logical_sources) != 1:
            category_failures["REALIZE-001"].append(
                f"{rule.rule_id}: logical source does not exist exactly once"
            )
            logical_source = None
        else:
            logical_source = logical_sources[0]
        matched: list[
            tuple[
                MaterializedRealization
                | FormatAliasRealization
                | BackendFallbackRealization
                | SynthesizedRealization,
                SemanticTensorDescriptor | None,
                RealizationEvidence | None,
            ]
        ] = []
        alternative_failures: dict[str, list[tuple[str, str]]] = {}
        for alternative in sorted(
            realization.alternatives, key=lambda item: item.realization_id
        ):
            failures: list[tuple[str, str]] = []
            selected_target: SemanticTensorDescriptor | None = None
            evidence_record: RealizationEvidence | None = None
            if isinstance(alternative, MaterializedRealization):
                matches = _tensor_matches(
                    target_entities,
                    alternative.tensor.tensor_name,
                    alternative.tensor.canonical_identity,
                )
                if len(matches) != 1:
                    failures.append(("REALIZE-003", "materialized tensor must exist exactly once"))
                else:
                    selected_target = matches[0]
            elif isinstance(alternative, FormatAliasRealization):
                aliases = _tensor_matches(
                    target_entities,
                    alternative.alias_tensor.tensor_name,
                    alternative.alias_tensor.canonical_identity,
                )
                backings = _tensor_matches(
                    target_entities,
                    alternative.backing_tensor.tensor_name,
                    alternative.backing_tensor.canonical_identity,
                )
                if len(aliases) != 1:
                    failures.append(("REALIZE-003", "format alias tensor must exist exactly once"))
                if len(backings) != 1:
                    failures.append(("REALIZE-003", "format alias backing must exist exactly once"))
                contract = alternative.format_contract
                if (
                    contract.target_format != manifest.target_format
                    or not _metadata_matches(
                        target, contract.metadata_key, contract.metadata_value
                    )
                ):
                    failures.append(
                        ("REALIZE-004", "explicit target-format alias contract is not established")
                    )
                if aliases:
                    selected_target = aliases[0]
            elif isinstance(alternative, BackendFallbackRealization):
                omitted = [
                    entity
                    for entity in target_entities
                    if entity.exact_name == alternative.omitted_tensor.tensor_name
                ]
                backings = _tensor_matches(
                    target_entities,
                    alternative.fallback_tensor.tensor_name,
                    alternative.fallback_tensor.canonical_identity,
                )
                if omitted:
                    failures.append(("REALIZE-002", "logical physical tensor is present"))
                if len(backings) != 1:
                    failures.append(("REALIZE-003", "fallback tensor must exist exactly once"))
                policy = alternative.backend_policy
                evidence_record = _trusted_evidence(pack, policy.evidence_id)
                if evidence_record is None:
                    failures.append(("REALIZE-004", "trusted evidence ID is unsupported"))
                elif any(
                    (
                        evidence_record.backend != policy.backend,
                        evidence_record.repository != policy.repository,
                        evidence_record.revision != policy.revision,
                        evidence_record.architecture != policy.architecture,
                        evidence_record.policy_symbol != policy.policy_symbol,
                        evidence_record.logical_identity != rule.target.canonical_identity,
                        evidence_record.fallback_identity
                        != alternative.fallback_tensor.canonical_identity,
                    )
                ):
                    failures.append(
                        ("REALIZE-004", "backend policy does not match trusted evidence")
                    )
                if (
                    policy.architecture != target.identity.architecture
                    or policy.architecture != manifest.model_family
                ):
                    failures.append(("REALIZE-005", "backend architecture scope does not match"))
                if not _provenance_matches(
                    conversion_provenance,
                    provenance_validation,
                    repository=policy.repository,
                    revision=policy.revision,
                ):
                    failures.append(
                        ("REALIZE-006", "validated pinned conversion provenance is required")
                    )
                if logical_source is not None and backings:
                    selected_target = _virtual_target(
                        logical_source,
                        backings[0],
                        exact_name=alternative.omitted_tensor.tensor_name,
                    )
            elif isinstance(alternative, SynthesizedRealization):
                matches = _tensor_matches(
                    target_entities,
                    alternative.tensor.tensor_name,
                    alternative.tensor.canonical_identity,
                )
                if len(matches) != 1:
                    failures.append(("REALIZE-003", "synthesized tensor must exist exactly once"))
                converter_policy = alternative.converter_policy
                if not _provenance_matches(
                    conversion_provenance,
                    provenance_validation,
                    repository=converter_policy.repository,
                    revision=converter_policy.revision,
                    tool_name=converter_policy.converter,
                ):
                    failures.append(
                        ("REALIZE-006", "pinned synthesizing converter provenance is required")
                    )
                if matches:
                    selected_target = matches[0]
            if (
                selected_target is not None
                and logical_source is not None
                and (
                    not _shape_matches(logical_source, selected_target, rule.shape_relation)
                    or logical_source.parameter != rule.parameter
                    or selected_target.parameter != rule.parameter
                )
            ):
                failures.append(("REALIZE-003", "shape or parameter semantics do not match"))
            alternative_failures[alternative.realization_id] = failures
            if not failures:
                matched.append((alternative, selected_target, evidence_record))

        if len(matched) != 1:
            category_failures["REALIZE-002"].append(
                f"{rule.rule_id}: expected one satisfied alternative, observed {len(matched)}"
            )
            chosen = None
        else:
            chosen = matched[0]
        for alternative_id, failures in sorted(alternative_failures.items()):
            for category, detail in failures:
                if chosen is None or alternative_id == chosen[0].realization_id:
                    category_failures[category].append(
                        f"{rule.rule_id}/{alternative_id}: {detail}"
                    )
        relation = rule.target.payload_relation
        if relation is None or relation.status != PayloadRelationStatus.NOT_CHECKED:
            category_failures["REALIZE-007"].append(
                f"{rule.rule_id}: payload relation must remain not_checked"
            )
        if chosen is None:
            selections.append(
                RealizationSelection(
                    rule_id=rule.rule_id,
                    logical_identity=rule.target.canonical_identity,
                    selected_realization_id=None,
                    realization_kind=None,
                    payload_relation_status=PayloadRelationStatus.NOT_CHECKED,
                    matched_realization_ids=sorted(item[0].realization_id for item in matched),
                    failures=[
                        f"{key}: {detail}"
                        for key, values in sorted(alternative_failures.items())
                        for _, detail in values
                    ],
                )
            )
            continue
        alternative, selected_target, evidence_record = chosen
        assert selected_target is not None
        backing_name: str | None
        policy_backend: str | None
        policy_repository: str | None
        policy_revision: str | None
        evidence_id: str | None
        if isinstance(alternative, BackendFallbackRealization):
            physical_name = alternative.omitted_tensor.tensor_name
            backing_name = alternative.fallback_tensor.tensor_name
            policy_backend = alternative.backend_policy.backend
            policy_repository = alternative.backend_policy.repository
            policy_revision = alternative.backend_policy.revision
            evidence_id = alternative.backend_policy.evidence_id
            architecture = alternative.backend_policy.architecture
        elif isinstance(alternative, FormatAliasRealization):
            physical_name = alternative.alias_tensor.tensor_name
            backing_name = alternative.backing_tensor.tensor_name
            policy_backend = policy_repository = policy_revision = evidence_id = None
            architecture = None
        elif isinstance(alternative, SynthesizedRealization):
            physical_name = alternative.tensor.tensor_name
            backing_name = None
            policy_backend = alternative.converter_policy.converter
            policy_repository = alternative.converter_policy.repository
            policy_revision = alternative.converter_policy.revision
            evidence_id = alternative.converter_policy.synthesis_rule_id
            architecture = target.identity.architecture
        else:
            physical_name = alternative.tensor.tensor_name
            backing_name = None
            policy_backend = policy_repository = policy_revision = evidence_id = None
            architecture = None
        selections.append(
            RealizationSelection(
                rule_id=rule.rule_id,
                logical_identity=rule.target.canonical_identity,
                selected_realization_id=alternative.realization_id,
                realization_kind=RealizationKind(alternative.kind),
                required_evidence_id=evidence_id,
                evidence_digest=None if evidence_record is None else evidence_record.digest,
                physical_tensor=physical_name,
                physical_tensor_present=any(
                    item.exact_name == physical_name for item in target_entities
                ),
                backing_tensor=backing_name,
                backing_tensor_present=(
                    None
                    if backing_name is None
                    else any(item.exact_name == backing_name for item in target_entities)
                ),
                backend=policy_backend,
                repository=policy_repository,
                revision=policy_revision,
                architecture=architecture,
                payload_relation_status=PayloadRelationStatus.NOT_CHECKED,
                matched_realization_ids=[alternative.realization_id],
            )
        )
        if selected_target not in augmented:
            augmented.append(selected_target)

    counts = Counter(
        selection.realization_kind.value
        for selection in selections
        if selection.realization_kind is not None
    )
    messages = {
        "REALIZE-001": "Realization declarations are valid",
        "REALIZE-002": "Exactly one realization alternative is satisfied",
        "REALIZE-003": "Required physical backing tensors and semantics are valid",
        "REALIZE-004": "Realization evidence is sufficient",
        "REALIZE-005": "Architecture and backend scopes match",
        "REALIZE-006": "Realizations are consistent with conversion provenance",
        "REALIZE-007": "Payload relation status remains explicit and not checked",
    }
    findings = [
        _finding(
            rule_id,
            bool(category_failures[rule_id]),
            messages[rule_id],
            {
                "realization_rule_count": len(rules),
                "selected_kind_counts": dict(sorted(counts.items())),
                "failure_count": len(category_failures[rule_id]),
                "failure_examples": category_failures[rule_id][:10],
            },
        )
        for rule_id in sorted(category_failures)
    ]
    return RealizationValidation(augmented, selections, findings)
