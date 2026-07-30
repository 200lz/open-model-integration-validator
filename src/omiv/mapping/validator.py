"""MAP-001 through MAP-009 structural semantic validation."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory
from omiv.hf.models import HFInventory
from omiv.mapping.manifest import resolve_manifest_model_pack
from omiv.mapping.models import (
    MappingCoverage,
    MappingFinding,
    MappingManifest,
    MappingSeverity,
    MappingStatus,
    MappingValidationReport,
    MaterializationPolicy,
    SemanticTensorDescriptor,
    ShapeRelation,
    SourceKind,
)
from omiv.mapping.ontology import gguf_semantic_view, hf_semantic_view
from omiv.mapping.resolver import ResolutionDiagnostics, resolve_mapping_with_diagnostics
from omiv.model_packs.base import ModelPack
from omiv.provenance.models import (
    ProvenanceStatus,
    ProvenanceValidationReport,
)

EXAMPLE_CAP = 10


def _finding(
    rule_id: str,
    status: MappingStatus,
    message: str,
    evidence: dict[str, Any],
) -> MappingFinding:
    severity = {
        MappingStatus.PASS: MappingSeverity.INFO,
        MappingStatus.WARN: MappingSeverity.WARNING,
        MappingStatus.FAIL: MappingSeverity.ERROR,
    }[status]
    return MappingFinding(
        rule_id=rule_id,
        severity=severity,
        status=status,
        message=message,
        evidence=evidence,
    )


def _entity_key(entity: SemanticTensorDescriptor) -> str:
    return f"{entity.source_kind.value}:{entity.canonical_identity or entity.exact_name}"


def _ignored_source_keys(
    source_entities: list[SemanticTensorDescriptor], manifest: MappingManifest
) -> dict[str, str]:
    ignored: dict[str, str] = {}
    for entry in manifest.ignored_sources:
        for entity in source_entities:
            if entity.canonical_identity == entry.selector.canonical_identity and (
                entry.selector.tensor_name is None
                or entity.exact_name == entry.selector.tensor_name
            ):
                ignored[_entity_key(entity)] = entry.justification
    return ignored


def _coverage(
    source_entities: list[SemanticTensorDescriptor],
    target_entities: list[SemanticTensorDescriptor],
    diagnostics: ResolutionDiagnostics,
    manifest: MappingManifest,
) -> tuple[MappingFinding, MappingFinding, MappingCoverage]:
    ignored = _ignored_source_keys(source_entities, manifest)
    source_mapped = set(diagnostics.source_match_counts)
    physical = [entity for entity in source_entities if entity.source_kind == SourceKind.PHYSICAL]
    logical = [entity for entity in source_entities if entity.source_kind == SourceKind.LOGICAL]
    unmapped_physical = sorted(
        entity.canonical_identity or entity.exact_name
        for entity in physical
        if _entity_key(entity) not in source_mapped and _entity_key(entity) not in ignored
    )
    unmapped_logical = sorted(
        entity.canonical_identity or entity.exact_name
        for entity in logical
        if _entity_key(entity) not in source_mapped and _entity_key(entity) not in ignored
    )
    unclassified_source = sorted(
        entity.exact_name
        for entity in source_entities
        if entity.classification == "unclassified" and _entity_key(entity) not in ignored
    )
    source_failed = manifest.require_complete_source_coverage and bool(
        unmapped_physical
        or unmapped_logical
        or unclassified_source
        or diagnostics.zero_source_matches
    )
    map001 = _finding(
        "MAP-001",
        MappingStatus.FAIL if source_failed else MappingStatus.PASS,
        (
            "Source semantic coverage is complete"
            if not source_failed
            else "Source semantic coverage is incomplete"
        ),
        {
            "physical_mapped": len(physical) - len(unmapped_physical),
            "physical_total": len(physical),
            "logical_mapped": len(logical) - len(unmapped_logical),
            "logical_total": len(logical),
            "unmapped_physical_count": len(unmapped_physical),
            "unmapped_physical_examples": unmapped_physical[:EXAMPLE_CAP],
            "unmapped_logical_count": len(unmapped_logical),
            "unmapped_logical_examples": unmapped_logical[:EXAMPLE_CAP],
            "unclassified_source_count": len(unclassified_source),
            "unclassified_source_examples": unclassified_source[:EXAMPLE_CAP],
            "ignored_source_count": len(ignored),
            "ignored_sources": [
                {"entity": key, "justification": ignored[key]}
                for key in sorted(ignored)[:EXAMPLE_CAP]
            ],
            "zero_source_binding_count": len(diagnostics.zero_source_matches),
            "zero_source_binding_examples": diagnostics.zero_source_matches[:EXAMPLE_CAP],
            "example_cap": EXAMPLE_CAP,
        },
    )

    target_mapped = set(diagnostics.target_name_match_counts)
    unclassified_target = sorted(
        entity.exact_name for entity in target_entities if entity.classification == "unclassified"
    )
    unexpected_target = sorted(
        entity.exact_name
        for entity in target_entities
        if entity.exact_name not in target_mapped and entity.classification == "classified"
    )
    target_failed = manifest.require_complete_target_coverage and bool(
        unexpected_target or unclassified_target or diagnostics.zero_target_matches
    )
    map002 = _finding(
        "MAP-002",
        MappingStatus.FAIL if target_failed else MappingStatus.PASS,
        (
            "Target semantic coverage is complete"
            if not target_failed
            else "Target semantic coverage is incomplete"
        ),
        {
            "target_explained": len(target_entities)
            - len(unexpected_target)
            - len(unclassified_target),
            "target_total": len(target_entities),
            "unexpected_target_count": len(unexpected_target),
            "unexpected_target_examples": unexpected_target[:EXAMPLE_CAP],
            "unclassified_target_count": len(unclassified_target),
            "unclassified_target_examples": unclassified_target[:EXAMPLE_CAP],
            "zero_target_binding_count": len(diagnostics.zero_target_matches),
            "zero_target_binding_examples": diagnostics.zero_target_matches[:EXAMPLE_CAP],
            "example_cap": EXAMPLE_CAP,
        },
    )
    duplicate_sources = sum(
        count - 1 for count in diagnostics.source_match_counts.values() if count > 1
    )
    duplicate_targets = sum(
        count - 1 for count in diagnostics.target_name_match_counts.values() if count > 1
    )
    coverage = MappingCoverage(
        physical_source_mapped=len(physical) - len(unmapped_physical),
        physical_source_total=len(physical),
        logical_source_mapped=len(logical) - len(unmapped_logical),
        logical_source_total=len(logical),
        target_explained=len(target_entities) - len(unexpected_target) - len(unclassified_target),
        target_total=len(target_entities),
        duplicate_source_count=duplicate_sources,
        duplicate_target_count=duplicate_targets,
        unmapped_source_count=len(unmapped_physical) + len(unmapped_logical),
        unmapped_target_count=len(unexpected_target) + len(unclassified_target),
    )
    return map001, map002, coverage


def _source_uniqueness(diagnostics: ResolutionDiagnostics) -> MappingFinding:
    duplicates = sorted(key for key, count in diagnostics.source_match_counts.items() if count > 1)
    failed = bool(
        duplicates or diagnostics.multiple_source_matches or diagnostics.source_kind_mismatches
    )
    return _finding(
        "MAP-003",
        MappingStatus.FAIL if failed else MappingStatus.PASS,
        (
            "Every mapped source semantic entity is unique"
            if not failed
            else "Source semantic mappings are not unique or have the wrong kind"
        ),
        {
            "duplicate_source_count": len(duplicates),
            "duplicate_source_examples": duplicates[:EXAMPLE_CAP],
            "multi_match_binding_count": len(diagnostics.multiple_source_matches),
            "multi_match_binding_examples": diagnostics.multiple_source_matches[:EXAMPLE_CAP],
            "source_kind_mismatch_count": len(diagnostics.source_kind_mismatches),
            "source_kind_mismatch_examples": diagnostics.source_kind_mismatches[:EXAMPLE_CAP],
            "example_cap": EXAMPLE_CAP,
        },
    )


def _target_uniqueness(diagnostics: ResolutionDiagnostics) -> MappingFinding:
    duplicate_names = sorted(
        key for key, count in diagnostics.target_name_match_counts.items() if count > 1
    )
    duplicate_identities = sorted(
        key for key, count in diagnostics.target_identity_match_counts.items() if count > 1
    )
    failed = bool(duplicate_names or duplicate_identities or diagnostics.multiple_target_matches)
    return _finding(
        "MAP-004",
        MappingStatus.FAIL if failed else MappingStatus.PASS,
        (
            "Every target tensor and semantic identity is produced once"
            if not failed
            else "Duplicate target mappings were detected"
        ),
        {
            "duplicate_target_name_count": len(duplicate_names),
            "duplicate_target_name_examples": duplicate_names[:EXAMPLE_CAP],
            "duplicate_target_identity_count": len(duplicate_identities),
            "duplicate_target_identity_examples": duplicate_identities[:EXAMPLE_CAP],
            "multi_match_binding_count": len(diagnostics.multiple_target_matches),
            "multi_match_binding_examples": diagnostics.multiple_target_matches[:EXAMPLE_CAP],
            "example_cap": EXAMPLE_CAP,
        },
    )


def _layers(diagnostics: ResolutionDiagnostics) -> MappingFinding:
    mismatches: list[dict[str, Any]] = []
    for resolution in diagnostics.resolutions:
        source, target = resolution.source, resolution.target
        if source.scope != target.scope or source.layer_id != target.layer_id:
            mismatches.append(
                {
                    "rule_id": resolution.rule_id,
                    "source_scope": source.scope,
                    "target_scope": target.scope,
                    "source_layer": source.layer_id,
                    "target_layer": target.layer_id,
                }
            )
        elif resolution.layer_id is not None and (
            source.layer_id != resolution.layer_id or target.layer_id != resolution.layer_id
        ):
            mismatches.append(
                {
                    "rule_id": resolution.rule_id,
                    "bound_layer": resolution.layer_id,
                    "source_layer": source.layer_id,
                    "target_layer": target.layer_id,
                }
            )
    missing_bindings = sorted(
        set(diagnostics.zero_source_matches) | set(diagnostics.zero_target_matches)
    )
    failed = bool(mismatches or missing_bindings)
    return _finding(
        "MAP-005",
        MappingStatus.FAIL if failed else MappingStatus.PASS,
        (
            "Model scope and layer identities are preserved"
            if not failed
            else "Layer identity or binding preservation failed"
        ),
        {
            "resolved_count": len(diagnostics.resolutions),
            "layer_mismatch_count": len(mismatches),
            "layer_mismatch_examples": mismatches[:EXAMPLE_CAP],
            "missing_binding_count": len(missing_bindings),
            "missing_binding_examples": missing_bindings[:EXAMPLE_CAP],
            "example_cap": EXAMPLE_CAP,
        },
    )


def _shapes(diagnostics: ResolutionDiagnostics) -> MappingFinding:
    mismatches: dict[tuple[str, tuple[int, ...], tuple[int, ...]], list[str]] = defaultdict(list)
    relation_counts: Counter[str] = Counter()
    for resolution in diagnostics.resolutions:
        relation_counts[resolution.shape_relation.value] += 1
        source_shape = resolution.source.shape
        target_shape = resolution.target.shape
        expected = (
            source_shape
            if resolution.shape_relation == ShapeRelation.IDENTICAL
            else list(reversed(source_shape))
        )
        if expected != target_shape:
            mismatches[
                (
                    resolution.shape_relation.value,
                    tuple(source_shape),
                    tuple(target_shape),
                )
            ].append(resolution.target.exact_name)
    groups = [
        {
            "shape_relation": relation,
            "source_shape": list(source_shape),
            "target_shape": list(target_shape),
            "tensor_count": len(names),
            "tensor_examples": sorted(names)[:EXAMPLE_CAP],
        }
        for (relation, source_shape, target_shape), names in sorted(mismatches.items())
    ]
    return _finding(
        "MAP-006",
        MappingStatus.FAIL if groups else MappingStatus.PASS,
        (
            "Every resolved descriptor shape satisfies its declared relation"
            if not groups
            else "One or more descriptor shape relations are incompatible"
        ),
        {
            "resolved_count": len(diagnostics.resolutions),
            "relation_counts": dict(sorted(relation_counts.items())),
            "mismatch_group_count": len(groups),
            "mismatch_groups": groups[:EXAMPLE_CAP],
            "descriptor_relation_only": True,
            "payload_transpose_claimed": False,
            "example_cap": EXAMPLE_CAP,
        },
    )


def _parameters(diagnostics: ResolutionDiagnostics) -> MappingFinding:
    mismatches: list[dict[str, Any]] = []
    for resolution in diagnostics.resolutions:
        source, target = resolution.source, resolution.target
        if (
            source.parameter != resolution.parameter
            or target.parameter != resolution.parameter
            or source.module != target.module
            or source.component != target.component
            or source.canonical_identity != target.canonical_identity
        ):
            mismatches.append(
                {
                    "rule_id": resolution.rule_id,
                    "source_identity": source.canonical_identity,
                    "target_identity": target.canonical_identity,
                    "declared_parameter": resolution.parameter,
                    "source_parameter": source.parameter,
                    "target_parameter": target.parameter,
                    "source_module": source.module,
                    "target_module": target.module,
                    "source_component": source.component,
                    "target_component": target.component,
                }
            )
    return _finding(
        "MAP-007",
        MappingStatus.FAIL if mismatches else MappingStatus.PASS,
        (
            "Semantic parameters, modules, and projections are compatible"
            if not mismatches
            else "Semantic parameter compatibility failed"
        ),
        {
            "checked_count": len(diagnostics.resolutions),
            "mismatch_count": len(mismatches),
            "mismatch_examples": mismatches[:EXAMPLE_CAP],
            "example_cap": EXAMPLE_CAP,
        },
    )


def _logical_tie(
    source: HFInventory,
    diagnostics: ResolutionDiagnostics,
    manifest: MappingManifest,
    pack: ModelPack,
) -> MappingFinding:
    logical_rules = [rule for rule in manifest.rules if rule.source_kind == SourceKind.LOGICAL]
    required = pack.provide_model_constraints().logical_tie_required
    if not source.logical_ties and not logical_rules and not required:
        return _finding(
            "MAP-008",
            MappingStatus.PASS,
            "No logical tied source is declared",
            {
                "logical_tied_source": None,
                "physical_source_identity": None,
                "source_materialized": None,
                "materialized_target": None,
                "payload_equality_status": "not applicable",
                "payload_origin": None,
                "failure_count": 0,
                "failure_examples": [],
                "physical_lm_head_required": False,
            },
        )
    logical_identities = sorted(
        {tie.logical_identity for tie in source.logical_ties}
        | {rule.source.canonical_identity for rule in logical_rules}
    )
    logical_identity = logical_identities[0] if len(logical_identities) == 1 else None
    ties = [
        tie
        for tie in source.logical_ties
        if logical_identity is not None and tie.logical_identity == logical_identity
    ]
    resolutions = [
        resolution
        for resolution in diagnostics.resolutions
        if logical_identity is not None
        and resolution.source.canonical_identity == logical_identity
        and resolution.source.source_kind == SourceKind.LOGICAL
    ]
    rules = {
        rule.rule_id: rule
        for rule in manifest.rules
        if logical_identity is not None
        and rule.source_kind == SourceKind.LOGICAL
        and rule.source.canonical_identity == logical_identity
    }
    failures: list[str] = []
    if logical_identity is None:
        failures.append("logical tie identity is missing or ambiguous")
    tie = ties[0] if len(ties) == 1 else None
    if tie is None:
        failures.append("logical tie is missing or duplicated")
    if len(resolutions) != 1:
        failures.append("logical tie does not resolve exactly once")
        resolution = None
    else:
        resolution = resolutions[0]
        rule = rules.get(resolution.rule_id)
        if not resolution.target.materialized:
            failures.append("logical target is not physically materialized")
        if rule is None or rule.target_materialization != MaterializationPolicy.REQUIRED:
            failures.append("target materialization is not declared required")
        if rule is None or tie is None or rule.physical_source != tie.physical_source_identity:
            failures.append("mapping rule has the wrong physical source identity")
        if rule is None or rule.payload_origin != "unverified":
            failures.append("payload origin must remain unverified")
    return _finding(
        "MAP-008",
        MappingStatus.FAIL if failures else MappingStatus.PASS,
        (
            "Logical tied output projection is structurally materialized"
            if not failures
            else "Logical tie materialization is invalid"
        ),
        {
            "logical_tied_source": logical_identity,
            "physical_source_identity": (None if tie is None else tie.physical_source_identity),
            "source_materialized": None if tie is None else tie.materialized,
            "materialized_target": (None if resolution is None else resolution.target.exact_name),
            "payload_equality_status": "not checked",
            "payload_origin": "unverified",
            "failure_count": len(failures),
            "failure_examples": failures[:EXAMPLE_CAP],
            "physical_lm_head_required": False,
        },
    )


def _metadata_values(target: GGUFInventory) -> dict[str, Any]:
    return {entry.key: entry.value for entry in target.metadata}


def _provenance(
    source: HFInventory,
    target: GGUFInventory,
    provenance_validation: ProvenanceValidationReport | None,
) -> MappingFinding:
    if provenance_validation is not None:
        lineage = provenance_validation.exact_lineage_status
        linked_failures = [
            item.rule_id
            for item in provenance_validation.findings
            if item.status == ProvenanceStatus.FAIL
        ]
        linked_warnings = [
            item.rule_id
            for item in provenance_validation.findings
            if item.status == ProvenanceStatus.WARN
        ]
        status = {
            ProvenanceStatus.PASS: MappingStatus.PASS,
            ProvenanceStatus.WARN: MappingStatus.WARN,
            ProvenanceStatus.FAIL: MappingStatus.FAIL,
        }[lineage]
        return _finding(
            "MAP-009",
            status,
            (
                "Validated conversion provenance establishes exact lineage"
                if status == MappingStatus.PASS
                else "Validated conversion provenance is contradictory"
                if status == MappingStatus.FAIL
                else "Validated conversion provenance is incomplete"
            ),
            {
                "provenance_supplied": True,
                "exact_lineage_status": lineage.value,
                "linked_failure_rules": linked_failures,
                "linked_warning_rules": linked_warnings,
                "limitation": ("Lineage does not prove converter correctness or numerical parity"),
            },
        )
    target_values = _metadata_values(target)
    target_fields = {
        "source_artifact_hash": "omiv.source.artifact_sha256",
        "source_repository": "omiv.source.repository",
        "source_revision": "omiv.source.revision",
        "converter_commit": "omiv.converter.commit",
        "conversion_command": "omiv.conversion.command",
    }
    missing: list[str] = []
    if not source.provenance.repository:
        missing.append("source_repository")
    if not source.provenance.revision:
        missing.append("source_revision")
    for label, key in target_fields.items():
        if target_values.get(key) in (None, ""):
            missing.append(label)
    mismatched: list[str] = []
    if (
        target_values.get(target_fields["source_repository"]) is not None
        and target_values.get(target_fields["source_repository"]) != source.provenance.repository
    ):
        mismatched.append("source_repository")
    if (
        target_values.get(target_fields["source_revision"]) is not None
        and target_values.get(target_fields["source_revision"]) != source.provenance.revision
    ):
        mismatched.append("source_revision")
    source_artifact_hash = target_values.get(target_fields["source_artifact_hash"])
    if source_artifact_hash is not None and (
        not isinstance(source_artifact_hash, str)
        or len(source_artifact_hash) != 64
        or any(character not in "0123456789abcdef" for character in source_artifact_hash)
    ):
        mismatched.append("source_artifact_hash")
    return _finding(
        "MAP-009",
        MappingStatus.WARN,
        "Exact source-to-target provenance is unavailable",
        {
            "provenance_supplied": False,
            "source_repository": source.provenance.repository,
            "source_revision": source.provenance.revision,
            "target_lineage_metadata": {
                label: target_values.get(key) for label, key in target_fields.items()
            },
            "missing_provenance_fields": sorted(missing),
            "mismatched_provenance_fields": sorted(mismatched),
            "exact_lineage_established": False,
            "limitation": (
                "Semantic and structural compatibility does not prove that the target "
                "was generated from this exact source artifact"
            ),
            "names_and_shapes_are_not_lineage_evidence": True,
        },
    )


def validate_semantic_mapping(
    source: HFInventory,
    target: GGUFInventory,
    manifest: MappingManifest,
    model_pack: ModelPack | None = None,
    provenance_validation: ProvenanceValidationReport | None = None,
) -> MappingValidationReport:
    pack = (
        resolve_manifest_model_pack(manifest)
        if model_pack is None
        else resolve_manifest_model_pack(manifest, requested_pack_id=model_pack.pack_id)
    )
    source_payload = source.model_dump(mode="json", by_alias=True)
    observed_source_sha256 = source_payload.pop("canonical_sha256")
    if canonical_sha256(source_payload) != observed_source_sha256:
        raise OmivInputError("HF inventory canonical SHA-256 does not match its contents")
    if source.summary.physical_tensor_count != len(source.tensors):
        raise OmivInputError("HF inventory physical tensor count is inconsistent")
    if source.summary.logical_tie_count != len(source.logical_ties):
        raise OmivInputError("HF inventory logical tie count is inconsistent")
    classified_count = sum(tensor.classification == "classified" for tensor in source.tensors)
    if (
        source.summary.classified_tensor_count != classified_count
        or source.summary.unclassified_tensor_count != len(source.tensors) - classified_count
    ):
        raise OmivInputError("HF inventory classification summary is inconsistent")
    if target.header.tensor_count != len(target.tensors):
        raise OmivInputError("GGUF inventory tensor count is inconsistent")
    if target.header.metadata_kv_count != len(target.metadata):
        raise OmivInputError("GGUF inventory metadata count is inconsistent")
    target_names = [tensor.name for tensor in target.tensors]
    if len(target_names) != len(set(target_names)):
        raise OmivInputError("GGUF inventory contains duplicate tensor names")
    if manifest.model_family != source.config.model_type:
        raise OmivInputError("mapping model_family does not match source inventory model type")
    if target.identity.architecture != manifest.model_family:
        raise OmivInputError("mapping model_family does not match target inventory architecture")
    source_entities = hf_semantic_view(source)
    target_entities = gguf_semantic_view(target, pack)
    diagnostics = resolve_mapping_with_diagnostics(source_entities, target_entities, manifest)
    map001, map002, coverage = _coverage(source_entities, target_entities, diagnostics, manifest)
    findings = [
        map001,
        map002,
        _source_uniqueness(diagnostics),
        _target_uniqueness(diagnostics),
        _layers(diagnostics),
        _shapes(diagnostics),
        _parameters(diagnostics),
        _logical_tie(source, diagnostics, manifest, pack),
        _provenance(source, target, provenance_validation),
    ]
    return MappingValidationReport(
        findings=findings,
        resolutions=diagnostics.resolutions,
        coverage=coverage,
        unverified_payload_relation_count=sum(
            finding.rule_id == "MAP-008"
            and finding.evidence.get("payload_equality_status") == "not checked"
            for finding in findings
        ),
    )


def format_mapping_report(report: MappingValidationReport) -> str:
    lines: list[str] = []
    for finding in report.findings:
        lines.append(f"{finding.status.value.upper()} {finding.rule_id} {finding.message}")
    return "\n".join(lines)
