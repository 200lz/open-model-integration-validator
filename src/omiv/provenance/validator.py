"""PROV-001 through PROV-012 generic lineage validation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.mapping.models import MappingManifest
from omiv.model_packs.base import ModelPack
from omiv.provenance.models import (
    ArtifactDigestEvidence,
    ConversionProvenance,
    InventoryEvidence,
    ProvenanceFinding,
    ProvenanceSeverity,
    ProvenanceStatus,
    ProvenanceSummary,
    ProvenanceValidationReport,
    RevisionKind,
)


@dataclass(frozen=True)
class ProvenanceValidationContext:
    source_inventory: InventoryEvidence
    target_inventory: InventoryEvidence
    mapping: MappingManifest
    model_pack: ModelPack
    source_artifacts: dict[str, Path] = field(default_factory=dict)
    target_artifacts: dict[str, Path] = field(default_factory=dict)
    observed_tool_head: str | None = None


def _finding(
    rule_id: str,
    status: ProvenanceStatus,
    message: str,
    evidence: dict[str, Any],
) -> ProvenanceFinding:
    severity = {
        ProvenanceStatus.PASS: ProvenanceSeverity.INFO,
        ProvenanceStatus.WARN: ProvenanceSeverity.WARNING,
        ProvenanceStatus.FAIL: ProvenanceSeverity.ERROR,
    }[status]
    return ProvenanceFinding(
        rule_id=rule_id,
        severity=severity,
        status=status,
        message=message,
        evidence=evidence,
    )


def _immutable_source_revision(value: str | None) -> bool:
    return value is not None and bool(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value))


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def _prov001(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    source = provenance.source
    conflicts: list[str] = []
    evidence = context.source_inventory
    if source.repository and evidence.repository and source.repository != evidence.repository:
        conflicts.append("repository")
    if source.revision and evidence.revision and source.revision != evidence.revision:
        conflicts.append("revision")
    required = [item for item in source.artifacts if item.required]
    complete_digests = bool(required) and all(
        item.digest_evidence == ArtifactDigestEvidence.FULL_ARTIFACT for item in required
    )
    repository_pin = bool(source.repository and _immutable_source_revision(source.revision))
    if conflicts:
        status = ProvenanceStatus.FAIL
        message = "Source identity claims conflict with inventory evidence"
    elif repository_pin or complete_digests:
        status = ProvenanceStatus.PASS
        message = "Source identity is sufficiently pinned"
    else:
        status = ProvenanceStatus.WARN
        message = "Source identity is known but exact artifact identity is incomplete"
    return _finding(
        "PROV-001",
        status,
        message,
        {
            "repository_revision_pin": repository_pin,
            "complete_required_artifact_digests": complete_digests,
            "required_artifact_count": len(required),
            "conflicts": conflicts,
        },
    )


def _observed_source_artifact(
    role: str, artifact_id: str, context: ProvenanceValidationContext
) -> tuple[int, str, str] | None:
    path = context.source_artifacts.get(role)
    if path is not None:
        size, digest = _hash_file(path)
        return size, digest, "current_file"
    observed = context.source_inventory.artifacts.get(role)
    if observed is None:
        observed = next(
            (
                item
                for item in context.source_inventory.artifacts.values()
                if item.artifact_id == artifact_id and item.full_artifact_digest
            ),
            None,
        )
    if observed is None or not observed.full_artifact_digest:
        return None
    return observed.byte_size, observed.sha256, "trusted_inventory"


def _prov002(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    checked: list[dict[str, Any]] = []
    unchecked: list[str] = []
    mismatches: list[dict[str, Any]] = []
    for artifact in provenance.source.artifacts:
        observed = _observed_source_artifact(artifact.role, artifact.artifact_id, context)
        if observed is None:
            unchecked.append(artifact.role)
            continue
        size, digest, evidence_kind = observed
        checked.append({"role": artifact.role, "evidence": evidence_kind})
        mismatch_fields: list[str] = []
        if size != artifact.byte_size:
            mismatch_fields.append("byte_size")
        if digest != artifact.sha256:
            mismatch_fields.append("sha256")
        if mismatch_fields:
            mismatches.append({"role": artifact.role, "fields": mismatch_fields})
    if mismatches:
        status = ProvenanceStatus.FAIL
        message = "One or more source artifact digests do not match"
    elif unchecked:
        status = ProvenanceStatus.WARN
        message = "Some source artifact digests were not independently checked"
    else:
        status = ProvenanceStatus.PASS
        message = "Source artifact digests match supplied evidence"
    return _finding(
        "PROV-002",
        status,
        message,
        {
            "checked": checked,
            "unchecked_roles": sorted(unchecked),
            "mismatches": mismatches,
        },
    )


def _prov003(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    source = provenance.source
    observed = context.source_inventory
    mismatches: list[str] = []
    if source.inventory_sha256 != observed.inventory_sha256:
        mismatches.append("inventory_sha256")
    if source.inventory_schema != observed.inventory_schema:
        mismatches.append("inventory_schema")
    if source.format != observed.format:
        mismatches.append("format")
    status = ProvenanceStatus.FAIL if mismatches else ProvenanceStatus.PASS
    return _finding(
        "PROV-003",
        status,
        "Source inventory identity matches"
        if not mismatches
        else "Source inventory identity differs",
        {
            "declared_sha256": source.inventory_sha256,
            "observed_sha256": observed.inventory_sha256,
            "mismatches": mismatches,
        },
    )


def _prov004(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    installed = context.model_pack
    source_pack = provenance.source.model_pack
    interpretation = provenance.interpretation.model_pack
    mismatches: list[str] = []
    for label, value, expected in (
        ("source.pack_id", source_pack.pack_id, installed.pack_id),
        ("source.pack_version", source_pack.pack_version, installed.pack_version),
        ("source.metadata_sha256", source_pack.metadata_sha256, installed.metadata.digest),
        ("interpretation.pack_id", interpretation.pack_id, installed.pack_id),
        ("interpretation.pack_version", interpretation.pack_version, installed.pack_version),
        (
            "interpretation.pack_schema_version",
            interpretation.pack_schema_version,
            installed.pack_schema_version,
        ),
        (
            "interpretation.metadata_sha256",
            interpretation.metadata_sha256,
            installed.metadata.digest,
        ),
    ):
        if value != expected:
            mismatches.append(label)
    return _finding(
        "PROV-004",
        ProvenanceStatus.FAIL if mismatches else ProvenanceStatus.PASS,
        "Model pack identity matches" if not mismatches else "Model pack identity differs",
        {"installed_pack_id": installed.pack_id, "mismatches": mismatches},
    )


def _prov005(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    declared = provenance.interpretation.mapping
    manifest = context.mapping
    reference = manifest.model_pack
    mismatches: list[str] = []
    if declared.mapping_id != manifest.mapping_id:
        mismatches.append("mapping_id")
    if declared.mapping_schema != manifest.mapping_schema:
        mismatches.append("mapping_schema")
    observed_digest = canonical_sha256(manifest.model_dump(mode="json"))
    if declared.canonical_sha256 != observed_digest:
        mismatches.append("canonical_sha256")
    if manifest.model_family != provenance.source.model_family:
        mismatches.append("model_family")
    if reference is not None:
        if reference.pack_id != provenance.interpretation.model_pack.pack_id:
            mismatches.append("model_pack.pack_id")
        if (
            reference.pack_schema_version
            != provenance.interpretation.model_pack.pack_schema_version
        ):
            mismatches.append("model_pack.pack_schema_version")
        if provenance.interpretation.model_pack.pack_version < reference.minimum_pack_version:
            mismatches.append("model_pack.minimum_pack_version")
    return _finding(
        "PROV-005",
        ProvenanceStatus.FAIL if mismatches else ProvenanceStatus.PASS,
        "Mapping manifest identity matches"
        if not mismatches
        else "Mapping manifest identity differs",
        {
            "declared_sha256": declared.canonical_sha256,
            "observed_sha256": observed_digest,
            "mismatches": mismatches,
        },
    )


def _tool_is_pinned(provenance: ConversionProvenance) -> bool:
    tool = provenance.process.tool
    if tool.revision_kind == RevisionKind.GIT_COMMIT:
        return bool(re.fullmatch(r"[0-9a-f]{40}", tool.revision))
    if tool.revision_kind == RevisionKind.CONTENT_DIGEST:
        return bool(re.fullmatch(r"[0-9a-f]{64}", tool.revision))
    return tool.revision_kind == RevisionKind.IMMUTABLE_VERSION and bool(tool.revision)


def _prov006(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    tool = provenance.process.tool
    conflict = (
        context.observed_tool_head is not None
        and tool.revision_kind == RevisionKind.GIT_COMMIT
        and tool.revision != context.observed_tool_head
    )
    pinned = _tool_is_pinned(provenance)
    status = (
        ProvenanceStatus.FAIL
        if conflict
        else ProvenanceStatus.PASS
        if pinned
        else ProvenanceStatus.WARN
    )
    return _finding(
        "PROV-006",
        status,
        (
            "Conversion tool identity conflicts with observed source"
            if conflict
            else "Conversion tool identity is pinned"
            if pinned
            else "Conversion tool identity is mutable or incomplete"
        ),
        {
            "revision_kind": tool.revision_kind.value,
            "declared_revision": tool.revision,
            "observed_repository_head": context.observed_tool_head,
            "immutable": pinned,
        },
    )


def _prov007(provenance: ConversionProvenance) -> ProvenanceFinding:
    invocation = provenance.process.invocation
    output_markers = ("{target_", "{output", "--output", "--outfile", "-o")
    identifiable = any(
        argument == marker or argument.startswith(marker)
        for argument in invocation.arguments
        for marker in output_markers
    ) or any(
        artifact.artifact_id in invocation.arguments for artifact in provenance.target.artifacts
    )
    problems: list[str] = []
    if not invocation.executable:
        problems.append("missing_executable")
    if not invocation.arguments:
        problems.append("missing_arguments")
    if not identifiable:
        problems.append("output_argument_not_identifiable")
    status = ProvenanceStatus.FAIL if problems else ProvenanceStatus.PASS
    return _finding(
        "PROV-007",
        status,
        "Invocation is reproducibly recorded"
        if not problems
        else "Invocation description is incomplete",
        {
            "argument_count": len(invocation.arguments),
            "redacted_arguments": invocation.redacted_arguments,
            "output_argument_identifiable": identifiable,
            "problems": problems,
            "shell_command_string": False,
        },
    )


def _prov008(provenance: ConversionProvenance) -> ProvenanceFinding:
    process = provenance.process
    target_roles = {item.role for item in provenance.target.artifacts}
    declared_roles = set(process.declared_outputs)
    problems: list[str] = []
    if process.result.success != (process.result.exit_code == 0):
        problems.append("success_exit_code_conflict")
    if not process.result.success and any(
        item.output_success for item in provenance.target.artifacts
    ):
        problems.append("failed_process_claims_completed_target")
    if process.result.success and any(
        not item.output_success for item in provenance.target.artifacts
    ):
        problems.append("successful_process_has_incomplete_target")
    if declared_roles != target_roles:
        problems.append("declared_output_roles_do_not_match_targets")
    return _finding(
        "PROV-008",
        ProvenanceStatus.FAIL if problems else ProvenanceStatus.PASS,
        "Process result is internally consistent"
        if not problems
        else "Process result is contradictory",
        {
            "declared_roles": sorted(declared_roles),
            "target_roles": sorted(target_roles),
            "problems": problems,
        },
    )


def _observed_target_artifact(
    role: str, artifact_id: str, context: ProvenanceValidationContext
) -> tuple[int, str, str] | None:
    path = context.target_artifacts.get(role)
    if path is not None:
        size, digest = _hash_file(path)
        return size, digest, "current_file"
    observed = context.target_inventory.artifacts.get(artifact_id)
    if observed is None:
        observed = context.target_inventory.artifacts.get(role)
    if observed is None and len(context.target_inventory.artifacts) == 1:
        observed = next(iter(context.target_inventory.artifacts.values()))
    if observed is None or not observed.full_artifact_digest:
        return None
    return observed.byte_size, observed.sha256, "inventory"


def _prov009(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    checked: list[dict[str, str]] = []
    unchecked: list[str] = []
    mismatches: list[dict[str, Any]] = []
    for artifact in provenance.target.artifacts:
        observed = _observed_target_artifact(artifact.role, artifact.artifact_id, context)
        if observed is None:
            unchecked.append(artifact.role)
            continue
        size, digest, kind = observed
        checked.append({"role": artifact.role, "evidence": kind})
        fields: list[str] = []
        if size != artifact.byte_size:
            fields.append("byte_size")
        if digest != artifact.sha256:
            fields.append("sha256")
        if fields:
            mismatches.append({"role": artifact.role, "fields": fields})
    status = (
        ProvenanceStatus.FAIL
        if mismatches
        else ProvenanceStatus.WARN
        if unchecked
        else ProvenanceStatus.PASS
    )
    return _finding(
        "PROV-009",
        status,
        (
            "Target artifact digest differs"
            if mismatches
            else "Target artifact digest was not checked"
            if unchecked
            else "Target artifact digest matches"
        ),
        {"checked": checked, "unchecked_roles": unchecked, "mismatches": mismatches},
    )


def _prov010(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    target = provenance.target
    observed = context.target_inventory
    mismatches: list[str] = []
    if target.inventory_sha256 != observed.inventory_sha256:
        mismatches.append("inventory_sha256")
    if target.inventory_schema != observed.inventory_schema:
        mismatches.append("inventory_schema")
    if target.format != observed.format:
        mismatches.append("format")
    return _finding(
        "PROV-010",
        ProvenanceStatus.FAIL if mismatches else ProvenanceStatus.PASS,
        "Target inventory identity matches"
        if not mismatches
        else "Target inventory identity differs",
        {
            "declared_sha256": target.inventory_sha256,
            "observed_sha256": observed.inventory_sha256,
            "mismatches": mismatches,
        },
    )


def _prov011(
    provenance: ConversionProvenance, context: ProvenanceValidationContext
) -> ProvenanceFinding:
    manifest = context.mapping
    problems: list[str] = []
    if provenance.source.model_family != manifest.model_family:
        problems.append("source_model_family")
    if provenance.source.model_pack.pack_id != provenance.interpretation.model_pack.pack_id:
        problems.append("model_pack_cross_link")
    if provenance.source.format != manifest.source_format:
        problems.append("source_format")
    if provenance.target.format != manifest.target_format:
        problems.append("target_format")
    if provenance.target.architecture and provenance.target.architecture != manifest.model_family:
        problems.append("target_architecture")
    if provenance.operation != provenance.process.operation:
        problems.append("operation")
    if set(provenance.process.declared_outputs) != {
        item.role for item in provenance.target.artifacts
    }:
        problems.append("declared_outputs")
    return _finding(
        "PROV-011",
        ProvenanceStatus.FAIL if problems else ProvenanceStatus.PASS,
        "Provenance chain is internally consistent"
        if not problems
        else "Provenance chain cross-links conflict",
        {"problems": problems},
    )


def _prov012(
    provenance: ConversionProvenance, findings: list[ProvenanceFinding]
) -> ProvenanceFinding:
    failures = [item.rule_id for item in findings if item.status == ProvenanceStatus.FAIL]
    source_exact = findings[0].status == ProvenanceStatus.PASS
    mapping_exact = findings[4].status == ProvenanceStatus.PASS
    tool_exact = findings[5].status == ProvenanceStatus.PASS
    target_exact = findings[8].status == ProvenanceStatus.PASS
    inventories_exact = (
        findings[2].status == ProvenanceStatus.PASS and findings[9].status == ProvenanceStatus.PASS
    )
    structurally_exact = (
        source_exact
        and mapping_exact
        and tool_exact
        and target_exact
        and inventories_exact
        and provenance.process.result.success
    )
    status = (
        ProvenanceStatus.FAIL
        if failures
        else ProvenanceStatus.PASS
        if structurally_exact
        else ProvenanceStatus.WARN
    )
    return _finding(
        "PROV-012",
        status,
        (
            "Exact lineage is sufficiently pinned"
            if status == ProvenanceStatus.PASS
            else "Exact lineage claims are contradictory"
            if status == ProvenanceStatus.FAIL
            else "Lineage is structurally valid but incomplete"
        ),
        {
            "failed_rules": failures,
            "source_exact": source_exact,
            "mapping_exact": mapping_exact,
            "tool_exact": tool_exact,
            "target_exact": target_exact,
            "inventories_exact": inventories_exact,
        },
    )


def _summary(findings: list[ProvenanceFinding]) -> ProvenanceSummary:
    by_id = {item.rule_id: item.status for item in findings}
    return ProvenanceSummary(
        pass_count=sum(item.status == ProvenanceStatus.PASS for item in findings),
        warn_count=sum(item.status == ProvenanceStatus.WARN for item in findings),
        fail_count=sum(item.status == ProvenanceStatus.FAIL for item in findings),
        source_identity_status=by_id["PROV-001"],
        source_artifact_status=by_id["PROV-002"],
        source_inventory_status=by_id["PROV-003"],
        model_pack_status=by_id["PROV-004"],
        mapping_status=by_id["PROV-005"],
        tool_identity_status=by_id["PROV-006"],
        invocation_status=by_id["PROV-007"],
        target_artifact_status=by_id["PROV-009"],
        target_inventory_status=by_id["PROV-010"],
        exact_lineage_status=by_id["PROV-012"],
    )


def validate_provenance(
    provenance: ConversionProvenance,
    context: ProvenanceValidationContext,
) -> ProvenanceValidationReport:
    """Validate a provenance chain against explicit inventory and interpretation evidence."""
    findings = [
        _prov001(provenance, context),
        _prov002(provenance, context),
        _prov003(provenance, context),
        _prov004(provenance, context),
        _prov005(provenance, context),
        _prov006(provenance, context),
        _prov007(provenance),
        _prov008(provenance),
        _prov009(provenance, context),
        _prov010(provenance, context),
        _prov011(provenance, context),
    ]
    findings.append(_prov012(provenance, findings))
    return ProvenanceValidationReport(findings=findings, summary=_summary(findings))


def format_provenance_report(report: ProvenanceValidationReport) -> str:
    return "\n".join(
        f"{item.status.value.upper()} {item.rule_id} {item.message}" for item in report.findings
    )
