"""Versioned persisted JSON and Markdown semantic mapping reports."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import ValidationError, model_validator

from omiv import __version__
from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory
from omiv.gguf.reporting import inventory_sha256 as gguf_inventory_sha256
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.hf.models import HFInventory
from omiv.mapping.models import (
    ManifestReportProvenance,
    MappingFinding,
    MappingManifest,
    MappingReportEnvelope,
    MappingReportExecution,
    MappingReportIntegrity,
    MappingReportPayload,
    MappingReportSummary,
    MappingReportTool,
    MappingResult,
    MappingStatus,
    MappingValidationReport,
    SourceReportProvenance,
    TargetReportProvenance,
)

MAPPING_REPORT_SCHEMA_ID: Final[
    Literal["omiv.semantic-mapping-report.v1"]
] = "omiv.semantic-mapping-report.v1"
MAX_REPORT_BYTES = 16 * 1024 * 1024


class ValidatedMappingReportPayload(MappingReportPayload):
    @model_validator(mode="after")
    def consistent_payload(self) -> ValidatedMappingReportPayload:
        expected_ids = [f"MAP-{number:03d}" for number in range(1, 10)]
        if [finding.rule_id for finding in self.findings] != expected_ids:
            raise ValueError("findings must contain MAP-001 through MAP-009 in order")
        expected_severity = {
            MappingStatus.PASS: "info",
            MappingStatus.WARN: "warning",
            MappingStatus.FAIL: "error",
        }
        if any(
            finding.severity.value != expected_severity[finding.status]
            for finding in self.findings
        ):
            raise ValueError("finding severity does not match status")
        expected_summary = _summary(
            self.findings,
            self.summary,
        )
        if self.summary != expected_summary:
            raise ValueError("summary does not match findings or resolutions")
        result = derive_mapping_result(self.findings)
        if self.execution.result != result:
            raise ValueError("execution result does not match findings")
        if self.execution.exit_code != (1 if result == MappingResult.FAIL else 0):
            raise ValueError("execution exit_code does not match result")
        return self


class ValidatedMappingReportEnvelope(MappingReportEnvelope):
    report: ValidatedMappingReportPayload


def source_inventory_sha256(inventory: HFInventory) -> str:
    payload = inventory.model_dump(mode="json", by_alias=True)
    observed = payload.pop("canonical_sha256")
    expected = canonical_sha256(payload)
    if observed != expected:
        raise OmivInputError("HF inventory canonical SHA-256 does not match its contents")
    return inventory.canonical_sha256


def mapping_sha256(manifest: MappingManifest) -> str:
    return canonical_sha256(manifest.model_dump(mode="json"))


def derive_mapping_result(findings: list[MappingFinding]) -> MappingResult:
    if any(finding.status == MappingStatus.FAIL for finding in findings):
        return MappingResult.FAIL
    if any(finding.status == MappingStatus.WARN for finding in findings):
        return MappingResult.PASS_WITH_WARNINGS
    return MappingResult.PASS


def _summary(
    findings: list[MappingFinding],
    coverage: MappingReportSummary,
) -> MappingReportSummary:
    return coverage.model_copy(
        update={
            "pass_count": sum(
                finding.status == MappingStatus.PASS for finding in findings
            ),
            "warn_count": sum(
                finding.status == MappingStatus.WARN for finding in findings
            ),
            "fail_count": sum(
                finding.status == MappingStatus.FAIL for finding in findings
            ),
        }
    )


def _report_summary(validation: MappingValidationReport) -> MappingReportSummary:
    coverage = validation.coverage
    return MappingReportSummary(
        pass_count=sum(
            finding.status == MappingStatus.PASS for finding in validation.findings
        ),
        warn_count=sum(
            finding.status == MappingStatus.WARN for finding in validation.findings
        ),
        fail_count=sum(
            finding.status == MappingStatus.FAIL for finding in validation.findings
        ),
        physical_source_mapped=coverage.physical_source_mapped,
        physical_source_total=coverage.physical_source_total,
        logical_source_mapped=coverage.logical_source_mapped,
        logical_source_total=coverage.logical_source_total,
        target_explained=coverage.target_explained,
        target_total=coverage.target_total,
        resolved_mapping_count=len(validation.resolutions),
        duplicate_source_count=coverage.duplicate_source_count,
        duplicate_target_count=coverage.duplicate_target_count,
        unmapped_source_count=coverage.unmapped_source_count,
        unmapped_target_count=coverage.unmapped_target_count,
        unverified_payload_relation_count=validation.unverified_payload_relation_count,
    )


def build_mapping_report_envelope(
    source: HFInventory,
    target: GGUFInventory,
    manifest: MappingManifest,
    validation: MappingValidationReport,
) -> ValidatedMappingReportEnvelope:
    if source.summary.physical_tensor_count != len(source.tensors):
        raise OmivInputError("HF inventory physical tensor count is inconsistent")
    if source.summary.logical_tie_count != len(source.logical_ties):
        raise OmivInputError("HF inventory logical tie count is inconsistent")
    if target.header.tensor_count != len(target.tensors):
        raise OmivInputError("GGUF inventory tensor count is inconsistent")
    if not target.identity.architecture or not target.identity.model_name:
        raise OmivInputError("GGUF inventory identity is incomplete")
    result = derive_mapping_result(validation.findings)
    payload = ValidatedMappingReportPayload(
        report_schema=MAPPING_REPORT_SCHEMA_ID,
        tool=MappingReportTool(
            name="open-model-integration-validator", version=__version__
        ),
        execution=MappingReportExecution(
            result=result, exit_code=1 if result == MappingResult.FAIL else 0
        ),
        source=SourceReportProvenance(
            inventory_sha256=source_inventory_sha256(source),
            repository=source.provenance.repository,
            revision=source.provenance.revision,
            physical_tensor_count=source.summary.physical_tensor_count,
            logical_tie_count=source.summary.logical_tie_count,
            model_family=source.config.model_type,
        ),
        target=TargetReportProvenance(
            inventory_sha256=gguf_inventory_sha256(target),
            artifact_sha256=target.artifact.sha256,
            architecture=target.identity.architecture,
            model_name=target.identity.model_name,
            tensor_count=target.header.tensor_count,
        ),
        mapping=ManifestReportProvenance(
            mapping_id=manifest.mapping_id,
            mapping_sha256=mapping_sha256(manifest),
            mapping_schema=manifest.mapping_schema,
        ),
        summary=_report_summary(validation),
        findings=validation.findings,
    )
    return ValidatedMappingReportEnvelope(
        report=payload,
        integrity=MappingReportIntegrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(payload.model_dump(mode="json")),
        ),
    )


def pretty_mapping_report_json(envelope: MappingReportEnvelope) -> str:
    return (
        json.dumps(
            envelope.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def load_mapping_report_envelope(path: Path) -> ValidatedMappingReportEnvelope:
    try:
        raw = path.read_bytes()
        value = parse_bounded_json_bytes(
            raw,
            source_name=path.name,
            max_bytes=MAX_REPORT_BYTES,
        )
        if value.get("report", {}).get("report_schema") != MAPPING_REPORT_SCHEMA_ID:
            raise OmivInputError("unsupported report schema")
        return ValidatedMappingReportEnvelope.model_validate(value)
    except OmivInputError:
        raise
    except (OSError, ValidationError) as exc:
        raise OmivInputError(f"invalid mapping report: {exc}") from exc


def mapping_report_integrity_matches(envelope: MappingReportEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.report.model_dump(mode="json")
    )


def _safe_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=True)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return text


def _finding_lines(finding: MappingFinding) -> list[str]:
    lines = [
        "",
        f"### {_safe_text(finding.rule_id)}",
        "",
        f"- Status: {finding.status.value.upper()}",
        f"- Message: {_safe_text(finding.message)}",
    ]
    evidence = finding.evidence
    if finding.rule_id == "MAP-006":
        lines.extend(
            [
                f"- Shape relation counts: {_safe_text(evidence.get('relation_counts', {}))}",
                f"- Resolved count: {_safe_text(evidence.get('resolved_count', 0))}",
                f"- Mismatch groups: {_safe_text(evidence.get('mismatch_group_count', 0))}",
                "- Payload transpose claimed: no",
            ]
        )
    elif finding.rule_id == "MAP-008":
        lines.extend(
            [
                "- Logical tied source: "
                + _safe_text(evidence.get("logical_tied_source")),
                "- Physical source identity: "
                + _safe_text(evidence.get("physical_source_identity")),
                "- Materialized target: "
                + _safe_text(evidence.get("materialized_target")),
                "- Payload equality status: "
                + _safe_text(evidence.get("payload_equality_status")),
            ]
        )
    elif finding.rule_id == "MAP-009":
        lines.extend(
            [
                "- Known source repository: "
                + _safe_text(evidence.get("source_repository")),
                "- Known source revision: "
                + _safe_text(evidence.get("source_revision")),
                "- Missing provenance fields: "
                + _safe_text(evidence.get("missing_provenance_fields")),
                "- Limitation: " + _safe_text(evidence.get("limitation")),
            ]
        )
    encoded = json.dumps(
        evidence,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    lines.extend(["- Evidence:", "    " + html.escape(encoded, quote=False)])
    return lines


def render_mapping_markdown(envelope: MappingReportEnvelope) -> str:
    report = envelope.report
    result = {
        MappingResult.PASS: "PASS",
        MappingResult.PASS_WITH_WARNINGS: "PASS WITH WARNINGS",
        MappingResult.FAIL: "FAIL",
    }[report.execution.result]
    summary = report.summary
    lines = [
        "# Open Model Integration Validator Mapping Report",
        "",
        "## Result",
        "",
        result,
        "",
        "## Source",
        "",
        f"- Repository: {_safe_text(report.source.repository)}",
        f"- Revision: {_safe_text(report.source.revision)}",
        f"- Physical tensors: {report.source.physical_tensor_count}",
        f"- Logical tensors: {report.source.logical_tie_count}",
        f"- Source inventory digest: {report.source.inventory_sha256}",
        "",
        "## Target",
        "",
        f"- Architecture: {_safe_text(report.target.architecture)}",
        f"- Model: {_safe_text(report.target.model_name)}",
        f"- Physical tensors: {report.target.tensor_count}",
        f"- Target artifact digest: {report.target.artifact_sha256}",
        f"- Target inventory digest: {report.target.inventory_sha256}",
        "",
        "## Mapping Manifest",
        "",
        f"- Mapping ID: {_safe_text(report.mapping.mapping_id)}",
        f"- Mapping digest: {report.mapping.mapping_sha256}",
        f"- Schema version: {_safe_text(report.mapping.mapping_schema)}",
        "",
        "## Coverage",
        "",
        "- Physical source mapped: "
        f"{summary.physical_source_mapped}/{summary.physical_source_total}",
        "- Logical source mapped: "
        f"{summary.logical_source_mapped}/{summary.logical_source_total}",
        f"- Target explained: {summary.target_explained}/{summary.target_total}",
        f"- Resolved mappings: {summary.resolved_mapping_count}",
        f"- Duplicate source mappings: {summary.duplicate_source_count}",
        f"- Duplicate target mappings: {summary.duplicate_target_count}",
        f"- Unmapped source entities: {summary.unmapped_source_count}",
        f"- Unmapped target entities: {summary.unmapped_target_count}",
        "",
        "## Findings",
    ]
    for finding in report.findings:
        lines.extend(_finding_lines(finding))
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Report schema: {_safe_text(report.report_schema)}",
            f"- Canonicalization: {_safe_text(envelope.integrity.canonicalization)}",
            f"- Report SHA-256: {envelope.integrity.sha256}",
            f"- Tool version: {_safe_text(report.tool.version)}",
            "",
        ]
    )
    return "\n".join(lines)
