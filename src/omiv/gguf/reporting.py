"""Versioned persisted reports for GGUF structural comparisons."""

from __future__ import annotations

import html
import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import Field, JsonValue, ValidationError, model_validator

from omiv import __version__
from omiv.canonical import CANONICALIZATION_ID, canonical_sha256, load_json_value
from omiv.errors import OmivInputError
from omiv.gguf.models import (
    GGUFComparisonFinding,
    GGUFComparisonPolicy,
    GGUFComparisonReport,
    GGUFComparisonStatus,
    GGUFInventory,
    StrictModel,
)

REPORT_SCHEMA_ID: Final[Literal["omiv.gguf-comparison-report.v1"]] = (
    "omiv.gguf-comparison-report.v1"
)
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ReportResult(StrEnum):
    PASS = "pass"
    PASS_WITH_WARNINGS = "pass_with_warnings"
    FAIL = "fail"


class ReportTool(StrictModel):
    name: Literal["open-model-integration-validator"]
    version: str


class ReportExecution(StrictModel):
    result: ReportResult
    exit_code: Literal[0, 1]

    @model_validator(mode="after")
    def result_matches_exit_code(self) -> ReportExecution:
        expected = 1 if self.result == ReportResult.FAIL else 0
        if self.exit_code != expected:
            raise ValueError("execution exit_code does not match result")
        return self


class ArtifactProvenance(StrictModel):
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_byte_size: int = Field(ge=0)
    gguf_version: int = Field(ge=1)
    architecture: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    tensor_count: int = Field(ge=0)
    metadata_count: int = Field(ge=0)


class PolicyProvenance(StrictModel):
    policy_id: str = Field(
        min_length=1,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    policy_schema_version: Literal[1]
    policy_sha256: str = Field(pattern=SHA256_PATTERN)


class ReportSummary(StrictModel):
    pass_count: int = Field(ge=0)
    warn_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)

    @model_validator(mode="after")
    def counts_add_up(self) -> ReportSummary:
        if self.pass_count + self.warn_count + self.fail_count != self.finding_count:
            raise ValueError("summary counts do not add up to finding_count")
        return self


class GGUFReportPayload(StrictModel):
    report_schema: Literal["omiv.gguf-comparison-report.v1"]
    tool: ReportTool
    execution: ReportExecution
    source: ArtifactProvenance
    target: ArtifactProvenance
    policy: PolicyProvenance
    findings: list[GGUFComparisonFinding]
    summary: ReportSummary

    @model_validator(mode="after")
    def findings_match_summary_and_result(self) -> GGUFReportPayload:
        expected_rule_ids = [f"GGUF-DIFF-{number:03d}" for number in range(1, 6)]
        if [item.rule_id for item in self.findings] != expected_rule_ids:
            raise ValueError("findings must contain GGUF-DIFF-001 through 005 in order")
        expected_severity = {
            GGUFComparisonStatus.PASS: "info",
            GGUFComparisonStatus.WARN: "warning",
            GGUFComparisonStatus.FAIL: "error",
        }
        if any(
            item.severity.value != expected_severity[item.status]
            for item in self.findings
        ):
            raise ValueError("finding severity does not match status")
        summary = summarize_findings(self.findings)
        if self.summary != summary:
            raise ValueError("summary does not match findings")
        result = derive_result(self.findings)
        if self.execution.result != result:
            raise ValueError("execution result does not match findings")
        return self


class ReportIntegrity(StrictModel):
    canonicalization: Literal["omiv-json-v1"]
    sha256: str = Field(pattern=SHA256_PATTERN)


class GGUFReportEnvelope(StrictModel):
    report: GGUFReportPayload
    integrity: ReportIntegrity


def inventory_sha256(inventory: GGUFInventory) -> str:
    return canonical_sha256(inventory.model_dump(mode="json"))


def policy_sha256(policy: GGUFComparisonPolicy) -> str:
    return canonical_sha256(policy.model_dump(mode="json"))


def summarize_findings(findings: list[GGUFComparisonFinding]) -> ReportSummary:
    return ReportSummary(
        pass_count=sum(item.status == GGUFComparisonStatus.PASS for item in findings),
        warn_count=sum(item.status == GGUFComparisonStatus.WARN for item in findings),
        fail_count=sum(item.status == GGUFComparisonStatus.FAIL for item in findings),
        finding_count=len(findings),
    )


def derive_result(findings: list[GGUFComparisonFinding]) -> ReportResult:
    if any(item.status == GGUFComparisonStatus.FAIL for item in findings):
        return ReportResult.FAIL
    if any(item.status == GGUFComparisonStatus.WARN for item in findings):
        return ReportResult.PASS_WITH_WARNINGS
    return ReportResult.PASS


def _artifact_provenance(inventory: GGUFInventory) -> ArtifactProvenance:
    if not inventory.identity.architecture:
        raise OmivInputError("inventory provenance is missing architecture")
    if not inventory.identity.model_name:
        raise OmivInputError("inventory provenance is missing model name")
    if inventory.header.tensor_count != len(inventory.tensors):
        raise OmivInputError(
            "malformed inventory provenance: tensor count does not match inventory"
        )
    if inventory.header.metadata_kv_count != len(inventory.metadata):
        raise OmivInputError(
            "malformed inventory provenance: metadata count does not match inventory"
        )
    try:
        return ArtifactProvenance(
            inventory_sha256=inventory_sha256(inventory),
            artifact_sha256=inventory.artifact.sha256,
            artifact_byte_size=inventory.artifact.byte_size,
            gguf_version=inventory.header.version,
            architecture=inventory.identity.architecture,
            model_name=inventory.identity.model_name,
            tensor_count=inventory.header.tensor_count,
            metadata_count=inventory.header.metadata_kv_count,
        )
    except ValidationError as exc:
        raise OmivInputError(f"malformed inventory provenance: {exc}") from exc


def build_report_envelope(
    source: GGUFInventory,
    target: GGUFInventory,
    policy: GGUFComparisonPolicy,
    comparison: GGUFComparisonReport,
) -> GGUFReportEnvelope:
    findings = list(comparison.findings)
    result = derive_result(findings)
    payload = GGUFReportPayload(
        report_schema=REPORT_SCHEMA_ID,
        tool=ReportTool(
            name="open-model-integration-validator",
            version=__version__,
        ),
        execution=ReportExecution(
            result=result,
            exit_code=1 if result == ReportResult.FAIL else 0,
        ),
        source=_artifact_provenance(source),
        target=_artifact_provenance(target),
        policy=PolicyProvenance(
            policy_id=policy.policy_id,
            policy_schema_version=policy.policy_schema_version,
            policy_sha256=policy_sha256(policy),
        ),
        findings=findings,
        summary=summarize_findings(findings),
    )
    return GGUFReportEnvelope(
        report=payload,
        integrity=ReportIntegrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(payload.model_dump(mode="json")),
        ),
    )


def pretty_report_json(envelope: GGUFReportEnvelope) -> str:
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


def load_report_envelope(path: Path) -> GGUFReportEnvelope:
    try:
        raw = load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, OmivInputError) as exc:
        raise OmivInputError(f"invalid report: {exc}") from exc
    if not isinstance(raw, dict):
        raise OmivInputError("invalid report: top-level value must be an object")
    report = raw.get("report")
    if not isinstance(report, dict):
        raise OmivInputError("invalid report: missing report payload")
    if report.get("report_schema") != REPORT_SCHEMA_ID:
        raise OmivInputError("unsupported report schema")
    try:
        return GGUFReportEnvelope.model_validate(raw)
    except ValidationError as exc:
        raise OmivInputError(f"invalid report: {exc}") from exc


def report_integrity_matches(envelope: GGUFReportEnvelope) -> bool:
    expected = canonical_sha256(envelope.report.model_dump(mode="json"))
    return envelope.integrity.sha256 == expected


def _safe_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=True)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return text


def _table_cell(value: Any) -> str:
    return _safe_text(value)


def _evidence_block(value: JsonValue | dict[str, JsonValue]) -> list[str]:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return ["", "    " + html.escape(encoded, quote=False)]


def _bounded_difference_lines(
    label: str, values: Any, *, cap: int = 10
) -> list[str]:
    items = values if isinstance(values, list) else []
    lines = [f"- {_safe_text(label)}: {len(items)}"]
    for item in items[:cap]:
        lines.extend(_evidence_block(item))
    if len(items) > cap:
        lines.append(f"- {_safe_text(label)} omitted: {len(items) - cap}")
    return lines


def _render_special_evidence(finding: GGUFComparisonFinding) -> list[str]:
    evidence = finding.evidence
    if finding.rule_id == "GGUF-DIFF-004":
        lines: list[str] = []
        for label, key in (
            ("Accepted transition groups", "accepted_transition_groups"),
            ("Rejected transition groups", "rejected_transition_groups"),
        ):
            groups = evidence.get(key, [])
            lines.extend(_bounded_difference_lines(label, groups))
        lines.append(
            f"- Checked tensors: {_safe_text(evidence.get('checked_tensor_count', 0))}"
        )
        return lines
    if finding.rule_id == "GGUF-DIFF-005":
        lines = []
        for label, key in (
            ("Allowed differences", "allowed_differences"),
            ("Warning differences", "warning_differences"),
            ("Required equality failures", "failed_differences"),
        ):
            lines.extend(_bounded_difference_lines(label, evidence.get(key, [])))
        lines.append(
            "- Ignored differences: "
            + _safe_text(evidence.get("ignored_difference_count", 0))
        )
        return lines
    return _evidence_block(evidence)


def render_markdown(envelope: GGUFReportEnvelope) -> str:
    payload = envelope.report
    result_label = {
        ReportResult.PASS: "PASS",
        ReportResult.PASS_WITH_WARNINGS: "PASS WITH WARNINGS",
        ReportResult.FAIL: "FAIL",
    }[payload.execution.result]
    lines = [
        "# Open Model Integration Validator Report",
        "",
        "## Result",
        "",
        result_label,
        "",
        "## Artifacts",
        "",
        "| Role | Architecture | Model | Artifact SHA-256 | Inventory SHA-256 "
        "| Byte size | Tensors | Metadata entries |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
    ]
    for role, artifact in (("Source", payload.source), ("Target", payload.target)):
        lines.append(
            "| "
            + " | ".join(
                _table_cell(value)
                for value in (
                    role,
                    artifact.architecture,
                    artifact.model_name,
                    artifact.artifact_sha256,
                    artifact.inventory_sha256,
                    artifact.artifact_byte_size,
                    artifact.tensor_count,
                    artifact.metadata_count,
                )
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Policy",
            "",
            f"- Policy ID: {_safe_text(payload.policy.policy_id)}",
            f"- Policy digest: {payload.policy.policy_sha256}",
            f"- Schema version: {payload.policy.policy_schema_version}",
            "",
            "## Summary",
            "",
            f"- Pass: {payload.summary.pass_count}",
            f"- Warn: {payload.summary.warn_count}",
            f"- Fail: {payload.summary.fail_count}",
            "",
            "## Findings",
        ]
    )
    for finding in payload.findings:
        lines.extend(
            [
                "",
                f"### {_safe_text(finding.rule_id)}",
                "",
                f"- Status: {finding.status.value.upper()}",
                f"- Rule ID: {_safe_text(finding.rule_id)}",
                f"- Message: {_safe_text(finding.message)}",
                "- Evidence:",
                *_render_special_evidence(finding),
            ]
        )
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Report schema: {_safe_text(payload.report_schema)}",
            f"- Canonicalization: {_safe_text(envelope.integrity.canonicalization)}",
            f"- Report SHA-256: {envelope.integrity.sha256}",
            f"- Tool version: {_safe_text(payload.tool.version)}",
            "",
        ]
    )
    return "\n".join(lines)
