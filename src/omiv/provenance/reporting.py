"""Deterministic JSON and Markdown conversion provenance reports."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import ValidationError

from omiv import __version__
from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.provenance.models import (
    ConversionProvenance,
    Integrity,
    ProvenanceEnvelope,
    ProvenanceReportEnvelope,
    ProvenanceReportExecution,
    ProvenanceReportPayload,
    ProvenanceReportTool,
    ProvenanceResult,
    ProvenanceStatus,
    ProvenanceValidationReport,
)

PROVENANCE_REPORT_SCHEMA_ID: Final[Literal["omiv.conversion-provenance-report.v1"]] = (
    "omiv.conversion-provenance-report.v1"
)
MAX_REPORT_BYTES = 16 * 1024 * 1024


def build_provenance_envelope(provenance: ConversionProvenance) -> ProvenanceEnvelope:
    payload = provenance.model_dump(mode="json")
    return ProvenanceEnvelope(
        provenance=provenance,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(payload),
        ),
    )


def provenance_integrity_matches(envelope: ProvenanceEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.provenance.model_dump(mode="json")
    )


def pretty_provenance_json(envelope: ProvenanceEnvelope) -> str:
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


def _result(report: ProvenanceValidationReport) -> ProvenanceResult:
    if report.summary.fail_count:
        return ProvenanceResult.FAIL
    if report.summary.warn_count:
        return ProvenanceResult.PASS_WITH_WARNINGS
    return ProvenanceResult.PASS


def _limitations(report: ProvenanceValidationReport) -> list[str]:
    limitations = [
        f"{item.rule_id}: {item.message}"
        for item in report.findings
        if item.status == ProvenanceStatus.WARN
    ]
    limitations.append(
        "Lineage does not prove converter correctness, target payload numerical "
        "correctness, or inference parity."
    )
    return limitations


def build_provenance_report_envelope(
    provenance: ConversionProvenance,
    validation: ProvenanceValidationReport,
) -> ProvenanceReportEnvelope:
    result = _result(validation)
    payload = ProvenanceReportPayload(
        report_schema=PROVENANCE_REPORT_SCHEMA_ID,
        tool=ProvenanceReportTool(
            name="open-model-integration-validator",
            version=__version__,
        ),
        execution=ProvenanceReportExecution(
            result=result,
            exit_code=1 if result == ProvenanceResult.FAIL else 0,
        ),
        provenance_sha256=canonical_sha256(provenance.model_dump(mode="json")),
        provenance=provenance,
        summary=validation.summary,
        findings=validation.findings,
        limitations=_limitations(validation),
    )
    return ProvenanceReportEnvelope(
        report=payload,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(payload.model_dump(mode="json")),
        ),
    )


def pretty_provenance_report_json(envelope: ProvenanceReportEnvelope) -> str:
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


def load_provenance_report_envelope(path: Path) -> ProvenanceReportEnvelope:
    try:
        value = parse_bounded_json_bytes(
            path.read_bytes(),
            source_name=path.name,
            max_bytes=MAX_REPORT_BYTES,
        )
        if value.get("report", {}).get("report_schema") != PROVENANCE_REPORT_SCHEMA_ID:
            raise OmivInputError("unsupported report schema")
        return ProvenanceReportEnvelope.model_validate(value)
    except OmivInputError:
        raise
    except (OSError, ValidationError) as exc:
        raise OmivInputError(f"invalid provenance report: {exc}") from exc


def provenance_report_integrity_matches(envelope: ProvenanceReportEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(envelope.report.model_dump(mode="json"))


def _safe_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=True)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return text


def render_provenance_markdown(envelope: ProvenanceReportEnvelope) -> str:
    report = envelope.report
    provenance = report.provenance
    source = provenance.source
    interpretation = provenance.interpretation
    process = provenance.process
    target = provenance.target
    summary = report.summary
    invocation = [process.invocation.executable, *process.invocation.arguments]
    lines = [
        "# Open Model Integration Validator Conversion Provenance Report",
        "",
        "## Result",
        "",
        f"- Result: {report.execution.result.value.upper()}",
        f"- PASS: {summary.pass_count}",
        f"- WARN: {summary.warn_count}",
        f"- FAIL: {summary.fail_count}",
        "",
        "## Source",
        "",
        f"- Format: {_safe_text(source.format)}",
        f"- Model family: {_safe_text(source.model_family)}",
        f"- Repository: {_safe_text(source.repository or 'not recorded')}",
        f"- Revision: {_safe_text(source.revision or 'not recorded')}",
        f"- Inventory digest: {source.inventory_sha256}",
        f"- Artifact digest coverage: "
        f"{sum(item.digest_evidence.value == 'full_artifact' for item in source.artifacts)}"
        f"/{len(source.artifacts)}",
        f"- Model pack: {_safe_text(source.model_pack.pack_id)} v{source.model_pack.pack_version}",
        "",
        "## Semantic Interpretation",
        "",
        f"- Model pack: {_safe_text(interpretation.model_pack.pack_id)}",
        f"- Pack metadata digest: {interpretation.model_pack.metadata_sha256}",
        f"- Mapping ID: {_safe_text(interpretation.mapping.mapping_id)}",
        f"- Mapping digest: {interpretation.mapping.canonical_sha256}",
        f"- Policy references: {len(interpretation.policies)}",
        "",
        "## Process",
        "",
        f"- Operation: {_safe_text(provenance.operation.value)}",
        f"- Tool: {_safe_text(process.tool.name)}",
        f"- Revision: {_safe_text(process.tool.revision)}",
        f"- Revision kind: {_safe_text(process.tool.revision_kind.value)}",
        f"- Entrypoint: {_safe_text(process.tool.entrypoint)}",
        f"- Invocation: {_safe_text(invocation)}",
        f"- Exit code: {process.result.exit_code}",
        f"- Success: {str(process.result.success).lower()}",
        "",
        "## Target",
        "",
        f"- Format: {_safe_text(target.format)}",
        f"- Architecture: {_safe_text(target.architecture or target.artifact_type)}",
        f"- Inventory digest: {target.inventory_sha256}",
    ]
    for artifact in target.artifacts:
        lines.extend(
            [
                f"- Artifact role: {_safe_text(artifact.role)}",
                f"  - Artifact ID: {_safe_text(artifact.artifact_id)}",
                f"  - Artifact digest: {artifact.sha256}",
                f"  - Artifact bytes: {artifact.byte_size}",
            ]
        )
    lines.extend(["", "## Lineage Findings"])
    for finding in report.findings:
        lines.extend(
            [
                "",
                f"### {_safe_text(finding.rule_id)}",
                "",
                f"- Status: {finding.status.value.upper()}",
                f"- Message: {_safe_text(finding.message)}",
                "- Evidence:",
                "    "
                + html.escape(
                    json.dumps(
                        finding.evidence,
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    quote=False,
                ),
            ]
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_safe_text(item)}" for item in report.limitations)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Report schema: {_safe_text(report.report_schema)}",
            f"- Provenance SHA-256: {report.provenance_sha256}",
            f"- Canonicalization: {_safe_text(envelope.integrity.canonicalization)}",
            f"- Report SHA-256: {envelope.integrity.sha256}",
            "",
        ]
    )
    return "\n".join(lines)
