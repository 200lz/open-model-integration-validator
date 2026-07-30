"""Deterministic integrity envelopes and Markdown for remote evidence."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.remote.models import (
    Integrity,
    PrefixProbeReport,
    RangeProbeReport,
    RemoteFinding,
    RemoteResult,
    RemoteSeverity,
    ReportEnvelope,
    ReportExecution,
    RepositorySnapshot,
    SnapshotEnvelope,
    SnapshotReport,
)

MAX_REMOTE_JSON_BYTES = 16 * 1024 * 1024


def snapshot_envelope(snapshot: RepositorySnapshot) -> SnapshotEnvelope:
    payload = snapshot.model_dump(mode="json")
    return SnapshotEnvelope(
        snapshot=snapshot,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(payload),
        ),
    )


def snapshot_integrity_matches(envelope: SnapshotEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.snapshot.model_dump(mode="json")
    )


def load_snapshot(path: Path) -> SnapshotEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_REMOTE_JSON_BYTES)
        envelope = SnapshotEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid remote snapshot: {exc}") from exc
    if not snapshot_integrity_matches(envelope):
        raise OmivInputError("remote snapshot integrity mismatch")
    return envelope


def _finding(rule_id: str, status: RemoteResult, message: str, **evidence: Any) -> RemoteFinding:
    severity = {
        RemoteResult.PASS: RemoteSeverity.INFO,
        RemoteResult.WARN: RemoteSeverity.WARNING,
        RemoteResult.FAIL: RemoteSeverity.ERROR,
    }[status]
    return RemoteFinding(
        rule_id=rule_id,
        severity=severity,
        status=status,
        message=message,
        evidence=evidence,
    )


def _execution(findings: list[RemoteFinding]) -> ReportExecution:
    result = (
        RemoteResult.FAIL
        if any(item.status == RemoteResult.FAIL for item in findings)
        else RemoteResult.WARN
        if any(item.status == RemoteResult.WARN for item in findings)
        else RemoteResult.PASS
    )
    return ReportExecution(result=result, exit_code=1 if result == RemoteResult.FAIL else 0)


def build_snapshot_report(envelope: SnapshotEnvelope) -> ReportEnvelope:
    snapshot = envelope.snapshot
    candidates = snapshot.summary.candidate_split_sets
    complete_layout = (
        bool(candidates)
        and all(item.complete for item in candidates)
        and not snapshot.summary.extra_gguf_files
    )
    metadata_complete = all(item.byte_size >= 0 for item in snapshot.files)
    findings = [
        _finding(
            "REMOTE-001",
            RemoteResult.PASS,
            "Repository revision resolved to an immutable commit.",
            requested_revision=snapshot.repository.requested_revision,
            resolved_revision=snapshot.repository.resolved_revision,
        ),
        _finding(
            "REMOTE-002",
            RemoteResult.PASS,
            "All selected paths passed canonical POSIX path validation.",
            selected_path_count=len(snapshot.files),
            strict_subtree=snapshot.selection.strict_subtree,
        ),
        _finding(
            "REMOTE-003",
            RemoteResult.PASS if metadata_complete and snapshot.files else RemoteResult.FAIL,
            "Selected file sizes are present and valid."
            if metadata_complete and snapshot.files
            else "Selection is empty or selected file size metadata is incomplete.",
            file_count=len(snapshot.files),
        ),
        _finding(
            "REMOTE-004",
            RemoteResult.PASS if complete_layout else RemoteResult.FAIL,
            "Candidate split filenames are complete."
            if complete_layout
            else "Filename-only candidate split evidence is incomplete.",
            candidate_count=len(candidates),
            complete_candidate_count=sum(item.complete for item in candidates),
            extra_gguf_file_count=len(snapshot.summary.extra_gguf_files),
        ),
        _finding(
            "REMOTE-005",
            RemoteResult.PASS,
            "No duplicate selected file identities were observed.",
            unique_file_count=len(snapshot.files),
        ),
        _finding(
            "REMOTE-006",
            RemoteResult.PASS,
            "Snapshot uses canonical ordering and deterministic payload hashing.",
            snapshot_sha256=envelope.integrity.sha256,
        ),
    ]
    report = SnapshotReport(
        report_schema="omiv.remote-snapshot-report.v1",
        execution=_execution(findings),
        snapshot_sha256=envelope.integrity.sha256,
        repository=snapshot.repository,
        selection=snapshot.selection,
        summary=snapshot.summary,
        findings=findings,
        limitations=[
            "Filename completeness is repository-layout evidence, not GGUF-header validation.",
            "No tensor payload bytes were requested by repository enumeration.",
        ],
    )
    return report_envelope(report)


def report_envelope(
    report: SnapshotReport | RangeProbeReport | PrefixProbeReport,
) -> ReportEnvelope:
    return ReportEnvelope(
        report=report,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(report.model_dump(mode="json")),
        ),
    )


def report_integrity_matches(envelope: ReportEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.report.model_dump(mode="json")
    )


def load_remote_report(path: Path) -> ReportEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_REMOTE_JSON_BYTES)
        envelope = ReportEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid remote report: {exc}") from exc
    return envelope


def pretty_json(value: SnapshotEnvelope | ReportEnvelope) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def safe_markdown_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=True)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, f"\\{character}")
    return text


_safe = safe_markdown_text


def render_markdown(envelope: ReportEnvelope) -> str:
    report = envelope.report
    title = {
        "omiv.remote-snapshot-report.v1": "Remote Repository Snapshot",
        "omiv.remote-range-probe-report.v1": "Remote Bounded Range Probe",
        "omiv.remote-gguf-prefix-report.v1": "Remote GGUF Prefix Probe",
    }[report.report_schema]
    lines = [
        f"# {_safe(title)}",
        "",
        "## Result",
        "",
        report.execution.result.value.upper(),
        "",
        "## Repository",
        "",
        "- Provider: huggingface",
        f"- Repository: {_safe(report.repository.repo_id)}",
        f"- Requested revision: {_safe(report.repository.requested_revision)}",
        f"- Resolved revision: {_safe(report.repository.resolved_revision)}",
    ]
    if isinstance(report, SnapshotReport):
        lines.extend(
            [
                f"- Selected files: {report.summary.file_count}",
                f"- Total declared bytes: {report.summary.total_byte_size}",
                f"- Candidate split sets: {len(report.summary.candidate_split_sets)}",
            ]
        )
    else:
        range_evidence = (
            report.evidence
            if isinstance(report, RangeProbeReport)
            else report.bounded_range_evidence
        )
        lines.extend(
            [
                f"- File: {_safe(range_evidence.path)}",
                f"- Requested range: {range_evidence.requested_range.offset}\\-"
                f"{range_evidence.requested_range.end}",
                f"- Response bytes: {range_evidence.response_byte_count}",
                f"- Response SHA\\-256: {_safe(range_evidence.response_sha256)}",
            ]
        )
        if isinstance(report, PrefixProbeReport):
            lines.extend(
                [
                    f"- GGUF magic valid: {str(report.gguf_magic_valid).lower()}",
                    f"- GGUF version: {_safe(report.version)}",
                    f"- Claim: {_safe(report.claim)}",
                ]
            )
    lines.extend(["", "## Findings"])
    for finding in report.findings:
        finding_evidence = json.dumps(
            finding.evidence,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        lines.extend(
            [
                "",
                f"### {_safe(finding.rule_id)}",
                "",
                f"- Status: {finding.status.value.upper()}",
                f"- Message: {_safe(finding.message)}",
                "- Evidence:",
                "",
                "    " + html.escape(finding_evidence, quote=False),
            ]
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_safe(item)}" for item in report.limitations)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Report schema: {_safe(report.report_schema)}",
            f"- Canonicalization: {_safe(envelope.integrity.canonicalization)}",
            f"- Report SHA\\-256: {envelope.integrity.sha256}",
            "",
        ]
    )
    return "\n".join(lines)
