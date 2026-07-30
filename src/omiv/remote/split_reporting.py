"""Integrity envelopes and deterministic reports for split GGUF aggregation."""

from __future__ import annotations

import html
import json
from pathlib import Path

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.remote.models import Integrity, RemoteResult, ReportExecution
from omiv.remote.reporting import safe_markdown_text
from omiv.remote.split_models import (
    SplitGGUFInventory,
    SplitGGUFReport,
    SplitInventoryEnvelope,
    SplitReportEnvelope,
)

MAX_SPLIT_ARTIFACT_BYTES = 1024 * 1024 * 1024


def build_split_inventory_envelope(
    inventory: SplitGGUFInventory,
) -> SplitInventoryEnvelope:
    return SplitInventoryEnvelope(
        inventory=inventory,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(inventory.model_dump(mode="json")),
        ),
    )


def split_inventory_integrity_matches(envelope: SplitInventoryEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.inventory.model_dump(mode="json")
    )


def load_split_inventory(path: Path) -> SplitInventoryEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_SPLIT_ARTIFACT_BYTES)
        envelope = SplitInventoryEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid remote split GGUF inventory: {exc}") from exc
    if not split_inventory_integrity_matches(envelope):
        raise OmivInputError("remote split GGUF inventory integrity mismatch")
    return envelope


def build_split_report(inventory: SplitInventoryEnvelope) -> SplitReportEnvelope:
    if not split_inventory_integrity_matches(inventory):
        raise OmivInputError("cannot report an invalid split inventory")
    findings = inventory.inventory.findings
    result = (
        RemoteResult.FAIL
        if any(item.status == RemoteResult.FAIL for item in findings)
        else RemoteResult.WARN
        if any(item.status == RemoteResult.WARN for item in findings)
        else RemoteResult.PASS
    )
    report = SplitGGUFReport(
        execution=ReportExecution(
            result=result, exit_code=1 if result == RemoteResult.FAIL else 0
        ),
        inventory_sha256=inventory.integrity.sha256,
        inventory=inventory.inventory,
        findings=findings,
        limitations=[
            "Metadata consistency applies only the recorded structural policy.",
            "Tensor names and shapes are not interpreted as Kimi K3 semantics.",
            "Payload spans use recorded GGML block layouts without reading payload bytes.",
            "Bounded spans do not prove payload presence, integrity, or quantization fidelity.",
            "No HF-to-GGUF mapping or runtime parity claim is made.",
        ],
    )
    return SplitReportEnvelope(
        report=report,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(report.model_dump(mode="json")),
        ),
    )


def split_report_integrity_matches(envelope: SplitReportEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.report.model_dump(mode="json")
    )


def load_split_report(path: Path) -> SplitReportEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_SPLIT_ARTIFACT_BYTES)
        envelope = SplitReportEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid remote split GGUF report: {exc}") from exc
    return envelope


def pretty_split_json(value: SplitInventoryEnvelope | SplitReportEnvelope) -> str:
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


def render_split_markdown(envelope: SplitReportEnvelope) -> str:
    report = envelope.report
    inventory = report.inventory
    lines = [
        "# Remote Split GGUF Report",
        "",
        "## Result",
        "",
        report.execution.result.value.upper(),
        "",
        "## Pinned Collection",
        "",
        f"- Repository: {safe_markdown_text(inventory.repository.repo_id)}",
        f"- Resolved revision: {inventory.repository.resolved_revision}",
        f"- Snapshot SHA-256: {inventory.snapshot_sha256}",
        f"- Shards: {inventory.shard_count}",
        f"- Declared split count: {inventory.declared_split_count}",
        f"- Repository bytes: {inventory.total_repository_bytes}",
        f"- Accepted header bytes: {inventory.total_header_bytes_accepted}",
        f"- Range requests: {inventory.total_request_count}",
        "",
        "## Split Identity",
        "",
        "| File ordinal | Header index | Header ordinal | Declared count | Agreement |",
        "| ---: | ---: | ---: | ---: | --- |",
    ]
    for item in inventory.split_identities:
        lines.append(
            f"| {item.filename_ordinal} | {item.header_split_index} | "
            f"{item.normalized_header_ordinal} | {item.header_split_count} | "
            f"{'yes' if item.agrees else 'no'} |"
        )
    lines.extend(
        [
            "",
            "## Tensor and Payload Summary",
            "",
            f"- Declared global tensor count: {inventory.global_tensor_count_metadata}",
            f"- Aggregated descriptors: {inventory.aggregated_tensor_count}",
            f"- Exact duplicate names: {inventory.duplicate_summary.exact_duplicate_count}",
            f"- Conflicting names: {inventory.duplicate_summary.conflict_count}",
            f"- Bounded spans: {inventory.payload_span_summary.bounded_count}",
            f"- Unsupported spans: {inventory.payload_span_summary.unsupported_count}",
            f"- Invalid spans: {inventory.payload_span_summary.invalid_count}",
            f"- Overlaps: {inventory.payload_span_summary.overlap_count}",
            "",
            "## Per-Shard Summary",
            "",
            "| Ordinal | Path | Metadata | Tensors | Header bytes | Requests | Span result |",
            "| ---: | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for shard in inventory.shard_summaries:
        lines.append(
            f"| {shard.filename_ordinal} | {safe_markdown_text(shard.path)} | "
            f"{shard.metadata_count} | {shard.tensor_count} | "
            f"{shard.accepted_header_bytes} | {shard.request_count} | "
            f"{safe_markdown_text(shard.payload_span_result)} |"
        )
    lines.extend(["", "## Findings"])
    for finding in report.findings:
        evidence = json.dumps(
            finding.evidence,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        lines.extend(
            [
                "",
                f"### {safe_markdown_text(finding.rule_id)}",
                "",
                f"- Status: {finding.status.value.upper()}",
                f"- Message: {safe_markdown_text(finding.message)}",
                "- Evidence:",
                "",
                "    " + html.escape(evidence, quote=False),
            ]
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {safe_markdown_text(item)}" for item in report.limitations)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Inventory SHA-256: {report.inventory_sha256}",
            f"- Aggregation policy SHA-256: {inventory.aggregation_policy_sha256}",
            f"- Metadata policy SHA-256: {inventory.metadata_policy_sha256}",
            f"- GGML type policy SHA-256: {inventory.ggml_type_policy_sha256}",
            f"- Report SHA-256: {envelope.integrity.sha256}",
            "",
        ]
    )
    return "\n".join(lines)
