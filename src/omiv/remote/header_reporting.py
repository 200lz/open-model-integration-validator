"""Integrity envelopes and reports for remote GGUF header inventories."""

from __future__ import annotations

import html
import json
from pathlib import Path

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.remote.header_models import (
    HeaderInventoryEnvelope,
    HeaderReportEnvelope,
    RemoteGGUFHeaderInventory,
    RemoteGGUFHeaderReport,
    build_header_findings,
)
from omiv.remote.models import Integrity, RemoteResult, ReportExecution
from omiv.remote.reporting import safe_markdown_text

MAX_HEADER_ARTIFACT_BYTES = 128 * 1024 * 1024


def build_header_inventory_envelope(
    inventory: RemoteGGUFHeaderInventory,
) -> HeaderInventoryEnvelope:
    return HeaderInventoryEnvelope(
        inventory=inventory,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(inventory.model_dump(mode="json")),
        ),
    )


def header_inventory_integrity_matches(envelope: HeaderInventoryEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.inventory.model_dump(mode="json")
    )


def load_header_inventory(path: Path) -> HeaderInventoryEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_HEADER_ARTIFACT_BYTES)
        envelope = HeaderInventoryEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid remote GGUF header inventory: {exc}") from exc
    if not header_inventory_integrity_matches(envelope):
        raise OmivInputError("remote GGUF header inventory integrity mismatch")
    return envelope


def build_header_report(
    inventory_envelope: HeaderInventoryEnvelope,
) -> HeaderReportEnvelope:
    if not header_inventory_integrity_matches(inventory_envelope):
        raise OmivInputError("cannot report an invalid header inventory envelope")
    report = RemoteGGUFHeaderReport(
        execution=ReportExecution(result=RemoteResult.PASS, exit_code=0),
        inventory_sha256=inventory_envelope.integrity.sha256,
        inventory=inventory_envelope.inventory,
        findings=build_header_findings(inventory_envelope.inventory),
        limitations=[
            "Metadata PASS validates binary encoding, not semantic correctness.",
            "Tensor descriptor PASS is per-file syntax, not Kimi K3 architecture evidence.",
            "No tensor payload byte, payload digest, or payload value was accessed.",
            "No cross-shard consistency or split-model claim is made.",
        ],
    )
    return HeaderReportEnvelope(
        report=report,
        integrity=Integrity(
            canonicalization=CANONICALIZATION_ID,
            sha256=canonical_sha256(report.model_dump(mode="json")),
        ),
    )


def header_report_integrity_matches(envelope: HeaderReportEnvelope) -> bool:
    return envelope.integrity.sha256 == canonical_sha256(
        envelope.report.model_dump(mode="json")
    )


def load_header_report(path: Path) -> HeaderReportEnvelope:
    try:
        raw, _ = load_bounded_json(path, max_bytes=MAX_HEADER_ARTIFACT_BYTES)
        envelope = HeaderReportEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid remote GGUF header report: {exc}") from exc
    return envelope


def pretty_header_json(
    value: HeaderInventoryEnvelope | HeaderReportEnvelope,
) -> str:
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


def render_header_markdown(envelope: HeaderReportEnvelope) -> str:
    report = envelope.report
    inventory = report.inventory
    lines = [
        "# Remote GGUF Header Report",
        "",
        "## Result",
        "",
        report.execution.result.value.upper(),
        "",
        "## Pinned Artifact",
        "",
        f"- Provider: {safe_markdown_text(inventory.provider)}",
        f"- Repository: {safe_markdown_text(inventory.repository.repo_id)}",
        f"- Resolved revision: {safe_markdown_text(inventory.repository.resolved_revision)}",
        f"- File: {safe_markdown_text(inventory.file.path)}",
        f"- Repository declared size: {inventory.file.byte_size}",
        f"- Snapshot SHA-256: {inventory.snapshot_sha256}",
        "",
        "## Header Boundary",
        "",
        f"- GGUF version: {inventory.gguf_version}",
        f"- Metadata entries: {inventory.metadata_count}",
        f"- Tensor descriptors: {inventory.tensor_count}",
        f"- Alignment: {inventory.alignment}",
        f"- Metadata and descriptor end (exclusive): {inventory.metadata_and_descriptor_end}",
        f"- Padding length: {inventory.padding_length}",
        f"- Header end / payload start (exclusive): {inventory.payload_start_offset}",
        f"- Highest accepted offset (inclusive): {inventory.highest_accepted_offset}",
        f"- Accepted remote bytes: {inventory.total_remote_bytes_accepted}",
        f"- HTTP Range requests: {inventory.request_count}",
        f"- Payload relation: {safe_markdown_text(inventory.summary.payload_relation)}",
        "",
        "## Largest Metadata Entries",
        "",
        "| Key | Type | Encoded bytes |",
        "| --- | --- | ---: |",
    ]
    for entry in inventory.summary.largest_metadata_entries:
        lines.append(
            f"| {safe_markdown_text(entry.key)} | "
            f"{safe_markdown_text(entry.value_type.value)} | "
            f"{entry.encoded_byte_length} |"
        )
    lines.extend(
        [
            "",
            "## Representative Tensor Descriptors",
            "",
            "| Name | Dimensions (GGUF order) | Type | Relative offset |",
            "| --- | --- | --- | ---: |",
        ]
    )
    tensors = {item.name: item for item in inventory.tensors}
    for name in inventory.summary.representative_tensor_names:
        tensor = tensors[name]
        dimensions = " × ".join(str(value) for value in tensor.dimensions)
        lines.append(
            f"| {safe_markdown_text(tensor.name)} | "
            f"{safe_markdown_text(dimensions)} | "
            f"{safe_markdown_text(tensor.ggml_type_name)} | {tensor.data_offset} |"
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
            f"- Parser policy SHA-256: {inventory.parser_policy_sha256}",
            f"- Report SHA-256: {envelope.integrity.sha256}",
            f"- Canonicalization: {safe_markdown_text(envelope.integrity.canonicalization)}",
            "",
        ]
    )
    return "\n".join(lines)
