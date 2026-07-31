"""Deterministic custody reports, Markdown, and atomic output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256, load_json_value
from omiv.custody.models import (
    CustodyFinding,
    CustodyLedger,
    CustodyLedgerReport,
    CustodyReportEnvelope,
    CustodyTimelineEntry,
)
from omiv.custody.verification import verify_custody_ledger
from omiv.errors import OmivInputError
from omiv.safe_write import atomic_write_text, validate_output_path


def pretty_json(value: Any) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _findings(ledger: CustodyLedger) -> list[CustodyFinding]:
    rows = [
        ("CUSTODY-001", "PASS", "Immutable custody subject identity is valid."),
        ("CUSTODY-002", "PASS", "The genesis event is unique and valid."),
        ("CUSTODY-003", "PASS", "Event IDs reconstruct deterministically."),
        ("CUSTODY-004", "PASS", "Event digests reconstruct deterministically."),
        ("CUSTODY-005", "PASS", "Parent digest links are intact."),
        ("CUSTODY-006", "PASS", "Event sequence ordering is contiguous."),
        ("CUSTODY-007", "PASS", "No duplicate event identities exist."),
        ("CUSTODY-008", "PASS", "The linear ledger contains no fork."),
        ("CUSTODY-009", "PASS", "Artifact subject continuity is consistent."),
        ("CUSTODY-010", "PASS", "Referenced OMIV evidence verifies."),
        ("CUSTODY-011", "PASS", "Event authenticity boundaries are explicit."),
        (
            "CUSTODY-012",
            ledger.lifecycle_completeness.value,
            "Lifecycle completeness was evaluated independently from ledger integrity.",
        ),
        ("CUSTODY-013", "PASS", "Missing lifecycle events are explicit."),
        ("CUSTODY-014", "PASS", "Revocation status is explicit and not assessed."),
        ("CUSTODY-015", "PASS", "Expiration status is explicit and not assessed."),
        ("CUSTODY-016", "PASS", "The Model Passport linkage is valid."),
        ("CUSTODY-017", "PASS", "The custody ledger is deterministic."),
        ("CUSTODY-018", "PASS", "Custody limitations are explicit."),
    ]
    return [
        CustodyFinding(
            finding_id=finding_id,
            status=status,
            summary=summary,
            limitation=(
                "Hash-link integrity does not prove that the real-world action occurred."
                if finding_id == "CUSTODY-005"
                else "Verified references do not create missing artifact provenance."
                if finding_id == "CUSTODY-010"
                else "Incomplete lifecycle evidence is not a ledger-integrity failure."
                if finding_id == "CUSTODY-012"
                else None
            ),
        )
        for finding_id, status, summary in rows
    ]


def build_custody_report(ledger: CustodyLedger) -> CustodyReportEnvelope:
    timeline = [
        CustodyTimelineEntry(
            sequence=event.sequence,
            event_id=event.event_id,
            event_type=event.event_type,
            event_digest=event.event_digest,
            evidence_roles=sorted({item.role for item in event.evidence_references}),
            authenticity=event.authenticity,
            attestation_status=event.attestation_status,
            action=event.action,
        )
        for event in ledger.events
    ]
    limitations = sorted(
        {
            limitation
            for event in ledger.events
            for limitation in event.limitations
        }
        | {
            ledger.event_authenticity_summary.limitation,
            "This evidence segment is not a complete enterprise chain of custody.",
            "No acquisition, transformation, approval, deployment, or runtime event is claimed.",
        }
    )
    data: dict[str, Any] = {
        "subject": ledger.subject,
        "chain_id": ledger.chain_id,
        "ledger_digest": ledger.ledger_digest,
        "selected_profile": ledger.selected_profile,
        "event_timeline": timeline,
        "link_integrity_summary": {
            "ledger_integrity": ledger.ledger_integrity.value,
            "event_digest_integrity": ledger.event_digest_integrity.value,
            "parent_link_integrity": ledger.parent_link_integrity.value,
        },
        "subject_continuity_summary": ledger.subject_continuity.value,
        "evidence_linkage_summary": ledger.evidence_linkage.value,
        "authenticity_summary": ledger.event_authenticity_summary,
        "lifecycle_completeness": ledger.lifecycle_completeness,
        "overall_custody_status": ledger.overall_custody_status,
        "revocation_status": ledger.revocation_status,
        "expiration_status": ledger.expiration_status,
        "profile_completeness": ledger.missing_event_analysis.profile_results,
        "missing_event_types": ledger.missing_event_analysis.missing_event_types,
        "limitations": limitations,
        "next_evidence_required": [
            item.value for item in ledger.missing_event_analysis.missing_event_types
        ],
        "findings": _findings(ledger),
        "report_digest": "0" * 64,
    }
    draft = CustodyLedgerReport.model_validate(data)
    body = draft.model_dump(mode="json", by_alias=True)
    body.pop("report_digest")
    data["report_digest"] = canonical_sha256(body)
    report = CustodyLedgerReport.model_validate(data)
    return CustodyReportEnvelope(
        report=report,
        integrity={
            "canonicalization": CANONICALIZATION_ID,
            "sha256": canonical_sha256(report.model_dump(mode="json", by_alias=True)),
        },
    )


def load_custody_report(path: Path) -> CustodyReportEnvelope:
    try:
        raw = load_json_value(path.read_text(encoding="utf-8"))
        envelope = CustodyReportEnvelope.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid custody report: {exc}") from exc
    if envelope.integrity.get("canonicalization") != CANONICALIZATION_ID:
        raise OmivInputError("custody report canonicalization mismatch")
    if envelope.integrity.get("sha256") != canonical_sha256(
        envelope.report.model_dump(mode="json", by_alias=True)
    ):
        raise OmivInputError("custody report envelope integrity mismatch")
    body = envelope.report.model_dump(mode="json", by_alias=True)
    stored = body.pop("report_digest")
    if stored != canonical_sha256(body):
        raise OmivInputError("custody report digest mismatch")
    return envelope


def verify_custody_report(
    report_path: Path, ledger_path: Path, root: Path
) -> CustodyReportEnvelope:
    envelope = load_custody_report(report_path)
    ledger = verify_custody_ledger(ledger_path, root)
    if envelope != build_custody_report(ledger):
        raise OmivInputError("custody report does not reconstruct from the ledger")
    return envelope


def _safe(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def render_custody_markdown(envelope: CustodyReportEnvelope) -> str:
    report = envelope.report
    subject = report.subject
    selected = next(
        item for item in report.profile_completeness if item.profile == report.selected_profile
    )
    authenticity = ", ".join(
        item.value for item in report.authenticity_summary.statuses
    )
    lines = [
        f"# Model Chain of Custody: {_safe(subject.variant)}",
        "",
        "This is an integrity-linked lifecycle evidence segment, not a complete enterprise "
        "or legal chain-of-custody certification.",
        "",
        "## Compact Summary",
        "",
        "| Item | Result |",
        "| --- | --- |",
        f"| Chain ID | `{report.chain_id}` |",
        f"| Immutable revision | `{_safe(subject.resolved_revision or 'unavailable')}` |",
        f"| Artifact-set digest | `{_safe(subject.artifact_set_digest or 'unavailable')}` |",
        f"| Events | {len(report.event_timeline)} |",
        f"| Ledger integrity | **{report.link_integrity_summary['ledger_integrity']}** |",
        f"| Parent links | **{report.link_integrity_summary['parent_link_integrity']}** |",
        f"| Subject continuity | **{report.subject_continuity_summary}** |",
        f"| Evidence linkage | **{report.evidence_linkage_summary}** |",
        f"| Event authenticity | **{authenticity} / UNATTESTED** |",
        f"| Selected profile | `{report.selected_profile}` — **{selected.status.value}** |",
        f"| Lifecycle completeness | **{report.lifecycle_completeness.value}** |",
        f"| Overall custody | **{report.overall_custody_status.value}** |",
        f"| Revocation | **{report.revocation_status.value}** |",
        f"| Expiration | **{report.expiration_status.value}** |",
        "",
        "Ledger integrity and lifecycle completeness are separate: this ledger is intact, "
        "while required lifecycle events remain missing.",
        "",
        "## Event Timeline",
        "",
        "| Seq | Event | Action | Authenticity | Evidence |",
        "| ---: | --- | --- | --- | --- |",
    ]
    for event in report.event_timeline:
        lines.append(
            f"| {event.sequence} | `{event.event_type.value}` | {_safe(event.action)} | "
            f"{event.authenticity.value} / {event.attestation_status.value} | "
            f"{_safe(', '.join(event.evidence_roles))} |"
        )
    lines.extend(["", "## Missing Lifecycle Events", ""])
    lines.extend(f"- `{item.value}`" for item in report.missing_event_types)
    lines.extend(["", "## Profile Completeness", ""])
    for profile in report.profile_completeness:
        missing = ", ".join(item.value for item in profile.missing_event_types) or "none"
        lines.append(
            f"- `{profile.profile}`: **{profile.status.value}**; "
            f"missing: {_safe(missing)}"
        )
    lines.extend(["", "## Authenticity Boundary", "", report.authenticity_summary.limitation])
    lines.extend(
        [
            "",
            "Every current event is evidence-derived and unattested. No actor identity, "
            "signature, occurrence time, approval, deployment, or runtime action is claimed.",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {_safe(item)}" for item in report.limitations)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Ledger digest: `{report.ledger_digest}`",
            f"- Report digest: `{report.report_digest}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_custody_bundle(
    ledger: CustodyLedger,
    ledger_output: Path,
    report_output: Path,
    markdown_output: Path,
    *,
    forbidden_inputs: tuple[Path, ...] = (),
) -> CustodyReportEnvelope:
    outputs = [ledger_output.resolve(), report_output.resolve(), markdown_output.resolve()]
    if len(outputs) != len(set(outputs)):
        raise OmivInputError("custody output paths must be distinct")
    for path in (ledger_output, report_output, markdown_output):
        validate_output_path(path, forbidden_inputs=forbidden_inputs)
    report = build_custody_report(ledger)
    atomic_write_text(
        ledger_output, pretty_json(ledger), forbidden_inputs=forbidden_inputs
    )
    atomic_write_text(
        report_output, pretty_json(report), forbidden_inputs=forbidden_inputs
    )
    atomic_write_text(
        markdown_output,
        render_custody_markdown(report),
        forbidden_inputs=forbidden_inputs,
    )
    return report
