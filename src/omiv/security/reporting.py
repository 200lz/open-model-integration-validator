"""Bounded loading and deterministic JSON/Markdown security reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.safe_write import atomic_write_text, validate_output_path
from omiv.security.building import identified
from omiv.security.models import (
    CoverageResult,
    FindingSeverity,
    SecurityEvaluationResult,
    SecurityEvidenceBundle,
    SecurityEvidencePolicy,
    SecurityInspectionPlan,
    SecurityReport,
)

MAX_SECURITY_JSON_BYTES = 16 * 1024 * 1024
T = TypeVar("T")


def _load(path: Path, model: type[T]) -> T:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("security input must be a regular non-symlink file")
    raw, _ = load_bounded_json(path, max_bytes=MAX_SECURITY_JSON_BYTES)
    try:
        return model.model_validate(raw)  # type: ignore[attr-defined,no-any-return]
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid security record: {exc}") from exc


def load_plan(path: Path) -> SecurityInspectionPlan:
    return _load(path, SecurityInspectionPlan)


def load_bundle(path: Path) -> SecurityEvidenceBundle:
    return _load(path, SecurityEvidenceBundle)


def load_policy(path: Path) -> SecurityEvidencePolicy:
    return _load(path, SecurityEvidencePolicy)


def load_evaluation(path: Path) -> SecurityEvaluationResult:
    return _load(path, SecurityEvaluationResult)


def load_report(path: Path) -> SecurityReport:
    return _load(path, SecurityReport)


def pretty_json(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_security_report(
    bundle: SecurityEvidenceBundle,
    evaluation: SecurityEvaluationResult,
) -> SecurityReport:
    if evaluation.bundle_digest != bundle.bundle_digest:
        raise OmivInputError("security report bundle/evaluation mismatch")
    counts = {
        severity: sum(x.severity == severity for x in bundle.findings)
        for severity in FindingSeverity
    }
    scanner_capability_coverage = (
        CoverageResult.UNSUPPORTED
        if bundle.unsupported_items
        else CoverageResult.COMPLETE
        if evaluation.required_methods_satisfied
        else CoverageResult.PARTIAL
    )
    body = {
        "schema": "omiv.security-report.v1",
        "bundle_id": bundle.bundle_id,
        "bundle_digest": bundle.bundle_digest,
        "evaluation": evaluation.model_dump(mode="json", by_alias=True),
        "scanner_ids": sorted(x.scanner_id for x in bundle.scanner_identities),
        "scanner_trust": evaluation.scanner_trust.value,
        "scanner_correctness_independently_proven": "NOT_ESTABLISHED",
        "methods": sorted(
            {
                method.value
                for record in bundle.execution_records
                for method in record.methods_executed
            }
        ),
        "execution_statuses": [x.status.value for x in bundle.execution_records],
        "declared_scope_paths": bundle.inspection_plan.scope.logical_paths,
        "declared_scope_coverage": bundle.coverage.status.value,
        "scanner_capability_coverage": scanner_capability_coverage.value,
        "declared_files": bundle.coverage.declared_files,
        "discovered_files": bundle.coverage.discovered_files,
        "files_inspected": bundle.coverage.inspected_files,
        "total_declared_bytes": bundle.coverage.total_declared_bytes,
        "total_discovered_bytes": bundle.coverage.total_discovered_bytes,
        "bytes_inspected": bundle.coverage.total_inspected_bytes,
        "bytes_not_inspected": bundle.coverage.bytes_not_inspected,
        "payload_bytes_read": any(x.payload_bytes_read for x in bundle.execution_records),
        "code_execution": False,
        "network_access": False,
        "finding_counts": {severity.value: counts[severity] for severity in FindingSeverity},
        "blocking_findings": len(evaluation.blocking_finding_ids),
        "unsupported_items": [x.model_dump(mode="json") for x in bundle.unsupported_items],
        "scan_errors": [x.model_dump(mode="json") for x in bundle.scan_errors],
        "signature_status": evaluation.signature_trust,
        "payload_integrity": "NOT_VERIFIED",
        "behavioral_runtime_safety": "NOT_VERIFIED",
        "no_findings_warning": "No findings does not prove safety or absence of vulnerabilities.",
        "limitations": sorted(set(evaluation.limitations)),
        "next_required_actions": [
            "Resolve blocking findings, unsupported scope, and scanner errors before strict "
            "promotion.",
            "Obtain separate payload-integrity, approval, deployment, and runtime evidence "
            "where required.",
        ],
    }
    return SecurityReport.model_validate(
        identified(body, "report_id", "security_report_", "report_digest")
    )


def verify_security_report(
    observed: SecurityReport,
    bundle: SecurityEvidenceBundle,
    evaluation: SecurityEvaluationResult,
) -> SecurityReport:
    expected = build_security_report(bundle, evaluation)
    if expected != observed:
        raise OmivInputError("security report does not match deterministic reconstruction")
    return observed


def render_security_markdown(report: SecurityReport) -> str:
    finding_lines = [
        f"- {severity.value}: {report.finding_counts[severity]}" for severity in FindingSeverity
    ]
    limitation_lines = [f"- {item}" for item in report.limitations]
    unsupported_lines = [
        f"- `{item.logical_path}`: {item.reason}" for item in report.unsupported_items
    ] or ["- None declared"]
    scope_lines = [f"- `{item}`" for item in report.declared_scope_paths] or ["- Empty scope"]
    return "\n".join(
        [
            "# OMIV Artifact Security Evidence Report",
            "",
            f"- Report: `{report.report_id}`",
            f"- Policy: `{report.evaluation.policy_id}`",
            f"- Security verdict under policy: **{report.evaluation.verdict.value}**",
            f"- Scanner identities: `{', '.join(report.scanner_ids)}`",
            f"- Scanner accepted by policy: **{report.scanner_trust.value}**",
            "- Scanner correctness independently proven: **NOT_ESTABLISHED**",
            f"- Inspection type: `{', '.join(item.value for item in report.methods)}`",
            f"- Declared-scope coverage: **{report.declared_scope_coverage.value}**",
            f"- Policy coverage result: **{report.evaluation.coverage_result.value}**",
            f"- Scanner-capability coverage: **{report.scanner_capability_coverage.value}**",
            f"- Files declared/discovered/inspected: {report.declared_files}/"
            f"{report.discovered_files}/{report.files_inspected}",
            f"- Bytes declared/discovered/inspected/not inspected: "
            f"{report.total_declared_bytes}/{report.total_discovered_bytes}/"
            f"{report.bytes_inspected}/{report.bytes_not_inspected}",
            f"- Payload bytes read: {'YES (BOUNDED)' if report.payload_bytes_read else 'NO'}",
            "- Code execution: **NO**",
            "- Network access: **NO**",
            f"- Blocking findings: {report.blocking_findings}",
            "- Payload integrity: **NOT_VERIFIED (SEPARATE)**",
            "- Behavioral/runtime safety: **NOT_VERIFIED**",
            "- Approval: **SEPARATE**",
            "- Deployment: **NOT_PERFORMED**",
            "",
            "## Declared inspection scope",
            "",
            *scope_lines,
            "",
            "## Findings by severity",
            "",
            *finding_lines,
            "",
            "## Unsupported scope",
            "",
            *unsupported_lines,
            "",
            "## Limitations",
            "",
            *limitation_lines,
            "",
            "> No findings does not prove safety or absence of vulnerabilities. A PASS only means",
            "> the supplied, verified evidence satisfies the selected policy for the declared "
            "scope.",
            "> Static inspection does not establish runtime safety, behavior, payload integrity,",
            "> tokenizer parity, or numerical fidelity.",
            "",
        ]
    )


def write_security_outputs(
    *,
    bundle_path: Path,
    bundle: SecurityEvidenceBundle,
    report_path: Path | None = None,
    report: SecurityReport | None = None,
    markdown_path: Path | None = None,
    forbidden_inputs: tuple[Path, ...] = (),
) -> None:
    outputs = [bundle_path, *(x for x in (report_path, markdown_path) if x is not None)]
    if len({x.resolve(strict=False) for x in outputs}) != len(outputs):
        raise OmivInputError("security outputs must use distinct paths")
    for output in outputs:
        validate_output_path(output, forbidden_inputs=forbidden_inputs)
    atomic_write_text(bundle_path, pretty_json(bundle), forbidden_inputs=forbidden_inputs)
    if report_path is not None and report is not None:
        atomic_write_text(report_path, pretty_json(report), forbidden_inputs=forbidden_inputs)
    if markdown_path is not None and report is not None:
        atomic_write_text(
            markdown_path, render_security_markdown(report), forbidden_inputs=forbidden_inputs
        )
