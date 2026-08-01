"""Deterministic governance JSON, Markdown, loading, and reconstruction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypeVar, cast

from pydantic import ValidationError

from omiv.canonical import load_json_value
from omiv.errors import OmivInputError
from omiv.governance.evaluation import verify_governance_report
from omiv.governance.models import (
    ApprovalCreateInput,
    ApprovalQuorumResult,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalRequestCreateInput,
    GovernancePolicy,
    GovernanceReport,
    PolicyDecisionRecord,
    PolicyEvaluationInput,
    PromotionDecisionRecord,
    PromotionGatePolicy,
    PromotionTarget,
    RejectionRecord,
    ReleaseCandidate,
    SeparationOfDutiesResult,
)
from omiv.safe_write import atomic_write_text

MAX_GOVERNANCE_INPUT_BYTES = 8 * 1024 * 1024
T = TypeVar("T")


def pretty_json(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=True)
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _read(path: Path) -> object:
    try:
        if path.is_symlink() or not path.is_file():
            raise OmivInputError("governance input must be a regular non-symlink file")
        if path.stat().st_size > MAX_GOVERNANCE_INPUT_BYTES:
            raise OmivInputError("governance input exceeds the bounded input limit")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot read governance input: {exc}") from exc


def _load(path: Path, model: type[T], label: str) -> T:
    try:
        return cast(T, model.model_validate(_read(path)))  # type: ignore[attr-defined]
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid {label}: {exc}") from exc


def load_policy(path: Path) -> GovernancePolicy:
    return _load(path, GovernancePolicy, "governance policy")


def load_evaluation_input(path: Path) -> PolicyEvaluationInput:
    return _load(path, PolicyEvaluationInput, "policy evaluation input")


def load_decision(path: Path) -> PolicyDecisionRecord:
    return _load(path, PolicyDecisionRecord, "policy decision")


def load_approval_request(path: Path) -> ApprovalRequest:
    return _load(path, ApprovalRequest, "approval request")


def load_approval_request_input(path: Path) -> ApprovalRequestCreateInput:
    return _load(path, ApprovalRequestCreateInput, "approval request input")


def load_approval(path: Path) -> ApprovalRecord:
    return _load(path, ApprovalRecord, "approval record")


def load_approval_input(path: Path) -> ApprovalCreateInput:
    return _load(path, ApprovalCreateInput, "approval input")


def load_quorum_result(path: Path) -> ApprovalQuorumResult:
    return _load(path, ApprovalQuorumResult, "approval quorum result")


def load_separation_result(path: Path) -> SeparationOfDutiesResult:
    return _load(path, SeparationOfDutiesResult, "separation-of-duties result")


def load_rejection(path: Path) -> RejectionRecord:
    return _load(path, RejectionRecord, "rejection record")


def load_target(path: Path) -> PromotionTarget:
    return _load(path, PromotionTarget, "promotion target")


def load_gate_policy(path: Path) -> PromotionGatePolicy:
    return _load(path, PromotionGatePolicy, "promotion gate policy")


def load_candidate(path: Path) -> ReleaseCandidate:
    return _load(path, ReleaseCandidate, "release candidate")


def load_promotion_decision(path: Path) -> PromotionDecisionRecord:
    return _load(path, PromotionDecisionRecord, "promotion decision")


def load_report(path: Path) -> GovernanceReport:
    return _load(path, GovernanceReport, "governance report")


def render_markdown(report: GovernanceReport) -> str:
    requirements = "\n".join(
        f"| `{item.requirement_id}` | {item.category.value} | {item.outcome.value} | "
        f"{'YES' if item.blocking else 'NO'} |"
        for item in report.requirement_results
    )
    blockers = "\n".join(f"- `{item}`" for item in report.blockers) or "- None"
    missing = (
        "\n".join(
            f"- {item.category.value}: {item.current_status.value}; {item.remediation}"
            for item in report.missing_evidence.items
        )
        or "- None"
    )
    limitations = "\n".join(f"- {item}" for item in report.limitations)
    approval = (
        f"request `{report.approval_request_id}`; records={len(report.approval_record_ids)}; "
        f"rejections={len(report.rejection_record_ids)}"
        if report.approval_request_id
        else "NOT_EVALUATED"
    )
    promotion = report.promotion_outcome.value if report.promotion_outcome else "NOT_EVALUATED"
    conditions = ", ".join(report.promotion_conditions) or "NONE"
    return (
        "# OMIV Governance Report\n\n"
        f"- Report: `{report.report_id}`\n"
        f"- Subject: `{report.subject.subject_id}`\n"
        f"- Artifact digest: `{report.subject.artifact_digest}`\n"
        f"- Policy: `{report.policy_id}` (`{report.policy_digest}`)\n"
        f"- Policy decision: **{report.decision_outcome.value}** under the selected policy\n"
        f"- Approval status: {approval}\n"
        f"- Logical promotion permission: **{promotion}**\n"
        f"- Logical target: `{report.promotion_target_id or 'NONE'}`\n"
        f"- Conditions: {conditions}\n"
        f"- Promotion performed: **{report.promotion_performed}**\n"
        f"- Registry write: **{report.registry_write}**\n"
        f"- Security evidence: **{report.security_status}**\n"
        f"- Deployment performed: **{report.deployment_status}**\n"
        f"- Runtime observation: **{report.runtime_status}**\n\n"
        "A policy decision proves only that supplied evidence was evaluated against the named "
        "policy. It does not independently prove underlying claims. Promotion permission does "
        "not prove upload, deployment, or runtime observation.\n\n"
        "## Evidence requirements\n\n"
        "| Requirement | Category | Outcome | Blocking |\n"
        "|---|---|---|---|\n"
        f"{requirements}\n\n"
        "## Blockers\n\n"
        f"{blockers}\n\n"
        "## Missing evidence\n\n"
        f"{missing}\n\n"
        "## Limitations\n\n"
        f"{limitations}\n"
    )


def write_outputs(
    value: object,
    output: Path,
    *,
    markdown: tuple[GovernanceReport, Path] | None = None,
    forbidden_inputs: tuple[Path, ...] = (),
) -> None:
    atomic_write_text(output, pretty_json(value), forbidden_inputs=forbidden_inputs)
    if markdown is not None:
        report, path = markdown
        atomic_write_text(path, render_markdown(report), forbidden_inputs=forbidden_inputs)


def verify_report_file(
    path: Path, decision: PolicyDecisionRecord, **kwargs: object
) -> GovernanceReport:
    observed = load_report(path)
    return verify_governance_report(observed, decision, **kwargs)
