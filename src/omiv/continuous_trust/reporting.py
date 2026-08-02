"""Deterministic Phase 5H JSON and Markdown reporting."""

from __future__ import annotations

from pydantic import BaseModel

from omiv.canonical import canonical_json_bytes
from omiv.continuous_trust.building import build_report
from omiv.continuous_trust.models import (
    AuditBundleCompleteness,
    AuditBundleManifest,
    AuditBundleReport,
    AuditBundleVerificationResult,
    TrustSnapshot,
)


def pretty_audit_json(value: BaseModel) -> str:
    import json

    return json.dumps(value.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n"


def render_audit_markdown(report: AuditBundleReport) -> str:
    gaps = "\n".join(f"- {x}" for x in report.outstanding_gaps) or "- None for declared purpose"
    limitations = "\n".join(f"- {x}" for x in report.limitations)
    return f"""# OMIV Historical Audit Bundle Report

- Evidence range: {report.evidence_range}
- Latest supplied snapshot: `{report.latest_supplied_snapshot_id}`
- Snapshot cutoff: `{report.latest_snapshot_cutoff}`
- Historical knowledge mode: `{report.knowledge_mode.value}`
- Policy: `{report.policy_set_id}` (`{report.policy_set_digest}`)
- Bundle purpose: `{report.purpose.value}`
- Bundle complete for: declared purpose only (`{report.completeness.value}`)
- Verification: `{report.verification.value}`
- Continuous monitoring: `NOT_IMPLEMENTED`
- Continuous observation: `NOT_ESTABLISHED`
- Trusted timestamp: `{report.trusted_timestamp}`
- Model payload included: `NO`
- Historical records modified: `NO`
- Revoked records retained: `YES`

## Outstanding gaps

{gaps}

## Limitations

{limitations}

No new evidence does not prove that no real-world change occurred.
"""


def verify_audit_report(
    report: AuditBundleReport,
    bundle: AuditBundleManifest,
    completeness: AuditBundleCompleteness,
    verification: AuditBundleVerificationResult,
    snapshot: TrustSnapshot,
) -> AuditBundleReport:
    expected = build_report(bundle, completeness, verification, snapshot)
    if canonical_json_bytes(report.model_dump(mode="json", by_alias=True)) != canonical_json_bytes(
        expected.model_dump(mode="json", by_alias=True)
    ):
        raise ValueError("audit report reconstruction mismatch")
    return report
