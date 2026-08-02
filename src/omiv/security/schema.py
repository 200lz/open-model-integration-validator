"""Explicit Phase 5F schema registry; model validation rejects unknown fields."""

from __future__ import annotations

from pydantic import BaseModel

from omiv.security.models import (
    CoverageSummary,
    CustodySecurityLinkage,
    GovernanceSecurityEvidenceAdapter,
    PassportSecuritySummary,
    ScannerIdentity,
    SecurityArtifactIndex,
    SecurityEvaluationResult,
    SecurityEvidenceBundle,
    SecurityEvidencePolicy,
    SecurityFinding,
    SecurityInspectionPlan,
    SecurityReport,
    SecurityScanExecutionInput,
    SecurityScanExecutionRecord,
)

SECURITY_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "omiv.security-inspection-plan.v1": SecurityInspectionPlan,
    "omiv.security-scan-execution-input.v1": SecurityScanExecutionInput,
    "omiv.security-scan-execution-record.v1": SecurityScanExecutionRecord,
    "omiv.scanner-identity.v1": ScannerIdentity,
    "omiv.security-finding.v1": SecurityFinding,
    "omiv.security-coverage.v1": CoverageSummary,
    "omiv.security-evidence-bundle.v1": SecurityEvidenceBundle,
    "omiv.security-evidence-policy.v1": SecurityEvidencePolicy,
    "omiv.security-evaluation.v1": SecurityEvaluationResult,
    "omiv.security-report.v1": SecurityReport,
    "omiv.governance-security-evidence-adapter.v1": GovernanceSecurityEvidenceAdapter,
    "omiv.passport-security-summary.v1": PassportSecuritySummary,
    "omiv.custody-security-linkage.v1": CustodySecurityLinkage,
    "omiv.security-artifact-index.v1": SecurityArtifactIndex,
}


def schema_model(schema_id: str) -> type[BaseModel]:
    try:
        return SECURITY_SCHEMA_MODELS[schema_id]
    except KeyError as exc:
        raise ValueError(f"unknown Phase 5F schema {schema_id!r}") from exc
