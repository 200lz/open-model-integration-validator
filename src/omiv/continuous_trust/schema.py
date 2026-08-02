"""Phase 5H strict schema registry and bounded loaders."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from omiv.continuous_trust import models
from omiv.hf.json_loader import load_bounded_json

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "omiv.evidence-set-manifest.v1": models.EvidenceSetManifest,
    "omiv.trust-snapshot.v1": models.TrustSnapshot,
    "omiv.historical-event.v1": models.HistoricalEvent,
    "omiv.trust-transition.v1": models.TrustTransition,
    "omiv.trust-timeline.v1": models.TrustTimeline,
    "omiv.timeline-fork.v1": models.TimelineFork,
    "omiv.historical-evaluation-request.v1": models.HistoricalEvaluationRequest,
    "omiv.historical-evaluation-result.v1": models.HistoricalEvaluationResult,
    "omiv.reevaluation-policy-set.v1": models.ReevaluationPolicySet,
    "omiv.revocation-propagation-result.v1": models.RevocationPropagationResult,
    "omiv.supersession-graph.v1": models.SupersessionGraph,
    "omiv.freshness-transition-result.v1": models.FreshnessTransitionResult,
    "omiv.renewal-record.v1": models.RenewalRecord,
    "omiv.audit-bundle-manifest.v1": models.AuditBundleManifest,
    "omiv.audit-bundle-completeness.v1": models.AuditBundleCompleteness,
    "omiv.audit-bundle-verification-result.v1": models.AuditBundleVerificationResult,
    "omiv.audit-bundle-report.v1": models.AuditBundleReport,
    "omiv.passport-historical-summary.v1": models.PassportHistoricalSummary,
    "omiv.custody-historical-linkage.v1": models.CustodyHistoricalLinkage,
    "omiv.governance-historical-adapter.v1": models.GovernanceHistoricalAdapter,
    "omiv.signed-historical-linkage.v1": models.SignedHistoricalLinkage,
    "omiv.continuous-trust-artifact-index.v1": models.ContinuousTrustArtifactIndex,
}
T = TypeVar("T", bound=BaseModel)


def load_audit(path: Path, model: type[T]) -> T:
    raw, _ = load_bounded_json(path, max_bytes=16 * 1024 * 1024)
    return model.model_validate(raw)
