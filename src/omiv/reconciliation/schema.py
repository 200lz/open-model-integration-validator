"""Phase 6B schema registry and canonical input loading."""

from pathlib import Path

from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.reconciliation import models

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "omiv.remote-artifact-locator.v1": models.RemoteArtifactLocator,
    "omiv.remote-snapshot-plan.v1": models.RemoteSnapshotPlan,
    "omiv.remote-collection-execution-record.v1": models.RemoteCollectionExecutionRecord,
    "omiv.remote-digest-descriptor.v1": models.RemoteDigestDescriptor,
    "omiv.remote-member-record.v1": models.RemoteMemberRecord,
    "omiv.remote-snapshot-manifest.v1": models.RemoteSnapshotManifest,
    "omiv.shard-topology.v1": models.ShardTopology,
    "omiv.shard-completeness-assessment.v1": models.ShardCompletenessAssessment,
    "omiv.remote-snapshot-expectation.v1": models.RemoteSnapshotExpectation,
    "omiv.remote-publisher-authority-evaluation.v1": (models.RemotePublisherAuthorityEvaluation),
    "omiv.remote-local-reconciliation-policy.v1": models.RemoteLocalReconciliationPolicy,
    "omiv.remote-local-reconciliation-comparison.v1": (models.RemoteLocalReconciliationComparison),
    "omiv.remote-local-reconciliation-evidence.v1": (models.RemoteLocalReconciliationEvidence),
    "omiv.remote-local-reconciliation-report.v1": models.RemoteLocalReconciliationReport,
    "omiv.reconciliation-local-manifest-reference.v1": models.LocalManifestReference,
    "omiv.remote-local-integration.v1": models.RemoteLocalIntegration,
    "omiv.reconciliation-artifact-index.v1": models.ReconciliationArtifactIndex,
}


def load_reconciliation(path: Path, model: type[BaseModel]) -> BaseModel:
    if path.is_symlink() or not path.is_file():
        raise OmivInputError("reconciliation input must be a regular non-symlink file")
    raw, _ = load_bounded_json(path, max_bytes=64 * 1024 * 1024)
    try:
        return model.model_validate(raw)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid reconciliation record: {exc}") from exc


def load_any_reconciliation(path: Path) -> BaseModel:
    raw, _ = load_bounded_json(path, max_bytes=64 * 1024 * 1024)
    schema = raw.get("schema")
    model = SCHEMA_MODELS.get(schema)
    if model is None:
        raise OmivInputError("unsupported reconciliation schema")
    try:
        return model.model_validate(raw)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid reconciliation record: {exc}") from exc
