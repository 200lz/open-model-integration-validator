"""Phase 6A schema registry."""

from pydantic import BaseModel

from omiv.payload_integrity import models

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "omiv.payload-inventory-plan.v1": models.PayloadInventoryPlan,
    "omiv.payload-expectation.v1": models.PayloadExpectation,
    "omiv.payload-expectation-materialization.v1": models.PayloadExpectationMaterialization,
    "omiv.payload-publisher-authority-evaluation.v1": (models.PayloadPublisherAuthorityEvaluation),
    "omiv.observed-payload-manifest.v1": models.ObservedPayloadManifest,
    "omiv.payload-hash-execution-record.v1": models.PayloadHashExecutionRecord,
    "omiv.payload-manifest-comparison.v1": models.PayloadManifestComparison,
    "omiv.payload-integrity-policy.v1": models.PayloadIntegrityPolicy,
    "omiv.payload-integrity-evidence.v1": models.PayloadIntegrityEvidence,
    "omiv.payload-integrity-report.v1": models.PayloadIntegrityReport,
    "omiv.payload-integrity-integration.v1": models.IntegrationLink,
    "omiv.payload-artifact-index.v1": models.PayloadArtifactIndex,
}
