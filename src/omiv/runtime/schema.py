"""Phase 5G schema registry."""

from typing import cast

from omiv.runtime import models

RUNTIME_SCHEMA_MODELS = {
    "omiv.product-subject.v1": models.ProductSubject,
    "omiv.deployment-artifact-set.v1": models.DeploymentArtifactSet,
    "omiv.deployment-configuration-identity.v1": models.DeploymentConfigurationIdentity,
    "omiv.assertion-authority-scope.v1": models.AssertionAuthorityScope,
    "omiv.deployment-instance-identity.v1": models.DeploymentInstanceIdentity,
    "omiv.deployment-intent.v1": models.DeploymentIntent,
    "omiv.deployment-manifest.v1": models.DeploymentManifest,
    "omiv.deployment-record.v1": models.DeploymentRecord,
    "omiv.runtime-engine-identity.v1": models.RuntimeEngineIdentity,
    "omiv.runtime-environment-identity.v1": models.RuntimeEnvironmentIdentity,
    "omiv.runtime-observer-identity.v1": models.RuntimeObserverIdentity,
    "omiv.replay-protection-context.v1": models.ReplayProtectionContext,
    "omiv.runtime-observation-plan.v1": models.RuntimeObservationPlan,
    "omiv.observation-coverage.v1": models.ObservationCoverage,
    "omiv.runtime-observation.v1": models.RuntimeObservation,
    "omiv.continuity-policy.v1": models.ContinuityPolicy,
    "omiv.drift-finding.v1": models.DriftFinding,
    "omiv.continuity-evaluation.v1": models.ContinuityEvaluation,
    "omiv.deployment-runtime-report.v1": models.DeploymentRuntimeReport,
    "omiv.governance-runtime-adapter.v1": models.GovernanceRuntimeAdapter,
    "omiv.passport-runtime-summary.v1": models.PassportRuntimeSummary,
    "omiv.custody-runtime-linkage.v1": models.CustodyRuntimeLinkage,
    "omiv.signed-runtime-linkage.v1": models.SignedRuntimeLinkage,
    "omiv.runtime-adapter-identity.v1": models.AdapterIdentity,
    "omiv.runtime-artifact-index.v1": models.RuntimeArtifactIndex,
}


def schema_model(schema_id: str) -> type[models.RuntimeModel]:
    try:
        return cast(type[models.RuntimeModel], RUNTIME_SCHEMA_MODELS[schema_id])
    except KeyError as exc:
        raise ValueError(f"unknown runtime schema {schema_id!r}") from exc
