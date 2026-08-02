"""Static Phase 5G adapter registry and derived governance, Passport, custody records."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.governance.models import (
    EvidenceCategory,
    EvidenceReference,
    GovernanceSubject,
    ReferenceAvailability,
    VerificationMode,
)
from omiv.runtime.building import build_adapter, identified
from omiv.runtime.models import (
    AdapterIdentity,
    ContinuityEvaluation,
    ContinuityVerdict,
    CustodyRuntimeLinkage,
    DeploymentManifest,
    DeploymentRecord,
    GovernanceRuntimeAdapter,
    PassportRuntimeSummary,
    RuntimeObservation,
    ScopeContext,
)

RESERVED_ADAPTER_IDS = {
    "omiv.adapter.oci-runtime.v1",
    "omiv.adapter.kubernetes.v1",
    "omiv.adapter.vllm.v1",
    "omiv.adapter.triton.v1",
    "omiv.adapter.tensorrt-llm.v1",
    "omiv.adapter.llama-cpp.v1",
    "omiv.adapter.mlx.v1",
    "omiv.adapter.ollama.v1",
    "omiv.adapter.lm-studio.v1",
    "omiv.adapter.cloud-endpoint.v1",
    "omiv.adapter.internal-platform.v1",
    "omiv.adapter.air-gapped-appliance.v1",
}


def adapter_registry(scope: ScopeContext) -> dict[str, AdapterIdentity]:
    return {
        "omiv.adapter.local-runtime.v1": build_adapter(scope),
        **{
            value: build_adapter(scope, value, operational=False)
            for value in sorted(RESERVED_ADAPTER_IDS)
        },
    }


def get_adapter(
    adapter_id: str, scope: ScopeContext, *, operational: bool = False
) -> AdapterIdentity:
    registry = adapter_registry(scope)
    if adapter_id not in registry:
        raise OmivInputError("unknown runtime adapter schema or version")
    adapter = registry[adapter_id]
    if operational and not adapter.operational:
        raise OmivInputError("reserved platform adapter fails closed operationally in Phase 5G")
    return adapter


def import_local_record(value: dict[str, Any], model: type[Any], adapter: AdapterIdentity) -> Any:
    """Normalize strict local JSON only; arbitrary verdict summaries are rejected."""
    trusted_adapter = adapter_registry(adapter.scope).get(adapter.adapter_id)
    if trusted_adapter is None or trusted_adapter != adapter:
        raise OmivInputError("runtime adapter identity or implementation digest mismatch")
    if not adapter.operational:
        raise OmivInputError("reserved adapter cannot normalize operational evidence")
    if any(key in value for key in ("pass", "passed", "runtime_verified", "deployed")):
        raise OmivInputError("arbitrary runtime PASS/deployment summary is not evidence")
    if value.get("schema") not in adapter.supported_output_schemas:
        raise OmivInputError("adapter does not support the normalized output schema")
    try:
        record = model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid normalized runtime record: {exc}") from exc
    strength = getattr(getattr(record, "assertion", None), "origin", None)
    if strength is not None and strength not in adapter.accepted_evidence_origins:
        raise OmivInputError("adapter output exceeds its declared evidence-strength ceiling")
    configuration = getattr(record, "configuration", None)
    if (
        configuration is not None
        and configuration.normalization_policy_digest != adapter.normalization_policy_digest
    ):
        raise OmivInputError("adapter normalization policy does not match the record")
    return record


def adapt_governance_runtime(
    evaluation: ContinuityEvaluation,
    *,
    source_security_verdict: str,
    source_security_limitations: list[str],
    allow_limited_security: bool,
) -> GovernanceRuntimeAdapter:
    if source_security_verdict == "PASS_WITH_LIMITATIONS" and not allow_limited_security:
        raise OmivInputError("strict governance policy rejects limited security evidence")
    source_limited = (
        bool(source_security_limitations) or source_security_verdict == "PASS_WITH_LIMITATIONS"
    )
    if evaluation.verdict == ContinuityVerdict.PASS and source_limited:
        deployment = runtime = continuity = "SATISFIED_WITH_LIMITATIONS"
    elif evaluation.verdict == ContinuityVerdict.PASS:
        deployment, runtime, continuity = "SATISFIED", "SATISFIED", "SATISFIED"
    elif evaluation.verdict == ContinuityVerdict.PASS_WITH_LIMITATIONS:
        deployment = runtime = continuity = "SATISFIED_WITH_LIMITATIONS"
    elif evaluation.verdict == ContinuityVerdict.IDENTITY_PROXY_MATCH:
        deployment, runtime, continuity = "SATISFIED_WITH_LIMITATIONS", "PROXY_ONLY", "PARTIAL"
    elif evaluation.verdict in {ContinuityVerdict.DRIFT_DETECTED, ContinuityVerdict.MISMATCH}:
        deployment, runtime, continuity = "SATISFIED", "SATISFIED", evaluation.verdict.value
    elif evaluation.verdict == ContinuityVerdict.EVIDENCE_BROKEN:
        deployment = runtime = continuity = "BROKEN"
    else:
        deployment, runtime, continuity = "MISSING", "MISSING", "NOT_EVALUATED"
    body = {
        "schema": "omiv.governance-runtime-adapter.v1",
        "subject_id": evaluation.subject_id,
        "instance_id": evaluation.instance_id,
        "continuity_evaluation_id": evaluation.evaluation_id,
        "continuity_evaluation_digest": evaluation.evaluation_digest,
        "source_security_verdict": source_security_verdict,
        "source_security_limitations": sorted(source_security_limitations),
        "deployment_evidence_outcome": deployment,
        "runtime_observation_outcome": runtime,
        "continuity_outcome": continuity,
        "limitations": sorted({*evaluation.limitations, *source_security_limitations}),
    }
    return GovernanceRuntimeAdapter.model_validate(
        identified(body, "adapter_id", "governance_runtime_", "adapter_digest")
    )


def governance_runtime_evidence_references(
    governance_subject: GovernanceSubject,
    manifest: DeploymentManifest,
    evaluation: ContinuityEvaluation,
) -> list[EvidenceReference]:
    """Emit Phase 5E references only from a matching reconstructed Phase 5G evaluation."""
    if governance_subject.artifact_set_digest != manifest.artifact_set.artifact_set_digest:
        raise OmivInputError("governance runtime adapter artifact-set subject mismatch")
    primary = next(item for item in manifest.artifact_set.members if item.role.value == "PRIMARY")
    if governance_subject.artifact_digest != primary.artifact.content_digest:
        raise OmivInputError("governance runtime adapter primary-artifact subject mismatch")
    if evaluation.artifact_set_id != manifest.artifact_set.artifact_set_id:
        raise OmivInputError("governance runtime adapter evaluation artifact-set mismatch")
    if evaluation.instance_id != manifest.instance.instance_id:
        raise OmivInputError("governance runtime adapter deployment-instance mismatch")
    if evaluation.verdict not in {
        ContinuityVerdict.PASS,
        ContinuityVerdict.PASS_WITH_LIMITATIONS,
    }:
        raise OmivInputError("blocking or incomplete continuity cannot satisfy governance")
    limitations = sorted(set(evaluation.limitations))
    trust = (
        "TRUSTED_BY_POLICY"
        if evaluation.observer_trust == "TRUSTED_BY_POLICY"
        else "UNTRUSTED_BY_POLICY"
    )
    return [
        EvidenceReference(
            evidence_id=(
                f"runtime_evidence_{category.value.lower()}_{evaluation.evaluation_digest[:24]}"
            ),
            category=category,
            schema="omiv.deployment-runtime-evidence.v1",
            object_id=evaluation.evaluation_id,
            digest=evaluation.evaluation_digest,
            subject_id=governance_subject.subject_id,
            governance_policy_id=evaluation.policy_id,
            availability=ReferenceAvailability.INCLUDED,
            verification_mode=VerificationMode.FULL,
            source_phase="5G",
            trust_status=trust,
            provenance_strength="SNAPSHOT_CONTINUITY",
            limitations=limitations,
        )
        for category in (EvidenceCategory.DEPLOYMENT, EvidenceCategory.RUNTIME_OBSERVATION)
    ]


def build_passport_runtime_summary(
    passport_id: str,
    passport_digest: str,
    manifest: DeploymentManifest,
    record: DeploymentRecord,
    observation: RuntimeObservation,
    evaluation: ContinuityEvaluation,
) -> PassportRuntimeSummary:
    body = {
        "schema": "omiv.passport-runtime-summary.v1",
        "passport_id": passport_id,
        "passport_digest": passport_digest,
        "subject_id": evaluation.subject_id,
        "artifact_set_id": evaluation.artifact_set_id,
        "instance_id": evaluation.instance_id,
        "deployment_declared": record.status.value.endswith("DECLARED"),
        "deployment_observed": record.status.value
        in {"COMPLETED_OBSERVED", "ROLLED_BACK_OBSERVED"},
        "runtime_observed": observation.status.value.startswith("COMPLETED"),
        "observation_strength": observation.assertion.origin.value,
        "observation_coverage": observation.coverage.status.value,
        "artifact_set_continuity": evaluation.artifact_set_continuity.value,
        "configuration_continuity": evaluation.configuration_continuity.value,
        "engine_continuity": evaluation.engine_continuity.value,
        "observer_trust": evaluation.observer_trust,
        "observer_authority": evaluation.observer_authority.value,
        "freshness": evaluation.freshness.value,
        "replay_status": evaluation.replay_status,
        "verdict": evaluation.verdict.value,
        "limitations": evaluation.limitations,
        "behavioral_parity": "NOT_CHECKED",
        "runtime_safety": "NOT_VERIFIED",
        "continuous_continuity": "NOT_ESTABLISHED",
    }
    return PassportRuntimeSummary.model_validate(
        identified(body, "summary_id", "passport_runtime_", "summary_digest")
    )


def build_custody_runtime_linkage(
    chain_id: str,
    ledger_digest: str,
    record: DeploymentRecord,
    observation: RuntimeObservation,
    evaluation: ContinuityEvaluation,
) -> CustodyRuntimeLinkage:
    events = [
        "DEPLOYMENT_INTENT_RECORDED",
        "DEPLOYMENT_RECORD_RECORDED",
        "RUNTIME_OBSERVATION_RECORDED",
    ]
    if evaluation.drift_findings:
        events.append("RUNTIME_DRIFT_DETECTED")
    if evaluation.verdict == ContinuityVerdict.REPLAY_REJECTED:
        events.append("RUNTIME_REPLAY_REJECTED")
    body = {
        "schema": "omiv.custody-runtime-linkage.v1",
        "chain_id": chain_id,
        "ledger_digest": ledger_digest,
        "subject_id": evaluation.subject_id,
        "artifact_set_id": evaluation.artifact_set_id,
        "instance_id": evaluation.instance_id,
        "event_types": events,
        "evidence_origin": observation.assertion.origin.value,
        "observer_authority": evaluation.observer_authority.value,
        "observation_coverage": observation.coverage.status.value,
        "verdict": evaluation.verdict.value,
        "limitations": sorted(
            {*record.limitations, *observation.limitations, *evaluation.limitations}
        ),
    }
    return CustodyRuntimeLinkage.model_validate(
        identified(body, "linkage_id", "custody_runtime_", "linkage_digest")
    )
