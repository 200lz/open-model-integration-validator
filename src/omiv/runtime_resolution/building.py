"""Deterministic builders for Phase 6E canonical evidence."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, TypeVar

from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.runtime.models import ProductSubject
from omiv.runtime_resolution.models import (
    AssumptionRegisterEntry,
    AssumptionStatus,
    AttestationMethod,
    AuthorityDimension,
    AuthorityStatus,
    BackendComparisonStatus,
    BackendDescriptor,
    BackendExecutionPlan,
    BackendExecutionRecord,
    BackendProbeDefinition,
    BackendResult,
    BackendResultObservation,
    ComparisonFinding,
    ContentAvailability,
    ContentIdentity,
    ContinuityOutcome,
    CoverageDimension,
    CrossBackendComparison,
    CrossBackendProbeSet,
    DenominatorAvailability,
    DeploymentDeclaration,
    DeploymentObservation,
    EvidenceStatus,
    ExecutionMode,
    IdentifierClassification,
    IdentifierKind,
    InferenceAttestation,
    InferenceIdentity,
    ModelRuntimeBinding,
    ObjectReference,
    ObservationLevel,
    ObservationStrength,
    OutputProvenanceEvidence,
    PolicyRequirement,
    ProofAvailability,
    ProvenanceVerificationStatus,
    ProviderRoutingStatement,
    RegistryResolutionReceipt,
    RequestedModelIdentifier,
    RequirementStatus,
    ResolutionContinuityAssessment,
    ResolutionExecutionRecord,
    ResolutionMechanism,
    ResolutionPlan,
    ResolutionStatus,
    ResultDimension,
    RoutingRule,
    RuntimeArtifactExpectation,
    RuntimeBindingOutcome,
    RuntimeIdentityExpectation,
    RuntimeIdentityObservation,
    RuntimeResolutionArtifactIndex,
    RuntimeResolutionArtifactIndexEntry,
    RuntimeResolutionAuthorityEvaluation,
    RuntimeResolutionIntegrationSummary,
    RuntimeResolutionLimits,
    RuntimeResolutionParityEvidence,
    RuntimeResolutionPolicy,
    RuntimeResolutionPolicyEvaluation,
    RuntimeResolutionReport,
    RuntimeResolutionScenarioCatalog,
    RuntimeResolutionScenarioResult,
    TypedParameter,
    finalize_identity,
    object_reference,
    verify_object_reference,
)

CanonicalModel = TypeVar("CanonicalModel", bound=BaseModel)


def build_canonical(model: type[CanonicalModel], body: dict[str, Any]) -> CanonicalModel:
    """Finalize one registered object with its schema-specific domain separator."""
    schema = str(body.get("schema"))
    from omiv.runtime_resolution.models import IDENTITY_SPECS

    try:
        id_field, digest_field, prefix = IDENTITY_SPECS[schema]
    except KeyError as exc:
        raise ValueError(f"unregistered Phase 6E canonical schema: {schema}") from exc
    return model.model_validate(finalize_identity(body, id_field, prefix, digest_field))


def coverage(
    dimension: str,
    numerator: int,
    denominator: int | None,
    *,
    scope: str = "declared.scope",
    reason: str | None = None,
) -> CoverageDimension:
    return CoverageDimension(
        dimension=dimension,
        numerator=numerator,
        denominator=denominator,
        denominator_availability=(
            DenominatorAvailability.AVAILABLE
            if denominator is not None
            else DenominatorAvailability.UNAVAILABLE
        ),
        selected_scope=scope,
        incomplete_reason=reason,
    )


def build_requested_identifier(
    subject: ProductSubject,
    requested: str,
    *,
    kind: IdentifierKind,
    provider: str = "provider.synthetic",
    namespace: str = "namespace.synthetic",
    api_surface: str = "api.synthetic",
    purpose: str = "inference.request",
) -> RequestedModelIdentifier:
    return build_canonical(
        RequestedModelIdentifier,
        {
            "schema": "omiv.requested-model-identifier.v1",
            "subject": subject,
            "scope": "runtime.resolution",
            "provider": provider,
            "namespace": namespace,
            "api_surface": api_surface,
            "purpose": purpose,
            "requested_identifier": requested,
            "requested_kind": kind,
            "provenance": "caller.declared",
            "requested_at": "NOT_RECORDED",
            "limitations": [
                "Requested identifier spelling does not prove immutability or weights."
            ],
        },
    )


def build_identifier_classification(
    subject: ProductSubject,
    requested: RequestedModelIdentifier,
    *,
    kind: IdentifierKind,
    provenance: ObservationLevel = ObservationLevel.CALLER_DECLARED,
    evidence: Iterable[ObjectReference] = (),
    authority: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    effective_from: str = "NOT_RECORDED",
) -> IdentifierClassification:
    return build_canonical(
        IdentifierClassification,
        {
            "schema": "omiv.identifier-classification.v1",
            "subject": subject,
            "scope": "runtime.resolution",
            "requested_identifier": object_reference(requested),
            "kind": kind,
            "provenance": provenance,
            "authority": authority,
            "effective_from": effective_from,
            "effective_until": "NOT_RECORDED",
            "mutability_evidence": sorted(
                evidence, key=lambda item: (item.schema_id, item.object_id)
            ),
            "evaluated_at": "NOT_RECORDED",
            "limitations": ["Identifier classification is not a runtime observation."],
        },
    )


def build_resolution_plan(
    subject: ProductSubject,
    requested: RequestedModelIdentifier,
    classification: IdentifierClassification,
    *,
    network_policy: str = "OFFLINE",
) -> ResolutionPlan:
    verify_object_reference(classification.requested_identifier, requested)
    return build_canonical(
        ResolutionPlan,
        {
            "schema": "omiv.resolution-plan.v1",
            "subject": subject,
            "scope": "runtime.resolution",
            "requested_identifier": object_reference(requested),
            "classification": object_reference(classification),
            "lookup_kind": "supplied.evidence",
            "permitted_sources": [
                ObservationLevel.CALLER_DECLARED,
                ObservationLevel.PROVIDER_DOCUMENTED_POLICY,
            ],
            "limits": RuntimeResolutionLimits(),
            "planned_at": "NOT_RECORDED",
            "network_policy": network_policy,
            "limitations": ["Plan contains no future execution, receipt, or evidence reference."],
        },
    )


def build_resolution_execution(
    subject: ProductSubject,
    plan: ResolutionPlan,
    supplied_inputs: Iterable[ObjectReference] = (),
    *,
    request_count: int = 0,
    status: str = "COMPLETED",
) -> ResolutionExecutionRecord:
    return build_canonical(
        ResolutionExecutionRecord,
        {
            "schema": "omiv.resolution-execution-record.v1",
            "subject": subject,
            "scope": plan.scope,
            "plan": object_reference(plan),
            "supplied_inputs": sorted(
                supplied_inputs, key=lambda item: (item.schema_id, item.object_id)
            ),
            "tool_identity": "omiv.phase6e.resolution.v1",
            "status": status,
            "request_count": request_count,
            "context": "offline.supplied.evidence",
            "executed_at": "NOT_RECORDED",
            "limitations": ["Execution record contains no resulting receipt or evidence ID."],
        },
    )


def build_routing_statement(
    subject: ProductSubject,
    *,
    provider: str,
    source_fixture_digest: str,
    source_url: str,
    rules: Iterable[RoutingRule],
    kind: str = "PROVIDER_DOCUMENTED_ROUTING_POLICY",
    api_surface: str = "api.provider.documentation",
    document_published_at: str = "NOT_RECORDED",
    document_updated_at: str = "NOT_RECORDED",
) -> ProviderRoutingStatement:
    return build_canonical(
        ProviderRoutingStatement,
        {
            "schema": "omiv.provider-routing-statement.v1",
            "subject": subject,
            "scope": "provider.documented.policy",
            "provider": provider,
            "api_surface": api_surface,
            "source_fixture_digest": source_fixture_digest,
            "source_url": source_url,
            "statement_kind": kind,
            "rules": sorted(
                rules,
                key=lambda rule: (
                    rule.requested_identifier.encode(),
                    rule.documented_target.encode(),
                ),
            ),
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "document_published_at": document_published_at,
            "document_updated_at": document_updated_at,
            "available_at": "NOT_RECORDED",
            "observed_at": "NOT_RECORDED",
            "evaluated_at": "NOT_RECORDED",
            "supplied_at": "NOT_RECORDED",
            "limitations": [
                "Public documentation is not observation of production request resolution."
            ],
        },
    )


def build_resolution_receipt(
    subject: ProductSubject,
    execution: ResolutionExecutionRecord,
    requested: RequestedModelIdentifier,
    *,
    status: ResolutionStatus,
    resolved: str | None,
    resolved_kind: IdentifierKind,
    level: ObservationLevel,
    evidence_digest: str,
    evidence: ObjectReference | None = None,
    mechanism: ResolutionMechanism = ResolutionMechanism.CALLER_SUPPLIED,
    redirect_chain: Iterable[Any] = (),
    resolved_at: str = "NOT_RECORDED",
    effective_at: str = "NOT_RECORDED",
    authority: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
) -> RegistryResolutionReceipt:
    if execution.subject != subject or requested.subject != subject:
        raise ValueError("resolution receipt subject mismatch")
    evidence_reference = evidence or object_reference(execution)
    if evidence_digest != evidence_reference.object_digest:
        raise ValueError("resolution evidence digest does not match referenced evidence")
    return build_canonical(
        RegistryResolutionReceipt,
        {
            "schema": "omiv.registry-resolution-receipt.v1",
            "subject": subject,
            "scope": "runtime.resolution",
            "execution": object_reference(execution),
            "provider": requested.provider,
            "namespace": requested.namespace,
            "api_surface": requested.api_surface,
            "purpose": requested.purpose,
            "requested_identifier": object_reference(requested),
            "lookup_kind": "supplied.evidence",
            "resolution_source": level.value.lower(),
            "resolution_mechanism": mechanism,
            "resolved_identifier": resolved,
            "resolved_identity_kind": resolved_kind,
            "status": status,
            "evidence": evidence_reference,
            "observation_level": level,
            "redirect_chain": list(redirect_chain),
            "provider_response_field": None,
            "endpoint_context": "not.observed",
            "authority": authority,
            "resolved_at": resolved_at,
            "effective_at": effective_at,
            "available_at": "NOT_RECORDED",
            "observed_at": "NOT_RECORDED",
            "evaluated_at": "NOT_RECORDED",
            "supplied_at": "NOT_RECORDED",
            "coverage": [coverage("resolution.receipt", 1, 1)],
            "limitations": [
                "Receipt observation level controls its meaning; a slug is not a payload digest."
            ],
        },
    )


def build_continuity_assessment(
    subject: ProductSubject,
    requested: RequestedModelIdentifier,
    receipts: Iterable[RegistryResolutionReceipt],
    *,
    outcome: ContinuityOutcome,
    findings: Iterable[str],
) -> ResolutionContinuityAssessment:
    values = tuple(receipts)
    return build_canonical(
        ResolutionContinuityAssessment,
        {
            "schema": "omiv.resolution-continuity-assessment.v1",
            "subject": subject,
            "scope": "supplied.observations",
            "requested_identifier": object_reference(requested),
            "receipts": [object_reference(value) for value in values],
            "outcome": outcome,
            "observation_count": len(values),
            "evaluated_at": "NOT_RECORDED",
            "coverage": [coverage("resolution.observations", len(values), len(values))],
            "findings": sorted(set(findings), key=str.encode),
            "limitations": [
                "Supplied observations do not establish continuous monitoring between observations."
            ],
        },
    )


def build_artifact_expectation(
    subject: ProductSubject,
    artifact_identity: ObjectReference,
    *,
    payload_identity: ObjectReference | None = None,
    tokenizer_identity: ObjectReference | None = None,
    quantization_identity: ObjectReference | None = None,
) -> RuntimeArtifactExpectation:
    return build_canonical(
        RuntimeArtifactExpectation,
        {
            "schema": "omiv.runtime-artifact-expectation.v1",
            "subject": subject,
            "scope": "deployment.expected.identity",
            "artifact_identity": artifact_identity,
            "payload_identity": payload_identity,
            "tokenizer_configuration_identity": tokenizer_identity,
            "quantization_identity": quantization_identity,
            "availability": "exact.reference.available",
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "available_at": "NOT_RECORDED",
            "limitations": ["Expected artifact identity is not observed runtime identity."],
        },
    )


def build_deployment_declaration(
    subject: ProductSubject, expectation: RuntimeArtifactExpectation
) -> DeploymentDeclaration:
    return build_canonical(
        DeploymentDeclaration,
        {
            "schema": "omiv.deployment-declaration.v1",
            "subject": subject,
            "scope": "deployment.synthetic",
            "artifact_expectation": object_reference(expectation),
            "environment": "environment.synthetic",
            "tenant": "tenant.synthetic",
            "project": "project.synthetic",
            "trust_domain": "trust-domain.synthetic",
            "declared_by": "actor.synthetic",
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "declared_at": "NOT_RECORDED",
            "limitations": ["Deployment declaration is not runtime observation."],
        },
    )


def build_deployment_observation(
    subject: ProductSubject,
    declaration: DeploymentDeclaration,
    execution: ResolutionExecutionRecord,
    expectation: RuntimeArtifactExpectation,
    *,
    strength: ObservationStrength,
    local_artifact: ObjectReference | None = None,
) -> DeploymentObservation:
    return build_canonical(
        DeploymentObservation,
        {
            "schema": "omiv.deployment-observation.v1",
            "subject": subject,
            "scope": declaration.scope,
            "declaration": object_reference(declaration),
            "execution": object_reference(execution),
            "expected_artifact": object_reference(expectation),
            "observed_control_plane_identity": (
                "deployment.synthetic.control-plane"
                if strength == ObservationStrength.CONTROL_PLANE_CONFIGURATION
                else None
            ),
            "observed_local_artifact": local_artifact,
            "strength": strength,
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "observed_at": "NOT_RECORDED",
            "coverage": [
                coverage(
                    "deployment.identity", int(strength != ObservationStrength.NOT_OBSERVED), 1
                )
            ],
            "findings": [strength.value],
            "limitations": [
                "Deployment observation strength is policy-selected and not self-upgrading."
            ],
        },
    )


def build_runtime_expectation(
    subject: ProductSubject,
    declaration: DeploymentDeclaration,
    artifact_expectation: RuntimeArtifactExpectation,
    *,
    minimum_strength: ObservationStrength,
) -> RuntimeIdentityExpectation:
    return build_canonical(
        RuntimeIdentityExpectation,
        {
            "schema": "omiv.runtime-identity-expectation.v1",
            "subject": subject,
            "scope": declaration.scope,
            "deployment_declaration": object_reference(declaration),
            "artifact_expectation": object_reference(artifact_expectation),
            "minimum_strength": minimum_strength,
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "available_at": "NOT_RECORDED",
            "limitations": ["Runtime identity expectation is not runtime observation."],
        },
    )


def build_runtime_observation(
    subject: ProductSubject,
    deployment_observation: DeploymentObservation,
    expectation: RuntimeIdentityExpectation,
    *,
    observed_identity: ObjectReference | None,
    strength: ObservationStrength,
) -> RuntimeIdentityObservation:
    return build_canonical(
        RuntimeIdentityObservation,
        {
            "schema": "omiv.runtime-identity-observation.v1",
            "subject": subject,
            "scope": expectation.scope,
            "deployment_observation": object_reference(deployment_observation),
            "expected_identity": object_reference(expectation),
            "observed_identity": observed_identity,
            "strength": strength,
            "observation_source": "supplied.runtime.observation",
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "observed_at": "NOT_RECORDED",
            "coverage": [coverage("runtime.identity", int(observed_identity is not None), 1)],
            "findings": [strength.value],
            "limitations": ["Observation strength does not independently establish authority."],
        },
    )


def build_runtime_binding(
    subject: ProductSubject,
    artifact_expectation: RuntimeArtifactExpectation,
    declaration: DeploymentDeclaration,
    runtime_expectation: RuntimeIdentityExpectation,
    *,
    deployment_observation: DeploymentObservation | None,
    runtime_observation: RuntimeIdentityObservation | None,
    accepted_strength: ObservationStrength,
    outcome: RuntimeBindingOutcome,
    policy: RuntimeResolutionPolicy,
) -> ModelRuntimeBinding:
    verify_object_reference(declaration.artifact_expectation, artifact_expectation)
    verify_object_reference(runtime_expectation.deployment_declaration, declaration)
    verify_object_reference(runtime_expectation.artifact_expectation, artifact_expectation)
    if policy.subject != subject:
        raise ValueError("runtime-binding policy subject mismatch")
    if outcome == RuntimeBindingOutcome.RUNTIME_IDENTITY_BOUND_FOR_DECLARED_SCOPE:
        if runtime_observation is None or runtime_observation.observed_identity is None:
            raise ValueError("runtime binding requires an observed exact identity")
        if runtime_observation.strength != accepted_strength:
            raise ValueError("runtime observation strength does not match accepted policy strength")
        if accepted_strength != policy.minimum_runtime_strength:
            raise ValueError("selected policy does not accept the runtime observation strength")
        verify_object_reference(runtime_observation.expected_identity, runtime_expectation)
        if runtime_observation.observed_identity != artifact_expectation.artifact_identity:
            raise ValueError("observed runtime identity does not match exact expected artifact")
        if deployment_observation is None:
            raise ValueError("runtime binding requires finalized deployment observation")
        verify_object_reference(deployment_observation.declaration, declaration)
        verify_object_reference(deployment_observation.expected_artifact, artifact_expectation)
    return build_canonical(
        ModelRuntimeBinding,
        {
            "schema": "omiv.model-runtime-binding.v1",
            "subject": subject,
            "scope": declaration.scope,
            "artifact_expectation": object_reference(artifact_expectation),
            "deployment_declaration": object_reference(declaration),
            "deployment_observation": (
                object_reference(deployment_observation) if deployment_observation else None
            ),
            "runtime_expectation": object_reference(runtime_expectation),
            "runtime_observation": (
                object_reference(runtime_observation) if runtime_observation else None
            ),
            "selected_policy": object_reference(policy),
            "accepted_strength": accepted_strength,
            "outcome": outcome,
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "evaluated_at": "NOT_RECORDED",
            "coverage": [coverage("runtime.binding", int(runtime_observation is not None), 1)],
            "limitations": [
                "Runtime binding is scope-qualified and is not provable "
                "weight-attributable inference."
            ],
        },
    )


def build_backend(
    subject: ProductSubject,
    name: str,
    binding: ModelRuntimeBinding,
    *,
    tokenizer_identity: ObjectReference | None = None,
) -> BackendDescriptor:
    return build_canonical(
        BackendDescriptor,
        {
            "schema": "omiv.backend-descriptor.v1",
            "subject": subject,
            "scope": "supplied.backend",
            "name": name,
            "version": "1.synthetic",
            "build_digest": canonical_sha256({"backend": name}),
            "hardware_class": "synthetic.cpu",
            "device_identity_availability": "UNAVAILABLE",
            "precision": "declared.float32",
            "quantization_mode": "not.declared",
            "declarations": [],
            "runtime_binding": object_reference(binding),
            "tokenizer_configuration_binding": tokenizer_identity,
            "execution_context": "supplied.synthetic",
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "limitations": ["Backend descriptor is not observation of backend behavior."],
        },
    )


def build_probe_definition(
    *,
    kind: str,
    input_identity: ContentIdentity,
    binding: ModelRuntimeBinding,
    dimensions: Iterable[ResultDimension],
    mode: ExecutionMode,
    seed: int | None = None,
    tokenizer_identity: ObjectReference | None = None,
) -> BackendProbeDefinition:
    body: dict[str, Any] = {
        "kind": kind,
        "input_identity": input_identity,
        "request_digest": input_identity.digest or canonical_sha256({"unavailable": kind}),
        "runtime_binding": object_reference(binding),
        "tokenizer_configuration_identity": tokenizer_identity,
        "decoding_configuration": [
            TypedParameter(name="temperature", value_type="DECIMAL", value="0")
        ],
        "tool_configuration_digest": None,
        "execution_mode": mode,
        "seed": seed,
        "dimensions": sorted(set(dimensions), key=str),
    }
    from omiv.runtime_resolution.models import canonical_probe_id

    return BackendProbeDefinition(
        probe_id=canonical_probe_id(body),
        kind=kind,
        input_identity=input_identity,
        request_digest=input_identity.digest or canonical_sha256({"unavailable": kind}),
        runtime_binding=object_reference(binding),
        tokenizer_configuration_identity=tokenizer_identity,
        decoding_configuration=(
            TypedParameter(name="temperature", value_type="DECIMAL", value="0"),
        ),
        tool_configuration_digest=None,
        execution_mode=mode,
        seed=seed,
        dimensions=tuple(sorted(set(dimensions), key=str)),
    )


def build_probe_set(
    subject: ProductSubject, probes: Iterable[BackendProbeDefinition]
) -> CrossBackendProbeSet:
    values = tuple(sorted(probes, key=lambda probe: probe.probe_id))
    return build_canonical(
        CrossBackendProbeSet,
        {
            "schema": "omiv.cross-backend-probe-set.v1",
            "subject": subject,
            "scope": "selected.backend.probes",
            "probes": values,
            "created_at": "NOT_RECORDED",
            "limitations": [
                "Finite supplied probes cannot establish complete backend equivalence."
            ],
        },
    )


def build_backend_plan(
    subject: ProductSubject,
    probe_set: CrossBackendProbeSet,
    backend: BackendDescriptor,
    binding: ModelRuntimeBinding,
) -> BackendExecutionPlan:
    return build_canonical(
        BackendExecutionPlan,
        {
            "schema": "omiv.backend-execution-plan.v1",
            "subject": subject,
            "scope": probe_set.scope,
            "probe_set": object_reference(probe_set),
            "backend": object_reference(backend),
            "runtime_binding": object_reference(binding),
            "selected_probe_ids": [probe.probe_id for probe in probe_set.probes],
            "limits": RuntimeResolutionLimits(),
            "planned_at": "NOT_RECORDED",
            "limitations": ["Plan contains no execution or result identity."],
        },
    )


def build_backend_execution(
    subject: ProductSubject,
    plan: BackendExecutionPlan,
    backend: BackendDescriptor,
    binding: ModelRuntimeBinding,
    probe_set: CrossBackendProbeSet,
) -> BackendExecutionRecord:
    return build_canonical(
        BackendExecutionRecord,
        {
            "schema": "omiv.backend-execution-record.v1",
            "subject": subject,
            "scope": plan.scope,
            "plan": object_reference(plan),
            "backend": object_reference(backend),
            "runtime_binding": object_reference(binding),
            "probe_set": object_reference(probe_set),
            "tool_identity": "caller.supplied.adapter.v1",
            "context": "synthetic.explicit",
            "status": "SUPPLIED_RESULT_EXECUTION_RECORDED",
            "executed_at": "NOT_RECORDED",
            "limitations": ["Execution record contains no resulting output or comparison ID."],
        },
    )


def build_result_observation(
    subject: ProductSubject,
    execution: BackendExecutionRecord,
    backend: BackendDescriptor,
    binding: ModelRuntimeBinding,
    probe_set: CrossBackendProbeSet,
    results: Iterable[BackendResult],
) -> BackendResultObservation:
    values = tuple(sorted(results, key=lambda result: result.probe_id))
    return build_canonical(
        BackendResultObservation,
        {
            "schema": "omiv.backend-result-observation.v1",
            "subject": subject,
            "scope": probe_set.scope,
            "execution": object_reference(execution),
            "backend": object_reference(backend),
            "runtime_binding": object_reference(binding),
            "probe_set": object_reference(probe_set),
            "results": values,
            "provenance": ObservationLevel.CALLER_DECLARED,
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "observed_at": "NOT_RECORDED",
            "coverage": [coverage("backend.results", len(values), len(probe_set.probes))],
            "limitations": ["Caller-supplied results are not direct runtime observations."],
        },
    )


def build_comparison(
    subject: ProductSubject,
    probe_set: CrossBackendProbeSet,
    bindings: Iterable[ModelRuntimeBinding],
    observations: Iterable[BackendResultObservation],
    *,
    status: BackendComparisonStatus,
    findings: Iterable[ComparisonFinding],
    policy: RuntimeResolutionPolicy | None = None,
) -> CrossBackendComparison:
    observation_values = tuple(observations)
    return build_canonical(
        CrossBackendComparison,
        {
            "schema": "omiv.cross-backend-comparison.v1",
            "subject": subject,
            "scope": probe_set.scope,
            "probe_set": object_reference(probe_set),
            "runtime_bindings": sorted(
                (object_reference(value) for value in bindings), key=lambda item: item.object_id
            ),
            "result_observations": sorted(
                (object_reference(value) for value in observation_values),
                key=lambda item: item.object_id,
            ),
            "policy": object_reference(policy) if policy else None,
            "status": status,
            "findings": sorted(findings, key=lambda item: (item.probe_id, item.dimension.value)),
            "coverage": [
                coverage("backend.observations", len(observation_values), len(observation_values))
            ],
            "evaluated_at": "NOT_RECORDED",
            "limitations": [
                "Finite supplied results cannot prove identical weights or complete behavior."
            ],
        },
    )


def build_inference_identity(
    subject: ProductSubject,
    requested: RequestedModelIdentifier,
    binding: ModelRuntimeBinding,
    execution: BackendExecutionRecord,
    result: BackendResultObservation,
    request: ContentIdentity,
    output: ContentIdentity,
    *,
    receipt: RegistryResolutionReceipt | None = None,
) -> InferenceIdentity:
    return build_canonical(
        InferenceIdentity,
        {
            "schema": "omiv.inference-identity.v1",
            "subject": subject,
            "scope": "synthetic.inference.correlation",
            "provider_context": requested.provider,
            "requested_identifier": object_reference(requested),
            "resolution_receipt": object_reference(receipt) if receipt else None,
            "resolved_identifier": receipt.resolved_identifier if receipt else None,
            "runtime_binding": object_reference(binding),
            "backend_execution": object_reference(execution),
            "request": request,
            "tokenizer_configuration_identity": None,
            "decoding_tool_configuration_digest": canonical_sha256({"decoding": "synthetic.fixed"}),
            "result_observation": object_reference(result),
            "output": output,
            "observed_at": "NOT_RECORDED",
            "coverage": [coverage("inference.identity", 1, 1)],
            "limitations": ["Canonical inference identity is a correlation record, not proof."],
        },
    )


def build_inference_attestation(
    subject: ProductSubject,
    inference: InferenceIdentity,
    binding: ModelRuntimeBinding,
    *,
    method: AttestationMethod,
    authority: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
    signer_key_reference: str | None = None,
    signature_report: ObjectReference | None = None,
) -> InferenceAttestation:
    if inference.output.digest is None:
        raise ValueError("attestation requires an output digest")
    return build_canonical(
        InferenceAttestation,
        {
            "schema": "omiv.inference-attestation.v1",
            "subject": subject,
            "scope": inference.scope,
            "issuer": "service.synthetic",
            "signer_key_reference": signer_key_reference,
            "signature_report": signature_report,
            "purpose": "service.output.claim",
            "authority": authority,
            "inference_identity": object_reference(inference),
            "runtime_binding": object_reference(binding),
            "output_digest": inference.output.digest,
            "method": method,
            "issued_at": "NOT_RECORDED",
            "limitations": [
                "Attestation is a claim; service signature validity is not weight attribution."
            ],
        },
    )


def build_output_provenance(
    subject: ProductSubject,
    inference: InferenceIdentity,
    attestation: InferenceAttestation,
    binding: ModelRuntimeBinding,
    *,
    proof_method: AttestationMethod,
    proof_availability: ProofAvailability,
    verification_status: ProvenanceVerificationStatus,
    policy: RuntimeResolutionPolicy,
    authority_evaluation: RuntimeResolutionAuthorityEvaluation,
) -> OutputProvenanceEvidence:
    if inference.request.digest is None:
        raise ValueError("output provenance requires request digest identity")
    verify_object_reference(attestation.inference_identity, inference)
    verify_object_reference(attestation.runtime_binding, binding)
    verify_object_reference(inference.runtime_binding, binding)
    if inference.output.digest != attestation.output_digest:
        raise ValueError("attestation output digest does not match inference output")
    if (
        verification_status == ProvenanceVerificationStatus.SERVICE_SIGNATURE_VERIFIED
        and attestation.method != AttestationMethod.SERVICE_SIGNATURE
    ):
        raise ValueError("service-signature verification requires a signed attestation")
    verify_object_reference(authority_evaluation.policy, policy)
    return build_canonical(
        OutputProvenanceEvidence,
        {
            "schema": "omiv.output-provenance-evidence.v1",
            "subject": subject,
            "scope": inference.scope,
            "output": inference.output,
            "request_digest": inference.request.digest,
            "inference_identity": object_reference(inference),
            "inference_attestation": object_reference(attestation),
            "runtime_binding": object_reference(binding),
            "claimed_weight_artifact_identity": None,
            "proof_method": proof_method,
            "proof_availability": proof_availability,
            "proof_reference": None,
            "verifier_availability": "NOT_AVAILABLE",
            "verification_status": verification_status,
            "verification_policy": object_reference(policy),
            "authority_evaluation": object_reference(authority_evaluation),
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "evaluated_at": "NOT_RECORDED",
            "coverage": [coverage("weight.attribution", 0, 1, reason="proof unavailable")],
            "limitations": ["OMIV Phase 6E does not implement or simulate provable inference."],
        },
    )


def build_policy(subject: ProductSubject) -> RuntimeResolutionPolicy:
    return build_canonical(
        RuntimeResolutionPolicy,
        {
            "schema": "omiv.runtime-resolution-policy.v1",
            "subject": subject,
            "scope": "runtime.resolution.policy",
            "accepted_identifier_kinds": [
                IdentifierKind.IMMUTABLE_PINNED_IDENTIFIER,
                IdentifierKind.VERSIONED_IDENTIFIER,
            ],
            "pinned_identifier_required": True,
            "mutable_alias_behavior": "require.observed.resolution",
            "redirect_behavior": "preserve.and.evaluate",
            "continuity_required": True,
            "minimum_resolution_level": ObservationLevel.CONTROL_PLANE_RESPONSE,
            "maximum_resolution_age_seconds": None,
            "minimum_runtime_strength": ObservationStrength.FILESYSTEM_ARTIFACT_OBSERVATION,
            "exact_artifact_binding_required": True,
            "tokenizer_configuration_required": True,
            "quantization_required": False,
            "required_dimensions": [ResultDimension.FINAL_OUTPUT_BYTES],
            "numerical_tolerance": "0",
            "stochastic_behavior": "not.directly.comparable",
            "minimum_probe_coverage": "1",
            "required_request_availability": [
                ContentAvailability.INLINE_SYNTHETIC,
                ContentAvailability.DIGEST_ONLY,
            ],
            "required_output_availability": [
                ContentAvailability.INLINE_SYNTHETIC,
                ContentAvailability.DIGEST_ONLY,
            ],
            "output_provenance_required": False,
            "accepted_attestation_methods": [AttestationMethod.SERVICE_SIGNATURE],
            "accepted_verification_statuses": [
                ProvenanceVerificationStatus.SERVICE_SIGNATURE_VERIFIED
            ],
            "freshness_behavior": "require.explicit.or.unavailable",
            "replay_behavior": "require.explicit.or.unavailable",
            "authority_required": True,
            "historical_mode": "KNOWN_AS_OF_CUTOFF",
            "missing_input_behavior": "not.evaluated",
            "unsupported_method_behavior": "fail.closed",
            "evaluation_context": "synthetic.explicit",
            "limitations": [
                "Policy cannot upgrade provider documentation or service signature semantics."
            ],
        },
    )


def build_policy_evaluation(
    subject: ProductSubject,
    policy: RuntimeResolutionPolicy,
    binding: ModelRuntimeBinding,
    *,
    comparison: CrossBackendComparison | None,
    provenance: OutputProvenanceEvidence | None,
    requirements: Iterable[PolicyRequirement],
    status: RequirementStatus,
) -> RuntimeResolutionPolicyEvaluation:
    return build_canonical(
        RuntimeResolutionPolicyEvaluation,
        {
            "schema": "omiv.runtime-resolution-policy-evaluation.v1",
            "subject": subject,
            "scope": policy.scope,
            "policy": object_reference(policy),
            "comparison": object_reference(comparison) if comparison else None,
            "runtime_binding": object_reference(binding),
            "output_provenance": object_reference(provenance) if provenance else None,
            "requirements": sorted(requirements, key=lambda item: item.requirement),
            "overall_status": status,
            "evaluated_at": "NOT_RECORDED",
            "limitations": ["All failed and unevaluated policy dimensions are preserved."],
        },
    )


def build_authority_evaluation(
    subject: ProductSubject,
    policy: RuntimeResolutionPolicy,
    purposes: Iterable[AuthorityDimension],
    *,
    status: AuthorityStatus,
) -> RuntimeResolutionAuthorityEvaluation:
    return build_canonical(
        RuntimeResolutionAuthorityEvaluation,
        {
            "schema": "omiv.runtime-resolution-authority-evaluation.v1",
            "subject": subject,
            "scope": policy.scope,
            "policy": object_reference(policy),
            "purposes": sorted(purposes, key=lambda item: item.purpose),
            "overall_status": status,
            "evaluated_at": "NOT_RECORDED",
            "limitations": ["Signature validity, trust, purpose, and authority remain separate."],
        },
    )


def build_evidence(
    subject: ProductSubject,
    continuity: ResolutionContinuityAssessment,
    binding: ModelRuntimeBinding,
    comparison: CrossBackendComparison,
    provenance: OutputProvenanceEvidence,
    policy_evaluation: RuntimeResolutionPolicyEvaluation,
    authority_evaluation: RuntimeResolutionAuthorityEvaluation,
    *,
    status: EvidenceStatus,
) -> RuntimeResolutionParityEvidence:
    return build_canonical(
        RuntimeResolutionParityEvidence,
        {
            "schema": "omiv.runtime-resolution-parity-evidence.v1",
            "subject": subject,
            "scope": "declared.phase6e.scope",
            "continuity": object_reference(continuity),
            "runtime_binding": object_reference(binding),
            "comparison": object_reference(comparison),
            "output_provenance": object_reference(provenance),
            "policy_evaluation": object_reference(policy_evaluation),
            "authority_evaluation": object_reference(authority_evaluation),
            "status": status,
            "coverage": [
                coverage("resolution", 1, 1),
                coverage("runtime.binding", int(binding.runtime_observation is not None), 1),
                coverage("output.provenance", 0, 1, reason="weight attribution unavailable"),
            ],
            "limitations": [
                "Phase 6E evidence does not establish safety, authenticity, "
                "or production readiness."
            ],
        },
    )


def build_integration(
    subject: ProductSubject,
    evidence: RuntimeResolutionParityEvidence,
    *,
    phase: str,
    state: str,
    upstream: ObjectReference | None = None,
) -> RuntimeResolutionIntegrationSummary:
    return build_canonical(
        RuntimeResolutionIntegrationSummary,
        {
            "schema": "omiv.runtime-resolution-integration-summary.v1",
            "subject": subject,
            "scope": evidence.scope,
            "phase": phase,
            "evidence": object_reference(evidence),
            "upstream": upstream,
            "state": state,
            "authority": AuthorityStatus.NOT_ESTABLISHED,
            "limitations": ["Derived integration summary does not rewrite prior evidence."],
        },
    )


def build_assumption(
    subject: ProductSubject,
    *,
    statement: str,
    status: AssumptionStatus,
    evidence: Iterable[ObjectReference],
    strength: ObservationLevel,
    boundary: str,
    schemas: Iterable[str],
    policy: RuntimeResolutionPolicy,
    basis: str,
    prior_status: AssumptionStatus = AssumptionStatus.ACTIVE,
    consequence: str = "Dependent conclusions require explicit reevaluation.",
    remediation: str = "Collect stronger scope-matched evidence in a future phase.",
    authority: AuthorityStatus = AuthorityStatus.NOT_ESTABLISHED,
) -> AssumptionRegisterEntry:
    return build_canonical(
        AssumptionRegisterEntry,
        {
            "schema": "omiv.assumption-register-entry.v1",
            "subject": subject,
            "scope": "phase6e.assumption.register",
            "statement": statement,
            "prior_status": prior_status,
            "status": status,
            "evidence_references": sorted(evidence, key=lambda item: item.object_id),
            "evidence_strength": strength,
            "affected_trust_boundary": boundary,
            "affected_schemas": sorted(set(schemas)),
            "affected_policies": [object_reference(policy)],
            "available_at": "NOT_RECORDED",
            "observed_at": "NOT_RECORDED",
            "evaluated_at": "NOT_RECORDED",
            "supplied_at": "NOT_RECORDED",
            "supersession": None,
            "basis": basis,
            "consequence": consequence,
            "remediation": remediation,
            "authority": authority,
            "limitations": ["Public documentation is not direct runtime observation."],
        },
    )


def build_report(
    subject: ProductSubject,
    evidence: RuntimeResolutionParityEvidence,
    findings: Iterable[str],
) -> RuntimeResolutionReport:
    values = tuple(sorted(set(findings), key=str.encode))
    included = values[:256]
    return build_canonical(
        RuntimeResolutionReport,
        {
            "schema": "omiv.runtime-resolution-report.v1",
            "subject": subject,
            "scope": evidence.scope,
            "evidence": object_reference(evidence),
            "title": "Synthetic Phase 6E runtime-resolution evidence",
            "status": evidence.status,
            "total_findings": len(values),
            "included_findings": len(included),
            "omitted_findings": len(values) - len(included),
            "inclusion_rule": "lexicographic.first.256",
            "truncation_status": (
                "NOT_TRUNCATED" if len(values) == len(included) else "DETERMINISTICALLY_TRUNCATED"
            ),
            "findings": included,
            "limitations": ["Report is derived and never feeds canonical evidence identity."],
        },
    )


def build_scenario(
    subject: ProductSubject,
    *,
    case_id: str,
    invariant: str,
    outcome: str,
    findings: Iterable[str],
    upstream: Iterable[ObjectReference],
) -> RuntimeResolutionScenarioResult:
    return build_canonical(
        RuntimeResolutionScenarioResult,
        {
            "schema": "omiv.runtime-resolution-scenario-result.v1",
            "subject": subject,
            "scope": f"scenario.{case_id}",
            "case_id": case_id,
            "exercised_invariant": invariant,
            "outcome": outcome,
            "findings": sorted(set(findings), key=str.encode),
            "upstream_objects": sorted(upstream, key=lambda item: item.object_id),
            "limitations": ["Synthetic scenario is not production model or runtime evidence."],
        },
    )


def build_catalog(
    subject: ProductSubject, scenarios: Iterable[RuntimeResolutionScenarioResult]
) -> RuntimeResolutionScenarioCatalog:
    values = tuple(sorted(scenarios, key=lambda value: value.case_id))
    return build_canonical(
        RuntimeResolutionScenarioCatalog,
        {
            "schema": "omiv.runtime-resolution-scenario-catalog.v1",
            "subject": subject,
            "scope": "phase6e.synthetic.scenarios",
            "classification": (
                "COMPLETE_AS_PROVIDER_NEUTRAL_RUNTIME_RESOLUTION_DEPLOYMENT_BINDING_"
                "AND_CROSS_BACKEND_PARITY_EVIDENCE_FOUNDATION_WITH_EXPLICIT_"
                "OBSERVATION_AND_PROVABLE_INFERENCE_LIMITATIONS"
            ),
            "scenarios": [object_reference(value) for value in values],
            "limitations": [
                "Generated scenarios demonstrate bounded semantics, not production inference."
            ],
        },
    )


def build_index(
    subject: ProductSubject, entries: Iterable[RuntimeResolutionArtifactIndexEntry]
) -> RuntimeResolutionArtifactIndex:
    values = tuple(sorted(entries, key=lambda item: item.path.encode()))
    return build_canonical(
        RuntimeResolutionArtifactIndex,
        {
            "schema": "omiv.runtime-resolution-artifact-index.v1",
            "subject": subject,
            "scope": "phase6e.generated.artifacts",
            "entries": values,
            "total_size": sum(item.size for item in values),
            "limitations": ["External index excludes itself."],
        },
    )
