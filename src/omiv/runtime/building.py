"""Deterministic builders for normalized Phase 5G records."""

from __future__ import annotations

from typing import Any, Literal

from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.runtime.models import (
    AdapterIdentity,
    ArtifactMemberObservation,
    ArtifactMemberRole,
    AssertionAuthorityScope,
    AssertionAuthorityStatus,
    DeploymentActorReference,
    DeploymentArtifactMember,
    DeploymentArtifactSet,
    DeploymentConfigurationIdentity,
    DeploymentInstanceIdentity,
    DeploymentIntent,
    DeploymentManifest,
    DeploymentRecord,
    DeploymentStatus,
    DeploymentTargetReference,
    DeploymentTargetType,
    EvidenceAcquisitionOrigin,
    EvidenceAssertion,
    EvidenceStrength,
    IdentityObservationMethod,
    NormalizedConfigurationField,
    ObservationCoverage,
    ObservationCoverageStatus,
    ObservationDimension,
    ObservationStatus,
    ObserverCapability,
    ProductSubject,
    ProductSubjectClass,
    ReplayProtectionContext,
    RuntimeArtifactSetObservation,
    RuntimeEngineFamily,
    RuntimeEngineIdentity,
    RuntimeEnvironmentIdentity,
    RuntimeObservation,
    RuntimeObservationPlan,
    RuntimeObserverIdentity,
    ScopeContext,
    SecretReference,
)


def identified(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    with_id = {**body, id_field: prefix + canonical_sha256(body)[:32]}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def synthetic_scope(
    *,
    tenant: str = "tenant.synthetic",
    project: str = "project.runtime",
    environment: str = "environment.team",
) -> ScopeContext:
    return ScopeContext(
        tenant_scope=tenant,
        organization_scope="organization.synthetic",
        project_scope=project,
        product_scope="product.generic-inference",
        trust_domain="trust-domain.synthetic",
        environment_scope=environment,
        target_scope="target-scope.runtime",
    )


def build_product_subject(
    subject_class: ProductSubjectClass,
    logical_name: str,
    scope: ScopeContext,
) -> ProductSubject:
    body = {
        "schema": "omiv.product-subject.v1",
        "subject_class": subject_class.value,
        "logical_name": logical_name,
        "scope": scope.model_dump(mode="json"),
        "limitations": ["Logical product subject identity does not prove artifact content."],
    }
    return ProductSubject.model_validate(
        identified(body, "subject_id", "product_subject_", "subject_digest")
    )


def build_artifact_reference(
    name: str, content_digest: str, *, format_name: str = "DECLARED"
) -> ArtifactReference:
    identity = {
        "origin_type": "SYNTHETIC_LOGICAL",
        "provider": "omiv-synthetic",
        "repository": "generic-product",
        "repository_type": "LOGICAL",
        "resolved_revision": "revision-1",
        "selection": name,
        "artifact_set_digest": None,
        "content_digest": content_digest,
        "format": format_name,
        "architecture": "generic",
        "variant": "synthetic",
        "file_count": 1,
        "total_declared_bytes": 0,
    }
    return ArtifactReference.model_validate(
        {
            **identity,
            "passport_id": None,
            "passport_digest": None,
            "validation_inventory_digest": None,
            "identity_digest": canonical_sha256(identity),
        }
    )


def artifact_member(
    logical_name: str,
    artifact_class: ProductSubjectClass,
    digest_seed: str,
    *,
    role: ArtifactMemberRole,
    required: bool = True,
    method: IdentityObservationMethod = IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
    generation_provenance_seed: str | None = None,
) -> DeploymentArtifactMember:
    return DeploymentArtifactMember(
        role=role,
        artifact_class=artifact_class,
        logical_name=logical_name,
        artifact=build_artifact_reference(logical_name, canonical_sha256({"fixture": digest_seed})),
        required=required,
        expected_observation_method=method,
        continuity_required=required,
        generation_provenance_digest=(
            canonical_sha256({"generation-parent": generation_provenance_seed})
            if generation_provenance_seed is not None
            else None
        ),
        limitations=["Synthetic digest identity only; semantic parity is not established."],
    )


def build_artifact_set(
    subject: ProductSubject, members: list[DeploymentArtifactMember]
) -> DeploymentArtifactSet:
    body = {
        "schema": "omiv.deployment-artifact-set.v1",
        "subject_id": subject.subject_id,
        "scope": subject.scope.model_dump(mode="json"),
        "members": [
            x.model_dump(mode="json") for x in sorted(members, key=lambda x: x.logical_name)
        ],
        "limitations": [
            "Members are evaluated independently; one match does not imply set continuity."
        ],
    }
    return DeploymentArtifactSet.model_validate(
        identified(body, "artifact_set_id", "deployment_artifact_set_", "artifact_set_digest")
    )


def build_authority(
    actor_id: str,
    scope: ScopeContext,
    *,
    assertion_types: list[str],
    actions: list[str],
    target_classes: list[DeploymentTargetType] | None = None,
    artifact_classes: list[ProductSubjectClass] | None = None,
    valid_from_sequence: int = 1,
    valid_through_sequence: int = 100,
) -> AssertionAuthorityScope:
    body = {
        "schema": "omiv.assertion-authority-scope.v1",
        "actor_id": actor_id,
        "object_types": sorted({"DEPLOYMENT_RECORD", "RUNTIME_OBSERVATION"}),
        "assertion_types": sorted(assertion_types),
        "artifact_classes": sorted(
            x.value for x in (artifact_classes or list(ProductSubjectClass))
        ),
        "target_classes": sorted(x.value for x in (target_classes or list(DeploymentTargetType))),
        "scope": scope.model_dump(mode="json"),
        "actions": sorted(actions),
        "valid_from_sequence": valid_from_sequence,
        "valid_through_sequence": valid_through_sequence,
        "delegated_by_authority_id": None,
        "maximum_delegation_depth": 0,
        "limitations": ["Authority is policy-scoped and does not prove the asserted fact."],
    }
    return AssertionAuthorityScope.model_validate(
        identified(body, "authority_id", "runtime_authority_", "authority_digest")
    )


def build_target(
    scope: ScopeContext,
    target_type: DeploymentTargetType = DeploymentTargetType.TEAM_INFERENCE_SERVICE,
) -> DeploymentTargetReference:
    return DeploymentTargetReference(
        target_id="target.synthetic-runtime",
        target_type=target_type,
        scope=scope,
        namespace="namespace.synthetic",
        region_classification="region.offline",
        registry_class="registry.logical",
        runtime_policy_digest=canonical_sha256({"runtime-policy": "v1"}),
        observer_policy_digest=canonical_sha256({"observer-policy": "v1"}),
        limitations=["Logical target only; OMIV performed no deployment or endpoint access."],
    )


def build_configuration(fields: dict[str, str] | None = None) -> DeploymentConfigurationIdentity:
    defaults = {"batch-size": "1", "precision": "declared"}
    aliases = {"batch_size": "batch-size"}
    supplied = fields or {}
    normalized_values = defaults.copy()
    sources: dict[str, Literal["EXPLICIT", "DEFAULT", "ALIAS_NORMALIZED"]] = {
        name: "DEFAULT" for name in defaults
    }
    for raw_name, value in supplied.items():
        name = aliases.get(raw_name, raw_name)
        if name not in defaults:
            raise ValueError(f"unknown runtime configuration field: {raw_name}")
        if not isinstance(value, str):
            raise ValueError(f"runtime configuration value must be a string: {raw_name}")
        if name in normalized_values and sources[name] != "DEFAULT":
            raise ValueError(f"duplicate runtime configuration alias: {raw_name}")
        normalized_values[name] = value
        sources[name] = "ALIAS_NORMALIZED" if raw_name in aliases else "EXPLICIT"
    normalized = [
        NormalizedConfigurationField(
            name=name,
            normalized_value=value,
            source=sources[name],
        )
        for name, value in sorted(normalized_values.items())
    ]
    secret_refs = [
        SecretReference(
            logical_reference_id="credential-reference.synthetic",
            provider_class="logical-provider.synthetic",
            reference_digest=canonical_sha256({"logical-reference": "synthetic"}),
        )
    ]
    body = {
        "schema": "omiv.deployment-configuration-identity.v1",
        "normalized_fields": [x.model_dump(mode="json") for x in normalized],
        "secret_references": [x.model_dump(mode="json") for x in secret_refs],
        "normalization_policy_digest": canonical_sha256({"normalization": "allowlisted-v1"}),
        "unknown_fields": [],
        "limitations": ["Normalized identity equality does not prove semantic equivalence."],
    }
    return DeploymentConfigurationIdentity.model_validate(
        identified(body, "configuration_id", "runtime_config_", "configuration_digest")
    )


def build_engine(
    *,
    family: RuntimeEngineFamily = RuntimeEngineFamily.CUSTOM_INFERENCE_SERVER,
    version: str = "1.0",
    binary_seed: str = "engine-binary-v1",
    revision: str = "revision-1",
    image_seed: str | None = None,
    dependency_lock_seed: str = "v1",
) -> RuntimeEngineIdentity:
    body = {
        "schema": "omiv.runtime-engine-identity.v1",
        "family": family.value,
        "name": "engine.synthetic",
        "display_version": version,
        "source_revision": revision,
        "binary_digest": canonical_sha256({"binary": binary_seed}),
        "container_image_digest": (
            canonical_sha256({"container-image": image_seed}) if image_seed is not None else None
        ),
        "build_configuration_digest": canonical_sha256({"engine-build": "v1"}),
        "dependency_lock_digest": canonical_sha256({"engine-lock": dependency_lock_seed}),
        "runtime_configuration_digest": canonical_sha256({"engine-runtime-config": "v1"}),
        "runtime_configuration_schema": "runtime-config.synthetic.v1",
        "trust_references": [],
        "limitations": ["Engine identity does not establish engine behavior or runtime safety."],
    }
    return RuntimeEngineIdentity.model_validate(
        identified(body, "engine_id", "runtime_engine_", "engine_digest")
    )


def build_environment(scope: ScopeContext) -> RuntimeEnvironmentIdentity:
    body = {
        "schema": "omiv.runtime-environment-identity.v1",
        "environment_class": "environment.synthetic",
        "operating_system_class": "os.generic",
        "architecture": "architecture.generic",
        "accelerator_class": "accelerator.declared",
        "container_vm_identity_digest": None,
        "dependency_lock_digest": canonical_sha256({"environment-lock": "v1"}),
        "runtime_policy_digest": canonical_sha256({"environment-runtime-policy": "v1"}),
        "network_policy_digest": canonical_sha256({"network-policy": "offline"}),
        "filesystem_policy_digest": canonical_sha256({"filesystem-policy": "declared"}),
        "trust_domain": scope.trust_domain,
        "limitations": [
            "Privacy-safe logical environment; no workstation fingerprinting occurred."
        ],
    }
    return RuntimeEnvironmentIdentity.model_validate(
        identified(body, "environment_id", "runtime_environment_", "environment_digest")
    )


def build_adapter(
    scope: ScopeContext,
    adapter_id: str = "omiv.adapter.local-runtime.v1",
    *,
    operational: bool = True,
) -> AdapterIdentity:
    body = {
        "schema": "omiv.runtime-adapter-identity.v1",
        "adapter_id": adapter_id,
        "adapter_schema_version": "v1",
        "implementation_version": "1.0",
        "source_revision": "phase-5g-static-registry-v1",
        "implementation_digest": canonical_sha256({"adapter": adapter_id, "implementation": "v1"}),
        "capabilities": ["LOCAL_JSON_NORMALIZATION"] if operational else [],
        "supported_input_schemas": ["omiv.runtime-adapter-input.v1"],
        "supported_output_schemas": ["omiv.deployment-record.v1", "omiv.runtime-observation.v1"],
        "supported_subject_classes": sorted(x.value for x in ProductSubjectClass),
        "supported_target_classes": sorted(x.value for x in DeploymentTargetType),
        "observation_strength_ceiling": EvidenceStrength.STRUCTURALLY_VERIFIED.value,
        "accepted_evidence_origins": [
            EvidenceStrength.DECLARED.value,
            EvidenceStrength.IMPORTED_UNVERIFIED.value,
            EvidenceStrength.STRUCTURALLY_VERIFIED.value,
            EvidenceStrength.EVIDENCE_LINKED.value,
        ],
        "normalization_policy_digest": canonical_sha256({"normalization": "allowlisted-v1"}),
        "scope": scope.model_dump(mode="json"),
        "operational": operational,
        "limitations": ["Adapter normalizes explicit local JSON and performs no platform access."],
    }
    return AdapterIdentity.model_validate({**body, "adapter_digest": canonical_sha256(body)})


def build_actor(
    actor_id: str,
    role: str,
    authority: AssertionAuthorityScope,
    *,
    signer: str | None = None,
    key: str | None = None,
    root: str | None = None,
) -> DeploymentActorReference:
    return DeploymentActorReference(
        actor_id=actor_id,
        role=role,
        signer_identity_id=signer,
        key_id=key,
        trust_root_id=root,
        authority_id=authority.authority_id,
        limitations=["Synthetic logical actor; authority remains policy-scoped."],
    )


def build_intent(
    subject: ProductSubject,
    artifact_set: DeploymentArtifactSet,
    target: DeploymentTargetReference,
    engine: RuntimeEngineIdentity,
    configuration: DeploymentConfigurationIdentity,
    requester: DeploymentActorReference,
    authority: AssertionAuthorityScope,
    *,
    security_verdict: str = "PASS_WITH_LIMITATIONS",
    security_limitations: list[str] | None = None,
) -> DeploymentIntent:
    body = {
        "schema": "omiv.deployment-intent.v1",
        "subject_id": subject.subject_id,
        "artifact_set_id": artifact_set.artifact_set_id,
        "artifact_set_digest": artifact_set.artifact_set_digest,
        "release_candidate_id": "release-candidate.synthetic",
        "promotion_decision_id": "promotion-decision.synthetic",
        "promotion_decision_digest": canonical_sha256({"promotion": "authorized"}),
        "promotion_outcome": "PROMOTE",
        "promotion_authorization_status": "VERIFIED",
        "governance_policy_id": "governance-policy.synthetic",
        "governance_decision_digest": canonical_sha256({"governance": "allow"}),
        "governance_decision_outcome": "ALLOW",
        "approval_quorum_status": "SATISFIED",
        "security_evaluation_id": "security-evaluation.synthetic",
        "security_evaluation_digest": canonical_sha256({"security": security_verdict}),
        "security_verdict": security_verdict,
        "security_limitations": sorted(
            security_limitations
            or ["Security evidence remains policy- and declared-scope limited."]
        ),
        "security_evaluation_freshness": "CURRENT",
        "security_evaluation_trust_status": "TRUSTED_BY_POLICY",
        "scope": subject.scope.model_dump(mode="json"),
        "target": target.model_dump(mode="json"),
        "expected_engine_id": engine.engine_id,
        "expected_configuration_id": configuration.configuration_id,
        "requester": requester.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json", by_alias=True),
        "evaluation_sequence": 10,
        "limitations": ["Deployment intent records authorization and does not prove deployment."],
    }
    return DeploymentIntent.model_validate(
        identified(body, "intent_id", "deployment_intent_", "intent_digest")
    )


def build_instance(
    intent: DeploymentIntent,
    artifact_set: DeploymentArtifactSet,
    configuration: DeploymentConfigurationIdentity,
    engine: RuntimeEngineIdentity,
    *,
    generation: int = 1,
    predecessor: str | None = None,
) -> DeploymentInstanceIdentity:
    body = {
        "schema": "omiv.deployment-instance-identity.v1",
        "intent_id": intent.intent_id,
        "target_id": intent.target.target_id,
        "scope": intent.scope.model_dump(mode="json"),
        "artifact_set_digest": artifact_set.artifact_set_digest,
        "configuration_digest": configuration.configuration_digest,
        "engine_digest": engine.engine_digest,
        "evaluation_context_digest": canonical_sha256(
            {"context-sequence": intent.evaluation_sequence, "generation": generation}
        ),
        "generation": generation,
        "predecessor_instance_id": predecessor,
    }
    return DeploymentInstanceIdentity.model_validate(
        identified(body, "instance_id", "deployment_instance_", "instance_digest")
    )


def build_manifest(
    intent: DeploymentIntent,
    instance: DeploymentInstanceIdentity,
    artifact_set: DeploymentArtifactSet,
    target: DeploymentTargetReference,
    engine: RuntimeEngineIdentity,
    configuration: DeploymentConfigurationIdentity,
    environment: RuntimeEnvironmentIdentity,
    adapter: AdapterIdentity,
) -> DeploymentManifest:
    body = {
        "schema": "omiv.deployment-manifest.v1",
        "intent_id": intent.intent_id,
        "intent_digest": intent.intent_digest,
        "instance": instance.model_dump(mode="json", by_alias=True),
        "artifact_set": artifact_set.model_dump(mode="json", by_alias=True),
        "passport_references": [],
        "governance_decision_digest": intent.governance_decision_digest,
        "security_evaluation_digest": intent.security_evaluation_digest,
        "security_verdict": intent.security_verdict,
        "security_limitations": intent.security_limitations,
        "promotion_decision_digest": intent.promotion_decision_digest,
        "target": target.model_dump(mode="json"),
        "engine": engine.model_dump(mode="json", by_alias=True),
        "configuration": configuration.model_dump(mode="json", by_alias=True),
        "expected_environment": environment.model_dump(mode="json", by_alias=True),
        "resource_profile_digest": canonical_sha256({"resource-profile": "synthetic"}),
        "startup_policy_digest": canonical_sha256({"startup-policy": "synthetic"}),
        "adapter": adapter.model_dump(mode="json", by_alias=True),
        "limitations": [
            "Manifest defines intended state; it does not prove deployed or loaded state."
        ],
    }
    return DeploymentManifest.model_validate(
        identified(body, "manifest_id", "deployment_manifest_", "manifest_digest")
    )


def build_assertion(
    strength: EvidenceStrength,
    *,
    authorized: bool = True,
    trusted: bool = False,
    corroborated: bool = False,
) -> EvidenceAssertion:
    acquisition_origin = {
        EvidenceStrength.DECLARED: EvidenceAcquisitionOrigin.DECLARED,
        EvidenceStrength.IMPORTED_UNVERIFIED: EvidenceAcquisitionOrigin.IMPORTED,
        EvidenceStrength.STRUCTURALLY_VERIFIED: EvidenceAcquisitionOrigin.IMPORTED,
        EvidenceStrength.EVIDENCE_LINKED: EvidenceAcquisitionOrigin.EVIDENCE_LINKED,
        EvidenceStrength.SYSTEM_OBSERVED: EvidenceAcquisitionOrigin.SYSTEM_OBSERVED,
        EvidenceStrength.SIGNED: EvidenceAcquisitionOrigin.DECLARED,
        EvidenceStrength.SIGNED_AND_TRUSTED: EvidenceAcquisitionOrigin.DECLARED,
        EvidenceStrength.INDEPENDENTLY_CORROBORATED: EvidenceAcquisitionOrigin.SYSTEM_OBSERVED,
    }[strength]
    signed = (
        strength
        in {
            EvidenceStrength.SIGNED,
            EvidenceStrength.SIGNED_AND_TRUSTED,
        }
        or trusted
    )
    return EvidenceAssertion(
        origin=strength,
        acquisition_origin=acquisition_origin,
        structurally_verified=strength
        not in {EvidenceStrength.DECLARED, EvidenceStrength.IMPORTED_UNVERIFIED},
        directly_observed=acquisition_origin == EvidenceAcquisitionOrigin.SYSTEM_OBSERVED,
        verification_mode="OFFLINE_NORMALIZED",
        signature_status="VALID" if signed else "NOT_PRESENT",
        trust_status="TRUSTED_BY_POLICY" if trusted else "NOT_EVALUATED",
        authority_status=(
            AssertionAuthorityStatus.AUTHORIZED
            if authorized
            else AssertionAuthorityStatus.UNAUTHORIZED
        ),
        corroboration_status="INDEPENDENT" if corroborated else "NOT_ESTABLISHED",
        independently_corroborated=corroborated,
        limitations=["Evidence strength and assertion authority are evaluated separately."],
    )


def build_deployment_record(
    manifest: DeploymentManifest,
    actor: DeploymentActorReference,
    authority: AssertionAuthorityScope,
    *,
    strength: EvidenceStrength = EvidenceStrength.SYSTEM_OBSERVED,
    status: DeploymentStatus = DeploymentStatus.COMPLETED_OBSERVED,
    trusted: bool = True,
    corroborated: bool = False,
) -> DeploymentRecord:
    body = {
        "schema": "omiv.deployment-record.v1",
        "instance_id": manifest.instance.instance_id,
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.manifest_digest,
        "target": manifest.target.model_dump(mode="json"),
        "deployed_artifact_set": manifest.artifact_set.model_dump(mode="json", by_alias=True),
        "configuration": manifest.configuration.model_dump(mode="json", by_alias=True),
        "engine": manifest.engine.model_dump(mode="json", by_alias=True),
        "actor": actor.model_dump(mode="json"),
        "actor_authority": authority.model_dump(mode="json", by_alias=True),
        "execution_reference_digest": None,
        "assertion": build_assertion(
            strength, trusted=trusted, corroborated=corroborated
        ).model_dump(mode="json"),
        "status": status.value,
        "evidence_references": [],
        "limitations": [
            "Deployment record evidence does not independently prove deployment success."
        ],
    }
    return DeploymentRecord.model_validate(
        identified(body, "record_id", "deployment_record_", "record_digest")
    )


def build_observer(
    scope: ScopeContext,
    authority: AssertionAuthorityScope,
    *,
    observer_id_seed: str = "team-observer",
    trusted: bool = True,
    strength_ceiling: EvidenceStrength = EvidenceStrength.INDEPENDENTLY_CORROBORATED,
    signer: str | None = "signer.runtime-observer",
    key: str | None = "key.runtime-observer",
    root: str | None = "root.runtime-observer",
) -> RuntimeObserverIdentity:
    body = {
        "schema": "omiv.runtime-observer-identity.v1",
        "name": observer_id_seed,
        "version": "1.0",
        "revision": "revision-1",
        "implementation_digest": canonical_sha256({"observer": observer_id_seed}),
        "configuration_digest": canonical_sha256({"observer-config": "bounded-v1"}),
        "capabilities": sorted(
            x.value
            for x in ObserverCapability
            if x != ObserverCapability.BEHAVIORAL_OBSERVATION_RESERVED
        ),
        "supported_target_types": sorted(x.value for x in DeploymentTargetType),
        "supported_artifact_classes": sorted(x.value for x in ProductSubjectClass),
        "observation_strength_ceiling": strength_ceiling.value,
        "scope": scope.model_dump(mode="json"),
        "authority": authority.model_dump(mode="json", by_alias=True),
        "signer_identity_id": signer,
        "key_id": key,
        "trust_root_id": root,
        "trust_references": ["trust-policy.runtime"] if trusted else [],
        "limitations": [
            "Trusted observer identity does not prove observer correctness or host integrity."
        ],
    }
    return RuntimeObserverIdentity.model_validate(
        identified(body, "observer_id", "runtime_observer_", "observer_digest")
    )


def build_replay_context(
    instance: DeploymentInstanceIdentity,
    manifest: DeploymentManifest,
    observer: RuntimeObserverIdentity,
    policy_digest: str,
    *,
    sequence_namespace: str = "sequence.runtime-observer",
    epoch: int = 1,
    sequence: int = 1,
    predecessor: str | None = None,
) -> ReplayProtectionContext:
    body = {
        "schema": "omiv.replay-protection-context.v1",
        "instance_id": instance.instance_id,
        "observer_id": observer.observer_id,
        "scope": instance.scope.model_dump(mode="json"),
        "manifest_digest": manifest.manifest_digest,
        "target_id": manifest.target.target_id,
        "artifact_set_digest": manifest.artifact_set.artifact_set_digest,
        "policy_digest": policy_digest,
        "sequence_namespace": sequence_namespace,
        "epoch": epoch,
        "expected_sequence": sequence,
        "predecessor_observation_id": predecessor,
        "evaluation_context_digest": instance.evaluation_context_digest,
    }
    return ReplayProtectionContext.model_validate(
        identified(body, "replay_id", "runtime_replay_", "replay_digest")
    )


def build_observation_plan(
    manifest: DeploymentManifest,
    observer: RuntimeObserverIdentity,
    replay: ReplayProtectionContext,
    required_dimensions: list[ObservationDimension],
    *,
    max_age: int = 5,
) -> RuntimeObservationPlan:
    body = {
        "schema": "omiv.runtime-observation-plan.v1",
        "instance_id": manifest.instance.instance_id,
        "manifest_id": manifest.manifest_id,
        "observer_id": observer.observer_id,
        "required_capabilities": sorted(x.value for x in observer.capabilities),
        "expected_artifact_set_digest": manifest.artifact_set.artifact_set_digest,
        "expected_configuration_digest": manifest.configuration.configuration_digest,
        "expected_engine_digest": manifest.engine.engine_digest,
        "expected_environment_digest": manifest.expected_environment.environment_digest,
        "expected_target_id": manifest.target.target_id,
        "required_dimensions": sorted(x.value for x in required_dimensions),
        "optional_dimensions": [],
        "maximum_age_sequences": max_age,
        "replay_context": replay.model_dump(mode="json", by_alias=True),
        "maximum_evidence_references": 32,
        "limitations": ["Observation plan defines required snapshot dimensions only."],
    }
    return RuntimeObservationPlan.model_validate(
        identified(body, "plan_id", "runtime_plan_", "plan_digest")
    )


def build_coverage(
    required: list[ObservationDimension],
    *,
    missing: list[ObservationDimension] | None = None,
    proxy: list[ObservationDimension] | None = None,
    inaccessible: list[ObservationDimension] | None = None,
) -> ObservationCoverage:
    missing_set, inaccessible_set = set(missing or []), set(inaccessible or [])
    observed = sorted(set(required) - missing_set - inaccessible_set, key=lambda x: x.value)
    status = (
        ObservationCoverageStatus.COMPLETE_FOR_REQUIRED_DIMENSIONS
        if len(observed) == len(set(required)) and not inaccessible_set
        else ObservationCoverageStatus.INCOMPLETE
    )
    body = {
        "schema": "omiv.observation-coverage.v1",
        "expected_dimensions": sorted(x.value for x in set(required)),
        "observed_dimensions": [x.value for x in observed],
        "unsupported_dimensions": [],
        "inaccessible_dimensions": sorted(x.value for x in inaccessible_set),
        "errored_dimensions": [],
        "stale_dimensions": [],
        "proxy_only_dimensions": sorted(x.value for x in set(proxy or [])),
        "independently_corroborated_dimensions": [],
        "status": status.value,
        "limitations": ["Coverage is complete only for explicitly required dimensions."],
    }
    return ObservationCoverage.model_validate(
        identified(body, "coverage_id", "runtime_coverage_", "coverage_digest")
    )


def build_artifact_observation(
    artifact_set: DeploymentArtifactSet,
    *,
    strength: EvidenceStrength,
    proxy: bool = False,
    proxy_method: IdentityObservationMethod = IdentityObservationMethod.CONTAINER_IMAGE_PROXY,
    overrides: dict[str, str | None] | None = None,
) -> RuntimeArtifactSetObservation:
    values: list[ArtifactMemberObservation] = []
    for member in artifact_set.members:
        observed = (overrides or {}).get(member.logical_name, member.artifact.identity_digest)
        values.append(
            ArtifactMemberObservation.model_validate(
                {
                    "logical_name": member.logical_name,
                    "observed_identity_digest": observed,
                    "method": (proxy_method if proxy else member.expected_observation_method).value,
                    "evidence_strength": strength.value,
                    "generation_provenance_digest": member.generation_provenance_digest,
                    "limitations": ["Proxy identity does not prove loaded-byte identity."]
                    if proxy
                    else [],
                }
            )
        )
    return RuntimeArtifactSetObservation(
        artifact_set_digest=artifact_set.artifact_set_digest if not proxy else None,
        members=values,
        limitations=["Observed component identities are evaluated independently."],
    )


def build_observation(
    plan: RuntimeObservationPlan,
    record: DeploymentRecord,
    observer: RuntimeObserverIdentity,
    artifact_observation: RuntimeArtifactSetObservation,
    coverage: ObservationCoverage,
    *,
    strength: EvidenceStrength = EvidenceStrength.INDEPENDENTLY_CORROBORATED,
    config_digest: str | None = None,
    engine_digest: str | None = None,
    engine_binary_digest: str | None = None,
    environment_digest: str | None = None,
    target_id: str | None = None,
    sequence: int = 1,
    predecessor: str | None = None,
    trusted: bool = True,
    authorized: bool = True,
    status: ObservationStatus = ObservationStatus.COMPLETED,
) -> RuntimeObservation:
    body = {
        "schema": "omiv.runtime-observation.v1",
        "instance_id": record.instance_id,
        "plan_id": plan.plan_id,
        "deployment_record_id": record.record_id,
        "observer_id": observer.observer_id,
        "observer_authority": observer.authority.model_dump(mode="json", by_alias=True),
        "observed_artifact_set": artifact_observation.model_dump(mode="json"),
        "observed_configuration_digest": config_digest,
        "observed_engine_digest": engine_digest,
        "observed_engine_binary_digest": engine_binary_digest,
        "observed_environment_digest": environment_digest,
        "observed_target_id": target_id,
        "assertion": build_assertion(
            strength,
            authorized=authorized,
            trusted=trusted,
            corroborated=strength == EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        ).model_dump(mode="json"),
        "coverage": coverage.model_dump(mode="json", by_alias=True),
        "sequence_namespace": plan.replay_context.sequence_namespace,
        "epoch": plan.replay_context.epoch,
        "sequence": sequence,
        "predecessor_observation_id": predecessor,
        "evaluation_context_digest": plan.replay_context.evaluation_context_digest,
        "status": status.value,
        "evidence_references": [],
        "limitations": [
            "Runtime observation is a point-in-time observer assertion, not continuous trust."
        ],
    }
    return RuntimeObservation.model_validate(
        identified(body, "observation_id", "runtime_observation_", "observation_digest")
    )
