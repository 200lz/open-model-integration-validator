"""Fail-closed Phase 5G authority, replay, coverage, drift, and continuity evaluation."""

from __future__ import annotations

from omiv.errors import OmivInputError
from omiv.runtime.building import identified
from omiv.runtime.models import (
    ArtifactMemberContinuity,
    ArtifactMemberRole,
    AssertionAuthorityStatus,
    ContinuityEvaluation,
    ContinuityLevel,
    ContinuityPolicy,
    ContinuityVerdict,
    DeploymentArtifactMember,
    DeploymentIntent,
    DeploymentManifest,
    DeploymentRecord,
    DeploymentStatus,
    DriftCategory,
    DriftFinding,
    EvidenceStrength,
    IdentityObservationMethod,
    ObservationCoverageStatus,
    ObservationDimension,
    ObservationStatus,
    ProductSubject,
    RuntimeFreshness,
    RuntimeObservation,
    RuntimeObservationPlan,
    RuntimeObserverIdentity,
)


def detect_observation_chain_forks(observations: list[RuntimeObservation]) -> list[str]:
    """Return deterministic fork descriptions without using timestamps or local state."""
    sequence_groups: dict[tuple[str, str, int, int], set[str]] = {}
    successor_groups: dict[tuple[str, str, int, str], set[str]] = {}
    for observation in observations:
        sequence_key = (
            observation.observer_id,
            observation.sequence_namespace,
            observation.epoch,
            observation.sequence,
        )
        sequence_groups.setdefault(sequence_key, set()).add(observation.observation_id)
        if observation.predecessor_observation_id is not None:
            successor_key = (
                observation.observer_id,
                observation.sequence_namespace,
                observation.epoch,
                observation.predecessor_observation_id,
            )
            successor_groups.setdefault(successor_key, set()).add(observation.observation_id)
    forks = [
        f"sequence-fork:{key}:{','.join(sorted(values))}"
        for key, values in sorted(sequence_groups.items())
        if len(values) > 1
    ]
    forks.extend(
        f"predecessor-fork:{key}:{','.join(sorted(values))}"
        for key, values in sorted(successor_groups.items())
        if len(values) > 1
    )
    return sorted(forks)


def _authority_status(
    observer: RuntimeObserverIdentity,
    observation: RuntimeObservation,
    manifest: DeploymentManifest,
) -> AssertionAuthorityStatus:
    authority = observer.authority
    scope_ok = (
        authority.scope
        == observation.observer_authority.scope
        == manifest.instance.scope
        == manifest.target.scope
    )
    identity_ok = (
        observation.observer_id == observer.observer_id
        and observation.observer_authority == authority
        and authority.actor_id == observer.authority.actor_id
    )
    object_ok = "RUNTIME_OBSERVATION" in authority.object_types
    action_ok = "OBSERVE_RUNTIME" in authority.actions
    assertion_ok = "RUNTIME_IDENTITY" in authority.assertion_types
    target_ok = manifest.target.target_type in authority.target_classes
    artifacts_ok = all(
        member.artifact_class in authority.artifact_classes
        for member in manifest.artifact_set.members
    )
    sequence_ok = (
        authority.valid_from_sequence <= observation.sequence <= authority.valid_through_sequence
    )
    return (
        AssertionAuthorityStatus.AUTHORIZED
        if all(
            (
                scope_ok,
                identity_ok,
                object_ok,
                action_ok,
                assertion_ok,
                target_ok,
                artifacts_ok,
                sequence_ok,
                authority.delegated_by_authority_id is None,
            )
        )
        else AssertionAuthorityStatus.UNAUTHORIZED
    )


def _deployment_authorized(record: DeploymentRecord, manifest: DeploymentManifest) -> bool:
    authority = record.actor_authority
    return all(
        (
            record.actor.authority_id == authority.authority_id,
            authority.actor_id == record.actor.actor_id,
            authority.scope == manifest.instance.scope == record.target.scope,
            "DEPLOYMENT_RECORD" in authority.object_types,
            "DEPLOYMENT_ACTION" in authority.assertion_types,
            "DEPLOY" in authority.actions,
            manifest.target.target_type in authority.target_classes,
            all(
                member.artifact_class in authority.artifact_classes
                for member in manifest.artifact_set.members
            ),
            authority.valid_from_sequence
            <= manifest.instance.generation
            <= authority.valid_through_sequence,
            authority.delegated_by_authority_id is None,
        )
    )


def _drift(
    category: DriftCategory,
    expected: str,
    observed: str,
    method: IdentityObservationMethod,
    strength: EvidenceStrength,
    manifest: DeploymentManifest,
) -> DriftFinding:
    body = {
        "schema": "omiv.drift-finding.v1",
        "category": category.value,
        "expected_reference": expected,
        "observed_reference": observed,
        "observation_method": method.value,
        "evidence_strength": strength.value,
        "severity": "HIGH",
        "confidence": "CONFIRMED"
        if method
        in {
            IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
            IdentityObservationMethod.DIRECT_ARTIFACT_SET_IDENTITY,
        }
        else "MEDIUM",
        "policy_impact": "BLOCKING",
        "scope": manifest.instance.scope.model_dump(mode="json"),
        "limitations": [
            "Identity drift does not by itself establish semantic or behavioral impact."
        ],
        "remediation": "Reconcile expected and observed identity evidence before reevaluation.",
    }
    return DriftFinding.model_validate(
        identified(body, "drift_id", "runtime_drift_", "drift_digest")
    )


def _member_result(
    expected: DeploymentArtifactMember,
    observation: RuntimeObservation,
    manifest: DeploymentManifest,
) -> tuple[ArtifactMemberContinuity, DriftFinding | None, bool]:
    observed = next(
        (
            item
            for item in observation.observed_artifact_set.members
            if item.logical_name == expected.logical_name
        ),
        None,
    )
    if observed is None or observed.observed_identity_digest is None:
        result = ContinuityLevel.UNOBSERVED
        method = IdentityObservationMethod.UNOBSERVED
        strength = EvidenceStrength.DECLARED
        drift = None
        proxy = False
    else:
        method, strength = observed.method, observed.evidence_strength
        proxy = method in {
            IdentityObservationMethod.CONTAINER_IMAGE_PROXY,
            IdentityObservationMethod.REGISTRY_REFERENCE_IDENTITY,
            IdentityObservationMethod.MANIFEST_IDENTITY,
            IdentityObservationMethod.CONFIGURATION_PROXY,
            IdentityObservationMethod.DECLARED_IDENTITY,
        }
        generated_provenance_mismatch = (
            expected.role == ArtifactMemberRole.RUNTIME_GENERATED
            and observed.generation_provenance_digest != expected.generation_provenance_digest
        )
        identity_mismatch = (
            expected.role != ArtifactMemberRole.RUNTIME_GENERATED
            and observed.observed_identity_digest != expected.artifact.identity_digest
        )
        if generated_provenance_mismatch or identity_mismatch:
            result = ContinuityLevel.MISMATCH
            category = (
                DriftCategory.PRIMARY_ARTIFACT_DIGEST_DRIFT
                if expected.role.value == "PRIMARY"
                else DriftCategory.UNKNOWN_RUNTIME_COMPONENT
                if expected.role == ArtifactMemberRole.RUNTIME_GENERATED
                else DriftCategory.COMPANION_ARTIFACT_DRIFT
            )
            drift = _drift(
                category,
                (
                    expected.generation_provenance_digest
                    if expected.role == ArtifactMemberRole.RUNTIME_GENERATED
                    else expected.artifact.identity_digest
                )
                or "UNAVAILABLE",
                (
                    observed.generation_provenance_digest
                    if expected.role == ArtifactMemberRole.RUNTIME_GENERATED
                    else observed.observed_identity_digest
                )
                or "UNAVAILABLE",
                method,
                strength,
                manifest,
            )
        elif proxy:
            result, drift = ContinuityLevel.IDENTITY_PROXY_MATCH, None
        else:
            result, drift = ContinuityLevel.FULL_CONTINUITY, None
    member = ArtifactMemberContinuity(
        logical_name=expected.logical_name,
        required=expected.required,
        method=method,
        evidence_strength=strength,
        result=result,
        limitations=(
            ["Proxy identity does not establish loaded-byte continuity."] if proxy else []
        ),
    )
    return member, drift, proxy


def evaluate_continuity(
    subject: ProductSubject,
    intent: DeploymentIntent,
    manifest: DeploymentManifest,
    record: DeploymentRecord,
    observer: RuntimeObserverIdentity,
    plan: RuntimeObservationPlan,
    observation: RuntimeObservation,
    policy: ContinuityPolicy,
    *,
    evaluation_sequence: int,
) -> ContinuityEvaluation:
    """Reconstruct a snapshot verdict; no caller-supplied verdict is accepted."""
    try:
        for value in (subject, intent, manifest, record, observer, plan, observation, policy):
            type(value).model_validate(value.model_dump(mode="json", by_alias=True))
    except ValueError as exc:
        raise OmivInputError(f"runtime evidence is broken: {exc}") from exc

    blockers: list[str] = []
    limitations = sorted(
        {
            *intent.limitations,
            *intent.security_limitations,
            *manifest.security_limitations,
            *manifest.limitations,
            *record.limitations,
            *observer.limitations,
            *plan.limitations,
            *observation.limitations,
            *policy.limitations,
            "Snapshot continuity does not establish continuously unchanged state.",
        }
    )
    broken = (
        subject.subject_id != intent.subject_id
        or subject.subject_id != manifest.artifact_set.subject_id
        or subject.subject_class not in policy.accepted_subject_classes
        or intent.intent_id != manifest.intent_id
        or intent.intent_digest != manifest.intent_digest
        or intent.artifact_set_id != manifest.artifact_set.artifact_set_id
        or intent.artifact_set_digest != manifest.artifact_set.artifact_set_digest
        or intent.target != manifest.target
        or intent.expected_engine_id != manifest.engine.engine_id
        or intent.expected_configuration_id != manifest.configuration.configuration_id
        or intent.scope != manifest.instance.scope
        or intent.governance_decision_digest != manifest.governance_decision_digest
        or intent.security_evaluation_digest != manifest.security_evaluation_digest
        or intent.security_verdict != manifest.security_verdict
        or intent.security_limitations != manifest.security_limitations
        or intent.promotion_decision_digest != manifest.promotion_decision_digest
        or record.manifest_id != manifest.manifest_id
        or record.manifest_digest != manifest.manifest_digest
        or record.instance_id != manifest.instance.instance_id
        or record.target != manifest.target
        or record.deployed_artifact_set != manifest.artifact_set
        or record.configuration != manifest.configuration
        or record.engine != manifest.engine
        or observation.plan_id != plan.plan_id
        or observation.deployment_record_id != record.record_id
        or observer.observer_id != observation.observer_id
        or plan.manifest_id != manifest.manifest_id
        or plan.observer_id != observer.observer_id
        or plan.expected_artifact_set_digest != manifest.artifact_set.artifact_set_digest
        or plan.expected_configuration_digest != manifest.configuration.configuration_digest
        or plan.expected_engine_digest != manifest.engine.engine_digest
        or plan.expected_environment_digest != manifest.expected_environment.environment_digest
        or plan.expected_target_id != manifest.target.target_id
        or plan.replay_context.policy_digest != policy.policy_digest
    )
    replay_broken = (
        observation.instance_id != manifest.instance.instance_id
        or plan.instance_id != manifest.instance.instance_id
        or plan.replay_context.instance_id != observation.instance_id
        or plan.replay_context.observer_id != observation.observer_id
        or plan.replay_context.scope != manifest.instance.scope
        or plan.replay_context.manifest_digest != manifest.manifest_digest
        or plan.replay_context.target_id != manifest.target.target_id
        or plan.replay_context.artifact_set_digest != manifest.artifact_set.artifact_set_digest
        or plan.replay_context.expected_sequence != observation.sequence
        or plan.replay_context.sequence_namespace != observation.sequence_namespace
        or plan.replay_context.epoch != observation.epoch
        or plan.replay_context.predecessor_observation_id != observation.predecessor_observation_id
        or plan.replay_context.evaluation_context_digest != observation.evaluation_context_digest
    )
    authority = _authority_status(observer, observation, manifest)
    deployment_authorized = _deployment_authorized(record, manifest)
    trusted = (
        bool(observer.trust_references)
        and observation.assertion.trust_status == "TRUSTED_BY_POLICY"
    )
    independent = (
        record.actor.actor_id != observer.authority.actor_id
        and record.actor.signer_identity_id != observer.signer_identity_id
    )
    distinct_signer = record.actor.signer_identity_id != observer.signer_identity_id
    distinct_key = record.actor.key_id != observer.key_id
    distinct_root = record.actor.trust_root_id != observer.trust_root_id
    corroborated = observation.assertion.corroboration_status == "INDEPENDENT"
    deployment_strength_ok = record.assertion.origin in policy.accepted_deployment_strengths
    observation_strength_ok = observation.assertion.origin in policy.accepted_observation_strengths
    signed_deployment = record.assertion.signature_status == "VALID"
    signed_observation = observation.assertion.signature_status == "VALID"

    member_results: list[ArtifactMemberContinuity] = []
    drift: list[DriftFinding] = []
    proxy = False
    for member in manifest.artifact_set.members:
        result, member_drift, member_proxy = _member_result(member, observation, manifest)
        member_results.append(result)
        proxy |= member_proxy
        if member_drift is not None:
            drift.append(member_drift)
    expected_names = {item.logical_name for item in manifest.artifact_set.members}
    for unexpected in observation.observed_artifact_set.members:
        if unexpected.logical_name not in expected_names:
            drift.append(
                _drift(
                    DriftCategory.UNKNOWN_RUNTIME_COMPONENT,
                    "NOT_DECLARED",
                    unexpected.observed_identity_digest or "UNAVAILABLE",
                    unexpected.method,
                    unexpected.evidence_strength,
                    manifest,
                )
            )
    if (
        observation.observed_artifact_set.artifact_set_digest is not None
        and observation.observed_artifact_set.artifact_set_digest
        != manifest.artifact_set.artifact_set_digest
    ):
        drift.append(
            _drift(
                DriftCategory.ARTIFACT_SET_DRIFT,
                manifest.artifact_set.artifact_set_digest,
                observation.observed_artifact_set.artifact_set_digest,
                IdentityObservationMethod.DIRECT_ARTIFACT_SET_IDENTITY,
                observation.assertion.origin,
                manifest,
            )
        )
    required_results = [x.result for x in member_results if x.required]
    optional_unobserved = any(
        not expected.required and result.result == ContinuityLevel.UNOBSERVED
        for expected, result in zip(manifest.artifact_set.members, member_results, strict=True)
    )
    if any(x == ContinuityLevel.MISMATCH for x in required_results):
        artifact_set_result = ContinuityLevel.MISMATCH
    elif any(x == ContinuityLevel.UNOBSERVED for x in required_results):
        artifact_set_result = ContinuityLevel.UNOBSERVED
    elif any(x == ContinuityLevel.IDENTITY_PROXY_MATCH for x in required_results):
        artifact_set_result = ContinuityLevel.IDENTITY_PROXY_MATCH
    elif all(x == ContinuityLevel.FULL_CONTINUITY for x in required_results):
        artifact_set_result = ContinuityLevel.FULL_CONTINUITY
    else:
        artifact_set_result = ContinuityLevel.PARTIAL_CONTINUITY

    def dimension(
        expected: str,
        observed: str | None,
        category: DriftCategory,
        method: IdentityObservationMethod,
    ) -> ContinuityLevel:
        if observed is None:
            return ContinuityLevel.UNOBSERVED
        if expected != observed:
            drift.append(
                _drift(category, expected, observed, method, observation.assertion.origin, manifest)
            )
            return ContinuityLevel.MISMATCH
        return ContinuityLevel.FULL_CONTINUITY

    config_result = dimension(
        manifest.configuration.configuration_digest,
        observation.observed_configuration_digest,
        DriftCategory.RUNTIME_CONFIGURATION_DRIFT,
        IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
    )
    engine_result = dimension(
        manifest.engine.engine_digest,
        observation.observed_engine_digest,
        DriftCategory.RUNTIME_ENGINE_DRIFT,
        IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
    )
    if (
        observation.observed_engine_binary_digest is not None
        and manifest.engine.binary_digest != observation.observed_engine_binary_digest
    ):
        drift.append(
            _drift(
                DriftCategory.ENGINE_BINARY_DRIFT,
                manifest.engine.binary_digest or "UNAVAILABLE",
                observation.observed_engine_binary_digest,
                IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
                observation.assertion.origin,
                manifest,
            )
        )
        engine_result = ContinuityLevel.MISMATCH
    environment_result = dimension(
        manifest.expected_environment.environment_digest,
        observation.observed_environment_digest,
        DriftCategory.ENVIRONMENT_DRIFT,
        IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
    )
    target_result = dimension(
        manifest.target.target_id,
        observation.observed_target_id,
        DriftCategory.TARGET_DRIFT,
        IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
    )
    age = evaluation_sequence - observation.sequence
    freshness = (
        RuntimeFreshness.INVALID
        if age < 0
        else RuntimeFreshness.STALE
        if age > policy.maximum_age_sequences
        else RuntimeFreshness.CURRENT
    )
    coverage_ok = (
        observation.coverage.status == ObservationCoverageStatus.COMPLETE_FOR_REQUIRED_DIMENSIONS
    )
    required_observed = set(policy.required_dimensions).issubset(
        observation.coverage.observed_dimensions
    )
    direct_values_present = all(
        (
            ObservationDimension.RUNTIME_CONFIG_DIGEST not in policy.required_dimensions
            or observation.observed_configuration_digest is not None,
            ObservationDimension.ENGINE_VERSION_REVISION not in policy.required_dimensions
            or observation.observed_engine_digest is not None,
            ObservationDimension.ENGINE_BINARY_DIGEST not in policy.required_dimensions
            or observation.observed_engine_binary_digest is not None,
            ObservationDimension.ENVIRONMENT_IDENTITY not in policy.required_dimensions
            or observation.observed_environment_digest is not None,
            ObservationDimension.TARGET_IDENTITY not in policy.required_dimensions
            or observation.observed_target_id is not None,
        )
    )
    if broken:
        verdict = ContinuityVerdict.EVIDENCE_BROKEN
        blockers.append("runtime evidence references are broken")
    elif replay_broken:
        verdict = ContinuityVerdict.REPLAY_REJECTED
        blockers.append(
            "observation is not bound to the exact deployment instance and replay context"
        )
    elif drift:
        verdict = ContinuityVerdict.DRIFT_DETECTED
        blockers.append("one or more required identities drifted")
    elif authority != AssertionAuthorityStatus.AUTHORIZED:
        verdict = ContinuityVerdict.OBSERVER_UNAUTHORIZED
        blockers.append("observer lacks authority for this assertion and scope")
    elif not deployment_authorized:
        verdict = ContinuityVerdict.DEPLOYMENT_UNVERIFIED
        blockers.append("deployment actor lacks authority for this assertion and scope")
    elif policy.require_trusted_observer and not trusted:
        verdict = ContinuityVerdict.OBSERVER_UNTRUSTED
        blockers.append("observer is not trusted by the selected policy")
    elif (
        not deployment_strength_ok
        or (policy.require_signed_deployment and not signed_deployment)
        or record.status
        in {
            DeploymentStatus.COMPLETED_DECLARED,
            DeploymentStatus.NOT_OBSERVED,
            DeploymentStatus.UNKNOWN,
        }
    ):
        verdict = ContinuityVerdict.DEPLOYMENT_UNVERIFIED
        blockers.append("deployment evidence does not satisfy policy")
    elif not coverage_ok or not required_observed or not direct_values_present:
        verdict = ContinuityVerdict.COVERAGE_INCOMPLETE
        blockers.append("mandatory observation dimensions are incomplete")
    elif freshness != RuntimeFreshness.CURRENT:
        verdict = ContinuityVerdict.STALE
        blockers.append(
            "runtime observation is stale or invalid for the explicit evaluation context"
        )
    elif observation.status in {
        ObservationStatus.NOT_OBSERVED,
        ObservationStatus.FAILED,
        ObservationStatus.INACCESSIBLE,
    }:
        verdict = ContinuityVerdict.NOT_OBSERVED
        blockers.append("runtime state was not observed")
    elif (
        intent.security_verdict == "PASS_WITH_LIMITATIONS"
        and not policy.allow_limited_security_evidence
    ):
        verdict = ContinuityVerdict.NOT_EVALUATED
        blockers.append("selected continuity policy rejects limited security evidence")
    elif policy.fail_closed_reserved:
        verdict = ContinuityVerdict.NOT_EVALUATED
        blockers.append("regulated profile remains fail closed in Phase 5G")
    elif policy.require_signed_observation and not signed_observation:
        verdict = ContinuityVerdict.OBSERVER_UNTRUSTED
        blockers.append("trusted signed runtime observation is required")
    elif not observation_strength_ok:
        verdict = ContinuityVerdict.PARTIAL_CONTINUITY
        blockers.append("observation evidence strength is below policy requirement")
    elif policy.require_independent_observer and not independent:
        verdict = ContinuityVerdict.OBSERVER_UNAUTHORIZED
        blockers.append("policy requires deployer/observer separation")
    elif policy.require_distinct_signer and not distinct_signer:
        verdict = ContinuityVerdict.OBSERVER_UNAUTHORIZED
        blockers.append("policy requires distinct deployment and observer signers")
    elif policy.require_distinct_key and not distinct_key:
        verdict = ContinuityVerdict.OBSERVER_UNAUTHORIZED
        blockers.append("policy requires distinct deployment and observer keys")
    elif policy.require_distinct_trust_root and not distinct_root:
        verdict = ContinuityVerdict.OBSERVER_UNAUTHORIZED
        blockers.append("policy requires distinct deployment and observer trust roots")
    elif policy.require_corroboration and not corroborated:
        verdict = ContinuityVerdict.PARTIAL_CONTINUITY
        blockers.append("policy requires independent corroboration")
    elif policy.require_direct_artifact_identity and proxy:
        verdict = ContinuityVerdict.IDENTITY_PROXY_MATCH
        blockers.append("required artifact identity is proxy-only")
    elif proxy:
        verdict = ContinuityVerdict.IDENTITY_PROXY_MATCH
    elif optional_unobserved:
        verdict = ContinuityVerdict.PARTIAL_CONTINUITY
        blockers.append("a declared optional or runtime-generated component was not observed")
    elif not independent:
        verdict = ContinuityVerdict.PASS_WITH_LIMITATIONS
        limitations.append("Deployment was self-observed; independent corroboration is absent.")
    elif policy.offline_trust_requires_limitation:
        verdict = ContinuityVerdict.PASS_WITH_LIMITATIONS
        limitations.extend(
            [
                "Offline trust-bundle freshness is explicit only for the supplied snapshot.",
                "Online revocation status was unavailable and was not treated as current.",
            ]
        )
    else:
        verdict = ContinuityVerdict.PASS

    unobserved = sorted(
        set(policy.required_dimensions) - set(observation.coverage.observed_dimensions),
        key=lambda x: x.value,
    )
    body = {
        "schema": "omiv.continuity-evaluation.v1",
        "subject_id": subject.subject_id,
        "artifact_set_id": manifest.artifact_set.artifact_set_id,
        "intent_digest": intent.intent_digest,
        "instance_id": manifest.instance.instance_id,
        "manifest_digest": manifest.manifest_digest,
        "deployment_record_digest": record.record_digest,
        "observation_digest": observation.observation_digest,
        "policy_id": policy.policy_id,
        "policy_digest": policy.policy_digest,
        "deployment_evidence": "VERIFIED" if deployment_strength_ok else "DECLARED_ONLY",
        "observation_integrity": "VALID" if not broken else "BROKEN",
        "observer_trust": "TRUSTED_BY_POLICY" if trusted else "UNTRUSTED_BY_POLICY",
        "observer_authority": authority.value,
        "separation_of_duties": "SATISFIED" if independent else "SELF_OBSERVED",
        "replay_status": "REJECTED" if replay_broken else "BOUND",
        "freshness": freshness.value,
        "coverage_status": observation.coverage.status.value,
        "artifact_members": [x.model_dump(mode="json") for x in member_results],
        "artifact_set_continuity": artifact_set_result.value,
        "configuration_continuity": config_result.value,
        "engine_continuity": engine_result.value,
        "environment_continuity": environment_result.value,
        "target_continuity": target_result.value,
        "security_evidence_continuity": intent.security_verdict,
        "governance_continuity": "APPLICABLE_TO_INSTANCE",
        "drift_findings": [
            x.model_dump(mode="json", by_alias=True)
            for x in sorted(drift, key=lambda x: x.drift_id)
        ],
        "verdict": verdict.value,
        "blockers": sorted(blockers),
        "limitations": sorted(set(limitations)),
        "unobserved_dimensions": [x.value for x in unobserved],
        "snapshot_scope": "SNAPSHOT_ONLY",
        "behavioral_parity": "NOT_CHECKED",
        "runtime_safety": "NOT_VERIFIED",
        "continuous_continuity": "NOT_ESTABLISHED",
        "trusted_timestamp_status": "NOT_AVAILABLE",
        "revocation_status": (
            "NOT_EVALUATED"
            if policy.fail_closed_reserved
            else "ONLINE_UNAVAILABLE"
            if policy.offline_trust_requires_limitation
            else "EVALUATED_NO_APPLICABLE_REVOCATION"
        ),
        "trust_bundle_freshness": (
            "NOT_EVALUATED"
            if policy.fail_closed_reserved
            else "LIMITED_OFFLINE_SNAPSHOT"
            if policy.offline_trust_requires_limitation
            else "CURRENT_FOR_EXPLICIT_CONTEXT"
        ),
        "structured_gaps": (
            [
                "ACTUAL_DEPLOYMENT_SIDE_EFFECT_NOT_OPERATIONALLY_OBSERVED",
                "BEHAVIORAL_PARITY_UNAVAILABLE",
                "CONTINUOUS_OBSERVATION_UNAVAILABLE",
                "CONTINUOUS_TRUST_REEVALUATION_UNAVAILABLE",
                "HARDWARE_RUNTIME_ATTESTATION_UNAVAILABLE",
                "NUMERICAL_PARITY_UNAVAILABLE",
                "ONLINE_REVOCATION_UNAVAILABLE",
                "QUANTIZATION_FIDELITY_UNAVAILABLE",
                "RUNTIME_SAFETY_UNAVAILABLE",
                "TOKENIZER_PARITY_UNAVAILABLE",
                "TRUSTED_TIMESTAMP_UNAVAILABLE",
            ]
            if policy.fail_closed_reserved
            else []
        ),
    }
    return ContinuityEvaluation.model_validate(
        identified(body, "evaluation_id", "runtime_evaluation_", "evaluation_digest")
    )


def verify_continuity_evaluation(
    observed: ContinuityEvaluation,
    subject: ProductSubject,
    intent: DeploymentIntent,
    manifest: DeploymentManifest,
    record: DeploymentRecord,
    observer: RuntimeObserverIdentity,
    plan: RuntimeObservationPlan,
    observation: RuntimeObservation,
    policy: ContinuityPolicy,
    *,
    evaluation_sequence: int,
) -> ContinuityEvaluation:
    expected = evaluate_continuity(
        subject,
        intent,
        manifest,
        record,
        observer,
        plan,
        observation,
        policy,
        evaluation_sequence=evaluation_sequence,
    )
    if expected != observed:
        raise OmivInputError("continuity evaluation does not match deterministic reconstruction")
    return observed
