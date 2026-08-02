"""Phase 5G deployment/runtime snapshot evidence and continuity tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.governance.evaluation import _evaluate_requirement, build_requirement, build_subject
from omiv.governance.models import EvidenceCategory, VerificationMode
from omiv.runtime.adapters import (
    RESERVED_ADAPTER_IDS,
    adapt_governance_runtime,
    get_adapter,
    governance_runtime_evidence_references,
    import_local_record,
)
from omiv.runtime.artifact_index import verify_runtime_artifact_index
from omiv.runtime.building import (
    artifact_member,
    build_actor,
    build_adapter,
    build_artifact_observation,
    build_artifact_set,
    build_assertion,
    build_authority,
    build_configuration,
    build_coverage,
    build_deployment_record,
    build_engine,
    build_environment,
    build_instance,
    build_intent,
    build_manifest,
    build_observation,
    build_observation_plan,
    build_observer,
    build_product_subject,
    build_replay_context,
    build_target,
    identified,
    synthetic_scope,
)
from omiv.runtime.continuity import (
    detect_observation_chain_forks,
    evaluate_continuity,
    verify_continuity_evaluation,
)
from omiv.runtime.examples import generate_runtime_examples
from omiv.runtime.models import (
    ArtifactMemberObservation,
    ArtifactMemberRole,
    AssertionAuthorityStatus,
    ContinuityPolicyProfile,
    ContinuityVerdict,
    DeploymentArtifactSet,
    DeploymentIntent,
    DeploymentStatus,
    EvidenceStrength,
    IdentityObservationMethod,
    ObservationCoverage,
    ObservationCoverageStatus,
    ObservationDimension,
    ProductSubject,
    ProductSubjectClass,
    RuntimeArtifactIndex,
    RuntimeArtifactSetObservation,
    RuntimeEngineFamily,
    RuntimeObservation,
    SecretReference,
)
from omiv.runtime.policy import PRECEDENCE, build_continuity_policy
from omiv.runtime.reporting import (
    build_runtime_report,
    render_runtime_markdown,
    verify_runtime_report,
)
from omiv.runtime.schema import RUNTIME_SCHEMA_MODELS, schema_model
from omiv.trust.models import ACTIVE_PURPOSES, SignaturePurpose, SignedObjectType
from omiv.trust.signing import EXPECTED_PURPOSE, OBJECT_METADATA


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("runtime-generated")
    generate_runtime_examples(root)
    return root


@pytest.fixture()
def canonical() -> dict[str, object]:
    scope = synthetic_scope()
    subject = build_product_subject(ProductSubjectClass.MODEL_WEIGHTS, "subject.test", scope)
    members = [
        artifact_member(
            "adapter.data",
            ProductSubjectClass.LORA_ADAPTER,
            "adapter",
            role=ArtifactMemberRole.MANDATORY_COMPANION,
        ),
        artifact_member(
            "model.weights",
            ProductSubjectClass.MODEL_WEIGHTS,
            "weights",
            role=ArtifactMemberRole.PRIMARY,
        ),
        artifact_member(
            "prompt.template",
            ProductSubjectClass.PROMPT_TEMPLATE,
            "prompt",
            role=ArtifactMemberRole.OPTIONAL_COMPANION,
            required=False,
        ),
        artifact_member(
            "runtime.generated-index",
            ProductSubjectClass.OTHER_DECLARED,
            "generated-logical-identity",
            role=ArtifactMemberRole.RUNTIME_GENERATED,
            required=False,
            generation_provenance_seed="weights",
        ),
        artifact_member(
            "tokenizer.data",
            ProductSubjectClass.TOKENIZER,
            "tokenizer",
            role=ArtifactMemberRole.MANDATORY_COMPANION,
        ),
    ]
    artifact_set = build_artifact_set(subject, members)
    deploy_auth = build_authority(
        "actor.deploy", scope, assertion_types=["DEPLOYMENT_ACTION"], actions=["DEPLOY"]
    )
    observer_auth = build_authority(
        "actor.observe",
        scope,
        assertion_types=["RUNTIME_IDENTITY"],
        actions=["OBSERVE_RUNTIME"],
    )
    target = build_target(scope)
    config = build_configuration()
    engine = build_engine()
    environment = build_environment(scope)
    actor = build_actor(
        "actor.deploy",
        "deployer",
        deploy_auth,
        signer="signer.deploy",
        key="key.deploy",
        root="root.deploy",
    )
    intent = build_intent(
        subject,
        artifact_set,
        target,
        engine,
        config,
        actor,
        deploy_auth,
        security_verdict="PASS",
    )
    instance = build_instance(intent, artifact_set, config, engine)
    manifest = build_manifest(
        intent,
        instance,
        artifact_set,
        target,
        engine,
        config,
        environment,
        build_adapter(scope),
    )
    record = build_deployment_record(
        manifest,
        actor,
        deploy_auth,
        strength=EvidenceStrength.SIGNED_AND_TRUSTED,
        trusted=True,
    )
    observer = build_observer(scope, observer_auth)
    policy = build_continuity_policy(ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY)
    replay = build_replay_context(instance, manifest, observer, policy.policy_digest)
    plan = build_observation_plan(manifest, observer, replay, policy.required_dimensions)
    coverage = build_coverage(policy.required_dimensions)
    observation = build_observation(
        plan,
        record,
        observer,
        build_artifact_observation(
            artifact_set, strength=EvidenceStrength.INDEPENDENTLY_CORROBORATED
        ),
        coverage,
        config_digest=config.configuration_digest,
        engine_digest=engine.engine_digest,
        engine_binary_digest=engine.binary_digest,
        environment_digest=environment.environment_digest,
        target_id=target.target_id,
    )
    evaluation = evaluate_continuity(
        subject,
        intent,
        manifest,
        record,
        observer,
        plan,
        observation,
        policy,
        evaluation_sequence=2,
    )
    return locals()


def _rebuild_observation(observation: RuntimeObservation, **updates: object) -> RuntimeObservation:
    body = observation.model_dump(mode="json", by_alias=True)
    body.pop("observation_id")
    body.pop("observation_digest")
    body.update(updates)
    return RuntimeObservation.model_validate(
        identified(body, "observation_id", "runtime_observation_", "observation_digest")
    )


def _evaluate_with(
    canonical: dict[str, object],
    *,
    observation: RuntimeObservation | None = None,
    observer: object | None = None,
    policy: object | None = None,
    intent: object | None = None,
    evaluation_sequence: int = 2,
):
    return evaluate_continuity(
        canonical["subject"],
        intent or canonical["intent"],
        canonical["manifest"],
        canonical["record"],
        observer or canonical["observer"],
        canonical["plan"],
        observation or canonical["observation"],
        policy or canonical["policy"],
        evaluation_sequence=evaluation_sequence,
    )


def test_precedence_is_exact() -> None:
    assert [
        ContinuityVerdict(value)
        for value in (
            "EVIDENCE_BROKEN",
            "REPLAY_REJECTED",
            "MISMATCH",
            "DRIFT_DETECTED",
            "OBSERVER_UNAUTHORIZED",
            "OBSERVER_UNTRUSTED",
            "DEPLOYMENT_UNVERIFIED",
            "COVERAGE_INCOMPLETE",
            "STALE",
            "NOT_OBSERVED",
            "NOT_EVALUATED",
            "IDENTITY_PROXY_MATCH",
            "PARTIAL_CONTINUITY",
            "PASS_WITH_LIMITATIONS",
            "PASS",
        )
    ] == PRECEDENCE


@pytest.mark.parametrize("subject_class", list(ProductSubjectClass))
def test_multi_product_subjects(subject_class: ProductSubjectClass) -> None:
    subject = build_product_subject(subject_class, "subject.multi-product", synthetic_scope())
    assert subject.subject_class == subject_class


@pytest.mark.parametrize(
    "family",
    [
        RuntimeEngineFamily.LLAMA_CPP,
        RuntimeEngineFamily.VLLM,
        RuntimeEngineFamily.ONNX_RUNTIME,
        RuntimeEngineFamily.EDGE_RUNTIME,
    ],
)
def test_multiple_engine_families(family: RuntimeEngineFamily) -> None:
    assert build_engine(family=family).family == family


def test_mixed_artifact_set_and_deterministic_identity(canonical: dict[str, object]) -> None:
    artifact_set = canonical["artifact_set"]
    assert isinstance(artifact_set, DeploymentArtifactSet)
    assert len({x.artifact_class for x in artifact_set.members}) >= 3
    assert artifact_set == DeploymentArtifactSet.model_validate(
        artifact_set.model_dump(mode="json", by_alias=True)
    )


def test_exactly_one_primary_required(canonical: dict[str, object]) -> None:
    value = canonical["artifact_set"].model_dump(mode="json", by_alias=True)  # type: ignore[union-attr]
    value["members"][0]["role"] = "PRIMARY"
    with pytest.raises(ValidationError):
        DeploymentArtifactSet.model_validate(value)


@pytest.mark.parametrize(
    "unsafe",
    [
        "/home/synthetic/runtime.json",
        "123e4567-e89b-12d3-a456-426614174000",
        "2026-08-02T12:00:00Z",
        "https://runtime.invalid/path?Signature=synthetic",
        "Bearer synthetic",
    ],
)
def test_portability_rejects_path_uuid_time_and_secrets(unsafe: str) -> None:
    with pytest.raises(ValidationError):
        build_product_subject(ProductSubjectClass.OTHER_DECLARED, unsafe, synthetic_scope())


def test_unknown_fields_and_caller_verdict_rejected(canonical: dict[str, object]) -> None:
    subject = canonical["subject"]
    assert isinstance(subject, ProductSubject)
    value = subject.model_dump(mode="json", by_alias=True)
    value["verdict"] = "PASS"
    with pytest.raises(ValidationError):
        ProductSubject.model_validate(value)


def test_configuration_field_order_and_secret_references() -> None:
    first = build_configuration({"precision": "declared", "batch-size": "1"})
    second = build_configuration({"batch-size": "1", "precision": "declared"})
    assert first == second
    raw = json.dumps(first.model_dump(mode="json"), sort_keys=True).lower()
    assert "secret_value" not in raw and "access_token" not in raw
    assert first.limitations == [
        "Normalized identity equality does not prove semantic equivalence."
    ]


def test_evidence_dimensions_do_not_use_ordinal_escalation() -> None:
    signed_declaration = build_assertion(EvidenceStrength.SIGNED)
    observed = build_assertion(EvidenceStrength.SYSTEM_OBSERVED)
    corroborated = build_assertion(
        EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        corroborated=True,
    )
    assert signed_declaration.signature_status == "VALID"
    assert not signed_declaration.directly_observed
    assert observed.signature_status == "NOT_PRESENT"
    assert observed.directly_observed
    assert corroborated.independently_corroborated
    assert corroborated.signature_status == "NOT_PRESENT"


def test_adapter_ceiling_is_explicit_not_enum_order(canonical: dict[str, object]) -> None:
    adapter = get_adapter("omiv.adapter.local-runtime.v1", canonical["scope"])
    assert adapter.accepted_evidence_origins == [
        EvidenceStrength.DECLARED,
        EvidenceStrength.IMPORTED_UNVERIFIED,
        EvidenceStrength.STRUCTURALLY_VERIFIED,
        EvidenceStrength.EVIDENCE_LINKED,
    ]
    value = canonical["observation"].model_dump(mode="json", by_alias=True)  # type: ignore[union-attr]
    value["assertion"] = build_assertion(EvidenceStrength.SIGNED).model_dump(mode="json")
    value.pop("observation_id")
    value.pop("observation_digest")
    signed = RuntimeObservation.model_validate(
        identified(value, "observation_id", "runtime_observation_", "observation_digest")
    )
    with pytest.raises(OmivInputError):
        import_local_record(
            signed.model_dump(mode="json", by_alias=True), RuntimeObservation, adapter
        )


def test_secret_reference_is_not_secret_value_fingerprint() -> None:
    configuration = build_configuration()
    reference = configuration.secret_references[0]
    assert reference.provider_class == "logical-provider.synthetic"
    assert (
        reference.reference_digest
        == hashlib.sha256(b'{"logical-reference":"synthetic"}').hexdigest()
    )
    raw = reference.model_dump(mode="json")
    raw["secret_value"] = "value-one"
    with pytest.raises(ValidationError):
        SecretReference.model_validate(raw)


def test_configuration_alias_defaults_unknown_and_types() -> None:
    alias = build_configuration({"batch_size": "2", "precision": "declared"})
    canonical_name = build_configuration({"batch-size": "2", "precision": "declared"})
    assert alias.configuration_digest != canonical_name.configuration_digest
    assert {field.source for field in alias.normalized_fields} == {
        "ALIAS_NORMALIZED",
        "EXPLICIT",
    }
    implicit = build_configuration()
    explicit = build_configuration({"batch-size": "1", "precision": "declared"})
    assert implicit.configuration_digest != explicit.configuration_digest
    with pytest.raises(ValueError, match="unknown runtime configuration field"):
        build_configuration({"unknown": "value"})
    with pytest.raises(ValueError, match="must be a string"):
        build_configuration({"batch-size": 1})  # type: ignore[dict-item]


def test_engine_same_version_different_binary_is_distinct() -> None:
    first = build_engine(version="1.0", binary_seed="first")
    second = build_engine(version="1.0", binary_seed="second")
    assert first.display_version == second.display_version
    assert first.binary_digest != second.binary_digest
    assert first.engine_digest != second.engine_digest


def test_engine_revision_image_and_dependency_identity_are_independent() -> None:
    baseline = build_engine(image_seed="image-one")
    revision = build_engine(revision="revision-2", image_seed="image-one")
    image = build_engine(image_seed="image-two")
    dependency = build_engine(image_seed="image-one", dependency_lock_seed="v2")
    assert baseline.display_version == revision.display_version
    assert baseline.binary_digest == revision.binary_digest
    assert baseline.engine_digest != revision.engine_digest
    assert baseline.container_image_digest != image.container_image_digest
    assert baseline.dependency_lock_digest != dependency.dependency_lock_digest
    assert baseline.runtime_configuration_digest


def test_full_team_continuity_passes(canonical: dict[str, object]) -> None:
    evaluation = canonical["evaluation"]
    assert evaluation.verdict == ContinuityVerdict.PASS  # type: ignore[union-attr]
    verify_continuity_evaluation(
        evaluation,
        canonical["subject"],
        canonical["intent"],
        canonical["manifest"],
        canonical["record"],
        canonical["observer"],
        canonical["plan"],
        canonical["observation"],
        canonical["policy"],
        evaluation_sequence=2,
    )


@pytest.mark.parametrize(
    ("name", "verdict"),
    [
        ("local-self-observed", "PASS_WITH_LIMITATIONS"),
        ("trusted-team", "PASS"),
        ("companion-drift", "DRIFT_DETECTED"),
        ("container-proxy", "IDENTITY_PROXY_MATCH"),
        ("registry-proxy", "IDENTITY_PROXY_MATCH"),
        ("configuration-drift", "DRIFT_DETECTED"),
        ("engine-binary-drift", "DRIFT_DETECTED"),
        ("stale-observation", "STALE"),
        ("unknown-observer", "OBSERVER_UNTRUSTED"),
        ("unauthorized-observer", "OBSERVER_UNAUTHORIZED"),
        ("cross-tenant", "OBSERVER_UNAUTHORIZED"),
        ("replayed-observation", "REPLAY_REJECTED"),
        ("declared-only", "DEPLOYMENT_UNVERIFIED"),
        ("air-gapped", "PASS_WITH_LIMITATIONS"),
        ("enterprise", "PASS"),
        ("regulated", "NOT_EVALUATED"),
    ],
)
def test_generated_scenario_outcomes(generated: Path, name: str, verdict: str) -> None:
    value = json.loads(
        (generated / "runtime" / "examples" / f"{name}.continuity-evaluation.json").read_text()
    )
    assert value["verdict"] == verdict
    assert value["snapshot_scope"] == "SNAPSHOT_ONLY"
    assert value["behavioral_parity"] == "NOT_CHECKED"
    assert value["runtime_safety"] == "NOT_VERIFIED"
    assert value["continuous_continuity"] == "NOT_ESTABLISHED"


def test_enterprise_pass_is_fully_reconstructed(generated: Path) -> None:
    value = json.loads(
        (generated / "runtime/examples/enterprise.continuity-evaluation.json").read_text()
    )
    assert value["verdict"] == "PASS"
    assert value["deployment_evidence"] == "VERIFIED"
    assert value["observer_trust"] == "TRUSTED_BY_POLICY"
    assert value["observer_authority"] == "AUTHORIZED"
    assert value["separation_of_duties"] == "SATISFIED"
    assert value["replay_status"] == "BOUND"
    assert value["freshness"] == "CURRENT"
    assert value["coverage_status"] == "COMPLETE_FOR_REQUIRED_DIMENSIONS"
    assert value["artifact_set_continuity"] == "FULL_CONTINUITY"
    assert value["configuration_continuity"] == "FULL_CONTINUITY"
    assert value["engine_continuity"] == "FULL_CONTINUITY"
    assert value["environment_continuity"] == "FULL_CONTINUITY"
    assert value["target_continuity"] == "FULL_CONTINUITY"
    assert not value["drift_findings"] and not value["structured_gaps"]
    assert all(
        member["result"] == "FULL_CONTINUITY"
        for member in value["artifact_members"]
        if member["required"]
    )


def test_air_gapped_stale_expired_and_wrong_domain_fail_closed(
    canonical: dict[str, object],
) -> None:
    policy = build_continuity_policy(ContinuityPolicyProfile.AIR_GAPPED_RUNTIME_CONTINUITY)

    def evaluate_observer(observer: object, evaluation_sequence: int = 2):
        replay = build_replay_context(
            canonical["instance"], canonical["manifest"], observer, policy.policy_digest
        )
        plan = build_observation_plan(
            canonical["manifest"], observer, replay, policy.required_dimensions
        )
        observation = build_observation(
            plan,
            canonical["record"],
            observer,
            build_artifact_observation(
                canonical["artifact_set"],
                strength=EvidenceStrength.INDEPENDENTLY_CORROBORATED,
            ),
            build_coverage(policy.required_dimensions),
            config_digest=canonical["config"].configuration_digest,
            engine_digest=canonical["engine"].engine_digest,
            engine_binary_digest=canonical["engine"].binary_digest,
            environment_digest=canonical["environment"].environment_digest,
            target_id=canonical["target"].target_id,
        )
        return evaluate_continuity(
            canonical["subject"],
            canonical["intent"],
            canonical["manifest"],
            canonical["record"],
            observer,
            plan,
            observation,
            policy,
            evaluation_sequence=evaluation_sequence,
        )

    assert evaluate_observer(canonical["observer"], 20).verdict == ContinuityVerdict.STALE
    expired_authority = build_authority(
        "actor.observe",
        canonical["scope"],
        assertion_types=["RUNTIME_IDENTITY"],
        actions=["OBSERVE_RUNTIME"],
        valid_from_sequence=0,
        valid_through_sequence=0,
    )
    expired_observer = build_observer(canonical["scope"], expired_authority)
    assert evaluate_observer(expired_observer).verdict == ContinuityVerdict.OBSERVER_UNAUTHORIZED
    wrong_scope = synthetic_scope(tenant="tenant.other")
    wrong_authority = build_authority(
        "actor.observe",
        wrong_scope,
        assertion_types=["RUNTIME_IDENTITY"],
        actions=["OBSERVE_RUNTIME"],
    )
    wrong_observer = build_observer(wrong_scope, wrong_authority)
    assert evaluate_observer(wrong_observer).verdict == ContinuityVerdict.OBSERVER_UNAUTHORIZED


def test_companion_drift_does_not_hide_primary_match(generated: Path) -> None:
    value = json.loads(
        (generated / "runtime/examples/companion-drift.continuity-evaluation.json").read_text()
    )
    members = {x["logical_name"]: x["result"] for x in value["artifact_members"]}
    assert members["model.weights"] == "FULL_CONTINUITY"
    assert members["tokenizer.data"] == "MISMATCH"
    assert value["drift_findings"][0]["category"] == "COMPANION_ARTIFACT_DRIFT"


def test_optional_and_runtime_generated_component_semantics(
    canonical: dict[str, object],
) -> None:
    original = canonical["observation"].observed_artifact_set
    optional_absent = RuntimeArtifactSetObservation(
        artifact_set_digest=None,
        members=[x for x in original.members if x.logical_name != "prompt.template"],
        limitations=original.limitations,
    )
    absent_observation = _rebuild_observation(
        canonical["observation"],
        observed_artifact_set=optional_absent.model_dump(mode="json"),
    )
    assert _evaluate_with(canonical, observation=absent_observation).verdict == (
        ContinuityVerdict.PARTIAL_CONTINUITY
    )

    matching = _evaluate_with(canonical)
    assert matching.verdict == ContinuityVerdict.PASS

    drifted_optional = build_artifact_observation(
        canonical["artifact_set"],
        strength=EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        overrides={"prompt.template": "f" * 64},
    )
    drift_observation = _rebuild_observation(
        canonical["observation"],
        observed_artifact_set=drifted_optional.model_dump(mode="json"),
    )
    assert _evaluate_with(canonical, observation=drift_observation).verdict == (
        ContinuityVerdict.DRIFT_DETECTED
    )

    generated_members = []
    for member in original.members:
        if member.logical_name == "runtime.generated-index":
            raw = member.model_dump(mode="json")
            raw["generation_provenance_digest"] = "e" * 64
            member = ArtifactMemberObservation.model_validate(raw)
        generated_members.append(member)
    generated_observation = _rebuild_observation(
        canonical["observation"],
        observed_artifact_set=RuntimeArtifactSetObservation(
            artifact_set_digest=original.artifact_set_digest,
            members=generated_members,
            limitations=original.limitations,
        ).model_dump(mode="json"),
    )
    generated_result = _evaluate_with(canonical, observation=generated_observation)
    assert generated_result.verdict == ContinuityVerdict.DRIFT_DETECTED
    assert any(
        finding.category.value == "UNKNOWN_RUNTIME_COMPONENT"
        for finding in generated_result.drift_findings
    )


def test_unexpected_runtime_component_is_explicit_drift(
    canonical: dict[str, object],
) -> None:
    observed = canonical["observation"].observed_artifact_set
    unexpected = ArtifactMemberObservation(
        logical_name="component.unexpected",
        observed_identity_digest="d" * 64,
        method=IdentityObservationMethod.DIRECT_BYTE_IDENTITY,
        evidence_strength=EvidenceStrength.SYSTEM_OBSERVED,
        limitations=[],
    )
    artifact_observation = RuntimeArtifactSetObservation(
        artifact_set_digest=observed.artifact_set_digest,
        members=[*observed.members, unexpected],
        limitations=observed.limitations,
    )
    observation = _rebuild_observation(
        canonical["observation"],
        observed_artifact_set=artifact_observation.model_dump(mode="json"),
    )
    result = _evaluate_with(canonical, observation=observation)
    assert result.verdict == ContinuityVerdict.DRIFT_DETECTED
    assert any(
        finding.category.value == "UNKNOWN_RUNTIME_COMPONENT" for finding in result.drift_findings
    )


def test_proxy_does_not_claim_loaded_bytes(generated: Path) -> None:
    value = json.loads(
        (generated / "runtime/examples/container-proxy.continuity-evaluation.json").read_text()
    )
    assert value["artifact_set_continuity"] == "IDENTITY_PROXY_MATCH"
    assert value["verdict"] == "IDENTITY_PROXY_MATCH"


def test_enterprise_mandatory_proxy_cannot_pass(canonical: dict[str, object]) -> None:
    policy = build_continuity_policy(ContinuityPolicyProfile.ENTERPRISE_DEPLOYMENT_CONTINUITY)
    replay = build_replay_context(
        canonical["instance"],
        canonical["manifest"],
        canonical["observer"],
        policy.policy_digest,
    )
    plan = build_observation_plan(
        canonical["manifest"], canonical["observer"], replay, policy.required_dimensions
    )
    coverage = build_coverage(
        policy.required_dimensions,
        proxy=[
            ObservationDimension.PRIMARY_ARTIFACT_DIGEST,
            ObservationDimension.ARTIFACT_SET_DIGEST,
        ],
    )
    observation = build_observation(
        plan,
        canonical["record"],
        canonical["observer"],
        build_artifact_observation(
            canonical["artifact_set"],
            strength=EvidenceStrength.INDEPENDENTLY_CORROBORATED,
            proxy=True,
        ),
        coverage,
        config_digest=canonical["config"].configuration_digest,
        engine_digest=canonical["engine"].engine_digest,
        engine_binary_digest=canonical["engine"].binary_digest,
        environment_digest=canonical["environment"].environment_digest,
        target_id=canonical["target"].target_id,
    )
    result = evaluate_continuity(
        canonical["subject"],
        canonical["intent"],
        canonical["manifest"],
        canonical["record"],
        canonical["observer"],
        plan,
        observation,
        policy,
        evaluation_sequence=2,
    )
    assert result.verdict == ContinuityVerdict.IDENTITY_PROXY_MATCH


def test_observation_authority_must_match_canonical_observer(
    canonical: dict[str, object],
) -> None:
    observation = _rebuild_observation(
        canonical["observation"],
        observer_authority=canonical["deploy_auth"].model_dump(mode="json", by_alias=True),
    )
    result = _evaluate_with(canonical, observation=observation)
    assert result.observer_authority == AssertionAuthorityStatus.UNAUTHORIZED
    assert result.verdict == ContinuityVerdict.OBSERVER_UNAUTHORIZED


def test_unverified_delegated_authority_fails_closed(canonical: dict[str, object]) -> None:
    authority_body = canonical["observer_auth"].model_dump(mode="json", by_alias=True)
    authority_body.pop("authority_id")
    authority_body.pop("authority_digest")
    authority_body["delegated_by_authority_id"] = "runtime_authority_" + "a" * 32
    authority = type(canonical["observer_auth"]).model_validate(
        identified(authority_body, "authority_id", "runtime_authority_", "authority_digest")
    )
    observer = build_observer(canonical["scope"], authority)
    policy = canonical["policy"]
    replay = build_replay_context(
        canonical["instance"], canonical["manifest"], observer, policy.policy_digest
    )
    plan = build_observation_plan(
        canonical["manifest"], observer, replay, policy.required_dimensions
    )
    observation = build_observation(
        plan,
        canonical["record"],
        observer,
        build_artifact_observation(
            canonical["artifact_set"],
            strength=EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        ),
        build_coverage(policy.required_dimensions),
        config_digest=canonical["config"].configuration_digest,
        engine_digest=canonical["engine"].engine_digest,
        engine_binary_digest=canonical["engine"].binary_digest,
        environment_digest=canonical["environment"].environment_digest,
        target_id=canonical["target"].target_id,
    )
    result = evaluate_continuity(
        canonical["subject"],
        canonical["intent"],
        canonical["manifest"],
        canonical["record"],
        observer,
        plan,
        observation,
        policy,
        evaluation_sequence=2,
    )
    assert result.verdict == ContinuityVerdict.OBSERVER_UNAUTHORIZED


@pytest.mark.parametrize(
    ("signer", "key", "root"),
    [
        ("signer.deploy", "key.observer", "root.runtime-observer"),
        ("signer.observer", "key.deploy", "root.runtime-observer"),
        ("signer.observer", "key.observer", "root.deploy"),
    ],
)
def test_enterprise_sod_checks_signer_key_and_root(
    canonical: dict[str, object], signer: str, key: str, root: str
) -> None:
    policy = build_continuity_policy(ContinuityPolicyProfile.ENTERPRISE_DEPLOYMENT_CONTINUITY)
    observer = build_observer(
        canonical["scope"],
        canonical["observer_auth"],
        signer=signer,
        key=key,
        root=root,
    )
    replay = build_replay_context(
        canonical["instance"], canonical["manifest"], observer, policy.policy_digest
    )
    plan = build_observation_plan(
        canonical["manifest"], observer, replay, policy.required_dimensions
    )
    observation = build_observation(
        plan,
        canonical["record"],
        observer,
        build_artifact_observation(
            canonical["artifact_set"],
            strength=EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        ),
        build_coverage(policy.required_dimensions),
        config_digest=canonical["config"].configuration_digest,
        engine_digest=canonical["engine"].engine_digest,
        engine_binary_digest=canonical["engine"].binary_digest,
        environment_digest=canonical["environment"].environment_digest,
        target_id=canonical["target"].target_id,
    )
    result = evaluate_continuity(
        canonical["subject"],
        canonical["intent"],
        canonical["manifest"],
        canonical["record"],
        observer,
        plan,
        observation,
        policy,
        evaluation_sequence=2,
    )
    assert result.verdict == ContinuityVerdict.OBSERVER_UNAUTHORIZED


def test_incomplete_coverage_cannot_pass(canonical: dict[str, object]) -> None:
    policy = canonical["policy"]
    missing = [ObservationDimension.ENGINE_BINARY_DIGEST]
    coverage = build_coverage(policy.required_dimensions, missing=missing)  # type: ignore[union-attr]
    observation = build_observation(
        canonical["plan"],
        canonical["record"],
        canonical["observer"],
        canonical["observation"].observed_artifact_set,
        coverage,  # type: ignore[union-attr]
        config_digest=canonical["config"].configuration_digest,  # type: ignore[union-attr]
        engine_digest=canonical["engine"].engine_digest,  # type: ignore[union-attr]
        environment_digest=canonical["environment"].environment_digest,  # type: ignore[union-attr]
        target_id=canonical["target"].target_id,  # type: ignore[union-attr]
    )
    result = evaluate_continuity(
        canonical["subject"],
        canonical["intent"],
        canonical["manifest"],
        canonical["record"],
        canonical["observer"],
        canonical["plan"],
        observation,
        policy,
        evaluation_sequence=2,
    )
    assert result.verdict == ContinuityVerdict.COVERAGE_INCOMPLETE


def test_false_complete_coverage_rejected() -> None:
    body = {
        "schema": "omiv.observation-coverage.v1",
        "coverage_id": "runtime_coverage_" + "0" * 32,
        "expected_dimensions": ["PRIMARY_ARTIFACT_DIGEST"],
        "observed_dimensions": [],
        "unsupported_dimensions": [],
        "inaccessible_dimensions": [],
        "errored_dimensions": [],
        "stale_dimensions": [],
        "proxy_only_dimensions": [],
        "independently_corroborated_dimensions": [],
        "status": "COMPLETE_FOR_REQUIRED_DIMENSIONS",
        "limitations": [],
        "coverage_digest": "0" * 64,
    }
    with pytest.raises(ValidationError):
        ObservationCoverage.model_validate(body)


def test_replay_binding_uses_instance_not_timestamp(generated: Path) -> None:
    value = json.loads(
        (generated / "runtime/examples/replayed-observation.continuity-evaluation.json").read_text()
    )
    assert value["replay_status"] == "REJECTED"
    assert value["verdict"] == "REPLAY_REJECTED"


def test_replay_namespace_epoch_and_fork_detection(canonical: dict[str, object]) -> None:
    wrong_namespace = _rebuild_observation(
        canonical["observation"], sequence_namespace="sequence.other-observer"
    )
    assert _evaluate_with(canonical, observation=wrong_namespace).verdict == (
        ContinuityVerdict.REPLAY_REJECTED
    )
    wrong_epoch = _rebuild_observation(canonical["observation"], epoch=2)
    assert _evaluate_with(canonical, observation=wrong_epoch).verdict == (
        ContinuityVerdict.REPLAY_REJECTED
    )
    competing = _rebuild_observation(
        canonical["observation"], limitations=["different successor content"]
    )
    forks = detect_observation_chain_forks([canonical["observation"], competing])
    assert len(forks) == 1 and forks[0].startswith("sequence-fork:")
    other_namespace = _rebuild_observation(
        competing, sequence_namespace="sequence.independent-observer"
    )
    assert not detect_observation_chain_forks([canonical["observation"], other_namespace])


def test_intent_is_reconstructed_and_bound_to_manifest(canonical: dict[str, object]) -> None:
    body = canonical["intent"].model_dump(mode="json", by_alias=True)
    body.pop("intent_id")
    body.pop("intent_digest")
    body["security_verdict"] = "PASS_WITH_LIMITATIONS"
    intent = DeploymentIntent.model_validate(
        identified(body, "intent_id", "deployment_intent_", "intent_digest")
    )
    result = _evaluate_with(canonical, intent=intent)
    assert result.verdict == ContinuityVerdict.EVIDENCE_BROKEN


def test_coverage_classifications_are_bounded_and_disjoint(
    canonical: dict[str, object],
) -> None:
    raw = canonical["observation"].coverage.model_dump(mode="json", by_alias=True)
    raw.pop("coverage_id")
    raw.pop("coverage_digest")
    raw["stale_dimensions"] = ["PRIMARY_ARTIFACT_DIGEST"]
    with pytest.raises(ValidationError, match="false complete observation coverage"):
        ObservationCoverage.model_validate(
            identified(raw, "coverage_id", "runtime_coverage_", "coverage_digest")
        )
    raw["status"] = ObservationCoverageStatus.FAILED.value
    raw["stale_dimensions"] = []
    raw["unsupported_dimensions"] = ["PRIMARY_ARTIFACT_DIGEST"]
    raw["inaccessible_dimensions"] = ["PRIMARY_ARTIFACT_DIGEST"]
    with pytest.raises(ValidationError, match="classifications overlap"):
        ObservationCoverage.model_validate(
            identified(raw, "coverage_id", "runtime_coverage_", "coverage_digest")
        )


def test_air_gapped_and_regulated_gaps_are_explicit(generated: Path) -> None:
    air = json.loads(
        (generated / "runtime/examples/air-gapped.continuity-evaluation.json").read_text()
    )
    assert air["verdict"] == "PASS_WITH_LIMITATIONS"
    assert any("Online revocation" in item for item in air["limitations"])
    assert air["trusted_timestamp_status"] == "NOT_AVAILABLE"
    assert air["revocation_status"] == "ONLINE_UNAVAILABLE"
    assert air["trust_bundle_freshness"] == "LIMITED_OFFLINE_SNAPSHOT"
    regulated = json.loads(
        (generated / "runtime/examples/regulated.continuity-evaluation.json").read_text()
    )
    assert regulated["verdict"] == "NOT_EVALUATED"
    assert {
        "CONTINUOUS_OBSERVATION_UNAVAILABLE",
        "BEHAVIORAL_PARITY_UNAVAILABLE",
        "NUMERICAL_PARITY_UNAVAILABLE",
        "TOKENIZER_PARITY_UNAVAILABLE",
        "TRUSTED_TIMESTAMP_UNAVAILABLE",
        "ONLINE_REVOCATION_UNAVAILABLE",
    }.issubset(regulated["structured_gaps"])


def test_wrong_authority_precedes_trust(generated: Path) -> None:
    value = json.loads(
        (
            generated / "runtime/examples/unauthorized-observer.continuity-evaluation.json"
        ).read_text()
    )
    assert value["observer_trust"] == "TRUSTED_BY_POLICY"
    assert value["observer_authority"] == "UNAUTHORIZED"
    assert value["verdict"] == "OBSERVER_UNAUTHORIZED"


def test_declaration_does_not_become_observed(canonical: dict[str, object]) -> None:
    record = build_deployment_record(
        canonical["manifest"],
        canonical["actor"],
        canonical["deploy_auth"],
        strength=EvidenceStrength.DECLARED,
        status=DeploymentStatus.COMPLETED_DECLARED,
        trusted=False,
    )
    assert record.status == DeploymentStatus.COMPLETED_DECLARED
    assert record.assertion.origin == EvidenceStrength.DECLARED


def test_declared_origin_cannot_claim_observed_completion(canonical: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        build_deployment_record(
            canonical["manifest"],
            canonical["actor"],
            canonical["deploy_auth"],
            strength=EvidenceStrength.DECLARED,
            status=DeploymentStatus.COMPLETED_OBSERVED,
        )


def test_static_adapter_registry_and_reserved_fail_closed(canonical: dict[str, object]) -> None:
    scope = canonical["scope"]
    local = get_adapter("omiv.adapter.local-runtime.v1", scope, operational=True)
    assert local.operational
    for adapter_id in RESERVED_ADAPTER_IDS:
        with pytest.raises(OmivInputError):
            get_adapter(adapter_id, scope, operational=True)


def test_unknown_adapter_and_fake_pass_rejected(canonical: dict[str, object]) -> None:
    with pytest.raises(OmivInputError):
        get_adapter("omiv.adapter.unknown.v1", canonical["scope"])
    with pytest.raises(OmivInputError):
        import_local_record(
            {"pass": True},
            ProductSubject,
            get_adapter("omiv.adapter.local-runtime.v1", canonical["scope"]),
        )


def test_adapter_cannot_escalate_strength(canonical: dict[str, object]) -> None:
    adapter = get_adapter("omiv.adapter.local-runtime.v1", canonical["scope"])
    value = canonical["observation"].model_dump(mode="json", by_alias=True)  # type: ignore[union-attr]
    with pytest.raises(OmivInputError):
        import_local_record(value, type(canonical["observation"]), adapter)


def test_adapter_implementation_and_schema_are_registry_bound(
    canonical: dict[str, object],
) -> None:
    adapter = get_adapter("omiv.adapter.local-runtime.v1", canonical["scope"])
    altered = adapter.model_copy(update={"implementation_digest": "0" * 64})
    value = canonical["observation"].model_dump(mode="json", by_alias=True)  # type: ignore[union-attr]
    with pytest.raises(OmivInputError, match="implementation digest mismatch"):
        import_local_record(value, RuntimeObservation, altered)
    with pytest.raises(OmivInputError, match="does not support"):
        import_local_record(
            canonical["subject"].model_dump(mode="json", by_alias=True),  # type: ignore[union-attr]
            ProductSubject,
            adapter,
        )


def test_governance_preserves_security_limitations(canonical: dict[str, object]) -> None:
    evaluation = canonical["evaluation"]
    with pytest.raises(OmivInputError):
        adapt_governance_runtime(
            evaluation,
            source_security_verdict="PASS_WITH_LIMITATIONS",
            source_security_limitations=["partial security scope"],
            allow_limited_security=False,
        )
    adapter = adapt_governance_runtime(
        evaluation,
        source_security_verdict="PASS_WITH_LIMITATIONS",
        source_security_limitations=["partial security scope"],
        allow_limited_security=True,
    )
    assert adapter.source_security_verdict == "PASS_WITH_LIMITATIONS"
    assert "partial security scope" in adapter.source_security_limitations
    assert adapter.continuity_outcome == "SATISFIED_WITH_LIMITATIONS"

    limited_by_source = adapt_governance_runtime(
        evaluation,
        source_security_verdict="PASS",
        source_security_limitations=["scanner coverage is policy-scoped"],
        allow_limited_security=False,
    )
    assert limited_by_source.deployment_evidence_outcome == "SATISFIED_WITH_LIMITATIONS"
    assert limited_by_source.runtime_observation_outcome == "SATISFIED_WITH_LIMITATIONS"


def test_phase5e_runtime_requirements_accept_only_strict_adapter(
    canonical: dict[str, object],
) -> None:
    manifest = canonical["manifest"]
    primary = next(item for item in manifest.artifact_set.members if item.role.value == "PRIMARY")  # type: ignore[union-attr]
    subject = build_subject(
        artifact_digest=primary.artifact.content_digest,
        artifact_set_digest=manifest.artifact_set.artifact_set_digest,  # type: ignore[union-attr]
        artifact_format="SYNTHETIC",
        origin_type="local",
        logical_locator="synthetic-runtime-artifact-set",
        variant="synthetic",
    )
    references = governance_runtime_evidence_references(subject, manifest, canonical["evaluation"])
    for category, reference in zip(
        (EvidenceCategory.DEPLOYMENT, EvidenceCategory.RUNTIME_OBSERVATION),
        references,
        strict=True,
    ):
        requirement = build_requirement(
            category,
            accepted_schemas=["omiv.deployment-runtime-evidence.v1"],
            accepted_verification_modes=[VerificationMode.FULL],
            accepted_trust_statuses=["TRUSTED_BY_POLICY"],
            source_phase="5G",
        )
        result = _evaluate_requirement(
            requirement,
            [reference],
            None,
            canonical["evaluation"].policy_id,  # type: ignore[union-attr]
        )
        assert result.outcome.value == "SATISFIED_WITH_LIMITATIONS"
        assert reference.limitations


def test_governance_runtime_adapter_rejects_wrong_artifact_set(
    canonical: dict[str, object],
) -> None:
    subject = build_subject(
        artifact_digest="0" * 64,
        artifact_set_digest="1" * 64,
        artifact_format="SYNTHETIC",
        origin_type="local",
        logical_locator="wrong-artifact-set",
        variant="synthetic",
    )
    with pytest.raises(OmivInputError):
        governance_runtime_evidence_references(
            subject, canonical["manifest"], canonical["evaluation"]
        )


def test_report_reconstruction_and_boundaries(canonical: dict[str, object]) -> None:
    report = build_runtime_report(
        canonical["subject"],
        canonical["manifest"],
        canonical["record"],
        canonical["observer"],
        canonical["observation"],
        canonical["evaluation"],
    )
    assert (
        verify_runtime_report(
            report,
            canonical["subject"],
            canonical["manifest"],
            canonical["record"],
            canonical["observer"],
            canonical["observation"],
            canonical["evaluation"],
        )
        == report
    )
    markdown = render_runtime_markdown(report)
    assert "Deployment performed by OMIV: **NO**" in markdown
    assert "Behavioral parity: **NOT_CHECKED**" in markdown
    assert "Runtime safety: **NOT_VERIFIED**" in markdown
    assert "Continuous continuity: **NOT_ESTABLISHED**" in markdown
    assert "Trusted timestamp: **NOT_AVAILABLE**" in markdown
    assert report.source_security_verdict == "PASS"
    assert report.source_security_limitations
    assert "Source security verdict: **PASS**" in markdown
    altered = report.model_copy(update={"limitations": ["altered"]})
    with pytest.raises(OmivInputError):
        verify_runtime_report(
            altered,
            canonical["subject"],
            canonical["manifest"],
            canonical["record"],
            canonical["observer"],
            canonical["observation"],
            canonical["evaluation"],
        )


def test_schema_registry_is_strict() -> None:
    assert (
        schema_model("omiv.runtime-observation.v1")
        is RUNTIME_SCHEMA_MODELS["omiv.runtime-observation.v1"]
    )
    with pytest.raises(ValueError):
        schema_model("omiv.runtime-unknown.v1")


def test_additive_signed_object_registry() -> None:
    expected = {
        SignedObjectType.DEPLOYMENT_INTENT: SignaturePurpose.DEPLOYMENT_INTENT_ISSUANCE,
        SignedObjectType.DEPLOYMENT_MANIFEST: SignaturePurpose.DEPLOYMENT_MANIFEST_ISSUANCE,
        SignedObjectType.DEPLOYMENT_RECORD: SignaturePurpose.DEPLOYMENT_RECORD_ISSUANCE,
        SignedObjectType.RUNTIME_OBSERVATION: SignaturePurpose.RUNTIME_OBSERVATION_ISSUANCE,
        SignedObjectType.CONTINUITY_EVALUATION: SignaturePurpose.CONTINUITY_EVALUATION_ISSUANCE,
    }
    for object_type, purpose in expected.items():
        assert EXPECTED_PURPOSE[object_type] == purpose
        assert purpose in ACTIVE_PURPOSES
        assert object_type in OBJECT_METADATA


def test_signed_fixtures_verify_and_do_not_upgrade_claims(generated: Path) -> None:
    for name in (
        "deployment-intent",
        "deployment-manifest",
        "deployment-record",
        "runtime-observation",
        "continuity-evaluation",
    ):
        linkage = json.loads(
            (generated / f"runtime/examples/signed-{name}.linkage.json").read_text()
        )
        assert linkage["evidence_origin_preserved"]
        assert linkage["authority_preserved"]
        assert linkage["coverage_preserved"]
        assert linkage["verdict_preserved"]
    enterprise_observation = json.loads(
        (generated / "runtime/examples/enterprise.observation.json").read_text()
    )
    signed_observation = json.loads(
        (generated / "runtime/examples/signed-runtime-observation.envelope.json").read_text()
    )
    assert signed_observation["signed_object_id"] == enterprise_observation["observation_id"]
    enterprise_evaluation = json.loads(
        (generated / "runtime/examples/enterprise.continuity-evaluation.json").read_text()
    )
    signed_evaluation = json.loads(
        (generated / "runtime/examples/signed-continuity-evaluation.envelope.json").read_text()
    )
    assert signed_evaluation["signed_object_id"] == enterprise_evaluation["evaluation_id"]


def test_artifact_index_budget_and_duplicates(generated: Path) -> None:
    index = RuntimeArtifactIndex.model_validate(
        json.loads((generated / "runtime/artifact-index.json").read_text())
    )
    assert verify_runtime_artifact_index(index, generated) == index
    assert len(index.entries) <= 100
    assert index.generated_json_count + index.generated_markdown_count == len(index.entries)
    assert len({x.sha256 for x in index.entries}) == len(index.entries)
    assert len({x.canonical_id for x in index.entries}) == len(index.entries)
    assert max(x.size for x in index.entries) < 1024 * 1024


def test_canonical_dependency_graph_is_acyclic(generated: Path) -> None:
    examples = generated / "runtime/examples"
    intent = json.loads((examples / "intent.json").read_text())
    instance = json.loads((examples / "instance.json").read_text())
    manifest = json.loads((examples / "manifest.json").read_text())
    plan = json.loads((examples / "trusted-team.observation-plan.json").read_text())
    observation = json.loads((examples / "trusted-team.observation.json").read_text())
    evaluation = json.loads((examples / "trusted-team.continuity-evaluation.json").read_text())
    assert not {"record_id", "observation_id", "evaluation_id"}.intersection(intent)
    assert not {"manifest_id", "plan_id", "observation_id"}.intersection(instance)
    assert "instance" in manifest and "observation_id" not in manifest
    assert plan["instance_id"] == instance["instance_id"]
    assert observation["plan_id"] == plan["plan_id"]
    assert evaluation["observation_digest"] == observation["observation_digest"]
    assert "report_id" not in evaluation
    index = json.loads((generated / "runtime/artifact-index.json").read_text())
    assert all(
        entry["relative_path"] != "runtime/artifact-index.json" for entry in index["entries"]
    )


def test_two_generations_are_byte_identical(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    one = generate_runtime_examples(first)
    two = generate_runtime_examples(second)
    assert one == two
    first_files = {p.relative_to(first): p.read_bytes() for p in first.rglob("*") if p.is_file()}
    second_files = {p.relative_to(second): p.read_bytes() for p in second.rglob("*") if p.is_file()}
    assert first_files == second_files


def test_runtime_core_has_no_product_or_platform_dependency() -> None:
    root = Path(__file__).parents[1] / "src/omiv/runtime"
    source = "\n".join(p.read_text() for p in root.glob("*.py"))
    for forbidden in (
        "model_packs",
        "kimi_k3",
        "kubernetes",
        "docker",
        "boto",
        "google.cloud",
        "azure",
        "vllm",
        "tensorrt",
        "llama_cpp",
        "mlx",
        "ollama",
    ):
        assert f"import {forbidden}" not in source


def test_no_network_process_or_dynamic_plugin_api() -> None:
    root = Path(__file__).parents[1] / "src/omiv/runtime"
    source = "\n".join(p.read_text() for p in root.glob("*.py"))
    for forbidden in (
        "requests.",
        "httpx.",
        "urllib.",
        "socket.",
        "subprocess.",
        "os.system",
        "shell=True",
        "importlib.",
        "__import__(",
        "pickle.load",
        "torch.load",
        "exec(",
    ):
        assert forbidden not in source


def test_kimi_gap_is_not_runtime_evidence(generated: Path) -> None:
    path = generated / "reports/runtime/kimi-k3.runtime-gap-report.json"
    value = json.loads(path.read_text())
    assert value["deployment"] == "NOT_PERFORMED"
    assert value["runtime_observation"] == "UNAVAILABLE"
    assert value["continuity"] == "NOT_EVALUATED"
    assert value["runtime_safety"] == "NOT_EVALUATED"
    with pytest.raises(ValidationError):
        ProductSubject.model_validate(value)


def test_generated_privacy(generated: Path) -> None:
    text = "\n".join(
        p.read_text(errors="replace") for p in generated.rglob("*") if p.is_file()
    ).lower()
    for forbidden in (
        "/home/",
        "/users/",
        "github_pat_",
        "ghp_",
        "x-amz-",
        "begin private key",
        "kubeconfig",
        "datetime.now",
        "time.time",
        "123e4567-e89b",
    ):
        assert forbidden not in text


def test_cli_create_verify_show_and_exit_codes(generated: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    examples = generated / "runtime/examples"
    copied = tmp_path / "intent.json"
    result = runner.invoke(
        app,
        [
            "runtime",
            "intent-create",
            "--input",
            str(examples / "intent.json"),
            "--output",
            str(copied),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app,
        ["runtime", "deployment-verify", "--record", str(examples / "deployment-record.json")],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app,
        [
            "runtime",
            "observation-verify",
            "--observation",
            str(examples / "trusted-team.observation.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app,
        ["runtime", "show", "--input", str(examples / "trusted-team.continuity-evaluation.json")],
    )
    assert result.exit_code == 0 and "Snapshot only" in result.output


def test_cli_continuity_and_report_reconstruction(generated: Path, tmp_path: Path) -> None:
    runner = CliRunner()
    examples, reports = generated / "runtime/examples", generated / "reports/runtime"
    output = tmp_path / "evaluation.json"
    result = runner.invoke(
        app,
        [
            "runtime",
            "continuity-evaluate",
            "--subject",
            str(examples / "subject.json"),
            "--intent",
            str(examples / "intent.json"),
            "--manifest",
            str(examples / "manifest.json"),
            "--record",
            str(examples / "deployment-record.json"),
            "--observer",
            str(examples / "observer.json"),
            "--plan",
            str(examples / "trusted-team.observation-plan.json"),
            "--observation",
            str(examples / "trusted-team.observation.json"),
            "--policy",
            str(generated / "runtime/policies/team_service_continuity.json"),
            "--evaluation-sequence",
            "2",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app,
        [
            "runtime",
            "report-verify",
            "--report",
            str(reports / "trusted-team.runtime-report.json"),
            "--subject",
            str(examples / "subject.json"),
            "--manifest",
            str(examples / "manifest.json"),
            "--record",
            str(examples / "deployment-record.json"),
            "--observer",
            str(examples / "observer.json"),
            "--observation",
            str(examples / "trusted-team.observation.json"),
            "--evaluation",
            str(examples / "trusted-team.continuity-evaluation.json"),
        ],
    )
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("name", "expected"),
    [("container-proxy", 1), ("replayed-observation", 2), ("companion-drift", 2)],
)
def test_cli_exit_code_mapping(generated: Path, name: str, expected: int) -> None:
    verdict = ContinuityVerdict(
        json.loads((generated / f"runtime/examples/{name}.continuity-evaluation.json").read_text())[
            "verdict"
        ]
    )
    from omiv.cli import _runtime_exit

    assert _runtime_exit(verdict) == expected


def test_checked_in_index_verifies() -> None:
    root = Path(__file__).parents[1]
    if not (root / "runtime/artifact-index.json").exists():
        pytest.skip("checked-in runtime examples have not yet been generated")
    index = RuntimeArtifactIndex.model_validate(
        json.loads((root / "runtime/artifact-index.json").read_text())
    )
    assert verify_runtime_artifact_index(index, root) == index


def test_original_phase5f_artifact_index_unchanged() -> None:
    root = Path(__file__).parents[1]
    data = (root / "security/artifact-index.json").read_bytes()
    assert (
        hashlib.sha256(data).hexdigest()
        == "3248ef06883cbbad4a6bbde7579dd9ca3ca6b652bd4b5026ab1ddc31a6cbd86e"
    )
