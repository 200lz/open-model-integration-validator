"""Compact deterministic multi-product Phase 5G fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.governance.evaluation import build_subject as build_governance_subject
from omiv.runtime.adapters import (
    adapt_governance_runtime,
    adapter_registry,
    build_custody_runtime_linkage,
    build_passport_runtime_summary,
    governance_runtime_evidence_references,
)
from omiv.runtime.building import (
    artifact_member,
    build_actor,
    build_adapter,
    build_artifact_observation,
    build_artifact_set,
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
from omiv.runtime.continuity import evaluate_continuity
from omiv.runtime.models import (
    ArtifactMemberRole,
    ContinuityPolicyProfile,
    DeploymentRecord,
    DeploymentStatus,
    EvidenceStrength,
    IdentityObservationMethod,
    ObservationDimension,
    ObservationStatus,
    ProductSubjectClass,
    RuntimeArtifactIndex,
    RuntimeArtifactIndexEntry,
    RuntimeObserverIdentity,
)
from omiv.runtime.policy import build_continuity_policy
from omiv.runtime.reporting import build_runtime_report, pretty_json, render_runtime_markdown
from omiv.runtime.signing import build_signed_runtime_linkage
from omiv.safe_write import atomic_write_text
from omiv.trust.models import BindingStatus, SignaturePurpose, SignedObjectType, SignerIdentityKind
from omiv.trust.signing import (
    build_binding,
    build_descriptor,
    build_key_identity,
    build_signature_record,
    build_signed_envelope,
    build_signer_identity,
    build_trust_bundle,
    build_trust_root,
)
from omiv.trust.signing import (
    build_policy as build_trust_policy,
)
from omiv.trust.verification import verify_envelope


def _write(path: Path, value: object) -> None:
    atomic_write_text(path, pretty_json(value))


def _canonical_id(value: dict[str, Any]) -> str:
    fields = (
        "signature_report_id",
        "evidence_id",
        "report_id",
        "evaluation_id",
        "observation_id",
        "plan_id",
        "record_id",
        "manifest_id",
        "summary_id",
        "linkage_id",
        "adapter_id",
        "instance_id",
        "intent_id",
        "replay_id",
        "coverage_id",
        "drift_id",
        "envelope_id",
        "authority_id",
        "configuration_id",
        "engine_id",
        "environment_id",
        "observer_id",
        "artifact_set_id",
        "subject_id",
        "policy_id",
        "bundle_id",
        "gap_report_id",
    )
    for field in fields:
        if isinstance(value.get(field), str):
            return str(value[field])
    return "runtime_markdown_" + canonical_sha256(value)[:32]


def generate_runtime_examples(root: Path) -> RuntimeArtifactIndex:
    """Generate all Phase 5G examples without network, deployment, or runtime access."""
    out = root / "runtime" / "examples"
    reports = root / "reports" / "runtime"
    out.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    scope = synthetic_scope()
    subject = build_product_subject(ProductSubjectClass.MODEL_WEIGHTS, "subject.synthetic", scope)
    members = [
        artifact_member(
            "adapter.data",
            ProductSubjectClass.LORA_ADAPTER,
            "adapter-v1",
            role=ArtifactMemberRole.MANDATORY_COMPANION,
        ),
        artifact_member(
            "model.weights",
            ProductSubjectClass.MODEL_WEIGHTS,
            "weights-v1",
            role=ArtifactMemberRole.PRIMARY,
        ),
        artifact_member(
            "prompt.template",
            ProductSubjectClass.PROMPT_TEMPLATE,
            "prompt-template-v1",
            role=ArtifactMemberRole.OPTIONAL_COMPANION,
            required=False,
        ),
        artifact_member(
            "runtime.generated-index",
            ProductSubjectClass.OTHER_DECLARED,
            "runtime-generated-logical-identity",
            role=ArtifactMemberRole.RUNTIME_GENERATED,
            required=False,
            generation_provenance_seed="weights-v1",
        ),
        artifact_member(
            "tokenizer.data",
            ProductSubjectClass.TOKENIZER,
            "tokenizer-v1",
            role=ArtifactMemberRole.MANDATORY_COMPANION,
        ),
    ]
    artifact_set = build_artifact_set(subject, members)
    deploy_authority = build_authority(
        "actor.deployer", scope, assertion_types=["DEPLOYMENT_ACTION"], actions=["DEPLOY"]
    )
    observer_authority = build_authority(
        "actor.observer", scope, assertion_types=["RUNTIME_IDENTITY"], actions=["OBSERVE_RUNTIME"]
    )
    target = build_target(scope)
    config = build_configuration()
    engine = build_engine()
    environment = build_environment(scope)
    adapter = build_adapter(scope)
    actor = build_actor(
        "actor.deployer",
        "deployer",
        deploy_authority,
        signer="signer.deployer",
        key="key.deployer",
        root="root.deployment",
    )
    intent = build_intent(
        subject,
        artifact_set,
        target,
        engine,
        config,
        actor,
        deploy_authority,
        security_verdict="PASS",
    )
    instance = build_instance(intent, artifact_set, config, engine)
    manifest = build_manifest(
        intent, instance, artifact_set, target, engine, config, environment, adapter
    )
    record = build_deployment_record(
        manifest,
        actor,
        deploy_authority,
        strength=EvidenceStrength.SIGNED_AND_TRUSTED,
        trusted=True,
    )
    observer = build_observer(scope, observer_authority)

    shared: dict[Path, object] = {
        out / "subject.json": subject,
        out / "artifact-set.json": artifact_set,
        out / "deployer-authority.json": deploy_authority,
        out / "observer-authority.json": observer_authority,
        out / "configuration.json": config,
        out / "engine.json": engine,
        out / "environment.json": environment,
        out / "local-adapter.json": adapter,
        out / "intent.json": intent,
        out / "instance.json": instance,
        out / "manifest.json": manifest,
        out / "deployment-record.json": record,
        out / "observer.json": observer,
    }
    for profile in ContinuityPolicyProfile:
        policy = build_continuity_policy(profile)
        shared[root / "runtime" / "policies" / f"{profile.value}.json"] = policy
    for adapter_id, adapter_value in adapter_registry(scope).items():
        if adapter_id != "omiv.adapter.local-runtime.v1":
            shared[
                out / "reserved-adapters" / f"{adapter_id.removeprefix('omiv.adapter.')}.json"
            ] = adapter_value
    generated: list[Path] = []
    for path, shared_value in shared.items():
        _write(path, shared_value)
        generated.append(path)

    scenarios: dict[str, tuple[Any, Any, Any, int]] = {}

    def make(
        name: str,
        profile: ContinuityPolicyProfile,
        *,
        rec: DeploymentRecord = record,
        obsr: RuntimeObserverIdentity = observer,
        artifact_overrides: dict[str, str | None] | None = None,
        proxy: bool = False,
        proxy_method: IdentityObservationMethod = IdentityObservationMethod.CONTAINER_IMAGE_PROXY,
        config_digest: str | None = config.configuration_digest,
        engine_digest: str | None = engine.engine_digest,
        engine_binary_digest: str | None = engine.binary_digest,
        environment_digest: str | None = environment.environment_digest,
        target_id: str | None = target.target_id,
        strength: EvidenceStrength = EvidenceStrength.INDEPENDENTLY_CORROBORATED,
        trusted: bool = True,
        sequence: int = 1,
        evaluation_sequence: int = 2,
        coverage_missing: list[ObservationDimension] | None = None,
        status: ObservationStatus = ObservationStatus.COMPLETED,
    ) -> None:
        policy = build_continuity_policy(profile)
        replay = build_replay_context(instance, manifest, obsr, policy.policy_digest)
        plan = build_observation_plan(manifest, obsr, replay, policy.required_dimensions)
        coverage = build_coverage(
            policy.required_dimensions,
            missing=coverage_missing,
            proxy=(
                [
                    ObservationDimension.PRIMARY_ARTIFACT_DIGEST,
                    ObservationDimension.ARTIFACT_SET_DIGEST,
                ]
                if proxy
                else []
            ),
        )
        observed_set = build_artifact_observation(
            artifact_set,
            strength=strength,
            proxy=proxy,
            proxy_method=proxy_method,
            overrides=artifact_overrides,
        )
        observation = build_observation(
            plan,
            rec,
            obsr,
            observed_set,
            coverage,
            strength=strength,
            config_digest=config_digest,
            engine_digest=engine_digest,
            engine_binary_digest=engine_binary_digest,
            environment_digest=environment_digest,
            target_id=target_id,
            sequence=sequence,
            trusted=trusted,
            status=status,
        )
        evaluation = evaluate_continuity(
            subject,
            intent,
            manifest,
            rec,
            obsr,
            plan,
            observation,
            policy,
            evaluation_sequence=evaluation_sequence,
        )
        scenarios[name] = (plan, observation, evaluation, evaluation_sequence)

    make("trusted-team", ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY)
    self_authority = build_authority(
        "actor.deployer", scope, assertion_types=["RUNTIME_IDENTITY"], actions=["OBSERVE_RUNTIME"]
    )
    self_observer = build_observer(
        scope,
        self_authority,
        observer_id_seed="self-observer",
        trusted=False,
        strength_ceiling=EvidenceStrength.SYSTEM_OBSERVED,
        signer="signer.deployer",
        key="key.deployer",
        root="root.deployment",
    )
    make(
        "local-self-observed",
        ContinuityPolicyProfile.LOCAL_RUNTIME_CONTINUITY,
        obsr=self_observer,
        strength=EvidenceStrength.SYSTEM_OBSERVED,
        trusted=False,
    )
    make(
        "companion-drift",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        artifact_overrides={"tokenizer.data": canonical_sha256({"tokenizer": "drift"})},
    )
    make("container-proxy", ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY, proxy=True)
    make(
        "registry-proxy",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        proxy=True,
        proxy_method=IdentityObservationMethod.REGISTRY_REFERENCE_IDENTITY,
    )
    make(
        "configuration-drift",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        config_digest=canonical_sha256({"config": "drift"}),
    )
    make(
        "engine-binary-drift",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        engine_binary_digest=canonical_sha256({"binary": "different-same-version"}),
    )
    make(
        "stale-observation",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        evaluation_sequence=20,
    )
    unknown_observer = build_observer(
        scope,
        observer_authority,
        observer_id_seed="unknown-observer",
        trusted=False,
        signer=None,
        key=None,
        root=None,
    )
    make(
        "unknown-observer",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        obsr=unknown_observer,
        trusted=False,
    )
    cross_scope = synthetic_scope(tenant="tenant.other")
    wrong_authority = build_authority(
        "actor.observer",
        cross_scope,
        assertion_types=["RUNTIME_IDENTITY"],
        actions=["OBSERVE_RUNTIME"],
    )
    wrong_observer = build_observer(
        cross_scope, wrong_authority, observer_id_seed="wrong-scope-observer"
    )
    make(
        "unauthorized-observer",
        ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY,
        obsr=wrong_observer,
    )
    make(
        "cross-tenant",
        ContinuityPolicyProfile.ENTERPRISE_DEPLOYMENT_CONTINUITY,
        obsr=wrong_observer,
    )
    make("replayed-observation", ContinuityPolicyProfile.TEAM_SERVICE_CONTINUITY, sequence=2)
    declared_record = build_deployment_record(
        manifest,
        actor,
        deploy_authority,
        strength=EvidenceStrength.DECLARED,
        status=DeploymentStatus.COMPLETED_DECLARED,
        trusted=False,
    )
    make(
        "declared-only",
        ContinuityPolicyProfile.LOCAL_RUNTIME_CONTINUITY,
        rec=declared_record,
        obsr=self_observer,
        strength=EvidenceStrength.DECLARED,
        trusted=False,
        status=ObservationStatus.NOT_OBSERVED,
    )
    make("air-gapped", ContinuityPolicyProfile.AIR_GAPPED_RUNTIME_CONTINUITY)
    make("enterprise", ContinuityPolicyProfile.ENTERPRISE_DEPLOYMENT_CONTINUITY)
    make("regulated", ContinuityPolicyProfile.REGULATED_RUNTIME_CONTINUITY)

    representative = {
        "local-self-observed",
        "trusted-team",
        "companion-drift",
        "container-proxy",
        "enterprise",
    }
    for name, (plan, observation, evaluation, _) in scenarios.items():
        values: dict[Path, object] = {
            out / f"{name}.observation.json": observation,
            out / f"{name}.continuity-evaluation.json": evaluation,
        }
        if name in {"local-self-observed", "trusted-team"}:
            values[out / f"{name}.observation-plan.json"] = plan
        for number, drift in enumerate(evaluation.drift_findings, start=1):
            values[out / f"{name}.drift-{number}.json"] = drift
        if name in representative:
            report_observer = self_observer if name == "local-self-observed" else observer
            report_record = declared_record if name == "declared-only" else record
            report = build_runtime_report(
                subject,
                manifest,
                report_record,
                report_observer,
                observation,
                evaluation,
            )
            values[reports / f"{name}.runtime-report.json"] = report
            markdown = reports / f"{name}.runtime-report.md"
            atomic_write_text(markdown, render_runtime_markdown(report))
            generated.append(markdown)
        for path, scenario_value in values.items():
            _write(path, scenario_value)
            generated.append(path)

    team_evaluation = scenarios["trusted-team"][2]
    governance = adapt_governance_runtime(
        team_evaluation,
        source_security_verdict=manifest.security_verdict,
        source_security_limitations=manifest.security_limitations,
        allow_limited_security=False,
    )
    primary = next(item for item in artifact_set.members if item.role == ArtifactMemberRole.PRIMARY)
    governance_subject = build_governance_subject(
        artifact_digest=primary.artifact.content_digest or "0" * 64,
        artifact_set_digest=artifact_set.artifact_set_digest,
        artifact_format="SYNTHETIC",
        origin_type="local",
        logical_locator="synthetic-runtime-artifact-set",
        variant="synthetic",
    )
    governance_references = governance_runtime_evidence_references(
        governance_subject, manifest, team_evaluation
    )
    passport = build_passport_runtime_summary(
        "mp_" + canonical_sha256({"passport": "runtime"})[:32],
        canonical_sha256({"passport-record": "runtime"}),
        manifest,
        record,
        scenarios["trusted-team"][1],
        team_evaluation,
    )
    custody = build_custody_runtime_linkage(
        "custody_" + canonical_sha256({"chain": "runtime"})[:32],
        canonical_sha256({"ledger": "runtime"}),
        record,
        scenarios["trusted-team"][1],
        team_evaluation,
    )
    derived = {
        out / "trusted-team.governance-runtime-adapter.json": governance,
        out / "trusted-team.deployment-evidence-reference.json": governance_references[0],
        out / "trusted-team.runtime-evidence-reference.json": governance_references[1],
        out / "trusted-team.passport-runtime-summary.json": passport,
        out / "trusted-team.custody-runtime-linkage.json": custody,
    }
    for path, derived_value in derived.items():
        _write(path, derived_value)
        generated.append(path)

    object_types = [
        SignedObjectType.DEPLOYMENT_INTENT,
        SignedObjectType.DEPLOYMENT_MANIFEST,
        SignedObjectType.DEPLOYMENT_RECORD,
        SignedObjectType.RUNTIME_OBSERVATION,
        SignedObjectType.CONTINUITY_EVALUATION,
    ]
    purposes = [
        SignaturePurpose.DEPLOYMENT_INTENT_ISSUANCE,
        SignaturePurpose.DEPLOYMENT_MANIFEST_ISSUANCE,
        SignaturePurpose.DEPLOYMENT_RECORD_ISSUANCE,
        SignaturePurpose.RUNTIME_OBSERVATION_ISSUANCE,
        SignaturePurpose.CONTINUITY_EVALUATION_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([71]) * 32)
    key = build_key_identity(private, allowed_object_types=object_types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic runtime evidence issuer",
        role="RUNTIME_OBSERVER",
        evidence=[canonical_sha256({"issuer": "runtime"})],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    trust_policy = build_trust_policy(
        "team_release",
        object_types=object_types,
        purposes=purposes,
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    trust_bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    signed_values: dict[Path, object] = {
        out / "runtime.trust-policy.json": trust_policy,
        out / "runtime.trust-bundle.json": trust_bundle,
    }
    signed_objects: list[tuple[str, BaseModel, SignedObjectType, SignaturePurpose]] = [
        ("deployment-intent", intent, object_types[0], purposes[0]),
        ("deployment-manifest", manifest, object_types[1], purposes[1]),
        ("deployment-record", record, object_types[2], purposes[2]),
        ("runtime-observation", scenarios["enterprise"][1], object_types[3], purposes[3]),
        ("continuity-evaluation", scenarios["enterprise"][2], object_types[4], purposes[4]),
    ]
    for name, signed_value, object_type, purpose in signed_objects:
        raw = signed_value.model_dump(mode="json", by_alias=True)
        descriptor = build_descriptor(raw, object_type, purpose, policy_id=trust_policy.policy_id)
        signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
        envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
        signature_report = verify_envelope(envelope, trust_bundle, trust_policy)
        linkage = build_signed_runtime_linkage(envelope, trust_status="TRUSTED_BY_POLICY")
        signed_values[out / f"signed-{name}.envelope.json"] = envelope
        signed_values[out / f"signed-{name}.linkage.json"] = linkage
        signed_values[reports / f"signed-{name}.signature-report.json"] = signature_report
    for path, signed_output in signed_values.items():
        _write(path, signed_output)
        generated.append(path)

    gap_body = {
        "schema": "omiv.runtime-gap-report.v1",
        "subject": "kimi-k3-analysis-only",
        "deployment": "NOT_PERFORMED",
        "runtime_observation": "UNAVAILABLE",
        "continuity": "NOT_EVALUATED",
        "observer": "UNAVAILABLE",
        "runtime_safety": "NOT_EVALUATED",
        "limitations": ["Analysis-only gap report; not deployment or runtime evidence."],
    }
    gap = identified(gap_body, "gap_report_id", "runtime_gap_", "gap_report_digest")
    gap_path = reports / "kimi-k3.runtime-gap-report.json"
    _write(gap_path, gap)
    generated.append(gap_path)

    unique_generated: list[Path] = []
    seen_content: set[str] = set()
    for path in dict.fromkeys(generated):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen_content:
            path.unlink()
            continue
        seen_content.add(digest)
        unique_generated.append(path)
    entries: list[RuntimeArtifactIndexEntry] = []
    for path in sorted(unique_generated):
        file_raw = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        if path.suffix == ".json":
            parsed = json.loads(file_raw)
            schema = str(parsed.get("schema", "omiv.runtime-generated.v1"))
            object_id = _canonical_id(parsed)
        else:
            schema = "omiv.runtime-report-markdown.v1"
            object_id = "runtime_markdown_" + hashlib.sha256(file_raw).hexdigest()[:32]
        entries.append(
            RuntimeArtifactIndexEntry(
                relative_path=relative,
                size=len(file_raw),
                sha256=hashlib.sha256(file_raw).hexdigest(),
                schema_id=schema,
                canonical_id=object_id,
            )
        )
    body = {
        "schema": "omiv.runtime-artifact-index.v1",
        "entries": [x.model_dump(mode="json") for x in entries],
        "total_size": sum(x.size for x in entries),
        "generated_json_count": sum(x.relative_path.endswith(".json") for x in entries),
        "generated_markdown_count": sum(x.relative_path.endswith(".md") for x in entries),
        "limitations": [
            "Index inventories compact synthetic Phase 5G evidence; no payloads or deployments."
        ],
    }
    index = RuntimeArtifactIndex.model_validate(
        identified(body, "index_id", "runtime_index_", "index_digest")
    )
    atomic_write_text(root / "runtime" / "artifact-index.json", pretty_json(index))
    return index


if __name__ == "__main__":
    generate_runtime_examples(Path.cwd())
