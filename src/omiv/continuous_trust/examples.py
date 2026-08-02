"""Compact deterministic generic Phase 5H fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.continuous_trust.building import (
    build_adapters,
    build_completeness,
    build_event,
    build_evidence_set,
    build_freshness,
    build_historical_result,
    build_renewal,
    build_report,
    build_subject,
    build_supersession,
    build_timeline,
    build_verification,
    compare_snapshots,
    evidence_ref,
    identified,
    propagate_revocation,
    reconstruct_snapshot,
)
from omiv.continuous_trust.bundles import build_bundle_manifest
from omiv.continuous_trust.models import (
    ArtifactIndexEntry,
    AuditBundleGap,
    AuditBundleMember,
    Availability,
    BundlePurpose,
    ContinuousTrustArtifactIndex,
    DependencyEdgeType,
    DimensionState,
    EventAuthority,
    EventType,
    EvidenceSetMember,
    ExplicitDependencyEdge,
    HistoricalEvaluationRequest,
    HistoricalKnowledgeMode,
    ReevaluationPolicySet,
    SupersessionEdge,
)
from omiv.continuous_trust.reporting import pretty_audit_json, render_audit_markdown
from omiv.continuous_trust.signing import build_signed_historical_linkage
from omiv.runtime.building import synthetic_scope
from omiv.safe_write import atomic_write_text
from omiv.trust.models import (
    BindingStatus,
    SignaturePurpose,
    SignedObjectType,
    SignerIdentityKind,
)
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
from omiv.trust.signing import build_policy as build_trust_policy
from omiv.trust.verification import verify_envelope


def _write(path: Path, value: BaseModel) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, pretty_audit_json(value))
    return path


def _canonical_id(value: dict[str, object]) -> str:
    fields = {
        "omiv.evidence-set-manifest.v1": "manifest_id",
        "omiv.trust-snapshot.v1": "snapshot_id",
        "omiv.historical-event.v1": "event_id",
        "omiv.trust-transition.v1": "transition_id",
        "omiv.trust-timeline.v1": "timeline_id",
        "omiv.timeline-fork.v1": "fork_id",
        "omiv.revocation-propagation-result.v1": "propagation_id",
        "omiv.supersession-graph.v1": "graph_id",
        "omiv.freshness-transition-result.v1": "freshness_id",
        "omiv.renewal-record.v1": "renewal_id",
        "omiv.historical-evaluation-request.v1": "request_id",
        "omiv.historical-evaluation-result.v1": "result_id",
        "omiv.reevaluation-policy-set.v1": "policy_set_id",
        "omiv.audit-bundle-manifest.v1": "bundle_id",
        "omiv.audit-bundle-completeness.v1": "completeness_id",
        "omiv.audit-bundle-verification-result.v1": "verification_id",
        "omiv.audit-bundle-report.v1": "report_id",
        "omiv.passport-historical-summary.v1": "summary_id",
        "omiv.custody-historical-linkage.v1": "linkage_id",
        "omiv.governance-historical-adapter.v1": "adapter_id",
    }
    schema = value.get("schema")
    if not isinstance(schema, str):
        raise ValueError("generated record has no schema identity")
    field = fields.get(schema)
    if field is not None:
        found = value.get(field)
        if isinstance(found, str):
            return found
    raise ValueError("generated record has no canonical identity")


def _policy(scope: BaseModel, name: str, strict: bool) -> ReevaluationPolicySet:
    refs = [
        evidence_ref(
            f"omiv.{family}-policy.v1",
            f"{family}_policy_{name}",
            canonical_sha256({family: name}),
            "5H"
            if family == "audit"
            else {"trust": "5D", "governance": "5E", "security": "5F", "continuity": "5G"}[family],
        )
        for family in ("trust", "governance", "security", "continuity", "audit")
    ]
    body = {
        "schema": "omiv.reevaluation-policy-set.v1",
        "policy_set_id": f"reevaluation_policy.{name}.v1",
        "policy_references": [x.model_dump(mode="json", by_alias=True) for x in refs],
        "scope": scope.model_dump(mode="json", by_alias=True),
        "authority_actor_id": "actor.policy-authority",
        "authority_key_id": "key.policy-authority",
        "authority_status": "AUTHORIZED",
        "authority_purpose": "HISTORICAL_REEVALUATION",
        "knowledge_mode": "KNOWN_AS_OF_CUTOFF",
        "policy_version": 1,
        "available_at": "2026-07-01T00:00:00Z",
        "allow_limited_security": not strict,
        "require_current_runtime": strict,
        "require_no_revocations": True,
    }
    return ReevaluationPolicySet.model_validate(
        {**body, "policy_set_digest": canonical_sha256(body)}
    )


def generate_continuous_trust_examples(root: Path) -> ContinuousTrustArtifactIndex:
    base = root / "continuous-trust"
    reports = root / "reports" / "continuous-trust"
    generated: list[Path] = []
    scope = synthetic_scope()
    subject = build_subject(
        "product_subject_2cb1fa6a8c4968f6d1ea3adc01896821",
        "ab87dcd7ebeb03bb3caa1ad15090f6936f8e89604852d7644b464eb261f65ecf",
        "MIXED_DEPLOYMENT_ARTIFACT_SET",
        scope,
    )
    context1 = canonical_sha256({"evaluation-sequence": 1, "time": "explicit-context-t1"})
    context2 = canonical_sha256({"evaluation-sequence": 2, "time": "explicit-context-t2"})
    time1 = "2026-07-01T00:00:00Z"
    time2 = "2026-08-01T00:00:00Z"
    refs = {
        "ARTIFACT_IDENTITY": evidence_ref(
            "omiv.product-subject.v1", subject.subject_id, subject.subject_digest, "5G"
        ),
        "ARTIFACT_SET": evidence_ref(
            "omiv.deployment-artifact-set.v1",
            "deployment_artifact_set_cd68f234c89aca95a9edbd9cef3391cd",
            "91586db6f9447406701de9681bd6509a7ab652dc82540c3fb797db2d533124ee",
            "5G",
        ),
        "ATTESTATION": evidence_ref(
            "omiv.artifact-attestation.v1",
            "attestation_synthetic-history",
            canonical_sha256({"attestation": "history"}),
            "5C",
        ),
        "CUSTODY": evidence_ref(
            "omiv.custody-ledger.v2",
            "custody_synthetic-history",
            canonical_sha256({"custody": "history"}),
            "5B",
        ),
        "TRUST": evidence_ref(
            "omiv.trust-bundle.v1",
            "trust_bundle_synthetic-history",
            canonical_sha256({"trust": "history"}),
            "5D",
        ),
        "AUTHORITY": evidence_ref(
            "omiv.assertion-authority-scope.v1",
            "runtime_authority_adb5472ff1c130437d9dac1fd5ebe46c",
            "de8bc5097b4a93ae2ff26bdff586efc43fc905a9d20057525728cba2fbcb71c4",
            "5G",
        ),
        "SECURITY": evidence_ref(
            "omiv.security-evaluation.v1",
            "security_evaluation_synthetic-history",
            canonical_sha256({"security": "limited"}),
            "5F",
        ),
        "GOVERNANCE": evidence_ref(
            "omiv.policy-decision.v1",
            "policy_decision_synthetic-history",
            canonical_sha256({"governance": "allow"}),
            "5E",
        ),
        "APPROVAL": evidence_ref(
            "omiv.approval-record.v1",
            "approval_synthetic-history",
            canonical_sha256({"approval": "valid"}),
            "5E",
        ),
        "DEPLOYMENT": evidence_ref(
            "omiv.deployment-record.v1",
            "deployment_record_054c7ffc6c9043c6380fb48a376ce6cf",
            "d1cbd9ddb901e395e7342e7effad74511fe3f59ceb53c0a034b47c4df3681195",
            "5G",
        ),
        "RUNTIME": evidence_ref(
            "omiv.runtime-observation.v1",
            "runtime_observation_ef4de78eb21c83dc7c28da10481842bf",
            "11d674c55fcd53404e578f5ca10f1045930eda900dfc30bcdc911c1702b6d5ee",
            "5G",
        ),
        "CONTINUITY": evidence_ref(
            "omiv.continuity-evaluation.v1",
            "runtime_evaluation_9f0cbbfbeda0d366a6aadcec6983be56",
            "db1db47d1060065c34946a1f3055bd13fbbe3e724ef45d0bd14bcc3d18d0a999",
            "5G",
        ),
    }

    def member(role: str) -> EvidenceSetMember:
        return EvidenceSetMember(
            reference=refs[role],
            role=role,
            availability=Availability.AVAILABLE,
            verification_mode="CANONICAL_DIGEST_VERIFIED",
            evidence_origin="EVIDENCE_LINKED",
            authority_status="AUTHORIZED",
            available_at=time2 if role == "SECURITY" else time1,
            inclusion_reason=(
                f"Required {role.lower()} evidence for the synthetic historical snapshot."
            ),
        )

    limited_roles = [x for x in refs if x != "SECURITY"]
    full_roles = list(refs)
    manifest1 = build_evidence_set(
        subject, [member(x) for x in limited_roles], version=1, context_digest=context1
    )
    manifest2 = build_evidence_set(
        subject,
        [member(x) for x in full_roles],
        version=2,
        context_digest=context2,
        predecessor=manifest1.manifest_id,
    )
    policy1 = _policy(scope, "team_history", False)
    policy2 = _policy(scope, "enterprise_history", True)
    trust_bundle_id = "trust_bundle_synthetic-history"
    trust_bundle_digest = refs["TRUST"].object_digest
    snapshot1 = reconstruct_snapshot(
        subject,
        manifest1,
        policy1,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context1,
        cutoff=time1,
    )
    snapshot2 = reconstruct_snapshot(
        subject,
        manifest2,
        policy1,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context2,
        cutoff=time2,
    )
    security_transition = compare_snapshots(
        snapshot1, snapshot2, changed_evidence=[refs["SECURITY"].object_id]
    )
    authority = EventAuthority(
        actor_id="runtime_observer_f69aee8f2aea0fa462a3538343161715",
        key_id="key.history-authority",
        trusted=True,
        authorized=True,
        assertion_types=[x.value for x in EventType],
        subject_id=subject.subject_id,
        allowed_object_schemas=sorted({value.schema_id for value in refs.values()}),
        purpose="HISTORICAL_EVENT_ASSERTION",
        key_usage="SIGNING",
        signer_binding_status="BOUND_AND_TRUSTED",
        scope=scope,
        valid_from_sequence=1,
        valid_through_sequence=100,
    )
    added = build_event(
        subject,
        EventType.SECURITY_EVIDENCE_ADDED,
        refs["SECURITY"],
        authority,
        sequence=1,
        predecessor=None,
        context_digest=context1,
        effective_at=time1,
        available_at=time1,
    )
    revoked = build_event(
        subject,
        EventType.EVIDENCE_REVOKED,
        refs["RUNTIME"],
        authority,
        sequence=2,
        predecessor=added.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
    )
    stale = build_event(
        subject,
        EventType.RUNTIME_OBSERVATION_STALE,
        refs["RUNTIME"],
        authority,
        sequence=3,
        predecessor=revoked.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
    )
    renewal_event = build_event(
        subject,
        EventType.RUNTIME_OBSERVATION_RENEWED,
        refs["RUNTIME"],
        authority,
        sequence=4,
        predecessor=stale.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
        observed_at=time2,
    )
    superseded_event = build_event(
        subject,
        EventType.EVIDENCE_SUPERSEDED,
        refs["SECURITY"],
        authority,
        sequence=5,
        predecessor=renewal_event.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
    )
    renewal = build_renewal(
        refs["RUNTIME"].object_id,
        "runtime_observation_renewed-synthetic",
        "deployment_instance_49be802bee3afc1dbeaf3b6ccf614ca2",
        "runtime_observer_f69aee8f2aea0fa462a3538343161715",
        renewal_event,
        "omiv.continuity-policy.team_service_continuity.v1",
        scope,
        ["ARTIFACT_IDENTITY", "CONFIGURATION_IDENTITY", "ENGINE_IDENTITY"],
        ["SECURITY_EVIDENCE", "APPROVAL", "BEHAVIORAL_SAFETY"],
        context2,
        4,
    )
    revoked_snapshot = reconstruct_snapshot(
        subject,
        manifest2,
        policy2,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context2,
        cutoff=time2,
        overrides={
            "RUNTIME_OBSERVATION": DimensionState.REVOKED,
            "RUNTIME_CONTINUITY": DimensionState.REVOKED,
        },
    )
    revoke_transition = compare_snapshots(
        snapshot2, revoked_snapshot, changed_evidence=[revoked.event_id]
    )
    restored_snapshot = reconstruct_snapshot(
        subject,
        manifest2,
        policy1,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context2,
        cutoff=time2,
    )
    restore_transition = compare_snapshots(
        revoked_snapshot, restored_snapshot, changed_evidence=[renewal_event.event_id]
    )
    timeline, forks = build_timeline(
        subject,
        [added, revoked, stale, renewal_event, superseded_event],
        [snapshot1, snapshot2, revoked_snapshot, restored_snapshot],
        [security_transition, revoke_transition, restore_transition],
        start=1,
        end=5,
        cutoff=time2,
    )
    fork_a = build_event(
        subject,
        EventType.DRIFT_DETECTED,
        refs["CONTINUITY"],
        authority,
        sequence=6,
        predecessor=superseded_event.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
    )
    fork_b = build_event(
        subject,
        EventType.DRIFT_RESOLVED,
        refs["CONTINUITY"],
        authority,
        sequence=6,
        predecessor=superseded_event.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
    )
    fork_timeline, detected_forks = build_timeline(
        subject,
        [added, revoked, stale, renewal_event, superseded_event, fork_a, fork_b],
        [snapshot1, snapshot2],
        [security_transition],
        start=1,
        end=6,
        cutoff=time2,
    )
    propagation = propagate_revocation(
        revoked,
        [
            ExplicitDependencyEdge(
                source_object_id=refs["RUNTIME"].object_id,
                dependent_object_id=refs["CONTINUITY"].object_id,
                edge_type=DependencyEdgeType.CONTINUITY_DEPENDENCY,
                affected_dimensions=["RUNTIME_OBSERVATION", "RUNTIME_CONTINUITY"],
            ),
            ExplicitDependencyEdge(
                source_object_id=refs["RUNTIME"].object_id,
                dependent_object_id="governance_runtime_synthetic",
                edge_type=DependencyEdgeType.EVIDENCE_DEPENDENCY,
                affected_dimensions=["GOVERNANCE_DECISION"],
            ),
            ExplicitDependencyEdge(
                source_object_id=refs["CONTINUITY"].object_id,
                dependent_object_id=snapshot2.snapshot_id,
                edge_type=DependencyEdgeType.EVIDENCE_DEPENDENCY,
                affected_dimensions=["RUNTIME_CONTINUITY"],
            ),
        ],
        [snapshot1, snapshot2],
    )
    supersession = build_supersession(
        subject,
        [
            SupersessionEdge(
                old_object_id=refs["SECURITY"].object_id,
                replacement_object_id="security_evaluation_replacement-synthetic",
                event_id=superseded_event.event_id,
            )
        ],
    )
    freshness = build_freshness(refs["RUNTIME"].object_id, "CURRENT", "STALE", context1, context2)
    request = HistoricalEvaluationRequest(
        schema="omiv.historical-evaluation-request.v1",
        request_id="historical_request_synthetic-v2",
        subject=subject,
        evidence_manifest_id=manifest2.manifest_id,
        evaluation_context_digest=context2,
        policy_set_id=policy1.policy_set_id,
        policy_set_digest=policy1.policy_set_digest,
        requested_dimensions=sorted(x.dimension for x in snapshot2.dimensions),
        cutoff_sequence=5,
        cutoff=time2,
        evaluated_at=time2,
        knowledge_mode=HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF,
        limitations=["Cutoff is explicit and does not mean current real-world state."],
    )
    result = build_historical_result(
        request,
        snapshot2,
        [added, revoked, stale, renewal_event, superseded_event],
        forks,
        security_transition,
    )
    canonical = {
        "objects/evidence-set-v1.json": manifest1,
        "objects/evidence-set-v2.json": manifest2,
        "snapshots/snapshot-t1.json": snapshot1,
        "snapshots/snapshot-t2.json": snapshot2,
        "snapshots/snapshot-revoked.json": revoked_snapshot,
        "policies/team-policy-set.json": policy1,
        "policies/enterprise-policy-set.json": policy2,
        "timeline/security-added.event.json": added,
        "timeline/runtime-revoked.event.json": revoked,
        "timeline/runtime-stale.event.json": stale,
        "timeline/runtime-renewed.event.json": renewal_event,
        "timeline/security-superseded.event.json": superseded_event,
        "timeline/timeline.json": timeline,
        "evaluations/security-transition.json": security_transition,
        "evaluations/revocation-transition.json": revoke_transition,
        "evaluations/restoration-transition.json": restore_transition,
        "evaluations/revocation-propagation.json": propagation,
        "evaluations/supersession-graph.json": supersession,
        "evaluations/freshness-transition.json": freshness,
        "evaluations/renewal.json": renewal,
        "evaluations/historical-request.json": request,
        "evaluations/historical-result.json": result,
    }
    for i, fork in enumerate(detected_forks, 1):
        generated.append(_write(base / "scenarios" / f"fork-{i}.json", fork))
    generated.extend(
        [
            _write(base / "scenarios/forked-timeline.json", fork_timeline),
            _write(base / "scenarios/fork-a.event.json", fork_a),
            _write(base / "scenarios/fork-b.event.json", fork_b),
        ]
    )
    bundle_root = base / "audit-bundle"
    for relative, value in canonical.items():
        generated.append(_write(bundle_root / relative, value))
    members = []
    for relative, value in sorted(canonical.items()):
        path = bundle_root / relative
        data = path.read_bytes()
        dumped = value.model_dump(mode="json", by_alias=True)
        object_id = _canonical_id(dumped)
        object_digest = next(
            (
                v
                for k, v in dumped.items()
                if k.endswith("_digest")
                and k
                not in {"evaluation_context_digest", "policy_set_digest", "trust_bundle_digest"}
                and isinstance(v, str)
            ),
            canonical_sha256(dumped),
        )
        members.append(
            AuditBundleMember(
                relative_path=relative,
                schema_id=dumped["schema"],
                object_id=object_id,
                object_digest=object_digest,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                inclusion_reason=(
                    "Required canonical member for offline enterprise historical reconstruction."
                ),
            )
        )
    exclusions = [
        AuditBundleGap(
            category="MODEL_PAYLOAD",
            required=False,
            state=Availability.EXCLUDED,
            reason="Model payload is excluded by Phase 5H policy.",
            affected_conclusion="Bundle verification does not establish payload completeness.",
            remediation="Transfer payload separately under an explicit future policy.",
        ),
        AuditBundleGap(
            category="TRUSTED_TIMESTAMP",
            required=False,
            state=Availability.UNAVAILABLE,
            reason="No timestamp authority was contacted.",
            affected_conclusion="Event time is supplied context, not trusted time.",
            remediation="Provide explicit trusted timestamp evidence in a future phase.",
        ),
        AuditBundleGap(
            category="CONTINUOUS_OBSERVATION",
            required=False,
            state=Availability.UNAVAILABLE,
            reason="Phase 5H is finite and offline.",
            affected_conclusion="Continuous real-world state is not established.",
            remediation="Use a separately authorized future continuous reevaluation system.",
        ),
    ]
    bundle = build_bundle_manifest(
        BundlePurpose.ENTERPRISE_AUDIT,
        subject,
        members,
        exclusions,
        start=1,
        end=5,
        completeness_policy_id="audit-completeness.enterprise.v1",
        completeness_policy_digest=canonical_sha256({"audit-completeness": "enterprise-v1"}),
    )
    completeness = build_completeness(bundle)
    verification = build_verification(
        bundle, completeness, [snapshot1.snapshot_id, snapshot2.snapshot_id], [timeline.timeline_id]
    )
    report = build_report(bundle, completeness, verification, snapshot2)
    generated.append(_write(bundle_root / "manifest.json", bundle))
    generated.append(_write(base / "verification/enterprise.completeness.json", completeness))
    generated.append(_write(base / "verification/enterprise.result.json", verification))
    generated.append(_write(reports / "enterprise.audit-report.json", report))
    md = reports / "enterprise.audit-report.md"
    atomic_write_text(md, render_audit_markdown(report))
    generated.append(md)

    # Compact purpose and transition scenarios reuse shared canonical objects rather
    # than copying bundle members. They make policy and evidence changes explicit.
    stable_transition = compare_snapshots(snapshot2, snapshot2)
    approval_withdrawn = build_event(
        subject,
        EventType.APPROVAL_WITHDRAWN,
        refs["APPROVAL"],
        authority,
        sequence=6,
        predecessor=superseded_event.event_id,
        context_digest=context2,
        effective_at=time2,
        available_at=time2,
    )
    withdrawn_snapshot = reconstruct_snapshot(
        subject,
        manifest2,
        policy1,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context2,
        cutoff=time2,
        overrides={"APPROVAL": DimensionState.WITHDRAWN},
    )
    withdrawal_transition = compare_snapshots(
        snapshot2, withdrawn_snapshot, changed_evidence=[approval_withdrawn.event_id]
    )
    stale_snapshot = reconstruct_snapshot(
        subject,
        manifest2,
        policy1,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context2,
        cutoff=time2,
        overrides={
            "RUNTIME_OBSERVATION": DimensionState.STALE,
            "RUNTIME_CONTINUITY": DimensionState.STALE,
            "FRESHNESS": DimensionState.STALE,
        },
    )
    stale_transition = compare_snapshots(
        snapshot2, stale_snapshot, changed_evidence=[stale.event_id]
    )
    strict_snapshot = reconstruct_snapshot(
        subject,
        manifest2,
        policy2,
        trust_bundle_id=trust_bundle_id,
        trust_bundle_digest=trust_bundle_digest,
        context_digest=context2,
        cutoff=time2,
    )
    policy_transition = compare_snapshots(snapshot2, strict_snapshot, changed_policy=True)
    scenario_records: dict[str, BaseModel] = {
        "stable.transition.json": stable_transition,
        "approval-withdrawn.event.json": approval_withdrawn,
        "withdrawn.snapshot.json": withdrawn_snapshot,
        "withdrawal.transition.json": withdrawal_transition,
        "stale.snapshot.json": stale_snapshot,
        "stale.transition.json": stale_transition,
        "strict-policy.snapshot.json": strict_snapshot,
        "policy-reclassified.transition.json": policy_transition,
    }

    purpose_bundles = {
        "air-gapped": build_bundle_manifest(
            BundlePurpose.AIR_GAPPED_TRANSFER,
            subject,
            members,
            exclusions,
            start=1,
            end=5,
            completeness_policy_id="audit-completeness.air-gapped.v1",
            completeness_policy_digest=canonical_sha256({"audit-completeness": "air-gapped-v1"}),
        ),
        "partial": build_bundle_manifest(
            BundlePurpose.TEAM_RELEASE_REVIEW,
            subject,
            [x for x in members if x.schema_id != "omiv.reevaluation-policy-set.v1"],
            exclusions,
            start=1,
            end=5,
            completeness_policy_id="audit-completeness.team.v1",
            completeness_policy_digest=canonical_sha256({"audit-completeness": "team-v1"}),
        ),
        "regulated": build_bundle_manifest(
            BundlePurpose.REGULATORY_EVIDENCE_EXPORT,
            subject,
            members,
            exclusions,
            start=1,
            end=5,
            completeness_policy_id="audit-completeness.regulated.v1",
            completeness_policy_digest=canonical_sha256({"audit-completeness": "regulated-v1"}),
        ),
    }
    for name, scenario_bundle in purpose_bundles.items():
        scenario_completeness = build_completeness(scenario_bundle)
        scenario_verification = build_verification(
            scenario_bundle,
            scenario_completeness,
            [snapshot2.snapshot_id],
            [timeline.timeline_id],
        )
        scenario_records[f"{name}.bundle-manifest.json"] = scenario_bundle
        scenario_records[f"{name}.completeness.json"] = scenario_completeness
        scenario_records[f"{name}.verification.json"] = scenario_verification
    for name, scenario_value in sorted(scenario_records.items()):
        generated.append(_write(base / "scenarios" / name, scenario_value))

    passport, custody, governance = build_adapters(
        snapshot2, security_transition, timeline, bundle, completeness
    )
    generated.extend(
        [
            _write(base / "adapters/passport-historical-summary.json", passport),
            _write(base / "adapters/custody-historical-linkage.json", custody),
            _write(base / "adapters/governance-historical-adapter.json", governance),
        ]
    )
    object_types = [
        SignedObjectType.TRUST_SNAPSHOT,
        SignedObjectType.TRUST_TIMELINE,
        SignedObjectType.HISTORICAL_EVALUATION_RESULT,
        SignedObjectType.AUDIT_BUNDLE_MANIFEST,
        SignedObjectType.AUDIT_BUNDLE_VERIFICATION_RESULT,
    ]
    purposes = [
        SignaturePurpose.TRUST_SNAPSHOT_ISSUANCE,
        SignaturePurpose.TRUST_TIMELINE_ISSUANCE,
        SignaturePurpose.HISTORICAL_EVALUATION_ISSUANCE,
        SignaturePurpose.AUDIT_BUNDLE_ISSUANCE,
        SignaturePurpose.AUDIT_BUNDLE_VERIFICATION_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([83]) * 32)
    key = build_key_identity(private, allowed_object_types=object_types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic historical audit issuer",
        role="AUDIT_ISSUER",
        evidence=[canonical_sha256({"issuer": "historical-audit"})],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    signing_policy = build_trust_policy(
        "team_release",
        object_types=object_types,
        purposes=purposes,
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    signing_bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    signed_dir = base / "signed"
    generated.extend(
        [
            _write(signed_dir / "historical.trust-policy.json", signing_policy),
            _write(signed_dir / "historical.trust-bundle.json", signing_bundle),
        ]
    )
    signed_objects = [
        ("snapshot", snapshot2, object_types[0], purposes[0]),
        ("timeline", timeline, object_types[1], purposes[1]),
        ("historical-evaluation", result, object_types[2], purposes[2]),
        ("audit-bundle", bundle, object_types[3], purposes[3]),
        ("bundle-verification", verification, object_types[4], purposes[4]),
    ]
    for name, value, object_type, purpose in signed_objects:
        raw = value.model_dump(mode="json", by_alias=True)
        descriptor = build_descriptor(raw, object_type, purpose, policy_id=signing_policy.policy_id)
        signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
        envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
        signature_report = verify_envelope(envelope, signing_bundle, signing_policy)
        linkage = build_signed_historical_linkage(
            envelope, trust_status=signature_report.overall_status.value
        )
        generated.extend(
            [
                _write(signed_dir / f"{name}.envelope.json", envelope),
                _write(signed_dir / f"{name}.linkage.json", linkage),
                _write(reports / f"{name}.signature-report.json", signature_report),
            ]
        )
    gap = {
        "schema": "omiv.historical-audit-gap-report.v1",
        "gap_report_id": "historical_gap_kimi-k3",
        "subject": "moonshotai/Kimi-K3",
        "available": "structural, custody, and trust gap records only",
        "missing": [
            "acquisition execution",
            "transformation execution",
            "security evidence",
            "deployment evidence",
            "runtime observation",
            "continuous observation",
        ],
        "current_state_claim": "NOT_MADE",
        "enterprise_bundle": "INCOMPLETE",
        "regulated_bundle": "INCOMPLETE",
        "model_payload_included": False,
        "limitations": ["Analysis-only gap report; no publisher authorization is implied."],
    }
    gap["gap_report_digest"] = canonical_sha256(gap)
    gap_path = reports / "kimi-k3.historical-audit-gap.json"
    gap_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(gap_path, json.dumps(gap, indent=2, sort_keys=True) + "\n")
    generated.append(gap_path)
    entries = []
    ids = set()
    hashes = set()
    for path in sorted(dict.fromkeys(generated)):
        data = path.read_bytes()
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256(data).hexdigest()
        if path.suffix == ".json":
            parsed = json.loads(data)
            schema = str(parsed.get("schema", "omiv.generated.v1"))
            try:
                cid = _canonical_id(parsed)
            except ValueError:
                cid = "generated_" + digest[:32]
        else:
            schema = "omiv.audit-report-markdown.v1"
            cid = "audit_markdown_" + digest[:32]
        if cid in ids or digest in hashes:
            raise ValueError(f"duplicate generated canonical ID or content: {rel} {cid} {digest}")
        ids.add(cid)
        hashes.add(digest)
        entries.append(
            ArtifactIndexEntry(
                relative_path=rel, size=len(data), sha256=digest, schema_id=schema, canonical_id=cid
            )
        )
    body = {
        "schema": "omiv.continuous-trust-artifact-index.v1",
        "entries": [x.model_dump(mode="json", by_alias=True) for x in entries],
        "generated_json_count": sum(x.relative_path.endswith(".json") for x in entries),
        "generated_markdown_count": sum(x.relative_path.endswith(".md") for x in entries),
        "total_size": sum(x.size for x in entries),
        "limitations": ["Index covers generated Phase 5H records and excludes itself."],
    }
    index = ContinuousTrustArtifactIndex.model_validate(
        identified(body, "index_id", "continuous_trust_index_", "index_digest")
    )
    atomic_write_text(base / "artifact-index.json", pretty_audit_json(index))
    return index


if __name__ == "__main__":
    generate_continuous_trust_examples(Path.cwd())
