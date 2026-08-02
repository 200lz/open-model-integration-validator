from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.continuous_trust.building import (
    build_completeness,
    build_event,
    build_historical_result,
    build_renewal,
    build_supersession,
    build_timeline,
    compare_snapshots,
    detect_forks,
    filter_evidence_set_known_as_of,
    propagate_revocation,
    reconstruct_snapshot,
    validate_renewal_chain,
)
from omiv.continuous_trust.bundles import (
    assert_acyclic_dependency_graph,
    build_bundle_manifest,
    bundle_dependency_graph,
    verify_bundle_directory,
    verify_continuous_trust_index,
)
from omiv.continuous_trust.examples import generate_continuous_trust_examples
from omiv.continuous_trust.models import (
    MAX_BUNDLE_MEMBERS,
    MAX_PROPAGATION_DEPTH,
    MAX_PROPAGATION_EDGES,
    MAX_RENEWAL_CHAIN_DEPTH,
    MAX_SUPERSESSION_DEPTH,
    MAX_SUPERSESSION_EDGES,
    MAX_TIMELINE_EVENTS,
    AuditBundleCompleteness,
    AuditBundleManifest,
    AuditBundleMember,
    AuditBundleReport,
    AuditBundleVerificationResult,
    ContinuousTrustArtifactIndex,
    DependencyEdgeType,
    DimensionState,
    EventAuthority,
    EventType,
    EvidenceSetManifest,
    ExplicitDependencyEdge,
    FreshnessTransitionResult,
    GovernanceHistoricalAdapter,
    HistoricalEvaluationRequest,
    HistoricalEvaluationResult,
    HistoricalEvent,
    PassportHistoricalSummary,
    ReevaluationPolicySet,
    RenewalRecord,
    RevocationPropagationResult,
    SnapshotState,
    SupersessionEdge,
    SupersessionGraph,
    TimelineCompleteness,
    TrustSnapshot,
    TrustTimeline,
    TrustTransition,
)
from omiv.continuous_trust.reporting import verify_audit_report
from omiv.continuous_trust.schema import SCHEMA_MODELS
from omiv.errors import OmivInputError
from omiv.runtime.building import synthetic_scope
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

runner = CliRunner()


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase5h-generated")
    generate_continuous_trust_examples(root)
    return root


def load(root: Path, relative: str) -> dict[str, object]:
    return json.loads((root / relative).read_text())


@pytest.mark.parametrize("schema", sorted(SCHEMA_MODELS))
def test_generated_schema_models_are_registered(generated: Path, schema: str) -> None:
    matches = []
    for path in generated.rglob("*.json"):
        value = json.loads(path.read_text())
        if value.get("schema") == schema:
            matches.append(value)
    if matches:
        SCHEMA_MODELS[schema].model_validate(matches[0])


def test_unknown_fields_and_caller_outcome_rejected(generated: Path) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t1.json")
    raw["caller_verdict"] = "TRUSTED_FOR_SCOPED_USE"
    with pytest.raises(ValidationError):
        TrustSnapshot.model_validate(raw)
    raw.pop("caller_verdict")
    raw["overall_state"] = "TRUSTED_FOR_SCOPED_USE"
    with pytest.raises(ValidationError):
        TrustSnapshot.model_validate(raw)


def test_redigested_caller_snapshot_outcome_is_reconstructed(generated: Path) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t1.json")
    raw["overall_state"] = "TRUSTED_FOR_SCOPED_USE"
    raw.pop("snapshot_id")
    raw.pop("snapshot_digest")
    digest = canonical_sha256(raw)
    raw["snapshot_id"] = "trust_snapshot_" + digest[:32]
    raw["snapshot_digest"] = digest
    with pytest.raises(ValidationError, match="reconstructed dimensions"):
        TrustSnapshot.model_validate(raw)


@pytest.mark.parametrize(
    "unsafe",
    ["/home/example/file", "../escape", "550e8400-e29b-41d4-a716-446655440000", "Bearer synthetic"],
)
def test_unsafe_identity_rejected(generated: Path, unsafe: str) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/objects/evidence-set-v1.json")
    raw["limitations"] = [unsafe]
    with pytest.raises(ValidationError):
        SCHEMA_MODELS[raw["schema"]].model_validate(raw)


def test_snapshot_dimensions_and_source_limitations(generated: Path) -> None:
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    dimensions = {x.dimension: x.state for x in snapshot.dimensions}
    assert dimensions["SECURITY_EVIDENCE"] == DimensionState.SATISFIED_WITH_LIMITATIONS
    assert dimensions["RUNTIME_CONTINUITY"] == DimensionState.SATISFIED_WITH_LIMITATIONS
    assert dimensions["PAYLOAD_INTEGRITY"] == DimensionState.NOT_CHECKED
    assert dimensions["TOKENIZER_PARITY"] == DimensionState.NOT_CHECKED
    assert dimensions["BEHAVIORAL_SAFETY"] == DimensionState.NOT_CHECKED
    assert snapshot.overall_state == SnapshotState.TRUSTED_WITH_LIMITATIONS
    assert any("snapshot-only" in x for x in snapshot.limitations)


def test_snapshot_immutability_and_policy_reevaluation(generated: Path) -> None:
    t1 = (generated / "continuous-trust/audit-bundle/snapshots/snapshot-t1.json").read_bytes()
    t2 = (generated / "continuous-trust/audit-bundle/snapshots/snapshot-t2.json").read_bytes()
    revoked = (
        generated / "continuous-trust/audit-bundle/snapshots/snapshot-revoked.json"
    ).read_bytes()
    assert t1 != t2 != revoked
    assert json.loads(t1)["snapshot_id"] != json.loads(revoked)["snapshot_id"]
    assert hashlib_sha256(t1) == hashlib_sha256(
        (generated / "continuous-trust/audit-bundle/snapshots/snapshot-t1.json").read_bytes()
    )


def test_canonical_models_are_frozen(generated: Path) -> None:
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t1.json")
    )
    with pytest.raises(ValidationError):
        snapshot.overall_state = SnapshotState.DENIED


def hashlib_sha256(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("evaluations/security-transition.json", "STRENGTHENED"),
        ("evaluations/revocation-transition.json", "REVOKED"),
        ("evaluations/restoration-transition.json", "RESTORED_WITH_NEW_EVIDENCE"),
    ],
)
def test_transition_outcomes(generated: Path, relative: str, expected: str) -> None:
    value = TrustTransition.model_validate(
        load(generated, "continuous-trust/audit-bundle/" + relative)
    )
    assert value.outcome.value == expected
    assert value.changed_dimensions


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("stable", "UNCHANGED"),
        ("withdrawal", "WITHDRAWN"),
        ("stale", "STALE"),
        ("policy-reclassified", "POLICY_RECLASSIFIED"),
    ],
)
def test_additional_transition_scenarios(generated: Path, name: str, expected: str) -> None:
    value = TrustTransition.model_validate(
        load(generated, f"continuous-trust/scenarios/{name}.transition.json")
    )
    assert value.outcome.value == expected


def test_stable_snapshot_transition_is_unchanged(generated: Path) -> None:
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    transition = compare_snapshots(snapshot, snapshot)
    assert transition.outcome.value == "UNCHANGED"


def test_timeline_order_and_declared_range(generated: Path) -> None:
    timeline = TrustTimeline.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/timeline.json")
    )
    assert timeline.completeness == TimelineCompleteness.COMPLETE_FOR_DECLARED_RANGE
    assert timeline.declared_start_sequence == 1
    assert timeline.declared_end_sequence == 5


def test_fork_is_detected_without_resolution(generated: Path) -> None:
    timeline = TrustTimeline.model_validate(
        load(generated, "continuous-trust/scenarios/forked-timeline.json")
    )
    assert timeline.completeness == TimelineCompleteness.FORKED
    assert timeline.fork_ids


def test_bundle_dependency_graph_is_acyclic_and_layered(generated: Path) -> None:
    manifest = AuditBundleManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/manifest.json")
    )
    graph = bundle_dependency_graph(manifest)
    assert_acyclic_dependency_graph(graph)
    schemas = {member.schema_id for member in manifest.members}
    assert "omiv.audit-bundle-manifest.v1" not in schemas
    assert "omiv.audit-bundle-verification-result.v1" not in schemas
    assert "omiv.signed-object-envelope.v1" not in schemas
    with pytest.raises(OmivInputError, match="cycle"):
        assert_acyclic_dependency_graph({"manifest": {"wrapper"}, "wrapper": {"manifest"}})


def test_cross_scope_event_rejected(generated: Path) -> None:
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    )
    wrong = event.model_copy(update={"scope": synthetic_scope(tenant="tenant.other")})
    with pytest.raises(OmivInputError):
        build_event(
            event.subject,
            EventType.EVIDENCE_ADDED,
            event.affected_object,
            EventAuthority.model_validate(
                {**event.authority.model_dump(), "scope": synthetic_scope(tenant="tenant.other")}
            ),
            sequence=9,
            predecessor=event.event_id,
            context_digest=event.evaluation_context_digest,
            effective_at="2026-08-01T00:00:00Z",
            available_at="2026-08-01T00:00:00Z",
        )
    assert wrong is not None


@pytest.mark.parametrize(
    "authority_update",
    [
        {"assertion_types": [EventType.DRIFT_DETECTED.value]},
        {"subject_id": "product_subject_wrong"},
        {"allowed_object_schemas": ["omiv.other-evidence.v1"]},
        {"trusted": False, "signer_binding_status": "UNTRUSTED"},
        {"signer_binding_status": "REVOKED"},
        {"signer_binding_status": "EXPIRED"},
    ],
)
def test_event_authority_fails_closed(generated: Path, authority_update: dict[str, object]) -> None:
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    )
    authority = event.authority.model_copy(update=authority_update)
    with pytest.raises(OmivInputError, match="not authorized"):
        build_event(
            event.subject,
            event.event_type,
            event.affected_object,
            authority,
            sequence=event.sequence,
            predecessor=event.predecessor_event_id,
            context_digest=event.evaluation_context_digest,
            effective_at=event.effective_at,
            available_at=event.available_at,
        )


def test_valid_signature_state_does_not_replace_event_authority(generated: Path) -> None:
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    )
    authority = event.authority.model_copy(update={"authorized": False})
    with pytest.raises(OmivInputError):
        build_event(
            event.subject,
            event.event_type,
            event.affected_object,
            authority,
            sequence=event.sequence,
            predecessor=None,
            context_digest=event.evaluation_context_digest,
            effective_at=event.effective_at,
            available_at=event.available_at,
        )


def test_untrusted_or_unauthorized_event_not_equated(generated: Path) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    raw["authority"]["authorized"] = False
    with pytest.raises(ValidationError):
        HistoricalEvent.model_validate(raw)


def test_revocation_propagation_retains_history(generated: Path) -> None:
    value = RevocationPropagationResult.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/revocation-propagation.json")
    )
    assert value.status == "PROPAGATED"
    assert value.transitive_dependent_ids
    assert len(value.unchanged_historical_snapshot_ids) == 2


def test_revocation_propagates_only_on_explicit_typed_edges(generated: Path) -> None:
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/runtime-revoked.event.json")
    )
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    unrelated = propagate_revocation(event, [], [snapshot])
    assert unrelated.transitive_dependent_ids == []
    assert unrelated.affected_dimensions == []
    edge = ExplicitDependencyEdge(
        source_object_id=event.affected_object.object_id,
        dependent_object_id="continuity.explicit-dependent",
        edge_type=DependencyEdgeType.CONTINUITY_DEPENDENCY,
        affected_dimensions=["RUNTIME_CONTINUITY"],
    )
    assert propagate_revocation(event, [edge] * MAX_PROPAGATION_EDGES, [snapshot]).status == (
        "PROPAGATED"
    )
    linked = propagate_revocation(event, [edge], [snapshot])
    assert linked.transitive_dependent_ids == ["continuity.explicit-dependent"]
    assert linked.affected_dimensions == ["RUNTIME_CONTINUITY"]


@pytest.mark.parametrize("state", ["CURRENT", "STALE"])
def test_freshness_uses_explicit_context(generated: Path, state: str) -> None:
    value = FreshnessTransitionResult.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/freshness-transition.json")
    )
    assert state in {value.previous_state, value.new_state}
    assert value.previous_context_digest != value.new_context_digest


def test_supersession_keeps_old_record(generated: Path) -> None:
    graph = SupersessionGraph.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/supersession-graph.json")
    )
    assert graph.edges
    assert "retained" in graph.limitations[0]


def test_supersession_does_not_clear_revocation(generated: Path) -> None:
    revoked = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-revoked.json")
    )
    graph = SupersessionGraph.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/supersession-graph.json")
    )
    assert graph.edges
    assert revoked.overall_state == SnapshotState.REVOKED
    assert any(dimension.state == DimensionState.REVOKED for dimension in revoked.dimensions)


def test_supersession_cycle_rejected(generated: Path) -> None:
    event_id = load(
        generated, "continuous-trust/audit-bundle/timeline/security-superseded.event.json"
    )["event_id"]
    subject = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    ).subject
    with pytest.raises(ValidationError):
        build_supersession(
            subject,
            [
                SupersessionEdge(
                    old_object_id="object.a", replacement_object_id="object.b", event_id=event_id
                ),
                SupersessionEdge(
                    old_object_id="object.b", replacement_object_id="object.a", event_id=event_id
                ),
            ],
        )


def test_renewal_is_dimension_limited(generated: Path) -> None:
    renewal = RenewalRecord.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/renewal.json")
    )
    assert "ARTIFACT_IDENTITY" in renewal.renewed_dimensions
    assert "SECURITY_EVIDENCE" in renewal.dimensions_not_renewed
    assert "BEHAVIORAL_SAFETY" in renewal.dimensions_not_renewed
    assert validate_renewal_chain([renewal]) == [renewal]


def test_renewal_scope_expansion_and_cycle_fail(generated: Path) -> None:
    renewal = RenewalRecord.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/renewal.json")
    )
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/runtime-renewed.event.json")
    )
    with pytest.raises(OmivInputError, match="scope expansion"):
        build_renewal(
            renewal.previous_observation_id,
            renewal.new_observation_id,
            renewal.deployment_instance_id,
            renewal.observer_id,
            event,
            renewal.policy_id,
            renewal.scope,
            ["SECURITY_EVIDENCE"],
            [],
            renewal.evaluation_context_digest,
            renewal.sequence,
        )
    cyclic = renewal.model_copy(update={"new_observation_id": renewal.previous_observation_id})
    with pytest.raises(OmivInputError, match="cycle"):
        validate_renewal_chain([cyclic])


def test_historical_evaluation_preserves_request_and_gaps(generated: Path) -> None:
    result = HistoricalEvaluationResult.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/historical-result.json")
    )
    assert result.accepted_evidence_ids
    assert result.gaps
    assert "explicit cutoff" in result.limitations[0]


def test_known_as_of_cutoff_excludes_late_arriving_evidence(generated: Path) -> None:
    request = HistoricalEvaluationRequest.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/historical-request.json")
    )
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    )
    at_cutoff = event.model_copy(update={"available_at": request.cutoff, "sequence": 1})
    late = event.model_copy(
        update={
            "event_id": "historical_event_" + "a" * 32,
            "available_at": "2026-08-02T00:00:00Z",
            "effective_at": "2026-06-01T00:00:00Z",
            "sequence": 2,
        }
    )
    result = build_historical_result(request, snapshot, [at_cutoff, late], [])
    assert at_cutoff.event_id in result.accepted_evidence_ids
    assert late.event_id in result.late_arriving_evidence_ids
    assert late.event_id not in result.accepted_evidence_ids
    assert result.knowledge_mode.value == "KNOWN_AS_OF_CUTOFF"


def test_effective_as_of_mode_is_explicitly_unsupported(generated: Path) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/evaluations/historical-request.json")
    raw["knowledge_mode"] = "EFFECTIVE_AS_OF_CUTOFF"
    with pytest.raises(ValidationError):
        HistoricalEvaluationRequest.model_validate(raw)


@pytest.mark.parametrize(
    "timestamp",
    ["2026-08-01", "2026-08-01T00:00:00", "2026-13-01T00:00:00Z"],
)
def test_historical_timestamp_must_be_canonical_utc(generated: Path, timestamp: str) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    raw["available_at"] = timestamp
    with pytest.raises(ValidationError):
        HistoricalEvent.model_validate(raw)


def test_timeline_filters_late_events_before_derivation(generated: Path) -> None:
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    )
    late = event.model_copy(
        update={
            "event_id": "historical_event_" + "b" * 32,
            "available_at": "2026-08-02T00:00:00Z",
            "sequence": 2,
        }
    )
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    timeline, forks = build_timeline(
        event.subject,
        [event, late],
        [snapshot],
        [],
        start=1,
        end=1,
        cutoff="2026-08-01T00:00:00Z",
    )
    assert timeline.event_ids == [event.event_id]
    assert forks == []


def test_available_before_but_effective_after_is_known_at_cutoff(generated: Path) -> None:
    request = HistoricalEvaluationRequest.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/historical-request.json")
    )
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    ).model_copy(
        update={
            "available_at": "2026-07-31T00:00:00Z",
            "effective_at": "2026-08-02T00:00:00Z",
        }
    )
    result = build_historical_result(request, snapshot, [event], [])
    assert result.accepted_evidence_ids == [event.event_id]


def test_evidence_set_filtering_occurs_by_availability(generated: Path) -> None:
    manifest = EvidenceSetManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/objects/evidence-set-v2.json")
    )
    filtered = filter_evidence_set_known_as_of(
        manifest,
        cutoff="2026-07-01T00:00:00Z",
        context_digest="f" * 64,
    )
    assert all(member.available_at <= "2026-07-01T00:00:00Z" for member in filtered.members)
    assert "SECURITY" not in {member.role for member in filtered.members}


def test_policy_is_exact_authorized_and_cutoff_aware(generated: Path) -> None:
    manifest = EvidenceSetManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/objects/evidence-set-v2.json")
    )
    policy_raw = load(generated, "continuous-trust/audit-bundle/policies/team-policy-set.json")
    policy = ReevaluationPolicySet.model_validate(policy_raw)
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    with pytest.raises(ValidationError):
        SCHEMA_MODELS["omiv.reevaluation-policy-set.v1"].model_validate(
            {**policy_raw, "policy_version": 2}
        )
    late_policy = policy.model_copy(update={"available_at": "2026-08-02T00:00:00Z"})
    with pytest.raises(OmivInputError, match="not known"):
        reconstruct_snapshot(
            snapshot.subject,
            manifest,
            late_policy,
            trust_bundle_id=snapshot.trust_bundle_id,
            trust_bundle_digest=snapshot.trust_bundle_digest,
            context_digest=snapshot.evaluation_context_digest,
            cutoff=snapshot.cutoff,
        )
    unauthorized = policy.model_copy(update={"authority_status": "UNAUTHORIZED"})
    with pytest.raises(OmivInputError, match="not authorized"):
        reconstruct_snapshot(
            snapshot.subject,
            manifest,
            unauthorized,
            trust_bundle_id=snapshot.trust_bundle_id,
            trust_bundle_digest=snapshot.trust_bundle_digest,
            context_digest=snapshot.evaluation_context_digest,
            cutoff=snapshot.cutoff,
        )


def test_enterprise_bundle_is_complete_with_explicit_exclusions(generated: Path) -> None:
    value = AuditBundleCompleteness.model_validate(
        load(generated, "continuous-trust/verification/enterprise.completeness.json")
    )
    assert value.state.value == "COMPLETE_WITH_LIMITATIONS"
    assert {x.category for x in value.gaps} == {
        "MODEL_PAYLOAD",
        "TRUSTED_TIMESTAMP",
        "CONTINUOUS_OBSERVATION",
    }


def test_timeline_and_bundle_completeness_are_independent(generated: Path) -> None:
    manifest = AuditBundleManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/manifest.json")
    )
    complete = build_completeness(
        manifest, timeline_states=[TimelineCompleteness.COMPLETE_FOR_DECLARED_RANGE]
    )
    forked = build_completeness(manifest, timeline_states=[TimelineCompleteness.FORKED])
    partial = build_completeness(manifest, timeline_states=[TimelineCompleteness.PARTIAL])
    assert complete.state.value == "COMPLETE_WITH_LIMITATIONS"
    assert forked.state.value == "FORKED_HISTORY"
    assert partial.state.value == "PARTIAL"
    assert complete.purpose == forked.purpose == partial.purpose


@pytest.mark.parametrize(
    ("name", "state", "outcome"),
    [
        ("air-gapped", "COMPLETE_WITH_LIMITATIONS", "VERIFIED_WITH_LIMITATIONS"),
        ("partial", "MISSING_REQUIRED_MEMBER", "INCOMPLETE"),
        ("regulated", "PARTIAL", "INCOMPLETE"),
    ],
)
def test_bundle_purpose_scenarios(generated: Path, name: str, state: str, outcome: str) -> None:
    completeness = AuditBundleCompleteness.model_validate(
        load(generated, f"continuous-trust/scenarios/{name}.completeness.json")
    )
    verification = AuditBundleVerificationResult.model_validate(
        load(generated, f"continuous-trust/scenarios/{name}.verification.json")
    )
    assert completeness.state.value == state
    assert verification.outcome.value == outcome


def test_offline_bundle_verification(generated: Path) -> None:
    root = generated / "continuous-trust/audit-bundle"
    manifest = AuditBundleManifest.model_validate(json.loads((root / "manifest.json").read_text()))
    result = verify_bundle_directory(root, manifest)
    assert result.outcome.value == "VERIFIED_WITH_LIMITATIONS"


def test_bundle_tamper_rejected(generated: Path, tmp_path: Path) -> None:
    source = generated / "continuous-trust/audit-bundle"
    target = tmp_path / "bundle"
    shutil.copytree(source, target)
    manifest = AuditBundleManifest.model_validate(
        json.loads((target / "manifest.json").read_text())
    )
    member = target / manifest.members[0].relative_path
    member.write_text(member.read_text() + " ")
    with pytest.raises(OmivInputError):
        verify_bundle_directory(target, manifest)


def test_bundle_extra_and_missing_member_rejected(generated: Path, tmp_path: Path) -> None:
    source = generated / "continuous-trust/audit-bundle"
    manifest = AuditBundleManifest.model_validate(
        json.loads((source / "manifest.json").read_text())
    )
    extra = tmp_path / "extra"
    shutil.copytree(source, extra)
    (extra / "objects/extra.json").write_text("{}")
    with pytest.raises(OmivInputError):
        verify_bundle_directory(extra, manifest)
    missing = tmp_path / "missing"
    shutil.copytree(source, missing)
    (missing / manifest.members[0].relative_path).unlink()
    with pytest.raises(OmivInputError):
        verify_bundle_directory(missing, manifest)


def test_bundle_symlink_rejected(generated: Path, tmp_path: Path) -> None:
    source = generated / "continuous-trust/audit-bundle"
    target = tmp_path / "symlink"
    shutil.copytree(source, target)
    (target / "unsafe-link").symlink_to(target / "manifest.json")
    manifest = AuditBundleManifest.model_validate(
        json.loads((target / "manifest.json").read_text())
    )
    with pytest.raises(OmivInputError):
        verify_bundle_directory(target, manifest)


@pytest.mark.parametrize(
    "path",
    [
        "../escape.json",
        "/absolute.json",
        "objects\\bad.json",
        "./dot.json",
        "objects//empty.json",
        "objects/name. ",
        "objects/name.",
        "objects/CON",
        "objects/con.json",
        "objects/AUX.txt",
        "objects/LPT1.report",
        "objects/control\x01.json",
        "objects/cafe\u0301.json",
    ],
)
def test_bundle_member_unsafe_path_rejected(path: str) -> None:
    with pytest.raises(ValidationError):
        AuditBundleMember(
            relative_path=path,
            schema_id="omiv.trust-snapshot.v1",
            object_id="trust_snapshot_" + "0" * 32,
            object_digest="0" * 64,
            sha256="1" * 64,
            size=1,
            inclusion_reason="invalid path test",
        )


@pytest.mark.parametrize(
    "paths",
    [
        ["A/report.json", "a/report.json"],
        ["objects/item", "objects/item/data.json"],
    ],
)
def test_bundle_normalized_and_prefix_collisions_rejected(
    generated: Path, paths: list[str]
) -> None:
    source = AuditBundleManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/manifest.json")
    )
    members = [
        AuditBundleMember(
            relative_path=path,
            schema_id="omiv.trust-snapshot.v1",
            object_id=f"object.member-{index}",
            object_digest=f"{index + 1:064x}",
            sha256=f"{index + 3:064x}",
            size=1,
            inclusion_reason="collision boundary test",
        )
        for index, path in enumerate(paths)
    ]
    with pytest.raises(ValidationError):
        build_bundle_manifest(
            source.purpose,
            source.subject,
            members,
            [],
            start=1,
            end=1,
            completeness_policy_id=source.completeness_policy_id,
            completeness_policy_digest=source.completeness_policy_digest,
        )


def test_bundle_member_limit_is_explicit(generated: Path) -> None:
    source = AuditBundleManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/manifest.json")
    )
    member = source.members[0]
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED:BUNDLE_MEMBERS"):
        build_bundle_manifest(
            source.purpose,
            source.subject,
            [member] * (MAX_BUNDLE_MEMBERS + 1),
            [],
            start=1,
            end=1,
            completeness_policy_id=source.completeness_policy_id,
            completeness_policy_digest=source.completeness_policy_digest,
        )


def test_report_reconstruction_and_boundaries(generated: Path) -> None:
    report = AuditBundleReport.model_validate(
        load(generated, "reports/continuous-trust/enterprise.audit-report.json")
    )
    bundle = AuditBundleManifest.model_validate(
        load(generated, "continuous-trust/audit-bundle/manifest.json")
    )
    completeness = AuditBundleCompleteness.model_validate(
        load(generated, "continuous-trust/verification/enterprise.completeness.json")
    )
    verification = AuditBundleVerificationResult.model_validate(
        load(generated, "continuous-trust/verification/enterprise.result.json")
    )
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    assert verify_audit_report(report, bundle, completeness, verification, snapshot) == report
    assert report.continuous_monitoring == "NOT_IMPLEMENTED"
    assert report.continuous_observation == "NOT_ESTABLISHED"
    assert report.model_payload_included is False


def test_tampered_report_rejected(generated: Path) -> None:
    raw = load(generated, "reports/continuous-trust/enterprise.audit-report.json")
    raw["continuous_observation"] = "NOT_ESTABLISHED"
    raw["outstanding_gaps"] = []
    with pytest.raises(ValidationError):
        AuditBundleReport.model_validate(raw)


def test_passport_custody_governance_are_separate(generated: Path) -> None:
    passport = PassportHistoricalSummary.model_validate(
        load(generated, "continuous-trust/adapters/passport-historical-summary.json")
    )
    governance = GovernanceHistoricalAdapter.model_validate(
        load(generated, "continuous-trust/adapters/governance-historical-adapter.json")
    )
    assert passport.continuous_observation == "NOT_ESTABLISHED"
    assert governance.security_state == DimensionState.SATISFIED_WITH_LIMITATIONS
    custody = load(generated, "continuous-trust/adapters/custody-historical-linkage.json")
    assert custody["append_only"] is True
    assert "CURRENTLY_TRUSTED" not in custody["event_types"]


def test_kimi_is_gap_only(generated: Path) -> None:
    gap = load(generated, "reports/continuous-trust/kimi-k3.historical-audit-gap.json")
    assert gap["current_state_claim"] == "NOT_MADE"
    assert gap["enterprise_bundle"] == "INCOMPLETE"
    assert gap["model_payload_included"] is False
    assert gap["schema"] not in SCHEMA_MODELS


def test_generated_artifact_index(generated: Path) -> None:
    index = ContinuousTrustArtifactIndex.model_validate(
        load(generated, "continuous-trust/artifact-index.json")
    )
    assert verify_continuous_trust_index(index, generated) == index
    assert len(index.entries) <= 120
    assert index.total_size <= 1_048_576
    assert max(x.size for x in index.entries) <= 1_048_576


def test_resource_bounds_fail_explicitly(generated: Path) -> None:
    event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/runtime-revoked.event.json")
    )
    snapshot = TrustSnapshot.model_validate(
        load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    )
    edge = ExplicitDependencyEdge(
        source_object_id=event.affected_object.object_id,
        dependent_object_id="object.dependent",
        edge_type=DependencyEdgeType.EVIDENCE_DEPENDENCY,
        affected_dimensions=["RUNTIME_CONTINUITY"],
    )
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED:REVOCATION_DEPENDENCY_EDGES"):
        propagate_revocation(event, [edge] * (MAX_PROPAGATION_EDGES + 1), [snapshot])
    chain = [
        ExplicitDependencyEdge(
            source_object_id=(
                event.affected_object.object_id if index == 0 else f"object.n{index}"
            ),
            dependent_object_id=f"object.n{index + 1}",
            edge_type=DependencyEdgeType.EVIDENCE_DEPENDENCY,
            affected_dimensions=["RUNTIME_CONTINUITY"],
        )
        for index in range(MAX_PROPAGATION_DEPTH + 1)
    ]
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED:REVOCATION_DEPTH"):
        propagate_revocation(event, chain, [snapshot])
    renewal = RenewalRecord.model_validate(
        load(generated, "continuous-trust/audit-bundle/evaluations/renewal.json")
    )
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED:RENEWAL_CHAIN_DEPTH"):
        validate_renewal_chain([renewal] * (MAX_RENEWAL_CHAIN_DEPTH + 1))
    timeline_event = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    )
    assert detect_forks([timeline_event] * MAX_TIMELINE_EVENTS) == []
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED:TIMELINE_EVENTS"):
        detect_forks([timeline_event] * (MAX_TIMELINE_EVENTS + 1))


def test_supersession_bounds_exact_and_beyond(generated: Path) -> None:
    subject = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-added.event.json")
    ).subject
    event_id = HistoricalEvent.model_validate(
        load(generated, "continuous-trust/audit-bundle/timeline/security-superseded.event.json")
    ).event_id
    exact = [
        SupersessionEdge(
            old_object_id=f"object.s{index}",
            replacement_object_id=f"object.s{index + 1}",
            event_id=event_id,
        )
        for index in range(MAX_SUPERSESSION_DEPTH)
    ]
    assert build_supersession(subject, exact).edges
    too_deep = exact + [
        SupersessionEdge(
            old_object_id=f"object.s{MAX_SUPERSESSION_DEPTH}",
            replacement_object_id=f"object.s{MAX_SUPERSESSION_DEPTH + 1}",
            event_id=event_id,
        )
    ]
    with pytest.raises(ValidationError, match="LIMIT_EXCEEDED:SUPERSESSION_DEPTH"):
        build_supersession(subject, too_deep)
    repeated = [exact[0]] * (MAX_SUPERSESSION_EDGES + 1)
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED:SUPERSESSION_EDGES"):
        build_supersession(subject, repeated)


def test_two_run_determinism(tmp_path: Path) -> None:
    one, two = tmp_path / "one", tmp_path / "two"
    generate_continuous_trust_examples(one)
    generate_continuous_trust_examples(two)
    one_files = {p.relative_to(one): p.read_bytes() for p in one.rglob("*") if p.is_file()}
    two_files = {p.relative_to(two): p.read_bytes() for p in two.rglob("*") if p.is_file()}
    assert one_files == two_files


@pytest.mark.parametrize(
    ("object_type", "purpose", "relative"),
    [
        (
            SignedObjectType.TRUST_SNAPSHOT,
            SignaturePurpose.TRUST_SNAPSHOT_ISSUANCE,
            "snapshots/snapshot-t2.json",
        ),
        (
            SignedObjectType.TRUST_TIMELINE,
            SignaturePurpose.TRUST_TIMELINE_ISSUANCE,
            "timeline/timeline.json",
        ),
        (
            SignedObjectType.HISTORICAL_EVALUATION_RESULT,
            SignaturePurpose.HISTORICAL_EVALUATION_ISSUANCE,
            "evaluations/historical-result.json",
        ),
        (
            SignedObjectType.AUDIT_BUNDLE_MANIFEST,
            SignaturePurpose.AUDIT_BUNDLE_ISSUANCE,
            "manifest.json",
        ),
    ],
)
def test_signed_historical_objects(
    generated: Path, object_type: SignedObjectType, purpose: SignaturePurpose, relative: str
) -> None:
    root = generated / "continuous-trust/audit-bundle"
    raw = json.loads((root / relative).read_text())
    private = Ed25519PrivateKey.from_private_bytes(bytes([83]) * 32)
    types = [
        SignedObjectType.TRUST_SNAPSHOT,
        SignedObjectType.TRUST_TIMELINE,
        SignedObjectType.HISTORICAL_EVALUATION_RESULT,
        SignedObjectType.AUDIT_BUNDLE_MANIFEST,
    ]
    purposes = [
        SignaturePurpose.TRUST_SNAPSHOT_ISSUANCE,
        SignaturePurpose.TRUST_TIMELINE_ISSUANCE,
        SignaturePurpose.HISTORICAL_EVALUATION_ISSUANCE,
        SignaturePurpose.AUDIT_BUNDLE_ISSUANCE,
    ]
    key = build_key_identity(private, allowed_object_types=types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic historical issuer",
        role="AUDIT_ISSUER",
        evidence=["2" * 64],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    policy = build_trust_policy(
        "team_release",
        object_types=types,
        purposes=purposes,
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    descriptor = build_descriptor(raw, object_type, purpose, policy_id=policy.policy_id)
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
    report = verify_envelope(envelope, bundle, policy)
    assert report.overall_status.value == "TRUSTED_SIGNATURE_WITH_LIMITATIONS"


def test_wrong_signature_purpose_fails(generated: Path) -> None:
    raw = load(generated, "continuous-trust/audit-bundle/snapshots/snapshot-t2.json")
    with pytest.raises(ValueError):
        build_descriptor(
            raw,
            SignedObjectType.TRUST_SNAPSHOT,
            SignaturePurpose.TRUST_TIMELINE_ISSUANCE,
            policy_id="policy.synthetic",
        )


@pytest.mark.parametrize(
    ("command", "path"),
    [
        ("snapshot-create", "snapshots/snapshot-t2.json"),
        ("event-create", "timeline/security-added.event.json"),
        ("timeline-build", "timeline/timeline.json"),
        ("transition-evaluate", "evaluations/security-transition.json"),
        ("reevaluate", "evaluations/historical-result.json"),
        ("revocation-propagate", "evaluations/revocation-propagation.json"),
        ("supersession-build", "evaluations/supersession-graph.json"),
        ("renewal-create", "evaluations/renewal.json"),
        ("bundle-create", "manifest.json"),
    ],
)
def test_cli_create_commands(generated: Path, tmp_path: Path, command: str, path: str) -> None:
    source = generated / "continuous-trust/audit-bundle" / path
    result = runner.invoke(
        app,
        ["audit", command, "--input", str(source), "--output", str(tmp_path / f"{command}.json")],
    )
    assert result.exit_code == 0, result.output
    assert "NOT_IMPLEMENTED" in result.output


def test_cli_verify_show_and_exit_codes(generated: Path) -> None:
    root = generated / "continuous-trust/audit-bundle"
    snapshot = runner.invoke(
        app, ["audit", "snapshot-verify", "--snapshot", str(root / "snapshots/snapshot-t2.json")]
    )
    assert snapshot.exit_code == 1
    assert "current_real_world=NOT_INFERRED" in snapshot.output
    bundle = runner.invoke(
        app,
        [
            "audit",
            "bundle-verify",
            "--bundle-root",
            str(root),
            "--manifest",
            str(root / "manifest.json"),
        ],
    )
    assert bundle.exit_code == 1
    assert "network=NO" in bundle.output
    show = runner.invoke(app, ["audit", "bundle-show", "--input", str(root / "manifest.json")])
    assert show.exit_code == 0
    assert "current real-world state=NOT_INFERRED" in show.output


def test_cli_report_verify(generated: Path) -> None:
    result = runner.invoke(
        app,
        [
            "audit",
            "report-verify",
            "--report",
            str(generated / "reports/continuous-trust/enterprise.audit-report.json"),
            "--bundle",
            str(generated / "continuous-trust/audit-bundle/manifest.json"),
            "--completeness",
            str(generated / "continuous-trust/verification/enterprise.completeness.json"),
            "--verification",
            str(generated / "continuous-trust/verification/enterprise.result.json"),
            "--snapshot",
            str(generated / "continuous-trust/audit-bundle/snapshots/snapshot-t2.json"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_generated_privacy_and_no_payload(generated: Path) -> None:
    content = "\n".join(
        p.read_text(errors="replace") for p in generated.rglob("*") if p.is_file()
    ).lower()
    for forbidden in (
        "begin private key",
        "github_pat_",
        "ghp_",
        "x-amz-",
        "/home/",
        "c:\\users\\",
        "datetime.now",
        "time.time",
        "model payload included: yes",
    ):
        assert forbidden not in content


def test_phase5g_artifact_index_unchanged() -> None:
    root = Path(__file__).resolve().parents[1]
    value = json.loads((root / "runtime/artifact-index.json").read_text())
    assert (
        value["index_digest"] == "440e81145c3d78f566d30eb28eb7f3be7406561b417b934c1b2c5102df89e083"
    )
