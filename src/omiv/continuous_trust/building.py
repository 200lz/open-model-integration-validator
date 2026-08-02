"""Deterministic builders and historical reconstruction for Phase 5H."""

from __future__ import annotations

from typing import Any

from omiv.canonical import canonical_sha256
from omiv.continuous_trust.models import (
    MAX_PROPAGATION_DEPTH,
    MAX_PROPAGATION_EDGES,
    MAX_PROPAGATION_NODES,
    MAX_RENEWAL_CHAIN_DEPTH,
    MAX_REPORT_INPUTS,
    MAX_SUPERSESSION_EDGES,
    MAX_SUPERSESSION_NODES,
    MAX_TIMELINE_EVENTS,
    MAX_TIMELINE_FORKS,
    MAX_TIMELINE_TRANSITIONS,
    AuditBundleCompleteness,
    AuditBundleManifest,
    AuditBundleReport,
    AuditBundleVerificationResult,
    Availability,
    BundleCompletenessState,
    BundlePurpose,
    CustodyHistoricalLinkage,
    DimensionState,
    EventAuthority,
    EventType,
    EvidenceObjectReference,
    EvidenceSetManifest,
    EvidenceSetMember,
    ExplicitDependencyEdge,
    FreshnessTransitionResult,
    GovernanceHistoricalAdapter,
    HistoricalEvaluationRequest,
    HistoricalEvaluationResult,
    HistoricalEvent,
    HistoricalKnowledgeMode,
    HistoricalSubject,
    PassportHistoricalSummary,
    ReevaluationPolicySet,
    RenewalRecord,
    RevocationPropagationResult,
    SnapshotState,
    SupersessionEdge,
    SupersessionGraph,
    TimelineCompleteness,
    TimelineFork,
    TransitionOutcome,
    TrustDimensionState,
    TrustGap,
    TrustSnapshot,
    TrustTimeline,
    TrustTransition,
    VerificationOutcome,
)
from omiv.errors import OmivInputError
from omiv.runtime.models import ScopeContext


def identified(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    with_id = {**body, id_field: prefix + canonical_sha256(body)[:32]}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def build_subject(
    subject_id: str, subject_digest: str, subject_class: str, scope: ScopeContext
) -> HistoricalSubject:
    return HistoricalSubject(
        subject_id=subject_id,
        subject_digest=subject_digest,
        subject_class=subject_class,
        scope=scope,
    )


def evidence_ref(
    schema: str, object_id: str, object_digest: str, phase: str
) -> EvidenceObjectReference:
    return EvidenceObjectReference(
        schema=schema, object_id=object_id, object_digest=object_digest, source_phase=phase
    )


def build_evidence_set(
    subject: HistoricalSubject,
    members: list[EvidenceSetMember],
    *,
    version: int,
    context_digest: str,
    predecessor: str | None = None,
) -> EvidenceSetManifest:
    body = {
        "schema": "omiv.evidence-set-manifest.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "evidence_set_version": version,
        "members": [
            x.model_dump(mode="json", by_alias=True)
            for x in sorted(members, key=lambda x: (x.role, x.reference.object_id))
        ],
        "predecessor_manifest_id": predecessor,
        "evaluation_context_digest": context_digest,
        "limitations": [
            "Finite supplied evidence only; absence of new evidence does not prove "
            "no real-world change."
        ],
    }
    return EvidenceSetManifest.model_validate(
        identified(body, "manifest_id", "evidence_set_", "manifest_digest")
    )


def filter_evidence_set_known_as_of(
    manifest: EvidenceSetManifest, *, cutoff: str, context_digest: str
) -> EvidenceSetManifest:
    """Create a finite manifest containing only evidence available by the cutoff."""
    included = [member for member in manifest.members if member.available_at <= cutoff]
    return build_evidence_set(
        manifest.subject,
        included,
        version=manifest.evidence_set_version,
        context_digest=context_digest,
        predecessor=manifest.predecessor_manifest_id,
    )


def reconstruct_snapshot(
    subject: HistoricalSubject,
    manifest: EvidenceSetManifest,
    policy: ReevaluationPolicySet,
    *,
    trust_bundle_id: str,
    trust_bundle_digest: str,
    context_digest: str,
    cutoff: str,
    overrides: dict[str, DimensionState] | None = None,
    extra_gaps: list[TrustGap] | None = None,
) -> TrustSnapshot:
    if manifest.subject != subject or policy.scope != subject.scope:
        raise OmivInputError("snapshot subject or policy scope mismatch")
    if policy.authority_status != "AUTHORIZED":
        raise OmivInputError("reevaluation policy authority is not authorized")
    if policy.available_at > cutoff:
        raise OmivInputError("policy was not known by historical cutoff")
    if any(member.available_at > cutoff for member in manifest.members):
        raise OmivInputError("evidence manifest contains evidence unavailable at cutoff")
    available_roles = {x.role for x in manifest.members if x.availability == Availability.AVAILABLE}
    dimensions = {
        "ARTIFACT_IDENTITY": DimensionState.SATISFIED
        if "ARTIFACT_IDENTITY" in available_roles
        else DimensionState.MISSING,
        "ARTIFACT_SET_COMPLETENESS": DimensionState.SATISFIED
        if "ARTIFACT_SET" in available_roles
        else DimensionState.PARTIAL,
        "SOURCE_PROVENANCE": DimensionState.SATISFIED_WITH_LIMITATIONS
        if "ATTESTATION" in available_roles
        else DimensionState.MISSING,
        "CUSTODY_INTEGRITY": DimensionState.SATISFIED
        if "CUSTODY" in available_roles
        else DimensionState.MISSING,
        "SIGNATURE_TRUST": DimensionState.SATISFIED
        if "TRUST" in available_roles
        else DimensionState.NOT_EVALUATED,
        "SIGNER_AUTHORITY": DimensionState.SATISFIED
        if "AUTHORITY" in available_roles
        else DimensionState.NOT_EVALUATED,
        "SECURITY_EVIDENCE": DimensionState.SATISFIED_WITH_LIMITATIONS
        if "SECURITY" in available_roles
        else DimensionState.MISSING,
        "GOVERNANCE_DECISION": DimensionState.SATISFIED
        if "GOVERNANCE" in available_roles
        else DimensionState.MISSING,
        "APPROVAL": DimensionState.SATISFIED
        if "APPROVAL" in available_roles
        else DimensionState.MISSING,
        "DEPLOYMENT_EVIDENCE": DimensionState.SATISFIED_WITH_LIMITATIONS
        if "DEPLOYMENT" in available_roles
        else DimensionState.MISSING,
        "RUNTIME_OBSERVATION": DimensionState.SATISFIED_WITH_LIMITATIONS
        if "RUNTIME" in available_roles
        else DimensionState.MISSING,
        "RUNTIME_CONTINUITY": DimensionState.SATISFIED_WITH_LIMITATIONS
        if "CONTINUITY" in available_roles
        else DimensionState.NOT_EVALUATED,
        "PAYLOAD_INTEGRITY": DimensionState.NOT_CHECKED,
        "TOKENIZER_PARITY": DimensionState.NOT_CHECKED,
        "QUANTIZATION_FIDELITY": DimensionState.NOT_CHECKED,
        "NUMERICAL_PARITY": DimensionState.NOT_CHECKED,
        "BEHAVIORAL_SAFETY": DimensionState.NOT_CHECKED,
        "REVOCATION": DimensionState.SATISFIED
        if policy.require_no_revocations
        else DimensionState.NOT_EVALUATED,
        "FRESHNESS": DimensionState.SATISFIED,
    }
    dimensions.update(overrides or {})
    evidence_by_role = {x.role: x.reference.object_id for x in manifest.members}
    rows = [
        TrustDimensionState(
            dimension=k,
            state=v,
            evidence_ids=([evidence_by_role[k]] if k in evidence_by_role else []),
            limitations=["State is reconstructed only from the finite supplied evidence set."],
        )
        for k, v in sorted(dimensions.items())
    ]
    gaps = list(extra_gaps or [])
    for name, state in dimensions.items():
        if state in {
            DimensionState.MISSING,
            DimensionState.UNAVAILABLE,
            DimensionState.NOT_CHECKED,
            DimensionState.NOT_EVALUATED,
            DimensionState.STALE,
            DimensionState.REVOKED,
            DimensionState.WITHDRAWN,
            DimensionState.BROKEN,
        }:
            gaps.append(
                TrustGap(
                    category=name,
                    state=Availability.UNAVAILABLE
                    if state
                    in {
                        DimensionState.NOT_CHECKED,
                        DimensionState.NOT_EVALUATED,
                        DimensionState.UNAVAILABLE,
                    }
                    else Availability.MISSING,
                    affected_conclusion=f"{name} cannot be treated as fully satisfied.",
                    remediation=(
                        "Supply authorized canonical evidence and reevaluate under an "
                        "explicit context."
                    ),
                )
            )
    states = set(dimensions.values())
    if DimensionState.BROKEN in states:
        overall = SnapshotState.BROKEN
    elif DimensionState.REVOKED in states:
        overall = SnapshotState.REVOKED
    elif DimensionState.DENIED in states or DimensionState.WITHDRAWN in states:
        overall = SnapshotState.DENIED
    elif DimensionState.STALE in states:
        overall = SnapshotState.STALE
    elif states.intersection({DimensionState.MISSING, DimensionState.UNKNOWN}):
        overall = SnapshotState.REVIEW_REQUIRED
    elif states.intersection(
        {
            DimensionState.SATISFIED_WITH_LIMITATIONS,
            DimensionState.PARTIAL,
            DimensionState.NOT_CHECKED,
            DimensionState.NOT_EVALUATED,
        }
    ):
        overall = SnapshotState.TRUSTED_WITH_LIMITATIONS
    else:
        overall = SnapshotState.TRUSTED_FOR_SCOPED_USE
    body = {
        "schema": "omiv.trust-snapshot.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "evidence_manifest_id": manifest.manifest_id,
        "evidence_manifest_digest": manifest.manifest_digest,
        "policy_set_id": policy.policy_set_id,
        "policy_set_digest": policy.policy_set_digest,
        "trust_bundle_id": trust_bundle_id,
        "trust_bundle_digest": trust_bundle_digest,
        "evaluation_context_digest": context_digest,
        "cutoff": cutoff,
        "knowledge_mode": HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF.value,
        "dimensions": [x.model_dump(mode="json", by_alias=True) for x in rows],
        "overall_state": overall.value,
        "gaps": [
            x.model_dump(mode="json", by_alias=True) for x in sorted(gaps, key=lambda x: x.category)
        ],
        "limitations": [
            "Historical snapshot is immutable and context-scoped.",
            "Latest supplied snapshot is not necessarily current real-world state.",
            "Continuous observation is NOT_ESTABLISHED.",
            "Phase 5F security limitations and Phase 5G snapshot-only limitations remain in force.",
        ],
    }
    return TrustSnapshot.model_validate(
        identified(body, "snapshot_id", "trust_snapshot_", "snapshot_digest")
    )


def build_event(
    subject: HistoricalSubject,
    event_type: EventType,
    affected: EvidenceObjectReference,
    authority: EventAuthority,
    *,
    sequence: int,
    predecessor: str | None,
    context_digest: str,
    effective_at: str,
    available_at: str,
    observed_at: str | None = None,
    namespace: str = "timeline.synthetic",
    epoch: int = 1,
) -> HistoricalEvent:
    if (
        authority.scope != subject.scope
        or not authority.authorized
        or event_type.value not in authority.assertion_types
        or authority.subject_id != subject.subject_id
        or affected.schema_id not in authority.allowed_object_schemas
        or authority.signer_binding_status != "BOUND_AND_TRUSTED"
    ):
        raise OmivInputError("event issuer is not authorized for event type and scope")
    body = {
        "schema": "omiv.historical-event.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "event_type": event_type.value,
        "affected_object": affected.model_dump(mode="json", by_alias=True),
        "predecessor_event_id": predecessor,
        "sequence_namespace": namespace,
        "epoch": epoch,
        "sequence": sequence,
        "assertion_origin": "SIGNED_AND_TRUSTED" if authority.trusted else "STRUCTURALLY_VERIFIED",
        "authority": authority.model_dump(mode="json", by_alias=True),
        "evidence_references": [],
        "effective_at": effective_at,
        "available_at": available_at,
        "observed_at": observed_at,
        "trusted_time_status": "NOT_AVAILABLE",
        "evaluation_context_digest": context_digest,
        "limitations": [
            "Event is supplied evidence; signature and authority do not independently "
            "prove the event occurred."
        ],
    }
    return HistoricalEvent.model_validate(
        identified(body, "event_id", "historical_event_", "event_digest")
    )


def detect_forks(events: list[HistoricalEvent]) -> list[TimelineFork]:
    if len(events) > MAX_TIMELINE_EVENTS:
        raise OmivInputError("LIMIT_EXCEEDED:TIMELINE_EVENTS")
    forks = []
    groups: dict[tuple[str, int, int], list[HistoricalEvent]] = {}
    successors: dict[str, list[HistoricalEvent]] = {}
    for e in events:
        groups.setdefault((e.sequence_namespace, e.epoch, e.sequence), []).append(e)
        if e.predecessor_event_id:
            successors.setdefault(e.predecessor_event_id, []).append(e)
    for key, values in sorted(groups.items()):
        if len({x.event_digest for x in values}) > 1:
            body = {
                "schema": "omiv.timeline-fork.v1",
                "outcome": "CONFLICT_DETECTED",
                "conflicting_event_ids": sorted(x.event_id for x in values),
                "reason": f"Different event content occupies sequence {key}.",
            }
            forks.append(
                TimelineFork.model_validate(
                    identified(body, "fork_id", "timeline_fork_", "fork_digest")
                )
            )
            if len(forks) > MAX_TIMELINE_FORKS:
                raise OmivInputError("LIMIT_EXCEEDED:TIMELINE_FORKS")
    for predecessor, values in sorted(successors.items()):
        if len({x.event_id for x in values}) > 1:
            body = {
                "schema": "omiv.timeline-fork.v1",
                "outcome": "FORK_DETECTED",
                "conflicting_event_ids": sorted(x.event_id for x in values),
                "reason": f"Multiple successors reference predecessor {predecessor}.",
            }
            forks.append(
                TimelineFork.model_validate(
                    identified(body, "fork_id", "timeline_fork_", "fork_digest")
                )
            )
            if len(forks) > MAX_TIMELINE_FORKS:
                raise OmivInputError("LIMIT_EXCEEDED:TIMELINE_FORKS")
    return forks


def build_timeline(
    subject: HistoricalSubject,
    events: list[HistoricalEvent],
    snapshots: list[TrustSnapshot],
    transitions: list[TrustTransition],
    *,
    start: int,
    end: int,
    cutoff: str | None = None,
) -> tuple[TrustTimeline, list[TimelineFork]]:
    if len(events) > MAX_TIMELINE_EVENTS:
        raise OmivInputError("LIMIT_EXCEEDED:TIMELINE_EVENTS")
    if len(transitions) > MAX_TIMELINE_TRANSITIONS:
        raise OmivInputError("LIMIT_EXCEEDED:TIMELINE_TRANSITIONS")
    if len({event.event_id for event in events}) != len(events):
        raise OmivInputError("duplicate timeline event identity")
    if any(e.subject != subject for e in events):
        raise OmivInputError("cross-scope timeline event")
    eligible = [event for event in events if cutoff is None or event.available_at <= cutoff]
    ordered = sorted(eligible, key=lambda e: (e.epoch, e.sequence, e.event_id))
    forks = detect_forks(ordered)
    seqs = {e.sequence for e in ordered}
    missing = sorted(set(range(start, end + 1)) - seqs)
    if forks:
        completeness = TimelineCompleteness.FORKED
    elif missing:
        completeness = TimelineCompleteness.MISSING_PREDECESSOR
    else:
        completeness = TimelineCompleteness.COMPLETE_FOR_DECLARED_RANGE
    body = {
        "schema": "omiv.trust-timeline.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "sequence_namespace": ordered[0].sequence_namespace if ordered else "timeline.synthetic",
        "epoch": ordered[0].epoch if ordered else 1,
        "event_ids": [e.event_id for e in ordered],
        "snapshot_ids": [x.snapshot_id for x in snapshots],
        "transition_ids": [x.transition_id for x in transitions],
        "fork_ids": [x.fork_id for x in forks],
        "completeness": completeness.value,
        "declared_start_sequence": start,
        "declared_end_sequence": end,
        "limitations": [
            "Completeness applies only to the supplied declared sequence range.",
            "Timeline ordering does not establish continuous monitoring.",
        ],
    }
    return TrustTimeline.model_validate(
        identified(body, "timeline_id", "trust_timeline_", "timeline_digest")
    ), forks


def compare_snapshots(
    previous: TrustSnapshot,
    new: TrustSnapshot,
    *,
    changed_evidence: list[str] | None = None,
    changed_policy: bool = False,
) -> TrustTransition:
    if previous.subject != new.subject:
        raise OmivInputError("snapshots are not comparable")
    old = {x.dimension: x.state for x in previous.dimensions}
    now = {x.dimension: x.state for x in new.dimensions}
    changed = sorted(k for k in old if old[k] != now.get(k))
    unchanged = sorted(k for k in old if old[k] == now.get(k))
    if not changed and not changed_policy:
        outcome = TransitionOutcome.UNCHANGED
    elif changed_policy:
        outcome = TransitionOutcome.POLICY_RECLASSIFIED
    elif any(now[k] == DimensionState.REVOKED for k in changed):
        outcome = TransitionOutcome.REVOKED
    elif any(now[k] == DimensionState.WITHDRAWN for k in changed):
        outcome = TransitionOutcome.WITHDRAWN
    elif any(now[k] == DimensionState.STALE for k in changed):
        outcome = TransitionOutcome.STALE
    elif previous.overall_state in {
        SnapshotState.DENIED,
        SnapshotState.STALE,
        SnapshotState.REVOKED,
    } and new.overall_state in {
        SnapshotState.TRUSTED_WITH_LIMITATIONS,
        SnapshotState.TRUSTED_FOR_SCOPED_USE,
    }:
        outcome = TransitionOutcome.RESTORED_WITH_NEW_EVIDENCE
    elif new.overall_state == SnapshotState.DENIED:
        outcome = TransitionOutcome.DENIED
    elif new.overall_state == SnapshotState.REVIEW_REQUIRED:
        outcome = TransitionOutcome.LIMITED
    else:
        outcome = TransitionOutcome.STRENGTHENED
    body = {
        "schema": "omiv.trust-transition.v1",
        "previous_snapshot_id": previous.snapshot_id,
        "new_snapshot_id": new.snapshot_id,
        "outcome": outcome.value,
        "changed_dimensions": changed,
        "unchanged_dimensions": unchanged,
        "changed_evidence": sorted(changed_evidence or []),
        "changed_policy": changed_policy,
        "reasons": [f"{k}: {old[k].value} -> {now[k].value}" for k in changed],
        "limitations": [
            "Transition describes supplied snapshots only; it is not a continuous-state assertion."
        ],
    }
    return TrustTransition.model_validate(
        identified(body, "transition_id", "trust_transition_", "transition_digest")
    )


def propagate_revocation(
    event: HistoricalEvent,
    dependencies: list[ExplicitDependencyEdge],
    snapshots: list[TrustSnapshot],
) -> RevocationPropagationResult:
    if len(dependencies) > MAX_PROPAGATION_EDGES:
        raise OmivInputError("LIMIT_EXCEEDED:REVOCATION_DEPENDENCY_EDGES")
    nodes = {
        value
        for edge in dependencies
        for value in (edge.source_object_id, edge.dependent_object_id)
    }
    if len(nodes) > MAX_PROPAGATION_NODES:
        raise OmivInputError("LIMIT_EXCEEDED:REVOCATION_NODES")
    affected: set[str] = set()
    if event.event_type != EventType.EVIDENCE_REVOKED or not event.authority.authorized:
        status = "UNAUTHORIZED"
        dependents = []
    else:
        status = "PROPAGATED"
        adjacency: dict[str, list[ExplicitDependencyEdge]] = {}
        for edge in dependencies:
            adjacency.setdefault(edge.source_object_id, []).append(edge)
        seen = set()
        stack = [(edge, 1) for edge in adjacency.get(event.affected_object.object_id, [])]
        while stack:
            edge, depth = stack.pop()
            if depth > MAX_PROPAGATION_DEPTH:
                raise OmivInputError("LIMIT_EXCEEDED:REVOCATION_DEPTH")
            item = edge.dependent_object_id
            if item not in seen:
                seen.add(item)
                affected.update(edge.affected_dimensions)
                stack.extend((next_edge, depth + 1) for next_edge in adjacency.get(item, []))
        dependents = sorted(seen)
    body = {
        "schema": "omiv.revocation-propagation-result.v1",
        "direct_target_ids": [event.affected_object.object_id],
        "transitive_dependent_ids": dependents,
        "affected_dimensions": sorted(affected) if dependents else [],
        "unchanged_historical_snapshot_ids": [x.snapshot_id for x in snapshots],
        "reevaluation_required": bool(dependents),
        "status": status,
        "limitations": [
            "Revocation limits dependent conclusions but does not delete historical evidence."
        ],
    }
    return RevocationPropagationResult.model_validate(
        identified(body, "propagation_id", "revocation_propagation_", "propagation_digest")
    )


def build_supersession(
    subject: HistoricalSubject, edges: list[SupersessionEdge], withdrawn: list[str] | None = None
) -> SupersessionGraph:
    if len(edges) > MAX_SUPERSESSION_EDGES:
        raise OmivInputError("LIMIT_EXCEEDED:SUPERSESSION_EDGES")
    nodes = {value for edge in edges for value in (edge.old_object_id, edge.replacement_object_id)}
    if len(nodes) > MAX_SUPERSESSION_NODES:
        raise OmivInputError("LIMIT_EXCEEDED:SUPERSESSION_NODES")
    body = {
        "schema": "omiv.supersession-graph.v1",
        "subject_id": subject.subject_id,
        "edges": [
            x.model_dump(mode="json", by_alias=True)
            for x in sorted(edges, key=lambda x: x.old_object_id)
        ],
        "withdrawn_object_ids": sorted(withdrawn or []),
        "conflicting_object_ids": [],
        "limitations": [
            "Supersession selects preferred future evidence; prior records are retained."
        ],
    }
    return SupersessionGraph.model_validate(
        identified(body, "graph_id", "supersession_graph_", "graph_digest")
    )


def build_freshness(
    object_id: str, previous: str, new: str, previous_context: str, new_context: str
) -> FreshnessTransitionResult:
    body = {
        "schema": "omiv.freshness-transition-result.v1",
        "object_id": object_id,
        "previous_state": previous,
        "new_state": new,
        "previous_context_digest": previous_context,
        "new_context_digest": new_context,
        "limitations": ["Freshness is evaluated only under explicit supplied contexts."],
    }
    return FreshnessTransitionResult.model_validate(
        identified(body, "freshness_id", "freshness_transition_", "freshness_digest")
    )


def build_renewal(
    previous_id: str,
    new_id: str,
    instance_id: str,
    observer_id: str,
    authority_event: HistoricalEvent,
    policy_id: str,
    scope: ScopeContext,
    renewed: list[str],
    not_renewed: list[str],
    context_digest: str,
    sequence: int,
) -> RenewalRecord:
    allowed_dimensions = {
        "ARTIFACT_IDENTITY",
        "CONFIGURATION_IDENTITY",
        "ENGINE_IDENTITY",
        "ENVIRONMENT_IDENTITY",
    }
    if (
        not authority_event.authority.authorized
        or authority_event.subject.scope != scope
        or authority_event.event_type != EventType.RUNTIME_OBSERVATION_RENEWED
        or authority_event.authority.actor_id != observer_id
        or authority_event.affected_object.object_id != previous_id
        or sequence != authority_event.sequence
    ):
        raise OmivInputError("unauthorized observation renewal")
    if not set(renewed).issubset(allowed_dimensions) or set(renewed).intersection(not_renewed):
        raise OmivInputError("renewal attempted dimension scope expansion")
    body = {
        "schema": "omiv.renewal-record.v1",
        "previous_observation_id": previous_id,
        "new_observation_id": new_id,
        "deployment_instance_id": instance_id,
        "observer_id": observer_id,
        "authority_event_id": authority_event.event_id,
        "policy_id": policy_id,
        "scope": scope.model_dump(mode="json", by_alias=True),
        "sequence": sequence,
        "renewed_dimensions": sorted(renewed),
        "dimensions_not_renewed": sorted(not_renewed),
        "evaluation_context_digest": context_digest,
        "limitations": ["Renewal applies only to explicitly renewed dimensions."],
    }
    return RenewalRecord.model_validate(
        identified(body, "renewal_id", "renewal_", "renewal_digest")
    )


def validate_renewal_chain(records: list[RenewalRecord]) -> list[RenewalRecord]:
    if len(records) > MAX_RENEWAL_CHAIN_DEPTH:
        raise OmivInputError("LIMIT_EXCEEDED:RENEWAL_CHAIN_DEPTH")
    by_previous: dict[str, RenewalRecord] = {}
    renewal_ids: set[str] = set()
    for record in records:
        if record.renewal_id in renewal_ids or record.previous_observation_id in by_previous:
            raise OmivInputError("duplicate or branching renewal chain")
        renewal_ids.add(record.renewal_id)
        by_previous[record.previous_observation_id] = record
    for start in by_previous:
        seen: set[str] = set()
        current = start
        while current in by_previous:
            if current in seen:
                raise OmivInputError("renewal chain cycle")
            seen.add(current)
            current = by_previous[current].new_observation_id
    return sorted(records, key=lambda record: (record.sequence, record.renewal_id))


def build_historical_result(
    request: HistoricalEvaluationRequest,
    snapshot: TrustSnapshot,
    events: list[HistoricalEvent],
    forks: list[TimelineFork],
    transition: TrustTransition | None = None,
) -> HistoricalEvaluationResult:
    if snapshot.cutoff != request.cutoff or snapshot.knowledge_mode != request.knowledge_mode:
        raise OmivInputError("snapshot historical cutoff or knowledge mode mismatch")
    if len(events) + len(forks) > MAX_REPORT_INPUTS:
        raise OmivInputError("LIMIT_EXCEEDED:HISTORICAL_RESULT_INPUTS")
    eligible = [
        event
        for event in events
        if event.available_at <= request.cutoff and event.sequence <= request.cutoff_sequence
    ]
    late = [event for event in events if event not in eligible]
    accepted = [e.event_id for e in eligible if e.authority.authorized]
    rejected = [e.event_id for e in eligible if not e.authority.authorized]
    body = {
        "schema": "omiv.historical-evaluation-result.v1",
        "request_id": request.request_id,
        "snapshot_id": snapshot.snapshot_id,
        "accepted_evidence_ids": sorted(accepted),
        "rejected_evidence_ids": sorted(rejected),
        "late_arriving_evidence_ids": sorted(e.event_id for e in late),
        "knowledge_mode": HistoricalKnowledgeMode.KNOWN_AS_OF_CUTOFF.value,
        "cutoff": request.cutoff,
        "revocation_event_ids": sorted(
            e.event_id
            for e in eligible
            if e.event_type == EventType.EVIDENCE_REVOKED and e.authority.authorized
        ),
        "superseded_object_ids": sorted(
            e.affected_object.object_id
            for e in eligible
            if e.event_type == EventType.EVIDENCE_SUPERSEDED
        ),
        "fork_ids": sorted(x.fork_id for x in forks),
        "transition_id": transition.transition_id if transition else None,
        "gaps": [x.model_dump(mode="json", by_alias=True) for x in snapshot.gaps],
        "limitations": [
            "Historical result reconstructs supplied evidence at the explicit cutoff only."
        ],
    }
    return HistoricalEvaluationResult.model_validate(
        identified(body, "result_id", "historical_eval_", "result_digest")
    )


def build_completeness(
    bundle: AuditBundleManifest,
    *,
    timeline_states: list[TimelineCompleteness] | None = None,
) -> AuditBundleCompleteness:
    schemas = {x.schema_id for x in bundle.members}
    required = {
        "omiv.trust-snapshot.v1",
        "omiv.trust-timeline.v1",
        "omiv.reevaluation-policy-set.v1",
    }
    missing = sorted(required - schemas)
    if timeline_states and any(state == TimelineCompleteness.FORKED for state in timeline_states):
        state = BundleCompletenessState.FORKED_HISTORY
        missing = ["non-forked-timeline"]
    elif timeline_states and any(
        state != TimelineCompleteness.COMPLETE_FOR_DECLARED_RANGE for state in timeline_states
    ):
        state = BundleCompletenessState.PARTIAL
        missing = ["complete-timeline-for-declared-range"]
    elif missing:
        state = BundleCompletenessState.MISSING_REQUIRED_MEMBER
    elif bundle.purpose == BundlePurpose.REGULATORY_EVIDENCE_EXPORT:
        state = BundleCompletenessState.PARTIAL
        missing = [
            "continuous-observation",
            "trusted-timestamp",
            "behavioral-evidence",
            "numerical-evidence",
        ]
    elif bundle.exclusions:
        state = BundleCompletenessState.COMPLETE_WITH_LIMITATIONS
    else:
        state = BundleCompletenessState.COMPLETE_FOR_PURPOSE
    body = {
        "schema": "omiv.audit-bundle-completeness.v1",
        "bundle_id": bundle.bundle_id,
        "purpose": bundle.purpose.value,
        "state": state.value,
        "satisfied_dimensions": sorted(schemas),
        "missing_dimensions": missing,
        "gaps": [x.model_dump(mode="json", by_alias=True) for x in bundle.exclusions],
        "limitations": ["Completeness is scoped to the declared bundle purpose and policy."],
    }
    return AuditBundleCompleteness.model_validate(
        identified(body, "completeness_id", "bundle_completeness_", "completeness_digest")
    )


def build_verification(
    bundle: AuditBundleManifest,
    completeness: AuditBundleCompleteness,
    snapshot_ids: list[str],
    timeline_ids: list[str],
) -> AuditBundleVerificationResult:
    if completeness.state == BundleCompletenessState.COMPLETE_FOR_PURPOSE:
        outcome = VerificationOutcome.VERIFIED
    elif completeness.state == BundleCompletenessState.COMPLETE_WITH_LIMITATIONS:
        outcome = VerificationOutcome.VERIFIED_WITH_LIMITATIONS
    elif completeness.state in {
        BundleCompletenessState.PARTIAL,
        BundleCompletenessState.MISSING_REQUIRED_MEMBER,
    }:
        outcome = VerificationOutcome.INCOMPLETE
    else:
        outcome = VerificationOutcome.FAILED
    body = {
        "schema": "omiv.audit-bundle-verification-result.v1",
        "bundle_id": bundle.bundle_id,
        "manifest_digest": bundle.manifest_digest,
        "outcome": outcome.value,
        "verified_member_ids": sorted(x.object_id for x in bundle.members),
        "rejected_member_ids": [],
        "completeness_id": completeness.completeness_id,
        "reconstructed_snapshot_ids": sorted(snapshot_ids),
        "reconstructed_timeline_ids": sorted(timeline_ids),
        "limitations": [
            "Offline verification establishes internal integrity, not independent truth "
            "of underlying claims."
        ],
    }
    return AuditBundleVerificationResult.model_validate(
        identified(body, "verification_id", "bundle_verification_", "verification_digest")
    )


def build_report(
    bundle: AuditBundleManifest,
    completeness: AuditBundleCompleteness,
    verification: AuditBundleVerificationResult,
    latest_snapshot: TrustSnapshot,
) -> AuditBundleReport:
    body = {
        "schema": "omiv.audit-bundle-report.v1",
        "bundle_id": bundle.bundle_id,
        "purpose": bundle.purpose.value,
        "evidence_range": (
            f"sequence {bundle.range_start_sequence} through {bundle.range_end_sequence}"
        ),
        "latest_supplied_snapshot_id": latest_snapshot.snapshot_id,
        "latest_snapshot_cutoff": latest_snapshot.cutoff,
        "knowledge_mode": latest_snapshot.knowledge_mode.value,
        "policy_set_id": latest_snapshot.policy_set_id,
        "policy_set_digest": latest_snapshot.policy_set_digest,
        "completeness": completeness.state.value,
        "verification": verification.outcome.value,
        "continuous_monitoring": "NOT_IMPLEMENTED",
        "continuous_observation": "NOT_ESTABLISHED",
        "trusted_timestamp": "NOT_AVAILABLE",
        "model_payload_included": False,
        "historical_records_modified": False,
        "revoked_records_retained": True,
        "outstanding_gaps": [x.category for x in bundle.exclusions],
        "limitations": [
            "Latest supplied snapshot is not necessarily current real-world state.",
            "Bundle completeness is for the declared purpose only.",
        ],
    }
    return AuditBundleReport.model_validate(
        identified(body, "report_id", "audit_report_", "report_digest")
    )


def build_adapters(
    snapshot: TrustSnapshot,
    transition: TrustTransition,
    timeline: TrustTimeline,
    bundle: AuditBundleManifest,
    completeness: AuditBundleCompleteness,
) -> tuple[PassportHistoricalSummary, CustodyHistoricalLinkage, GovernanceHistoricalAdapter]:
    dims = {x.dimension: x.state for x in snapshot.dimensions}
    pbody = {
        "schema": "omiv.passport-historical-summary.v1",
        "passport_id": "mp_synthetic-historical",
        "subject_id": snapshot.subject.subject_id,
        "latest_supplied_snapshot_id": snapshot.snapshot_id,
        "latest_snapshot_cutoff": snapshot.cutoff,
        "knowledge_mode": snapshot.knowledge_mode.value,
        "policy_set_id": snapshot.policy_set_id,
        "policy_set_digest": snapshot.policy_set_digest,
        "historical_snapshot_count": 2,
        "prior_states": [SnapshotState.TRUSTED_WITH_LIMITATIONS.value],
        "current_reconstructed_state": snapshot.overall_state.value,
        "revoked_object_ids": [],
        "superseded_object_ids": [],
        "stale_dimensions": [k for k, v in dims.items() if v == DimensionState.STALE],
        "audit_bundle_ids": [bundle.bundle_id],
        "continuous_observation": "NOT_ESTABLISHED",
        "trusted_timestamp": "NOT_AVAILABLE",
        "limitations": snapshot.limitations,
    }
    passport = PassportHistoricalSummary.model_validate(
        identified(pbody, "summary_id", "passport_history_", "summary_digest")
    )
    cbody = {
        "schema": "omiv.custody-historical-linkage.v1",
        "chain_id": "custody_synthetic-history",
        "subject_id": snapshot.subject.subject_id,
        "event_types": [
            "TRUST_SNAPSHOT_RECORDED",
            "TRUST_REEVALUATION_RECORDED",
            "AUDIT_BUNDLE_CREATED",
            "AUDIT_BUNDLE_VERIFIED",
        ],
        "snapshot_ids": [snapshot.snapshot_id],
        "timeline_id": timeline.timeline_id,
        "audit_bundle_ids": [bundle.bundle_id],
        "append_only": True,
        "limitations": [
            "Custody linkage records supplied historical evidence; it does not claim current trust."
        ],
    }
    custody = CustodyHistoricalLinkage.model_validate(
        identified(cbody, "linkage_id", "custody_history_", "linkage_digest")
    )
    gbody = {
        "schema": "omiv.governance-historical-adapter.v1",
        "subject_id": snapshot.subject.subject_id,
        "snapshot_id": snapshot.snapshot_id,
        "previous_snapshot_id": transition.previous_snapshot_id,
        "transition_id": transition.transition_id,
        "policy_set_id": snapshot.policy_set_id,
        "policy_set_digest": snapshot.policy_set_digest,
        "knowledge_mode": snapshot.knowledge_mode.value,
        "cutoff": snapshot.cutoff,
        "approval_state": dims["APPROVAL"].value,
        "security_state": dims["SECURITY_EVIDENCE"].value,
        "runtime_state": dims["RUNTIME_CONTINUITY"].value,
        "bundle_completeness": completeness.state.value,
        "outstanding_gaps": [x.category for x in snapshot.gaps],
        "source_limitations": snapshot.limitations,
    }
    governance = GovernanceHistoricalAdapter.model_validate(
        identified(gbody, "adapter_id", "governance_history_", "adapter_digest")
    )
    return passport, custody, governance
