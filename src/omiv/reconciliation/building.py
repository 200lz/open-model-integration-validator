"""Deterministic builders, factual comparison, and policy evaluation for Phase 6B."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.payload_integrity.models import ArtifactRole, CompletionState, ObservedPayloadManifest
from omiv.reconciliation.models import (
    IMMUTABLE_REVISION_KINDS,
    AuthorityOutcome,
    CollectionLimits,
    CollectionMode,
    CompletenessStatus,
    DigestKind,
    ExpectationScope,
    FindingKind,
    ListingCompleteness,
    NetworkUse,
    ObjectReference,
    ObservationLevel,
    PayloadDownloadPolicy,
    PayloadDownloadState,
    ProvenanceStrength,
    ProviderKind,
    ReconciliationFinding,
    ReconciliationOutcome,
    ReconciliationStatus,
    RemoteArtifactLocator,
    RemoteCollectionExecutionRecord,
    RemoteDigestDescriptor,
    RemoteExpectationMember,
    RemoteLocalIntegration,
    RemoteLocalReconciliationComparison,
    RemoteLocalReconciliationEvidence,
    RemoteLocalReconciliationPolicy,
    RemoteLocalReconciliationReport,
    RemoteMemberRecord,
    RemoteMemberRole,
    RemotePublisherAuthorityEvaluation,
    RemoteSnapshotExpectation,
    RemoteSnapshotManifest,
    RemoteSnapshotPlan,
    RequestedRevisionKind,
    ResolvedRevisionKind,
    SemanticTarget,
    ShardCompletenessAssessment,
    ShardTopology,
    StorageRepresentation,
    TopologyStatus,
    remote_member_set_digest,
)
from omiv.runtime.models import ProductSubject
from omiv.trust.models import OverallSignedObjectStatus, SignatureReport


def identified(
    body: dict[str, Any], id_field: str, prefix: str, digest_field: str
) -> dict[str, Any]:
    identity = prefix + canonical_sha256(body)[:32]
    with_id = {**body, id_field: identity}
    return {**with_id, digest_field: canonical_sha256(with_id)}


def digested(body: dict[str, Any], digest_field: str) -> dict[str, Any]:
    return {**body, digest_field: canonical_sha256(body)}


def reference(value: Any, id_field: str, digest_field: str) -> ObjectReference:
    return ObjectReference(
        schema_id=value.schema_id,
        object_id=getattr(value, id_field),
        object_digest=getattr(value, digest_field),
    )


def build_locator(
    subject: ProductSubject,
    *,
    provider_kind: ProviderKind,
    provider_instance: str,
    namespace: str,
    artifact_name: str,
    artifact_kind: str,
    requested_revision: str,
    requested_revision_kind: RequestedRevisionKind,
    trust_domain: str | None = None,
    limitations: Iterable[str] = (),
) -> RemoteArtifactLocator:
    body = {
        "schema": "omiv.remote-artifact-locator.v1",
        "provider_kind": provider_kind.value,
        "provider_instance": provider_instance,
        "namespace": namespace,
        "artifact_name": artifact_name,
        "artifact_kind": artifact_kind,
        "requested_revision": requested_revision,
        "requested_revision_kind": requested_revision_kind.value,
        "subject": subject.model_dump(mode="json", by_alias=True),
        "trust_domain": trust_domain or subject.scope.trust_domain,
        "limitations": [
            "Locator is a declaration and does not prove repository or revision existence.",
            *limitations,
        ],
    }
    return RemoteArtifactLocator.model_validate(
        identified(body, "locator_id", "remote_locator_", "locator_digest")
    )


def build_plan(
    locator: RemoteArtifactLocator,
    *,
    collection_mode: CollectionMode = CollectionMode.IMPORTED_OFFLINE_SNAPSHOT,
    adapter_id: str = "omiv.adapter.imported-snapshot",
    adapter_version: str = "version.v1",
    allowed_hosts: tuple[str, ...] = (),
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    limits: CollectionLimits | None = None,
) -> RemoteSnapshotPlan:
    body = {
        "schema": "omiv.remote-snapshot-plan.v1",
        "locator_id": locator.locator_id,
        "locator_digest": locator.locator_digest,
        "collection_mode": collection_mode.value,
        "requested_metadata_scope": ["member.names", "member.sizes", "typed.digest.metadata"],
        "payload_download_policy": PayloadDownloadPolicy.FORBIDDEN.value,
        "provider_adapter_id": adapter_id,
        "provider_adapter_version": adapter_version,
        "limits": (limits or CollectionLimits()).model_dump(mode="json"),
        "allowed_hosts": sorted(allowed_hosts),
        "redirect_policy": "ALLOWLIST_ONLY",
        "requested_digest_semantics": [kind.value for kind in DigestKind],
        "requested_available_at": available_at,
        "requested_observed_at": observed_at,
        "limitations": [
            "Collection is bounded and completeness is limited to its declared response or "
            "import scope.",
            "Payload download is forbidden.",
        ],
    }
    return RemoteSnapshotPlan.model_validate(
        identified(body, "plan_id", "remote_plan_", "plan_digest")
    )


def build_execution_record(
    plan: RemoteSnapshotPlan,
    locator: RemoteArtifactLocator,
    *,
    network_use: NetworkUse = NetworkUse.NONE,
    contacted_hosts: tuple[str, ...] = (),
    requested_urls: tuple[str, ...] = (),
    request_count: int = 0,
    response_count: int = 0,
    response_bytes: int = 0,
    redirect_hosts: tuple[str, ...] = (),
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    errors: tuple[str, ...] = (),
) -> RemoteCollectionExecutionRecord:
    if plan.locator_id != locator.locator_id or plan.locator_digest != locator.locator_digest:
        raise OmivInputError("plan does not bind the supplied locator")
    body = {
        "schema": "omiv.remote-collection-execution-record.v1",
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "locator_id": locator.locator_id,
        "locator_digest": locator.locator_digest,
        "collector_id": plan.provider_adapter_id,
        "collector_version": plan.provider_adapter_version,
        "collection_mode": plan.collection_mode.value,
        "effective_limits": plan.limits.model_dump(mode="json"),
        "network_use": network_use.value,
        "contacted_hosts": sorted(set(contacted_hosts)),
        "requested_urls": sorted(set(requested_urls)),
        "request_count": request_count,
        "response_count": response_count,
        "response_bytes": response_bytes,
        "redirect_hosts": sorted(set(redirect_hosts)),
        "payload_download": PayloadDownloadState.NOT_PERFORMED.value,
        "payload_bytes_downloaded": 0,
        "available_at": available_at,
        "observed_at": observed_at,
        "result_reference_status": "LINKED_DOWNSTREAM_BY_SNAPSHOT",
        "coverage_summary": "BOUNDED_DECLARED_SCOPE",
        "errors": list(errors),
        "limitations": [
            "Execution record does not contain a reverse reference to its resulting snapshot.",
            "Collector trust does not establish publisher authority or response correctness.",
        ],
    }
    return RemoteCollectionExecutionRecord.model_validate(
        identified(body, "execution_id", "remote_execution_", "execution_digest")
    )


def build_digest_descriptor(
    kind: DigestKind,
    value: str = "",
    *,
    evidence_source: str = "source.imported-metadata",
    observation_level: ObservationLevel = ObservationLevel.METADATA_ONLY,
    provenance_strength: ProvenanceStrength = ProvenanceStrength.IMPORTED_UNVERIFIED,
    payload_semantics_validated: bool = False,
    limitations: Iterable[str] = (),
) -> RemoteDigestDescriptor:
    semantic = {
        DigestKind.PAYLOAD_SHA256: ("SHA256", "PAYLOAD_BYTES", True),
        DigestKind.LFS_OID_SHA256: (
            "SHA256",
            "PAYLOAD_BYTES" if payload_semantics_validated else "UNKNOWN",
            payload_semantics_validated and observation_level == ObservationLevel.POINTER_OBSERVED,
        ),
        DigestKind.XET_DECLARED_PAYLOAD_SHA256: (
            "SHA256",
            "PAYLOAD_BYTES" if payload_semantics_validated else "UNKNOWN",
            payload_semantics_validated
            and observation_level == ObservationLevel.PAYLOAD_DIGEST_DECLARED,
        ),
        DigestKind.XET_OBJECT_ID: ("PROVIDER_OPAQUE", "PROVIDER_OBJECT", False),
        DigestKind.GIT_BLOB_SHA1: ("SHA1", "GIT_OBJECT", False),
        DigestKind.GIT_BLOB_SHA256: ("SHA256", "GIT_OBJECT", False),
        DigestKind.OCI_CONTENT_DIGEST: ("DECLARED", "CONTAINER_CONTENT", False),
        DigestKind.HTTP_ETAG: ("OPAQUE", "UNKNOWN", False),
        DigestKind.PROVIDER_OPAQUE_ID: ("OPAQUE", "UNKNOWN", False),
        DigestKind.UNAVAILABLE: ("UNAVAILABLE", "UNKNOWN", False),
    }[kind]
    return RemoteDigestDescriptor(
        kind=kind,
        algorithm=semantic[0],
        canonical_value=value,
        semantic_target=SemanticTarget(semantic[1]),
        evidence_source=evidence_source,
        observation_level=observation_level,
        provenance_strength=provenance_strength,
        payload_comparable=semantic[2],
        limitations=tuple(limitations),
    )


def build_member(
    path: str,
    *,
    role: RemoteMemberRole,
    logical_size: int | None,
    digests: Iterable[RemoteDigestDescriptor] = (),
    storage_representation: StorageRepresentation = StorageRepresentation.UNKNOWN,
    observation_level: ObservationLevel = ObservationLevel.METADATA_ONLY,
    provenance_strength: ProvenanceStrength = ProvenanceStrength.IMPORTED_UNVERIFIED,
    member_provenance: str = "source.imported-metadata",
    available_at: str = "NOT_RECORDED",
    limitations: Iterable[str] = (),
) -> RemoteMemberRecord:
    ordered_digests = sorted(digests, key=lambda x: x.kind.value)
    body: dict[str, Any] = {
        "schema": "omiv.remote-member-record.v1",
        "path": path,
        "role": role.value,
        "logical_size": logical_size,
        "digests": [item.model_dump(mode="json", by_alias=True) for item in ordered_digests],
        "storage_representation": storage_representation.value,
        "observation_level": observation_level.value,
        "provenance_strength": provenance_strength.value,
        "member_provenance": member_provenance,
        "available_at": available_at,
        "limitations": list(limitations),
    }
    return RemoteMemberRecord.model_validate(
        identified(body, "member_id", "remote_member_", "member_digest")
    )


def build_snapshot(
    locator: RemoteArtifactLocator,
    plan: RemoteSnapshotPlan,
    execution: RemoteCollectionExecutionRecord,
    members: Iterable[RemoteMemberRecord],
    *,
    resolved_revision: str,
    resolved_revision_kind: ResolvedRevisionKind,
    listing_completeness: ListingCompleteness,
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
    provenance_strength: ProvenanceStrength = ProvenanceStrength.IMPORTED_UNVERIFIED,
    unavailable_members: tuple[str, ...] = (),
    unsupported_members: tuple[str, ...] = (),
    errors: tuple[str, ...] = (),
    limitations: Iterable[str] = (),
) -> RemoteSnapshotManifest:
    if (plan.locator_id, plan.locator_digest) != (locator.locator_id, locator.locator_digest):
        raise OmivInputError("snapshot plan does not bind locator")
    if (execution.plan_id, execution.plan_digest) != (plan.plan_id, plan.plan_digest):
        raise OmivInputError("execution does not bind plan")
    ordered = tuple(sorted(members, key=lambda x: x.path.encode()))
    body: dict[str, Any] = {
        "schema": "omiv.remote-snapshot-manifest.v1",
        "locator_id": locator.locator_id,
        "locator_digest": locator.locator_digest,
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "execution_id": execution.execution_id,
        "execution_digest": execution.execution_digest,
        "requested_revision": locator.requested_revision,
        "resolved_revision": resolved_revision,
        "resolved_revision_kind": resolved_revision_kind.value,
        "revision_resolution_evidence": "EXPLICITLY_SUPPLIED_BY_COLLECTION_OR_IMPORT",
        "subject": locator.subject.model_dump(mode="json", by_alias=True),
        "provider_kind": locator.provider_kind.value,
        "provider_instance": locator.provider_instance,
        "namespace": locator.namespace,
        "artifact_name": locator.artifact_name,
        "members": [x.model_dump(mode="json", by_alias=True) for x in ordered],
        "member_set_digest": remote_member_set_digest(ordered),
        "observation_coverage": "DECLARED_IMPORT_OR_RESPONSE_SCOPE_ONLY",
        "provider_listing_completeness": listing_completeness.value,
        "unavailable_members": sorted(unavailable_members),
        "unsupported_members": sorted(unsupported_members),
        "errors": list(errors),
        "available_at": available_at,
        "observed_at": observed_at,
        "provenance_strength": provenance_strength.value,
        "limitations": [
            "Remote listing completeness is limited to the declared response or import scope.",
            "Snapshot observation does not establish publisher authority, authenticity, or "
            "current state.",
            *limitations,
        ],
    }
    if resolved_revision_kind not in IMMUTABLE_REVISION_KINDS:
        body["limitations"].append(
            "Resolved revision is mutable, unresolved, or opaque and cannot establish "
            "reproducible snapshot identity."
        )
    return RemoteSnapshotManifest.model_validate(
        identified(body, "manifest_id", "remote_snapshot_", "manifest_digest")
    )


def assess_completeness(
    topology: ShardTopology,
    snapshot: RemoteSnapshotManifest,
    local_manifest: ObservedPayloadManifest | None = None,
) -> ShardCompletenessAssessment:
    if (topology.snapshot_id, topology.snapshot_digest) != (
        snapshot.manifest_id,
        snapshot.manifest_digest,
    ):
        raise OmivInputError("topology does not bind snapshot")
    remote_paths = {member.path for member in snapshot.members}
    local_paths = {member.path for member in local_manifest.files} if local_manifest else set()
    required = set(topology.required_shards) | set(topology.companion_artifacts)
    missing_remote = sorted(required - remote_paths)
    missing_local = sorted(required - local_paths) if local_manifest else []
    missing_remote_shards = set(topology.required_shards) - remote_paths
    remote_records = {member.path: member for member in snapshot.members}
    local_records = (
        {member.path: member for member in local_manifest.files} if local_manifest else {}
    )
    comparable_paths = {
        path
        for path in required & remote_paths
        if any(item.payload_comparable for item in remote_records[path].digests)
    }
    matching_paths = {
        path
        for path in comparable_paths & local_paths
        if any(
            descriptor.payload_comparable
            and descriptor.canonical_value == local_records[path].primary_content_digest.value
            for descriptor in remote_records[path].digests
        )
    }
    if topology.status == TopologyStatus.LIMIT_EXCEEDED:
        status = CompletenessStatus.LIMIT_EXCEEDED
    elif topology.status == TopologyStatus.CONFLICTING_INDEXES:
        status = CompletenessStatus.CONFLICTING_INDEXES
    elif topology.status == TopologyStatus.HEURISTIC_ONLY:
        status = CompletenessStatus.HEURISTIC_ONLY
    elif topology.status == TopologyStatus.TOPOLOGY_UNAVAILABLE:
        status = CompletenessStatus.TOPOLOGY_UNAVAILABLE
    elif missing_remote_shards:
        status = CompletenessStatus.INDEX_REFERENCES_MISSING_MEMBER
    elif missing_remote:
        status = CompletenessStatus.INCOMPLETE_REMOTE_MEMBERS
    elif local_manifest is not None and missing_local:
        status = CompletenessStatus.INCOMPLETE_LOCAL_MEMBERS
    else:
        status = CompletenessStatus.COMPLETE_FOR_EXPLICIT_TOPOLOGY_SCOPE
    body = {
        "schema": "omiv.shard-completeness-assessment.v1",
        "topology_id": topology.topology_id,
        "topology_digest": topology.topology_digest,
        "snapshot_id": snapshot.manifest_id,
        "snapshot_digest": snapshot.manifest_digest,
        "local_manifest_id": local_manifest.manifest_id if local_manifest else None,
        "local_manifest_digest": local_manifest.manifest_digest if local_manifest else None,
        "index_declaration_coverage": topology.coverage,
        "remote_member_presence": "COMPLETE" if not missing_remote else "INCOMPLETE",
        "local_member_presence": (
            "NOT_EVALUATED"
            if local_manifest is None
            else "COMPLETE"
            if not missing_local
            else "INCOMPLETE"
        ),
        "digest_comparability": (
            "ALL_REQUIRED_MEMBERS"
            if comparable_paths == required
            else "PARTIAL"
            if comparable_paths
            else "NONE"
        ),
        "local_byte_match": (
            "NOT_EVALUATED"
            if local_manifest is None
            else "ALL_COMPARABLE_MATCH"
            if matching_paths == comparable_paths and comparable_paths
            else "MISMATCH_OR_INCOMPLETE"
        ),
        "mandatory_companion_coverage": (
            "COMPLETE" if not (set(topology.companion_artifacts) - remote_paths) else "INCOMPLETE"
        ),
        "missing_remote_members": missing_remote,
        "missing_local_members": missing_local,
        "status": status.value,
        "limitations": [
            "Completeness is qualified by explicit topology scope and does not establish "
            "tensor-semantic completeness."
        ],
    }
    return ShardCompletenessAssessment.model_validate(
        identified(body, "assessment_id", "shard_assessment_", "assessment_digest")
    )


def build_expectation(
    snapshot: RemoteSnapshotManifest,
    *,
    expectation_scope: ExpectationScope,
    logical_root: str = "artifact.root",
    selected_paths: Iterable[str] | None = None,
    required_roles: Iterable[RemoteMemberRole] = (),
    authority: RemotePublisherAuthorityEvaluation | None = None,
) -> RemoteSnapshotExpectation:
    paths = (
        set(selected_paths) if selected_paths is not None else {x.path for x in snapshot.members}
    )
    selected: list[RemoteExpectationMember] = []
    for member in snapshot.members:
        if member.path not in paths:
            continue
        comparable = next((item for item in member.digests if item.payload_comparable), None)
        selected.append(
            RemoteExpectationMember(
                path=member.path,
                role=member.role,
                logical_size=member.logical_size,
                comparable_digest=comparable,
                remote_member_id=member.member_id,
                remote_member_digest=member.member_digest,
            )
        )
    if paths != {x.path for x in selected}:
        raise OmivInputError("selected expectation path is absent from remote snapshot")
    body = {
        "schema": "omiv.remote-snapshot-expectation.v1",
        "snapshot_id": snapshot.manifest_id,
        "snapshot_digest": snapshot.manifest_digest,
        "subject": snapshot.subject.model_dump(mode="json", by_alias=True),
        "logical_root": logical_root,
        "resolved_revision": snapshot.resolved_revision,
        "resolved_revision_kind": snapshot.resolved_revision_kind.value,
        "remote_listing_completeness": snapshot.provider_listing_completeness.value,
        "remote_unavailable_members": snapshot.unavailable_members,
        "expectation_scope": expectation_scope.value,
        "selected_members": [x.model_dump(mode="json", by_alias=True) for x in selected],
        "required_roles": sorted({x.value for x in required_roles}),
        # Authority is evaluated downstream to preserve an acyclic graph.
        "publisher_authority_evaluation_id": None,
        "publisher_authority_evaluation_digest": None,
        "available_at": snapshot.available_at,
        "provenance_strength": snapshot.provenance_strength.value,
        "limitations": [
            "Remote observation becomes an expectation only for the explicitly selected scope.",
            "Opaque or metadata-only digests do not create a local byte expectation.",
            "Publisher authority remains a separate downstream evaluation.",
        ],
    }
    if authority is not None:
        raise OmivInputError("authority must evaluate the finalized expectation downstream")
    return RemoteSnapshotExpectation.model_validate(
        identified(body, "expectation_id", "remote_expectation_", "expectation_digest")
    )


def build_authority_evaluation(
    expectation: RemoteSnapshotExpectation,
    trust_report: SignatureReport,
    *,
    provider_instance: str,
    namespace: str,
    authorized: bool,
) -> RemotePublisherAuthorityEvaluation:
    if (
        trust_report.signed_object_id != expectation.expectation_id
        or trust_report.signed_object_digest
        != canonical_sha256(expectation.model_dump(mode="json", by_alias=True))
        or not trust_report.signature_results
    ):
        raise OmivInputError("trust report does not bind the exact remote expectation")
    trusted = (
        trust_report.overall_status == OverallSignedObjectStatus.TRUSTED_SIGNATURE_WITH_LIMITATIONS
    )
    if authorized and not trusted:
        raise OmivInputError("publisher authorization requires a trusted exact-object signature")
    signature = trust_report.signature_results[0]
    body = {
        "schema": "omiv.remote-publisher-authority-evaluation.v1",
        "expectation_id": expectation.expectation_id,
        "expectation_digest": expectation.expectation_digest,
        "trust_report_id": trust_report.report_id,
        "trust_report_digest": trust_report.report_digest,
        "subject": expectation.subject.model_dump(mode="json", by_alias=True),
        "provider_instance": provider_instance,
        "namespace": namespace,
        "resolved_revision": expectation.resolved_revision,
        "purpose": "remote.snapshot-expectation",
        "scope": expectation.subject.scope.model_dump(mode="json"),
        "expectation_scope": expectation.expectation_scope.value,
        "signer_id": signature.signer_identity_id or "signer.identity-unavailable",
        "key_id": signature.key_id,
        "signer_binding_status": (
            signature.signer_binding_status.value
            if signature.signer_binding_status
            else "NOT_EVALUATED"
        ),
        "validity_context": signature.expiration_status.value,
        "delegation_context": signature.delegation_status.value,
        "revocation_context": signature.revocation_status.value,
        "authority_outcome": (
            AuthorityOutcome.AUTHORIZED_PUBLISHER.value
            if authorized
            else AuthorityOutcome.UNAUTHORIZED.value
        ),
        "limitations": [
            "Authority is scoped to the exact expectation, subject, provider, namespace, "
            "revision, purpose, and trust domain.",
            "A trusted collector signature is not publisher authority unless explicitly "
            "authorized here.",
        ],
    }
    return RemotePublisherAuthorityEvaluation.model_validate(
        identified(
            body,
            "authority_evaluation_id",
            "remote_authority_",
            "authority_evaluation_digest",
        )
    )


def build_policy(
    policy_id: str,
    subject: ProductSubject,
    *,
    allowed_providers: Iterable[ProviderKind] = tuple(ProviderKind),
    require_publisher_authority: bool = False,
) -> RemoteLocalReconciliationPolicy:
    body = {
        "schema": "omiv.remote-local-reconciliation-policy.v1",
        "policy_id": policy_id,
        "scope": subject.scope.model_dump(mode="json"),
        "allowed_providers": sorted({x.value for x in allowed_providers}),
        "require_immutable_revision": True,
        "accepted_expectation_scopes": [
            ExpectationScope.COMPLETE_REMOTE_MEMBER_SET.value,
            ExpectationScope.EXPLICIT_SHARD_SET.value,
            ExpectationScope.SELECTED_REQUIRED_MEMBERS.value,
        ],
        "accepted_topology_sources": [
            "EXPLICIT_INDEX",
            "EXPLICIT_PROVIDER_MANIFEST",
            "EXPLICIT_USER_DECLARATION",
        ],
        "accepted_remote_listing_coverage": [
            ListingCompleteness.COMPLETE_FOR_DECLARED_RESPONSE_SCOPE.value
        ],
        "accepted_local_coverage": [CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE.value],
        "accepted_digest_semantics": [
            DigestKind.PAYLOAD_SHA256.value,
            DigestKind.LFS_OID_SHA256.value,
            DigestKind.XET_DECLARED_PAYLOAD_SHA256.value,
        ],
        "require_publisher_authority": require_publisher_authority,
        "allow_extra_members": False,
        "allow_missing_members": False,
        "require_shard_completeness": True,
        "require_mandatory_companions": True,
        "available_at_required": False,
        "limitations": [
            "Policy decides sufficiency; it cannot alter factual comparison findings or "
            "strengthen evidence."
        ],
    }
    return RemoteLocalReconciliationPolicy.model_validate(digested(body, "policy_digest"))


_ROLE_EQUIVALENCE = {
    RemoteMemberRole.PRIMARY_SHARD: ArtifactRole.PRIMARY,
    RemoteMemberRole.MANDATORY_COMPANION: ArtifactRole.MANDATORY_COMPANION,
    RemoteMemberRole.OPTIONAL_COMPANION: ArtifactRole.OPTIONAL_COMPANION,
}


def compare_remote_to_local(
    expectation: RemoteSnapshotExpectation,
    local: ObservedPayloadManifest,
    *,
    authority: RemotePublisherAuthorityEvaluation | None = None,
) -> RemoteLocalReconciliationComparison:
    if expectation.subject != local.subject:
        raise OmivInputError("remote expectation and local manifest subjects differ")
    if expectation.logical_root != local.logical_root:
        raise OmivInputError("remote expectation and local manifest logical roots differ")
    expected = {x.path: x for x in expectation.selected_members}
    observed = {x.path: x for x in local.files}
    findings: list[ReconciliationFinding] = []
    matching: list[str] = []
    comparable: list[str] = []
    digest_matches: list[str] = []
    mismatch = False
    for path in sorted(expected.keys() | observed.keys(), key=lambda x: x.encode()):
        remote = expected.get(path)
        local_record = observed.get(path)
        kinds: list[FindingKind] = []
        if remote is None:
            kinds.append(
                FindingKind.PATH_EXTRA_LOCAL
                if expectation.expectation_scope == ExpectationScope.COMPLETE_REMOTE_MEMBER_SET
                else FindingKind.PATH_OUTSIDE_EXPECTATION_SCOPE
            )
            mismatch |= expectation.expectation_scope == ExpectationScope.COMPLETE_REMOTE_MEMBER_SET
        elif local_record is None:
            kinds.append(FindingKind.PATH_MISSING_LOCAL)
            mismatch = True
        else:
            kinds.append(FindingKind.PATH_MATCH)
            if remote.logical_size is None:
                pass
            elif remote.logical_size == local_record.size:
                kinds.append(FindingKind.SIZE_MATCH)
            else:
                kinds.append(FindingKind.SIZE_MISMATCH)
                mismatch = True
            expected_role = _ROLE_EQUIVALENCE.get(remote.role)
            if expected_role is None:
                kinds.append(FindingKind.ROLE_MISMATCH)
            elif expected_role == local_record.artifact_role:
                kinds.append(FindingKind.ROLE_MATCH)
            else:
                kinds.append(FindingKind.ROLE_MISMATCH)
                mismatch = True
            if remote.comparable_digest is None:
                kinds.append(FindingKind.DIGEST_NOT_COMPARABLE)
            else:
                comparable.append(path)
                if (
                    remote.comparable_digest.canonical_value
                    == local_record.primary_content_digest.value
                ):
                    kinds.append(FindingKind.DIGEST_MATCH)
                    digest_matches.append(path)
                else:
                    kinds.append(FindingKind.DIGEST_MISMATCH)
                    mismatch = True
            if not any(
                item in kinds
                for item in (
                    FindingKind.SIZE_MISMATCH,
                    FindingKind.DIGEST_MISMATCH,
                    FindingKind.ROLE_MISMATCH,
                )
            ):
                matching.append(path)
        findings.append(
            ReconciliationFinding(
                path=path,
                findings=tuple(kinds),
                remote_size=remote.logical_size if remote else None,
                local_size=local_record.size if local_record else None,
                remote_digest_kind=(
                    remote.comparable_digest.kind if remote and remote.comparable_digest else None
                ),
                remote_digest=(
                    remote.comparable_digest.canonical_value
                    if remote and remote.comparable_digest
                    else None
                ),
                local_payload_sha256=(
                    local_record.primary_content_digest.value if local_record else None
                ),
            )
        )
    missing = sorted(expected.keys() - observed.keys())
    extra = sorted(observed.keys() - expected.keys())
    authorized = (
        authority is not None
        and authority.authority_outcome == AuthorityOutcome.AUTHORIZED_PUBLISHER
    )
    if (
        expectation.remote_listing_completeness
        != ListingCompleteness.COMPLETE_FOR_DECLARED_RESPONSE_SCOPE
        or expectation.remote_unavailable_members
    ):
        status = ReconciliationStatus.INCOMPLETE_REMOTE_EVIDENCE
    elif local.completion_state != CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE:
        status = ReconciliationStatus.INCOMPLETE_LOCAL_OBSERVATION
        for finding in findings:
            if FindingKind.LOCAL_OBSERVATION_INCOMPLETE not in finding.findings:
                pass
    elif expectation.resolved_revision_kind not in IMMUTABLE_REVISION_KINDS:
        status = ReconciliationStatus.MUTABLE_OR_UNRESOLVED_REVISION
    elif mismatch:
        status = ReconciliationStatus.MISMATCH
    elif not comparable:
        status = ReconciliationStatus.MEMBER_SET_MATCH_DIGESTS_UNAVAILABLE
    elif len(comparable) != len(expected):
        status = ReconciliationStatus.METADATA_MATCH_ONLY
    elif authority is not None and not authorized:
        status = ReconciliationStatus.EXPECTATION_UNAUTHORIZED
    else:
        status = ReconciliationStatus.EXACT_MATCH_FOR_RECONCILIATION_SCOPE
    if local.completion_state != CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE:
        findings = [
            item.model_copy(
                update={
                    "findings": tuple(
                        dict.fromkeys((*item.findings, FindingKind.LOCAL_OBSERVATION_INCOMPLETE))
                    )
                }
            )
            for item in findings
        ]
    body = {
        "schema": "omiv.remote-local-reconciliation-comparison.v1",
        "expectation_id": expectation.expectation_id,
        "expectation_digest": expectation.expectation_digest,
        "local_manifest_id": local.manifest_id,
        "local_manifest_digest": local.manifest_digest,
        "subject_id": expectation.subject.subject_id,
        "subject_scope_digest": canonical_sha256(expectation.subject.scope.model_dump(mode="json")),
        "logical_root": local.logical_root,
        "expectation_scope": expectation.expectation_scope.value,
        "findings": [x.model_dump(mode="json") for x in findings],
        "matching_members": matching,
        "missing_local_members": missing,
        "extra_local_members": extra,
        "digest_comparable_members": comparable,
        "digest_matching_members": digest_matches,
        "status": status.value,
        "limitations": [
            "Comparison is factual; policy allowances do not remove findings.",
            "Exact local reconciliation does not establish authenticity, safety, semantic "
            "correctness, or runtime identity.",
        ],
    }
    return RemoteLocalReconciliationComparison.model_validate(
        identified(body, "comparison_id", "remote_local_comparison_", "comparison_digest")
    )


def evaluate_reconciliation(
    *,
    locator: RemoteArtifactLocator,
    plan: RemoteSnapshotPlan,
    execution: RemoteCollectionExecutionRecord,
    snapshot: RemoteSnapshotManifest,
    topology: ShardTopology,
    completeness: ShardCompletenessAssessment,
    expectation: RemoteSnapshotExpectation,
    local: ObservedPayloadManifest,
    comparison: RemoteLocalReconciliationComparison,
    policy: RemoteLocalReconciliationPolicy,
    authority: RemotePublisherAuthorityEvaluation | None = None,
    evaluated_at: str = "NOT_RECORDED",
) -> RemoteLocalReconciliationEvidence:
    refs = (
        (snapshot.locator_id, snapshot.locator_digest, locator.locator_id, locator.locator_digest),
        (snapshot.plan_id, snapshot.plan_digest, plan.plan_id, plan.plan_digest),
        (
            snapshot.execution_id,
            snapshot.execution_digest,
            execution.execution_id,
            execution.execution_digest,
        ),
        (
            topology.snapshot_id,
            topology.snapshot_digest,
            snapshot.manifest_id,
            snapshot.manifest_digest,
        ),
        (
            expectation.snapshot_id,
            expectation.snapshot_digest,
            snapshot.manifest_id,
            snapshot.manifest_digest,
        ),
        (
            comparison.expectation_id,
            comparison.expectation_digest,
            expectation.expectation_id,
            expectation.expectation_digest,
        ),
        (
            comparison.local_manifest_id,
            comparison.local_manifest_digest,
            local.manifest_id,
            local.manifest_digest,
        ),
    )
    if any((a, b) != (c, d) for a, b, c, d in refs):
        raise OmivInputError("reconciliation dependency graph contains a mismatched reference")
    if (
        completeness.topology_id,
        completeness.topology_digest,
        completeness.snapshot_id,
        completeness.snapshot_digest,
    ) != (
        topology.topology_id,
        topology.topology_digest,
        snapshot.manifest_id,
        snapshot.manifest_digest,
    ):
        raise OmivInputError("completeness assessment does not bind topology and snapshot")
    authorized = (
        authority is not None
        and authority.authority_outcome == AuthorityOutcome.AUTHORIZED_PUBLISHER
    )
    if authority is not None and (
        authority.expectation_id != expectation.expectation_id
        or authority.expectation_digest != expectation.expectation_digest
        or authority.subject != expectation.subject
        or authority.provider_instance != locator.provider_instance
        or authority.namespace != locator.namespace
        or authority.resolved_revision != expectation.resolved_revision
        or authority.scope != expectation.subject.scope
    ):
        raise OmivInputError("publisher authority does not match the exact expectation scope")
    digest_kinds = {
        member.comparable_digest.kind
        for member in expectation.selected_members
        if member.comparable_digest is not None
    }
    satisfied = (
        locator.provider_kind in policy.allowed_providers
        and policy.scope == expectation.subject.scope
        and (
            not policy.require_immutable_revision
            or snapshot.resolved_revision_kind in IMMUTABLE_REVISION_KINDS
        )
        and expectation.expectation_scope in policy.accepted_expectation_scopes
        and topology.topology_source in policy.accepted_topology_sources
        and snapshot.provider_listing_completeness in policy.accepted_remote_listing_coverage
        and local.completion_state in policy.accepted_local_coverage
        and digest_kinds <= set(policy.accepted_digest_semantics)
        and (not policy.require_publisher_authority or authorized)
        and (policy.allow_extra_members or not comparison.extra_local_members)
        and (policy.allow_missing_members or not comparison.missing_local_members)
        and (
            not policy.require_shard_completeness
            or completeness.status == CompletenessStatus.COMPLETE_FOR_EXPLICIT_TOPOLOGY_SCOPE
        )
        and comparison.status == ReconciliationStatus.EXACT_MATCH_FOR_RECONCILIATION_SCOPE
    )
    if comparison.status == ReconciliationStatus.EXACT_MATCH_FOR_RECONCILIATION_SCOPE:
        outcome = (
            ReconciliationOutcome.LOCAL_BYTES_MATCH_AUTHORIZED_PINNED_EXPECTATION
            if authorized
            else ReconciliationOutcome.LOCAL_BYTES_MATCH_COMPARABLE_REMOTE_EXPECTATION
        )
    elif comparison.status == ReconciliationStatus.MISMATCH:
        outcome = ReconciliationOutcome.MISMATCH
    elif comparison.status == ReconciliationStatus.MUTABLE_OR_UNRESOLVED_REVISION:
        outcome = ReconciliationOutcome.MUTABLE_REVISION
    elif comparison.status == ReconciliationStatus.EXPECTATION_UNAUTHORIZED:
        outcome = ReconciliationOutcome.EXPECTATION_UNAUTHORIZED
    elif comparison.status in {
        ReconciliationStatus.MEMBER_SET_MATCH_DIGESTS_UNAVAILABLE,
        ReconciliationStatus.NOT_COMPARABLE,
    }:
        outcome = ReconciliationOutcome.NOT_COMPARABLE
    elif comparison.status == ReconciliationStatus.METADATA_MATCH_ONLY:
        outcome = ReconciliationOutcome.METADATA_MATCHES
    else:
        outcome = ReconciliationOutcome.INCOMPLETE
    body = {
        "schema": "omiv.remote-local-reconciliation-evidence.v1",
        "subject": expectation.subject.model_dump(mode="json", by_alias=True),
        "locator": reference(locator, "locator_id", "locator_digest").model_dump(mode="json"),
        "plan": reference(plan, "plan_id", "plan_digest").model_dump(mode="json"),
        "execution": reference(execution, "execution_id", "execution_digest").model_dump(
            mode="json"
        ),
        "snapshot": reference(snapshot, "manifest_id", "manifest_digest").model_dump(mode="json"),
        "topology": reference(topology, "topology_id", "topology_digest").model_dump(mode="json"),
        "completeness_assessment": reference(
            completeness, "assessment_id", "assessment_digest"
        ).model_dump(mode="json"),
        "expectation": reference(expectation, "expectation_id", "expectation_digest").model_dump(
            mode="json"
        ),
        "publisher_authority": (
            reference(
                authority, "authority_evaluation_id", "authority_evaluation_digest"
            ).model_dump(mode="json")
            if authority
            else None
        ),
        "local_manifest": reference(local, "manifest_id", "manifest_digest").model_dump(
            mode="json"
        ),
        "comparison": reference(comparison, "comparison_id", "comparison_digest").model_dump(
            mode="json"
        ),
        "policy": ObjectReference(
            schema_id=policy.schema_id,
            object_id=policy.policy_id,
            object_digest=policy.policy_digest,
        ).model_dump(mode="json"),
        "outcome": outcome.value,
        "policy_satisfied": satisfied,
        "available_at": snapshot.available_at,
        "observed_at": snapshot.observed_at,
        "evaluated_at": evaluated_at,
        "limitations": [
            "Evidence binds exact inputs but does not establish authenticity, semantic "
            "correctness, safety, or runtime identity."
        ],
    }
    return RemoteLocalReconciliationEvidence.model_validate(
        identified(body, "evidence_id", "remote_local_evidence_", "evidence_digest")
    )


def build_report(
    evidence: RemoteLocalReconciliationEvidence,
    comparison: RemoteLocalReconciliationComparison,
    topology: ShardTopology,
    completeness: ShardCompletenessAssessment,
    execution: RemoteCollectionExecutionRecord,
    authority: RemotePublisherAuthorityEvaluation | None = None,
) -> RemoteLocalReconciliationReport:
    body = {
        "schema": "omiv.remote-local-reconciliation-report.v1",
        "evidence": evidence.model_dump(mode="json", by_alias=True),
        "comparison": comparison.model_dump(mode="json", by_alias=True),
        "topology_status": topology.status.value,
        "completeness_status": completeness.status.value,
        "publisher_authority": (
            authority.authority_outcome.value if authority else AuthorityOutcome.NOT_EVALUATED.value
        ),
        "network_use": execution.network_use.value,
        "payload_download": execution.payload_download.value,
        "model_authenticity": "NOT_ESTABLISHED",
        "model_semantic_correctness": "NOT_EVALUATED",
        "model_safety": "NOT_VERIFIED",
        "runtime_identity": "NOT_OBSERVED",
        "limitations": [
            "Report derives only from bound evidence and is not itself an evidence source."
        ],
    }
    return RemoteLocalReconciliationReport.model_validate(
        identified(body, "report_id", "remote_local_report_", "report_digest")
    )


def build_integration(
    evidence: RemoteLocalReconciliationEvidence,
    integration_type: str,
    *,
    source_object: ObjectReference | None = None,
) -> RemoteLocalIntegration:
    status = {
        "PASSPORT": "DERIVED_RECONCILIATION_SUMMARY_ONLY",
        "CUSTODY": "APPEND_ONLY_EVENT_INPUT",
        "GOVERNANCE": "EVIDENCE_STATE_ONLY_NO_APPROVAL",
        "SECURITY": "EXACT_LOCAL_PAYLOAD_BINDING_REQUIRED_NO_PASS",
        "RUNTIME": "EXPECTED_IDENTITY_ONLY",
        "HISTORICAL": "TIME_SCOPED_EVIDENCE_ONLY",
        "AUDIT": "FUTURE_TYPED_BUNDLE_MEMBER",
    }.get(integration_type)
    if status is None:
        raise OmivInputError("unsupported reconciliation integration type")
    body = {
        "schema": "omiv.remote-local-integration.v1",
        "integration_type": integration_type,
        "reconciliation_evidence_id": evidence.evidence_id,
        "reconciliation_evidence_digest": evidence.evidence_digest,
        "source_object": source_object.model_dump(mode="json") if source_object else None,
        "derived_status": status,
        "accepted": False,
        "creates_approval": False,
        "creates_security_pass": False,
        "observed_runtime_identity": False,
        "mutates_prior_artifact": False,
        "available_at": evidence.available_at,
        "limitations": ["Adapter cannot strengthen provenance, authority, completeness, or trust."],
    }
    return RemoteLocalIntegration.model_validate(
        identified(body, "integration_id", "remote_local_integration_", "integration_digest")
    )
