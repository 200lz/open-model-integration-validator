"""Strict canonical models for provider-neutral Phase 6B reconciliation."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, StringConstraints, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.models import CompletionState, ObservedPayloadManifest
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.runtime.models import ProductSubject, ScopeContext

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
REVISION_PATTERN = r"^[^\x00-\x1f\x7f]{1,512}$"
MAX_MEMBERS = 100_000
MAX_INDEX_MAPPINGS = 500_000
MAX_FINDINGS = 200_000
ExplicitTime = Annotated[
    str,
    StringConstraints(
        pattern=r"^(NOT_RECORDED|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$"
    ),
]


class ReconciliationModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class ProviderKind(StrEnum):
    HUGGING_FACE = "HUGGING_FACE"
    GIT_REPOSITORY = "GIT_REPOSITORY"
    OCI_REGISTRY = "OCI_REGISTRY"
    PRIVATE_REGISTRY = "PRIVATE_REGISTRY"
    IMPORTED_SNAPSHOT = "IMPORTED_SNAPSHOT"
    OTHER_DECLARED = "OTHER_DECLARED"


class RequestedRevisionKind(StrEnum):
    BRANCH = "BRANCH"
    TAG = "TAG"
    COMMIT = "COMMIT"
    CONTENT_DIGEST = "CONTENT_DIGEST"
    PROVIDER_SNAPSHOT = "PROVIDER_SNAPSHOT"
    OTHER_DECLARED = "OTHER_DECLARED"


class ResolvedRevisionKind(StrEnum):
    IMMUTABLE_COMMIT = "IMMUTABLE_COMMIT"
    IMMUTABLE_CONTENT_DIGEST = "IMMUTABLE_CONTENT_DIGEST"
    PROVIDER_IMMUTABLE_SNAPSHOT = "PROVIDER_IMMUTABLE_SNAPSHOT"
    MUTABLE_BRANCH = "MUTABLE_BRANCH"
    MUTABLE_TAG = "MUTABLE_TAG"
    UNRESOLVED = "UNRESOLVED"
    PROVIDER_OPAQUE = "PROVIDER_OPAQUE"


IMMUTABLE_REVISION_KINDS = {
    ResolvedRevisionKind.IMMUTABLE_COMMIT,
    ResolvedRevisionKind.IMMUTABLE_CONTENT_DIGEST,
    ResolvedRevisionKind.PROVIDER_IMMUTABLE_SNAPSHOT,
}


class CollectionMode(StrEnum):
    IMPORTED_OFFLINE_SNAPSHOT = "IMPORTED_OFFLINE_SNAPSHOT"
    PREVIOUSLY_COLLECTED_SNAPSHOT = "PREVIOUSLY_COLLECTED_SNAPSHOT"
    BOUNDED_PUBLIC_METADATA_COLLECTION = "BOUNDED_PUBLIC_METADATA_COLLECTION"


class PayloadDownloadPolicy(StrEnum):
    FORBIDDEN = "FORBIDDEN"
    BOUNDED_NON_PAYLOAD_METADATA_ONLY = "BOUNDED_NON_PAYLOAD_METADATA_ONLY"


class NetworkUse(StrEnum):
    NONE = "NONE"
    PUBLIC_METADATA_ONLY = "PUBLIC_METADATA_ONLY"


class PayloadDownloadState(StrEnum):
    NOT_PERFORMED = "NOT_PERFORMED"
    PROHIBITED_REQUEST_REJECTED = "PROHIBITED_REQUEST_REJECTED"


class DigestKind(StrEnum):
    PAYLOAD_SHA256 = "PAYLOAD_SHA256"
    LFS_OID_SHA256 = "LFS_OID_SHA256"
    XET_OBJECT_ID = "XET_OBJECT_ID"
    XET_DECLARED_PAYLOAD_SHA256 = "XET_DECLARED_PAYLOAD_SHA256"
    GIT_BLOB_SHA1 = "GIT_BLOB_SHA1"
    GIT_BLOB_SHA256 = "GIT_BLOB_SHA256"
    OCI_CONTENT_DIGEST = "OCI_CONTENT_DIGEST"
    HTTP_ETAG = "HTTP_ETAG"
    PROVIDER_OPAQUE_ID = "PROVIDER_OPAQUE_ID"
    UNAVAILABLE = "UNAVAILABLE"


class SemanticTarget(StrEnum):
    PAYLOAD_BYTES = "PAYLOAD_BYTES"
    POINTER_BYTES = "POINTER_BYTES"
    GIT_OBJECT = "GIT_OBJECT"
    CONTAINER_CONTENT = "CONTAINER_CONTENT"
    PROVIDER_OBJECT = "PROVIDER_OBJECT"
    UNKNOWN = "UNKNOWN"


class ObservationLevel(StrEnum):
    NAME_ONLY = "NAME_ONLY"
    METADATA_ONLY = "METADATA_ONLY"
    POINTER_OBSERVED = "POINTER_OBSERVED"
    HEADER_BOUNDED = "HEADER_BOUNDED"
    PAYLOAD_DIGEST_DECLARED = "PAYLOAD_DIGEST_DECLARED"
    PAYLOAD_BYTES_HASHED = "PAYLOAD_BYTES_HASHED"


class ProvenanceStrength(StrEnum):
    DECLARED = "DECLARED"
    IMPORTED_UNVERIFIED = "IMPORTED_UNVERIFIED"
    PROVIDER_OBSERVED = "PROVIDER_OBSERVED"
    SYSTEM_OBSERVED = "SYSTEM_OBSERVED"
    SIGNED = "SIGNED"
    SIGNED_AND_TRUSTED = "SIGNED_AND_TRUSTED"


class StorageRepresentation(StrEnum):
    DIRECT_FILE = "DIRECT_FILE"
    GIT_LFS_POINTER = "GIT_LFS_POINTER"
    XET_BACKED_OBJECT = "XET_BACKED_OBJECT"
    GIT_BLOB = "GIT_BLOB"
    OCI_BLOB = "OCI_BLOB"
    PROVIDER_OPAQUE = "PROVIDER_OPAQUE"
    UNKNOWN = "UNKNOWN"


class RemoteMemberRole(StrEnum):
    PRIMARY_SHARD = "PRIMARY_SHARD"
    INDEX = "INDEX"
    MANDATORY_COMPANION = "MANDATORY_COMPANION"
    OPTIONAL_COMPANION = "OPTIONAL_COMPANION"
    PROMPT_ARTIFACT = "PROMPT_ARTIFACT"
    SOURCE_ARTIFACT = "SOURCE_ARTIFACT"
    OTHER_DECLARED = "OTHER_DECLARED"
    UNKNOWN = "UNKNOWN"


class ListingCompleteness(StrEnum):
    COMPLETE_FOR_DECLARED_RESPONSE_SCOPE = "COMPLETE_FOR_DECLARED_RESPONSE_SCOPE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


class TopologySource(StrEnum):
    EXPLICIT_INDEX = "EXPLICIT_INDEX"
    EXPLICIT_PROVIDER_MANIFEST = "EXPLICIT_PROVIDER_MANIFEST"
    EXPLICIT_USER_DECLARATION = "EXPLICIT_USER_DECLARATION"
    FILENAME_HEURISTIC = "FILENAME_HEURISTIC"
    UNAVAILABLE = "UNAVAILABLE"


class TopologyStatus(StrEnum):
    EXPLICIT_TOPOLOGY_AVAILABLE = "EXPLICIT_TOPOLOGY_AVAILABLE"
    HEURISTIC_ONLY = "HEURISTIC_ONLY"
    TOPOLOGY_UNAVAILABLE = "TOPOLOGY_UNAVAILABLE"
    CONFLICTING_INDEXES = "CONFLICTING_INDEXES"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID = "INVALID"


class CompletenessStatus(StrEnum):
    COMPLETE_FOR_EXPLICIT_TOPOLOGY_SCOPE = "COMPLETE_FOR_EXPLICIT_TOPOLOGY_SCOPE"
    INCOMPLETE_REMOTE_MEMBERS = "INCOMPLETE_REMOTE_MEMBERS"
    INCOMPLETE_LOCAL_MEMBERS = "INCOMPLETE_LOCAL_MEMBERS"
    INDEX_REFERENCES_MISSING_MEMBER = "INDEX_REFERENCES_MISSING_MEMBER"
    CONFLICTING_INDEXES = "CONFLICTING_INDEXES"
    TOPOLOGY_UNAVAILABLE = "TOPOLOGY_UNAVAILABLE"
    HEURISTIC_ONLY = "HEURISTIC_ONLY"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID = "INVALID"


class ExpectationScope(StrEnum):
    COMPLETE_REMOTE_MEMBER_SET = "COMPLETE_REMOTE_MEMBER_SET"
    EXPLICIT_SHARD_SET = "EXPLICIT_SHARD_SET"
    SELECTED_REQUIRED_MEMBERS = "SELECTED_REQUIRED_MEMBERS"
    PARTIAL_REMOTE_REFERENCE = "PARTIAL_REMOTE_REFERENCE"


class AuthorityOutcome(StrEnum):
    AUTHORIZED_PUBLISHER = "AUTHORIZED_PUBLISHER"
    UNAUTHORIZED = "UNAUTHORIZED"
    NOT_EVALUATED = "NOT_EVALUATED"


class FindingKind(StrEnum):
    PATH_MATCH = "PATH_MATCH"
    PATH_MISSING_LOCAL = "PATH_MISSING_LOCAL"
    PATH_EXTRA_LOCAL = "PATH_EXTRA_LOCAL"
    PATH_OUTSIDE_EXPECTATION_SCOPE = "PATH_OUTSIDE_EXPECTATION_SCOPE"
    SIZE_MATCH = "SIZE_MATCH"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    DIGEST_MATCH = "DIGEST_MATCH"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    DIGEST_NOT_COMPARABLE = "DIGEST_NOT_COMPARABLE"
    ROLE_MATCH = "ROLE_MATCH"
    ROLE_MISMATCH = "ROLE_MISMATCH"
    REMOTE_MEMBER_UNAVAILABLE = "REMOTE_MEMBER_UNAVAILABLE"
    LOCAL_OBSERVATION_INCOMPLETE = "LOCAL_OBSERVATION_INCOMPLETE"


class ReconciliationStatus(StrEnum):
    EXACT_MATCH_FOR_RECONCILIATION_SCOPE = "EXACT_MATCH_FOR_RECONCILIATION_SCOPE"
    METADATA_MATCH_ONLY = "METADATA_MATCH_ONLY"
    MEMBER_SET_MATCH_DIGESTS_UNAVAILABLE = "MEMBER_SET_MATCH_DIGESTS_UNAVAILABLE"
    MISMATCH = "MISMATCH"
    INCOMPLETE_REMOTE_EVIDENCE = "INCOMPLETE_REMOTE_EVIDENCE"
    INCOMPLETE_LOCAL_OBSERVATION = "INCOMPLETE_LOCAL_OBSERVATION"
    MUTABLE_OR_UNRESOLVED_REVISION = "MUTABLE_OR_UNRESOLVED_REVISION"
    EXPECTATION_UNAUTHORIZED = "EXPECTATION_UNAUTHORIZED"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID = "INVALID"


class ReconciliationOutcome(StrEnum):
    REMOTE_SNAPSHOT_OBSERVED = "REMOTE_SNAPSHOT_OBSERVED"
    MEMBER_SET_MATCHES = "MEMBER_SET_MATCHES"
    METADATA_MATCHES = "METADATA_MATCHES"
    LOCAL_BYTES_MATCH_COMPARABLE_REMOTE_EXPECTATION = (
        "LOCAL_BYTES_MATCH_COMPARABLE_REMOTE_EXPECTATION"
    )
    LOCAL_BYTES_MATCH_AUTHORIZED_PINNED_EXPECTATION = (
        "LOCAL_BYTES_MATCH_AUTHORIZED_PINNED_EXPECTATION"
    )
    MISMATCH = "MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    MUTABLE_REVISION = "MUTABLE_REVISION"
    EXPECTATION_UNAUTHORIZED = "EXPECTATION_UNAUTHORIZED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INVALID = "INVALID"


class RemoteArtifactLocator(ReconciliationModel):
    schema_id: Literal["omiv.remote-artifact-locator.v1"] = Field(
        default="omiv.remote-artifact-locator.v1", alias="schema"
    )
    locator_id: str = Field(pattern=r"^remote_locator_[0-9a-f]{32}$")
    provider_kind: ProviderKind
    provider_instance: str = Field(min_length=1, max_length=512)
    namespace: str = Field(min_length=1, max_length=256)
    artifact_name: str = Field(min_length=1, max_length=256)
    artifact_kind: str = Field(pattern=ID_PATTERN)
    requested_revision: str = Field(pattern=REVISION_PATTERN)
    requested_revision_kind: RequestedRevisionKind
    subject: ProductSubject
    trust_domain: str = Field(pattern=ID_PATTERN)
    limitations: tuple[str, ...]
    locator_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_locator(self) -> RemoteArtifactLocator:
        _validate_locator_text(self.provider_instance)
        for part in (self.namespace, self.artifact_name):
            if part in {".", ".."} or "/" in part or "\\" in part or _has_control(part):
                raise ValueError("ambiguous provider-relative path")
        if _has_control(self.requested_revision):
            raise ValueError("revision contains control characters")
        if "?" in self.requested_revision or "#" in self.requested_revision:
            raise ValueError("revision cannot contain query or fragment syntax")
        _identity(self, "locator_id", "remote_locator_", "locator_digest")
        return self


class CollectionLimits(ReconciliationModel):
    maximum_requests: int = Field(default=50, ge=1, le=50)
    maximum_members: int = Field(default=MAX_MEMBERS, ge=1, le=MAX_MEMBERS)
    maximum_response_bytes: int = Field(default=16 * 1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    maximum_total_response_bytes: int = Field(
        default=128 * 1024 * 1024, ge=1024, le=128 * 1024 * 1024
    )
    maximum_redirects_per_request: int = Field(default=3, ge=0, le=3)
    maximum_index_bytes: int = Field(default=64 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    maximum_index_mappings: int = Field(default=MAX_INDEX_MAPPINGS, ge=1, le=MAX_INDEX_MAPPINGS)
    maximum_metadata_file_bytes: int = Field(default=2 * 1024 * 1024, ge=0, le=2 * 1024 * 1024)
    maximum_payload_bytes: Literal[0] = 0
    maximum_archive_bytes: Literal[0] = 0
    maximum_executable_bytes: Literal[0] = 0


class RemoteSnapshotPlan(ReconciliationModel):
    schema_id: Literal["omiv.remote-snapshot-plan.v1"] = Field(
        default="omiv.remote-snapshot-plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=r"^remote_plan_[0-9a-f]{32}$")
    locator_id: str = Field(pattern=r"^remote_locator_[0-9a-f]{32}$")
    locator_digest: str = Field(pattern=SHA256_PATTERN)
    collection_mode: CollectionMode
    requested_metadata_scope: tuple[str, ...]
    payload_download_policy: PayloadDownloadPolicy = PayloadDownloadPolicy.FORBIDDEN
    provider_adapter_id: str = Field(pattern=ID_PATTERN)
    provider_adapter_version: str = Field(pattern=ID_PATTERN)
    limits: CollectionLimits = CollectionLimits()
    allowed_hosts: tuple[str, ...]
    redirect_policy: Literal["ALLOWLIST_ONLY"] = "ALLOWLIST_ONLY"
    requested_digest_semantics: tuple[DigestKind, ...]
    requested_available_at: ExplicitTime
    requested_observed_at: ExplicitTime
    limitations: tuple[str, ...]
    plan_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteSnapshotPlan:
        if (
            self.payload_download_policy != PayloadDownloadPolicy.FORBIDDEN
            and self.limits.maximum_payload_bytes
        ):
            raise ValueError("payload collection is unsupported")
        if len(set(self.allowed_hosts)) != len(self.allowed_hosts):
            raise ValueError("duplicate allowed host")
        if self.allowed_hosts != tuple(sorted(self.allowed_hosts)):
            raise ValueError("allowed hosts must be canonically ordered")
        if len(set(self.requested_digest_semantics)) != len(self.requested_digest_semantics):
            raise ValueError("duplicate requested digest semantics")
        _identity(self, "plan_id", "remote_plan_", "plan_digest")
        return self


class RemoteCollectionExecutionRecord(ReconciliationModel):
    schema_id: Literal["omiv.remote-collection-execution-record.v1"] = Field(
        default="omiv.remote-collection-execution-record.v1", alias="schema"
    )
    execution_id: str = Field(pattern=r"^remote_execution_[0-9a-f]{32}$")
    plan_id: str = Field(pattern=r"^remote_plan_[0-9a-f]{32}$")
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    locator_id: str = Field(pattern=r"^remote_locator_[0-9a-f]{32}$")
    locator_digest: str = Field(pattern=SHA256_PATTERN)
    collector_id: str = Field(pattern=ID_PATTERN)
    collector_version: str = Field(pattern=ID_PATTERN)
    collection_mode: CollectionMode
    effective_limits: CollectionLimits
    network_use: NetworkUse
    contacted_hosts: tuple[str, ...] = Field(max_length=50)
    requested_urls: tuple[str, ...] = Field(max_length=50)
    request_count: int = Field(ge=0, le=50)
    response_count: int = Field(ge=0, le=50)
    response_bytes: int = Field(ge=0, le=128 * 1024 * 1024)
    redirect_hosts: tuple[str, ...] = Field(max_length=150)
    payload_download: PayloadDownloadState
    payload_bytes_downloaded: Literal[0] = 0
    available_at: ExplicitTime
    observed_at: ExplicitTime
    result_reference_status: Literal["LINKED_DOWNSTREAM_BY_SNAPSHOT"] = (
        "LINKED_DOWNSTREAM_BY_SNAPSHOT"
    )
    coverage_summary: str
    errors: tuple[str, ...]
    limitations: tuple[str, ...]
    execution_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_execution(self) -> RemoteCollectionExecutionRecord:
        if self.network_use == NetworkUse.NONE and any(
            (
                self.contacted_hosts,
                self.requested_urls,
                self.request_count,
                self.response_count,
                self.response_bytes,
            )
        ):
            raise ValueError("offline execution cannot claim network activity")
        if self.network_use == NetworkUse.PUBLIC_METADATA_ONLY and (
            not self.contacted_hosts or self.request_count < 1 or self.response_count < 1
        ):
            raise ValueError("network execution requires actual request/response accounting")
        if self.contacted_hosts != tuple(sorted(set(self.contacted_hosts))):
            raise ValueError("contacted hosts must be unique and ordered")
        if self.requested_urls != tuple(sorted(set(self.requested_urls))):
            raise ValueError("requested URLs must be unique and ordered")
        if self.redirect_hosts != tuple(sorted(set(self.redirect_hosts))):
            raise ValueError("redirect hosts must be unique and ordered")
        for url in self.requested_urls:
            _validate_public_url(url)
        _identity(self, "execution_id", "remote_execution_", "execution_digest")
        return self


class RemoteDigestDescriptor(ReconciliationModel):
    schema_id: Literal["omiv.remote-digest-descriptor.v1"] = Field(
        default="omiv.remote-digest-descriptor.v1", alias="schema"
    )
    kind: DigestKind
    algorithm: str
    canonical_value: str
    semantic_target: SemanticTarget
    evidence_source: str = Field(pattern=ID_PATTERN)
    observation_level: ObservationLevel
    provenance_strength: ProvenanceStrength
    payload_comparable: bool
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def semantic_consistency(self) -> RemoteDigestDescriptor:
        expected = {
            DigestKind.PAYLOAD_SHA256: ("SHA256", 64),
            DigestKind.LFS_OID_SHA256: ("SHA256", 64),
            DigestKind.XET_DECLARED_PAYLOAD_SHA256: ("SHA256", 64),
            DigestKind.GIT_BLOB_SHA1: ("SHA1", 40),
            DigestKind.GIT_BLOB_SHA256: ("SHA256", 64),
        }
        if self.kind == DigestKind.UNAVAILABLE:
            if (
                self.canonical_value
                or self.payload_comparable
                or self.semantic_target != SemanticTarget.UNKNOWN
            ):
                raise ValueError("unavailable digest must have no value or semantics")
        elif not self.canonical_value:
            raise ValueError("available digest requires a value")
        if self.kind in expected:
            algorithm, length = expected[self.kind]
            if self.algorithm != algorithm:
                raise ValueError("digest kind has incompatible declared algorithm")
            if not re.fullmatch(rf"[0-9a-f]{{{length}}}", self.canonical_value):
                raise ValueError("invalid canonical digest value")
        required_targets = {
            DigestKind.PAYLOAD_SHA256: SemanticTarget.PAYLOAD_BYTES,
            DigestKind.XET_OBJECT_ID: SemanticTarget.PROVIDER_OBJECT,
            DigestKind.GIT_BLOB_SHA1: SemanticTarget.GIT_OBJECT,
            DigestKind.GIT_BLOB_SHA256: SemanticTarget.GIT_OBJECT,
            DigestKind.OCI_CONTENT_DIGEST: SemanticTarget.CONTAINER_CONTENT,
            DigestKind.HTTP_ETAG: SemanticTarget.UNKNOWN,
            DigestKind.PROVIDER_OPAQUE_ID: SemanticTarget.UNKNOWN,
        }
        if self.kind in required_targets and self.semantic_target != required_targets[self.kind]:
            raise ValueError("digest kind has incompatible semantic target")
        if self.kind in {DigestKind.LFS_OID_SHA256, DigestKind.XET_DECLARED_PAYLOAD_SHA256} and (
            self.semantic_target not in {SemanticTarget.PAYLOAD_BYTES, SemanticTarget.UNKNOWN}
        ):
            raise ValueError("declared payload identifier has incompatible semantic target")
        comparable = (
            (
                self.kind == DigestKind.PAYLOAD_SHA256
                and self.semantic_target == SemanticTarget.PAYLOAD_BYTES
            )
            or (
                self.kind == DigestKind.LFS_OID_SHA256
                and self.semantic_target == SemanticTarget.PAYLOAD_BYTES
                and self.observation_level == ObservationLevel.POINTER_OBSERVED
            )
            or (
                self.kind == DigestKind.XET_DECLARED_PAYLOAD_SHA256
                and self.semantic_target == SemanticTarget.PAYLOAD_BYTES
                and self.observation_level == ObservationLevel.PAYLOAD_DIGEST_DECLARED
            )
        )
        if self.payload_comparable != comparable:
            raise ValueError("payload comparability must follow explicit semantics")
        if (
            self.kind
            in {
                DigestKind.XET_OBJECT_ID,
                DigestKind.GIT_BLOB_SHA1,
                DigestKind.GIT_BLOB_SHA256,
                DigestKind.HTTP_ETAG,
                DigestKind.PROVIDER_OPAQUE_ID,
            }
            and self.payload_comparable
        ):
            raise ValueError("object or opaque identity is not a payload digest")
        return self


class RemoteMemberRecord(ReconciliationModel):
    schema_id: Literal["omiv.remote-member-record.v1"] = Field(
        default="omiv.remote-member-record.v1", alias="schema"
    )
    member_id: str = Field(pattern=r"^remote_member_[0-9a-f]{32}$")
    path: str = Field(min_length=1, max_length=1024)
    role: RemoteMemberRole
    logical_size: int | None = Field(default=None, ge=0)
    digests: tuple[RemoteDigestDescriptor, ...]
    storage_representation: StorageRepresentation
    observation_level: ObservationLevel
    provenance_strength: ProvenanceStrength
    member_provenance: str = Field(pattern=ID_PATTERN)
    available_at: ExplicitTime
    limitations: tuple[str, ...]
    member_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteMemberRecord:
        validate_portable_path(self.path)
        if len({x.kind for x in self.digests}) != len(self.digests):
            raise ValueError("duplicate digest semantics for member")
        if tuple(sorted(self.digests, key=lambda x: x.kind.value)) != self.digests:
            raise ValueError("member digest descriptors must be canonically ordered")
        _identity(self, "member_id", "remote_member_", "member_digest")
        return self


class RemoteSnapshotManifest(ReconciliationModel):
    schema_id: Literal["omiv.remote-snapshot-manifest.v1"] = Field(
        default="omiv.remote-snapshot-manifest.v1", alias="schema"
    )
    manifest_id: str = Field(pattern=r"^remote_snapshot_[0-9a-f]{32}$")
    locator_id: str = Field(pattern=r"^remote_locator_[0-9a-f]{32}$")
    locator_digest: str = Field(pattern=SHA256_PATTERN)
    plan_id: str = Field(pattern=r"^remote_plan_[0-9a-f]{32}$")
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    execution_id: str = Field(pattern=r"^remote_execution_[0-9a-f]{32}$")
    execution_digest: str = Field(pattern=SHA256_PATTERN)
    requested_revision: str
    resolved_revision: str
    resolved_revision_kind: ResolvedRevisionKind
    revision_resolution_evidence: str
    subject: ProductSubject
    provider_kind: ProviderKind
    provider_instance: str
    namespace: str
    artifact_name: str
    members: tuple[RemoteMemberRecord, ...] = Field(max_length=MAX_MEMBERS)
    member_set_digest: str = Field(pattern=SHA256_PATTERN)
    observation_coverage: str
    provider_listing_completeness: ListingCompleteness
    unavailable_members: tuple[str, ...]
    unsupported_members: tuple[str, ...]
    errors: tuple[str, ...]
    available_at: ExplicitTime
    observed_at: ExplicitTime
    provenance_strength: ProvenanceStrength
    limitations: tuple[str, ...]
    manifest_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> RemoteSnapshotManifest:
        paths = tuple(x.path for x in self.members)
        validate_path_set(paths)
        if tuple(sorted(self.members, key=lambda x: x.path.encode())) != self.members:
            raise ValueError("remote members must be canonically ordered")
        if len({member.member_id for member in self.members}) != len(self.members):
            raise ValueError("remote snapshot contains duplicate member identities")
        if len({member.member_digest for member in self.members}) != len(self.members):
            raise ValueError("remote snapshot contains duplicate member records")
        if self.member_set_digest != remote_member_set_digest(self.members):
            raise ValueError("remote member-set digest mismatch")
        if self.resolved_revision_kind in IMMUTABLE_REVISION_KINDS and not self.resolved_revision:
            raise ValueError("immutable revision requires a resolved identity")
        _identity(self, "manifest_id", "remote_snapshot_", "manifest_digest")
        return self


class ShardGroup(ReconciliationModel):
    group_id: str = Field(pattern=ID_PATTERN)
    required_shards: tuple[str, ...]
    optional_shards: tuple[str, ...] = ()
    logical_key_count: int = Field(ge=0)

    @model_validator(mode="after")
    def paths(self) -> ShardGroup:
        validate_path_set(self.required_shards + self.optional_shards)
        return self


class ShardTopology(ReconciliationModel):
    schema_id: Literal["omiv.shard-topology.v1"] = Field(
        default="omiv.shard-topology.v1", alias="schema"
    )
    topology_id: str = Field(pattern=r"^shard_topology_[0-9a-f]{32}$")
    subject: ProductSubject
    snapshot_id: str = Field(pattern=r"^remote_snapshot_[0-9a-f]{32}$")
    snapshot_digest: str = Field(pattern=SHA256_PATTERN)
    topology_source: TopologySource
    source_member_ids: tuple[str, ...]
    declared_index_files: tuple[str, ...]
    shard_groups: tuple[ShardGroup, ...]
    required_shards: tuple[str, ...]
    optional_shards: tuple[str, ...]
    companion_artifacts: tuple[str, ...]
    referenced_logical_key_count: int = Field(ge=0, le=MAX_INDEX_MAPPINGS)
    duplicate_references: tuple[str, ...]
    conflicting_references: tuple[str, ...]
    missing_referenced_remote_members: tuple[str, ...]
    unreferenced_shard_like_members: tuple[str, ...]
    limits: CollectionLimits
    coverage: str
    status: TopologyStatus
    limitations: tuple[str, ...]
    topology_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_topology(self) -> ShardTopology:
        validate_path_set(self.required_shards + self.optional_shards + self.companion_artifacts)
        if (
            self.topology_source == TopologySource.FILENAME_HEURISTIC
            and self.status != TopologyStatus.HEURISTIC_ONLY
        ):
            raise ValueError("filename heuristics may create hints only")
        if (
            self.topology_source in {TopologySource.FILENAME_HEURISTIC, TopologySource.UNAVAILABLE}
            and self.required_shards
        ):
            raise ValueError("non-explicit topology cannot establish required shards")
        _identity(self, "topology_id", "shard_topology_", "topology_digest")
        return self


class ShardCompletenessAssessment(ReconciliationModel):
    schema_id: Literal["omiv.shard-completeness-assessment.v1"] = Field(
        default="omiv.shard-completeness-assessment.v1", alias="schema"
    )
    assessment_id: str = Field(pattern=r"^shard_assessment_[0-9a-f]{32}$")
    topology_id: str = Field(pattern=r"^shard_topology_[0-9a-f]{32}$")
    topology_digest: str = Field(pattern=SHA256_PATTERN)
    snapshot_id: str = Field(pattern=r"^remote_snapshot_[0-9a-f]{32}$")
    snapshot_digest: str = Field(pattern=SHA256_PATTERN)
    local_manifest_id: str | None = None
    local_manifest_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    index_declaration_coverage: str
    remote_member_presence: str
    local_member_presence: str
    digest_comparability: str
    local_byte_match: str
    mandatory_companion_coverage: str
    missing_remote_members: tuple[str, ...]
    missing_local_members: tuple[str, ...]
    status: CompletenessStatus
    limitations: tuple[str, ...]
    assessment_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> ShardCompletenessAssessment:
        if (self.local_manifest_id is None) != (self.local_manifest_digest is None):
            raise ValueError("local manifest reference must be complete")
        _identity(self, "assessment_id", "shard_assessment_", "assessment_digest")
        return self


class RemoteExpectationMember(ReconciliationModel):
    path: str
    role: RemoteMemberRole
    logical_size: int | None = Field(default=None, ge=0)
    comparable_digest: RemoteDigestDescriptor | None
    remote_member_id: str
    remote_member_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def path_and_digest(self) -> RemoteExpectationMember:
        validate_portable_path(self.path)
        if self.comparable_digest is not None and not self.comparable_digest.payload_comparable:
            raise ValueError("expectation comparable digest is not payload-comparable")
        return self


class RemoteSnapshotExpectation(ReconciliationModel):
    schema_id: Literal["omiv.remote-snapshot-expectation.v1"] = Field(
        default="omiv.remote-snapshot-expectation.v1", alias="schema"
    )
    expectation_id: str = Field(pattern=r"^remote_expectation_[0-9a-f]{32}$")
    snapshot_id: str = Field(pattern=r"^remote_snapshot_[0-9a-f]{32}$")
    snapshot_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    logical_root: str = Field(pattern=ID_PATTERN)
    resolved_revision: str
    resolved_revision_kind: ResolvedRevisionKind
    remote_listing_completeness: ListingCompleteness
    remote_unavailable_members: tuple[str, ...]
    expectation_scope: ExpectationScope
    selected_members: tuple[RemoteExpectationMember, ...]
    required_roles: tuple[RemoteMemberRole, ...]
    publisher_authority_evaluation_id: str | None = None
    publisher_authority_evaluation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    available_at: ExplicitTime
    provenance_strength: ProvenanceStrength
    limitations: tuple[str, ...]
    expectation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteSnapshotExpectation:
        validate_path_set(tuple(x.path for x in self.selected_members))
        if (
            tuple(sorted(self.selected_members, key=lambda x: x.path.encode()))
            != self.selected_members
        ):
            raise ValueError("expectation members must be canonically ordered")
        if len({member.remote_member_id for member in self.selected_members}) != len(
            self.selected_members
        ):
            raise ValueError("expectation contains duplicate remote member identities")
        if (self.publisher_authority_evaluation_id is None) != (
            self.publisher_authority_evaluation_digest is None
        ):
            raise ValueError("publisher authority reference must be complete")
        _identity(self, "expectation_id", "remote_expectation_", "expectation_digest")
        return self


class RemotePublisherAuthorityEvaluation(ReconciliationModel):
    schema_id: Literal["omiv.remote-publisher-authority-evaluation.v1"] = Field(
        default="omiv.remote-publisher-authority-evaluation.v1", alias="schema"
    )
    authority_evaluation_id: str = Field(pattern=r"^remote_authority_[0-9a-f]{32}$")
    expectation_id: str = Field(pattern=r"^remote_expectation_[0-9a-f]{32}$")
    expectation_digest: str = Field(pattern=SHA256_PATTERN)
    trust_report_id: str = Field(pattern=r"^trust_report_[0-9a-f]{32}$")
    trust_report_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ProductSubject
    provider_instance: str
    namespace: str
    resolved_revision: str
    purpose: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    expectation_scope: ExpectationScope
    signer_id: str = Field(pattern=ID_PATTERN)
    key_id: str = Field(pattern=ID_PATTERN)
    signer_binding_status: str
    validity_context: str
    delegation_context: str
    revocation_context: str
    authority_outcome: AuthorityOutcome
    limitations: tuple[str, ...]
    authority_evaluation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemotePublisherAuthorityEvaluation:
        _identity(
            self, "authority_evaluation_id", "remote_authority_", "authority_evaluation_digest"
        )
        return self


class ReconciliationFinding(ReconciliationModel):
    path: str
    findings: tuple[FindingKind, ...]
    remote_size: int | None = Field(default=None, ge=0)
    local_size: int | None = Field(default=None, ge=0)
    remote_digest_kind: DigestKind | None = None
    remote_digest: str | None = None
    local_payload_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)


class RemoteLocalReconciliationComparison(ReconciliationModel):
    schema_id: Literal["omiv.remote-local-reconciliation-comparison.v1"] = Field(
        default="omiv.remote-local-reconciliation-comparison.v1", alias="schema"
    )
    comparison_id: str = Field(pattern=r"^remote_local_comparison_[0-9a-f]{32}$")
    expectation_id: str = Field(pattern=r"^remote_expectation_[0-9a-f]{32}$")
    expectation_digest: str = Field(pattern=SHA256_PATTERN)
    local_manifest_id: str
    local_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str
    subject_scope_digest: str = Field(pattern=SHA256_PATTERN)
    logical_root: str
    expectation_scope: ExpectationScope
    findings: tuple[ReconciliationFinding, ...] = Field(max_length=MAX_FINDINGS)
    matching_members: tuple[str, ...]
    missing_local_members: tuple[str, ...]
    extra_local_members: tuple[str, ...]
    digest_comparable_members: tuple[str, ...]
    digest_matching_members: tuple[str, ...]
    status: ReconciliationStatus
    limitations: tuple[str, ...]
    comparison_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteLocalReconciliationComparison:
        paths = tuple(item.path for item in self.findings)
        validate_path_set(paths)
        if self.findings != tuple(sorted(self.findings, key=lambda item: item.path.encode())):
            raise ValueError("reconciliation findings must be canonically ordered")
        _identity(self, "comparison_id", "remote_local_comparison_", "comparison_digest")
        return self


class RemoteLocalReconciliationPolicy(ReconciliationModel):
    schema_id: Literal["omiv.remote-local-reconciliation-policy.v1"] = Field(
        default="omiv.remote-local-reconciliation-policy.v1", alias="schema"
    )
    policy_id: str = Field(pattern=ID_PATTERN)
    scope: ScopeContext
    allowed_providers: tuple[ProviderKind, ...]
    require_immutable_revision: bool
    accepted_expectation_scopes: tuple[ExpectationScope, ...]
    accepted_topology_sources: tuple[TopologySource, ...]
    accepted_remote_listing_coverage: tuple[ListingCompleteness, ...]
    accepted_local_coverage: tuple[CompletionState, ...]
    accepted_digest_semantics: tuple[DigestKind, ...]
    require_publisher_authority: bool
    allow_extra_members: bool
    allow_missing_members: bool
    require_shard_completeness: bool
    require_mandatory_companions: bool
    available_at_required: bool
    limitations: tuple[str, ...]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteLocalReconciliationPolicy:
        _digest_only(self, "policy_digest")
        return self


class ObjectReference(ReconciliationModel):
    schema_id: str
    object_id: str
    object_digest: str = Field(pattern=SHA256_PATTERN)


class RemoteLocalReconciliationEvidence(ReconciliationModel):
    schema_id: Literal["omiv.remote-local-reconciliation-evidence.v1"] = Field(
        default="omiv.remote-local-reconciliation-evidence.v1", alias="schema"
    )
    evidence_id: str = Field(pattern=r"^remote_local_evidence_[0-9a-f]{32}$")
    subject: ProductSubject
    locator: ObjectReference
    plan: ObjectReference
    execution: ObjectReference
    snapshot: ObjectReference
    topology: ObjectReference
    completeness_assessment: ObjectReference
    expectation: ObjectReference
    publisher_authority: ObjectReference | None
    local_manifest: ObjectReference
    comparison: ObjectReference
    policy: ObjectReference
    outcome: ReconciliationOutcome
    policy_satisfied: bool
    available_at: ExplicitTime
    observed_at: ExplicitTime
    evaluated_at: ExplicitTime
    limitations: tuple[str, ...]
    evidence_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteLocalReconciliationEvidence:
        _identity(self, "evidence_id", "remote_local_evidence_", "evidence_digest")
        return self


class RemoteLocalReconciliationReport(ReconciliationModel):
    schema_id: Literal["omiv.remote-local-reconciliation-report.v1"] = Field(
        default="omiv.remote-local-reconciliation-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^remote_local_report_[0-9a-f]{32}$")
    evidence: RemoteLocalReconciliationEvidence
    comparison: RemoteLocalReconciliationComparison
    topology_status: TopologyStatus
    completeness_status: CompletenessStatus
    publisher_authority: AuthorityOutcome
    network_use: NetworkUse
    payload_download: PayloadDownloadState
    model_authenticity: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    model_semantic_correctness: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    model_safety: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    runtime_identity: Literal["NOT_OBSERVED"] = "NOT_OBSERVED"
    limitations: tuple[str, ...]
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteLocalReconciliationReport:
        _identity(self, "report_id", "remote_local_report_", "report_digest")
        return self


class LocalManifestReference(ReconciliationModel):
    schema_id: Literal["omiv.reconciliation-local-manifest-reference.v1"] = Field(
        default="omiv.reconciliation-local-manifest-reference.v1", alias="schema"
    )
    reference_id: str = Field(pattern=r"^local_manifest_reference_[0-9a-f]{32}$")
    local_manifest_id: str
    local_manifest_digest: str = Field(pattern=SHA256_PATTERN)
    subject_id: str
    logical_root: str
    source_schema: Literal["omiv.observed-payload-manifest.v1"] = (
        "omiv.observed-payload-manifest.v1"
    )
    source_path: str
    limitations: tuple[str, ...]
    reference_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> LocalManifestReference:
        validate_portable_path(self.source_path)
        _identity(self, "reference_id", "local_manifest_reference_", "reference_digest")
        return self


class RemoteLocalIntegration(ReconciliationModel):
    schema_id: Literal["omiv.remote-local-integration.v1"] = Field(
        default="omiv.remote-local-integration.v1", alias="schema"
    )
    integration_id: str = Field(pattern=r"^remote_local_integration_[0-9a-f]{32}$")
    integration_type: Literal[
        "PASSPORT", "CUSTODY", "GOVERNANCE", "SECURITY", "RUNTIME", "HISTORICAL", "AUDIT"
    ]
    reconciliation_evidence_id: str = Field(pattern=r"^remote_local_evidence_[0-9a-f]{32}$")
    reconciliation_evidence_digest: str = Field(pattern=SHA256_PATTERN)
    source_object: ObjectReference | None
    derived_status: str
    accepted: bool
    creates_approval: Literal[False] = False
    creates_security_pass: Literal[False] = False
    observed_runtime_identity: Literal[False] = False
    mutates_prior_artifact: Literal[False] = False
    available_at: ExplicitTime
    limitations: tuple[str, ...]
    integration_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> RemoteLocalIntegration:
        _identity(self, "integration_id", "remote_local_integration_", "integration_digest")
        return self


class ReconciliationArtifactIndexEntry(ReconciliationModel):
    path: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    schema_id: str
    canonical_id: str


class ReconciliationArtifactIndex(ReconciliationModel):
    schema_id: Literal["omiv.reconciliation-artifact-index.v1"] = Field(
        default="omiv.reconciliation-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^reconciliation_index_[0-9a-f]{32}$")
    entries: tuple[ReconciliationArtifactIndexEntry, ...] = Field(max_length=170)
    total_size: int = Field(ge=0)
    limitations: tuple[str, ...]
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identity(self) -> ReconciliationArtifactIndex:
        paths = tuple(entry.path for entry in self.entries)
        validate_path_set(paths)
        if self.entries != tuple(sorted(self.entries, key=lambda entry: entry.path.encode())):
            raise ValueError("reconciliation index entries must be canonically ordered")
        if len({entry.canonical_id for entry in self.entries}) != len(self.entries):
            raise ValueError("reconciliation index contains duplicate canonical identities")
        _identity(self, "index_id", "reconciliation_index_", "index_digest")
        return self


def remote_member_set_digest(members: tuple[RemoteMemberRecord, ...]) -> str:
    return canonical_sha256(
        {
            "domain": "omiv.remote-member-set.v1",
            "members": [
                {"path": x.path, "member_id": x.member_id, "member_digest": x.member_digest}
                for x in members
            ],
        }
    )


def local_manifest_reference(manifest: ObservedPayloadManifest) -> ObjectReference:
    return ObjectReference(
        schema_id=manifest.schema_id,
        object_id=manifest.manifest_id,
        object_digest=manifest.manifest_digest,
    )


def _has_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_locator_text(value: str) -> None:
    if _has_control(value) or "@" in value:
        raise ValueError("provider instance contains credentials or control characters")
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("provider instance cannot contain credentials, query, or fragment")
    if parsed.path not in {"", "/"} or not parsed.hostname:
        raise ValueError("provider instance must identify a host, not a repository path")


def _validate_public_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("requested URL must be credential-free HTTPS")
    if parsed.query or parsed.fragment:
        raise ValueError("canonical requested URL cannot contain query or fragment")


def _identity(value: ReconciliationModel, id_field: str, prefix: str, digest_field: str) -> None:
    body: dict[str, Any] = value.model_dump(mode="json", by_alias=True)
    digest = str(body.pop(digest_field))
    identity = str(body.pop(id_field))
    expected_id = prefix + canonical_sha256(body)[:32]
    if identity != expected_id or digest != canonical_sha256({**body, id_field: expected_id}):
        raise ValueError("canonical identity or digest mismatch")


def _digest_only(value: ReconciliationModel, digest_field: str) -> None:
    body: dict[str, Any] = value.model_dump(mode="json", by_alias=True)
    digest = str(body.pop(digest_field))
    if digest != canonical_sha256(body):
        raise ValueError("canonical digest mismatch")
