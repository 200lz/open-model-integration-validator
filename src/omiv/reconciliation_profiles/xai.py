"""Pinned xAI public-provider metadata fixtures and offline practice evidence."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_path_set
from omiv.reconciliation.building import (
    assess_completeness,
    build_digest_descriptor,
    build_execution_record,
    build_expectation,
    build_locator,
    build_member,
    build_plan,
    build_snapshot,
    identified,
    reference,
)
from omiv.reconciliation.indexes import build_unavailable_topology
from omiv.reconciliation.models import (
    CollectionMode,
    DigestKind,
    ExpectationScope,
    ListingCompleteness,
    NetworkUse,
    ObjectReference,
    ObservationLevel,
    ProvenanceStrength,
    ProviderKind,
    RemoteMemberRecord,
    RemoteMemberRole,
    RequestedRevisionKind,
    ResolvedRevisionKind,
    StorageRepresentation,
)
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubjectClass

FIXTURE_CLASSIFICATION = "PINNED_PUBLIC_PROVIDER_METADATA_FIXTURE"
PRACTICE_CLASSIFICATION = "XAI_PUBLIC_PINNED_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD"


class XaiProfileModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class PinnedDigest(XaiProfileModel):
    kind: Literal["LFS_OID_SHA256", "XET_OBJECT_ID", "PROVIDER_OPAQUE_ID"]
    canonical_value: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def syntax(self) -> PinnedDigest:
        if self.kind == "LFS_OID_SHA256" and not _is_lower_hex(self.canonical_value, 64):
            raise ValueError("LFS OID must be lowercase SHA-256 syntax")
        return self


class PinnedMember(XaiProfileModel):
    path: str
    declared_size: int = Field(ge=0)
    storage_representation: Literal["DIRECT_FILE", "XET_BACKED_OBJECT"]
    digests: tuple[PinnedDigest, ...]

    @model_validator(mode="after")
    def semantics(self) -> PinnedMember:
        validate_path_set((self.path,))
        if self.digests != tuple(sorted(self.digests, key=lambda item: item.kind)):
            raise ValueError("pinned digest descriptors must be canonically ordered")
        kinds = {item.kind for item in self.digests}
        if len(kinds) != len(self.digests):
            raise ValueError("duplicate pinned digest semantics")
        if "PROVIDER_OPAQUE_ID" not in kinds:
            raise ValueError("provider member identity must be retained")
        xet = self.storage_representation == "XET_BACKED_OBJECT"
        if xet != ({"LFS_OID_SHA256", "XET_OBJECT_ID"} <= kinds):
            raise ValueError("Xet storage requires distinct LFS and Xet descriptors")
        if xet and len({item.canonical_value for item in self.digests}) != len(self.digests):
            raise ValueError("LFS, Xet, and provider object identities must remain distinct")
        return self


class PinnedXaiMetadataFixture(XaiProfileModel):
    schema_id: Literal["omiv.pinned-public-provider-metadata-fixture.v1"] = Field(
        default="omiv.pinned-public-provider-metadata-fixture.v1", alias="schema"
    )
    fixture_id: str = Field(pattern=r"^pinned_provider_metadata_[0-9a-f]{32}$")
    classification: Literal["PINNED_PUBLIC_PROVIDER_METADATA_FIXTURE"]
    provider: Literal["HUGGING_FACE"]
    namespace: Literal["xai-org"]
    repository: Literal["grok-1", "grok-2"]
    resolved_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    resolved_revision_kind: Literal["IMMUTABLE_COMMIT"]
    members: tuple[PinnedMember, ...] = Field(max_length=100_000)
    source_endpoint_class: Literal["HUGGING_FACE_PUBLIC_MODEL_REVISION_AND_RECURSIVE_TREE_API"]
    provider_listing_coverage: Literal["COMPLETE_PINNED_PROVIDER_LISTING_SCOPE"]
    imported_tree_pages: int = Field(ge=1, le=50)
    pagination_termination: Literal["NO_NEXT_LINK_OBSERVED_BY_BOUNDED_ADAPTER"]
    request_count: int = Field(ge=1, le=50)
    response_count: int = Field(ge=1, le=50)
    response_bytes: int = Field(ge=1, le=128 * 1024 * 1024)
    redirect_count: Literal[0]
    weight_file_get_count: Literal[0]
    payload_bytes_downloaded: Literal[0]
    raw_response_retention: Literal["NOT_RETAINED"]
    availability: Literal["NOT_RECORDED"]
    observation_time: Literal["NOT_RECORDED"]
    publisher_authority: Literal["NOT_ESTABLISHED"]
    payload_observation: Literal["NOT_PERFORMED"]
    payload_comparability: Literal["DIGEST_NOT_COMPARABLE"]
    freshness_current_state: Literal["NOT_ESTABLISHED"]
    model_authenticity: Literal["NOT_ESTABLISHED"]
    security_safety: Literal["NOT_EVALUATED"]
    tokenizer_config_parity: Literal["NOT_EVALUATED"]
    runtime_identity: Literal["NOT_OBSERVED"]
    limitations: tuple[str, ...]
    fixture_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity_and_coverage(self) -> PinnedXaiMetadataFixture:
        paths = tuple(member.path for member in self.members)
        validate_path_set(paths)
        if self.members != tuple(sorted(self.members, key=lambda item: item.path.encode())):
            raise ValueError("pinned members must be canonically ordered")
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate pinned member paths")
        if self.request_count != self.response_count:
            raise ValueError("successful pinned capture requires matched request/response counts")
        _validate_identity(self, "fixture_id", "pinned_provider_metadata_", "fixture_digest")
        return self


class PracticeIntegrationSummary(XaiProfileModel):
    integration_type: Literal["PASSPORT", "GOVERNANCE", "HISTORICAL", "AUDIT"]
    derived_status: str
    accepted: Literal[False] = False
    creates_authority: Literal[False] = False
    mutates_prior_artifact: Literal[False] = False
    limitations: tuple[str, ...]


class XaiPinnedMetadataEvidence(XaiProfileModel):
    schema_id: Literal["omiv.xai-pinned-metadata-practice-evidence.v1"] = Field(
        default="omiv.xai-pinned-metadata-practice-evidence.v1", alias="schema"
    )
    evidence_id: str = Field(pattern=r"^xai_metadata_evidence_[0-9a-f]{32}$")
    classification: Literal["XAI_PUBLIC_PINNED_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD"]
    source_fixture: ObjectReference
    locator: ObjectReference
    plan: ObjectReference
    execution: ObjectReference
    snapshot: ObjectReference
    topology: ObjectReference
    completeness_assessment: ObjectReference
    expectation: ObjectReference
    namespace: Literal["xai-org"]
    repository: Literal["grok-1", "grok-2"]
    resolved_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    member_count: int = Field(ge=1)
    declared_total_bytes: int = Field(ge=1)
    storage_distribution: dict[str, int]
    digest_distribution: dict[str, int]
    payload_comparable_member_count: Literal[0]
    provider_listing_completeness: Literal["COMPLETE_FOR_DECLARED_RESPONSE_SCOPE"]
    topology_status: Literal["TOPOLOGY_UNAVAILABLE"]
    local_member_presence: Literal["NOT_EVALUATED"]
    local_byte_match: Literal["NOT_EVALUATED"]
    publisher_authority: Literal["NOT_ESTABLISHED"]
    payload_download: Literal["NOT_PERFORMED"]
    payload_bytes_observed: Literal[0]
    model_authenticity: Literal["NOT_ESTABLISHED"]
    security_safety: Literal["NOT_EVALUATED"]
    tokenizer_config_parity: Literal["NOT_EVALUATED"]
    runtime_identity: Literal["NOT_OBSERVED"]
    freshness_current_state: Literal["NOT_ESTABLISHED"]
    observation_time: Literal["NOT_RECORDED"]
    integration_summaries: tuple[PracticeIntegrationSummary, ...]
    limitations: tuple[str, ...]
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity(self) -> XaiPinnedMetadataEvidence:
        kinds = tuple(item.integration_type for item in self.integration_summaries)
        if kinds != ("AUDIT", "GOVERNANCE", "HISTORICAL", "PASSPORT"):
            raise ValueError("practice integration summaries must be complete and ordered")
        _validate_identity(self, "evidence_id", "xai_metadata_evidence_", "evidence_digest")
        return self


class XaiCaseSummary(XaiProfileModel):
    repository: Literal["xai-org/grok-1", "xai-org/grok-2"]
    resolved_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    member_count: int = Field(ge=1)
    declared_total_bytes: int = Field(ge=1)
    storage_distribution: dict[str, int]
    digest_distribution: dict[str, int]
    request_count: int = Field(ge=1)
    response_count: int = Field(ge=1)
    response_bytes: int = Field(ge=1)
    payload_bytes_downloaded: Literal[0]
    payload_comparable_member_count: Literal[0]
    evidence: ObjectReference


class XaiCaseStudyReport(XaiProfileModel):
    schema_id: Literal["omiv.xai-public-artifact-metadata-case-study.v1"] = Field(
        default="omiv.xai-public-artifact-metadata-case-study.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^xai_case_study_[0-9a-f]{32}$")
    title: Literal["OMIV xAI Public Artifact Metadata Assurance Case Study"]
    classification: Literal["XAI_PUBLIC_PINNED_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD"]
    cases: tuple[XaiCaseSummary, ...]
    established: tuple[str, ...]
    not_established: tuple[str, ...]
    provider_neutral_readiness: tuple[str, ...]
    affiliation: Literal["NO_XAI_ENDORSEMENT_OR_PUBLISHER_AUTHORIZATION_CLAIMED"]
    limitations: tuple[str, ...]
    report_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity(self) -> XaiCaseStudyReport:
        if tuple(item.repository for item in self.cases) != (
            "xai-org/grok-1",
            "xai-org/grok-2",
        ):
            raise ValueError("case study cases must be complete and ordered")
        _validate_identity(self, "report_id", "xai_case_study_", "report_digest")
        return self


def build_pinned_fixture(body: dict[str, Any]) -> PinnedXaiMetadataFixture:
    return PinnedXaiMetadataFixture.model_validate(
        identified(body, "fixture_id", "pinned_provider_metadata_", "fixture_digest")
    )


def load_pinned_fixture(path: Path) -> PinnedXaiMetadataFixture:
    raw = path.read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise OmivInputError("pinned metadata fixture exceeds byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OmivInputError(f"invalid pinned metadata fixture: {exc}") from exc
    return PinnedXaiMetadataFixture.model_validate(value)


def build_xai_practice_objects(fixture: PinnedXaiMetadataFixture) -> dict[str, Any]:
    subject = build_product_subject(
        ProductSubjectClass.MODEL_WEIGHTS,
        f"xai.{fixture.repository}.pinned-metadata",
        synthetic_scope(
            project="project.reconciliation-practice",
            environment="environment.offline",
        ),
    )
    locator = build_locator(
        subject,
        provider_kind=ProviderKind.HUGGING_FACE,
        provider_instance="huggingface.co",
        namespace=fixture.namespace,
        artifact_name=fixture.repository,
        artifact_kind="artifact.model-repository",
        requested_revision=fixture.resolved_revision,
        requested_revision_kind=RequestedRevisionKind.COMMIT,
        limitations=("Pinned fixture import does not assert xAI publisher authority.",),
    )
    plan = build_plan(
        locator,
        collection_mode=CollectionMode.PREVIOUSLY_COLLECTED_SNAPSHOT,
        adapter_id="omiv.adapter.huggingface-pinned-metadata",
        allowed_hosts=("huggingface.co",),
    )
    base_url = f"https://huggingface.co/api/models/xai-org/{fixture.repository}"
    execution = build_execution_record(
        plan,
        locator,
        network_use=NetworkUse.PUBLIC_METADATA_ONLY,
        contacted_hosts=("huggingface.co",),
        requested_urls=(
            f"{base_url}/revision/{fixture.resolved_revision}",
            f"{base_url}/tree/{fixture.resolved_revision}",
        ),
        request_count=fixture.request_count,
        response_count=fixture.response_count,
        response_bytes=fixture.response_bytes,
        available_at="NOT_RECORDED",
        observed_at="NOT_RECORDED",
    )
    members = tuple(_build_member(member) for member in fixture.members)
    snapshot = build_snapshot(
        locator,
        plan,
        execution,
        members,
        resolved_revision=fixture.resolved_revision,
        resolved_revision_kind=ResolvedRevisionKind.IMMUTABLE_COMMIT,
        listing_completeness=ListingCompleteness.COMPLETE_FOR_DECLARED_RESPONSE_SCOPE,
        provenance_strength=ProvenanceStrength.IMPORTED_UNVERIFIED,
        limitations=(
            "Snapshot was reconstructed offline from a reviewed pinned public-provider "
            "metadata fixture.",
            "Complete pinned provider listing does not establish complete model topology.",
            "Availability, observation time, publisher authority, freshness, and payload "
            "observation remain explicitly unestablished.",
        ),
    )
    topology = build_unavailable_topology(snapshot)
    completeness = assess_completeness(topology, snapshot)
    expectation = build_expectation(
        snapshot,
        expectation_scope=ExpectationScope.COMPLETE_REMOTE_MEMBER_SET,
        logical_root=f"artifact.xai-{fixture.repository}",
    )
    evidence = _build_evidence(
        fixture, locator, plan, execution, snapshot, topology, completeness, expectation
    )
    return {
        "locator": locator,
        "plan": plan,
        "execution": execution,
        "snapshot": snapshot,
        "topology": topology,
        "completeness": completeness,
        "expectation": expectation,
        "evidence": evidence,
    }


def build_case_study(
    fixtures: tuple[PinnedXaiMetadataFixture, ...],
    evidences: tuple[XaiPinnedMetadataEvidence, ...],
) -> XaiCaseStudyReport:
    by_repo = {item.repository: item for item in evidences}
    cases = []
    for fixture in sorted(fixtures, key=lambda item: item.repository):
        evidence = by_repo[fixture.repository]
        cases.append(
            {
                "repository": f"xai-org/{fixture.repository}",
                "resolved_revision": fixture.resolved_revision,
                "member_count": len(fixture.members),
                "declared_total_bytes": sum(item.declared_size for item in fixture.members),
                "storage_distribution": _storage_distribution(fixture),
                "digest_distribution": _digest_distribution(fixture),
                "request_count": fixture.request_count,
                "response_count": fixture.response_count,
                "response_bytes": fixture.response_bytes,
                "payload_bytes_downloaded": 0,
                "payload_comparable_member_count": 0,
                "evidence": reference(evidence, "evidence_id", "evidence_digest").model_dump(
                    mode="json"
                ),
            }
        )
    body = {
        "schema": "omiv.xai-public-artifact-metadata-case-study.v1",
        "title": "OMIV xAI Public Artifact Metadata Assurance Case Study",
        "classification": PRACTICE_CLASSIFICATION,
        "cases": cases,
        "established": [
            "Exact immutable repository revisions were pinned.",
            "Canonical member paths, declared sizes, storage representations, and typed "
            "provider identifiers were reconstructed.",
            "Bounded request/response accounting and zero payload download were preserved.",
        ],
        "not_established": [
            "Publisher authority, endorsement, model authenticity, and current state.",
            "Payload-byte equality, security safety, tokenizer/config parity, and "
            "runtime identity.",
            "Complete shard or tensor topology in the absence of an explicit parsed index.",
        ],
        "provider_neutral_readiness": [
            "The same core preserves Kimi evidence limitations without upgrading prior claims.",
            "DeepSeek remains a readiness profile until a reviewed pinned snapshot is supplied.",
            "Provider profiles import the core; the provider-neutral core imports no xAI profile.",
        ],
        "affiliation": "NO_XAI_ENDORSEMENT_OR_PUBLISHER_AUTHORIZATION_CLAIMED",
        "limitations": [
            "Large public repository listings are useful supply-chain cases because path, size, "
            "storage, digest, topology, payload, authority, and freshness claims must remain "
            "separate.",
            "The report derives from pinned fixtures and is not a source-evidence identity.",
        ],
    }
    return XaiCaseStudyReport.model_validate(
        identified(body, "report_id", "xai_case_study_", "report_digest")
    )


def render_case_study(report: XaiCaseStudyReport) -> str:
    lines = [
        f"# {report.title}",
        "",
        f"Classification: `{report.classification}`",
        "",
        "Large Grok repository snapshots exercise supply-chain separation between repository "
        "listing, storage identifiers, payload observation, topology, authority, and freshness.",
        "",
        "## Pinned cases",
        "",
    ]
    for case in report.cases:
        lines.extend(
            [
                f"- `{case.repository}` at `{case.resolved_revision}`: {case.member_count} "
                f"members, {case.declared_total_bytes} declared bytes; storage "
                f"`{json.dumps(case.storage_distribution, sort_keys=True)}`; digest semantics "
                f"`{json.dumps(case.digest_distribution, sort_keys=True)}`; "
                f"{case.request_count} requests/{case.response_count} responses/"
                f"{case.response_bytes} response bytes; 0 payload bytes.",
                "",
            ]
        )
    lines.extend(["## Established", "", *[f"- {item}" for item in report.established], ""])
    lines.extend(["## Not established", "", *[f"- {item}" for item in report.not_established], ""])
    lines.extend(
        [
            "## Provider-neutral readiness",
            "",
            *[f"- {item}" for item in report.provider_neutral_readiness],
            "",
            "No xAI endorsement, affiliation, or publisher authorization is claimed.",
            "",
        ]
    )
    return "\n".join(lines)


def _build_member(member: PinnedMember) -> RemoteMemberRecord:
    digests = tuple(
        build_digest_descriptor(
            DigestKind(item.kind),
            item.canonical_value,
            evidence_source="source.pinned-public-provider-metadata-fixture",
            observation_level=ObservationLevel.METADATA_ONLY,
            provenance_strength=ProvenanceStrength.IMPORTED_UNVERIFIED,
            limitations=(
                "Provider object metadata was imported without payload-byte observation.",
            ),
        )
        for item in member.digests
    )
    return build_member(
        member.path,
        role=RemoteMemberRole.UNKNOWN,
        logical_size=member.declared_size,
        digests=digests,
        storage_representation=StorageRepresentation(member.storage_representation),
        observation_level=ObservationLevel.METADATA_ONLY,
        provenance_strength=ProvenanceStrength.IMPORTED_UNVERIFIED,
        member_provenance="source.pinned-public-provider-metadata-fixture",
        available_at="NOT_RECORDED",
        limitations=(
            "Member role and shard topology were not inferred from the filename.",
            "No payload bytes were downloaded or hashed.",
        ),
    )


def _build_evidence(fixture: PinnedXaiMetadataFixture, *objects: Any) -> XaiPinnedMetadataEvidence:
    locator, plan, execution, snapshot, topology, completeness, expectation = objects
    integrations = tuple(
        PracticeIntegrationSummary.model_validate(
            {
                "integration_type": kind,
                "derived_status": status,
                "limitations": [limitation],
            }
        )
        for kind, status, limitation in (
            (
                "AUDIT",
                "PINNED_METADATA_AUDIT_REFERENCE_ONLY",
                "No signed audit-bundle member was created.",
            ),
            (
                "GOVERNANCE",
                "EVIDENCE_STATE_ONLY_NO_APPROVAL",
                "No governance approval was created.",
            ),
            (
                "HISTORICAL",
                "NOT_RECORDED_CANNOT_ESTABLISH_CUTOFF",
                "No historical availability time was inferred.",
            ),
            (
                "PASSPORT",
                "DERIVED_METADATA_SUMMARY_ONLY",
                "No payload or publisher authority was added.",
            ),
        )
    )
    body = {
        "schema": "omiv.xai-pinned-metadata-practice-evidence.v1",
        "classification": PRACTICE_CLASSIFICATION,
        "source_fixture": ObjectReference(
            schema_id=fixture.schema_id,
            object_id=fixture.fixture_id,
            object_digest=fixture.fixture_digest,
        ).model_dump(mode="json"),
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
        "namespace": fixture.namespace,
        "repository": fixture.repository,
        "resolved_revision": fixture.resolved_revision,
        "member_count": len(fixture.members),
        "declared_total_bytes": sum(item.declared_size for item in fixture.members),
        "storage_distribution": _storage_distribution(fixture),
        "digest_distribution": _digest_distribution(fixture),
        "payload_comparable_member_count": 0,
        "provider_listing_completeness": "COMPLETE_FOR_DECLARED_RESPONSE_SCOPE",
        "topology_status": "TOPOLOGY_UNAVAILABLE",
        "local_member_presence": "NOT_EVALUATED",
        "local_byte_match": "NOT_EVALUATED",
        "publisher_authority": "NOT_ESTABLISHED",
        "payload_download": "NOT_PERFORMED",
        "payload_bytes_observed": 0,
        "model_authenticity": "NOT_ESTABLISHED",
        "security_safety": "NOT_EVALUATED",
        "tokenizer_config_parity": "NOT_EVALUATED",
        "runtime_identity": "NOT_OBSERVED",
        "freshness_current_state": "NOT_ESTABLISHED",
        "observation_time": "NOT_RECORDED",
        "integration_summaries": [item.model_dump(mode="json") for item in integrations],
        "limitations": [
            "Complete pinned provider listing is not complete model topology.",
            "All remote members listed is not all local members present or matching payload bytes.",
            "Typed LFS, Xet, and provider object identifiers remain non-payload-comparable at "
            "metadata-only observation level.",
        ],
    }
    return XaiPinnedMetadataEvidence.model_validate(
        identified(body, "evidence_id", "xai_metadata_evidence_", "evidence_digest")
    )


def _storage_distribution(fixture: PinnedXaiMetadataFixture) -> dict[str, int]:
    return dict(sorted(Counter(item.storage_representation for item in fixture.members).items()))


def _digest_distribution(fixture: PinnedXaiMetadataFixture) -> dict[str, int]:
    return dict(
        sorted(Counter(digest.kind for item in fixture.members for digest in item.digests).items())
    )


def _validate_identity(value: StrictModel, id_field: str, prefix: str, digest_field: str) -> None:
    body = value.model_dump(mode="json", by_alias=True)
    digest = body.pop(digest_field)
    identity = body.pop(id_field)
    expected = prefix + canonical_sha256(body)[:32]
    if identity != expected or digest != canonical_sha256({**body, id_field: expected}):
        raise ValueError("canonical xAI fixture or evidence identity mismatch")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise json.JSONDecodeError(f"duplicate object key: {key}", key, 0)
        result[key] = value
    return result


def _is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)
