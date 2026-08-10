"""Phase 6B provider-neutral shard and remote/local reconciliation tests."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.payload_integrity.models import ObservedPayloadManifest
from omiv.payload_integrity.reporting import load_payload
from omiv.reconciliation.artifact_index import verify_reconciliation_artifact_index
from omiv.reconciliation.building import (
    build_digest_descriptor,
    build_locator,
    build_plan,
    compare_remote_to_local,
)
from omiv.reconciliation.collection import (
    BoundedMetadataClient,
    HttpMetadataResponse,
)
from omiv.reconciliation.examples import generate_reconciliation_examples
from omiv.reconciliation.indexes import (
    build_heuristic_hints,
    build_topology_from_indexes,
    load_shard_index,
    parse_shard_index_bytes,
)
from omiv.reconciliation.models import (
    CollectionLimits,
    CollectionMode,
    DigestKind,
    FindingKind,
    ObservationLevel,
    ProviderKind,
    ReconciliationArtifactIndex,
    ReconciliationStatus,
    RemoteArtifactLocator,
    RemoteDigestDescriptor,
    RemoteLocalReconciliationComparison,
    RemotePublisherAuthorityEvaluation,
    RemoteSnapshotExpectation,
    RemoteSnapshotManifest,
    RequestedRevisionKind,
    SemanticTarget,
    TopologyStatus,
)
from omiv.reconciliation.preservation import audit_baseline, reconstruct_reported_counts
from omiv.reconciliation.schema import SCHEMA_MODELS, load_reconciliation
from omiv.reconciliation_profiles.examples import generate_all_reconciliation_examples
from omiv.reconciliation_profiles.huggingface import collect_huggingface_metadata
from omiv.reconciliation_profiles.models import PracticeProfile
from omiv.reconciliation_profiles.xai import (
    PRACTICE_CLASSIFICATION,
    PinnedXaiMetadataFixture,
    XaiCaseStudyReport,
    XaiPinnedMetadataEvidence,
    load_pinned_fixture,
)
from omiv.trust.models import SignatureReport

RUNNER = CliRunner()
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase6b-generated")
    generate_all_reconciliation_examples(root)
    return root


@pytest.fixture(scope="module")
def xai_fixtures() -> tuple[PinnedXaiMetadataFixture, ...]:
    root = REPOSITORY_ROOT / "fixtures/reconciliation/xai"
    return tuple(
        load_pinned_fixture(root / f"{repository}.pinned-metadata.json")
        for repository in ("grok-1", "grok-2")
    )


def _load(root: Path, relative: str, model: type[Any]) -> Any:
    return load_reconciliation(root / relative, model)


def _local() -> ObservedPayloadManifest:
    return load_payload(
        REPOSITORY_ROOT / "payload-integrity/observations/local.manifest.json",
        ObservedPayloadManifest,
    )


def test_all_phase6b_schema_ids_are_registered() -> None:
    required = {
        "omiv.remote-artifact-locator.v1",
        "omiv.remote-snapshot-plan.v1",
        "omiv.remote-collection-execution-record.v1",
        "omiv.remote-digest-descriptor.v1",
        "omiv.remote-member-record.v1",
        "omiv.remote-snapshot-manifest.v1",
        "omiv.shard-topology.v1",
        "omiv.shard-completeness-assessment.v1",
        "omiv.remote-snapshot-expectation.v1",
        "omiv.remote-publisher-authority-evaluation.v1",
        "omiv.remote-local-reconciliation-policy.v1",
        "omiv.remote-local-reconciliation-comparison.v1",
        "omiv.remote-local-reconciliation-evidence.v1",
        "omiv.remote-local-reconciliation-report.v1",
        "omiv.remote-local-integration.v1",
        "omiv.reconciliation-artifact-index.v1",
    }
    assert required <= SCHEMA_MODELS.keys()


def test_generated_canonical_models_reconstruct(generated: Path) -> None:
    index = _load(
        generated,
        "reconciliation/artifact-index.json",
        ReconciliationArtifactIndex,
    )
    verify_reconciliation_artifact_index(generated, index)
    for entry in index.entries:
        if entry.schema_id in SCHEMA_MODELS:
            value = _load(generated, entry.path, SCHEMA_MODELS[entry.schema_id])
            assert value.model_dump(mode="json", by_alias=True)["schema"] == entry.schema_id


def test_objects_are_frozen(generated: Path) -> None:
    locator = _load(
        generated,
        "reconciliation/declarations/generic.locator.json",
        RemoteArtifactLocator,
    )
    with pytest.raises(ValidationError):
        locator.namespace = "changed"


@pytest.mark.parametrize(
    "provider_instance,namespace,artifact",
    [
        ("https://user:pass@example.invalid", "namespace", "artifact"),
        ("https://example.invalid?token=secret", "namespace", "artifact"),
        ("https://example.invalid#fragment", "namespace", "artifact"),
        ("example.invalid/path", "namespace", "artifact"),
        ("example.invalid", "../namespace", "artifact"),
        ("example.invalid", "namespace", "a/b"),
    ],
)
def test_locator_rejects_unsafe_or_ambiguous_values(
    provider_instance: str, namespace: str, artifact: str
) -> None:
    with pytest.raises(ValidationError):
        build_locator(
            _local().subject,
            provider_kind=ProviderKind.OTHER_DECLARED,
            provider_instance=provider_instance,
            namespace=namespace,
            artifact_name=artifact,
            artifact_kind="artifact.test",
            requested_revision="main",
            requested_revision_kind=RequestedRevisionKind.BRANCH,
        )


def test_requested_branch_is_not_immutable(generated: Path) -> None:
    locator = _load(
        generated,
        "reconciliation/declarations/generic.locator.json",
        RemoteArtifactLocator,
    )
    assert locator.requested_revision_kind == RequestedRevisionKind.TAG
    snapshot = _load(
        generated,
        "reconciliation/snapshots/generic.snapshot.json",
        RemoteSnapshotManifest,
    )
    assert snapshot.requested_revision == "fixture-v1"
    assert snapshot.resolved_revision != snapshot.requested_revision
    assert snapshot.resolved_revision_kind.value == "IMMUTABLE_CONTENT_DIGEST"


def test_payload_sha256_is_comparable() -> None:
    descriptor = build_digest_descriptor(DigestKind.PAYLOAD_SHA256, "a" * 64)
    assert descriptor.payload_comparable
    assert descriptor.semantic_target == SemanticTarget.PAYLOAD_BYTES


def test_lfs_requires_observed_pointer_semantics() -> None:
    metadata = build_digest_descriptor(DigestKind.LFS_OID_SHA256, "a" * 64)
    assert not metadata.payload_comparable
    pointer = build_digest_descriptor(
        DigestKind.LFS_OID_SHA256,
        "a" * 64,
        observation_level=ObservationLevel.POINTER_OBSERVED,
        payload_semantics_validated=True,
    )
    assert pointer.payload_comparable


def test_xet_declared_payload_sha_requires_explicit_label() -> None:
    object_id = build_digest_descriptor(DigestKind.XET_OBJECT_ID, "a" * 64)
    assert not object_id.payload_comparable
    declared = build_digest_descriptor(
        DigestKind.XET_DECLARED_PAYLOAD_SHA256,
        "a" * 64,
        observation_level=ObservationLevel.PAYLOAD_DIGEST_DECLARED,
        payload_semantics_validated=True,
    )
    assert declared.payload_comparable


@pytest.mark.parametrize(
    "kind,value",
    [
        (DigestKind.GIT_BLOB_SHA1, "a" * 40),
        (DigestKind.GIT_BLOB_SHA256, "a" * 64),
        (DigestKind.HTTP_ETAG, "a" * 64),
        (DigestKind.PROVIDER_OPAQUE_ID, "a" * 64),
    ],
)
def test_same_shaped_non_payload_ids_are_not_comparable(kind: DigestKind, value: str) -> None:
    assert not build_digest_descriptor(kind, value).payload_comparable


def test_invalid_payload_digest_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_digest_descriptor(DigestKind.PAYLOAD_SHA256, "a" * 40)


def test_digest_semantics_cannot_be_upgraded_by_flag() -> None:
    with pytest.raises(ValidationError):
        RemoteDigestDescriptor(
            kind=DigestKind.XET_OBJECT_ID,
            algorithm="PROVIDER_OPAQUE",
            canonical_value="a" * 64,
            semantic_target=SemanticTarget.PROVIDER_OBJECT,
            evidence_source="source.test",
            observation_level=ObservationLevel.METADATA_ONLY,
            provenance_strength="DECLARED",
            payload_comparable=True,
            limitations=(),
        )


def test_execution_graph_is_forward_only(generated: Path) -> None:
    execution = json.loads(
        (generated / "reconciliation/executions/generic.execution.json").read_text()
    )
    snapshot = json.loads(
        (generated / "reconciliation/snapshots/generic.snapshot.json").read_text()
    )
    assert "manifest_id" not in execution
    assert "manifest_digest" not in execution
    assert snapshot["execution_id"] == execution["execution_id"]
    assert snapshot["execution_digest"] == execution["execution_digest"]


def test_external_index_excludes_itself(generated: Path) -> None:
    index = _load(
        generated,
        "reconciliation/artifact-index.json",
        ReconciliationArtifactIndex,
    )
    assert "reconciliation/artifact-index.json" not in {entry.path for entry in index.entries}


def test_index_strict_utf8_and_json() -> None:
    with pytest.raises(OmivInputError, match="UTF-8"):
        parse_shard_index_bytes(b"\xff")
    with pytest.raises(OmivInputError, match="invalid JSON"):
        parse_shard_index_bytes(b'{"weight_map":')


def test_index_rejects_duplicate_keys() -> None:
    with pytest.raises(OmivInputError, match="duplicate object key"):
        parse_shard_index_bytes(b'{"weight_map":{"layer":"a.bin","layer":"b.bin"}}')


def test_index_rejects_unsafe_shard_paths() -> None:
    with pytest.raises(OmivInputError, match="unsafe shard path"):
        parse_shard_index_bytes(b'{"weight_map":{"layer":"../weight.bin"}}')


def test_index_byte_and_entry_limits() -> None:
    raw = b'{"weight_map":{"layer":"weight.bin"}}'
    with pytest.raises(OmivInputError, match="byte limit"):
        parse_shard_index_bytes(raw, maximum_bytes=10)
    with pytest.raises(OmivInputError, match="LIMIT_EXCEEDED"):
        parse_shard_index_bytes(raw, maximum_mappings=0)


def test_index_nesting_limit() -> None:
    raw = ('{"x":' * 140 + "0" + "}" * 140).encode()
    with pytest.raises(OmivInputError, match="nesting"):
        parse_shard_index_bytes(raw)


def test_realistic_large_index_is_supported() -> None:
    weight_map = {f"layer.{index}.weight": f"shards/{index % 32:05}.bin" for index in range(50_000)}
    parsed = parse_shard_index_bytes(json.dumps({"weight_map": weight_map}).encode())
    assert len(parsed.mappings) == 50_000
    assert len(parsed.declared_shards) == 32


def test_explicit_topology_is_deterministic(generated: Path) -> None:
    snapshot = _load(
        generated,
        "reconciliation/snapshots/generic.snapshot.json",
        RemoteSnapshotManifest,
    )
    index = load_shard_index(generated / "reconciliation/indexes/generic.weights.index.json")
    one = build_topology_from_indexes(snapshot, (index,))
    two = build_topology_from_indexes(snapshot, (index,))
    assert one == two
    assert one.status == TopologyStatus.EXPLICIT_TOPOLOGY_AVAILABLE


def test_conflicting_indexes_are_preserved(generated: Path) -> None:
    snapshot = _load(
        generated,
        "reconciliation/snapshots/generic.snapshot.json",
        RemoteSnapshotManifest,
    )
    one = parse_shard_index_bytes(
        b'{"weight_map":{"layer":"weights/part-00001-of-00002.payload"}}',
        source_name="one.json",
    )
    two = parse_shard_index_bytes(
        b'{"weight_map":{"layer":"weights/part-00002-of-00002.payload"}}',
        source_name="two.json",
    )
    topology = build_topology_from_indexes(snapshot, (one, two))
    assert topology.status == TopologyStatus.CONFLICTING_INDEXES
    assert topology.conflicting_references == ("layer",)


def test_missing_referenced_member_is_preserved(generated: Path) -> None:
    snapshot = _load(
        generated,
        "reconciliation/snapshots/generic.snapshot.json",
        RemoteSnapshotManifest,
    )
    index = parse_shard_index_bytes(b'{"weight_map":{"layer":"weights/missing.bin"}}')
    topology = build_topology_from_indexes(snapshot, (index,))
    assert topology.missing_referenced_remote_members == ("weights/missing.bin",)


def test_filename_heuristics_never_establish_membership(generated: Path) -> None:
    snapshot = _load(
        generated,
        "reconciliation/snapshots/generic.snapshot.json",
        RemoteSnapshotManifest,
    )
    topology = build_heuristic_hints(snapshot, ("weights/part-00001-of-00002.payload",))
    assert topology.status == TopologyStatus.HEURISTIC_ONLY
    assert not topology.required_shards


def test_exact_reconciliation_preserves_all_dimensions(generated: Path) -> None:
    comparison = _load(
        generated,
        "reconciliation/comparisons/exact.json",
        RemoteLocalReconciliationComparison,
    )
    assert comparison.status == ReconciliationStatus.EXACT_MATCH_FOR_RECONCILIATION_SCOPE
    for finding in comparison.findings:
        assert FindingKind.PATH_MATCH in finding.findings
        assert FindingKind.SIZE_MATCH in finding.findings
        assert FindingKind.DIGEST_MATCH in finding.findings
        assert FindingKind.ROLE_MATCH in finding.findings


def test_metadata_only_never_becomes_byte_match(generated: Path) -> None:
    comparison = _load(
        generated,
        "reconciliation/comparisons/metadata-only.json",
        RemoteLocalReconciliationComparison,
    )
    assert comparison.status == ReconciliationStatus.MEMBER_SET_MATCH_DIGESTS_UNAVAILABLE
    assert all(FindingKind.DIGEST_NOT_COMPARABLE in item.findings for item in comparison.findings)


def test_simultaneous_size_and_digest_mismatch(generated: Path) -> None:
    comparison = _load(
        generated,
        "reconciliation/comparisons/mismatch.json",
        RemoteLocalReconciliationComparison,
    )
    assert comparison.status == ReconciliationStatus.MISMATCH
    first = comparison.findings[0]
    assert FindingKind.SIZE_MISMATCH in first.findings
    assert FindingKind.DIGEST_MISMATCH in first.findings


def test_incomplete_local_observation_remains_incomplete(generated: Path) -> None:
    comparison = _load(
        generated,
        "reconciliation/comparisons/incomplete.json",
        RemoteLocalReconciliationComparison,
    )
    assert comparison.status == ReconciliationStatus.INCOMPLETE_LOCAL_OBSERVATION
    assert all(
        FindingKind.LOCAL_OBSERVATION_INCOMPLETE in item.findings for item in comparison.findings
    )


def test_mutable_revision_and_unauthorized_expectation_are_distinct(generated: Path) -> None:
    expectation = _load(
        generated,
        "reconciliation/expectations/generic.expectation.json",
        RemoteSnapshotExpectation,
    )
    authority = _load(
        generated,
        "reconciliation/expectations/publisher-authority.json",
        RemotePublisherAuthorityEvaluation,
    )
    unauthorized = compare_remote_to_local(expectation, _local(), authority=authority)
    assert unauthorized.status == ReconciliationStatus.EXPECTATION_UNAUTHORIZED
    mutable = expectation.model_copy(update={"resolved_revision_kind": "MUTABLE_BRANCH"})
    assert (
        compare_remote_to_local(mutable, _local()).status
        == ReconciliationStatus.MUTABLE_OR_UNRESOLVED_REVISION
    )


def test_subject_and_logical_root_must_match(generated: Path) -> None:
    expectation = _load(
        generated,
        "reconciliation/expectations/generic.expectation.json",
        RemoteSnapshotExpectation,
    )
    changed = expectation.model_copy(update={"logical_root": "artifact.other"})
    with pytest.raises(OmivInputError, match="logical roots"):
        compare_remote_to_local(changed, _local())


def test_namespace_and_trusted_signature_do_not_self_authorize(generated: Path) -> None:
    authority = _load(
        generated,
        "reconciliation/expectations/publisher-authority.json",
        RemotePublisherAuthorityEvaluation,
    )
    report = _load(
        generated,
        "reports/reconciliation/expectation.signature-report.json",
        SignatureReport,
    )
    assert report.overall_status.value == "TRUSTED_SIGNATURE_WITH_LIMITATIONS"
    assert authority.authority_outcome.value == "UNAUTHORIZED"


def test_practice_profiles_are_non_operational(generated: Path) -> None:
    profiles = [
        PracticeProfile.model_validate(
            json.loads((generated / f"reconciliation/profiles/{name}.json").read_text())
        )
        for name in ("kimi", "deepseek", "xai")
    ]
    assert all(not profile.operational_evidence for profile in profiles)
    assert all(not profile.payload_verified for profile in profiles)
    assert any("NOT_SUPPLIED" in item for item in profiles[1].limitations)
    assert profiles[2].status.value == "PUBLIC_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD"
    assert len(profiles[2].prior_evidence) == 2
    assert not profiles[2].authority_inferred_from_namespace


def test_exhaustive_prior_artifact_preservation_discovery() -> None:
    audit = audit_baseline(REPOSITORY_ROOT)
    assert len(audit.inventory) == 627
    assert len(audit.exclusions) == 237
    assert (
        audit.path_set_digest == "ece522cc790276b7b68e04b86fb927c8ab8b6d3d84d3428c3cffe8368fb5834e"
    )
    assert not audit.changed_or_missing_paths
    assert not audit.missing_prior_index_members
    assert not audit.missing_phase6a_generated_paths
    assert audit.phase6a_generated_count == 33
    paths = {item.relative_path for item in audit.inventory}
    assert "schemas/kimi_k3.yaml" in paths
    external = next(
        item for item in audit.inventory if item.relative_path == "reports/raw/kimi_k3_tensors.json"
    )
    assert external.git_blob_identity == "NOT_TRACKED_AT_BASELINE"
    external_audit = audit.external_artifacts[0]
    assert external_audit.expected_identity_status == "EXPECTED_IDENTITY_RECORDED"
    assert external_audit.availability_status in {
        "PRESENT_AND_VERIFIED",
        "NOT_AVAILABLE",
    }
    if external_audit.availability_status == "PRESENT_AND_VERIFIED":
        assert external.baseline_sha256 == external.current_sha256
    else:
        assert external.current_size is None
        assert external.current_sha256 is None


def test_prior_count_discrepancy_is_reconstructed_from_rules() -> None:
    assert reconstruct_reported_counts(REPOSITORY_ROOT) == {
        "phase6a_release_audit_pre_phase6a": 592,
        "narrow_phase5a_through_phase6a_delta": 497,
        "exhaustive_phase6b_baseline": 627,
    }


def test_pinned_xai_fixture_exact_reconstruction(
    xai_fixtures: tuple[PinnedXaiMetadataFixture, ...],
) -> None:
    expected = {
        "grok-1": (
            "5de83eb225f49624b424f1c8aa74f96983b5885c",
            773,
            318_239_889_830,
            {"DIRECT_FILE": 3, "XET_BACKED_OBJECT": 770},
            {"LFS_OID_SHA256": 770, "PROVIDER_OPAQUE_ID": 773, "XET_OBJECT_ID": 770},
        ),
        "grok-2": (
            "daf4395a80ad177386cfe39641b64fc12b1d70ed",
            44,
            539_040_431_665,
            {"DIRECT_FILE": 5, "XET_BACKED_OBJECT": 39},
            {"LFS_OID_SHA256": 39, "PROVIDER_OPAQUE_ID": 44, "XET_OBJECT_ID": 39},
        ),
    }
    for fixture in xai_fixtures:
        revision, count, total, storage, digests = expected[fixture.repository]
        assert fixture.classification == "PINNED_PUBLIC_PROVIDER_METADATA_FIXTURE"
        assert fixture.provider == "HUGGING_FACE"
        assert fixture.namespace == "xai-org"
        assert fixture.resolved_revision == revision
        assert len(fixture.members) == count
        assert sum(item.declared_size for item in fixture.members) == total
        assert Counter(item.storage_representation for item in fixture.members) == storage
        assert Counter(d.kind for item in fixture.members for d in item.digests) == digests
        assert len({item.path for item in fixture.members}) == count
        assert fixture.imported_tree_pages == 1
        assert fixture.request_count == fixture.response_count == 2
        assert fixture.redirect_count == fixture.weight_file_get_count == 0
        assert fixture.payload_bytes_downloaded == 0
        assert fixture.raw_response_retention == "NOT_RETAINED"


def test_xai_digest_semantics_remain_distinct_and_non_comparable(
    xai_fixtures: tuple[PinnedXaiMetadataFixture, ...],
) -> None:
    for fixture in xai_fixtures:
        for member in fixture.members:
            values = {item.kind: item.canonical_value for item in member.digests}
            if member.storage_representation == "XET_BACKED_OBJECT":
                assert len(set(values.values())) == 3
                assert "LFS_OID_SHA256" in values and "XET_OBJECT_ID" in values
            assert "PAYLOAD_SHA256" not in values
        assert fixture.payload_comparability == "DIGEST_NOT_COMPARABLE"


def test_generated_xai_objects_preserve_topology_authority_and_freshness(generated: Path) -> None:
    for repository in ("grok-1", "grok-2"):
        base = generated / "reconciliation/practice/xai" / repository
        evidence = XaiPinnedMetadataEvidence.model_validate(
            json.loads((base / "evidence.json").read_text())
        )
        snapshot = _load(
            generated,
            f"reconciliation/practice/xai/{repository}/snapshot.json",
            RemoteSnapshotManifest,
        )
        expectation = _load(
            generated,
            f"reconciliation/practice/xai/{repository}/expectation.json",
            RemoteSnapshotExpectation,
        )
        assert evidence.classification == PRACTICE_CLASSIFICATION
        assert evidence.payload_comparable_member_count == 0
        assert evidence.publisher_authority == "NOT_ESTABLISHED"
        assert evidence.topology_status == "TOPOLOGY_UNAVAILABLE"
        assert evidence.local_member_presence == evidence.local_byte_match == "NOT_EVALUATED"
        assert evidence.observation_time == "NOT_RECORDED"
        assert evidence.freshness_current_state == "NOT_ESTABLISHED"
        assert snapshot.observed_at == snapshot.available_at == "NOT_RECORDED"
        assert expectation.publisher_authority_evaluation_id is None
        assert all(member.comparable_digest is None for member in expectation.selected_members)


def test_xai_case_study_is_deterministic_and_bounded(generated: Path) -> None:
    path = generated / "reports/reconciliation/xai-public-metadata-case-study.json"
    report = XaiCaseStudyReport.model_validate(json.loads(path.read_text()))
    assert report.classification == PRACTICE_CLASSIFICATION
    assert [case.member_count for case in report.cases] == [773, 44]
    assert all(case.payload_bytes_downloaded == 0 for case in report.cases)
    assert all(case.payload_comparable_member_count == 0 for case in report.cases)
    markdown = (path.with_suffix(".md")).read_text()
    assert "No xAI endorsement" in markdown
    assert "interview" not in markdown.lower()


def test_offline_xai_generation_never_invokes_live_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from omiv.reconciliation_profiles import huggingface

    def prohibited(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline generation attempted live network collection")

    monkeypatch.setattr(huggingface.UrllibMetadataTransport, "request", prohibited)
    generate_all_reconciliation_examples(tmp_path)


def test_generated_dependency_graph_is_acyclic(generated: Path) -> None:
    index = _load(generated, "reconciliation/artifact-index.json", ReconciliationArtifactIndex)
    records = {
        entry.canonical_id: json.loads((generated / entry.path).read_text())
        for entry in index.entries
        if entry.path.endswith(".json")
    }
    canonical_digest_fields = {
        "omiv.remote-artifact-locator.v1": "locator_digest",
        "omiv.remote-snapshot-plan.v1": "plan_digest",
        "omiv.remote-collection-execution-record.v1": "execution_digest",
        "omiv.remote-member-record.v1": "member_digest",
        "omiv.remote-snapshot-manifest.v1": "manifest_digest",
        "omiv.shard-topology.v1": "topology_digest",
        "omiv.shard-completeness-assessment.v1": "assessment_digest",
        "omiv.remote-snapshot-expectation.v1": "expectation_digest",
        "omiv.remote-publisher-authority-evaluation.v1": "authority_evaluation_digest",
        "omiv.remote-local-reconciliation-comparison.v1": "comparison_digest",
        "omiv.remote-local-reconciliation-evidence.v1": "evidence_digest",
        "omiv.remote-local-reconciliation-report.v1": "report_digest",
        "omiv.remote-local-integration.v1": "integration_digest",
        "omiv.reconciliation-local-manifest-reference.v1": "reference_digest",
        "omiv.reconciliation-practice-profile.v1": "profile_digest",
        "omiv.xai-pinned-metadata-practice-evidence.v1": "evidence_digest",
        "omiv.xai-public-artifact-metadata-case-study.v1": "report_digest",
        "omiv.signed-object-envelope.v1": "envelope_digest",
        "omiv.signature-report.v1": "report_digest",
        "omiv.trust-policy.v1": "policy_digest",
        "omiv.trust-bundle.v1": "bundle_digest",
    }
    digest_to_id: dict[str, str] = {}
    for identity, record in records.items():
        field = canonical_digest_fields.get(record["schema"])
        if field is not None:
            digest_to_id[record[field]] = identity
    graph = {identity: set() for identity in records}

    def strings(value: object):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from strings(child)
        elif isinstance(value, list):
            for child in value:
                yield from strings(child)

    for identity, record in records.items():
        for value in strings(record):
            dependency = value if value in records else digest_to_id.get(value)
            if dependency is not None and dependency != identity:
                graph[identity].add(dependency)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identity: str) -> None:
        if identity in visiting:
            raise AssertionError(f"canonical dependency cycle through {identity}")
        if identity in visited:
            return
        visiting.add(identity)
        for dependency in graph[identity]:
            visit(dependency)
        visiting.remove(identity)
        visited.add(identity)

    for identity in graph:
        visit(identity)
    assert visited == set(graph)


def test_profiles_import_core_but_core_imports_no_profiles() -> None:
    core = REPOSITORY_ROOT / "src/omiv/reconciliation"
    assert all("reconciliation_profiles" not in path.read_text() for path in core.glob("*.py"))
    practice = (REPOSITORY_ROOT / "src/omiv/reconciliation_profiles/practice.py").read_text()
    assert "from omiv.reconciliation.models import" in practice


class FakeTransport:
    def __init__(self, responses: list[HttpMetadataResponse]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def request(self, url: str, *, timeout_seconds: float) -> HttpMetadataResponse:
        self.urls.append(url)
        if not self.responses:
            raise AssertionError("unexpected request")
        return self.responses.pop(0)


def _hf_inputs() -> tuple[RemoteArtifactLocator, Any]:
    locator = build_locator(
        _local().subject,
        provider_kind=ProviderKind.HUGGING_FACE,
        provider_instance="huggingface.co",
        namespace="organization.synthetic",
        artifact_name="metadata-fixture",
        artifact_kind="artifact.model-repository",
        requested_revision="main",
        requested_revision_kind=RequestedRevisionKind.BRANCH,
    )
    plan = build_plan(
        locator,
        collection_mode=CollectionMode.BOUNDED_PUBLIC_METADATA_COLLECTION,
        adapter_id="omiv.adapter.huggingface-metadata",
        allowed_hosts=("huggingface.co",),
    )
    return locator, plan


def test_live_adapter_uses_injected_transport_and_accounts_zero_payload() -> None:
    locator, plan = _hf_inputs()
    body = json.dumps(
        {
            "sha": "1" * 40,
        }
    ).encode()
    tree = json.dumps(
        [
            {
                "type": "file",
                "path": "weights/model.safetensors",
                "size": 123,
                "xetHash": "xet-object",
                "oid": "git-object",
            }
        ]
    ).encode()
    transport = FakeTransport(
        [
            HttpMetadataResponse(200, {"content-type": "application/json"}, body),
            HttpMetadataResponse(200, {"content-type": "application/json"}, tree),
        ]
    )
    captured: list[tuple[str, bytes]] = []
    execution, snapshot = collect_huggingface_metadata(
        locator,
        plan,
        observed_at="2026-08-02T00:00:00Z",
        transport=transport,
        raw_response_sink=lambda label, raw: captured.append((label, raw)),
    )
    assert execution.network_use.value == "PUBLIC_METADATA_ONLY"
    assert execution.request_count == execution.response_count == 2
    assert execution.response_bytes == len(body) + len(tree)
    assert execution.payload_bytes_downloaded == 0
    assert execution.payload_download.value == "NOT_PERFORMED"
    assert not snapshot.members[0].digests[0].payload_comparable
    assert snapshot.members[0].role.value == "UNKNOWN"
    assert [label for label, _ in captured] == ["model", "tree-0000"]


def test_live_adapter_follows_all_allowlisted_pagination() -> None:
    locator, plan = _hf_inputs()
    revision = "1" * 40
    model = json.dumps({"sha": revision}).encode()
    page_one = json.dumps(
        [{"type": "file", "path": "one.json", "size": 1, "oid": "1" * 40}]
    ).encode()
    page_two = json.dumps(
        [{"type": "file", "path": "two.json", "size": 2, "oid": "2" * 40}]
    ).encode()
    next_url = f"https://huggingface.co/api/models/test/tree/{revision}?cursor=public"
    transport = FakeTransport(
        [
            HttpMetadataResponse(200, {"content-type": "application/json"}, model),
            HttpMetadataResponse(
                200,
                {
                    "content-type": "application/json",
                    "link": f'<{next_url}>; rel="next"',
                },
                page_one,
            ),
            HttpMetadataResponse(200, {"content-type": "application/json"}, page_two),
        ]
    )
    captured: list[str] = []
    execution, snapshot = collect_huggingface_metadata(
        locator,
        plan,
        observed_at="NOT_RECORDED",
        transport=transport,
        raw_response_sink=lambda label, raw: captured.append(label),
    )
    assert execution.request_count == execution.response_count == 3
    assert [member.path for member in snapshot.members] == ["one.json", "two.json"]
    assert captured == ["model", "tree-0000", "tree-0001"]


def test_pinned_xai_fixtures_exclude_live_and_volatile_fields() -> None:
    for path in sorted((REPOSITORY_ROOT / "fixtures/reconciliation/xai").glob("*.json")):
        text = path.read_text()
        for prohibited in (
            "/tmp/",
            "cookie",
            "authorization",
            "signed_url",
            "downloads",
            "likes",
            "lastModified",
            "createdAt",
            "access_token",
            "?token=",
        ):
            assert prohibited not in text


def test_metadata_client_rejects_redirect_escape() -> None:
    client = BoundedMetadataClient(
        FakeTransport(
            [
                HttpMetadataResponse(
                    302,
                    {"location": "https://evil.example/metadata"},
                    b"",
                )
            ]
        ),
        allowed_hosts=("huggingface.co",),
        limits=CollectionLimits(),
    )
    with pytest.raises(OmivInputError, match="allowlist"):
        client.get_json_metadata("https://huggingface.co/api/models/test")


@pytest.mark.parametrize(
    "url",
    [
        "https://huggingface.co/path/model.safetensors",
        "https://huggingface.co/path/archive.zip",
        "https://huggingface.co/api/models/a?token=secret",
        "https://user:pass@huggingface.co/api/models/a",
    ],
)
def test_metadata_client_rejects_payloads_archives_and_credentials(url: str) -> None:
    client = BoundedMetadataClient(
        FakeTransport([]),
        allowed_hosts=("huggingface.co",),
        limits=CollectionLimits(),
    )
    with pytest.raises(OmivInputError):
        client.get_json_metadata(url)


def test_metadata_client_enforces_response_limit() -> None:
    limits = CollectionLimits(maximum_response_bytes=1024)
    client = BoundedMetadataClient(
        FakeTransport([HttpMetadataResponse(200, {}, b"x" * 1025)]),
        allowed_hosts=("huggingface.co",),
        limits=limits,
    )
    with pytest.raises(OmivInputError, match="INDIVIDUAL_RESPONSE_BYTES"):
        client.get_json_metadata("https://huggingface.co/api/models/test")


def test_metadata_client_retries_timeouts_with_bound() -> None:
    class TimeoutTransport:
        calls = 0

        def request(self, url: str, *, timeout_seconds: float) -> HttpMetadataResponse:
            self.calls += 1
            raise TimeoutError

    transport = TimeoutTransport()
    client = BoundedMetadataClient(
        transport,
        allowed_hosts=("huggingface.co",),
        limits=CollectionLimits(),
        maximum_retries=1,
    )
    with pytest.raises(OmivInputError, match="timed out"):
        client.get_json_metadata("https://huggingface.co/api/models/test")
    assert transport.calls == 2


def test_offline_generation_is_byte_deterministic(tmp_path: Path) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    first = generate_all_reconciliation_examples(one)
    second = generate_all_reconciliation_examples(two)
    assert first == second
    one_files = {
        path.relative_to(one): path.read_bytes() for path in one.rglob("*") if path.is_file()
    }
    two_files = {
        path.relative_to(two): path.read_bytes() for path in two.rglob("*") if path.is_file()
    }
    assert one_files == two_files
    assert len(first.entries) <= 110
    assert sum(path.suffix == ".md" for path in one_files) <= 3


def test_cli_import_index_shards_local_and_verify(generated: Path, tmp_path: Path) -> None:
    snapshot = generated / "reconciliation/snapshots/generic.snapshot.json"
    index = generated / "reconciliation/indexes/generic.weights.index.json"
    expectation = generated / "reconciliation/expectations/generic.expectation.json"
    local = REPOSITORY_ROOT / "payload-integrity/observations/local.manifest.json"
    assert RUNNER.invoke(app, ["reconcile", "import-snapshot", str(snapshot)]).exit_code == 0
    inspected = RUNNER.invoke(app, ["reconcile", "inspect-index", str(index)])
    assert inspected.exit_code == 0
    assert "logical_mapping_count" in inspected.stdout
    topology_output = tmp_path / "topology.json"
    assert (
        RUNNER.invoke(
            app,
            [
                "reconcile",
                "shards",
                "--snapshot",
                str(snapshot),
                "--index",
                str(index),
                "--output",
                str(topology_output),
            ],
        ).exit_code
        == 0
    )
    comparison_output = tmp_path / "comparison.json"
    local_result = RUNNER.invoke(
        app,
        [
            "reconcile",
            "local",
            "--expectation",
            str(expectation),
            "--local-manifest",
            str(local),
            "--output",
            str(comparison_output),
        ],
    )
    assert local_result.exit_code == 0
    assert "verified safe" not in local_result.stdout.lower()
    assert RUNNER.invoke(app, ["reconcile", "verify", str(comparison_output)]).exit_code == 0


def test_cli_metadata_only_uses_exit_one(generated: Path) -> None:
    comparison = generated / "reconciliation/comparisons/metadata-only.json"
    result = RUNNER.invoke(app, ["reconcile", "verify", str(comparison)])
    assert result.exit_code == 1
    assert "model_safety=NOT_VERIFIED" in result.stdout


def test_cli_live_collection_requires_explicit_opt_in(tmp_path: Path) -> None:
    subject = REPOSITORY_ROOT / "runtime/examples/subject.json"
    result = RUNNER.invoke(
        app,
        [
            "reconcile",
            "collect-hf-metadata",
            "--repo",
            "organization/repository",
            "--revision",
            "main",
            "--subject",
            str(subject),
            "--observed-at",
            "NOT_RECORDED",
            "--metadata-only",
            "--no-payload",
            "--output",
            str(tmp_path / "snapshot.json"),
            "--execution-output",
            str(tmp_path / "execution.json"),
        ],
    )
    assert result.exit_code == 2
    assert "requires --allow-network" in result.stderr


def test_generic_generator_does_not_change_phase6a_manifest(tmp_path: Path) -> None:
    before = (REPOSITORY_ROOT / "payload-integrity/observations/local.manifest.json").read_bytes()
    generate_reconciliation_examples(tmp_path)
    after = (REPOSITORY_ROOT / "payload-integrity/observations/local.manifest.json").read_bytes()
    assert after == before
