from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.payload_integrity import observation as observation_module
from omiv.payload_integrity import verify_payload_artifact_index
from omiv.payload_integrity.adapters import (
    bind_security,
    governance_adapter,
    historical_reference,
    runtime_expected_identity,
)
from omiv.payload_integrity.building import (
    artifact_set_digest,
    build_expectation,
    build_plan,
    build_policy,
    build_publisher_authority_evaluation,
    build_reference,
    compare_manifests,
    evaluate_evidence,
    materialization_known_as_of_cutoff,
    materialize_reference,
)
from omiv.payload_integrity.examples import generate_payload_examples
from omiv.payload_integrity.models import (
    MAX_FILES,
    ArtifactRole,
    ComparisonStatus,
    CompletionState,
    EvidenceOutcome,
    ExpectationScope,
    FindingKind,
    MaterializationState,
    ObservedPayloadManifest,
    PayloadArtifactIndex,
    PayloadExpectation,
    PayloadFileRecord,
    PayloadHashExecutionRecord,
    PrimaryContentDigest,
    ResourceLimits,
    RootMode,
)
from omiv.payload_integrity.observation import observe_payload
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.payload_integrity.reporting import load_payload, pretty_json, verify_report
from omiv.payload_integrity.schema import SCHEMA_MODELS
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubjectClass
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

runner = CliRunner()


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase6a-generated")
    generate_payload_examples(root)
    return root


@pytest.fixture
def subject():
    return build_product_subject(
        ProductSubjectClass.DEPLOYMENT_PACKAGE,
        "generic.payload-test",
        synthetic_scope(project="project.payload", environment="environment.local"),
    )


def _tree(root: Path) -> None:
    (root / ".hidden").write_bytes(b"hidden")
    (root / "nested").mkdir()
    (root / "nested/data.bin").write_bytes(b"abc" * 100_000)
    (root / "zero").write_bytes(b"")


def _observed(tmp_path: Path, subject):
    _tree(tmp_path)
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.test")
    return (*observe_payload(tmp_path, plan), plan)


def _expectation_trust_report(expectation: PayloadExpectation):
    private = Ed25519PrivateKey.from_private_bytes(bytes([43]) * 32)
    object_type = SignedObjectType.PAYLOAD_EXPECTATION
    purpose = SignaturePurpose.PAYLOAD_EXPECTATION_ISSUANCE
    key = build_key_identity(
        private, allowed_object_types=[object_type], allowed_purposes=[purpose]
    )
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic publisher",
        role="PUBLISHER",
        evidence=["2" * 64],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    policy = build_trust_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    raw = expectation.model_dump(mode="json", by_alias=True)
    descriptor = build_descriptor(raw, object_type, purpose, policy_id=policy.policy_id)
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
    return verify_envelope(envelope, bundle, policy)


def test_generated_schemas_and_index(generated: Path) -> None:
    index = load_payload(generated / "payload-integrity/artifact-index.json", PayloadArtifactIndex)
    verify_payload_artifact_index(generated, index)
    assert len(index.entries) < 90
    assert all((generated / x.path).is_file() for x in index.entries)
    assert set(SCHEMA_MODELS).issuperset(
        json.loads(path.read_text())["schema"]
        for path in generated.rglob("*.json")
        if "signed" not in path.parts and "signature-report" not in path.name
    )


def test_artifact_index_is_external_and_tampering_fails(generated: Path) -> None:
    index = load_payload(generated / "payload-integrity/artifact-index.json", PayloadArtifactIndex)
    assert "payload-integrity/artifact-index.json" not in {x.path for x in index.entries}
    tampered = index.model_copy(update={"total_size": index.total_size + 1})
    with pytest.raises(ValueError, match="total size"):
        verify_payload_artifact_index(generated, tampered)


def test_dependency_graph_is_derived_and_acyclic(generated: Path) -> None:
    index = load_payload(generated / "payload-integrity/artifact-index.json", PayloadArtifactIndex)
    records: dict[str, dict[str, object]] = {}
    id_to_node: dict[str, str] = {}
    digest_to_node: dict[str, str] = {}
    digest_fields = {
        "omiv.payload-inventory-plan.v1": "plan_digest",
        "omiv.payload-expectation.v1": "expectation_digest",
        "omiv.payload-expectation-materialization.v1": "materialization_digest",
        "omiv.payload-publisher-authority-evaluation.v1": "authority_evaluation_digest",
        "omiv.observed-payload-manifest.v1": "manifest_digest",
        "omiv.payload-hash-execution-record.v1": "execution_digest",
        "omiv.payload-manifest-comparison.v1": "comparison_digest",
        "omiv.payload-integrity-policy.v1": "policy_digest",
        "omiv.payload-integrity-evidence.v1": "evidence_digest",
        "omiv.payload-integrity-report.v1": "report_digest",
        "omiv.payload-integrity-integration.v1": "integration_digest",
        "omiv.signed-object-envelope.v1": "envelope_digest",
        "omiv.signature-verification-report.v1": "report_digest",
        "omiv.trust-policy.v1": "policy_digest",
        "omiv.trust-bundle.v1": "bundle_digest",
    }
    for entry in index.entries:
        node = f"{entry.schema_id}:{entry.canonical_id}"
        id_to_node[entry.canonical_id] = node
        if entry.path.endswith(".json"):
            record = json.loads((generated / entry.path).read_text())
            records[node] = record
            digest_field = digest_fields.get(entry.schema_id)
            if digest_field and isinstance(record.get(digest_field), str):
                digest_to_node[str(record[digest_field])] = node
    index_node = f"{index.schema_id}:{index.index_id}"
    graph: dict[str, set[str]] = {node: set() for node in records}
    graph[index_node] = set(records)

    def strings(value: object):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for child in value.values():
                yield from strings(child)
        elif isinstance(value, list):
            for child in value:
                yield from strings(child)

    for node, record in records.items():
        for value in strings(record):
            dependency = id_to_node.get(value) or digest_to_node.get(value)
            if dependency is not None and dependency != node:
                graph[node].add(dependency)
        assert node not in graph[node]

    execution_node = next(
        node for node in graph if node.startswith("omiv.payload-hash-execution-record.v1:")
    )
    manifest_node = next(
        node for node in graph if node.startswith("omiv.observed-payload-manifest.v1:")
    )
    assert execution_node in graph[manifest_node]
    assert manifest_node not in graph[execution_node]
    assert "result_reference_status" in records[execution_node]
    assert index_node not in graph[index_node]
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: tuple[str, ...]) -> None:
        if node in visiting:
            raise AssertionError("canonical dependency cycle: " + " -> ".join((*path, node)))
        if node in visited:
            return
        visiting.add(node)
        for dependency in sorted(graph[node]):
            visit(dependency, (*path, node))
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node, ())
    assert visited == set(graph)


def test_directory_observation_streaming_and_hidden(tmp_path: Path, subject) -> None:
    manifest, execution, _ = _observed(tmp_path, subject)
    assert manifest.completion_state == CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE
    assert [x.path for x in manifest.files] == [".hidden", "nested/data.bin", "zero"]
    assert manifest.coverage.hashed_bytes == 300_006
    assert execution.network_use == "NONE"
    assert execution.model_deserialization == "NOT_PERFORMED"
    assert execution.model_execution == "NOT_PERFORMED"
    assert execution.available_at == "NOT_RECORDED"
    assert str(tmp_path) not in pretty_json(manifest)


def test_digest_independent_of_chunk_size(tmp_path: Path, subject) -> None:
    _tree(tmp_path)
    small = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.test", chunk_size=64 * 1024)
    large = build_plan(
        subject, RootMode.DIRECTORY_ROOT, "artifact.test", chunk_size=2 * 1024 * 1024
    )
    one, _ = observe_payload(tmp_path, small)
    two, _ = observe_payload(tmp_path, large)
    assert one.artifact_set_payload_digest == two.artifact_set_payload_digest
    assert [x.primary_content_digest for x in one.files] == [
        x.primary_content_digest for x in two.files
    ]


def test_single_file_logical_name_independent_of_local_basename(tmp_path: Path, subject) -> None:
    first = tmp_path / "machine-a"
    second = tmp_path / "machine-b"
    first.write_bytes(b"same")
    second.write_bytes(b"same")
    plan = build_plan(
        subject, RootMode.SINGLE_FILE_ROOT, "artifact.single", logical_name="weights.payload"
    )
    one, _ = observe_payload(first, plan)
    two, _ = observe_payload(second, plan)
    assert one.artifact_set_payload_digest == two.artifact_set_payload_digest
    assert one.files[0].path == "weights.payload"


def test_single_file_requires_logical_name(subject) -> None:
    with pytest.raises(ValidationError):
        build_plan(subject, RootMode.SINGLE_FILE_ROOT, "artifact.single")


@pytest.mark.parametrize(
    "unsafe",
    [
        "/abs",
        "C:/drive",
        "//unc/path",
        "../escape",
        "a/./b",
        "a//b",
        "a\\..\\b",
        "a\x00b",
        "a\x01b",
        "cafe\u0301",
        "name.",
        "name ",
        "CON",
        "con.json",
        "LPT1.txt",
        "bad\udcff",
        "bad\uffff",
        "https://example/path",
    ],
)
def test_unsafe_paths_rejected(unsafe: str) -> None:
    with pytest.raises(ValueError):
        validate_portable_path(unsafe)


def test_valid_unicode_and_collision_rules() -> None:
    assert validate_portable_path("nested/café/資料.json") == "nested/café/資料.json"
    with pytest.raises(ValueError):
        validate_path_set(("A/file", "a/file"))
    with pytest.raises(ValueError):
        validate_path_set(("file", "file/child"))
    with pytest.raises(ValueError):
        validate_path_set(("same", "same"))


def test_symlink_root_and_member_rejected(tmp_path: Path, subject) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "file").write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.test")
    with pytest.raises(OmivInputError):
        observe_payload(link, plan)
    (target / "member-link").symlink_to(target / "file")
    manifest, _ = observe_payload(target, plan)
    assert manifest.completion_state == CompletionState.INCOMPLETE
    assert FindingKind.UNSUPPORTED_ENTRY in manifest.findings or manifest.coverage.unsupported_paths


def test_hardlink_alias_rejected(tmp_path: Path, subject) -> None:
    first = tmp_path / "first"
    first.write_text("same")
    os.link(first, tmp_path / "second")
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.test")
    manifest, _ = observe_payload(tmp_path, plan)
    assert manifest.completion_state == CompletionState.INCOMPLETE
    assert manifest.coverage.rejected_hardlink_paths
    assert FindingKind.HARDLINK_ALIAS_REJECTED in manifest.findings


def test_hardlink_detection_unavailable_prevents_complete(
    tmp_path: Path, subject, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "file").write_text("x")
    monkeypatch.setattr(observation_module, "_identity", lambda value: None)
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.test")
    manifest, _ = observe_payload(tmp_path, plan)
    assert manifest.coverage.hardlink_detection == "UNAVAILABLE"
    assert manifest.completion_state == CompletionState.INCOMPLETE


def test_opened_file_changed_during_hash(
    tmp_path: Path, subject, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "file"
    path.write_bytes(b"a" * 200_000)
    original_read = observation_module.os.read
    changed = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        block = original_read(descriptor, size)
        if block and not changed:
            changed = True
            with path.open("ab") as handle:
                handle.write(b"changed")
        return block

    monkeypatch.setattr(observation_module.os, "read", mutating_read)
    plan = build_plan(
        subject,
        RootMode.SINGLE_FILE_ROOT,
        "artifact.race",
        logical_name="file.payload",
        chunk_size=64 * 1024,
    )
    manifest, _ = observe_payload(path, plan)
    assert FindingKind.OPENED_FILE_CHANGED_DURING_HASH in manifest.findings


def test_stable_descriptor_with_rebound_path(
    tmp_path: Path, subject, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "file"
    path.write_bytes(b"a" * 200_000)
    displaced = tmp_path / "old"
    original_read = observation_module.os.read
    rebound = False

    def rebinding_read(descriptor: int, size: int) -> bytes:
        nonlocal rebound
        block = original_read(descriptor, size)
        if block and not rebound:
            rebound = True
            path.rename(displaced)
            path.write_bytes(b"b" * 200_000)
        return block

    monkeypatch.setattr(observation_module.os, "read", rebinding_read)
    plan = build_plan(
        subject,
        RootMode.SINGLE_FILE_ROOT,
        "artifact.race",
        logical_name="file.payload",
        chunk_size=64 * 1024,
    )
    manifest, _ = observe_payload(path, plan)
    assert FindingKind.PATH_REBOUND_DURING_OBSERVATION in manifest.findings


def test_root_changed_second_inventory(
    tmp_path: Path, subject, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "file").write_text("x")
    original_hash = observation_module._hash_file
    added = False

    def changing_hash(entry, chunk_size):
        nonlocal added
        result = original_hash(entry, chunk_size)
        if not added:
            added = True
            (tmp_path / "new-file").write_text("new")
        return result

    monkeypatch.setattr(observation_module, "_hash_file", changing_hash)
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.race")
    manifest, _ = observe_payload(tmp_path, plan)
    assert FindingKind.ROOT_CHANGED_DURING_OBSERVATION in manifest.findings


def test_fifo_unsupported_where_available(tmp_path: Path, subject) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    os.mkfifo(tmp_path / "pipe")
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.test")
    manifest, _ = observe_payload(tmp_path, plan)
    assert manifest.coverage.unsupported_paths == ("pipe",)
    assert manifest.completion_state == CompletionState.INCOMPLETE


def test_complete_selected_partial_and_mismatch(tmp_path: Path, subject) -> None:
    manifest, execution, _ = _observed(tmp_path, subject)
    complete = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    exact = compare_manifests(complete, manifest)
    assert exact.status == ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE
    selected = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files[:1],
        ExpectationScope.SELECTED_REQUIRED_MEMBERS,
    )
    selected_result = compare_manifests(selected, manifest)
    assert selected_result.status == ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE
    assert selected_result.outside_scope_members
    selected_evidence = evaluate_evidence(
        manifest, execution.execution_id, selected_result, selected
    )
    assert selected_evidence.outcome == EvidenceOutcome.MATCHES_EXPECTATION_SCOPE
    changed = list(manifest.files)
    row = changed[0]
    changed[0] = row.model_copy(
        update={
            "size": row.size + 1,
            "primary_content_digest": PrimaryContentDigest(value="f" * 64),
        }
    )
    expectation = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        tuple(changed),
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    result = compare_manifests(expectation, manifest)
    assert result.status == ComparisonStatus.MISMATCH
    finding = next(x for x in result.findings if x.path == row.path)
    assert FindingKind.SIZE_MISMATCH in finding.findings
    assert FindingKind.CONTENT_DIGEST_MISMATCH in finding.findings


def test_extra_is_factual_and_rename_is_missing_plus_extra(tmp_path: Path, subject) -> None:
    manifest, _, _ = _observed(tmp_path, subject)
    expectation = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files[1:],
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    result = compare_manifests(expectation, manifest)
    assert result.extra_members == (manifest.files[0].path,)
    renamed = manifest.files[0].model_copy(update={"path": "renamed"})
    expectation2 = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        (renamed, *manifest.files[1:]),
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    result2 = compare_manifests(expectation2, manifest)
    assert (
        renamed.path in result2.missing_members and manifest.files[0].path in result2.extra_members
    )


def test_digest_reference_never_exact(tmp_path: Path, subject) -> None:
    manifest, _, _ = _observed(tmp_path, subject)
    complete = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    reference = build_reference(
        complete,
        state=MaterializationState.DIGEST_REFERENCE_ONLY,
        available_at="2026-01-01T00:00:00Z",
    )
    reference_bytes = pretty_json(reference)
    assert compare_manifests(reference, manifest).status == ComparisonStatus.DIGEST_REFERENCE_ONLY
    supplied = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
        available_at="2026-01-03T00:00:00Z",
    )
    # Bind this declaration to the independently supplied canonical object.
    reference = build_reference(
        supplied,
        available_at="2026-01-01T00:00:00Z",
    )
    reference_bytes = pretty_json(reference)
    materialized = materialize_reference(reference, supplied, evaluated_at="2026-01-03T00:00:00Z")
    assert materialized.materialization_state == MaterializationState.FULL_EXPECTATION_AVAILABLE
    assert materialized.reference_expectation_id == reference.expectation_id
    assert materialized.supplied_expectation_id == supplied.expectation_id
    compared = compare_manifests(
        supplied, manifest, reference=reference, materialization=materialized
    )
    assert compared.status == (ComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE)
    assert compared.reference_expectation_id == reference.expectation_id
    assert compared.supplied_expectation_id == supplied.expectation_id
    assert pretty_json(reference) == reference_bytes
    assert not materialization_known_as_of_cutoff(materialized, "2026-01-02T00:00:00Z")
    assert materialization_known_as_of_cutoff(materialized, "2026-01-03T00:00:00Z")


@pytest.mark.parametrize(
    "field,value",
    [
        ("expectation_id", "payload_expectation_" + "0" * 32),
        ("expectation_digest", "0" * 64),
        ("root_mode", RootMode.SINGLE_FILE_ROOT),
        ("logical_root", "artifact.wrong"),
        ("expectation_scope", ExpectationScope.SELECTED_REQUIRED_MEMBERS),
    ],
)
def test_reference_rejects_wrong_supplied_identity(
    tmp_path: Path, subject, field: str, value: object
) -> None:
    manifest, _, _ = _observed(tmp_path, subject)
    supplied = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    reference = build_reference(supplied)
    with pytest.raises(OmivInputError, match="identity or scope mismatch"):
        materialize_reference(reference, supplied.model_copy(update={field: value}))


def test_reference_authority_does_not_transfer(tmp_path: Path, subject) -> None:
    manifest, execution, _ = _observed(tmp_path, subject)
    supplied = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    reference = build_reference(supplied)
    reference_authority = build_publisher_authority_evaluation(
        reference,
        trust_report=_expectation_trust_report(reference),
        authorized=True,
    )
    materialization = materialize_reference(reference, supplied)
    comparison = compare_manifests(
        supplied, manifest, reference=reference, materialization=materialization
    )
    evidence = evaluate_evidence(manifest, execution.execution_id, comparison, supplied)
    assert materialization.authority_transfer == "NOT_PERFORMED"
    assert evidence.publisher_authority_status == "NOT_EVALUATED"
    assert evidence.outcome == EvidenceOutcome.MATCHES_COMPLETE_EXPECTATION
    with pytest.raises(OmivInputError, match="authority evaluation scope mismatch"):
        evaluate_evidence(
            manifest,
            execution.execution_id,
            comparison,
            supplied,
            authority_evaluation=reference_authority,
        )


def test_reference_rejects_wrong_schema_and_subject(tmp_path: Path, subject) -> None:
    manifest, _, _ = _observed(tmp_path, subject)
    supplied = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    reference = build_reference(supplied)
    malformed = supplied.model_dump(mode="json", by_alias=True)
    malformed["schema"] = "omiv.payload-inventory-plan.v1"
    with pytest.raises(ValidationError):
        PayloadExpectation.model_validate(malformed)
    other_subject = build_product_subject(
        ProductSubjectClass.DEPLOYMENT_PACKAGE,
        "generic.payload-other",
        synthetic_scope(project="project.payload", environment="environment.local"),
    )
    wrong_subject = build_expectation(
        other_subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    with pytest.raises(OmivInputError, match="identity or scope mismatch"):
        materialize_reference(reference, wrong_subject)


def test_role_and_domain_separated_identity(subject) -> None:
    digest = PrimaryContentDigest(value=hashlib.sha256(b"x").hexdigest())
    absent = PayloadFileRecord(
        path="x",
        logical_file_kind="regular.file",
        size=1,
        primary_content_digest=digest,
        artifact_role=ArtifactRole.ABSENT_ROLE,
    )
    primary = absent.model_copy(update={"artifact_role": ArtifactRole.PRIMARY})
    optional = absent.model_copy(update={"artifact_role": ArtifactRole.OPTIONAL_COMPANION})
    assert (
        len(
            {
                artifact_set_digest(RootMode.DIRECTORY_ROOT, "root.x", (x,))
                for x in (absent, primary, optional)
            }
        )
        == 3
    )
    second = primary.model_copy(update={"path": "y"})
    assert artifact_set_digest(
        RootMode.DIRECTORY_ROOT, "root.x", (absent, second)
    ) == artifact_set_digest(RootMode.DIRECTORY_ROOT, "root.x", (second, absent))


def test_other_declared_requires_detail() -> None:
    digest = PrimaryContentDigest(value="0" * 64)
    with pytest.raises(ValidationError):
        PayloadFileRecord(
            path="x",
            logical_file_kind="regular.file",
            size=0,
            primary_content_digest=digest,
            artifact_role=ArtifactRole.OTHER_DECLARED,
        )


def test_policy_and_publisher_authority(tmp_path: Path, subject) -> None:
    manifest, execution, _ = _observed(tmp_path, subject)
    unsigned = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    result = compare_manifests(unsigned, manifest)
    policy = build_policy(
        "payload-policy.strict.v1",
        subject.scope,
        expectation_scope=ExpectationScope.COMPLETE_DECLARED_FILE_SET,
        require_authorized_publisher=True,
    )
    evidence = evaluate_evidence(manifest, execution.execution_id, result, unsigned, policy)
    assert evidence.outcome == EvidenceOutcome.MATCHES_COMPLETE_EXPECTATION
    assert evidence.policy_satisfied is False
    authorized = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    authority = build_publisher_authority_evaluation(
        authorized,
        trust_report=_expectation_trust_report(authorized),
        authorized=True,
    )
    accepted = evaluate_evidence(
        manifest,
        execution.execution_id,
        compare_manifests(authorized, manifest),
        authorized,
        policy,
        authority,
    )
    assert accepted.outcome == EvidenceOutcome.MATCHES_AUTHORIZED_COMPLETE_EXPECTATION
    assert accepted.policy_satisfied is True


def test_authority_and_exact_input_bindings_fail_closed(tmp_path: Path, subject) -> None:
    manifest, execution, _ = _observed(tmp_path, subject)
    expectation = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        "artifact.test",
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    comparison = compare_manifests(expectation, manifest)
    with pytest.raises(OmivInputError, match="execution reference"):
        evaluate_evidence(manifest, "payload_execution_wrong", comparison, expectation)
    for field, value in (
        ("execution_id", "payload_execution_" + "0" * 32),
        ("execution_digest", "0" * 64),
    ):
        changed = execution.model_dump(mode="json", by_alias=True)
        changed[field] = value
        with pytest.raises(ValidationError, match="canonical identity or digest"):
            PayloadHashExecutionRecord.model_validate(changed)
    for field, value in (
        ("execution_id", "payload_execution_" + "0" * 32),
        ("execution_digest", "0" * 64),
        ("manifest_id", "observed_payload_" + "0" * 32),
        ("manifest_digest", "0" * 64),
    ):
        changed = manifest.model_dump(mode="json", by_alias=True)
        changed[field] = value
        with pytest.raises(ValidationError, match="canonical identity or digest"):
            ObservedPayloadManifest.model_validate(changed)


def test_phase5_adapter_boundaries(tmp_path: Path, subject) -> None:
    manifest, execution, _ = _observed(tmp_path, subject)
    evidence = evaluate_evidence(manifest, execution.execution_id)
    assert not bind_security(
        evidence,
        security_subject_id=evidence.subject_id,
        security_payload_digest="0" * 64,
        security_evidence_id="security.test",
        security_evidence_digest="1" * 64,
        security_scope_digest=evidence.subject_scope_digest,
        complete_coverage=True,
    ).accepted
    assert bind_security(
        evidence,
        security_subject_id=evidence.subject_id,
        security_payload_digest=evidence.artifact_set_payload_digest,
        security_evidence_id="security.test",
        security_evidence_digest="1" * 64,
        security_scope_digest=evidence.subject_scope_digest,
        complete_coverage=True,
    ).accepted
    assert not bind_security(
        evidence,
        security_subject_id="product_subject_wrong",
        security_payload_digest=evidence.artifact_set_payload_digest,
        security_evidence_id="security.wrong-subject",
        security_evidence_digest="3" * 64,
        security_scope_digest=evidence.subject_scope_digest,
        complete_coverage=True,
    ).accepted
    assert not bind_security(
        evidence,
        security_subject_id=evidence.subject_id,
        security_payload_digest=evidence.artifact_set_payload_digest,
        security_evidence_id="security.wrong-scope",
        security_evidence_digest="4" * 64,
        security_scope_digest="5" * 64,
        complete_coverage=True,
    ).accepted
    partial = bind_security(
        evidence,
        security_subject_id=evidence.subject_id,
        security_payload_digest=evidence.artifact_set_payload_digest,
        security_evidence_id="security.partial",
        security_evidence_digest="2" * 64,
        security_scope_digest=evidence.subject_scope_digest,
        complete_coverage=False,
        security_limitations=("Scanner coverage was partial.",),
    )
    assert not partial.accepted and partial.coverage_status == "PARTIAL"
    runtime = runtime_expected_identity(evidence)
    assert "EXPECTED_RUNTIME_IDENTITY_ONLY" in runtime.source_status
    assert runtime.expected_runtime_payload_digest == evidence.artifact_set_payload_digest
    assert runtime.observed_runtime_payload_digest is None
    assert runtime.runtime_observer_assertion == "NOT_CREATED"
    assert runtime.deployment_status == "NOT_PERFORMED"
    assert runtime.runtime_continuity == "NOT_EVALUATED"
    assert runtime.behavioral_correctness == "NOT_EVALUATED"
    assert not governance_adapter(evidence).accepted
    historical = historical_reference(evidence)
    assert not historical.accepted
    assert historical.available_at == "NOT_RECORDED"
    assert historical.observed_at == "NOT_RECORDED"
    assert historical.evaluated_at == "NOT_RECORDED"
    assert historical.known_as_of_cutoff_eligible is False
    assert evidence.outcome == EvidenceOutcome.OBSERVED


def test_report_reconstruction(generated: Path) -> None:
    report = json.loads(
        (generated / "reports/payload-integrity/local.payload-report.json").read_text()
    )
    model = SCHEMA_MODELS[report["schema"]].model_validate(report)
    assert verify_report(model, model.evidence, model.comparison) == model


def test_signatures_do_not_create_publisher_authority(generated: Path) -> None:
    expectation = load_payload(
        generated / "payload-integrity/expectations/selected.json", PayloadExpectation
    )
    private = Ed25519PrivateKey.from_private_bytes(bytes([42]) * 32)
    object_type = SignedObjectType.PAYLOAD_EXPECTATION
    purpose = SignaturePurpose.PAYLOAD_EXPECTATION_ISSUANCE
    key = build_key_identity(
        private, allowed_object_types=[object_type], allowed_purposes=[purpose]
    )
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Internal CI",
        role="CI",
        evidence=["1" * 64],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    policy = build_trust_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    bundle = build_trust_bundle(
        [build_trust_root(key)], [key], identities=[signer], bindings=[binding]
    )
    raw = expectation.model_dump(mode="json", by_alias=True)
    descriptor = build_descriptor(raw, object_type, purpose, policy_id=policy.policy_id)
    signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
    assert "TRUSTED_SIGNATURE" in verify_envelope(envelope, bundle, policy).overall_status.value
    assert expectation.authority_status == "NOT_EVALUATED"


def test_generated_signatures_are_representative_and_detached(generated: Path) -> None:
    expected = {
        "expectation.envelope.json": "PAYLOAD_EXPECTATION",
        "manifest.envelope.json": "OBSERVED_PAYLOAD_MANIFEST",
        "evidence.envelope.json": "PAYLOAD_INTEGRITY_EVIDENCE",
    }
    envelopes = sorted((generated / "payload-integrity/signed").glob("*.envelope.json"))
    assert {path.name for path in envelopes} == set(expected)
    unsigned_paths = {
        "expectation.envelope.json": "payload-integrity/expectations/complete.json",
        "manifest.envelope.json": "payload-integrity/observations/local.manifest.json",
        "evidence.envelope.json": "payload-integrity/evidence/authorized-complete.json",
    }
    for envelope_path in envelopes:
        envelope = json.loads(envelope_path.read_text())
        unsigned = json.loads((generated / unsigned_paths[envelope_path.name]).read_text())
        assert envelope["signed_object_type"] == expected[envelope_path.name]
        assert envelope["signed_object"] == unsigned
        assert "signatures" not in unsigned
    assert not list(generated.rglob("*.pem"))
    assert not list(generated.rglob("*.key"))


def test_metadata_scalability_10000_records() -> None:
    digest = PrimaryContentDigest(value="a" * 64)
    records = tuple(
        PayloadFileRecord(
            path=f"files/{i:05d}",
            logical_file_kind="regular.file",
            size=i,
            primary_content_digest=digest,
            artifact_role=ArtifactRole.ABSENT_ROLE,
        )
        for i in range(10_000)
    )
    first = artifact_set_digest(RootMode.DIRECTORY_ROOT, "artifact.scale", records)
    assert first == artifact_set_digest(
        RootMode.DIRECTORY_ROOT, "artifact.scale", tuple(reversed(records))
    )


def test_large_sparse_streaming(tmp_path: Path, subject) -> None:
    path = tmp_path / "large"
    with path.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)
    plan = build_plan(
        subject,
        RootMode.SINGLE_FILE_ROOT,
        "artifact.large",
        logical_name="large.payload",
        chunk_size=64 * 1024,
    )
    manifest, _ = observe_payload(path, plan)
    assert manifest.coverage.hashed_bytes == 32 * 1024 * 1024


def test_file_count_limit(tmp_path: Path, subject) -> None:
    (tmp_path / "a").write_text("a")
    (tmp_path / "b").write_text("b")
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.limit")
    limited = plan.model_copy(
        update={"limits": plan.limits.model_copy(update={"maximum_files": 1})}
    )
    with pytest.raises(Exception, match="LIMIT_EXCEEDED:FILE_COUNT"):
        observe_payload(tmp_path, limited)
    assert MAX_FILES == 100_000


def test_declared_resource_limit_boundaries() -> None:
    assert ResourceLimits(maximum_files=MAX_FILES).maximum_files == MAX_FILES
    with pytest.raises(ValidationError):
        ResourceLimits(maximum_files=MAX_FILES + 1)
    assert ResourceLimits(maximum_depth=64).maximum_depth == 64
    with pytest.raises(ValidationError):
        ResourceLimits(maximum_depth=65)
    assert ResourceLimits(maximum_path_length=1024).maximum_path_length == 1024
    with pytest.raises(ValidationError):
        ResourceLimits(maximum_path_length=1025)
    assert ResourceLimits(maximum_component_length=255).maximum_component_length == 255
    with pytest.raises(ValidationError):
        ResourceLimits(maximum_component_length=256)


def test_generation_byte_determinism(tmp_path: Path) -> None:
    one = tmp_path / "one"
    two = tmp_path / "two"
    generate_payload_examples(one)
    generate_payload_examples(two)
    a = {p.relative_to(one): p.read_bytes() for p in one.rglob("*") if p.is_file()}
    b = {p.relative_to(two): p.read_bytes() for p in two.rglob("*") if p.is_file()}
    assert a == b


def test_cli_manifest_compare_verify(tmp_path: Path, generated: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "x").write_text("x")
    subject_path = tmp_path / "subject.json"
    subject_path.write_text(
        json.dumps(
            json.loads((generated / "payload-integrity/plans/local.plan.json").read_text())[
                "subject"
            ]
        )
    )
    manifest_path = tmp_path / "manifest.json"
    result = runner.invoke(
        app,
        [
            "payload",
            "manifest",
            str(source),
            "--subject",
            str(subject_path),
            "--output",
            str(manifest_path),
            "--root-mode",
            "DIRECTORY_ROOT",
            "--logical-root",
            "artifact.cli",
        ],
    )
    assert result.exit_code == 0, result.output
    manifest = load_payload(manifest_path, ObservedPayloadManifest)
    expectation = build_expectation(
        manifest.subject,
        manifest.root_mode,
        manifest.logical_root,
        manifest.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    expected_path = tmp_path / "expected.json"
    expected_path.write_text(pretty_json(expectation))
    comparison_path = tmp_path / "comparison.json"
    compared = runner.invoke(
        app,
        [
            "payload",
            "compare",
            "--expected",
            str(expected_path),
            "--observed",
            str(manifest_path),
            "--output",
            str(comparison_path),
        ],
    )
    assert compared.exit_code == 0
    verified = runner.invoke(app, ["payload", "verify-manifest", str(manifest_path)])
    assert verified.exit_code == 0
    bad = runner.invoke(
        app,
        [
            "payload",
            "manifest",
            str(source),
            "--subject",
            str(subject_path),
            "--output",
            str(tmp_path / "bad.json"),
            "--root-mode",
            "SINGLE_FILE_ROOT",
            "--logical-root",
            "artifact.cli",
        ],
    )
    assert bad.exit_code == 2


def test_no_phase6a_generated_local_identity(generated: Path) -> None:
    combined = "\n".join(p.read_text(errors="ignore") for p in generated.rglob("*") if p.is_file())
    for forbidden in ("/home/", "/Users/", "BEGIN PRIVATE KEY", "datetime.now", "time.time"):
        assert forbidden not in combined
