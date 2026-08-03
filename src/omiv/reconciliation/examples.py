"""Deterministic offline Phase 6B examples and practice-readiness records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.payload_integrity.building import (
    artifact_set_digest,
)
from omiv.payload_integrity.building import (
    identified as payload_identified,
)
from omiv.payload_integrity.models import (
    CompletionState,
    Coverage,
    ObservedPayloadManifest,
    PayloadFileRecord,
    PrimaryContentDigest,
)
from omiv.payload_integrity.reporting import load_payload
from omiv.reconciliation.building import (
    assess_completeness,
    build_authority_evaluation,
    build_digest_descriptor,
    build_execution_record,
    build_expectation,
    build_integration,
    build_locator,
    build_member,
    build_plan,
    build_policy,
    build_report,
    build_snapshot,
    compare_remote_to_local,
    evaluate_reconciliation,
    identified,
)
from omiv.reconciliation.indexes import build_topology_from_indexes, parse_shard_index_bytes
from omiv.reconciliation.models import (
    DigestKind,
    ExpectationScope,
    ListingCompleteness,
    LocalManifestReference,
    ObservationLevel,
    ProvenanceStrength,
    ProviderKind,
    ReconciliationArtifactIndex,
    ReconciliationArtifactIndexEntry,
    RemoteMemberRole,
    RequestedRevisionKind,
    ResolvedRevisionKind,
    StorageRepresentation,
)
from omiv.reconciliation.reporting import pretty_json, render_markdown
from omiv.safe_write import atomic_write_text
from omiv.trust.models import (
    BindingStatus,
    SignaturePurpose,
    SignatureReport,
    SignedObjectEnvelope,
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
    atomic_write_text(path, pretty_json(value))
    return path


def _write_dict(path: Path, value: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def _canonical_id(value: dict[str, Any]) -> str:
    schema_fields = {
        "omiv.remote-artifact-locator.v1": "locator_id",
        "omiv.remote-snapshot-plan.v1": "plan_id",
        "omiv.remote-collection-execution-record.v1": "execution_id",
        "omiv.remote-member-record.v1": "member_id",
        "omiv.remote-snapshot-manifest.v1": "manifest_id",
        "omiv.shard-topology.v1": "topology_id",
        "omiv.shard-completeness-assessment.v1": "assessment_id",
        "omiv.remote-snapshot-expectation.v1": "expectation_id",
        "omiv.remote-publisher-authority-evaluation.v1": "authority_evaluation_id",
        "omiv.remote-local-reconciliation-comparison.v1": "comparison_id",
        "omiv.remote-local-reconciliation-policy.v1": "policy_id",
        "omiv.remote-local-reconciliation-evidence.v1": "evidence_id",
        "omiv.remote-local-reconciliation-report.v1": "report_id",
        "omiv.remote-local-integration.v1": "integration_id",
        "omiv.reconciliation-local-manifest-reference.v1": "reference_id",
        "omiv.supplied-shard-index-fixture.v1": "fixture_id",
        "omiv.signature-report.v1": "report_id",
        "omiv.signed-object-envelope.v1": "envelope_id",
        "omiv.trust-policy.v1": "policy_id",
        "omiv.trust-bundle.v1": "bundle_id",
    }
    field = schema_fields.get(str(value.get("schema")))
    if field is not None and isinstance(value.get(field), str):
        return str(value[field])
    for field in (
        "locator_id",
        "plan_id",
        "execution_id",
        "member_id",
        "manifest_id",
        "topology_id",
        "assessment_id",
        "authority_evaluation_id",
        "comparison_id",
        "expectation_id",
        "policy_id",
        "evidence_id",
        "report_id",
        "integration_id",
        "reference_id",
        "profile_id",
        "fixture_id",
        "envelope_id",
        "bundle_id",
    ):
        candidate = value.get(field)
        if isinstance(candidate, str):
            return candidate
    raise ValueError("generated record lacks a canonical identity")


def _derived_local(
    source: ObservedPayloadManifest,
    files: tuple[PayloadFileRecord, ...],
    *,
    complete: bool,
) -> ObservedPayloadManifest:
    hashed_bytes = sum(item.size for item in files)
    discovered_files = len(files) if complete else len(source.files)
    discovered_bytes = hashed_bytes if complete else source.coverage.discovered_bytes
    coverage = Coverage(
        discovered_regular_files=discovered_files,
        hashed_files=len(files),
        discovered_bytes=discovered_bytes,
        hashed_bytes=hashed_bytes,
        inaccessible_paths=() if complete else (source.files[-1].path,),
    )
    body = {
        "schema": "omiv.observed-payload-manifest.v1",
        "subject": source.subject.model_dump(mode="json", by_alias=True),
        "root_mode": source.root_mode.value,
        "logical_root": source.logical_root,
        "plan_id": source.plan_id,
        "plan_digest": source.plan_digest,
        "files": [item.model_dump(mode="json") for item in files],
        "artifact_set_payload_digest": artifact_set_digest(
            source.root_mode, source.logical_root, files
        ),
        "coverage": coverage.model_dump(mode="json"),
        "findings": [] if complete else ["UNSUPPORTED_ENTRY"],
        "completion_state": (
            CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE.value
            if complete
            else CompletionState.INCOMPLETE.value
        ),
        "observation_provenance": "SYSTEM_OBSERVED",
        "execution_id": source.execution_id,
        "execution_digest": source.execution_digest,
        "available_at": source.available_at,
        "observed_at": source.observed_at,
        "limitations": [
            "Synthetic derived test fixture; no additional hashing or payload observation occurred."
        ],
    }
    return ObservedPayloadManifest.model_validate(
        payload_identified(body, "manifest_id", "observed_payload_", "manifest_digest")
    )


def _fixture_index() -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": "omiv.supplied-shard-index-fixture.v1",
        "metadata": {"total_size": 38},
        "weight_map": {
            "layer.0.weight": "weights/part-00001-of-00002.payload",
            "layer.1.weight": "weights/part-00002-of-00002.payload",
        },
        "limitations": [
            "Synthetic declaration only; logical keys and shard payloads were not opened."
        ],
    }
    fixture_id = "shard_index_fixture_" + canonical_sha256(body)[:32]
    return {
        **body,
        "fixture_id": fixture_id,
        "fixture_digest": canonical_sha256({**body, "fixture_id": fixture_id}),
    }


def generate_reconciliation_examples(root: Path) -> ReconciliationArtifactIndex:
    repository_root = Path(__file__).resolve().parents[3]
    local_path = repository_root / "payload-integrity" / "observations" / "local.manifest.json"
    local = load_payload(local_path, ObservedPayloadManifest)
    base = root / "reconciliation"
    reports = root / "reports" / "reconciliation"
    generated: list[Path] = []

    locator = build_locator(
        local.subject,
        provider_kind=ProviderKind.IMPORTED_SNAPSHOT,
        provider_instance="artifacts.example.invalid",
        namespace="namespace.synthetic",
        artifact_name="generic-multishard-package",
        artifact_kind="artifact.generic-package",
        requested_revision="fixture-v1",
        requested_revision_kind=RequestedRevisionKind.TAG,
    )
    plan = build_plan(locator)
    execution = build_execution_record(plan, locator)
    remote_members = tuple(
        build_member(
            file.path,
            role={
                "weights/part-00001-of-00002.payload": RemoteMemberRole.PRIMARY_SHARD,
                "weights/part-00002-of-00002.payload": RemoteMemberRole.MANDATORY_COMPANION,
                "config/settings.json": RemoteMemberRole.MANDATORY_COMPANION,
                "notes/empty.txt": RemoteMemberRole.OPTIONAL_COMPANION,
            }[file.path],
            logical_size=file.size,
            digests=(
                build_digest_descriptor(
                    DigestKind.PAYLOAD_SHA256,
                    file.primary_content_digest.value,
                    observation_level=ObservationLevel.PAYLOAD_DIGEST_DECLARED,
                    provenance_strength=ProvenanceStrength.IMPORTED_UNVERIFIED,
                ),
            ),
            storage_representation=StorageRepresentation.DIRECT_FILE,
            observation_level=ObservationLevel.PAYLOAD_DIGEST_DECLARED,
            limitations=("Digest was imported from a synthetic reviewed fixture.",),
        )
        for file in local.files
    )
    snapshot = build_snapshot(
        locator,
        plan,
        execution,
        remote_members,
        resolved_revision="sha256:" + "1" * 64,
        resolved_revision_kind=ResolvedRevisionKind.IMMUTABLE_CONTENT_DIGEST,
        listing_completeness=ListingCompleteness.COMPLETE_FOR_DECLARED_RESPONSE_SCOPE,
    )
    index_fixture = _fixture_index()
    index_bytes = (json.dumps(index_fixture, indent=2, sort_keys=True) + "\n").encode()
    parsed_index = parse_shard_index_bytes(index_bytes, source_name="generic.weights.index.json")
    topology = build_topology_from_indexes(
        snapshot,
        (parsed_index,),
        companion_artifacts=("config/settings.json",),
    )
    completeness = assess_completeness(topology, snapshot, local)
    expectation = build_expectation(
        snapshot,
        expectation_scope=ExpectationScope.COMPLETE_REMOTE_MEMBER_SET,
        logical_root=local.logical_root,
        required_roles=(RemoteMemberRole.PRIMARY_SHARD, RemoteMemberRole.MANDATORY_COMPANION),
    )
    exact = compare_remote_to_local(expectation, local)
    policy = build_policy("reconciliation-policy.synthetic.v1", local.subject)

    object_types = [
        SignedObjectType.REMOTE_SNAPSHOT_MANIFEST,
        SignedObjectType.REMOTE_SNAPSHOT_EXPECTATION,
        SignedObjectType.REMOTE_LOCAL_RECONCILIATION_EVIDENCE,
    ]
    purposes = [
        SignaturePurpose.REMOTE_SNAPSHOT_MANIFEST_ISSUANCE,
        SignaturePurpose.REMOTE_SNAPSHOT_EXPECTATION_ISSUANCE,
        SignaturePurpose.REMOTE_LOCAL_RECONCILIATION_EVIDENCE_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([107]) * 32)
    key = build_key_identity(private, allowed_object_types=object_types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic reconciliation evidence issuer",
        role="RECONCILIATION_EVIDENCE_ISSUER",
        evidence=[canonical_sha256({"issuer": "reconciliation"})],
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

    def signed(
        value: BaseModel, object_type: SignedObjectType, purpose: SignaturePurpose
    ) -> tuple[SignedObjectEnvelope, SignatureReport]:
        raw = value.model_dump(mode="json", by_alias=True)
        descriptor = build_descriptor(raw, object_type, purpose, policy_id=trust_policy.policy_id)
        signature = build_signature_record(descriptor, private, key, binding_id=binding.binding_id)
        envelope = build_signed_envelope(raw, object_type, [signature], keys=[key])
        return envelope, verify_envelope(envelope, trust_bundle, trust_policy)

    snapshot_envelope, snapshot_signature_report = signed(
        snapshot,
        SignedObjectType.REMOTE_SNAPSHOT_MANIFEST,
        SignaturePurpose.REMOTE_SNAPSHOT_MANIFEST_ISSUANCE,
    )
    expectation_envelope, expectation_signature_report = signed(
        expectation,
        SignedObjectType.REMOTE_SNAPSHOT_EXPECTATION,
        SignaturePurpose.REMOTE_SNAPSHOT_EXPECTATION_ISSUANCE,
    )
    authority = build_authority_evaluation(
        expectation,
        expectation_signature_report,
        provider_instance=locator.provider_instance,
        namespace=locator.namespace,
        authorized=False,
    )
    evidence = evaluate_reconciliation(
        locator=locator,
        plan=plan,
        execution=execution,
        snapshot=snapshot,
        topology=topology,
        completeness=completeness,
        expectation=expectation,
        local=local,
        comparison=exact,
        policy=policy,
        authority=authority,
    )
    evidence_envelope, evidence_signature_report = signed(
        evidence,
        SignedObjectType.REMOTE_LOCAL_RECONCILIATION_EVIDENCE,
        SignaturePurpose.REMOTE_LOCAL_RECONCILIATION_EVIDENCE_ISSUANCE,
    )
    report = build_report(evidence, exact, topology, completeness, execution, authority)

    opaque_members = tuple(
        build_member(
            file.path,
            role=remote.role,
            logical_size=file.size,
            digests=(
                build_digest_descriptor(
                    DigestKind.PROVIDER_OPAQUE_ID,
                    "opaque-" + canonical_sha256({"path": file.path})[:32],
                ),
            ),
            storage_representation=StorageRepresentation.PROVIDER_OPAQUE,
        )
        for file, remote in zip(local.files, remote_members, strict=True)
    )
    metadata_snapshot = build_snapshot(
        locator,
        plan,
        execution,
        opaque_members,
        resolved_revision="sha256:" + "2" * 64,
        resolved_revision_kind=ResolvedRevisionKind.IMMUTABLE_CONTENT_DIGEST,
        listing_completeness=ListingCompleteness.COMPLETE_FOR_DECLARED_RESPONSE_SCOPE,
        limitations=("Digest identifiers are provider-opaque and not payload-comparable.",),
    )
    metadata_expectation = build_expectation(
        metadata_snapshot,
        expectation_scope=ExpectationScope.COMPLETE_REMOTE_MEMBER_SET,
        logical_root=local.logical_root,
    )
    metadata_comparison = compare_remote_to_local(metadata_expectation, local)

    changed_first = local.files[0].model_copy(
        update={
            "size": local.files[0].size + 1,
            "primary_content_digest": PrimaryContentDigest(value="f" * 64),
        }
    )
    mismatch_local = _derived_local(local, (changed_first, *local.files[1:]), complete=True)
    mismatch_comparison = compare_remote_to_local(expectation, mismatch_local)
    incomplete_local = _derived_local(local, local.files[:-1], complete=False)
    incomplete_comparison = compare_remote_to_local(expectation, incomplete_local)

    local_reference_body = {
        "schema": "omiv.reconciliation-local-manifest-reference.v1",
        "local_manifest_id": local.manifest_id,
        "local_manifest_digest": local.manifest_digest,
        "subject_id": local.subject.subject_id,
        "logical_root": local.logical_root,
        "source_schema": local.schema_id,
        "source_path": "payload-integrity/observations/local.manifest.json",
        "limitations": [
            "Reference preserves the exact Phase 6A identity and does not duplicate byte "
            "observation."
        ],
    }
    local_reference = LocalManifestReference.model_validate(
        identified(
            local_reference_body,
            "reference_id",
            "local_manifest_reference_",
            "reference_digest",
        )
    )

    objects: list[tuple[str, BaseModel]] = [
        ("declarations/generic.locator.json", locator),
        ("plans/generic.plan.json", plan),
        ("executions/generic.execution.json", execution),
        *[
            (f"members/member-{index:02}.json", member)
            for index, member in enumerate(remote_members, 1)
        ],
        ("snapshots/generic.snapshot.json", snapshot),
        ("topology/generic.topology.json", topology),
        ("assessments/generic.completeness.json", completeness),
        ("expectations/generic.expectation.json", expectation),
        ("expectations/publisher-authority.json", authority),
        ("local/phase-6a.manifest-reference.json", local_reference),
        ("comparisons/exact.json", exact),
        ("snapshots/metadata-only.snapshot.json", metadata_snapshot),
        ("expectations/metadata-only.expectation.json", metadata_expectation),
        ("comparisons/metadata-only.json", metadata_comparison),
        ("comparisons/mismatch.json", mismatch_comparison),
        ("comparisons/incomplete.json", incomplete_comparison),
        ("policies/synthetic.json", policy),
        ("evidence/generic.json", evidence),
        *[
            (f"integrations/{kind.lower()}.json", build_integration(evidence, kind))
            for kind in (
                "PASSPORT",
                "CUSTODY",
                "GOVERNANCE",
                "SECURITY",
                "RUNTIME",
                "HISTORICAL",
                "AUDIT",
            )
        ],
        ("signed/trust-policy.json", trust_policy),
        ("signed/trust-bundle.json", trust_bundle),
        ("signed/snapshot.envelope.json", snapshot_envelope),
        ("signed/expectation.envelope.json", expectation_envelope),
        ("signed/evidence.envelope.json", evidence_envelope),
    ]
    for relative, value in objects:
        generated.append(_write(base / relative, value))
    generated.append(_write_dict(base / "indexes" / "generic.weights.index.json", index_fixture))
    generated.extend(
        [
            _write(reports / "generic.reconciliation-report.json", report),
            _write(reports / "snapshot.signature-report.json", snapshot_signature_report),
            _write(reports / "expectation.signature-report.json", expectation_signature_report),
            _write(reports / "evidence.signature-report.json", evidence_signature_report),
        ]
    )
    markdown = reports / "generic.reconciliation-report.md"
    markdown.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(markdown, render_markdown(report))
    generated.append(markdown)

    entries: list[ReconciliationArtifactIndexEntry] = []
    identities: set[str] = set()
    contents: set[str] = set()
    for path in sorted(set(generated)):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        relative = path.relative_to(root).as_posix()
        if path.suffix == ".json":
            parsed = json.loads(data)
            schema = str(parsed["schema"])
            canonical_id = _canonical_id(parsed)
        else:
            schema = "omiv.remote-local-reconciliation-report-markdown.v1"
            canonical_id = "reconciliation_markdown_" + digest[:32]
        if digest in contents or canonical_id in identities:
            raise ValueError(
                f"duplicate generated content or canonical identity: {relative} {canonical_id}"
            )
        contents.add(digest)
        identities.add(canonical_id)
        entries.append(
            ReconciliationArtifactIndexEntry(
                path=relative,
                size=len(data),
                sha256=digest,
                schema_id=schema,
                canonical_id=canonical_id,
            )
        )
    body = {
        "schema": "omiv.reconciliation-artifact-index.v1",
        "entries": [item.model_dump(mode="json") for item in entries],
        "total_size": sum(item.size for item in entries),
        "limitations": [
            "External index excludes itself and deterministic artifacts contain no model "
            "payload bytes."
        ],
    }
    artifact_index = ReconciliationArtifactIndex.model_validate(
        identified(body, "index_id", "reconciliation_index_", "index_digest")
    )
    atomic_write_text(base / "artifact-index.json", pretty_json(artifact_index))
    return artifact_index


if __name__ == "__main__":
    generate_reconciliation_examples(Path.cwd())
