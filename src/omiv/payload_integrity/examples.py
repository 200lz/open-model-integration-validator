"""Compact deterministic generic Phase 6A examples."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from omiv.canonical import canonical_sha256
from omiv.payload_integrity.adapters import (
    bind_security,
    custody_linkage,
    governance_adapter,
    historical_reference,
    passport_summary,
    runtime_expected_identity,
)
from omiv.payload_integrity.building import (
    build_expectation,
    build_plan,
    build_policy,
    build_publisher_authority_evaluation,
    build_reference,
    build_report,
    compare_manifests,
    evaluate_evidence,
    identified,
    materialize_reference,
)
from omiv.payload_integrity.models import (
    ArtifactIndexEntry,
    ArtifactRole,
    ExpectationScope,
    MaterializationState,
    PayloadArtifactIndex,
    PayloadFileRecord,
    PrimaryContentDigest,
    RootMode,
)
from omiv.payload_integrity.observation import observe_payload
from omiv.payload_integrity.reporting import pretty_json, render_markdown
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.models import ProductSubjectClass
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
from omiv.trust.signing import (
    build_policy as build_trust_policy,
)
from omiv.trust.verification import verify_envelope


def _write(path: Path, value: BaseModel) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, pretty_json(value))
    return path


def _canonical_id(value: dict[str, object]) -> str:
    schema = value.get("schema")
    if not isinstance(schema, str):
        raise ValueError("generated record lacks schema identity")
    field = {
        "omiv.payload-inventory-plan.v1": "plan_id",
        "omiv.payload-expectation.v1": "expectation_id",
        "omiv.payload-expectation-materialization.v1": "materialization_id",
        "omiv.payload-publisher-authority-evaluation.v1": "authority_evaluation_id",
        "omiv.observed-payload-manifest.v1": "manifest_id",
        "omiv.payload-hash-execution-record.v1": "execution_id",
        "omiv.payload-manifest-comparison.v1": "comparison_id",
        "omiv.payload-integrity-policy.v1": "policy_id",
        "omiv.payload-integrity-evidence.v1": "evidence_id",
        "omiv.payload-integrity-report.v1": "report_id",
        "omiv.payload-integrity-integration.v1": "integration_id",
        "omiv.signed-object-envelope.v1": "envelope_id",
        "omiv.signature-verification-report.v1": "report_id",
        "omiv.signature-report.v1": "report_id",
        "omiv.trust-policy.v1": "policy_id",
        "omiv.trust-bundle.v1": "bundle_id",
    }.get(schema)
    if field is not None and isinstance(value.get(field), str):
        return str(value[field])
    raise ValueError("generated record lacks canonical identity")


def generate_payload_examples(root: Path) -> PayloadArtifactIndex:
    base = root / "payload-integrity"
    reports = root / "reports" / "payload-integrity"
    generated: list[Path] = []
    subject = build_product_subject(
        ProductSubjectClass.DEPLOYMENT_PACKAGE,
        "generic.payload-package",
        synthetic_scope(project="project.payload", environment="environment.local"),
    )
    roles: dict[str, tuple[ArtifactRole, str | None]] = {
        "weights/part-00001-of-00002.payload": (ArtifactRole.PRIMARY, None),
        "weights/part-00002-of-00002.payload": (ArtifactRole.MANDATORY_COMPANION, None),
        "config/settings.json": (ArtifactRole.MANDATORY_COMPANION, None),
        "notes/empty.txt": (ArtifactRole.OPTIONAL_COMPANION, None),
    }
    plan = build_plan(subject, RootMode.DIRECTORY_ROOT, "artifact.generic-package")
    with tempfile.TemporaryDirectory(prefix="omiv-payload-example-") as temporary:
        source = Path(temporary)
        for relative, data in {
            "weights/part-00001-of-00002.payload": b"synthetic-part-one\n",
            "weights/part-00002-of-00002.payload": b"synthetic-part-two\n",
            "config/settings.json": b'{"mode":"synthetic"}\n',
            "notes/empty.txt": b"",
        }.items():
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        observed, execution = observe_payload(source, plan, roles=roles)
    complete = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        plan.logical_root,
        observed.files,
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
        source_provider="provider.synthetic",
        source_namespace="namespace.synthetic-model",
    )
    selected = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        plan.logical_root,
        observed.files[:2],
        ExpectationScope.SELECTED_REQUIRED_MEMBERS,
    )
    referenced = build_reference(
        complete,
        state=MaterializationState.DIGEST_REFERENCE_ONLY,
        available_at="2026-01-01T00:00:00Z",
    )
    materialization = materialize_reference(
        referenced, complete, evaluated_at="2026-01-02T00:00:00Z"
    )
    exact = compare_manifests(complete, observed)
    selected_comparison = compare_manifests(selected, observed)
    digest_comparison = compare_manifests(referenced, observed)
    referenced_comparison = compare_manifests(
        complete, observed, reference=referenced, materialization=materialization
    )
    changed = list(observed.files)
    original = changed[0]
    changed[0] = PayloadFileRecord(
        path=original.path,
        logical_file_kind=original.logical_file_kind,
        size=original.size + 1,
        primary_content_digest=PrimaryContentDigest(value="0" * 64),
        artifact_role=original.artifact_role,
        declared_role_detail=original.declared_role_detail,
    )
    mismatch_expectation = build_expectation(
        subject,
        RootMode.DIRECTORY_ROOT,
        plan.logical_root,
        tuple(changed),
        ExpectationScope.COMPLETE_DECLARED_FILE_SET,
    )
    mismatch = compare_manifests(mismatch_expectation, observed)
    policy = build_policy(
        "payload-policy.enterprise-local.v1",
        subject.scope,
        expectation_scope=ExpectationScope.COMPLETE_DECLARED_FILE_SET,
        require_authorized_publisher=True,
    )
    types = [
        SignedObjectType.PAYLOAD_EXPECTATION,
        SignedObjectType.OBSERVED_PAYLOAD_MANIFEST,
        SignedObjectType.PAYLOAD_INTEGRITY_EVIDENCE,
    ]
    purposes = [
        SignaturePurpose.PAYLOAD_EXPECTATION_ISSUANCE,
        SignaturePurpose.OBSERVED_PAYLOAD_MANIFEST_ISSUANCE,
        SignaturePurpose.PAYLOAD_INTEGRITY_EVIDENCE_ISSUANCE,
    ]
    private = Ed25519PrivateKey.from_private_bytes(bytes([96]) * 32)
    key = build_key_identity(private, allowed_object_types=types, allowed_purposes=purposes)
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic payload evidence issuer",
        role="PAYLOAD_EVIDENCE_ISSUER",
        evidence=[canonical_sha256({"issuer": "payload"})],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    trust_policy = build_trust_policy(
        "team_release",
        object_types=types,
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

    expectation_envelope, expectation_trust_report = signed(
        complete,
        SignedObjectType.PAYLOAD_EXPECTATION,
        SignaturePurpose.PAYLOAD_EXPECTATION_ISSUANCE,
    )
    publisher_authority = build_publisher_authority_evaluation(
        complete,
        trust_report=expectation_trust_report,
        authorized=True,
        evaluated_at="2026-01-02T00:00:00Z",
    )
    evidence = evaluate_evidence(
        observed,
        execution.execution_id,
        exact,
        complete,
        policy,
        publisher_authority,
    )
    report = build_report(evidence, exact)
    objects: list[tuple[str, BaseModel]] = [
        ("plans/local.plan.json", plan),
        ("observations/local.manifest.json", observed),
        ("executions/local.execution.json", execution),
        ("expectations/complete.json", complete),
        ("expectations/selected.json", selected),
        ("expectations/referenced.json", referenced),
        ("expectations/materialization.json", materialization),
        ("expectations/publisher-authority.json", publisher_authority),
        ("expectations/mismatch.json", mismatch_expectation),
        ("comparisons/exact.json", exact),
        ("comparisons/selected.json", selected_comparison),
        ("comparisons/digest-only.json", digest_comparison),
        ("comparisons/referenced.json", referenced_comparison),
        ("comparisons/mismatch.json", mismatch),
        ("policies/enterprise-local.json", policy),
        ("evidence/authorized-complete.json", evidence),
        ("adapters/passport.json", passport_summary(evidence)),
        ("adapters/custody.json", custody_linkage(evidence)),
        ("adapters/governance.json", governance_adapter(evidence)),
        (
            "adapters/security.json",
            bind_security(
                evidence,
                security_subject_id=evidence.subject_id,
                security_payload_digest=evidence.artifact_set_payload_digest,
                security_evidence_id="security_evidence.synthetic.v1",
                security_evidence_digest=canonical_sha256({"security": "synthetic"}),
                security_scope_digest=evidence.subject_scope_digest,
                complete_coverage=True,
                security_limitations=("Synthetic security evidence linkage only.",),
            ),
        ),
        ("adapters/runtime.json", runtime_expected_identity(evidence)),
        ("adapters/historical.json", historical_reference(evidence)),
    ]
    for relative, value in objects:
        generated.append(_write(base / relative, value))
    generated.append(_write(reports / "local.payload-report.json", report))
    markdown = reports / "local.payload-report.md"
    markdown.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(markdown, render_markdown(report))
    generated.append(markdown)
    generated.extend(
        [
            _write(base / "signed/trust-policy.json", trust_policy),
            _write(base / "signed/trust-bundle.json", trust_bundle),
            _write(base / "signed/expectation.envelope.json", expectation_envelope),
            _write(reports / "expectation.signature-report.json", expectation_trust_report),
        ]
    )
    for name, value, object_type, purpose in zip(
        ("manifest", "evidence"),
        (observed, evidence),
        types[1:],
        purposes[1:],
        strict=True,
    ):
        envelope, trust_report = signed(value, object_type, purpose)
        generated.extend(
            [
                _write(base / f"signed/{name}.envelope.json", envelope),
                _write(reports / f"{name}.signature-report.json", trust_report),
            ]
        )
    entries: list[ArtifactIndexEntry] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for path in sorted(set(generated)):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        relative = path.relative_to(root).as_posix()
        if path.suffix == ".json":
            parsed = json.loads(data)
            schema = str(parsed["schema"])
            canonical_id = _canonical_id(parsed)
        else:
            schema = "omiv.payload-report-markdown.v1"
            canonical_id = "payload_markdown_" + digest[:32]
        if digest in hashes or canonical_id in ids:
            raise ValueError(
                f"duplicate generated content or canonical identity: {relative} {canonical_id}"
            )
        hashes.add(digest)
        ids.add(canonical_id)
        entries.append(
            ArtifactIndexEntry(
                path=relative,
                size=len(data),
                sha256=digest,
                schema_id=schema,
                canonical_id=canonical_id,
            )
        )
    body = {
        "schema": "omiv.payload-artifact-index.v1",
        "entries": [x.model_dump(mode="json") for x in entries],
        "total_size": sum(x.size for x in entries),
        "limitations": ["Index excludes itself and contains no payload bytes."],
    }
    index = PayloadArtifactIndex.model_validate(
        identified(body, "index_id", "payload_index_", "index_digest")
    )
    atomic_write_text(base / "artifact-index.json", pretty_json(index))
    return index


if __name__ == "__main__":
    generate_payload_examples(Path.cwd())
