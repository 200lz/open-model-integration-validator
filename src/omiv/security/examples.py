"""Deterministic compact synthetic Phase 5F fixtures and reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omiv.canonical import canonical_sha256
from omiv.governance.evaluation import (
    build_evaluation_input,
    build_governance_policy,
    build_governance_report,
    build_policy_decision,
    build_requirement,
    build_requirement_set,
    build_subject,
)
from omiv.governance.models import EvidenceCategory, VerificationMode
from omiv.safe_write import atomic_write_text
from omiv.security.adapters import (
    adapt_governance_security_evidence,
    build_custody_security_linkage,
    build_passport_security_summary,
)
from omiv.security.building import build_plan, builtin_scanner_identity, identified
from omiv.security.evaluation import evaluate_security_bundle
from omiv.security.models import (
    InspectionBounds,
    SecurityArtifactIndex,
    SecurityArtifactIndexEntry,
    SecurityEvaluationResult,
    SecurityEvidenceBundle,
    SecurityInspectionScope,
    SecurityRequirementProfile,
    SecurityScanExecutionInput,
)
from omiv.security.policy import build_security_policy
from omiv.security.reporting import build_security_report, pretty_json, render_security_markdown
from omiv.security.scanning import describe_local_artifact, inspect_local_artifact
from omiv.security.signing import build_signed_security_linkage
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
from omiv.trust.signing import (
    build_policy as build_trust_policy,
)
from omiv.trust.verification import verify_envelope


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _scenario(
    root: Path,
    name: str,
    artifact: Path,
    *,
    maximum_bytes_per_file: int = 1024 * 1024,
    policy_profile: SecurityRequirementProfile = (
        SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE
    ),
) -> list[Path]:
    scanner = builtin_scanner_identity()
    subject, items = describe_local_artifact(artifact)
    bounds = InspectionBounds(
        maximum_file_count=100,
        maximum_total_bytes_read=8 * 1024 * 1024,
        maximum_bytes_per_file=maximum_bytes_per_file,
        maximum_archive_entry_count=100,
        maximum_metadata_bytes=1024 * 1024,
        maximum_finding_count=100,
        maximum_evidence_snippet_length=128,
        maximum_recursion_depth=8,
    )
    scope = SecurityInspectionScope(
        logical_paths=sorted(item.logical_path for item in items),
        mandatory_paths=sorted(item.logical_path for item in items),
        declared_file_count=len(items),
        declared_total_bytes=sum(item.size for item in items),
        include_archive_metadata=(
            artifact.suffix == ".zip" or artifact.name.endswith(".archive-manifest.json")
        ),
    )
    plan = build_plan(subject, scope, scanner.capability.methods, bounds)
    bundle = inspect_local_artifact(artifact, plan, scanner)
    policy = build_security_policy(policy_profile)
    evaluation = evaluate_security_bundle(bundle, policy)
    report = build_security_report(bundle, evaluation)
    example_dir = root / "security" / "examples"
    report_dir = root / "reports" / "security"
    values = {
        example_dir / f"{name}.inspection-plan.json": plan,
        example_dir / f"{name}.scanner-identity.json": scanner,
        example_dir / f"{name}.scan-execution.json": bundle.execution_records[0],
        example_dir / f"{name}.coverage.json": bundle.coverage,
        example_dir / f"{name}.security-bundle.json": bundle,
        example_dir / f"{name}.security-evaluation.json": evaluation,
        report_dir / f"{name}.security-report.json": report,
    }
    execution_input = SecurityScanExecutionInput(
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        scanner_id=scanner.scanner_id,
        scanner_digest=scanner.scanner_digest,
        configuration_digest=scanner.configuration_digest,
        subject=subject,
    )
    values[example_dir / f"{name}.scan-execution-input.json"] = execution_input
    for number, finding in enumerate(bundle.findings, start=1):
        values[example_dir / f"{name}.finding-{number}.json"] = finding
    paths: list[Path] = []
    for path, value in values.items():
        atomic_write_text(path, pretty_json(value))
        paths.append(path)
    markdown = report_dir / f"{name}.security-report.md"
    atomic_write_text(markdown, render_security_markdown(report))
    paths.append(markdown)
    return paths


def _object_identity(value: dict[str, Any]) -> str:
    fields = (
        "plan_id",
        "scanner_id",
        "execution_id",
        "finding_id",
        "coverage_id",
        "bundle_id",
        "policy_id",
        "evaluation_id",
        "report_id",
        "gap_report_id",
        "adapter_id",
        "evidence_id",
        "summary_id",
        "linkage_id",
        "bundle_id",
        "envelope_id",
        "signature_report_id",
        "trust_report_id",
        "decision_id",
        "requirement_set_id",
    )
    for field in fields:
        if isinstance(value.get(field), str):
            return str(value[field])
    return "indexed_" + canonical_sha256(value)[:32]


def generate_security_examples(root: Path) -> SecurityArtifactIndex:
    """Generate all fixtures offline; repeated runs are byte-identical."""
    artifacts = root / "security" / "examples" / "artifacts"
    for obsolete_archive in (
        artifacts / "archive-traversal.zip",
        artifacts / "malformed-archive.zip",
    ):
        if obsolete_archive.exists():
            obsolete_archive.unlink()
    _write_bytes(artifacts / "clean.safetensors", (2).to_bytes(8, "little") + b"{}")
    _write_bytes(artifacts / "unsafe-serialization.pkl", b"\x80synthetic pickle marker only\n")
    _write_bytes(artifacts / "script.py", b'print("harmless script fixture; never executed")\n')
    _write_bytes(
        artifacts / "private-marker.txt",
        b"BEGIN " + b"PRIVATE KEY synthetic marker without key material\n",
    )
    _write_bytes(
        artifacts / "signed-url-marker.txt",
        b"signed-url-indicator: X-Amz-Synthetic redacted\n",
    )
    _write_bytes(
        artifacts / "archive-traversal.archive-manifest.json",
        b'{"entries":[{"kind":"file","name":"../synthetic-escape.txt"}]}\n',
    )
    _write_bytes(artifacts / "partial-scan.gguf", b"GGUF" + b"bounded-prefix-only" * 2)
    _write_bytes(
        artifacts / "malformed-archive.archive-manifest.json",
        b'{"entries":"not-a-list"}\n',
    )
    generated: list[Path] = []
    scenarios = (
        (
            "clean",
            ".safetensors",
            1024 * 1024,
            SecurityRequirementProfile.PERSONAL_LOCAL_SECURITY_REVIEW,
        ),
        ("unsafe-serialization", ".pkl", 1024 * 1024, None),
        ("script", ".py", 1024 * 1024, None),
        ("private-marker", ".txt", 1024 * 1024, None),
        ("signed-url-marker", ".txt", 1024 * 1024, None),
        ("archive-traversal", ".archive-manifest.json", 1024 * 1024, None),
        ("partial-scan", ".gguf", 8, None),
        ("malformed-archive", ".archive-manifest.json", 1024 * 1024, None),
    )
    for name, suffix, per_file_bound, policy_profile in scenarios:
        generated.extend(
            _scenario(
                root,
                name,
                artifacts / f"{name}{suffix}",
                maximum_bytes_per_file=per_file_bound,
                policy_profile=(
                    policy_profile or SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE
                ),
            )
        )

    clean_bundle_path = root / "security" / "examples" / "clean.security-bundle.json"
    clean_bundle = json.loads(clean_bundle_path.read_text())
    bundle = SecurityEvidenceBundle.model_validate(clean_bundle)
    release_policy = build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE)
    release_evaluation = evaluate_security_bundle(bundle, release_policy)
    digest = bundle.subject.content_digest
    if digest is None:
        raise ValueError("clean fixture requires a content digest")
    governance_subject = build_subject(
        artifact_digest=digest,
        artifact_format="safetensors",
        origin_type="local",
        logical_locator="synthetic/clean.safetensors",
        variant="synthetic",
    )
    governance_adapter, governance_reference = adapt_governance_security_evidence(
        governance_subject, bundle, release_evaluation, release_policy
    )
    passport_identity = {
        "passport_id": "mp_" + canonical_sha256({"subject": digest})[:32],
        "passport_digest": canonical_sha256({"passport": digest}),
    }
    passport_summary = build_passport_security_summary(
        passport_identity, bundle, release_evaluation
    )
    ledger_identity = {
        "chain_id": "custody_" + canonical_sha256({"subject": digest})[:32],
        "ledger_digest": canonical_sha256({"ledger": digest}),
    }
    custody_linkage = build_custody_security_linkage(ledger_identity, bundle, release_evaluation)
    adapter_values = {
        root
        / "security"
        / "examples"
        / "clean.governance-security-adapter.json": governance_adapter,
        root
        / "security"
        / "examples"
        / "clean.governance-evidence-reference.json": governance_reference,
        root / "security" / "examples" / "clean.passport-security-summary.json": passport_summary,
        root / "security" / "examples" / "clean.custody-security-linkage.json": custody_linkage,
    }
    for path, value in adapter_values.items():
        atomic_write_text(path, pretty_json(value))
        generated.append(path)

    security_requirement = build_requirement(
        EvidenceCategory.SECURITY_INSPECTION,
        accepted_schemas=["omiv.artifact-security-evidence.v1"],
        accepted_verification_modes=[VerificationMode.FULL],
        allow_with_limitations=True,
        remediation="Supply verified subject-matched Phase 5F security evidence.",
        source_phase="5F",
    )
    payload_requirement = build_requirement(
        EvidenceCategory.PAYLOAD_INTEGRITY,
        accepted_schemas=["omiv.payload-integrity-evidence.v1"],
        remediation="Supply separate verified payload-integrity evidence.",
        source_phase="5F",
    )
    requirement_set = build_requirement_set([security_requirement, payload_requirement])
    derived_policy = build_governance_policy(
        "team_release_candidate",
        requirement_set,
        accepted_formats=["archive", "generic-file", "gguf", "safetensors"],
        accepted_origin_types=["local"],
    )
    governance_values = {
        root
        / "security"
        / "examples"
        / "derived-team-release.requirement-set.json": requirement_set,
        root
        / "security"
        / "examples"
        / "derived-team-release.governance-policy.json": derived_policy,
    }

    def add_derived_governance(
        name: str,
        scenario_bundle: SecurityEvidenceBundle,
        scenario_evaluation: SecurityEvaluationResult,
        scenario_policy: Any,
        *,
        signature_report: Any = None,
    ) -> None:
        scenario_digest = scenario_bundle.subject.content_digest
        if scenario_digest is None:
            scenario_digest = scenario_bundle.subject.artifact_set_digest
        if scenario_digest is None:
            raise ValueError("derived governance fixture requires artifact identity")
        scenario_subject = build_subject(
            artifact_digest=scenario_digest,
            artifact_format=scenario_bundle.subject.format or "generic-file",
            origin_type="local",
            logical_locator=f"synthetic/{name}",
            variant="synthetic",
        )
        scenario_adapter, scenario_reference = adapt_governance_security_evidence(
            scenario_subject,
            scenario_bundle,
            scenario_evaluation,
            scenario_policy,
            signature_report=signature_report,
        )
        scenario_input = build_evaluation_input(
            scenario_subject, derived_policy, [scenario_reference]
        )
        scenario_decision = build_policy_decision(scenario_input, derived_policy)
        scenario_report = build_governance_report(scenario_decision)
        scenario_values = {
            root / "security" / "examples" / f"{name}.governance-security-adapter.json": (
                scenario_adapter
            ),
            root / "security" / "examples" / f"{name}.policy-evaluation-input.json": (
                scenario_input
            ),
            root / "security" / "examples" / f"{name}.policy-decision.json": (scenario_decision),
            root / "reports" / "security" / f"{name}.governance-report.json": scenario_report,
        }
        for scenario_path, scenario_value in scenario_values.items():
            atomic_write_text(scenario_path, pretty_json(scenario_value))
            generated.append(scenario_path)

    add_derived_governance("derived-team-release", bundle, release_evaluation, release_policy)
    for scenario_name in ("unsafe-serialization", "partial-scan"):
        scenario_bundle = SecurityEvidenceBundle.model_validate(
            json.loads(
                (
                    root / "security" / "examples" / f"{scenario_name}.security-bundle.json"
                ).read_text()
            )
        )
        scenario_evaluation = evaluate_security_bundle(scenario_bundle, release_policy)
        add_derived_governance(
            f"derived-{scenario_name}", scenario_bundle, scenario_evaluation, release_policy
        )
    untrusted_policy = build_security_policy(
        SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE,
        accepted_scanner_ids=["scanner_" + "0" * 32],
    )
    untrusted_evaluation = evaluate_security_bundle(bundle, untrusted_policy)
    add_derived_governance(
        "derived-untrusted-scanner", bundle, untrusted_evaluation, untrusted_policy
    )
    for path, value in governance_values.items():
        atomic_write_text(path, pretty_json(value))
        generated.append(path)

    object_type = SignedObjectType.SECURITY_EVIDENCE_BUNDLE
    purpose = SignaturePurpose.SECURITY_EVIDENCE_ISSUANCE
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes([66]) * 32)
    key = build_key_identity(
        signing_key,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
    )
    signer = build_signer_identity(
        SignerIdentityKind.SERVICE_DECLARED,
        "Synthetic offline security scanner",
        role="SECURITY_SCANNER",
        evidence=[canonical_sha256({"fixture": "security-scanner-identity"})],
        verification_status="EVIDENCE_LINKED",
    )
    binding = build_binding(signer, key, status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE)
    trust_root = build_trust_root(key)
    trust_policy = build_trust_policy(
        "team_release",
        object_types=[object_type],
        purposes=[purpose],
        minimum_binding_status=BindingStatus.VERIFIED_BY_TRUST_BUNDLE,
    )
    trust_bundle = build_trust_bundle([trust_root], [key], identities=[signer], bindings=[binding])
    descriptor = build_descriptor(
        bundle.model_dump(mode="json", by_alias=True),
        object_type,
        purpose,
        policy_id=trust_policy.policy_id,
    )
    signature = build_signature_record(descriptor, signing_key, key, binding_id=binding.binding_id)
    envelope = build_signed_envelope(
        bundle.model_dump(mode="json", by_alias=True), object_type, [signature], keys=[key]
    )
    signature_report = verify_envelope(envelope, trust_bundle, trust_policy)
    linkage = build_signed_security_linkage(envelope, trust_status="TRUSTED_BY_POLICY")
    unknown_signing_key = Ed25519PrivateKey.from_private_bytes(bytes([67]) * 32)
    unknown_key = build_key_identity(
        unknown_signing_key,
        allowed_object_types=[object_type],
        allowed_purposes=[purpose],
    )
    unknown_descriptor = build_descriptor(
        bundle.model_dump(mode="json", by_alias=True),
        object_type,
        purpose,
        policy_id=trust_policy.policy_id,
    )
    unknown_signature = build_signature_record(unknown_descriptor, unknown_signing_key, unknown_key)
    unknown_envelope = build_signed_envelope(
        bundle.model_dump(mode="json", by_alias=True),
        object_type,
        [unknown_signature],
        keys=[unknown_key],
    )
    unknown_signature_report = verify_envelope(unknown_envelope, trust_bundle, trust_policy)
    enterprise_policy = build_security_policy(
        SecurityRequirementProfile.ENTERPRISE_ARTIFACT_SECURITY_GATE
    )
    enterprise_evaluation = evaluate_security_bundle(
        bundle, enterprise_policy, signature_report=signature_report
    )
    untrusted_enterprise_evaluation = evaluate_security_bundle(
        bundle, enterprise_policy, signature_report=unknown_signature_report
    )
    add_derived_governance(
        "derived-enterprise-signed",
        bundle,
        enterprise_evaluation,
        enterprise_policy,
        signature_report=signature_report,
    )
    signed_values = {
        root / "security" / "examples" / "trusted-security.trust-policy.json": trust_policy,
        root / "security" / "examples" / "trusted-security.trust-bundle.json": trust_bundle,
        root
        / "security"
        / "examples"
        / "trusted-clean.security-bundle.signed-envelope.json": envelope,
        root / "security" / "examples" / "trusted-clean.signed-security-linkage.json": linkage,
        root
        / "security"
        / "examples"
        / "trusted-clean.enterprise-security-evaluation.json": enterprise_evaluation,
        root / "security" / "examples" / "untrusted-clean.enterprise-security-evaluation.json": (
            untrusted_enterprise_evaluation
        ),
        root / "reports" / "security" / "trusted-clean.signature-report.json": signature_report,
        root
        / "security"
        / "examples"
        / "untrusted-clean.security-bundle.signed-envelope.json": unknown_envelope,
        root / "reports" / "security" / "untrusted-clean.signature-report.json": (
            unknown_signature_report
        ),
    }
    for path, value in signed_values.items():
        atomic_write_text(path, pretty_json(value))
        generated.append(path)

    policy_dir = root / "security" / "policies"
    for profile in SecurityRequirementProfile:
        policy = build_security_policy(profile)
        path = policy_dir / f"{profile.value}.json"
        atomic_write_text(path, pretty_json(policy))
        generated.append(path)

    gap_body = {
        "schema": "omiv.security-gap-report.v1",
        "subject": "Kimi-K3 remote case study",
        "security_inspection": "UNAVAILABLE",
        "payload_acquired": False,
        "scanner_run": False,
        "coverage": "NOT_ASSESSED",
        "security_requirement": "UNSATISFIED",
        "verdict": "NOT_EVALUATED",
        "limitations": [
            "No local Kimi payload was acquired or scanned.",
            "No Kimi security PASS, malware-free claim, approval, or promotion is produced.",
        ],
    }
    gap = identified(gap_body, "gap_report_id", "security_gap_", "gap_report_digest")
    gap_path = root / "reports" / "security" / "kimi-k3.security-gap-report.json"
    atomic_write_text(gap_path, pretty_json(gap))
    generated.append(gap_path)

    entries: list[SecurityArtifactIndexEntry] = []
    for path in sorted(artifacts.iterdir()):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        entries.append(
            SecurityArtifactIndexEntry(
                relative_path=path.relative_to(root).as_posix(),
                schema="omiv.synthetic-security-fixture.v1",
                object_id="synthetic_fixture_" + digest[:32],
                digest=digest,
                size_bytes=len(raw),
            )
        )
    for path in sorted(generated):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        indexed_value: dict[str, Any] | None = json.loads(raw) if path.suffix == ".json" else None
        entries.append(
            SecurityArtifactIndexEntry(
                relative_path=path.relative_to(root).as_posix(),
                schema=(
                    indexed_value["schema"]
                    if indexed_value is not None
                    else "omiv.security-report-markdown.v1"
                ),
                object_id=(
                    _object_identity(indexed_value)
                    if indexed_value is not None
                    else "security_markdown_" + digest[:32]
                ),
                digest=digest,
                size_bytes=len(raw),
            )
        )
    body = {
        "schema": "omiv.security-artifact-index.v1",
        "entries": [
            entry.model_dump(mode="json", by_alias=True)
            for entry in sorted(entries, key=lambda item: item.relative_path)
        ],
        "limitations": [
            "The index covers canonical Phase 5F JSON records, not artifact safety or "
            "runtime state."
        ],
    }
    index = SecurityArtifactIndex.model_validate(
        identified(body, "index_id", "security_index_", "index_digest")
    )
    atomic_write_text(root / "security" / "artifact-index.json", pretty_json(index))
    return index


if __name__ == "__main__":
    generate_security_examples(Path.cwd())
