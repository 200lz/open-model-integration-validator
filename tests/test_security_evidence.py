"""Phase 5F artifact security evidence, bounded inspection, and adapter tests."""

from __future__ import annotations

import json
import os
import socket
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.governance.evaluation import build_subject
from omiv.security.adapters import adapt_governance_security_evidence, import_external_result
from omiv.security.artifact_index import verify_security_artifact_index
from omiv.security.building import (
    artifact_reference,
    build_plan,
    builtin_scanner_identity,
)
from omiv.security.evaluation import evaluate_security_bundle
from omiv.security.examples import generate_security_examples
from omiv.security.models import (
    FindingClassification,
    InspectionBounds,
    ScannerTrust,
    SecurityEvidenceBundle,
    SecurityInspectionScope,
    SecurityRequirementProfile,
    SecurityVerdict,
)
from omiv.security.policy import build_security_policy
from omiv.security.reporting import (
    build_security_report,
    pretty_json,
    render_security_markdown,
    verify_security_report,
)
from omiv.security.scanning import describe_local_artifact, inspect_local_artifact
from omiv.security.schema import SECURITY_SCHEMA_MODELS, schema_model
from omiv.trust.models import SignaturePurpose, SignedObjectType
from omiv.trust.signing import EXPECTED_PURPOSE, OBJECT_METADATA

runner = CliRunner()


def _bounds(**updates: int) -> InspectionBounds:
    values = {
        "maximum_file_count": 20,
        "maximum_total_bytes_read": 1024 * 1024,
        "maximum_bytes_per_file": 64 * 1024,
        "maximum_archive_entry_count": 20,
        "maximum_metadata_bytes": 64 * 1024,
        "maximum_finding_count": 100,
        "maximum_evidence_snippet_length": 128,
        "maximum_recursion_depth": 4,
    }
    values.update(updates)
    return InspectionBounds(**values)


def _inspect(path: Path, *, bounds: InspectionBounds | None = None):
    subject, items = describe_local_artifact(path)
    scope = SecurityInspectionScope(
        logical_paths=sorted(item.logical_path for item in items),
        mandatory_paths=sorted(item.logical_path for item in items),
        declared_file_count=len(items),
        declared_total_bytes=sum(item.size for item in items),
        include_archive_metadata=path.suffix == ".zip",
    )
    scanner = builtin_scanner_identity()
    plan = build_plan(subject, scope, scanner.capability.methods, bounds or _bounds())
    return inspect_local_artifact(path, plan, scanner), plan, scanner


def test_generic_clean_artifact_is_scope_limited_pass(tmp_path: Path) -> None:
    artifact = tmp_path / "model.safetensors"
    artifact.write_bytes((2).to_bytes(8, "little") + b"{}")
    bundle, plan, scanner = _inspect(artifact)
    evaluation = evaluate_security_bundle(
        bundle,
        build_security_policy(SecurityRequirementProfile.PERSONAL_LOCAL_SECURITY_REVIEW),
    )
    assert bundle.subject.format == "safetensors"
    assert bundle.coverage.status.value == "COMPLETE_FOR_DECLARED_SCOPE"
    assert evaluation.verdict == SecurityVerdict.PASS_WITH_LIMITATIONS
    assert evaluation.scanner_trust == ScannerTrust.TRUSTED_BY_POLICY
    assert plan.allow_code_execution is False
    assert scanner.capability.network_access is False


@pytest.mark.parametrize(
    ("name", "content", "category"),
    [
        ("weights.pkl", b"\x80synthetic", FindingClassification.UNSAFE_SERIALIZATION_FORMAT),
        ("helper.py", b"print('harmless')", FindingClassification.SCRIPT_CONTENT_PRESENT),
        ("native.bin", b"\x7fELFnot-an-executable", FindingClassification.NATIVE_BINARY_PRESENT),
        (
            "metadata.txt",
            b"BEGIN " + b"PRIVATE KEY synthetic marker only",
            FindingClassification.PRIVATE_KEY_MATERIAL_PATTERN,
        ),
        (
            "metadata.txt",
            b"https://invalid.example/object?X-Amz-Synthetic",
            FindingClassification.SIGNED_URL_PATTERN,
        ),
        (
            "loader.txt",
            b"pickle.load(value)",
            FindingClassification.DESERIALIZATION_EXECUTION_PATTERN,
        ),
    ],
)
def test_bounded_patterns_are_normalized_and_blocked(
    tmp_path: Path, name: str, content: bytes, category: FindingClassification
) -> None:
    artifact = tmp_path / name
    artifact.write_bytes(content)
    bundle, _, _ = _inspect(artifact)
    assert category in {item.category for item in bundle.findings}
    evaluation = evaluate_security_bundle(
        bundle,
        build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE),
    )
    assert evaluation.verdict == SecurityVerdict.FAIL
    assert evaluation.blocking_finding_ids
    serialized = pretty_json(bundle)
    assert "synthetic marker only" not in serialized
    assert "X-Amz-Synthetic" not in serialized


def test_archive_traversal_metadata_detected_without_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape.txt", "harmless")
    bundle, _, _ = _inspect(archive)
    assert FindingClassification.PATH_TRAVERSAL_ENTRY in {x.category for x in bundle.findings}
    assert not (tmp_path / "escape.txt").exists()


def test_archive_entry_limit_fails_closed(tmp_path: Path) -> None:
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for number in range(3):
            handle.writestr(f"entry-{number}.txt", "x")
    bundle, _, _ = _inspect(archive, bounds=_bounds(maximum_archive_entry_count=2))
    evaluation = evaluate_security_bundle(
        bundle,
        build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE),
    )
    assert bundle.scan_errors[0].error_code == "ARCHIVE_ENTRY_LIMIT_EXCEEDED"
    assert evaluation.verdict == SecurityVerdict.FAIL


def test_per_file_bound_cannot_be_complete(tmp_path: Path) -> None:
    artifact = tmp_path / "large.gguf"
    artifact.write_bytes(b"GGUF" + b"x" * 100)
    bundle, _, _ = _inspect(artifact, bounds=_bounds(maximum_bytes_per_file=8))
    evaluation = evaluate_security_bundle(
        bundle,
        build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE),
    )
    assert bundle.coverage.total_inspected_bytes == 8
    assert evaluation.verdict == SecurityVerdict.COVERAGE_INCOMPLETE


def test_symlink_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("harmless")
    link = tmp_path / "link.txt"
    link.symlink_to(artifact)
    with pytest.raises(OmivInputError, match="symlink"):
        describe_local_artifact(link)


def test_nested_symlink_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "set"
    root.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("outside")
    (root / "link").symlink_to(target)
    with pytest.raises(OmivInputError, match="symlink"):
        describe_local_artifact(root)


def test_fifo_and_socket_are_rejected(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(OmivInputError, match="regular file or directory"):
        describe_local_artifact(fifo)
    sock_path = tmp_path / "sock"
    with socket.socket(socket.AF_UNIX) as sock:
        try:
            sock.bind(str(sock_path))
        except PermissionError:
            pytest.skip("sandbox prohibits Unix-domain socket creation")
        with pytest.raises(OmivInputError, match="regular file or directory"):
            describe_local_artifact(sock_path)


def test_plan_rejects_reserved_dynamic_analysis(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    subject, items = describe_local_artifact(artifact)
    scope = SecurityInspectionScope(
        logical_paths=[items[0].logical_path],
        mandatory_paths=[items[0].logical_path],
        declared_file_count=1,
        declared_total_bytes=1,
    )
    from omiv.security.models import InspectionMethod

    with pytest.raises(ValidationError, match="reserved"):
        build_plan(
            subject,
            scope,
            [InspectionMethod.CONTROLLED_DYNAMIC_ANALYSIS_RESERVED],
            _bounds(),
        )


def test_unknown_fields_and_caller_verdict_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    raw = bundle.model_dump(mode="json", by_alias=True)
    raw["verdict"] = "PASS"
    with pytest.raises(ValidationError):
        SecurityEvidenceBundle.model_validate(raw)


@pytest.mark.parametrize(
    "limitation",
    [
        "2026-08-02T12:00:00Z",
        "123e4567-e89b-12d3-a456-426614174000",
        "x" * 513,
        "/local/machine/path",
    ],
)
def test_nonportable_or_unbounded_plan_values_are_rejected(tmp_path: Path, limitation: str) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    subject, items = describe_local_artifact(artifact)
    scope = SecurityInspectionScope(
        logical_paths=[items[0].logical_path],
        mandatory_paths=[items[0].logical_path],
        declared_file_count=1,
        declared_total_bytes=1,
    )
    with pytest.raises(ValidationError):
        build_plan(
            subject,
            scope,
            builtin_scanner_identity().capability.methods,
            _bounds(),
            limitations=[limitation],
        )


def test_tampered_coverage_is_rejected(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    raw = bundle.model_dump(mode="json", by_alias=True)
    raw["coverage"]["inspected_files"] = 0
    with pytest.raises(ValidationError, match="inspected-file count"):
        SecurityEvidenceBundle.model_validate(raw)


def test_untrusted_scanner_precedence(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    policy = build_security_policy(
        SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE,
        accepted_scanner_ids=["scanner_" + "0" * 32],
    )
    evaluation = evaluate_security_bundle(bundle, policy)
    assert evaluation.verdict == SecurityVerdict.SCANNER_UNTRUSTED


def test_enterprise_requires_trusted_signature(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    policy = build_security_policy(SecurityRequirementProfile.ENTERPRISE_ARTIFACT_SECURITY_GATE)
    unsigned = evaluate_security_bundle(bundle, policy)
    assert unsigned.verdict == SecurityVerdict.SCANNER_UNTRUSTED


def test_regulated_profile_fails_closed(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    policy = build_security_policy(SecurityRequirementProfile.REGULATED_ARTIFACT_SECURITY_GATE)
    result = evaluate_security_bundle(bundle, policy)
    assert result.verdict == SecurityVerdict.FAIL


def test_external_adapter_rejects_fake_pass_and_unknown_schema() -> None:
    with pytest.raises(OmivInputError, match="unknown"):
        import_external_result({"schema": "vendor.scan.v9"})
    with pytest.raises(OmivInputError, match="summary"):
        import_external_result({"schema": "omiv.security-evidence-bundle.v1", "pass": True})


def test_governance_adapter_reconstructs_policy_driven_pass(tmp_path: Path) -> None:
    artifact = tmp_path / "a.safetensors"
    artifact.write_bytes((2).to_bytes(8, "little") + b"{}")
    bundle, _, _ = _inspect(artifact)
    policy = build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE)
    evaluation = evaluate_security_bundle(bundle, policy)
    digest = bundle.subject.content_digest
    assert digest is not None
    subject = build_subject(
        artifact_digest=digest,
        artifact_format="safetensors",
        origin_type="local",
        logical_locator="synthetic/a.safetensors",
        variant="synthetic",
    )
    adapter, reference = adapt_governance_security_evidence(subject, bundle, evaluation, policy)
    assert adapter.requirement_outcome == "SATISFIED"
    assert reference.schema_id == "omiv.artifact-security-evidence.v1"
    assert reference.verification_mode.value == "FULL"


def test_governance_adapter_rejects_wrong_subject(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    evaluation = evaluate_security_bundle(
        bundle, build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE)
    )
    wrong = build_subject(
        artifact_digest="0" * 64,
        artifact_format="generic-file",
        origin_type="local",
        logical_locator="synthetic/wrong",
        variant="synthetic",
    )
    with pytest.raises(OmivInputError, match="does not match"):
        adapt_governance_security_evidence(
            wrong,
            bundle,
            evaluation,
            build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE),
        )


def test_governance_adapter_rejects_policy_mismatch_and_tampered_evaluation(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "a.safetensors"
    artifact.write_bytes((2).to_bytes(8, "little") + b"{}")
    bundle, _, _ = _inspect(artifact)
    release_policy = build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE)
    personal_policy = build_security_policy(
        SecurityRequirementProfile.PERSONAL_LOCAL_SECURITY_REVIEW
    )
    evaluation = evaluate_security_bundle(bundle, release_policy)
    digest = bundle.subject.content_digest
    assert digest is not None
    subject = build_subject(
        artifact_digest=digest,
        artifact_format="safetensors",
        origin_type="local",
        logical_locator="synthetic/a.safetensors",
        variant="synthetic",
    )
    with pytest.raises(OmivInputError, match="reconstruction"):
        adapt_governance_security_evidence(subject, bundle, evaluation, personal_policy)
    tampered = evaluation.model_copy(update={"verdict": SecurityVerdict.PASS_WITH_LIMITATIONS})
    with pytest.raises(OmivInputError, match="reconstruction"):
        adapt_governance_security_evidence(subject, bundle, tampered, release_policy)


def test_governance_adapter_limitations_are_selected_by_security_policy(tmp_path: Path) -> None:
    artifact = tmp_path / "a.safetensors"
    artifact.write_bytes((2).to_bytes(8, "little") + b"{}")
    bundle, _, _ = _inspect(artifact)
    policy = build_security_policy(SecurityRequirementProfile.PERSONAL_LOCAL_SECURITY_REVIEW)
    evaluation = evaluate_security_bundle(bundle, policy)
    digest = bundle.subject.content_digest
    assert digest is not None
    subject = build_subject(
        artifact_digest=digest,
        artifact_format="safetensors",
        origin_type="local",
        logical_locator="synthetic/a.safetensors",
        variant="synthetic",
    )
    adapter, _ = adapt_governance_security_evidence(subject, bundle, evaluation, policy)
    assert adapter.requirement_outcome == "SATISFIED_WITH_LIMITATIONS"


def test_report_is_reconstructable_and_has_boundary_warning(tmp_path: Path) -> None:
    artifact = tmp_path / "a.txt"
    artifact.write_text("x")
    bundle, _, _ = _inspect(artifact)
    evaluation = evaluate_security_bundle(
        bundle, build_security_policy(SecurityRequirementProfile.TEAM_RELEASE_SECURITY_GATE)
    )
    report = build_security_report(bundle, evaluation)
    assert verify_security_report(report, bundle, evaluation) == report
    markdown = render_security_markdown(report)
    assert "Code execution: **NO**" in markdown
    assert "No findings does not prove safety" in markdown
    assert "Scanner correctness independently proven: **NOT_ESTABLISHED**" in markdown
    assert "Declared-scope coverage" in markdown
    assert "Scanner-capability coverage" in markdown
    altered = report.model_copy(update={"blocking_findings": 99})
    with pytest.raises(OmivInputError, match="reconstruction"):
        verify_security_report(altered, bundle, evaluation)


@pytest.mark.parametrize("origin", ["local", "s3", "oci", "internal_registry", "air_gapped"])
def test_generic_artifact_reference_origins(origin: str) -> None:
    reference = artifact_reference(
        origin_type=origin,
        provider="synthetic-provider",
        repository="synthetic-artifact",
        variant="test",
        file_count=1,
        total_declared_bytes=1,
        content_digest="1" * 64,
        format="onnx",
    )
    assert reference.origin_type == origin


def test_security_core_has_no_model_pack_dependency() -> None:
    root = Path(__file__).parents[1] / "src" / "omiv" / "security"
    text = "\n".join(path.read_text() for path in root.glob("*.py"))
    assert "omiv.model_packs" not in text
    assert "kimi_k3" not in text.lower()


def test_scanner_capability_does_not_claim_unimplemented_categories() -> None:
    categories = set(builtin_scanner_identity().capability.finding_categories)
    assert FindingClassification.OVERLAPPING_PAYLOAD_RANGE not in categories
    assert FindingClassification.REMOTE_CODE_REFERENCE not in categories
    assert FindingClassification.MODEL_CUSTOM_CODE_DECLARATION not in categories


def test_benign_documentation_words_do_not_create_execution_findings(tmp_path: Path) -> None:
    artifact = tmp_path / "README.txt"
    artifact.write_text(
        "This documentation discusses password, token, secret, subprocess, import, shell, "
        "and https://example.invalid without executable syntax."
    )
    bundle, _, _ = _inspect(artifact)
    categories = {finding.category for finding in bundle.findings}
    assert FindingClassification.SUBPROCESS_EXECUTION_PATTERN not in categories
    assert FindingClassification.SHELL_EXECUTION_PATTERN not in categories
    assert FindingClassification.DYNAMIC_IMPORT_PATTERN not in categories
    assert FindingClassification.SUSPICIOUS_NETWORK_REFERENCE not in categories


def test_signed_object_registry_has_bounded_security_types() -> None:
    assert OBJECT_METADATA[SignedObjectType.SECURITY_EVIDENCE_BUNDLE] == (
        {"omiv.security-evidence-bundle.v1"},
        "bundle_id",
        "bundle_digest",
    )
    assert EXPECTED_PURPOSE[SignedObjectType.SECURITY_SCAN_EXECUTION_RECORD] == (
        SignaturePurpose.SECURITY_SCAN_ISSUANCE
    )
    assert EXPECTED_PURPOSE[SignedObjectType.SECURITY_EVALUATION] == (
        SignaturePurpose.SECURITY_EVALUATION_ISSUANCE
    )


def test_schema_registry_is_explicit_and_unknown_schema_fails() -> None:
    assert schema_model("omiv.security-evidence-bundle.v1") is SecurityEvidenceBundle
    assert len(SECURITY_SCHEMA_MODELS) == 14
    with pytest.raises(ValueError, match="unknown Phase 5F schema"):
        schema_model("omiv.security-unknown.v1")


def test_checked_in_security_artifact_index_verifies() -> None:
    root = Path(__file__).parents[1]
    from omiv.security.models import SecurityArtifactIndex

    index = SecurityArtifactIndex.model_validate(
        json.loads((root / "security" / "artifact-index.json").read_text())
    )
    assert verify_security_artifact_index(index, root) == index
    indexed = {entry.relative_path for entry in index.entries}
    assert "security/examples/artifacts/clean.safetensors" in indexed
    assert "security/examples/artifacts/partial-scan.gguf" in indexed
    untrusted_signed = json.loads(
        (root / "security/examples/untrusted-clean.enterprise-security-evaluation.json").read_text()
    )
    assert untrusted_signed["signature_trust"] == "UNTRUSTED_BY_POLICY"
    assert untrusted_signed["verdict"] == "SCANNER_UNTRUSTED"


def test_cli_plan_inspect_verify_evaluate_and_show(tmp_path: Path) -> None:
    artifact = tmp_path / "model.onnx"
    artifact.write_text("synthetic static metadata")
    plan = tmp_path / "plan.json"
    execution = tmp_path / "execution.json"
    bundle = tmp_path / "bundle.json"
    report = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    evaluation = tmp_path / "evaluation.json"
    result = runner.invoke(
        app, ["security", "plan-create", "--artifact", str(artifact), "--output", str(plan)]
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app,
        [
            "security",
            "inspect",
            "--plan",
            str(plan),
            "--artifact",
            str(artifact),
            "--output",
            str(execution),
            "--bundle-output",
            str(bundle),
            "--report-output",
            str(report),
            "--markdown-output",
            str(markdown),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "PASS_WITH_LIMITATIONS" in result.output
    evidence_result = runner.invoke(app, ["security", "evidence-verify", "--bundle", str(bundle)])
    assert evidence_result.exit_code == 1
    assert "verdict=NOT_EVALUATED" in evidence_result.output
    result = runner.invoke(
        app,
        [
            "security",
            "evaluate",
            "--bundle",
            str(bundle),
            "--policy",
            "team_release_security_gate",
            "--output",
            str(evaluation),
        ],
    )
    assert result.exit_code == 2, result.output
    assert runner.invoke(app, ["security", "show", "--input", str(evaluation)]).exit_code == 0
    assert (
        runner.invoke(
            app,
            [
                "security",
                "report-verify",
                "--report",
                str(report),
                "--bundle",
                str(bundle),
                "--evaluation",
                str(evaluation),
            ],
        ).exit_code
        == 2
    )  # report was built under the personal policy, so mismatch is rejected


def test_cli_governance_adapter_is_policy_driven(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    bundle_path = root / "security/examples/clean.security-bundle.json"
    evaluation_path = root / "security/examples/clean.security-evaluation.json"
    bundle = SecurityEvidenceBundle.model_validate(json.loads(bundle_path.read_text()))
    digest = bundle.subject.content_digest
    assert digest is not None
    subject = build_subject(
        artifact_digest=digest,
        artifact_format="safetensors",
        origin_type="local",
        logical_locator="synthetic/clean.safetensors",
        variant="synthetic",
    )
    subject_path = tmp_path / "subject.json"
    subject_path.write_text(json.dumps(subject.model_dump(mode="json")))
    result = runner.invoke(
        app,
        [
            "security",
            "governance-adapt",
            "--bundle",
            str(bundle_path),
            "--evaluation",
            str(evaluation_path),
            "--policy",
            "personal_local_security_review",
            "--governance-subject",
            str(subject_path),
            "--output",
            str(tmp_path / "adapter.json"),
            "--evidence-output",
            str(tmp_path / "evidence.json"),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "SATISFIED_WITH_LIMITATIONS" in result.output


def test_cli_report_verify_preserves_limited_exit_status() -> None:
    root = Path(__file__).parents[1]
    result = runner.invoke(
        app,
        [
            "security",
            "report-verify",
            "--report",
            str(root / "reports/security/clean.security-report.json"),
            "--bundle",
            str(root / "security/examples/clean.security-bundle.json"),
            "--evaluation",
            str(root / "security/examples/clean.security-evaluation.json"),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "verdict=PASS_WITH_LIMITATIONS" in result.output


def test_deterministic_ids_and_json(tmp_path: Path) -> None:
    artifact = tmp_path / "model.gguf"
    artifact.write_bytes(b"GGUFsynthetic")
    first, first_plan, _ = _inspect(artifact)
    second, second_plan, _ = _inspect(artifact)
    assert first_plan == second_plan
    assert first == second
    assert pretty_json(first) == pretty_json(second)
    assert canonical_sha256(json.loads(pretty_json(first))) == canonical_sha256(
        json.loads(pretty_json(second))
    )


def test_fresh_example_regeneration_is_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_index = generate_security_examples(first)
    second_index = generate_security_examples(second)
    assert first_index == second_index
    first_files = {
        path.relative_to(first): path.read_bytes() for path in first.rglob("*") if path.is_file()
    }
    second_files = {
        path.relative_to(second): path.read_bytes() for path in second.rglob("*") if path.is_file()
    }
    assert first_files == second_files
