"""Phase 6F Assurance Bundle vertical-slice tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from omiv.assurance.archive import pack_bundle
from omiv.assurance.models import (
    AssuranceBundleManifest,
    AssuranceTrustPolicy,
    BundleStatus,
    PreflightStatus,
)
from omiv.assurance.operations import (
    build_bundle,
    build_preflight,
    load_request,
    verify_bundle,
)
from omiv.assurance.registry import supported_schemas
from omiv.assurance.signatures import build_signature, verify_signatures, write_signature
from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError

ROOT = Path(__file__).parents[1]
KNOWN_SOURCE = "payload-integrity/comparisons/exact.json"
KNOWN_SCHEMA = "omiv.payload-manifest-comparison.v1"
runner = CliRunner()


def _request(
    tmp_path: Path, requirements: list[dict], operations: list[dict] | None = None
) -> Path:
    path = tmp_path / "request.json"
    path.write_text(
        json.dumps(
            {
                "schema": "omiv.assurance-request.v1",
                "request_id": "unsloth-case-followup",
                "subject": "synthetic Phase 6F interoperability test",
                "requirements": requirements,
                "planned_operations": operations or [],
            }
        ),
        encoding="utf-8",
    )
    return path


def _known(member_path: str = "evidence/payload-comparison.json") -> dict:
    return {
        "member_path": member_path,
        "source_path": KNOWN_SOURCE,
        "phase": "PHASE_6A",
        "required": True,
        "media_type": "application/json",
        "expected_schema": KNOWN_SCHEMA,
        "dimension": "STRUCTURE",
        "verdict_role": "DIMENSION_VERDICT",
    }


def test_tracked_offline_example_preflights_ready() -> None:
    request = load_request(ROOT / "examples/assurance-bundle/request.json")
    plan = build_preflight(request, ROOT)
    assert plan.status == PreflightStatus.READY
    assert not any((plan.costs.download, plan.costs.network, plan.costs.conversion, plan.costs.gpu))


def test_tracked_conformance_requests_preserve_complete_and_incomplete_states() -> None:
    valid = build_preflight(
        load_request(ROOT / "fixtures/assurance-bundle/valid-request.json"), ROOT
    )
    incomplete = build_preflight(
        load_request(ROOT / "fixtures/assurance-bundle/incomplete-request.json"), ROOT
    )
    assert valid.status == PreflightStatus.READY
    assert incomplete.status == PreflightStatus.BLOCKED
    assert incomplete.costs.gpu is True


def test_complete_plan_build_and_offline_verify(tmp_path: Path) -> None:
    request = load_request(_request(tmp_path, [_known()]))
    plan = build_preflight(request, ROOT)
    assert plan.status == PreflightStatus.READY
    assert plan.costs.network is False
    assert plan.members[0].schema_support.value == "SUPPORTED_AND_VALID"

    bundle = tmp_path / "bundle"
    manifest = build_bundle(plan, ROOT, bundle)
    assert manifest.status == BundleStatus.COMPLETE
    manifest_json = json.loads((bundle / "assurance-bundle.json").read_text())
    assert not any("source_path" in item for item in manifest_json["members"])
    assert {item["path"] for item in manifest_json["core_files"]} == {
        "subject.json",
        "verdict.json",
        "evidence-index.json",
        "findings.json",
        "unknowns.json",
        "capabilities.json",
    }
    verdict = json.loads((bundle / "verdict.json").read_text())
    assert verdict["overall"] == "PASS"
    assert verdict["dimensions"][0]["dimension"] == "STRUCTURE"

    report = verify_bundle(bundle)
    assert report.status == BundleStatus.COMPLETE
    assert report.available == 1
    assert report.evidence["offline"] is True


def test_missing_unknown_and_costly_work_are_explicit_and_fail_closed(tmp_path: Path) -> None:
    unknown = {
        "member_path": "evidence/future.json",
        "source_path": KNOWN_SOURCE,
        "phase": "EXTERNAL",
        "required": False,
        "media_type": "application/json",
        "expected_schema": "external.future-evidence.v1",
    }
    missing = {
        "member_path": "evidence/missing.json",
        "source_path": "not-present/missing.json",
        "phase": "PHASE_6E",
        "required": True,
        "media_type": "application/json",
        "expected_schema": "omiv.runtime-resolution-parity-evidence.v1",
    }
    request = load_request(
        _request(
            tmp_path,
            [unknown, missing],
            [
                {"cost_class": "NETWORK", "reason": "would collect missing evidence"},
                {"cost_class": "GPU", "reason": "would run compatibility probes"},
            ],
        )
    )
    plan = build_preflight(request, ROOT)
    assert plan.status == PreflightStatus.BLOCKED
    assert plan.costs.network and plan.costs.gpu
    assert {issue for item in plan.members for issue in item.issues} >= {
        "EVIDENCE_SCHEMA_UNSUPPORTED_FOR_PHASE",
        "REQUIRED_EVIDENCE_MISSING",
    }

    bundle = tmp_path / "incomplete"
    manifest = build_bundle(plan, ROOT, bundle)
    assert manifest.status == BundleStatus.INCOMPLETE
    report = verify_bundle(bundle)
    assert report.status == BundleStatus.INCOMPLETE
    assert report.missing == 1
    assert report.unknown == 1


def test_tampering_and_untracked_files_are_invalid(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    evidence = bundle / "evidence/payload-comparison.json"
    evidence.write_text("{}", encoding="utf-8")
    (bundle / "untracked.txt").write_text("unexpected", encoding="utf-8")

    report = verify_bundle(bundle)
    assert report.status == BundleStatus.INVALID
    assert {item.code for item in report.findings} >= {
        "BUNDLE_FILE_SET_MISMATCH",
        "EVIDENCE_INTEGRITY_MISMATCH",
    }


def test_core_projection_tampering_is_invalid(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    verdict_path = bundle / "verdict.json"
    verdict = json.loads(verdict_path.read_text())
    verdict["overall"] = "FAIL"
    verdict_path.write_text(json.dumps(verdict), encoding="utf-8")
    assert verify_bundle(bundle).status == BundleStatus.INVALID


def test_v1_rejects_noncanonical_core_file_set(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    manifest_path = bundle / "assurance-bundle.json"
    raw = json.loads(manifest_path.read_text())
    raw["core_files"][0]["path"] = "alternate-subject.json"
    (bundle / "subject.json").replace(bundle / "alternate-subject.json")
    body = {key: value for key, value in raw.items() if key not in {"bundle_id", "bundle_digest"}}
    digest = canonical_sha256({"domain": raw["schema"], "body": body})
    raw["bundle_id"] = f"assurance_bundle_{digest[:32]}"
    raw["bundle_digest"] = digest
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    report = verify_bundle(bundle)
    assert report.status == BundleStatus.INVALID
    assert "CORE_FILE_SET_MISMATCH" in {item.code for item in report.findings}


def test_unsupported_required_feature_fails_closed(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    manifest_path = bundle / "assurance-bundle.json"
    raw = json.loads(manifest_path.read_text())
    raw["required_features"].append("future-feature")
    body = {key: value for key, value in raw.items() if key not in {"bundle_id", "bundle_digest"}}
    digest = canonical_sha256({"domain": raw["schema"], "body": body})
    raw["bundle_id"] = f"assurance_bundle_{digest[:32]}"
    raw["bundle_digest"] = digest
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(OmivInputError, match="unsupported Assurance Bundle profile"):
        verify_bundle(bundle)


def test_manifest_semantic_projection_must_reconstruct_from_evidence(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    manifest_path = bundle / "assurance-bundle.json"
    raw = json.loads(manifest_path.read_text())
    raw["members"][0]["semantic_status"] = "FAIL"
    raw["members"][0]["semantic_summary"] = "forged projection"
    body = {key: value for key, value in raw.items() if key not in {"bundle_id", "bundle_digest"}}
    digest = canonical_sha256({"domain": raw["schema"], "body": body})
    raw["bundle_id"] = f"assurance_bundle_{digest[:32]}"
    raw["bundle_digest"] = digest
    AssuranceBundleManifest.model_validate(raw)
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")

    report = verify_bundle(bundle)
    assert report.status == BundleStatus.INVALID
    assert "SEMANTIC_PROJECTION_MISMATCH" in {item.code for item in report.findings}


def test_phase5_schema_registry_is_interoperable(tmp_path: Path) -> None:
    assert "omiv.model-passport.v1" in supported_schemas()
    requirement = {
        "member_path": "provenance/passport.json",
        "source_path": "passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json",
        "phase": "PHASE_5",
        "required": True,
        "media_type": "application/json",
        "expected_schema": "omiv.model-passport.v1",
        "dimension": "PROVENANCE",
        "verdict_role": "SUPPORTING",
    }
    plan = build_preflight(load_request(_request(tmp_path, [requirement])), ROOT)
    assert plan.status == PreflightStatus.READY
    assert plan.members[0].schema_support.value == "SUPPORTED_AND_VALID"


def test_phase7b_candidate_evidence_is_not_registered_in_phase6f() -> None:
    assert "omiv.runtime-compatibility-evidence.v1" not in supported_schemas()


def test_deterministic_archive_and_offline_cli_verification(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    first, second = tmp_path / "first.omiv", tmp_path / "second.omiv"
    pack_bundle(bundle, first)
    pack_bundle(bundle, second)
    assert first.read_bytes() == second.read_bytes()
    result = runner.invoke(app, ["assurance", "verify", "--bundle", str(first)])
    assert result.exit_code == 0, result.output
    assert "COMPLETE" in result.stdout
    product_result = runner.invoke(app, ["verify", str(first)])
    assert product_result.exit_code == 0, product_result.output
    assert "COMPLETE" in product_result.stdout


def test_signature_integrity_and_external_trust_policy(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    private = Ed25519PrivateKey.generate()
    signature = build_signature(bundle, private, "test-key")
    write_signature(bundle, signature)
    policy = AssuranceTrustPolicy(
        policy_id="assurance-policy.test.v1",
        allowed_key_ids=["test-key"],
        allowed_public_key_sha256=[hashlib.sha256(bytes.fromhex(signature.public_key)).hexdigest()],
    )
    valid, trusted, issues = verify_signatures(bundle, policy)
    assert (valid, trusted, issues) == (1, 1, [])
    rejected = policy.model_copy(update={"allowed_key_ids": ["different-key"]})
    assert verify_signatures(bundle, rejected)[2] == ["TRUST_POLICY_MINIMUM_SIGNATURES_NOT_MET"]


def test_opaque_binary_members_are_streamed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    artifact = source_root / "payload.bin"
    artifact.write_bytes(b"streamed" * 200_000)
    request = load_request(
        _request(
            tmp_path,
            [
                {
                    "member_path": "provenance/payload.bin",
                    "source_path": "payload.bin",
                    "phase": "EXTERNAL",
                    "required": True,
                    "media_type": "application/octet-stream",
                    "expected_schema": None,
                    "dimension": "PROVENANCE",
                    "verdict_role": "SUPPORTING",
                }
            ],
        )
    )
    original = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        if path == artifact:
            raise AssertionError("binary evidence must be streamed")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    plan = build_preflight(request, source_root)
    bundle = tmp_path / "streamed-bundle"
    build_bundle(plan, source_root, bundle)
    assert verify_bundle(bundle).status == BundleStatus.COMPLETE


def test_build_detects_change_after_preflight(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "evidence.json"
    source.write_bytes((ROOT / KNOWN_SOURCE).read_bytes())
    request = load_request(
        _request(
            tmp_path,
            [
                {
                    **_known(),
                    "source_path": "evidence.json",
                }
            ],
        )
    )
    plan = build_preflight(request, source_root)
    source.write_text("{}", encoding="utf-8")
    with pytest.raises(OmivInputError, match="changed after preflight"):
        build_bundle(plan, source_root, tmp_path / "bundle")


def test_request_rejects_traversal_and_portable_collisions(tmp_path: Path) -> None:
    with pytest.raises(OmivInputError):
        load_request(_request(tmp_path, [{**_known(), "source_path": "../secret.json"}]))
    with pytest.raises(OmivInputError):
        load_request(_request(tmp_path, [_known("Evidence/a.json"), _known("evidence/A.json")]))
    with pytest.raises(OmivInputError, match="opaque binary"):
        load_request(
            _request(
                tmp_path,
                [
                    {
                        **_known(),
                        "media_type": "application/octet-stream",
                        "expected_schema": None,
                    }
                ],
            )
        )


def test_bundle_symlink_fails_closed_when_platform_supports_it(tmp_path: Path) -> None:
    plan = build_preflight(load_request(_request(tmp_path, [_known()])), ROOT)
    bundle = tmp_path / "bundle"
    build_bundle(plan, ROOT, bundle)
    link = bundle / "broken-link"
    try:
        link.symlink_to(bundle / "absent")
    except OSError:
        pytest.skip("symlinks unavailable")
    report = verify_bundle(bundle)
    assert report.status == BundleStatus.INVALID
    assert "BUNDLE_SYMLINK_PRESENT" in {item.code for item in report.findings}


def test_assurance_slice_has_no_network_process_or_gpu_execution_surface() -> None:
    source = (ROOT / "src/omiv/assurance/operations.py").read_text(encoding="utf-8")
    for forbidden in ("subprocess", "socket", "urllib", "requests", "httpx", "cuda"):
        assert f"import {forbidden}" not in source
    assert "collect_" not in source
    assert "run_conversion" not in source


def test_cli_is_concise_but_retains_machine_reports(tmp_path: Path) -> None:
    request = _request(tmp_path, [_known()])
    plan = tmp_path / "plan.json"
    planned = runner.invoke(
        app,
        [
            "assurance",
            "plan",
            "--request",
            str(request),
            "--root",
            str(ROOT),
            "--output",
            str(plan),
        ],
    )
    assert planned.exit_code == 0
    assert planned.stdout.startswith("READY members=1 missing=0 unknown=0 costly=none")
    assert json.loads(plan.read_text())["schema"] == "omiv.assurance-plan.v1"

    bundle = tmp_path / "bundle"
    built = runner.invoke(
        app,
        ["assurance", "build", "--plan", str(plan), "--root", str(ROOT), "--output", str(bundle)],
    )
    assert built.exit_code == 0
    assert built.stdout.startswith("COMPLETE bundle=assurance_bundle_")

    report = tmp_path / "verification.json"
    verified = runner.invoke(
        app,
        ["assurance", "verify", "--bundle", str(bundle), "--report-output", str(report)],
    )
    assert verified.exit_code == 0
    assert verified.stdout.startswith("COMPLETE bundle=assurance_bundle_")
    assert json.loads(report.read_text())["evidence"]["offline"] is True
