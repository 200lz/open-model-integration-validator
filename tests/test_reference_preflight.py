"""Muse Glimmer acceptance tests for provider-neutral Reference Preflight."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import zlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from omiv.assurance.archive import pack_bundle
from omiv.assurance.models import (
    BundleStatus,
    PreflightStatus,
    SchemaSupport,
    VerdictRole,
)
from omiv.assurance.operations import build_bundle, build_preflight, verify_bundle
from omiv.cli import app
from omiv.reference_preflight.models import (
    ArtifactRole,
    ReferencePreflightEvidence,
    ReferencePreflightProfile,
)
from omiv.reference_preflight.operations import (
    build_assurance_request,
    build_reference_preflight,
    concise_evidence_summary,
    load_profile,
    write_evidence,
)
from omiv.reference_preflight.probes import (
    PNG_HEIGHT,
    PNG_WIDTH,
    RED_SQUARE_END,
    RED_SQUARE_START,
    build_red_square_png,
)
from omiv.runtime_compatibility.models import (
    BoundedCapture,
    EnvironmentVariable,
    ProcessCapture,
    StageStatus,
    derive_native_stage_results,
)

ROOT = Path(__file__).parents[1]
PROFILE_PATH = ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json"
IMAGE_FIXTURE_PATH = ROOT / "examples/reference-preflight/probes/red-square.png"
runner = CliRunner()


def _profile() -> ReferencePreflightProfile:
    return load_profile(PROFILE_PATH)


def _evidence(reference: str = "meta-models/Muse-Glimmer-30B-GGUF") -> ReferencePreflightEvidence:
    return build_reference_preflight(_profile(), reference)


def test_muse_offline_replay_separates_every_evidence_boundary() -> None:
    first = _evidence()
    second = _evidence()

    assert first == second
    assert first.resolved_identity == (
        "meta-models/Muse-Glimmer-30B-GGUF@43c7eadd41352a299ea8e0a36b3157978dd63596"
    )
    assert first.resolved_identity_status == "REMOTE_REVISION_PINNED"
    assert first.payload_verification == "NOT_DOWNLOADED"
    assert first.source_binding == "NOT_ESTABLISHED"
    assert first.architecture_status == "DECLARED"
    assert first.architecture == "muse-glimmer"
    assert first.tokenizer_configuration == "REMOTE_METADATA_OBSERVED"
    assert first.runtime_probe == "NOT_RUN"
    assert first.numerical_fidelity == "NOT_EVALUATED"
    assert first.semantic_fidelity == "NOT_EVALUATED"
    assert first.performance == "NOT_EVALUATED"
    assert first.safety == "NOT_EVALUATED"
    assert first.production_readiness == "NOT_ESTABLISHED"

    artifacts = {item.role: item for item in first.profile.artifacts}
    assert set(artifacts) == {
        ArtifactRole.MAIN_MODEL,
        ArtifactRole.PERCEPTION_ENCODER,
        ArtifactRole.DRAFTER,
    }
    assert all(item.payload_verification == "NOT_DOWNLOADED" for item in artifacts.values())
    assert artifacts[ArtifactRole.MAIN_MODEL].provider_identity == (
        "4cc57c0f51040a226e5a72cc47b7613f7772950e460a665f7083de89f183f60e"
    )
    assert all(
        item.cryptographic_binding == "NOT_ESTABLISHED" for item in first.profile.relationships
    )

    llama, ollama = first.profile.runtime_candidates
    assert llama.exact_release == "b10353"
    assert llama.exact_commit == "f8def7fe168bab245fbf15d3f18b26dbb1ef73c8"
    assert llama.support_commit == "62bf73d25c53b8161f8a22894d4f90c4aebbd7d0"
    assert ollama.compatibility_status == "DECLARED_NOT_PROBED"
    registry = first.profile.registry_observations[0]
    assert registry.mutable_tag is True
    assert registry.manifest_digest == (
        "de878ce33ad81d060001db1469a02eebe4d86f0ad58cfe52dc062fdcbe4464c1"
    )
    assert registry.runtime_probe == "NOT_RUN"
    assert {layer.role for layer in registry.layers} == {"model", "projector", "params"}


def test_concise_verdict_is_a_deterministic_twelve_line_projection() -> None:
    evidence = _evidence()
    first = concise_evidence_summary(evidence)
    second = concise_evidence_summary(_evidence())

    assert first == second
    assert len(first.splitlines()) == 12
    assert first.splitlines() == [
        "Artifact reference    meta-models/Muse-Glimmer-30B-GGUF",
        "Resolved identity     REMOTE_REVISION_PINNED: "
        "meta-models/Muse-Glimmer-30B-GGUF@"
        "43c7eadd41352a299ea8e0a36b3157978dd63596",
        "Payload verification  NOT_DOWNLOADED",
        "Source binding        NOT_ESTABLISHED",
        "Architecture          DECLARED: muse-glimmer",
        "Tokenizer/config      REMOTE_METADATA_OBSERVED",
        "Companion artifacts   DECLARED: DRAFTER + PERCEPTION_ENCODER",
        "Runtime candidates    llama.cpp / Ollama",
        "Runtime requirement   DECLARED_OFFICIAL_REQUIREMENT: llama.cpp >= b10353; "
        "acceptance plan pins b10353 exactly",
        "Runtime probe         NOT_RUN",
        "Provenance gaps       EXPLICIT: 6",
        f"Next step             READY_FOR_GPU: execute {evidence.future_runtime_plan.plan_id}",
    ]


@pytest.mark.parametrize(
    "reference",
    [
        "meta-models/Muse-Glimmer-30B-GGUF",
        "https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF/",
        "hf://meta-models/Muse-Glimmer-30B-GGUF",
    ],
)
def test_reference_aliases_normalize_without_becoming_resolved_identity(reference: str) -> None:
    evidence = _evidence(reference)

    assert evidence.input_reference == reference
    assert evidence.artifact_reference == "meta-models/Muse-Glimmer-30B-GGUF"
    assert evidence.resolved_identity.endswith("@43c7eadd41352a299ea8e0a36b3157978dd63596")


def test_unknown_reference_fails_without_inference() -> None:
    with pytest.raises(ValueError, match="not covered"):
        _evidence("somewhere-else/Muse-Glimmer-30B-GGUF")


def test_cli_replay_and_machine_evidence_are_byte_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    request = tmp_path / "request.json"
    arguments = [
        "reference-preflight",
        "plan",
        "--profile",
        str(PROFILE_PATH),
        "--reference",
        "meta-models/Muse-Glimmer-30B-GGUF",
        "--root",
        str(tmp_path),
    ]
    first_result = runner.invoke(
        app,
        [*arguments, "--output", str(first), "--assurance-request-output", str(request)],
    )
    second_result = runner.invoke(app, [*arguments, "--output", str(second)])

    assert first_result.exit_code == 0, first_result.output
    assert second_result.exit_code == 0, second_result.output
    assert first_result.stdout == second_result.stdout
    assert first.read_bytes() == second.read_bytes()
    assert (
        json.loads(request.read_text(encoding="utf-8"))["planned_operations"][0]["cost_class"]
        == "GPU"
    )

    verified = runner.invoke(app, ["reference-preflight", "verify", "--evidence", str(first)])
    assert verified.exit_code == 0, verified.output
    assert verified.stdout == first_result.stdout


def test_phase6f_bundle_preserves_candidate_as_supporting_evidence(tmp_path: Path) -> None:
    evidence = _evidence()
    evidence_path = tmp_path / "muse-reference-evidence.json"
    write_evidence(evidence, evidence_path)
    request = build_assurance_request(evidence, evidence_path.name)

    plan = build_preflight(request, tmp_path)
    assert request.request_id == "reference-588e595d7c9c9c71c40a3ca8"
    assert plan.plan_id == "assurance_plan_dac49586cd0838c76bd3af9baf7c2d76"
    assert plan.plan_digest == (
        "dac49586cd0838c76bd3af9baf7c2d76e49b5ba9186955ceb3157038c96ea998"
    )
    assert plan.status == PreflightStatus.REVIEW_REQUIRED
    assert plan.costs.gpu is True
    assert plan.members[0].schema_support == SchemaSupport.NOT_APPLICABLE
    assert plan.members[0].verdict_role == VerdictRole.SUPPORTING
    assert plan.members[0].semantic_status == "NOT_TESTED"

    bundle = tmp_path / "bundle"
    manifest = build_bundle(plan, tmp_path, bundle)
    report = verify_bundle(bundle)
    verdict = json.loads((bundle / "verdict.json").read_text(encoding="utf-8"))
    bundled = next((bundle / "provenance").glob("reference-preflight-*.json"))

    assert manifest.status == BundleStatus.COMPLETE
    assert manifest.bundle_id == "assurance_bundle_21d17ccfae39ef3d219c83d6926bdf3a"
    assert manifest.bundle_digest == (
        "21d17ccfae39ef3d219c83d6926bdf3a9db8d05bffa078bc432a2d0647d9a4e1"
    )
    assert report.status == BundleStatus.COMPLETE
    assert report.evidence["phase_boundaries_preserved"] is True
    assert verdict["overall"] == "UNKNOWN"
    assert verdict["verdict_id"] == "assurance_verdict_16ebe37bc2cac6b22daae8cca0c7261f"
    assert verdict["verdict_digest"] == (
        "16ebe37bc2cac6b22daae8cca0c7261f78a2a7a0b14a9bacfc8fff2f87609d17"
    )
    assert verdict["dimensions"][0]["status"] == "NOT_TESTED"
    assert bundled.read_bytes() == evidence_path.read_bytes()
    assert evidence.payload_verification == "NOT_DOWNLOADED"
    assert evidence.runtime_probe == "NOT_RUN"

    first_archive = tmp_path / "first.omiv"
    second_archive = tmp_path / "second.omiv"
    pack_bundle(bundle, first_archive)
    pack_bundle(bundle, second_archive)
    assert first_archive.read_bytes() == second_archive.read_bytes()


def test_complete_future_plan_is_canonical_and_unexecuted() -> None:
    evidence = _evidence()
    plan = evidence.future_runtime_plan

    assert plan.execution_status == "NOT_RUN"
    assert plan.unknown_stages == ["LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT"]
    assert plan.dflash_observations == ["DISABLED", "ENABLED"]
    assert plan.preferred_gpu_class == "NVIDIA RTX 5090 (32 GB VRAM)"
    assert plan.maximum_gpu_count == 1
    assert plan.maximum_pod_count == 1
    assert plan.maximum_total_authorized_compute_usd == 5
    assert plan.maximum_working_duration_seconds == 4 * 60 * 60
    assert plan.stop_new_work_before_deadline_seconds == 30 * 60
    assert plan.artifact_payload_bytes == 19_788_220_960
    assert plan.direct_llama_cpp_workspace_bytes == 50_000_000_000
    assert plan.llama_cpp_plus_ollama_workspace_bytes == 80_000_000_000
    assert plan.image_fixture == "examples/reference-preflight/probes/red-square.png"
    assert plan.image_fixture_sha256 == (
        "53bf31df09c932233812a2c7b61c89a0ecbbaee90ab63f36058099e5d008e852"
    )
    assert plan.ollama_role == "SECONDARY_RUNTIME_OBSERVATION"
    assert plan.ollama_mutable_tags == ["muse-glimmer:30b", "muse-glimmer:latest"]
    assert plan.direct_llama_cpp_independent_of_ollama is True
    assert "immediately before any future GPU execution" in plan.ollama_observation
    assert "abort on manifest drift unless a new plan is reviewed" in plan.ollama_observation
    assert "exact authorized Pod" in plan.pod_termination_requirement
    assert "verify that exact Pod is terminated" in plan.pod_termination_requirement
    assert any("GPU identity and backend observation" in item for item in plan.evidence_to_retain)
    assert any("exit codes, timeout state" in item for item in plan.evidence_to_retain)
    assert any("additional GPU or Pod" in item for item in plan.stop_conditions)
    assert any(
        "No performance, fidelity, safety or production-readiness claim" in item
        for item in plan.non_claims
    )
    assert {item.role for item in plan.artifacts} == {
        ArtifactRole.MAIN_MODEL,
        ArtifactRole.PERCEPTION_ENCODER,
        ArtifactRole.DRAFTER,
    }
    assert all(item.downloaded is False for item in plan.artifacts)
    assert sum(item.declared_size for item in plan.artifacts) == plan.artifact_payload_bytes
    assert plan.plan_id == "reference_runtime_plan_97626690850636d5dd0276f9844742c6"
    assert plan.plan_digest == (
        "97626690850636d5dd0276f9844742c6eb164a090bebed03b70a0246271f3a48"
    )
    assert evidence.profile_digest == (
        "ea5f5c792e27e8bba080fbd2a406e4629db3acb06e5d588f03ff3804e81047c3"
    )
    assert evidence.evidence_id == (
        "reference_preflight_evidence_588e595d7c9c9c71c40a3ca88822195f"
    )
    assert evidence.evidence_digest == (
        "588e595d7c9c9c71c40a3ca88822195f94c7dfcb18d0e55ede45af5332760c77"
    )

    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["future_runtime_plan"]["question"] = "coherently replaced only outside the plan"
    with pytest.raises(ValueError, match="future runtime plan canonical identity mismatch"):
        ReferencePreflightEvidence.model_validate(raw)


def test_runtime_image_fixture_is_a_fixed_png_with_one_red_square() -> None:
    fixture = IMAGE_FIXTURE_PATH.read_bytes()

    assert fixture == build_red_square_png()
    assert len(fixture) == 4246
    assert hashlib.sha256(fixture).hexdigest() == (
        "53bf31df09c932233812a2c7b61c89a0ecbbaee90ab63f36058099e5d008e852"
    )
    assert fixture.startswith(b"\x89PNG\r\n\x1a\n")

    chunks: dict[bytes, bytes] = {}
    offset = 8
    while offset < len(fixture):
        length = struct.unpack(">I", fixture[offset : offset + 4])[0]
        kind = fixture[offset + 4 : offset + 8]
        data = fixture[offset + 8 : offset + 8 + length]
        chunks[kind] = data
        offset += length + 12

    width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", chunks[b"IHDR"]
    )
    assert (width, height) == (PNG_WIDTH, PNG_HEIGHT) == (64, 64)
    assert (bit_depth, color_type, compression, filtering, interlace) == (8, 3, 0, 0, 0)
    assert chunks[b"PLTE"] == bytes((255, 255, 255, 212, 0, 0))

    scanlines = zlib.decompress(chunks[b"IDAT"])
    assert len(scanlines) == PNG_HEIGHT * (PNG_WIDTH + 1)
    for y in range(PNG_HEIGHT):
        row = scanlines[y * (PNG_WIDTH + 1) : (y + 1) * (PNG_WIDTH + 1)]
        assert row[0] == 0
        for x, palette_index in enumerate(row[1:]):
            expected = int(
                RED_SQUARE_START <= x < RED_SQUARE_END
                and RED_SQUARE_START <= y < RED_SQUARE_END
            )
            assert palette_index == expected


def test_future_plan_cannot_drift_from_observed_pins_or_bound_profile() -> None:
    profile_raw = _profile().model_dump(mode="json", by_alias=True)
    profile_raw["future_runtime_plan"]["artifacts"][0]["provider_identity"] = "0" * 64
    with pytest.raises(ValueError, match="artifact pin differs"):
        ReferencePreflightProfile.model_validate(profile_raw)

    evidence = _evidence()
    evidence_raw = evidence.model_dump(mode="json", by_alias=True)
    plan = evidence_raw["future_runtime_plan"]
    plan["question"] = "A different, coherently canonicalized future question"
    plan_body = {key: value for key, value in plan.items() if key not in {"plan_id", "plan_digest"}}
    digest = hashlib.sha256(
        json.dumps(
            {"body": plan_body, "domain": plan["schema"]},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    plan["plan_digest"] = digest
    plan["plan_id"] = f"reference_runtime_plan_{digest[:32]}"
    evidence_body = {
        key: value
        for key, value in evidence_raw.items()
        if key not in {"evidence_id", "evidence_digest"}
    }
    evidence_digest = hashlib.sha256(
        json.dumps(
            {"body": evidence_body, "domain": evidence_raw["schema"]},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    evidence_raw["evidence_digest"] = evidence_digest
    evidence_raw["evidence_id"] = f"reference_preflight_evidence_{evidence_digest[:32]}"
    with pytest.raises(ValueError, match="differs from the bound profile plan"):
        ReferencePreflightEvidence.model_validate(evidence_raw)


def _capture(raw: bytes) -> BoundedCapture:
    return BoundedCapture(
        captured_base64=base64.b64encode(raw).decode("ascii"),
        captured_bytes=len(raw),
        limit_bytes=4096,
        overflow=False,
        captured_sha256=hashlib.sha256(raw).hexdigest(),
    )


def test_phase7b1_self_authored_pass_declaration_remains_conservative() -> None:
    declared = json.dumps(
        {
            "schema": "omiv.runtime-compatibility-runner-report.v1",
            "status": "PASS",
            "stages": [
                {"stage": stage, "status": "PASS"}
                for stage in ("LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT")
            ],
        },
        sort_keys=True,
    )
    capture = ProcessCapture(
        arguments=["{runtime_executable}"],
        environment=[EnvironmentVariable(name="PATH", value="/usr/bin:/bin")],
        return_code=0,
        timed_out=False,
        duration_ms=1,
        stdout=_capture(declared.encode("utf-8")),
        stderr=_capture(b""),
    )

    stages, issues = derive_native_stage_results(capture, declared)

    assert issues == []
    assert [item.status for item in stages] == [
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.PASS,
    ]


def test_generic_engine_has_no_muse_branch_and_accepts_another_profile() -> None:
    profile = _profile()
    raw = profile.model_dump(mode="json", by_alias=True)
    raw["profile_name"] = "Provider-neutral synthetic reference"
    raw["canonical_reference"] = "provider.example/model"
    raw["reference_aliases"] = ["provider.example/model"]
    raw["resolved_revision"] = "revision-001"
    raw["configuration"]["architecture"] = "example-architecture"
    synthetic = ReferencePreflightProfile.model_validate(raw)

    evidence = build_reference_preflight(synthetic, "provider.example/model")
    source = (
        (ROOT / "src/omiv/reference_preflight/operations.py").read_text(encoding="utf-8").lower()
    )

    assert evidence.artifact_reference == "provider.example/model"
    assert evidence.resolved_identity == "provider.example/model@revision-001"
    assert evidence.architecture == "example-architecture"
    assert "muse" not in source
    for forbidden in ("subprocess", "socket", "urllib", "requests", "httpx"):
        assert f"import {forbidden}" not in source
