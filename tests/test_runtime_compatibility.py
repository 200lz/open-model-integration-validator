"""Candidate Phase 7B local runtime compatibility profile tests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.runtime_compatibility.models import (
    PROFILE_ID,
    CompatibilityStatus,
    PlanStatus,
    RuntimeCompatibilityLimits,
    RuntimeCompatibilityRequest,
    RuntimeTestVector,
    StageStatus,
)
from omiv.runtime_compatibility.operations import (
    build_plan,
    execute_plan,
    load_evidence,
    load_request,
)

ROOT = Path(__file__).parents[1]
runner = CliRunner()
VERSION = "llama.cpp synthetic-runner 1.0"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rehash_evidence(value: dict[str, object]) -> None:
    body = {
        key: item
        for key, item in value.items()
        if key not in {"evidence_id", "evidence_digest"}
    }
    digest = canonical_sha256({"domain": value["schema"], "body": body})
    value["evidence_id"] = f"runtime_compat_evidence_{digest[:32]}"
    value["evidence_digest"] = digest


def _script(tmp_path: Path, run_body: str) -> Path:
    path = tmp_path / "explicit-runner.py"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import sys\n"
        "import time\n"
        "from pathlib import Path\n"
        f"VERSION = {VERSION!r}\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print(VERSION)\n"
        "    raise SystemExit(0)\n"
        f"{run_body}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _request(tmp_path: Path, executable: Path, artifact: Path) -> RuntimeCompatibilityRequest:
    return RuntimeCompatibilityRequest(
        request_id="phase7b-test",
        executable_path=executable.relative_to(tmp_path).as_posix(),
        executable_sha256=_digest(executable),
        expected_runtime_version=VERSION,
        artifact_path=artifact.relative_to(tmp_path).as_posix(),
        artifact_sha256=_digest(artifact),
        test_vector=RuntimeTestVector(
            vector_id="vector-v1",
            prompt="The capital of France is",
            expected_output="Paris",
            max_generated_tokens=8,
        ),
        limits=RuntimeCompatibilityLimits(
            timeout_seconds=1,
            version_timeout_seconds=1,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_executable_bytes=64 * 1024,
            max_artifact_bytes=1024,
            max_work_files=4,
            max_work_file_bytes=1024,
            max_work_total_bytes=2048,
        ),
    )


def _fixture(
    tmp_path: Path, run_body_factory: object | None = None
) -> tuple[RuntimeCompatibilityRequest, Path, Path]:
    artifact = tmp_path / "synthetic.gguf"
    artifact.write_bytes(b"synthetic artifact, not a model\n")
    body = "sys.stdout.write('Paris')"
    if isinstance(run_body_factory, str):
        body = run_body_factory
    executable = _script(tmp_path, body)
    return _request(tmp_path, executable, artifact), executable, artifact


def test_tracked_native_output_probe_retains_raw_observation_and_unknown_internals() -> None:
    request = load_request(ROOT / "examples/runtime-compatibility/request.json")
    plan = build_plan(request, ROOT)
    assert plan.status == PlanStatus.READY
    assert plan.invocation.shell is False
    assert plan.invocation.accelerator == "CPU_ONLY"
    assert plan.costs.network is False
    assert plan.costs.download is False
    assert plan.costs.compilation is False
    assert plan.costs.conversion is False
    assert plan.costs.runtime_execution is True
    assert plan.costs.gpu is False

    evidence = execute_plan(plan, ROOT)

    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert [item.status for item in evidence.stages] == [
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.PASS,
    ]
    assert evidence.runtime.execution_sha256 == request.executable_sha256
    assert evidence.runtime.observed_version == request.expected_runtime_version
    assert evidence.artifact.execution_sha256 == request.artifact_sha256
    assert evidence.compatibility_execution is not None
    assert evidence.compatibility_execution.stdout.captured_bytes <= (
        request.limits.max_stdout_bytes
    )
    assert len(evidence.unknowns) == 4
    assert evidence.plan.plan_id == plan.plan_id
    assert evidence.plan.plan_digest == plan.plan_digest
    assert evidence.compatibility_execution.arguments == plan.invocation.run_arguments
    assert evidence.compatibility_execution.environment == plan.invocation.environment
    assert not any(argument.startswith("--omiv-") for argument in plan.invocation.run_arguments)


def test_cli_vertical_slice_writes_evidence_and_concise_stage_summary(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    planned = runner.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(ROOT / "examples/runtime-compatibility/request.json"),
            "--root",
            str(ROOT),
            "--output",
            str(plan_path),
        ],
    )
    assert planned.exit_code == 0, planned.output
    assert "executable_present=yes executable=yes executable_pinned=yes" in planned.stdout
    assert "artifact_present=yes artifact_pinned=yes" in planned.stdout
    assert "network=no download=no compilation=no conversion=no runtime=yes gpu=no" in (
        planned.stdout
    )

    executed = runner.invoke(
        app,
        [
            "runtime-compat",
            "run",
            "--plan",
            str(plan_path),
            "--root",
            str(ROOT),
            "--output",
            str(evidence_path),
        ],
    )
    assert executed.exit_code == 1, executed.output
    assert "llama.cpp\nLOAD       UNKNOWN\nTOKENIZER  UNKNOWN" in executed.stdout
    assert "OUTPUT     PASS" in executed.stdout
    assert "Runtime compatibility: NOT_VERIFIED" in executed.stdout
    assert load_evidence(evidence_path).candidate_notice == (
        "PHASE_7B_CANDIDATE_PHASE_7_UNFROZEN"
    )

    verified = runner.invoke(
        app,
        ["runtime-compat", "verify", "--evidence", str(evidence_path)],
    )
    assert verified.exit_code == 1, verified.output


def test_plan_is_read_only_and_never_executes_the_supplied_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, _executable, _artifact = _fixture(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("preflight must not start a process")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    before = sorted(path.name for path in tmp_path.iterdir())
    plan = build_plan(request, tmp_path)
    assert plan.status == PlanStatus.READY
    assert sorted(path.name for path in tmp_path.iterdir()) == before


def test_missing_explicit_executable_blocks_without_path_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path_directory = tmp_path / "path-bin"
    path_directory.mkdir()
    path_candidate = _script(path_directory, "sys.stdout.write('should not run')")
    path_candidate.rename(path_directory / "missing-runner")
    monkeypatch.setenv("PATH", str(path_directory))
    artifact = tmp_path / "synthetic.gguf"
    artifact.write_bytes(b"synthetic\n")
    request = RuntimeCompatibilityRequest(
        request_id="missing-runtime",
        executable_path="missing-runner",
        executable_sha256="0" * 64,
        expected_runtime_version=VERSION,
        artifact_path=artifact.name,
        artifact_sha256=_digest(artifact),
        test_vector=RuntimeTestVector(
            vector_id="vector-v1", prompt="prompt", expected_output="output"
        ),
    )
    plan = build_plan(request, tmp_path)
    assert plan.status == PlanStatus.BLOCKED
    assert plan.executable.observed_sha256 is None
    assert any("missing" in item.lower() for item in plan.missing)


def test_changed_artifact_after_preflight_is_not_executed(tmp_path: Path) -> None:
    request, _executable, artifact = _fixture(tmp_path)
    plan = build_plan(request, tmp_path)
    artifact.write_bytes(b"changed after preflight\n")

    evidence = execute_plan(plan, tmp_path)

    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert evidence.compatibility_execution is None
    assert all(item.status == StageStatus.NOT_TESTED for item in evidence.stages)
    assert "ARTIFACT_CHANGED_AFTER_PREFLIGHT" in {item.code for item in evidence.findings}


def test_changed_runtime_after_preflight_is_not_executed(tmp_path: Path) -> None:
    request, executable, _artifact = _fixture(tmp_path)
    plan = build_plan(request, tmp_path)
    executable.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    executable.chmod(0o755)

    evidence = execute_plan(plan, tmp_path)

    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert evidence.version_execution is None
    assert evidence.compatibility_execution is None
    assert all(item.status == StageStatus.NOT_TESTED for item in evidence.stages)
    assert "RUNTIME_CHANGED_AFTER_PREFLIGHT" in {item.code for item in evidence.findings}


@pytest.mark.parametrize("binding", ["runtime", "artifact"])
def test_mismatched_explicit_pin_blocks_preflight(tmp_path: Path, binding: str) -> None:
    request, _executable, _artifact = _fixture(tmp_path)
    request = request.model_copy(
        update={
            "executable_sha256" if binding == "runtime" else "artifact_sha256": "0" * 64
        }
    )

    plan = build_plan(request, tmp_path)

    assert plan.status == PlanStatus.BLOCKED
    selected = plan.executable if binding == "runtime" else plan.artifact
    assert selected.observed_sha256 != selected.expected_sha256
    assert selected.issues == [
        "Observed SHA-256 does not match the explicitly supplied digest."
    ]


@pytest.mark.parametrize(
    ("body", "expected_code"),
    [
        ("sys.stdout.buffer.write(b'\\xff')", "NATIVE_STDOUT_NOT_UTF8"),
        (
            "sys.stdout.write('Paris'); sys.stderr.buffer.write(b'\\xff')",
            "NATIVE_STDERR_NOT_UTF8",
        ),
        ("sys.stdout.write('x' * 2048)", "NATIVE_STDOUT_OVERFLOW"),
        ("sys.stderr.write('x' * 2048)", "NATIVE_STDERR_OVERFLOW"),
        ("time.sleep(2)", "NATIVE_EXECUTION_TIMEOUT"),
        ("raise SystemExit(7)", "NATIVE_EXECUTION_NONZERO"),
    ],
)
def test_non_utf8_overflow_timeout_and_nonzero_fail_closed_with_unknown_stages(
    tmp_path: Path, body: str, expected_code: str
) -> None:
    request, _executable, _artifact = _fixture(tmp_path, body)
    evidence = execute_plan(build_plan(request, tmp_path), tmp_path)

    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert all(item.status == StageStatus.UNKNOWN for item in evidence.stages)
    assert expected_code in {item.code for item in evidence.findings}
    assert len(evidence.unknowns) == 5
    assert evidence.compatibility_execution is not None
    assert evidence.compatibility_execution.stdout.captured_bytes <= 1024


def test_self_authored_omiv_pass_report_is_not_privileged(tmp_path: Path) -> None:
    artifact = tmp_path / "synthetic.gguf"
    artifact.write_bytes(b"synthetic artifact\n")
    report = {
        "schema": "omiv.runtime-compatibility-runner-report.v1",
        "profile_id": PROFILE_ID,
        "status": "PASS",
        "stages": [
            {"stage": stage, "status": "PASS"}
            for stage in ("LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT")
        ],
    }
    authored_output = json.dumps(report, separators=(",", ":"))
    executable = _script(
        tmp_path,
        f"sys.stdout.write({authored_output!r})",
    )
    request = _request(tmp_path, executable, artifact)
    request = request.model_copy(
        update={
            "test_vector": request.test_vector.model_copy(
                update={"expected_output": authored_output}
            )
        }
    )
    evidence = execute_plan(build_plan(request, tmp_path), tmp_path)
    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert [item.status for item in evidence.stages] == [
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.UNKNOWN,
        StageStatus.PASS,
    ]
    assert all("runtime-compatibility-runner-report" not in item.basis for item in evidence.stages)


def test_ambiguous_runtime_version_prevents_compatibility_invocation(tmp_path: Path) -> None:
    request, executable, _artifact = _fixture(tmp_path)
    source = executable.read_text(encoding="utf-8").replace(VERSION, "ambiguous-version")
    executable.write_text(source, encoding="utf-8")
    executable.chmod(0o755)
    request = request.model_copy(update={"executable_sha256": _digest(executable)})

    evidence = execute_plan(build_plan(request, tmp_path), tmp_path)

    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert evidence.compatibility_execution is None
    assert all(item.status == StageStatus.NOT_TESTED for item in evidence.stages)
    assert "RUNTIME_VERSION_MISMATCH" in {item.code for item in evidence.findings}


def test_exact_output_mismatch_fails_output_stage(tmp_path: Path) -> None:
    artifact = tmp_path / "synthetic.gguf"
    artifact.write_bytes(b"synthetic artifact\n")
    executable = _script(tmp_path, "sys.stdout.write('Lyon')")
    evidence = execute_plan(
        build_plan(_request(tmp_path, executable, artifact), tmp_path), tmp_path
    )
    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert evidence.stages[-1].status == StageStatus.FAIL
    assert "EXPECTED_OUTPUT_MISMATCH" in {item.code for item in evidence.findings}


def test_unexpected_runtime_file_fails_closed_and_is_bounded(tmp_path: Path) -> None:
    artifact = tmp_path / "synthetic.gguf"
    artifact.write_bytes(b"synthetic artifact\n")
    executable = _script(
        tmp_path,
        "Path('unexpected.txt').write_text('bounded')\n"
        "sys.stdout.write('Paris')",
    )
    evidence = execute_plan(
        build_plan(_request(tmp_path, executable, artifact), tmp_path), tmp_path
    )
    assert evidence.status == CompatibilityStatus.NOT_VERIFIED
    assert evidence.work_files[0].path == "unexpected.txt"
    assert evidence.work_files[0].size == len(b"bounded")
    assert "UNEXPECTED_WORK_FILE" in {item.code for item in evidence.findings}


def test_unsupported_schema_and_profile_fail_closed(tmp_path: Path) -> None:
    request = json.loads(
        (ROOT / "examples/runtime-compatibility/request.json").read_text(encoding="utf-8")
    )
    request["schema"] = "omiv.runtime-compatibility-request.v999"
    path = tmp_path / "unsupported-schema.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid runtime compatibility request"):
        load_request(path)

    request["schema"] = "omiv.runtime-compatibility-request.v1"
    request["profile_id"] = "omiv.runtime-compatibility-profile.unknown.v1"
    path.write_text(json.dumps(request), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid runtime compatibility request"):
        load_request(path)


def test_cli_exit_codes_distinguish_blocked_unverified_and_malformed(
    tmp_path: Path,
) -> None:
    request, _executable, artifact = _fixture(tmp_path)
    request_path = tmp_path / "request.json"
    request_path.write_text(
        json.dumps(request.model_dump(mode="json", by_alias=True)), encoding="utf-8"
    )
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    planned = runner.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(request_path),
            "--root",
            str(tmp_path),
            "--output",
            str(plan_path),
        ],
    )
    assert planned.exit_code == 0, planned.output
    executed = runner.invoke(
        app,
        [
            "runtime-compat",
            "run",
            "--plan",
            str(plan_path),
            "--root",
            str(tmp_path),
            "--output",
            str(evidence_path),
        ],
    )
    assert executed.exit_code == 1, executed.output
    assert load_evidence(evidence_path).status == CompatibilityStatus.NOT_VERIFIED

    missing = request.model_copy(
        update={
            "request_id": "blocked-cli",
            "artifact_path": "missing.gguf",
            "artifact_sha256": "0" * 64,
        }
    )
    request_path.write_text(
        json.dumps(missing.model_dump(mode="json", by_alias=True)), encoding="utf-8"
    )
    blocked = runner.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(request_path),
            "--root",
            str(tmp_path),
            "--output",
            str(tmp_path / "blocked-plan.json"),
        ],
    )
    assert blocked.exit_code == 1, blocked.output
    assert "executable_present=yes executable=yes executable_pinned=yes" in blocked.stdout
    assert "artifact_present=no artifact_pinned=no" in blocked.stdout

    malformed = json.loads(request_path.read_text(encoding="utf-8"))
    malformed["profile_id"] = "omiv.runtime-compatibility-profile.unsupported.v1"
    request_path.write_text(json.dumps(malformed), encoding="utf-8")
    rejected = runner.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(request_path),
            "--root",
            str(tmp_path),
            "--output",
            str(tmp_path / "rejected-plan.json"),
        ],
    )
    assert rejected.exit_code == 2, rejected.output
    assert artifact.exists()


def test_offline_verify_reconstructs_required_captured_execution(tmp_path: Path) -> None:
    request, _executable, _artifact = _fixture(tmp_path)
    evidence = execute_plan(build_plan(request, tmp_path), tmp_path)
    value = evidence.model_dump(mode="json", by_alias=True)
    value["version_execution"] = None
    _rehash_evidence(value)
    path = tmp_path / "tampered-evidence.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(OmivInputError, match="captured version observation"):
        load_evidence(path)


@pytest.mark.parametrize(
    "mutation",
    [
        "request_id",
        "plan_id",
        "plan_digest",
        "plan_content",
        "invocation",
        "environment",
        "limits",
        "artifact_binding",
        "runtime_binding",
        "test_vector",
    ],
)
def test_offline_verification_rejects_rehashed_incoherent_plan_projection(
    tmp_path: Path, mutation: str
) -> None:
    request, _executable, _artifact = _fixture(tmp_path)
    evidence = execute_plan(build_plan(request, tmp_path), tmp_path)
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    if mutation == "request_id":
        value["request_id"] = "replacement-request"
    elif mutation == "plan_id":
        value["plan_id"] = "runtime_compat_plan_" + "f" * 32
    elif mutation == "plan_digest":
        value["plan_digest"] = "f" * 64
    elif mutation == "plan_content":
        value["plan"]["expected_work"][0] = "Replaced plan content."
    elif mutation in {"invocation", "environment"}:
        invocation = value["invocation"]
        if mutation == "invocation":
            invocation["run_arguments"][4] = "replacement prompt"
        else:
            invocation["environment"][0]["value"] = "replacement"
        invocation_body = {
            key: item for key, item in invocation.items() if key != "command_digest"
        }
        invocation["command_digest"] = canonical_sha256({"invocation": invocation_body})
    elif mutation == "limits":
        value["limits"]["timeout_seconds"] = 2
    elif mutation == "artifact_binding":
        value["artifact"]["execution_sha256"] = "f" * 64
    elif mutation == "runtime_binding":
        value["runtime"]["execution_sha256"] = "f" * 64
    elif mutation == "test_vector":
        value["test_vector"]["expected_output"] = "replacement"
        value["test_vector_digest"] = canonical_sha256(
            {"runtime-test-vector": value["test_vector"]}
        )
    _rehash_evidence(value)
    path = tmp_path / f"tampered-{mutation}.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(OmivInputError, match="invalid runtime compatibility evidence"):
        load_evidence(path)


def test_execution_surface_uses_argument_arrays_and_no_shell() -> None:
    source = (ROOT / "src/omiv/runtime_compatibility/operations.py").read_text(
        encoding="utf-8"
    )
    assert "subprocess.Popen(" in source
    assert "shell=False" in source
    assert "cwd=cwd" in source
    assert "env=environment" in source
    assert "start_new_session=True" in source
    for forbidden in ("shell=True", "socket", "urllib", "requests", "httpx", "cuda"):
        assert forbidden not in source
    assert os.access(
        ROOT / "examples/runtime-compatibility/synthetic-llama-runner.py", os.X_OK
    )
