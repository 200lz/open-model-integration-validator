"""Bounded local orchestration for candidate runtime compatibility profiles."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import IO, Any

from pydantic import BaseModel, ValidationError

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.payload_integrity.paths import validate_portable_path
from omiv.runtime_compatibility.models import (
    PROFILE_ENVIRONMENT,
    PROFILE_NAME,
    BoundedCapture,
    CompatibilityStatus,
    EnvironmentVariable,
    ExecutionFileBinding,
    FileAvailability,
    FindingSeverity,
    LocalFileBinding,
    PlanStatus,
    ProcessCapture,
    RuntimeCompatibilityEvidence,
    RuntimeCompatibilityFinding,
    RuntimeCompatibilityPlan,
    RuntimeCompatibilityRequest,
    RuntimeCostSummary,
    RuntimeIdentityEvidence,
    StageResult,
    StageStatus,
    WorkFileRecord,
    build_profile_invocation,
    derive_native_stage_results,
)
from omiv.safe_write import atomic_write_text

MAX_CONTROL_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 64 * 1024


def _pretty(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def load_request(path: Path) -> RuntimeCompatibilityRequest:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return RuntimeCompatibilityRequest.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime compatibility request: {exc}") from exc


def load_plan(path: Path) -> RuntimeCompatibilityPlan:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return RuntimeCompatibilityPlan.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime compatibility plan: {exc}") from exc


def load_evidence(path: Path) -> RuntimeCompatibilityEvidence:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return RuntimeCompatibilityEvidence.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime compatibility evidence: {exc}") from exc


def write_plan(plan: RuntimeCompatibilityPlan, output: Path) -> None:
    atomic_write_text(output, _pretty(plan))


def write_evidence(evidence: RuntimeCompatibilityEvidence, output: Path) -> None:
    atomic_write_text(output, _pretty(evidence))


def _resolve_local_path(root: Path, portable_path: str) -> Path:
    validate_portable_path(portable_path)
    target = root / Path(*portable_path.split("/"))
    cursor = root
    for component in portable_path.split("/"):
        cursor /= component
        if cursor.is_symlink():
            raise OmivInputError(f"local input path contains a symlink: {portable_path}")
    resolved = target.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise OmivInputError(f"local input path escapes root: {portable_path}")
    return target


def _hash_regular_file(path: Path, maximum_bytes: int) -> tuple[int, str]:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise OmivInputError(f"local input is not a regular file: {path.name}")
    if before.st_size > maximum_bytes:
        raise OmivInputError(
            f"local input exceeds its byte limit: {path.name} ({before.st_size} > {maximum_bytes})"
        )
    digest = hashlib.sha256()
    observed = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_READ_CHUNK)
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise OmivInputError(f"local input grew beyond its byte limit: {path.name}")
            digest.update(chunk)
    after = path.stat(follow_symlinks=False)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or observed != after.st_size:
        raise OmivInputError(f"local input changed while it was hashed: {path.name}")
    return observed, digest.hexdigest()


def _inspect_binding(
    root: Path,
    portable_path: str,
    expected_sha256: str,
    maximum_bytes: int,
    *,
    require_executable: bool,
) -> LocalFileBinding:
    try:
        path = _resolve_local_path(root, portable_path)
    except (OSError, ValueError, OmivInputError) as exc:
        return LocalFileBinding(
            path=portable_path,
            expected_sha256=expected_sha256,
            availability=FileAvailability.INVALID,
            executable=False if require_executable else None,
            issues=[str(exc)],
        )
    if not path.exists():
        return LocalFileBinding(
            path=portable_path,
            expected_sha256=expected_sha256,
            availability=FileAvailability.MISSING,
            executable=False if require_executable else None,
            issues=["Explicitly supplied local file is missing."],
        )
    try:
        size, digest = _hash_regular_file(path, maximum_bytes)
    except (OSError, OmivInputError) as exc:
        return LocalFileBinding(
            path=portable_path,
            expected_sha256=expected_sha256,
            availability=FileAvailability.INVALID,
            executable=False if require_executable else None,
            issues=[str(exc)],
        )
    executable = os.access(path, os.X_OK) if require_executable else None
    issues: list[str] = []
    if digest != expected_sha256:
        issues.append("Observed SHA-256 does not match the explicitly supplied digest.")
    if require_executable and not executable:
        issues.append("Explicitly supplied runtime file is not executable.")
    return LocalFileBinding(
        path=portable_path,
        expected_sha256=expected_sha256,
        availability=FileAvailability.AVAILABLE,
        observed_sha256=digest,
        size=size,
        executable=executable,
        issues=issues,
    )


def build_plan(
    request: RuntimeCompatibilityRequest, root: Path
) -> RuntimeCompatibilityPlan:
    if os.name != "posix":
        raise OmivInputError(
            "candidate runtime compatibility execution requires POSIX process controls"
        )
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("runtime compatibility root must be a regular local directory")
    resolved_root = root.resolve()
    executable = _inspect_binding(
        resolved_root,
        request.executable_path,
        request.executable_sha256,
        request.limits.max_executable_bytes,
        require_executable=True,
    )
    artifact = _inspect_binding(
        resolved_root,
        request.artifact_path,
        request.artifact_sha256,
        request.limits.max_artifact_bytes,
        require_executable=False,
    )
    ready = not executable.issues and not artifact.issues
    available = [
        label
        for label, binding in (("runtime executable", executable), ("artifact", artifact))
        if binding.availability == FileAvailability.AVAILABLE
    ]
    missing = [
        f"{label}: {issue}"
        for label, binding in (("runtime executable", executable), ("artifact", artifact))
        for issue in binding.issues
    ]
    body: dict[str, Any] = {
        "schema": "omiv.runtime-compatibility-plan.v1",
        "request": request.model_dump(mode="json", by_alias=True),
        "status": PlanStatus.READY.value if ready else PlanStatus.BLOCKED.value,
        "profile_name": PROFILE_NAME,
        "executable": executable.model_dump(mode="json"),
        "artifact": artifact.model_dump(mode="json"),
        "invocation": build_profile_invocation(request).model_dump(mode="json"),
        "available": available,
        "missing": missing,
        "expected_work": [
            "Re-hash the executable and artifact before and after execution.",
            "Run the supplied executable version command under bounded local controls.",
            "Run one CPU-only supplied test vector through the native CLI and capture its "
            "raw output.",
        ],
        "costs": RuntimeCostSummary().model_dump(mode="json"),
        "limitations": [
            "Phase 7B is a candidate capability; Phase 7 scope remains unfrozen.",
            "The profile applies only to the exact artifact, executable, version, invocation, "
            "CPU-only environment, limits, and test vector recorded here.",
            "The explicitly supplied executable must be trusted by the operator; this "
            "orchestrator is not a security sandbox.",
            "No result is generalized to another artifact, runtime, device, accelerator, "
            "prompt, or environment.",
            "The native CLI does not independently expose model loading, tokenization, "
            "prefill, or decode internals; those stages remain UNKNOWN.",
        ],
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return RuntimeCompatibilityPlan.model_validate(
        {**body, "plan_id": f"runtime_compat_plan_{digest[:32]}", "plan_digest": digest}
    )


def _bounded_capture(raw: bytes, limit: int, overflow: bool) -> BoundedCapture:
    return BoundedCapture(
        captured_base64=base64.b64encode(raw).decode("ascii"),
        captured_bytes=len(raw),
        limit_bytes=limit,
        overflow=overflow,
        captured_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _terminate(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        raise OmivInputError("runtime process could not be terminated within its bound") from exc


def _child_file_limit(maximum_bytes: int) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum_bytes, maximum_bytes))


def _run_bounded(
    actual_arguments: list[str],
    evidence_arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    evidence_environment: list[EnvironmentVariable],
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    max_work_file_bytes: int,
) -> ProcessCapture:
    started = time.monotonic()
    process = subprocess.Popen(
        actual_arguments,
        shell=False,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=lambda: _child_file_limit(max_work_file_bytes),
    )
    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise OmivInputError("runtime process pipes were not available")
    stdout_descriptor = process.stdout.fileno()
    stderr_descriptor = process.stderr.fileno()
    streams: dict[int, tuple[IO[bytes], bytearray, int]] = {
        stdout_descriptor: (process.stdout, bytearray(), max_stdout_bytes),
        stderr_descriptor: (process.stderr, bytearray(), max_stderr_bytes),
    }
    overflow = {process.stdout.fileno(): False, process.stderr.fileno(): False}
    selector = selectors.DefaultSelector()
    for descriptor, (stream, _buffer, _limit) in streams.items():
        selector.register(stream, selectors.EVENT_READ, descriptor)
    deadline = started + timeout_seconds
    timed_out = False
    killed = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(process)
                killed = True
                break
            events = selector.select(timeout=min(0.05, remaining))
            if not events and process.poll() is not None:
                events = selector.select(timeout=0)
            for key, _mask in events:
                descriptor = int(key.data)
                stream, buffer, limit = streams[descriptor]
                chunk = os.read(descriptor, _READ_CHUNK)
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                room = limit - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])
                if len(chunk) > room:
                    overflow[descriptor] = True
                    _terminate(process)
                    killed = True
                    break
            if killed:
                break
    finally:
        selector.close()
        for stream, _buffer, _limit in streams.values():
            if not stream.closed:
                stream.close()
    if not killed:
        try:
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate(process)
    duration_ms = max(0, int((time.monotonic() - started) * 1000))
    stdout_buffer = bytes(streams[stdout_descriptor][1])
    stderr_buffer = bytes(streams[stderr_descriptor][1])
    return ProcessCapture(
        arguments=evidence_arguments,
        environment=evidence_environment,
        return_code=process.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
        stdout=_bounded_capture(stdout_buffer, max_stdout_bytes, overflow[stdout_descriptor]),
        stderr=_bounded_capture(stderr_buffer, max_stderr_bytes, overflow[stderr_descriptor]),
    )


def _capture_bytes(capture: BoundedCapture) -> bytes:
    return base64.b64decode(capture.captured_base64, validate=True)


def _execution_binding(
    root: Path,
    planned: LocalFileBinding,
    maximum_bytes: int,
) -> tuple[ExecutionFileBinding, str | None]:
    if planned.observed_sha256 is None:
        raise OmivInputError("ready plan lacks a preflight file digest")
    try:
        path = _resolve_local_path(root, planned.path)
        size, digest = _hash_regular_file(path, maximum_bytes)
    except (OSError, ValueError, OmivInputError) as exc:
        return (
            ExecutionFileBinding(
                path=planned.path,
                expected_sha256=planned.expected_sha256,
                preflight_sha256=planned.observed_sha256,
            ),
            str(exc),
        )
    binding = ExecutionFileBinding(
        path=planned.path,
        expected_sha256=planned.expected_sha256,
        preflight_sha256=planned.observed_sha256,
        execution_sha256=digest,
        execution_size=size,
    )
    if digest != planned.expected_sha256 or digest != planned.observed_sha256:
        return binding, f"{planned.path} changed after preflight or no longer matches its pin"
    return binding, None


def _finding(
    findings: list[RuntimeCompatibilityFinding],
    code: str,
    severity: FindingSeverity,
    detail: str,
) -> None:
    if len(findings) < 256:
        findings.append(
            RuntimeCompatibilityFinding(code=code, severity=severity, detail=detail[:1000])
        )


def _inspect_work_directory(
    root: Path,
    plan: RuntimeCompatibilityPlan,
    findings: list[RuntimeCompatibilityFinding],
) -> list[WorkFileRecord]:
    records: list[WorkFileRecord] = []
    stack = [root]
    observed_entries = 0
    observed_total = 0
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.encode("utf-8"))
        except OSError as exc:
            _finding(findings, "WORK_DIRECTORY_READ_FAILED", FindingSeverity.ERROR, str(exc))
            break
        for entry in entries:
            observed_entries += 1
            if observed_entries > plan.request.limits.max_work_files:
                _finding(
                    findings,
                    "WORK_FILE_COUNT_EXCEEDED",
                    FindingSeverity.ERROR,
                    "The runtime working directory exceeded its entry bound.",
                )
                return records
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                validate_portable_path(relative)
            except ValueError as exc:
                _finding(findings, "UNSAFE_WORK_FILE", FindingSeverity.ERROR, str(exc))
                continue
            if entry.is_symlink():
                _finding(
                    findings,
                    "UNEXPECTED_WORK_SYMLINK",
                    FindingSeverity.ERROR,
                    f"The runtime created a symlink: {relative}",
                )
            elif entry.is_dir(follow_symlinks=False):
                stack.append(path)
                _finding(
                    findings,
                    "UNEXPECTED_WORK_DIRECTORY",
                    FindingSeverity.ERROR,
                    f"The runtime created a directory: {relative}",
                )
            elif entry.is_file(follow_symlinks=False):
                size = entry.stat(follow_symlinks=False).st_size
                observed_total += size
                digest: str | None = None
                if size > plan.request.limits.max_work_file_bytes:
                    _finding(
                        findings,
                        "WORK_FILE_SIZE_EXCEEDED",
                        FindingSeverity.ERROR,
                        f"The runtime-created file exceeded its bound: {relative}",
                    )
                elif observed_total > plan.request.limits.max_work_total_bytes:
                    _finding(
                        findings,
                        "WORK_FILE_TOTAL_EXCEEDED",
                        FindingSeverity.ERROR,
                        "Runtime-created files exceeded the cumulative byte bound.",
                    )
                else:
                    _observed, digest = _hash_regular_file(
                        path, plan.request.limits.max_work_file_bytes
                    )
                records.append(WorkFileRecord(path=relative, size=size, sha256=digest))
                _finding(
                    findings,
                    "UNEXPECTED_WORK_FILE",
                    FindingSeverity.ERROR,
                    f"The no-output-files profile observed a runtime-created file: {relative}",
                )
            else:
                _finding(
                    findings,
                    "UNEXPECTED_WORK_OBJECT",
                    FindingSeverity.ERROR,
                    f"The runtime created a non-regular object: {relative}",
                )
    return records


def _parse_version(capture: ProcessCapture) -> tuple[str | None, str | None]:
    if capture.timed_out:
        return None, "Runtime version command timed out."
    if capture.stdout.overflow or capture.stderr.overflow:
        return None, "Runtime version command exceeded a captured-output bound."
    if capture.return_code != 0:
        return None, f"Runtime version command exited with {capture.return_code}."
    try:
        version = _capture_bytes(capture.stdout).decode("utf-8").strip()
        _capture_bytes(capture.stderr).decode("utf-8")
    except UnicodeDecodeError:
        return None, "Runtime version stdout or stderr is not valid UTF-8."
    if not version:
        return None, "Runtime version output is empty."
    if len(version) > 512:
        return None, "Runtime version output is too long to identify unambiguously."
    return version, None


def _runtime_environment(work_directory: Path) -> dict[str, str]:
    return {
        name: str(work_directory) if value == "{WORK_DIRECTORY}" else value
        for name, value in PROFILE_ENVIRONMENT
    }


def _build_evidence(
    plan: RuntimeCompatibilityPlan,
    *,
    artifact: ExecutionFileBinding,
    runtime: RuntimeIdentityEvidence,
    version_execution: ProcessCapture | None,
    compatibility_execution: ProcessCapture | None,
    work_files: list[WorkFileRecord],
    stages: list[StageResult],
    findings: list[RuntimeCompatibilityFinding],
) -> RuntimeCompatibilityEvidence:
    unknowns = [
        f"{item.stage.value} was {item.status.value}; compatibility is not established."
        for item in stages
        if item.status in {StageStatus.UNKNOWN, StageStatus.NOT_TESTED}
    ]
    verified = (
        version_execution is not None
        and version_execution.return_code == 0
        and not version_execution.timed_out
        and not version_execution.stdout.overflow
        and not version_execution.stderr.overflow
        and runtime.identity_verified
        and artifact.execution_sha256
        == artifact.expected_sha256
        == artifact.preflight_sha256
        and compatibility_execution is not None
        and compatibility_execution.return_code == 0
        and not compatibility_execution.timed_out
        and not compatibility_execution.stdout.overflow
        and not compatibility_execution.stderr.overflow
        and all(item.status == StageStatus.PASS for item in stages)
        and not any(item.severity == FindingSeverity.ERROR for item in findings)
        and not unknowns
        and not work_files
    )
    vector_digest = canonical_sha256(
        {"runtime-test-vector": plan.request.test_vector.model_dump(mode="json")}
    )
    body: dict[str, Any] = {
        "schema": "omiv.runtime-compatibility-evidence.v1",
        "candidate_notice": "PHASE_7B_CANDIDATE_PHASE_7_UNFROZEN",
        "plan": plan.model_dump(mode="json", by_alias=True),
        "request_id": plan.request.request_id,
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "profile_id": plan.request.profile_id,
        "profile_name": PROFILE_NAME,
        "status": (
            CompatibilityStatus.VERIFIED_WITHIN_PROFILE.value
            if verified
            else CompatibilityStatus.NOT_VERIFIED.value
        ),
        "artifact": artifact.model_dump(mode="json"),
        "runtime": runtime.model_dump(mode="json"),
        "invocation": plan.invocation.model_dump(mode="json"),
        "test_vector": plan.request.test_vector.model_dump(mode="json"),
        "test_vector_digest": vector_digest,
        "limits": plan.request.limits.model_dump(mode="json"),
        "version_execution": (
            version_execution.model_dump(mode="json") if version_execution is not None else None
        ),
        "compatibility_execution": (
            compatibility_execution.model_dump(mode="json")
            if compatibility_execution is not None
            else None
        ),
        "work_files": [item.model_dump(mode="json") for item in work_files],
        "stages": [item.model_dump(mode="json") for item in stages],
        "findings": [item.model_dump(mode="json") for item in findings],
        "unknowns": unknowns,
        "limitations": [
            "Phase 7B is a candidate capability; Phase 7 scope remains unfrozen.",
            "VERIFIED_WITHIN_PROFILE is reserved for a profile with complete independently "
            "observable stages; this native-output profile leaves internal stages UNKNOWN.",
            "Raw native stdout and stderr are runtime observations, but they do not prove "
            "model loading, tokenization, prefill, or decode internals; those stages remain "
            "UNKNOWN for this profile.",
            "Canonical hashes establish integrity and internal consistency, not origin "
            "authenticity, runtime honesty, or weight-attributable inference.",
            "The bounded probe does not establish numerical or semantic equivalence, "
            "production readiness, performance, safety, or approval.",
            "No conclusion is generalized to another artifact, runtime, device, accelerator, "
            "prompt, or environment.",
        ],
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return RuntimeCompatibilityEvidence.model_validate(
        {
            **body,
            "evidence_id": f"runtime_compat_evidence_{digest[:32]}",
            "evidence_digest": digest,
        }
    )


def execute_plan(plan: RuntimeCompatibilityPlan, root: Path) -> RuntimeCompatibilityEvidence:
    if plan.status != PlanStatus.READY:
        raise OmivInputError("blocked runtime compatibility plan cannot be executed")
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("runtime compatibility root must be a regular local directory")
    resolved_root = root.resolve()
    findings: list[RuntimeCompatibilityFinding] = []
    artifact, artifact_issue = _execution_binding(
        resolved_root, plan.artifact, plan.request.limits.max_artifact_bytes
    )
    runtime_file, runtime_issue = _execution_binding(
        resolved_root, plan.executable, plan.request.limits.max_executable_bytes
    )
    if artifact_issue is not None:
        _finding(
            findings,
            "ARTIFACT_CHANGED_AFTER_PREFLIGHT",
            FindingSeverity.ERROR,
            artifact_issue,
        )
    if runtime_issue is not None:
        _finding(findings, "RUNTIME_CHANGED_AFTER_PREFLIGHT", FindingSeverity.ERROR, runtime_issue)
    runtime = RuntimeIdentityEvidence(
        **runtime_file.model_dump(mode="python"),
        expected_version=plan.request.expected_runtime_version,
        observed_version=None,
        identity_verified=False,
    )
    stages, _stage_issues = derive_native_stage_results(
        None, plan.request.test_vector.expected_output
    )
    if artifact_issue is not None or runtime_issue is not None:
        return _build_evidence(
            plan,
            artifact=artifact,
            runtime=runtime,
            version_execution=None,
            compatibility_execution=None,
            work_files=[],
            stages=stages,
            findings=findings,
        )

    executable_path = _resolve_local_path(resolved_root, plan.executable.path).resolve()
    artifact_path = _resolve_local_path(resolved_root, plan.artifact.path).resolve()
    version_execution: ProcessCapture | None = None
    compatibility_execution: ProcessCapture | None = None
    work_files: list[WorkFileRecord] = []
    output_parent = resolved_root
    with tempfile.TemporaryDirectory(prefix=".omiv-runtime-compat-", dir=output_parent) as name:
        work_directory = Path(name)
        environment = _runtime_environment(work_directory)
        try:
            version_execution = _run_bounded(
                [str(executable_path), "--version"],
                plan.invocation.version_arguments,
                cwd=work_directory,
                environment=environment,
                evidence_environment=plan.invocation.environment,
                timeout_seconds=plan.request.limits.version_timeout_seconds,
                max_stdout_bytes=plan.request.limits.max_stdout_bytes,
                max_stderr_bytes=plan.request.limits.max_stderr_bytes,
                max_work_file_bytes=plan.request.limits.max_work_file_bytes,
            )
        except (OSError, OmivInputError) as exc:
            _finding(findings, "VERSION_EXECUTION_FAILED", FindingSeverity.ERROR, str(exc))
        observed_version: str | None = None
        version_issue: str | None = "Runtime version command did not start."
        if version_execution is not None:
            observed_version, version_issue = _parse_version(version_execution)
        if version_issue is not None:
            _finding(findings, "RUNTIME_IDENTITY_AMBIGUOUS", FindingSeverity.ERROR, version_issue)

        after_version_artifact, artifact_after_issue = _execution_binding(
            resolved_root, plan.artifact, plan.request.limits.max_artifact_bytes
        )
        after_version_runtime, runtime_after_issue = _execution_binding(
            resolved_root, plan.executable, plan.request.limits.max_executable_bytes
        )
        artifact = after_version_artifact
        runtime_file = after_version_runtime
        if artifact_after_issue is not None:
            _finding(
                findings,
                "ARTIFACT_CHANGED_DURING_VERSION_CHECK",
                FindingSeverity.ERROR,
                artifact_after_issue,
            )
        if runtime_after_issue is not None:
            _finding(
                findings,
                "RUNTIME_CHANGED_DURING_VERSION_CHECK",
                FindingSeverity.ERROR,
                runtime_after_issue,
            )
        runtime = RuntimeIdentityEvidence(
            **runtime_file.model_dump(mode="python"),
            expected_version=plan.request.expected_runtime_version,
            observed_version=observed_version,
            identity_verified=(
                observed_version == plan.request.expected_runtime_version
                and runtime_after_issue is None
            ),
        )
        if (
            observed_version is not None
            and observed_version != plan.request.expected_runtime_version
        ):
            _finding(
                findings,
                "RUNTIME_VERSION_MISMATCH",
                FindingSeverity.ERROR,
                "Observed runtime version does not match the explicitly supplied version pin.",
            )

        work_files = _inspect_work_directory(work_directory, plan, findings)
        if (
            runtime.identity_verified
            and artifact_after_issue is None
            and runtime_after_issue is None
            and not any(item.severity == FindingSeverity.ERROR for item in findings)
        ):
            actual_arguments = [
                str(executable_path) if item == "{runtime_executable}" else
                str(artifact_path) if item == "{artifact}" else item
                for item in plan.invocation.run_arguments
            ]
            try:
                compatibility_execution = _run_bounded(
                    actual_arguments,
                    plan.invocation.run_arguments,
                    cwd=work_directory,
                    environment=environment,
                    evidence_environment=plan.invocation.environment,
                    timeout_seconds=plan.request.limits.timeout_seconds,
                    max_stdout_bytes=plan.request.limits.max_stdout_bytes,
                    max_stderr_bytes=plan.request.limits.max_stderr_bytes,
                    max_work_file_bytes=plan.request.limits.max_work_file_bytes,
                )
            except (OSError, OmivInputError) as exc:
                _finding(
                    findings,
                    "COMPATIBILITY_EXECUTION_FAILED",
                    FindingSeverity.ERROR,
                    str(exc),
                )
            stages, stage_issues = derive_native_stage_results(
                compatibility_execution, plan.request.test_vector.expected_output
            )
            for code, detail in stage_issues:
                _finding(findings, code, FindingSeverity.ERROR, detail)
            if compatibility_execution is not None and not stage_issues:
                _finding(
                    findings,
                    "INTERNAL_STAGES_UNOBSERVABLE",
                    FindingSeverity.WARN,
                    "Native output cannot independently establish LOAD, TOKENIZER, PREFILL, "
                    "or DECODE internals.",
                )
            work_files = _inspect_work_directory(work_directory, plan, findings)

    final_artifact, final_artifact_issue = _execution_binding(
        resolved_root, plan.artifact, plan.request.limits.max_artifact_bytes
    )
    final_runtime_file, final_runtime_issue = _execution_binding(
        resolved_root, plan.executable, plan.request.limits.max_executable_bytes
    )
    artifact = final_artifact
    if final_artifact_issue is not None:
        _finding(
            findings,
            "ARTIFACT_CHANGED_DURING_EXECUTION",
            FindingSeverity.ERROR,
            final_artifact_issue,
        )
    if final_runtime_issue is not None:
        _finding(
            findings,
            "RUNTIME_CHANGED_DURING_EXECUTION",
            FindingSeverity.ERROR,
            final_runtime_issue,
        )
    runtime = RuntimeIdentityEvidence(
        **final_runtime_file.model_dump(mode="python"),
        expected_version=plan.request.expected_runtime_version,
        observed_version=runtime.observed_version,
        identity_verified=(
            runtime.observed_version == plan.request.expected_runtime_version
            and final_runtime_issue is None
        ),
    )
    return _build_evidence(
        plan,
        artifact=artifact,
        runtime=runtime,
        version_execution=version_execution,
        compatibility_execution=compatibility_execution,
        work_files=work_files,
        stages=stages,
        findings=findings,
    )


def concise_plan_summary(plan: RuntimeCompatibilityPlan) -> str:
    executable_present = plan.executable.availability == FileAvailability.AVAILABLE
    artifact_present = plan.artifact.availability == FileAvailability.AVAILABLE
    executable_pinned = (
        executable_present
        and plan.executable.observed_sha256 == plan.executable.expected_sha256
    )
    artifact_pinned = (
        artifact_present and plan.artifact.observed_sha256 == plan.artifact.expected_sha256
    )
    return (
        f"{plan.status.value} profile={plan.profile_name} "
        f"executable_present={'yes' if executable_present else 'no'} "
        f"executable={'yes' if plan.executable.executable is True else 'no'} "
        f"executable_pinned={'yes' if executable_pinned else 'no'} "
        f"artifact_present={'yes' if artifact_present else 'no'} "
        f"artifact_pinned={'yes' if artifact_pinned else 'no'} "
        "network=no download=no compilation=no conversion=no runtime=yes gpu=no"
    )


def concise_evidence_summary(evidence: RuntimeCompatibilityEvidence) -> str:
    rows: list[str] = [evidence.profile_name]
    rows.extend(f"{item.stage.value:<10} {item.status.value}" for item in evidence.stages)
    rows.extend(("", f"Runtime compatibility: {evidence.status.value}"))
    return "\n".join(rows)
