"""Fail-closed loopback controller for the Phase 7B.3 server profile."""

from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import socket
import stat
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.runtime_compatibility.controlled_models import (
    CONTROLLED_ENVIRONMENT,
    CONTROLLED_EVIDENCE_SCHEMA,
    CONTROLLED_LIMITATIONS,
    CONTROLLED_PLAN_SCHEMA,
    CONTROLLED_TRUST_STATEMENT,
    ArtifactRole,
    BackendObservation,
    ContainmentObservation,
    ControlledEvidence,
    ControlledFinding,
    ControlledPlan,
    ControlledProbe,
    ControlledProcess,
    ControlledRequest,
    ControlledServerInvocation,
    ControlledServerObservation,
    DFlashObservation,
    HttpExchange,
    PrivacyBoundary,
    ProbeModality,
    ProbeObservation,
    RehashBinding,
    RehashBoundary,
    WorkBoundary,
    build_controlled_invocation,
    controlled_decode_complete,
    controlled_image_completion_request_bytes,
    derive_controlled_runtime_version,
    validate_observation,
)
from omiv.runtime_compatibility.external_operations import _reject_sensitive_text
from omiv.runtime_compatibility.models import (
    BoundedCapture,
    CompatibilityStatus,
    EnvironmentVariable,
    FindingSeverity,
    LocalFileBinding,
    PlanStatus,
    StageName,
    StageResult,
    StageStatus,
)
from omiv.runtime_compatibility.operations import (
    _CONTAINMENT_MECHANISM,
    MAX_RUNTIME_COMPAT_EVIDENCE_BYTES,
    MAX_RUNTIME_COMPAT_PLAN_BYTES,
    MAX_RUNTIME_COMPAT_REQUEST_BYTES,
    _ContainedProcess,
    _ContainmentReport,
    _inspect_binding,
    _run_bounded,
)
from omiv.safe_write import atomic_write_text

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


def load_controlled_request_value(value: Any) -> ControlledRequest:
    try:
        return ControlledRequest.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError("invalid controlled runtime request") from exc


def load_controlled_plan_value(value: Any) -> ControlledPlan:
    try:
        return ControlledPlan.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError("invalid controlled runtime plan") from exc


def load_controlled_evidence_value(value: Any) -> ControlledEvidence:
    try:
        return ControlledEvidence.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError("invalid controlled runtime evidence") from exc


def load_controlled_request(path: Path) -> ControlledRequest:
    value, _raw = load_bounded_json(path, max_bytes=MAX_RUNTIME_COMPAT_REQUEST_BYTES)
    return load_controlled_request_value(value)


def load_controlled_plan(path: Path) -> ControlledPlan:
    value, _raw = load_bounded_json(path, max_bytes=MAX_RUNTIME_COMPAT_PLAN_BYTES)
    return load_controlled_plan_value(value)


def load_controlled_evidence(path: Path) -> ControlledEvidence:
    value, _raw = load_bounded_json(path, max_bytes=MAX_RUNTIME_COMPAT_EVIDENCE_BYTES)
    return load_controlled_evidence_value(value)


def write_controlled_plan(plan: ControlledPlan, output: Path) -> None:
    atomic_write_text(output, _pretty(plan))


def write_controlled_evidence(evidence: ControlledEvidence, output: Path) -> None:
    atomic_write_text(output, _pretty(evidence))


def build_controlled_plan(request: ControlledRequest, root: Path) -> ControlledPlan:
    if os.name != "posix":
        raise OmivInputError("controlled runtime execution requires POSIX process controls")
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("controlled runtime root must be a regular local directory")
    resolved = root.resolve()
    executable_pin = request.executable_sha256 or "0" * 64
    executable = _inspect_binding(
        resolved,
        request.executable_path,
        executable_pin,
        request.limits.max_executable_bytes,
        require_executable=True,
    )
    executable_issues = list(executable.issues)
    if request.executable_sha256 is None:
        executable_issues.append("A locally observed executable SHA-256 pin is required.")
    if request.expected_runtime_version is None:
        executable_issues.append("An exact locally observed runtime version is required.")
    if executable_issues != executable.issues:
        executable = executable.model_copy(update={"issues": executable_issues})
    artifacts = [
        _inspect_binding(
            resolved,
            item.path,
            item.sha256,
            request.limits.max_artifact_bytes,
            require_executable=False,
        )
        for item in request.artifacts
    ]
    for index, (declared, binding) in enumerate(zip(request.artifacts, artifacts, strict=True)):
        if binding.size is not None and binding.size != declared.size:
            artifacts[index] = binding.model_copy(
                update={
                    "issues": [
                        *binding.issues,
                        "Observed byte size does not match the explicitly supplied size.",
                    ]
                }
            )
    ready = not executable.issues and all(not item.issues for item in artifacts)
    request_value = request.model_dump(mode="json", by_alias=True)
    body: dict[str, Any] = {
        "schema": CONTROLLED_PLAN_SCHEMA,
        "request_digest": canonical_sha256({"domain": request.schema_id, "body": request_value}),
        "candidate_notice": "PHASE_7B3_CANDIDATE_PHASE_7_UNFROZEN",
        "request": request_value,
        "status": PlanStatus.READY.value if ready else PlanStatus.BLOCKED.value,
        "executable": executable.model_dump(mode="json"),
        "artifacts": [item.model_dump(mode="json") for item in artifacts],
        "invocation": build_controlled_invocation(request).model_dump(mode="json"),
        "limitations": list(CONTROLLED_LIMITATIONS),
    }
    digest = canonical_sha256({"domain": CONTROLLED_PLAN_SCHEMA, "body": body})
    return ControlledPlan.model_validate(
        {**body, "plan_id": f"controlled_runtime_plan_{digest[:32]}", "plan_digest": digest}
    )


def _capture(raw: bytes, limit: int, *, overflow: bool = False) -> BoundedCapture:
    return BoundedCapture(
        captured_base64=base64.b64encode(raw).decode("ascii"),
        captured_bytes=len(raw),
        limit_bytes=limit,
        overflow=overflow,
        captured_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _environment(work: Path) -> tuple[dict[str, str], list[EnvironmentVariable]]:
    evidence = [
        EnvironmentVariable(name=name, value=value) for name, value in CONTROLLED_ENVIRONMENT
    ]
    actual = {
        item.name: str(work) if item.value == "{WORK_DIRECTORY}" else item.value
        for item in evidence
    }
    return actual, evidence


@dataclass(frozen=True)
class _BoundInput:
    role: str
    portable_path: str
    descriptor: int
    size: int
    sha256: str

    @property
    def child_path(self) -> str:
        return f"/proc/self/fd/{self.descriptor}"


@dataclass
class _ExecutionInputs:
    executable: _BoundInput
    artifacts: dict[ArtifactRole, _BoundInput]

    @property
    def pass_fds(self) -> tuple[int, ...]:
        return (self.executable.descriptor, *(item.descriptor for item in self.artifacts.values()))

    def close(self) -> None:
        for descriptor in self.pass_fds:
            with suppress(OSError):
                os.close(descriptor)


def _open_portable_regular(root: Path, portable_path: str) -> int:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise OmivInputError("descriptor-backed controlled inputs are unsupported")
    components = portable_path.split("/")
    directory = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for component in components[:-1]:
            next_directory = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        return os.open(
            components[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    except OSError as exc:
        raise OmivInputError(
            "controlled input could not be opened without following links"
        ) from exc
    finally:
        os.close(directory)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        if written <= 0:
            raise OmivInputError("controlled immutable snapshot write did not complete")
        offset += written


def _snapshot_input(
    root: Path,
    role: str,
    portable_path: str,
    expected_size: int,
    expected_sha256: str,
    maximum_bytes: int,
    *,
    executable: bool,
) -> _BoundInput:
    if (
        not hasattr(os, "memfd_create")
        or not hasattr(os, "MFD_ALLOW_SEALING")
        or not hasattr(fcntl, "F_ADD_SEALS")
        or not Path("/proc/self/fd").is_dir()
    ):
        raise OmivInputError("sealed descriptor-backed controlled inputs are unsupported")
    source = _open_portable_regular(root, portable_path)
    snapshot = -1
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise OmivInputError("controlled input is not a regular file")
        if before.st_size > maximum_bytes or before.st_size != expected_size:
            raise OmivInputError("controlled input size differs from its pinned bound")
        snapshot = os.memfd_create(f"omiv-{role.lower()}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(source, min(_READ_CHUNK, maximum_bytes - observed + 1))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes or observed > expected_size:
                raise OmivInputError("controlled input grew beyond its pinned byte bound")
            digest.update(chunk)
            _write_all(snapshot, chunk)
        after = os.fstat(source)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        observed_sha256 = digest.hexdigest()
        if (
            identity_before != identity_after
            or observed != expected_size
            or observed_sha256 != expected_sha256
        ):
            raise OmivInputError("controlled input changed during immutable binding")
        os.fchmod(snapshot, 0o500 if executable else 0o400)
        seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(snapshot, fcntl.F_GET_SEALS) & seals != seals:
            raise OmivInputError("controlled immutable snapshot seals were not applied")
        os.lseek(snapshot, 0, os.SEEK_SET)
        return _BoundInput(
            role=role,
            portable_path=portable_path,
            descriptor=snapshot,
            size=observed,
            sha256=observed_sha256,
        )
    except OSError as exc:
        if snapshot >= 0:
            os.close(snapshot)
        raise OmivInputError("controlled immutable input binding failed") from exc
    except BaseException:
        if snapshot >= 0:
            os.close(snapshot)
        raise
    finally:
        os.close(source)


def _bind_execution_inputs(plan: ControlledPlan, root: Path) -> _ExecutionInputs:
    executable = _snapshot_input(
        root,
        "EXECUTABLE",
        plan.executable.path,
        plan.executable.size or 0,
        plan.executable.expected_sha256,
        plan.request.limits.max_executable_bytes,
        executable=True,
    )
    artifacts: dict[ArtifactRole, _BoundInput] = {}
    try:
        for declared, binding in zip(plan.request.artifacts, plan.artifacts, strict=True):
            artifacts[declared.role] = _snapshot_input(
                root,
                declared.role.value,
                binding.path,
                declared.size,
                binding.expected_sha256,
                plan.request.limits.max_artifact_bytes,
                executable=False,
            )
        return _ExecutionInputs(executable=executable, artifacts=artifacts)
    except BaseException:
        for item in artifacts.values():
            os.close(item.descriptor)
        os.close(executable.descriptor)
        raise


def _controlled_from_native(
    capture: Any,
    arguments: list[str],
    environment: list[EnvironmentVariable],
    containment: dict[str, Any],
    termination: Literal["GRACEFUL", "SIGTERM", "SIGKILL"],
) -> ControlledProcess:
    return ControlledProcess(
        arguments=arguments,
        environment=environment,
        started=True,
        alive_at_ready=False,
        ended=True,
        return_code=capture.return_code,
        startup_timed_out=capture.timed_out,
        probe_timed_out=False,
        termination=termination,
        containment=ContainmentObservation.model_validate(containment),
        stdout=capture.stdout,
        stderr=capture.stderr,
    )


def _select_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        probe.bind(("127.0.0.1", 0))
        address = probe.getsockname()
        if address[0] != "127.0.0.1":
            raise OmivInputError("loopback port selection returned a non-loopback address")
        return int(address[1])


def _bounded_nodes(value: Any, limit: int) -> None:
    count = 0
    stack = [value]
    while stack:
        item = stack.pop()
        count += 1
        if count > limit:
            raise OmivInputError("controlled JSON value count exceeded its bound")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _http_exchange(
    port: int,
    method: Literal["GET", "POST"],
    endpoint: Literal["/health", "/tokenize", "/completion"],
    request_value: dict[str, Any] | None,
    *,
    deadline: float,
    request_maximum: int,
    response_maximum: int,
    max_nodes: int,
) -> tuple[HttpExchange, dict[str, Any]]:
    body = b"" if request_value is None else canonical_json_bytes(request_value)
    if len(body) > request_maximum:
        raise OmivInputError("controlled request body exceeds its byte bound")
    header_lines = [
        f"{method} {endpoint} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Connection: close",
    ]
    if method == "POST":
        header_lines.extend(["Content-Type: application/json", f"Content-Length: {len(body)}"])
    request_raw = ("\r\n".join(header_lines) + "\r\n\r\n").encode("ascii") + body
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setblocking(False)
    try:
        connect_status = connection.connect_ex(("127.0.0.1", port))
        if connect_status not in {0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY}:
            raise OSError(connect_status, "loopback connect failed")
        if connect_status != 0:
            _wait_socket(connection, deadline, writable=True)
            socket_error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if socket_error:
                raise OSError(socket_error, "loopback connect failed")
        sent = 0
        while sent < len(request_raw):
            _wait_socket(connection, deadline, writable=True)
            written = connection.send(request_raw[sent:])
            if written <= 0:
                raise OSError("loopback request transmission stopped")
            sent += written
        header_limit = 16 * 1024
        received = bytearray()
        while b"\r\n\r\n" not in received:
            _wait_socket(connection, deadline, writable=False)
            chunk = connection.recv(
                min(_READ_CHUNK, header_limit + response_maximum + 1 - len(received))
            )
            if not chunk:
                raise OSError("loopback response ended before headers completed")
            received.extend(chunk)
            if len(received) > header_limit + response_maximum:
                raise OmivInputError("controlled response headers or body exceeded its bound")
        header_raw, initial_body = bytes(received).split(b"\r\n\r\n", 1)
        status, content_type, content_length = _parse_response_headers(header_raw)
        if content_length is not None and content_length > response_maximum:
            raise OmivInputError("controlled response body exceeds its byte bound")
        response_body = bytearray(initial_body)
        if len(response_body) > response_maximum:
            raise OmivInputError("controlled response body exceeds its byte bound")
        if content_length is not None:
            if len(response_body) > content_length:
                raise OmivInputError("controlled response exceeded its declared length")
            while len(response_body) < content_length:
                _wait_socket(connection, deadline, writable=False)
                chunk = connection.recv(min(_READ_CHUNK, content_length - len(response_body)))
                if not chunk:
                    raise OSError("loopback response ended before its declared length")
                response_body.extend(chunk)
        else:
            while True:
                _wait_socket(connection, deadline, writable=False)
                chunk = connection.recv(min(_READ_CHUNK, response_maximum + 1 - len(response_body)))
                if not chunk:
                    break
                response_body.extend(chunk)
                if len(response_body) > response_maximum:
                    raise OmivInputError("controlled response body exceeds its byte bound")
        raw = bytes(response_body)
    except (OSError, TimeoutError, ValueError) as exc:
        raise OmivInputError("controlled loopback request did not complete within bounds") from exc
    finally:
        connection.close()
    value = parse_bounded_json_bytes(
        raw, source_name="controlled loopback response", max_bytes=response_maximum
    )
    _bounded_nodes(value, max_nodes)
    if not isinstance(value, dict):
        raise OmivInputError("controlled loopback response must be a JSON object")
    exchange = HttpExchange(
        method=method,
        endpoint=endpoint,
        request_headers=[] if method == "GET" else ["Content-Type: application/json"],
        request_body=_capture(body, request_maximum),
        request_digest=hashlib.sha256(body).hexdigest(),
        status_code=status,
        response_content_type=content_type,
        response_body=_capture(raw, response_maximum),
        response_digest=hashlib.sha256(raw).hexdigest(),
    )
    return exchange, value


def _wait_socket(connection: socket.socket, deadline: float, *, writable: bool) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("controlled loopback absolute deadline expired")
    readable = [] if writable else [connection]
    writeable = [connection] if writable else []
    ready_read, ready_write, exceptional = select.select(
        readable, writeable, [connection], remaining
    )
    if exceptional or (writable and not ready_write) or (not writable and not ready_read):
        raise TimeoutError("controlled loopback absolute deadline expired")


def _parse_response_headers(raw: bytes) -> tuple[int, str, int | None]:
    if len(raw) > 16 * 1024:
        raise OmivInputError("controlled response headers exceeded their byte bound")
    try:
        lines = raw.decode("iso-8859-1").split("\r\n")
    except UnicodeDecodeError as exc:
        raise OmivInputError("controlled response headers were malformed") from exc
    status_parts = lines[0].split(" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or not status_parts[1].isdigit()
    ):
        raise OmivInputError("controlled response status line was malformed")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            raise OmivInputError("controlled response header was malformed")
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if normalized in headers:
            raise OmivInputError("controlled response contained duplicate headers")
        headers[normalized] = value.strip()
    if "transfer-encoding" in headers:
        raise OmivInputError("controlled response transfer encoding is unsupported")
    content_length: int | None = None
    if "content-length" in headers:
        declared = headers["content-length"]
        if not declared.isdigit():
            raise OmivInputError("controlled response length was malformed")
        content_length = int(declared)
    return int(status_parts[1]), headers.get("content-type", ""), content_length


def _rehash(
    plan: ControlledPlan,
    root: Path,
    boundary: Literal["PRE_START", "POST_READY", "POST_PROBES", "POST_SHUTDOWN"],
) -> RehashBoundary:
    expected: list[tuple[str, LocalFileBinding, int]] = [
        ("EXECUTABLE", plan.executable, plan.request.limits.max_executable_bytes),
        *[
            (declared.role.value, binding, plan.request.limits.max_artifact_bytes)
            for declared, binding in zip(plan.request.artifacts, plan.artifacts, strict=True)
        ],
    ]
    bindings: list[RehashBinding] = []
    for role, planned, maximum in expected:
        descriptor = _open_portable_regular(root, planned.path)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise OmivInputError("controlled re-hash input is not a bounded regular file")
            hasher = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, min(_READ_CHUNK, maximum - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise OmivInputError("controlled re-hash input exceeded its byte bound")
                hasher.update(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or size != after.st_size:
                raise OmivInputError("controlled re-hash input changed while inspected")
            digest = hasher.hexdigest()
        finally:
            os.close(descriptor)
        if digest != planned.expected_sha256 or size != planned.size:
            raise OmivInputError(f"pinned {role.lower()} bytes changed at {boundary}")
        bindings.append(RehashBinding(role=role, path=planned.path, size=size, sha256=digest))
    return RehashBoundary(boundary=boundary, bindings=bindings)


def _portable_sources(sources: list[bytes], *, root: Path, work: Path, ports: list[int]) -> None:
    dynamic = [str(root).encode(), str(work).encode(), *(str(item).encode() for item in ports)]
    for raw in sources:
        if any(marker and marker in raw for marker in dynamic):
            raise OmivInputError("controlled retained source exposed a private runtime value")
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OmivInputError("controlled retained source is not valid UTF-8") from exc
        try:
            parsed = json.loads(value) if value.startswith(("{", "[")) else value
        except (json.JSONDecodeError, ValueError):
            parsed = value
        pending = [parsed]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, str):
                for line in item.splitlines() or [""]:
                    _reject_sensitive_text(line, "controlled retained source")


def _work_boundary(work: Path, limits: Any) -> WorkBoundary:
    entries: list[str] = []
    total = 0
    for current, directories, files in os.walk(work, topdown=True, followlinks=False):
        directories.sort(key=lambda value: value.encode("utf-8"))
        files.sort(key=lambda value: value.encode("utf-8"))
        base = Path(current)
        for name in [*directories, *files]:
            path = base / name
            relative = path.relative_to(work).as_posix()
            entries.append(relative)
            if len(entries) > limits.max_work_entries:
                raise OmivInputError("controlled work entry count exceeded its bound")
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                if info.st_size > limits.max_work_file_bytes:
                    raise OmivInputError("controlled work file exceeded its byte bound")
                total += info.st_size
                if total > limits.max_work_total_bytes:
                    raise OmivInputError("controlled work files exceeded their total bound")
    return WorkBoundary(entries=entries, unexpected=bool(entries), cleanup_complete=False)


def _parse_observation(
    probe: ControlledProbe,
    request: ControlledRequest,
    tokenize: HttpExchange,
    token_value: dict[str, Any],
    completion: HttpExchange,
    completion_value: dict[str, Any],
) -> ProbeObservation:
    maximum = request.limits.max_response_bytes
    if tokenize.status_code != 200 or tokenize.response_content_type != "application/json":
        raise OmivInputError("tokenize response status or content type is unsupported")
    if set(token_value) != {"tokens"} or not isinstance(token_value["tokens"], list):
        raise OmivInputError("tokenize response has an unknown or malformed schema")
    tokens = token_value["tokens"]
    if (
        not tokens
        or len(tokens) > 4096
        or any(type(item) is not int or item < 0 or item > 2**31 - 1 for item in tokens)
    ):
        raise OmivInputError("tokenize response contains an empty, invalid, or oversized array")
    if completion.status_code != 200 or completion.response_content_type != "application/json":
        raise OmivInputError("completion response status or content type is unsupported")
    required = {
        "content",
        "prompt_tokens",
        "predicted_tokens",
        "prompt_ms",
        "predicted_ms",
        "finish_reason",
        "backend",
        "dflash",
    }
    if set(completion_value) != required:
        raise OmivInputError("completion response has unknown or missing fields")
    try:
        backend = BackendObservation.model_validate(completion_value["backend"])
        dflash = DFlashObservation.model_validate(completion_value["dflash"])
    except ValidationError as exc:
        raise OmivInputError("completion response has invalid typed runtime facts") from exc
    content = completion_value["content"]
    if not isinstance(content, str) or not content:
        raise OmivInputError("completion response content is empty or invalid")
    integer_fields = ("prompt_tokens", "predicted_tokens", "prompt_ms", "predicted_ms")
    if any(type(completion_value[name]) is not int for name in integer_fields):
        raise OmivInputError("completion response counters are not strict integers")
    prompt_tokens = completion_value["prompt_tokens"]
    predicted_tokens = completion_value["predicted_tokens"]
    if prompt_tokens <= 0 or prompt_tokens != len(tokens):
        raise OmivInputError("prompt-token counter is absent or incoherent")
    if predicted_tokens <= 0 or predicted_tokens > probe.max_generated_tokens:
        raise OmivInputError("predicted-token counter is absent or outside its bound")
    if completion_value["finish_reason"] not in {"stop", "length"}:
        raise OmivInputError("completion finish reason is unsupported")
    if dflash.active != probe.use_dflash:
        raise OmivInputError("DFlash activation fact is absent or incoherent")
    if probe.use_dflash and dflash.draft_tokens <= 0:
        raise OmivInputError("DFlash generated draft-token count is not positive")
    if not probe.use_dflash and (dflash.draft_tokens or dflash.accepted_tokens):
        raise OmivInputError("non-DFlash probe reported impossible draft-token counts")
    raw_content = content.encode("utf-8")
    if len(raw_content) > maximum:
        raise OmivInputError("completion content exceeds the response bound")
    observation = ProbeObservation(
        probe_id=probe.probe_id,
        tokenize=tokenize,
        completion=completion,
        tokens=tokens,
        content=_capture(raw_content, maximum),
        prompt_tokens=prompt_tokens,
        predicted_tokens=predicted_tokens,
        prompt_ms=completion_value["prompt_ms"],
        predicted_ms=completion_value["predicted_ms"],
        finish_reason=completion_value["finish_reason"],
        backend=backend,
        dflash=dflash,
        predicate_matched=content == probe.expected_content,
    )
    try:
        validate_observation(observation, probe, request)
    except (TypeError, ValueError) as exc:
        raise OmivInputError("completion response differs from the controlled request") from exc
    return observation


def _request_values(
    probe: ControlledProbe, image: bytes | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    prompt = f"[img-0]\n{probe.prompt}" if probe.modality == ProbeModality.IMAGE else probe.prompt
    tokenize: dict[str, Any] = {"content": prompt}
    completion: dict[str, Any] = {
        "prompt": prompt,
        "seed": 0,
        "temperature": 0,
        "n_predict": probe.max_generated_tokens,
        "cache_prompt": False,
    }
    if probe.modality == ProbeModality.IMAGE:
        if image is None:
            raise OmivInputError("image probe lacks pinned IMAGE bytes")
        completion["image_data"] = [{"data": base64.b64encode(image).decode("ascii"), "id": 0}]
    return tokenize, completion


def _stages(
    observations: list[ProbeObservation],
    count: int,
    ready: bool,
    servers: list[ControlledServerObservation],
    work: WorkBoundary,
) -> list[StageResult]:
    complete = len(observations) == count
    matches = sum(item.predicate_matched for item in observations)
    return [
        StageResult(
            stage=StageName.LOAD,
            status=StageStatus.PASS if ready else StageStatus.FAIL,
            basis=(
                "Sealed pinned execution bytes, profile-owned argv, live process, strict "
                "readiness, and post-ready re-hash were observed."
            ),
        ),
        StageResult(
            stage=StageName.TOKENIZER,
            status=StageStatus.PASS if complete else StageStatus.UNKNOWN,
            basis=(
                "Every mandatory profile-owned tokenize exchange returned a non-empty bounded "
                "valid token array."
            ),
        ),
        StageResult(
            stage=StageName.PREFILL,
            status=StageStatus.PASS if complete else StageStatus.UNKNOWN,
            basis=(
                "Every completion reported a positive prompt counter coherent with its tokenize "
                "response."
            ),
        ),
        StageResult(
            stage=StageName.DECODE,
            status=(
                StageStatus.PASS
                if complete and controlled_decode_complete(servers, work)
                else StageStatus.FAIL
            ),
            basis=(
                "Every completion reported positive bounded predicted tokens and a supported "
                "terminal condition."
            ),
        ),
        StageResult(
            stage=StageName.OUTPUT,
            status=StageStatus.PASS if complete and matches == count else StageStatus.FAIL,
            basis=(
                f"Profile-owned EXACT_UTF8 predicates matched {matches}/{count} mandatory probes."
            ),
        ),
    ]


def _build_evidence(
    plan: ControlledPlan,
    version: ControlledProcess,
    observed_version: str | None,
    boundaries: list[RehashBoundary],
    servers: list[ControlledServerObservation],
    observations: list[ProbeObservation],
    work: WorkBoundary,
    findings: list[ControlledFinding],
) -> ControlledEvidence:
    stages = _stages(
        observations,
        len(plan.request.probes),
        len(servers) == len(plan.invocation.servers),
        servers,
        work,
    )
    verified = (
        observed_version == plan.request.expected_runtime_version
        and len(boundaries) == 4
        and len(observations) == len(plan.request.probes)
        and all(
            server.process.started
            and server.process.alive_at_ready
            and server.process.ended
            and server.process.return_code == 0
            and server.process.termination in {"GRACEFUL", "SIGTERM"}
            and not server.process.startup_timed_out
            and not server.process.probe_timed_out
            and not server.process.stdout.overflow
            and not server.process.stderr.overflow
            for server in servers
        )
        and not work.unexpected
        and work.cleanup_complete
        and all(item.status == StageStatus.PASS for item in stages)
        and not any(item.blocking for item in findings)
    )
    body: dict[str, Any] = {
        "schema": CONTROLLED_EVIDENCE_SCHEMA,
        "candidate_notice": "PHASE_7B3_CANDIDATE_PHASE_7_UNFROZEN",
        "plan": plan.model_dump(mode="json", by_alias=True),
        "request_digest": plan.request_digest,
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "profile_id": plan.request.profile_id,
        "status": CompatibilityStatus.VERIFIED_WITHIN_PROFILE.value
        if verified
        else CompatibilityStatus.NOT_VERIFIED.value,
        "version_execution": version.model_dump(mode="json"),
        "observed_runtime_version": observed_version,
        "rehash_boundaries": [item.model_dump(mode="json") for item in boundaries],
        "servers": [item.model_dump(mode="json") for item in servers],
        "probes": [item.model_dump(mode="json") for item in observations],
        "work_boundary": work.model_dump(mode="json"),
        "privacy_boundary": PrivacyBoundary().model_dump(mode="json"),
        "stages": [item.model_dump(mode="json") for item in stages],
        "findings": [item.model_dump(mode="json") for item in findings],
        "limitations": list(CONTROLLED_LIMITATIONS),
        "trust_statement": CONTROLLED_TRUST_STATEMENT,
    }
    digest = canonical_sha256({"domain": CONTROLLED_EVIDENCE_SCHEMA, "body": body})
    return ControlledEvidence.model_validate(
        {
            **body,
            "evidence_id": f"controlled_runtime_evidence_{digest[:32]}",
            "evidence_digest": digest,
        }
    )


def _read_pinned_image(
    plan: ControlledPlan, artifacts: dict[ArtifactRole, _BoundInput]
) -> bytes | None:
    declared = next(
        (item for item in plan.request.artifacts if item.role == ArtifactRole.IMAGE), None
    )
    if declared is None:
        return None
    if any(
        controlled_image_completion_request_bytes(probe, declared.size)
        > plan.request.limits.max_request_bytes
        for probe in plan.request.probes
        if probe.modality == ProbeModality.IMAGE
    ):
        raise OmivInputError("encoded IMAGE request exceeds the controlled request-body limit")
    source = artifacts[ArtifactRole.IMAGE]
    raw = bytearray()
    digest = hashlib.sha256()
    offset = 0
    while offset < declared.size:
        chunk = os.pread(source.descriptor, min(_READ_CHUNK, declared.size - offset), offset)
        if not chunk:
            break
        raw.extend(chunk)
        digest.update(chunk)
        offset += len(chunk)
        if offset > declared.size:
            raise OmivInputError("pinned IMAGE bytes exceeded their declared bound")
    if offset != declared.size or digest.hexdigest() != declared.sha256:
        raise OmivInputError("pinned IMAGE bytes changed before request construction")
    return bytes(raw)


def _server_arguments(
    invocation: ControlledServerInvocation,
    inputs: _ExecutionInputs,
    port: int,
) -> list[str]:
    replacements = {
        "{runtime_executable}": inputs.executable.child_path,
        "{artifact:MAIN}": inputs.artifacts[ArtifactRole.MAIN].child_path,
        "{OMIV_SELECTED_PORT}": str(port),
    }
    for role in (ArtifactRole.PROJECTOR, ArtifactRole.DFLASH):
        if role in inputs.artifacts:
            replacements[f"{{artifact:{role.value}}}"] = inputs.artifacts[role].child_path
    return [replacements.get(item, item) for item in invocation.arguments]


@dataclass
class _RunningServer:
    invocation: ControlledServerInvocation
    port: int
    process: _ContainedProcess
    readiness: HttpExchange | None
    observations: list[ProbeObservation]
    termination: Literal["NOT_STARTED", "GRACEFUL", "SIGTERM", "SIGKILL"] = "NOT_STARTED"
    report: _ContainmentReport | None = None
    closed: bool = False


def _shutdown_server(runtime: _RunningServer, plan: ControlledPlan) -> None:
    if runtime.closed:
        return
    error: OmivInputError | None = None
    try:
        runtime.report = runtime.process.finish(
            mode="TERMINATE",
            timeout_seconds=0,
            grace_seconds=plan.request.limits.shutdown_timeout_seconds,
        )
        runtime.termination = runtime.report.termination  # type: ignore[assignment]
    except OmivInputError as exc:
        error = exc
    runtime.closed = True
    if error is not None:
        raise error


def _start_server_configuration(
    plan: ControlledPlan,
    invocation: ControlledServerInvocation,
    inputs: _ExecutionInputs,
    work: Path,
    environment: dict[str, str],
) -> _RunningServer:
    port = _select_port()
    actual_arguments = _server_arguments(invocation, inputs, port)
    process = _ContainedProcess.start(
        actual_arguments,
        cwd=work,
        environment=environment,
        max_stdout_bytes=plan.request.limits.max_stdout_bytes,
        max_stderr_bytes=plan.request.limits.max_stderr_bytes,
        max_work_file_bytes=plan.request.limits.max_work_file_bytes,
        pass_fds=inputs.pass_fds,
    )
    runtime: _RunningServer | None = None
    try:
        deadline = time.monotonic() + plan.request.limits.startup_timeout_seconds
        while time.monotonic() < deadline:
            return_code, stdout_overflow, stderr_overflow = process.status()
            if return_code is not None:
                raise OmivInputError("controlled server exited before readiness")
            if stdout_overflow or stderr_overflow:
                raise OmivInputError("controlled server stream overflowed before readiness")
            try:
                candidate, value = _http_exchange(
                    port,
                    "GET",
                    "/health",
                    None,
                    deadline=deadline,
                    request_maximum=plan.request.limits.max_request_bytes,
                    response_maximum=plan.request.limits.max_response_bytes,
                    max_nodes=plan.request.limits.max_json_tokens,
                )
                if (
                    candidate.status_code == 200
                    and candidate.response_content_type == "application/json"
                    and value == {"status": "ok"}
                ):
                    return_code, _stdout_overflow, _stderr_overflow = process.status()
                    if return_code is not None:
                        raise OmivInputError("controlled server exited at readiness")
                    runtime = _RunningServer(
                        invocation=invocation,
                        port=port,
                        process=process,
                        readiness=candidate,
                        observations=[],
                    )
                    return runtime
            except OmivInputError:
                time.sleep(0.02)
        raise OmivInputError("controlled server readiness deadline expired")
    except BaseException:
        if runtime is None:
            provisional = _RunningServer(
                invocation=invocation,
                port=port,
                process=process,
                readiness=None,
                observations=[],
            )
            _shutdown_server(provisional, plan)
        raise


def _probe_server_configuration(
    runtime: _RunningServer, plan: ControlledPlan, image: bytes | None
) -> None:
    probes = [item for item in plan.request.probes if item.probe_id in runtime.invocation.probe_ids]
    for probe in probes:
        return_code, stdout_overflow, stderr_overflow = runtime.process.status()
        if return_code is not None:
            raise OmivInputError("controlled server exited before all probes completed")
        tokenize_value, completion_value = _request_values(probe, image)
        deadline = time.monotonic() + plan.request.limits.probe_timeout_seconds
        tokenize, token_response = _http_exchange(
            runtime.port,
            "POST",
            "/tokenize",
            tokenize_value,
            deadline=deadline,
            request_maximum=plan.request.limits.max_request_bytes,
            response_maximum=plan.request.limits.max_response_bytes,
            max_nodes=plan.request.limits.max_json_tokens,
        )
        completion, completion_response = _http_exchange(
            runtime.port,
            "POST",
            "/completion",
            completion_value,
            deadline=deadline,
            request_maximum=plan.request.limits.max_request_bytes,
            response_maximum=plan.request.limits.max_response_bytes,
            max_nodes=plan.request.limits.max_json_tokens,
        )
        runtime.observations.append(
            _parse_observation(
                probe,
                plan.request,
                tokenize,
                token_response,
                completion,
                completion_response,
            )
        )
        _return_code, stdout_overflow, stderr_overflow = runtime.process.status()
        if stdout_overflow or stderr_overflow:
            raise OmivInputError("controlled server process stream exceeded its bound")


def _require_servers_alive(runtimes: list[_RunningServer], boundary: str) -> None:
    if not runtimes:
        raise OmivInputError(f"controlled server exited at {boundary}")
    for runtime in runtimes:
        return_code, stdout_overflow, stderr_overflow = runtime.process.status()
        if return_code is not None or stdout_overflow or stderr_overflow:
            raise OmivInputError(f"controlled server exited at {boundary}")


def _server_record(
    runtime: _RunningServer,
    plan: ControlledPlan,
    work: Path,
    evidence_environment: list[EnvironmentVariable],
) -> ControlledServerObservation:
    if not runtime.closed or runtime.readiness is None or runtime.report is None:
        raise OmivInputError(
            "controlled server was recorded before complete readiness and shutdown"
        )
    stdout = runtime.report.stdout
    stderr = runtime.report.stderr
    retained = [stdout, stderr]
    exchanges = [
        runtime.readiness,
        *(item.tokenize for item in runtime.observations),
        *(item.completion for item in runtime.observations),
    ]
    for exchange in exchanges:
        retained.extend(
            [
                base64.b64decode(exchange.request_body.captured_base64, validate=True),
                base64.b64decode(exchange.response_body.captured_base64, validate=True),
            ]
        )
    _portable_sources(retained, root=work.parent.resolve(), work=work, ports=[runtime.port])
    process_record = ControlledProcess(
        arguments=runtime.invocation.arguments,
        environment=evidence_environment,
        started=True,
        alive_at_ready=True,
        ended=True,
        return_code=runtime.report.return_code,
        startup_timed_out=False,
        probe_timed_out=False,
        termination=runtime.termination,
        containment=ContainmentObservation.model_validate(runtime.report.observation),
        stdout=_capture(
            stdout,
            plan.request.limits.max_stdout_bytes,
            overflow=runtime.report.stdout_overflow,
        ),
        stderr=_capture(
            stderr,
            plan.request.limits.max_stderr_bytes,
            overflow=runtime.report.stderr_overflow,
        ),
    )
    return ControlledServerObservation(
        use_dflash=runtime.invocation.use_dflash,
        probe_ids=runtime.invocation.probe_ids,
        readiness=runtime.readiness,
        process=process_record,
    )


def execute_controlled_plan(plan: ControlledPlan, root: Path) -> ControlledEvidence:
    if plan.status != PlanStatus.READY:
        raise OmivInputError("blocked controlled runtime plan cannot be executed")
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("controlled runtime root must be a regular local directory")
    resolved = root.resolve()
    work = Path(tempfile.mkdtemp(prefix=".omiv-controlled-runtime-", dir=resolved))
    inputs: _ExecutionInputs | None = None
    environment, evidence_environment = _environment(work)
    empty = _capture(b"", plan.request.limits.max_stdout_bytes)
    version = ControlledProcess(
        arguments=plan.invocation.version_arguments,
        environment=evidence_environment,
        started=False,
        alive_at_ready=False,
        ended=False,
        return_code=None,
        startup_timed_out=False,
        probe_timed_out=False,
        termination="NOT_STARTED",
        stdout=empty,
        stderr=_capture(b"", plan.request.limits.max_stderr_bytes),
    )
    boundaries: list[RehashBoundary] = []
    servers: list[ControlledServerObservation] = []
    observations_by_id: dict[str, ProbeObservation] = {}
    observed_version: str | None = None
    work_record = WorkBoundary(entries=[], unexpected=False, cleanup_complete=False)
    findings: list[ControlledFinding] = []
    try:
        inputs = _bind_execution_inputs(plan, resolved)
        boundaries.append(_rehash(plan, resolved, "PRE_START"))
        image = _read_pinned_image(plan, inputs.artifacts)
        version_containment: dict[str, Any] = {}
        version_termination: list[str] = []
        native_version = _run_bounded(
            [inputs.executable.child_path, "--version"],
            plan.invocation.version_arguments,
            cwd=work,
            environment=environment,
            evidence_environment=evidence_environment,
            timeout_seconds=plan.request.limits.version_timeout_seconds,
            max_stdout_bytes=plan.request.limits.max_stdout_bytes,
            max_stderr_bytes=plan.request.limits.max_stderr_bytes,
            max_work_file_bytes=plan.request.limits.max_work_file_bytes,
            pass_fds=inputs.pass_fds,
            containment_observation=version_containment,
            termination_observation=version_termination,
        )
        if len(version_termination) != 1 or version_termination[0] not in {
            "GRACEFUL",
            "SIGTERM",
            "SIGKILL",
        }:
            raise OmivInputError("controlled version termination observation was incomplete")
        version = _controlled_from_native(
            native_version,
            plan.invocation.version_arguments,
            evidence_environment,
            version_containment,
            version_termination[0],  # type: ignore[arg-type]
        )
        if (
            native_version.return_code != 0
            or native_version.timed_out
            or native_version.stdout.overflow
            or native_version.stderr.overflow
        ):
            raise OmivInputError("controlled runtime version observation was incomplete")
        version_stdout = base64.b64decode(native_version.stdout.captured_base64, validate=True)
        version_stderr = base64.b64decode(native_version.stderr.captured_base64, validate=True)
        _portable_sources([version_stdout, version_stderr], root=resolved, work=work, ports=[])
        try:
            observed_version = derive_controlled_runtime_version(version_stdout, version_stderr)
        except ValueError as exc:
            raise OmivInputError(str(exc)) from exc
        if observed_version != plan.request.expected_runtime_version:
            raise OmivInputError("controlled runtime version does not match its exact pin")

        runtimes: list[_RunningServer] = []
        try:
            for invocation in plan.invocation.servers:
                runtimes.append(
                    _start_server_configuration(
                        plan,
                        invocation,
                        inputs,
                        work,
                        environment,
                    )
                )
            _require_servers_alive(runtimes, "POST_READY")
            boundaries.append(_rehash(plan, resolved, "POST_READY"))
            _require_servers_alive(runtimes, "POST_READY")
            for runtime in runtimes:
                _probe_server_configuration(runtime, plan, image)
            _require_servers_alive(runtimes, "POST_PROBES")
            boundaries.append(_rehash(plan, resolved, "POST_PROBES"))
            _require_servers_alive(runtimes, "POST_PROBES")
        finally:
            shutdown_error: OmivInputError | None = None
            for runtime in runtimes:
                try:
                    _shutdown_server(runtime, plan)
                except OmivInputError as exc:
                    if shutdown_error is None:
                        shutdown_error = exc
            if shutdown_error is not None:
                raise shutdown_error
        for runtime in runtimes:
            server = _server_record(runtime, plan, work, evidence_environment)
            servers.append(server)
            observations_by_id.update({item.probe_id: item for item in runtime.observations})
        boundaries.append(_rehash(plan, resolved, "POST_SHUTDOWN"))
        work_record = _work_boundary(work, plan.request.limits)
    finally:
        if inputs is not None:
            inputs.close()
        shutil.rmtree(work)
        cleanup_complete = not work.exists()
        work_record = work_record.model_copy(update={"cleanup_complete": cleanup_complete})
    observations = [observations_by_id[item.probe_id] for item in plan.request.probes]
    stderr = b"\n".join(
        base64.b64decode(item.process.stderr.captured_base64, validate=True) for item in servers
    )
    if b"tokenizer eot/eog" in stderr.lower():
        findings.append(
            ControlledFinding(
                code="TOKENIZER_EOT_EOG_WARNING",
                severity=FindingSeverity.WARN,
                blocking=False,
                detail=(
                    "The pinned runtime emitted its tokenizer EOT/EOG warning. This profile "
                    "records it as nonfatal and makes no tokenizer/config parity claim."
                ),
            )
        )
    return _build_evidence(
        plan,
        version,
        observed_version,
        boundaries,
        servers,
        observations,
        work_record,
        findings,
    )


def concise_controlled_plan(plan: ControlledPlan) -> str:
    pinned = sum(
        item.observed_sha256 == item.expected_sha256 and not item.issues for item in plan.artifacts
    )
    return (
        f"{plan.status.value} profile={plan.request.profile_id} "
        f"executable_pinned={'yes' if not plan.executable.issues else 'no'} "
        f"artifact_payloads={pinned}/{len(plan.artifacts)} loopback=127.0.0.1 "
        "network=loopback-only shell=no phase7=unfrozen"
    )


def concise_controlled_evidence(evidence: ControlledEvidence) -> str:
    rows = [
        "Runtime/profile identity       VERIFIED",
        "Artifact payloads              VERIFIED "
        f"{len(evidence.plan.artifacts)}/{len(evidence.plan.artifacts)}",
        "Executable                     VERIFIED",
        "Backend/device/offload         VERIFIED_REQUEST_BOUND",
    ]
    for stage in evidence.stages:
        suffix = (
            f" {sum(item.predicate_matched for item in evidence.probes)}/"
            f"{len(evidence.probes)} probes"
            if stage.stage == StageName.OUTPUT
            else ""
        )
        rows.append(f"{stage.stage.value:<30} {stage.status.value}{suffix}")
    rows.append(f"Runtime compatibility         {evidence.status.value}")
    rows.append("Scope                         WITHIN_PROFILE; Phase 7 remains unfrozen")
    return "\n".join(rows)


# --- R11 item 2: CUDA containment preflight ---------------------------------

# The version step already runs the pinned executable inside the exact final
# containment, so it exercises CUDA initialisation there.  For A6 this probe
# lets a real GPU host verify CUDA init inside that identical containment
# BEFORE downloading model bytes, failing fast if the containment/driver stack
# cannot initialise the GPU.  CI has no GPU, so it must use a deterministic
# synthetic substitute that verifies the containment mechanics only and makes
# no CUDA-compatibility claim.
CONTROLLED_CUDA_PREFLIGHT_REAL = "REAL_GPU_CUDA_INIT_WITHIN_CONTAINMENT"
CONTROLLED_CUDA_PREFLIGHT_SYNTHETIC = "SYNTHETIC_CONTAINMENT_MECHANICS_ONLY_NOT_A_CUDA_CLAIM"
CONTROLLED_CUDA_PREFLIGHT_FAILED = "CUDA_PREFLIGHT_FAILED"

# llama.cpp logs `ggml_cuda_init:` lines on SUCCESS too (e.g. "found 1 CUDA
# devices"), so the gate must match failure-specific text only.  A healthy
# CUDA initialization inside the containment must pass; these markers fail it.
_CUDA_FAILURE_MARKERS = (
    "ggml_cuda_init: failed",
    "no CUDA devices found",
    "CUDA error",
    "CUDA_ERROR_",
    "cudaErrorInitializationError",
    "failed to initialize CUDA",
)


@dataclass(frozen=True)
class ControlledProbeResult:
    return_code: int | None
    timed_out: bool
    termination: str
    stdout: bytes
    stderr: bytes
    stdout_overflow: bool
    stderr_overflow: bool
    mechanism: str


def run_controlled_probe(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    max_stdout_bytes: int = 1 << 20,
    max_stderr_bytes: int = 1 << 20,
    max_work_file_bytes: int = 1 << 20,
    timeout_seconds: float = 30.0,
) -> ControlledProbeResult:
    """Run one command inside the exact final containment and bound its output.

    Reuses the identical containment path (user+PID+mount namespaces, private
    fresh /proc, atomic pre-exec gate, kernel whole-tree cleanup) as the version
    and server steps, so a CUDA probe run through it observes exactly what the
    real runtime will.  Never establishes a controlled verdict on its own.
    """
    process = _ContainedProcess.start(
        arguments,
        cwd=cwd,
        environment=environment,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        max_work_file_bytes=max_work_file_bytes,
        pass_fds=(),
    )
    report = process.finish(mode="WAIT", timeout_seconds=timeout_seconds, grace_seconds=1.0)
    return ControlledProbeResult(
        return_code=report.return_code,
        timed_out=report.timed_out,
        termination=report.termination,
        stdout=report.stdout,
        stderr=report.stderr,
        stdout_overflow=report.stdout_overflow,
        stderr_overflow=report.stderr_overflow,
        mechanism=str(report.observation.get("mechanism", "")),
    )


def evaluate_cuda_preflight(result: ControlledProbeResult, *, expected_gpu_marker: str) -> str:
    """Classify a CUDA preflight result. Real success requires a real GPU marker.

    A clean exit alone is never sufficient: the probe stdout/stderr must contain
    the caller-supplied GPU identity marker (e.g. the observed RTX 5090 name),
    which a synthetic, GPU-less substitute cannot produce.  This guarantees a
    synthetic run can never be upgraded into the real GPU gate.
    """
    if not expected_gpu_marker:
        raise ValueError("a real GPU marker is required to satisfy the CUDA preflight gate")
    combined = result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace")
    healthy = (
        result.return_code == 0
        and not result.timed_out
        and not result.stdout_overflow
        and not result.stderr_overflow
        and result.mechanism == _CONTAINMENT_MECHANISM
        and not any(marker in combined for marker in _CUDA_FAILURE_MARKERS)
        and expected_gpu_marker in combined
    )
    return CONTROLLED_CUDA_PREFLIGHT_REAL if healthy else CONTROLLED_CUDA_PREFLIGHT_FAILED


# --- R11 item 3: runtime code identity --------------------------------------

# Project-owned runtime components. A thin launcher that dynamically loads these
# does not have its server/CUDA logic covered by the launcher's own SHA-256.
PROJECT_PRIVATE_RUNTIME_SONAME_PREFIXES = (
    "libllama",
    "libggml",
    "libmtmd",
)


def classify_project_runtime_linkage(needed_sonames: list[str]) -> list[str]:
    """Flag project-private shared objects a launcher dynamically depends on."""
    issues: list[str] = []
    for soname in needed_sonames:
        base = soname.split("/")[-1]
        if any(base.startswith(prefix) for prefix in PROJECT_PRIVATE_RUNTIME_SONAME_PREFIXES):
            issues.append(
                f"Runtime launcher dynamically depends on project-private component: {base}"
            )
    return issues


def require_static_project_runtime(needed_sonames: list[str]) -> None:
    """Preferred R11 identity: reject a launcher with project-private .so deps.

    When this passes, the executable SHA-256 covers the project runtime logic.
    It never covers the system CUDA/driver toolkit, whose identity is recorded
    separately (driver + toolkit facts) and is an explicit trust boundary.
    """
    issues = classify_project_runtime_linkage(needed_sonames)
    if issues:
        raise OmivInputError("; ".join(issues))


# --- R11 item 4: raw capture retention hygiene ------------------------------

_PRESIGNED_QUERY_RE = re.compile(
    r"([?&])"
    r"(?:X-Amz-[^=&\s]+|Policy|Signature|Key-Pair-Id|Expires|[A-Za-z0-9_-]*token|user_id)"
    r"=[^&\s]*",
    re.IGNORECASE,
)
_HOME_PATH_RE = re.compile(r"(?:/home/[^/\s:]+|/root(?=/|\s|$))")


def redact_portable_capture_text(text: str) -> str:
    """Strip presigned-URL secrets, host home paths from retained capture text."""
    redacted = _PRESIGNED_QUERY_RE.sub(r"\1[REDACTED]", text)
    return _HOME_PATH_RE.sub("/home/[REDACTED]", redacted)


def bounded_capture_manifest(
    name: str, argv: list[str], result: ControlledProbeResult
) -> dict[str, Any]:
    """Bind argv, exit, timeout/overflow and byte/SHA-256 identity for a capture."""
    return {
        "name": name,
        "argv": list(argv),
        "return_code": result.return_code,
        "timed_out": result.timed_out,
        "termination": result.termination,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout_overflow": result.stdout_overflow,
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_overflow": result.stderr_overflow,
    }
