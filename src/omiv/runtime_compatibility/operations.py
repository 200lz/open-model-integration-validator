"""Bounded local orchestration for candidate runtime compatibility profiles."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
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

# Serialized-object limits are deliberately separate.  Text fields are charged at
# the JSON worst case of six bytes per schema character (``\uXXXX``); captured
# bytes use the exact base64 expansion.  The finite margins cover keys,
# separators, indentation, integer spellings, and small profile-owned literals.
_MIB = 1024 * 1024
_JSON_MAX_BYTES_PER_CHARACTER = 6
_MAX_REQUEST_EXPECTED_CONTENT_CHARACTERS = 16 * _MIB
_MAX_REQUEST_PROMPT_CHARACTERS = 16 * 32_768
_MAX_REQUEST_PATH_AND_ID_CHARACTERS = 10 * 1024 + 16 * 96 + 128 + 512
_REQUEST_CANONICAL_FORMAT_MARGIN_BYTES = 8 * _MIB
MAX_RUNTIME_COMPAT_REQUEST_BYTES = (
    _JSON_MAX_BYTES_PER_CHARACTER
    * (
        _MAX_REQUEST_EXPECTED_CONTENT_CHARACTERS
        + _MAX_REQUEST_PROMPT_CHARACTERS
        + _MAX_REQUEST_PATH_AND_ID_CHARACTERS
    )
    + _REQUEST_CANONICAL_FORMAT_MARGIN_BYTES
)
_PLAN_BINDING_INVOCATION_AND_FORMAT_MARGIN_BYTES = 24 * _MIB
MAX_RUNTIME_COMPAT_PLAN_BYTES = (
    MAX_RUNTIME_COMPAT_REQUEST_BYTES + _PLAN_BINDING_INVOCATION_AND_FORMAT_MARGIN_BYTES
)


def _base64_size(raw_bytes: int) -> int:
    return 4 * ((raw_bytes + 2) // 3)


_MAX_EVIDENCE_PROCESS_COUNT = 3  # version plus two server configurations
_MAX_EVIDENCE_PROBE_COUNT = 16
_MAX_EVIDENCE_SERVER_COUNT = 2
_MAX_EVIDENCE_PROCESS_CAPTURE_BASE64_BYTES = _MAX_EVIDENCE_PROCESS_COUNT * (
    _base64_size(16 * _MIB) + _base64_size(4 * _MIB)
)
_MAX_EVIDENCE_HTTP_CAPTURE_BASE64_BYTES = (
    # Two readiness responses; GET request bodies are schema-required empty.
    _MAX_EVIDENCE_SERVER_COUNT * _base64_size(4 * _MIB)
    # Each probe retains tokenize and completion request/response bodies.
    + _MAX_EVIDENCE_PROBE_COUNT * (2 * _base64_size(4 * _MIB) + 2 * _base64_size(4 * _MIB))
    # Each probe also retains its projected completion content capture.
    + _MAX_EVIDENCE_PROBE_COUNT * _base64_size(4 * _MIB)
)
_MAX_EVIDENCE_REHASH_PATH_CHARACTERS = 4 * 9 * (32 + 1024)
_MAX_EVIDENCE_FINDING_CHARACTERS = 256 * (128 + 1000)
_MAX_EVIDENCE_WORK_PATH_CHARACTERS = 256 * 1024
_EVIDENCE_CANONICAL_FORMAT_MARGIN_BYTES = 32 * _MIB
MAX_RUNTIME_COMPAT_EVIDENCE_BYTES = (
    MAX_RUNTIME_COMPAT_PLAN_BYTES
    + _MAX_EVIDENCE_PROCESS_CAPTURE_BASE64_BYTES
    + _MAX_EVIDENCE_HTTP_CAPTURE_BASE64_BYTES
    + _JSON_MAX_BYTES_PER_CHARACTER
    * (
        _MAX_EVIDENCE_REHASH_PATH_CHARACTERS
        + _MAX_EVIDENCE_FINDING_CHARACTERS
        + _MAX_EVIDENCE_WORK_PATH_CHARACTERS
    )
    + _EVIDENCE_CANONICAL_FORMAT_MARGIN_BYTES
)
_READ_CHUNK = 64 * 1024
_CONTAINMENT_CONTROL_PAYLOAD_BYTES = 512 * 1024
_CONTAINMENT_CONTROL_METADATA_BYTES = 16 * 1024
_CONTAINMENT_CONTROL_MAX_BYTES = (
    _CONTAINMENT_CONTROL_PAYLOAD_BYTES + _CONTAINMENT_CONTROL_METADATA_BYTES
)
_CONTAINMENT_MAX_STDOUT_BYTES = 16 * 1024 * 1024
_CONTAINMENT_MAX_STDERR_BYTES = 4 * 1024 * 1024
_CONTAINMENT_CAPTURE_MAGIC = b"OMIVCAP2"
_CONTAINMENT_SELFTEST_STDOUT = b"OMIV containment stdout self-test\n"
_CONTAINMENT_SELFTEST_STDERR = b"OMIV containment stderr self-test\n"
_CONTAINMENT_MECHANISM = "LINUX_USER_PID_MOUNT_NAMESPACE_INIT_PIDFD_V2"
_CONTAINMENT_CONTROL_PROTOCOL = "LENGTH_DELIMITED_JSON_V2"
_CONTAINMENT_CAPTURE_PROTOCOL = "INDEPENDENT_LENGTH_DELIMITED_BINARY_V1"
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_PR_SET_PDEATHSIG = 1
_CLONE_NEWUSER = 0x10000000
_CLONE_NEWPID = 0x20000000
_CLONE_NEWNS = 0x00020000
_MS_REC = 0x4000
_MS_PRIVATE = 0x40000
_MAX_CONTAINED_IDENTITIES = 4096
_PERSISTENT_ENUMERATION_FAILURE = False


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


def load_request(path: Path) -> Any:
    value, _ = load_bounded_json(path, max_bytes=MAX_RUNTIME_COMPAT_REQUEST_BYTES)
    if isinstance(value, dict) and value.get("schema") == (
        "omiv.controlled-runtime-compatibility-request.v1"
    ):
        from omiv.runtime_compatibility.controlled_operations import (
            load_controlled_request_value,
        )

        return load_controlled_request_value(value)
    try:
        return RuntimeCompatibilityRequest.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime compatibility request: {exc}") from exc


def load_plan(path: Path) -> Any:
    value, _ = load_bounded_json(path, max_bytes=MAX_RUNTIME_COMPAT_PLAN_BYTES)
    if isinstance(value, dict) and value.get("schema") == (
        "omiv.controlled-runtime-compatibility-plan.v1"
    ):
        from omiv.runtime_compatibility.controlled_operations import load_controlled_plan_value

        return load_controlled_plan_value(value)
    try:
        return RuntimeCompatibilityPlan.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime compatibility plan: {exc}") from exc


def load_evidence(path: Path) -> Any:
    value, _ = load_bounded_json(path, max_bytes=MAX_RUNTIME_COMPAT_EVIDENCE_BYTES)
    if isinstance(value, dict) and value.get("schema") == (
        "omiv.controlled-runtime-compatibility-evidence.v1"
    ):
        from omiv.runtime_compatibility.controlled_operations import (
            load_controlled_evidence_value,
        )

        return load_controlled_evidence_value(value)
    try:
        return RuntimeCompatibilityEvidence.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid runtime compatibility evidence: {exc}") from exc


def write_plan(plan: Any, output: Path) -> None:
    atomic_write_text(output, _pretty(plan))


def write_evidence(evidence: Any, output: Path) -> None:
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
    except (OSError, ValueError, OmivInputError):
        return LocalFileBinding(
            path=portable_path,
            expected_sha256=expected_sha256,
            availability=FileAvailability.INVALID,
            executable=False if require_executable else None,
            issues=["Local input path is invalid."],
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
    except (OSError, OmivInputError):
        return LocalFileBinding(
            path=portable_path,
            expected_sha256=expected_sha256,
            availability=FileAvailability.INVALID,
            executable=False if require_executable else None,
            issues=["Local input could not be inspected under bounded controls."],
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


def build_plan(request: Any, root: Path) -> Any:
    from omiv.runtime_compatibility.controlled_models import ControlledRequest

    if isinstance(request, ControlledRequest):
        from omiv.runtime_compatibility.controlled_operations import build_controlled_plan

        return build_controlled_plan(request, root)
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


def _child_file_limit(maximum_bytes: int) -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum_bytes, maximum_bytes))


def _prctl(option: int, argument: Any) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = int(libc.prctl(option, argument, 0, 0, 0))
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _unshare(flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if int(libc.unshare(flags)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _mount(source: str | None, target: str, fstype: str | None, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = int(
        libc.mount(
            source.encode() if source is not None else None,
            target.encode(),
            fstype.encode() if fstype is not None else None,
            ctypes.c_ulong(flags),
            None,
        )
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _isolate_mount_namespace_and_proc() -> None:
    """Give the PID-namespace init its own mount namespace and a fresh /proc.

    Runs only in the child that is init (PID 1) of the freshly created PID
    namespace.  Without this, the contained tree keeps the outer mount
    namespace's ``/proc``, which still reflects the outer PID namespace; on GPU
    stacks that stale view breaks CUDA/UVM initialization, and it also leaks
    outer process identities into the contained runtime.

    Order is load-bearing: create the mount namespace, make propagation
    recursively private BEFORE any mount so nothing can propagate back to the
    host/supervisor mount namespace (this covers the privileged no-userns
    fallback, where an unshared mount namespace otherwise inherits shared
    propagation), then mount a fresh procfs that represents the new PID
    namespace.  The verification is decisive: ``/proc/self`` resolves to the
    reader's PID *in the namespace the procfs is tied to*, so the init sees
    ``/proc/self/stat`` report PID 1 only when the mount is the fresh one; a
    stale outer procfs would report the outer PID.  Any failure raises, and the
    caller fails closed before the runtime is released.
    """
    _unshare(_CLONE_NEWNS)
    _mount(None, "/", None, _MS_REC | _MS_PRIVATE)
    _mount("proc", "/proc", "proc", 0)
    try:
        with open("/proc/self/stat", encoding="utf-8") as handle:
            reported_pid = handle.read().split(maxsplit=1)[0]
    except OSError as exc:
        raise OSError(exc.errno or 0, "fresh /proc could not be read after mounting") from exc
    if reported_pid != "1":
        raise RuntimeError("fresh /proc does not represent the contained PID namespace")


def _establish_pid_namespace() -> int:
    """Create an owned PID+mount namespace and return 0 in its init, or its host PID.

    In the init child, user (when available), PID, and mount namespaces plus a
    private fresh /proc are all established before returning 0; any failure
    raises so the trusted bootstrap fails closed before releasing the runtime.
    """
    outer_uid = os.getuid()
    outer_gid = os.getgid()
    try:
        _unshare(_CLONE_NEWUSER)
    except OSError:
        # A privileged RunPod container may forbid nested user namespaces while
        # still granting CAP_SYS_ADMIN for a direct PID namespace.
        _unshare(_CLONE_NEWPID)
    else:
        setgroups = Path("/proc/self/setgroups")
        if setgroups.exists():
            setgroups.write_text("deny", encoding="ascii")
        Path("/proc/self/uid_map").write_text(f"0 {outer_uid} 1\n", encoding="ascii")
        Path("/proc/self/gid_map").write_text(f"0 {outer_gid} 1\n", encoding="ascii")
        _unshare(_CLONE_NEWPID)
    pid = os.fork()
    if pid == 0:
        # Init of the new PID namespace: isolate the mount namespace and mount a
        # private fresh /proc before any runtime bytes are reached.
        _isolate_mount_namespace_and_proc()
    return pid


class _KernelContainment:
    """Stable kernel handles whose target is the init of one owned PID namespace."""

    def __init__(self, init_descriptor: int) -> None:
        self.init_descriptor = init_descriptor
        self.emergency_descriptor = os.dup(init_descriptor)
        self.term_sent = 0
        self.kill_sent = 0
        self.primary_signal_failure = False

    @staticmethod
    def _readable(descriptor: int, timeout: float = 0.0) -> bool:
        return bool(select.select([descriptor], [], [], timeout)[0])

    def empty(self) -> bool:
        # Linux synchronously SIGKILLs every member when namespace PID 1 dies;
        # pidfd readability therefore proves that this namespace can retain no
        # live process, without any /proc enumeration or pathname lookup.
        return self._readable(self.emergency_descriptor)

    def signal(self, signum: signal.Signals, *, emergency: bool = False) -> None:
        if self.primary_signal_failure and not emergency:
            raise OSError("injected kernel whole-tree kill failure")
        descriptor = self.emergency_descriptor if emergency else self.init_descriptor
        try:
            signal.pidfd_send_signal(descriptor, signum)
        except ProcessLookupError:
            return
        if signum == signal.SIGTERM:
            self.term_sent += 1
        elif signum == signal.SIGKILL:
            self.kill_sent += 1

    def wait_empty(self, deadline: float) -> None:
        if self.empty():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self._readable(self.emergency_descriptor, remaining):
            raise RuntimeError("kernel-owned PID namespace did not become empty within bounds")

    def close(self) -> None:
        for descriptor in (self.init_descriptor, self.emergency_descriptor):
            with suppress(OSError):
                os.close(descriptor)


def _require_containment_platform() -> None:
    if not sys.platform.startswith("linux") or not Path("/proc/self/task").is_dir():
        raise OmivInputError("controller-owned descendant containment is unavailable")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise OmivInputError("controller-owned stable process identities are unavailable")
    value = ctypes.c_int()
    try:
        _prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(value))
        descriptor = os.pidfd_open(os.getpid(), 0)
    except OSError as exc:
        raise OmivInputError("controller-owned descendant containment is unavailable") from exc
    os.close(descriptor)


def _send_containment_message(descriptor: int, value: dict[str, Any]) -> None:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > _CONTAINMENT_CONTROL_MAX_BYTES:
        raise RuntimeError("containment protocol message exceeded its bound")
    framed = len(raw).to_bytes(4, "big") + raw
    offset = 0
    while offset < len(framed):
        written = os.write(descriptor, framed[offset:])
        if written <= 0:
            raise RuntimeError("containment protocol message was truncated")
        offset += written


def _read_containment_bytes(descriptor: int, size: int, timeout: float | None) -> bytes:
    raw = bytearray()
    deadline = None if timeout is None else time.monotonic() + timeout
    while len(raw) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                raise TimeoutError("containment protocol response timed out")
        chunk = os.read(descriptor, size - len(raw))
        if not chunk:
            raise RuntimeError("containment protocol message was absent")
        raw.extend(chunk)
    return bytes(raw)


def _receive_containment_message(
    descriptor: int, *, timeout: float | None = None
) -> dict[str, Any]:
    size = int.from_bytes(_read_containment_bytes(descriptor, 4, timeout), "big")
    if size <= 0 or size > _CONTAINMENT_CONTROL_MAX_BYTES:
        raise RuntimeError("containment protocol message was oversized")
    raw = _read_containment_bytes(descriptor, size, timeout)
    try:
        value = json.loads(raw, object_pairs_hook=_containment_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("containment protocol message was malformed") from exc
    if not isinstance(value, dict):
        raise RuntimeError("containment protocol message was malformed")
    return value


def _containment_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("containment protocol message contained a duplicate field")
        value[key] = item
    return value


def _require_containment_fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise RuntimeError("containment protocol message fields were malformed")


def _send_capture_frame(
    descriptor: int,
    *,
    phase: bytes,
    stream: bytes,
    raw: bytes | bytearray,
    maximum: int,
) -> None:
    if phase not in {b"P", b"R"} or stream not in {b"O", b"E"} or len(raw) > maximum:
        raise RuntimeError("containment capture frame was invalid")
    header = _CONTAINMENT_CAPTURE_MAGIC + phase + stream + len(raw).to_bytes(8, "big")
    for block in (header, raw):
        offset = 0
        while offset < len(block):
            written = os.write(descriptor, block[offset:])
            if written <= 0:
                raise RuntimeError("containment capture frame was truncated")
            offset += written


def _receive_capture_frame(
    descriptor: int,
    *,
    phase: bytes,
    stream: bytes,
    maximum: int,
    timeout: float,
) -> bytes:
    header = _read_containment_bytes(descriptor, len(_CONTAINMENT_CAPTURE_MAGIC) + 2 + 8, timeout)
    if (
        header[: len(_CONTAINMENT_CAPTURE_MAGIC)] != _CONTAINMENT_CAPTURE_MAGIC
        or header[len(_CONTAINMENT_CAPTURE_MAGIC) : len(_CONTAINMENT_CAPTURE_MAGIC) + 1] != phase
        or header[len(_CONTAINMENT_CAPTURE_MAGIC) + 1 : len(_CONTAINMENT_CAPTURE_MAGIC) + 2]
        != stream
    ):
        raise RuntimeError("containment capture frame was reordered or malformed")
    declared = int.from_bytes(header[-8:], "big")
    if declared > maximum:
        raise RuntimeError("containment capture declared an oversized payload")
    return _read_containment_bytes(descriptor, declared, timeout)


def _require_containment_eof(descriptor: int, timeout: float) -> None:
    ready = select.select([descriptor], [], [], timeout)[0]
    if not ready:
        raise TimeoutError("containment protocol EOF timed out")
    if os.read(descriptor, 1):
        raise RuntimeError("containment protocol contained trailing data")


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    start_time: int
    descriptor: int


class _SupervisorCollector:
    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self.stream = stream
        self.limit = limit
        self.data = bytearray()
        self.observed_bytes = 0
        self.overflow = False
        self.eof = False
        self.started = False
        self.error = False
        self.thread = threading.Thread(target=self._read, daemon=True)

    def _read(self) -> None:
        try:
            while True:
                chunk = self.stream.read(_READ_CHUNK)
                if not chunk:
                    self.eof = True
                    return
                self.observed_bytes += len(chunk)
                room = self.limit - len(self.data)
                if room > 0:
                    self.data.extend(chunk[:room])
                if len(chunk) > room:
                    self.overflow = True
        except BaseException:
            self.error = True
        finally:
            self.stream.close()

    def start(self) -> None:
        self.thread.start()
        self.started = True

    def finish(self, deadline: float) -> None:
        if not self.started:
            raise RuntimeError("contained stream collector was not started")
        self.thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self.thread.is_alive() or not self.eof or self.error:
            raise RuntimeError("contained stream collector did not reach bounded EOF")


class _SubreaperState:
    def __init__(self, leader: subprocess.Popen[bytes]) -> None:
        self.leader = leader
        self.identities: dict[tuple[int, int], _ProcessIdentity] = {}
        self.reaped: set[tuple[int, int]] = set()
        self.adopted_reaped = 0
        self.term_signaled: set[tuple[int, int]] = set()
        self.kill_signaled: set[tuple[int, int]] = set()
        self.waitable_reaped = 0
        self.force_enumeration_failure = False
        leader_key = self._remember(leader.pid)
        if leader_key is None:
            raise RuntimeError("contained leader identity was unavailable after launch")
        self.leader_key = leader_key

    @staticmethod
    def _stat(pid: int) -> tuple[str, int, int] | None:
        try:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            fields = raw[raw.rfind(")") + 2 :].split()
            return fields[0], int(fields[1]), int(fields[19])
        except (OSError, ValueError, IndexError):
            return None

    @staticmethod
    def _children(pid: int) -> list[int]:
        task_root = Path(f"/proc/{pid}/task")
        try:
            tasks = list(task_root.iterdir())
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise RuntimeError("contained descendant enumeration failed") from exc
        if len(tasks) > _MAX_CONTAINED_IDENTITIES:
            raise RuntimeError("contained task enumeration exceeded its bound")
        children: set[int] = set()
        for task in tasks:
            if not task.name.isdigit():
                continue
            try:
                raw = (task / "children").read_text(encoding="ascii")
                children.update(int(item) for item in raw.split())
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                raise RuntimeError("contained descendant enumeration failed") from exc
            if len(children) > _MAX_CONTAINED_IDENTITIES:
                raise RuntimeError("contained descendant enumeration exceeded its bound")
        return sorted(children)

    def _remember(self, pid: int) -> tuple[int, int] | None:
        observed = self._stat(pid)
        if observed is None:
            return None
        _state, _parent, start_time = observed
        key = (pid, start_time)
        if key in self.identities:
            return key
        if len(self.identities) >= _MAX_CONTAINED_IDENTITIES:
            raise RuntimeError("contained descendant identity count exceeded its bound")
        try:
            descriptor = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            return None
        confirmed = self._stat(pid)
        if confirmed is None or confirmed[2] != start_time:
            os.close(descriptor)
            return None
        self.identities[key] = _ProcessIdentity(pid, start_time, descriptor)
        return key

    def discover(self) -> set[tuple[int, int]]:
        if self.force_enumeration_failure or _PERSISTENT_ENUMERATION_FAILURE:
            raise RuntimeError("contained descendant enumeration failed persistently")
        descendants: set[tuple[int, int]] = set()
        pending = self._children(os.getpid())
        visited: set[int] = set()
        while pending:
            pid = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            if len(visited) > _MAX_CONTAINED_IDENTITIES:
                raise RuntimeError("contained descendant enumeration exceeded its bound")
            key = self._remember(pid)
            if key is not None:
                descendants.add(key)
                pending.extend(self._children(pid))
        return descendants

    def reap(self) -> None:
        while True:
            try:
                info = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                return
            if info is None:
                return
            pid = int(info.si_pid)
            key = self._remember(pid)
            waited_pid, status = os.waitpid(pid, 0)
            if waited_pid != pid:
                raise RuntimeError("contained child reap identity mismatch")
            self.waitable_reaped += 1
            if key is not None:
                self.reaped.add(key)
                if key != self.leader_key:
                    self.adopted_reaped += 1
            elif pid != self.leader.pid:
                self.adopted_reaped += 1
            if pid == self.leader.pid:
                self.reaped.add(self.leader_key)
                self.leader.returncode = os.waitstatus_to_exitcode(status)

    def signal(self, keys: set[tuple[int, int]], signum: signal.Signals) -> None:
        recorded = self.term_signaled if signum == signal.SIGTERM else self.kill_signaled
        for key in keys:
            if key in recorded:
                continue
            identity = self.identities[key]
            try:
                signal.pidfd_send_signal(identity.descriptor, signum)
                recorded.add(key)
            except ProcessLookupError:
                continue

    def close(self) -> None:
        for identity in self.identities.values():
            with suppress(OSError):
                os.close(identity.descriptor)


def _contained_bootstrap_main(
    gate_descriptor: int,
    configuration_descriptor: int,
    namespace_descriptor: int,
) -> None:
    """Trusted gate-held bootstrap; untrusted bytes are reached only after release."""
    try:
        configuration = _receive_containment_message(configuration_descriptor)
        _require_containment_fields(
            configuration,
            {"arguments", "environment", "max_work_file_bytes", "pass_fds"},
        )
        arguments = configuration["arguments"]
        environment = configuration["environment"]
        passed = configuration["pass_fds"]
        maximum = configuration["max_work_file_bytes"]
        if (
            not isinstance(arguments, list)
            or not arguments
            or any(not isinstance(item, str) or not item for item in arguments)
            or not isinstance(environment, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in environment.items()
            )
            or not isinstance(passed, list)
            or any(type(item) is not int or item < 0 for item in passed)
            or type(maximum) is not int
            or maximum <= 0
        ):
            raise RuntimeError("contained bootstrap configuration was malformed")
        os.close(configuration_descriptor)
        namespace_init = _establish_pid_namespace()
        if namespace_init:
            os.close(gate_descriptor)
            _send_containment_message(
                namespace_descriptor,
                {"init_pid": namespace_init, "status": "PID_NAMESPACE_READY"},
            )
            os.close(namespace_descriptor)
            while True:
                try:
                    waited_pid, status = os.waitpid(namespace_init, 0)
                    break
                except InterruptedError:
                    continue
            if waited_pid != namespace_init:
                raise RuntimeError("PID namespace init reap identity mismatch")
            if os.WIFEXITED(status):
                os._exit(os.WEXITSTATUS(status))
            os._exit(128 + os.WTERMSIG(status))
        os.close(namespace_descriptor)
        _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL)
        _child_file_limit(maximum)
        release = os.read(gate_descriptor, 1)
        trailing = os.read(gate_descriptor, 1)
        if release != b"R" or trailing:
            raise RuntimeError("contained bootstrap release gate was malformed")
        os.close(gate_descriptor)
        for descriptor in passed:
            os.set_inheritable(descriptor, True)
        os.execve(arguments[0], arguments, environment)
    except BaseException:
        os._exit(127)


def _spawn_gated_leader(
    arguments: list[str],
    *,
    cwd: str,
    environment: dict[str, str],
    max_work_file_bytes: int,
    pass_fds: tuple[int, ...],
) -> tuple[subprocess.Popen[bytes], int, _KernelContainment]:
    gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
    namespace_read, namespace_write = os.pipe2(os.O_CLOEXEC)
    runtime_environment = environment
    environment = {
        "PYTHONPATH": os.pathsep.join(item for item in sys.path if item),
        "PYTHONUNBUFFERED": "1",
    }
    try:
        with tempfile.TemporaryFile(mode="w+b") as configuration:
            _send_containment_message(
                configuration.fileno(),
                {
                    "arguments": arguments,
                    "environment": runtime_environment,
                    "max_work_file_bytes": max_work_file_bytes,
                    "pass_fds": list(pass_fds),
                },
            )
            configuration.seek(0)
            command = [
                sys.executable,
                "-c",
                (
                    "from omiv.runtime_compatibility.operations import "
                    "_contained_bootstrap_main as m; import sys; "
                    "m(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))"
                ),
                str(gate_read),
                str(configuration.fileno()),
                str(namespace_write),
            ]
            leader = subprocess.Popen(
                command,
                shell=False,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                pass_fds=(gate_read, configuration.fileno(), namespace_write, *pass_fds),
            )
    except BaseException:
        os.close(gate_write)
        os.close(namespace_read)
        raise
    finally:
        os.close(gate_read)
        os.close(namespace_write)
    if leader.stdout is None or leader.stderr is None:
        with suppress(OSError):
            os.close(gate_write)
        os.close(namespace_read)
        leader.kill()
        leader.wait(timeout=2)
        raise RuntimeError("contained leader streams were unavailable")
    containment: _KernelContainment | None = None
    try:
        namespace = _receive_containment_message(namespace_read, timeout=5.0)
        _require_containment_fields(namespace, {"init_pid", "status"})
        init_pid = namespace["init_pid"]
        if (
            namespace["status"] != "PID_NAMESPACE_READY"
            or type(init_pid) is not int
            or init_pid <= 0
        ):
            raise RuntimeError("PID namespace bootstrap report was malformed")
        descriptor = os.pidfd_open(init_pid, 0)
        containment = _KernelContainment(descriptor)
        if containment.empty():
            raise RuntimeError("PID namespace init exited before launch was armed")
        return leader, gate_write, containment
    except BaseException:
        with suppress(OSError):
            os.close(gate_write)
        if containment is not None:
            containment.close()
        with suppress(subprocess.TimeoutExpired):
            leader.wait(timeout=2)
        if leader.returncode is None:
            leader.kill()
            leader.wait(timeout=2)
        raise
    finally:
        os.close(namespace_read)


def _release_contained_leader(gate_descriptor: int) -> None:
    try:
        if os.write(gate_descriptor, b"R") != 1:
            raise RuntimeError("contained bootstrap release was truncated")
    finally:
        os.close(gate_descriptor)


def _emergency_children() -> list[int]:
    if _PERSISTENT_ENUMERATION_FAILURE:
        raise RuntimeError("emergency descendant enumeration failed persistently")
    task_root = Path("/proc/self/task")
    try:
        tasks = list(task_root.iterdir())
    except OSError as exc:
        raise RuntimeError("emergency descendant enumeration failed") from exc
    children: set[int] = set()
    for task in tasks:
        if not task.name.isdigit():
            continue
        try:
            raw = (task / "children").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RuntimeError("emergency descendant enumeration failed") from exc
        try:
            children.update(int(item) for item in raw.split())
        except ValueError as exc:
            raise RuntimeError("emergency descendant enumeration failed") from exc
        if len(children) > _MAX_CONTAINED_IDENTITIES:
            raise RuntimeError("emergency descendant enumeration exceeded its bound")
    return sorted(children)


def _emergency_signal_direct_child(pid: int, signum: signal.Signals) -> None:
    observed = _SubreaperState._stat(pid)
    if observed is None or observed[1] != os.getpid() or observed[0] == "Z":
        return
    start_time = observed[2]
    descriptor = -1
    try:
        descriptor = os.pidfd_open(pid, 0)
        confirmed = _SubreaperState._stat(pid)
        if confirmed is None or confirmed[1] != os.getpid() or confirmed[2] != start_time:
            return
        signal.pidfd_send_signal(descriptor, signum)
    except ProcessLookupError:
        return
    except OSError:
        confirmed = _SubreaperState._stat(pid)
        if confirmed is not None and confirmed[1] == os.getpid() and confirmed[2] == start_time:
            os.kill(pid, signum)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _emergency_reap(leader: subprocess.Popen[bytes]) -> None:
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return
        if pid == leader.pid:
            leader.returncode = os.waitstatus_to_exitcode(status)


def _emergency_signal_known(state: _SubreaperState | None, signum: signal.Signals) -> None:
    if state is None:
        return
    for identity in state.identities.values():
        with suppress(OSError):
            signal.pidfd_send_signal(identity.descriptor, signum)


def _drain_uncollected_stream(stream: IO[bytes], deadline: float) -> None:
    descriptor = stream.fileno()
    os.set_blocking(descriptor, False)
    while time.monotonic() < deadline:
        try:
            chunk = os.read(descriptor, _READ_CHUNK)
        except BlockingIOError:
            select.select([descriptor], [], [], max(0.0, deadline - time.monotonic()))
            continue
        if not chunk:
            stream.close()
            return
    raise RuntimeError("emergency stream drain did not reach bounded EOF")


def _emergency_cleanup(
    leader: subprocess.Popen[bytes],
    containment: _KernelContainment | None,
    state: _SubreaperState | None,
    stdout: _SupervisorCollector | None,
    stderr: _SupervisorCollector | None,
    gate_descriptor: int | None,
) -> None:
    """Independent bounded cleanup used after every partially installed launch."""
    if gate_descriptor is not None:
        with suppress(OSError):
            os.close(gate_descriptor)
    term_deadline = time.monotonic() + 0.25
    if containment is not None and not containment.empty():
        with suppress(OSError):
            containment.signal(signal.SIGTERM, emergency=True)
    _emergency_signal_known(state, signal.SIGTERM)
    if containment is None and state is None:
        with suppress(ProcessLookupError):
            leader.terminate()
    while time.monotonic() < term_deadline:
        _emergency_reap(leader)
        try:
            children = _emergency_children()
        except RuntimeError:
            children = []
        for pid in children:
            _emergency_signal_direct_child(pid, signal.SIGTERM)
        if containment is not None:
            if containment.empty():
                break
        elif not children:
            break
        time.sleep(0.01)
    kill_deadline = time.monotonic() + 3.0
    if containment is not None and not containment.empty():
        with suppress(OSError):
            containment.signal(signal.SIGKILL, emergency=True)
    _emergency_signal_known(state, signal.SIGKILL)
    if containment is None and leader.returncode is None:
        with suppress(ProcessLookupError):
            leader.kill()
    while time.monotonic() < kill_deadline:
        _emergency_reap(leader)
        try:
            children = _emergency_children()
        except RuntimeError:
            children = []
        for pid in children:
            _emergency_signal_direct_child(pid, signal.SIGKILL)
        _emergency_reap(leader)
        if containment is not None:
            if containment.empty() and leader.returncode is not None:
                break
        elif not children and leader.returncode is not None:
            break
        time.sleep(0.01)
    _emergency_reap(leader)
    if containment is not None:
        containment.wait_empty(kill_deadline)
    if leader.returncode is None:
        raise RuntimeError("emergency cleanup did not prove the descendant tree empty")
    eof_deadline = time.monotonic() + 2.0
    for collector, stream in ((stdout, leader.stdout), (stderr, leader.stderr)):
        if stream is None:
            raise RuntimeError("emergency cleanup lacked a process stream")
        if collector is not None and collector.started:
            collector.finish(eof_deadline)
        else:
            _drain_uncollected_stream(stream, eof_deadline)


def _exercise_containment() -> tuple[bytes, bytes]:
    code = (
        "import os,time; "
        f"os.write(1,{_CONTAINMENT_SELFTEST_STDOUT!r}); "
        "pid=os.fork(); "
        "(os.setsid(),os.fork() and os._exit(0),os.write(2,"
        + repr(_CONTAINMENT_SELFTEST_STDERR)
        + "),time.sleep(30)) if pid==0 else time.sleep(30)"
    )
    leader, gate, containment = _spawn_gated_leader(
        [sys.executable, "-c", code],
        cwd="/tmp",
        environment={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"},
        max_work_file_bytes=1024,
        pass_fds=(),
    )
    state: _SubreaperState | None = None
    stdout: _SupervisorCollector | None = None
    stderr: _SupervisorCollector | None = None
    try:
        if leader.stdout is None or leader.stderr is None:
            raise RuntimeError("containment self-test streams were unavailable")
        state = _SubreaperState(leader)
        stdout = _SupervisorCollector(leader.stdout, len(_CONTAINMENT_SELFTEST_STDOUT))
        stderr = _SupervisorCollector(leader.stderr, len(_CONTAINMENT_SELFTEST_STDERR))
        stdout.start()
        stderr.start()
        state.discover()
        _release_contained_leader(gate)
        gate = -1
        discovery_deadline = time.monotonic() + 1.0
        descendants: set[tuple[int, int]] = set()
        while time.monotonic() < discovery_deadline:
            descendants = state.discover()
            if len(descendants) >= 3:
                break
            time.sleep(0.01)
        if len(descendants) < 3:
            raise RuntimeError("containment self-test did not enumerate its descendant")
        state.force_enumeration_failure = True
        termination, _residual = _supervisor_cleanup(state, containment, stdout, stderr, 0.25)
        if (
            termination != "SIGKILL"
            or containment.term_sent != 1
            or containment.kill_sent != 1
            or bytes(stdout.data) != _CONTAINMENT_SELFTEST_STDOUT
            or bytes(stderr.data) != _CONTAINMENT_SELFTEST_STDERR
            or stdout.observed_bytes != len(_CONTAINMENT_SELFTEST_STDOUT)
            or stderr.observed_bytes != len(_CONTAINMENT_SELFTEST_STDERR)
        ):
            raise RuntimeError("containment behavioral self-test was incomplete")
        return bytes(stdout.data), bytes(stderr.data)
    except BaseException:
        _emergency_cleanup(leader, containment, state, stdout, stderr, None if gate < 0 else gate)
        raise
    finally:
        containment.close()
        if state is not None:
            state.close()


def _supervisor_cleanup(
    state: _SubreaperState,
    containment: _KernelContainment,
    stdout: _SupervisorCollector,
    stderr: _SupervisorCollector,
    grace_seconds: float,
) -> tuple[str, bool]:
    state.reap()
    with suppress(RuntimeError):
        state.discover()
    known_extra_members = len(state.identities) > 2
    residual_after_leader = containment.empty() and known_extra_members
    if containment.empty():
        termination = "GRACEFUL"
    else:
        termination = "SIGTERM"
        term_deadline = time.monotonic() + grace_seconds
        containment.signal(signal.SIGTERM)
        while not containment.empty() and time.monotonic() < term_deadline:
            time.sleep(0.01)
            state.reap()
            with suppress(RuntimeError):
                state.discover()
        if containment.empty() and known_extra_members:
            # Terminating namespace PID 1 makes Linux deliver SIGKILL to all
            # remaining members. Record that kernel whole-tree action even
            # though it does not require a second userspace signal syscall.
            termination = "SIGKILL"
            containment.kill_sent += 1
        if not containment.empty():
            termination = "SIGKILL"
            kill_deadline = time.monotonic() + 2.0
            containment.signal(signal.SIGKILL)
            while not containment.empty() and time.monotonic() < kill_deadline:
                time.sleep(0.01)
                state.reap()
                with suppress(RuntimeError):
                    state.discover()
            containment.wait_empty(kill_deadline)
    reap_deadline = time.monotonic() + 2.0
    while state.leader.returncode is None and time.monotonic() < reap_deadline:
        state.reap()
        time.sleep(0.01)
    if state.leader.returncode is None:
        raise RuntimeError("contained bootstrap was not reaped within bounds")
    eof_deadline = time.monotonic() + 2.0
    stdout.finish(eof_deadline)
    stderr.finish(eof_deadline)
    state.reap()
    try:
        remaining = state.discover()
    except RuntimeError:
        remaining = set()
    if remaining:
        raise RuntimeError("controller-owned descendants appeared after bounded cleanup")
    if state.leader.returncode is None or state.leader_key not in state.reaped:
        raise RuntimeError("contained leader was not reaped")
    return termination, residual_after_leader


def _containment_supervisor_main(
    read_descriptor: int,
    write_descriptor: int,
    stdout_descriptor: int,
    stderr_descriptor: int,
    fault: str | None = None,
) -> None:
    global _PERSISTENT_ENUMERATION_FAILURE
    faults = frozenset(item for item in (fault or "").split("+") if item)
    leader: subprocess.Popen[bytes] | None = None
    containment: _KernelContainment | None = None
    gate_descriptor: int | None = None
    state: _SubreaperState | None = None
    stdout_collector: _SupervisorCollector | None = None
    stderr_collector: _SupervisorCollector | None = None
    try:
        value = ctypes.c_int(1)
        _prctl(_PR_SET_CHILD_SUBREAPER, value)
        observed = ctypes.c_int()
        _prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(observed))
        if observed.value != 1:
            raise RuntimeError("subreaper verification failed")
        descriptor = os.pidfd_open(os.getpid(), 0)
        os.close(descriptor)
        if "containment_unavailable" in faults:
            raise RuntimeError("injected kernel containment unavailability")
        probe_stdout, probe_stderr = _exercise_containment()
        _send_containment_message(
            write_descriptor,
            {
                "status": "SELF_TEST_COMPLETE",
                "stdout_bytes": len(probe_stdout),
                "stdout_sha256": hashlib.sha256(probe_stdout).hexdigest(),
                "stderr_bytes": len(probe_stderr),
                "stderr_sha256": hashlib.sha256(probe_stderr).hexdigest(),
            },
        )
        _send_capture_frame(
            stdout_descriptor,
            phase=b"P",
            stream=b"O",
            raw=probe_stdout,
            maximum=len(_CONTAINMENT_SELFTEST_STDOUT),
        )
        _send_capture_frame(
            stderr_descriptor,
            phase=b"P",
            stream=b"E",
            raw=probe_stderr,
            maximum=len(_CONTAINMENT_SELFTEST_STDERR),
        )
        acknowledgement = _receive_containment_message(read_descriptor)
        _require_containment_fields(acknowledgement, {"command"})
        if acknowledgement["command"] != "SELF_TEST_ACK":
            raise RuntimeError("containment self-test acknowledgement was malformed")
        _send_containment_message(
            write_descriptor,
            {
                "behavioral_exercise": True,
                "capture_protocol": _CONTAINMENT_CAPTURE_PROTOCOL,
                "control_protocol": _CONTAINMENT_CONTROL_PROTOCOL,
                "mechanism": _CONTAINMENT_MECHANISM,
                "status": "CONTAINMENT_READY",
            },
        )
        launch = _receive_containment_message(read_descriptor)
        _require_containment_fields(
            launch,
            {
                "arguments",
                "command",
                "cwd",
                "environment",
                "max_stderr_bytes",
                "max_stdout_bytes",
                "max_work_file_bytes",
                "pass_fds",
            },
        )
        if launch["command"] != "LAUNCH":
            raise RuntimeError("containment launch command was malformed")
        max_stdout_bytes = launch["max_stdout_bytes"]
        max_stderr_bytes = launch["max_stderr_bytes"]
        if (
            type(max_stdout_bytes) is not int
            or not 0 <= max_stdout_bytes <= _CONTAINMENT_MAX_STDOUT_BYTES
            or type(max_stderr_bytes) is not int
            or not 0 <= max_stderr_bytes <= _CONTAINMENT_MAX_STDERR_BYTES
        ):
            raise RuntimeError("containment capture limits were malformed")
        leader, gate_descriptor, containment = _spawn_gated_leader(
            launch["arguments"],
            cwd=launch["cwd"],
            environment=launch["environment"],
            max_work_file_bytes=int(launch["max_work_file_bytes"]),
            pass_fds=tuple(int(item) for item in launch["pass_fds"]),
        )
        if "leader_pidfd" in faults:
            raise RuntimeError("injected leader pidfd acquisition failure")
        if leader.stdout is None or leader.stderr is None:
            raise RuntimeError("contained leader streams were unavailable")
        state = _SubreaperState(leader)
        state.discover()
        if "collector_construct" in faults:
            raise RuntimeError("injected collector construction failure")
        stdout_collector = _SupervisorCollector(leader.stdout, max_stdout_bytes)
        stderr_collector = _SupervisorCollector(leader.stderr, max_stderr_bytes)
        stdout_collector.start()
        if "collector_start" in faults:
            raise RuntimeError("injected collector start failure")
        stderr_collector.start()
        _send_containment_message(write_descriptor, {"status": "LAUNCH_ARMED"})
        release = _receive_containment_message(read_descriptor)
        _require_containment_fields(release, {"command"})
        if release["command"] != "RELEASE":
            raise RuntimeError("contained bootstrap release command was malformed")
        _release_contained_leader(gate_descriptor)
        gate_descriptor = None
        if "persistent_enumeration" in faults:
            state.force_enumeration_failure = True
            _PERSISTENT_ENUMERATION_FAILURE = True
        if "stale_containment_handle" in faults:
            os.close(containment.init_descriptor)
            containment.init_descriptor = -1
        if "whole_tree_kill_failure" in faults:
            containment.primary_signal_failure = True
        if faults & {"post_launch_enumeration", "protocol_result"}:
            time.sleep(1.0)
        if "post_launch_enumeration" in faults:
            raise RuntimeError("injected post-launch descendant enumeration failure")
        if "persistent_enumeration" not in faults:
            state.discover()
        if "protocol_result" in faults:
            raise RuntimeError("injected launch-result delivery failure")
        _send_containment_message(write_descriptor, {"status": "LAUNCHED"})
        while True:
            command = _receive_containment_message(read_descriptor)
            state.reap()
            with suppress(RuntimeError):
                state.discover()
            if command.get("command") == "STATUS":
                _require_containment_fields(command, {"command"})
                _send_containment_message(
                    write_descriptor,
                    {
                        "status": "RUNNING",
                        "return_code": state.leader.returncode,
                        "stdout_overflow": stdout_collector.overflow,
                        "stderr_overflow": stderr_collector.overflow,
                    },
                )
                continue
            timed_out = False
            if command.get("command") == "WAIT":
                _require_containment_fields(
                    command, {"command", "grace_seconds", "timeout_seconds"}
                )
                deadline = time.monotonic() + float(command["timeout_seconds"])
                while (
                    state.leader.returncode is None
                    and not stdout_collector.overflow
                    and not stderr_collector.overflow
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                    state.reap()
                    with suppress(RuntimeError):
                        state.discover()
                timed_out = state.leader.returncode is None and not (
                    stdout_collector.overflow or stderr_collector.overflow
                )
            elif command.get("command") == "TERMINATE":
                _require_containment_fields(command, {"command", "grace_seconds"})
            else:
                raise RuntimeError("containment lifecycle command was malformed")
            if "emergency_cleanup" in faults:
                raise RuntimeError("injected primary cleanup failure")
            if "collector_failure" in faults:
                stdout_collector.error = True
            termination, residual_after_leader = _supervisor_cleanup(
                state,
                containment,
                stdout_collector,
                stderr_collector,
                float(command["grace_seconds"]),
            )
            _require_containment_eof(read_descriptor, 1.0)
            stdout_raw = stdout_collector.data
            stderr_raw = stderr_collector.data
            report = {
                "status": "CLEANUP_COMPLETE",
                "mechanism": _CONTAINMENT_MECHANISM,
                "control_protocol": _CONTAINMENT_CONTROL_PROTOCOL,
                "capture_protocol": _CONTAINMENT_CAPTURE_PROTOCOL,
                "atomic_launch_tested": True,
                "preexec_gate": "TRUSTED_BOOTSTRAP_EOF_RELEASE",
                "return_code": state.leader.returncode,
                "timed_out": timed_out,
                "termination": termination,
                "stdout_captured_bytes": len(stdout_raw),
                "stdout_observed_bytes": stdout_collector.observed_bytes,
                "stdout_sha256": hashlib.sha256(stdout_raw).hexdigest(),
                "stderr_captured_bytes": len(stderr_raw),
                "stderr_observed_bytes": stderr_collector.observed_bytes,
                "stderr_sha256": hashlib.sha256(stderr_raw).hexdigest(),
                "stdout_overflow": stdout_collector.overflow,
                "stderr_overflow": stderr_collector.overflow,
                "identities_observed": max(len(state.identities), state.waitable_reaped, 1),
                "waitable_children_reaped": state.waitable_reaped,
                "adopted_children_reaped": state.adopted_reaped,
                "sigterm_sent": containment.term_sent,
                "sigkill_sent": containment.kill_sent,
                "descendants_remaining": 0,
                "streams_eof": stdout_collector.eof and stderr_collector.eof,
                "residual_after_leader": residual_after_leader,
            }
            if "capture_inconsistent" in faults:
                report["stdout_sha256"] = "0" * 64
            if "control_duplicate" in faults:
                raw = b'{"status":"CLEANUP_COMPLETE","status":"CONTAINMENT_FAILED"}'
                framed = len(raw).to_bytes(4, "big") + raw
                os.write(write_descriptor, framed)
                return
            _send_containment_message(write_descriptor, report)
            malformed_capture = faults & {
                "capture_oversized",
                "capture_truncated",
                "capture_reordered",
            }
            if malformed_capture:
                declared = (
                    max_stdout_bytes + 1
                    if "capture_oversized" in faults
                    else len(stdout_raw) + 1
                    if "capture_truncated" in faults
                    else len(stdout_raw)
                )
                stream = b"E" if "capture_reordered" in faults else b"O"
                header = _CONTAINMENT_CAPTURE_MAGIC + b"R" + stream + declared.to_bytes(8, "big")
                os.write(stdout_descriptor, header)
                if "capture_oversized" not in faults:
                    os.write(stdout_descriptor, stdout_raw)
                return
            _send_capture_frame(
                stdout_descriptor,
                phase=b"R",
                stream=b"O",
                raw=stdout_raw,
                maximum=max_stdout_bytes,
            )
            if "capture_trailing" in faults:
                os.write(stdout_descriptor, b"X")
            _send_capture_frame(
                stderr_descriptor,
                phase=b"R",
                stream=b"E",
                raw=stderr_raw,
                maximum=max_stderr_bytes,
            )
            return
    except BaseException as exc:
        cleanup_complete = leader is None
        if leader is not None:
            try:
                _emergency_cleanup(
                    leader,
                    containment,
                    state,
                    stdout_collector,
                    stderr_collector,
                    gate_descriptor,
                )
                cleanup_complete = True
            except BaseException:
                cleanup_complete = False
        with suppress(BaseException):
            _send_containment_message(
                write_descriptor,
                {
                    "descendants_remaining": 0 if cleanup_complete else 1,
                    "emergency_cleanup_complete": cleanup_complete,
                    "reason": type(exc).__name__,
                    "status": "CONTAINMENT_FAILED",
                    "streams_eof": cleanup_complete,
                },
            )
    finally:
        if containment is not None:
            containment.close()
        if state is not None:
            state.close()
        for descriptor in (
            read_descriptor,
            write_descriptor,
            stdout_descriptor,
            stderr_descriptor,
        ):
            with suppress(OSError):
                os.close(descriptor)


@dataclass(frozen=True)
class _ContainmentReport:
    return_code: int
    timed_out: bool
    termination: str
    stdout: bytes
    stderr: bytes
    stdout_overflow: bool
    stderr_overflow: bool
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    observation: dict[str, Any]
    residual_after_leader: bool


class _ContainedProcess:
    def __init__(
        self,
        supervisor: subprocess.Popen[bytes],
        read_descriptor: int,
        write_descriptor: int,
        stdout_descriptor: int,
        stderr_descriptor: int,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> None:
        self.supervisor = supervisor
        self.read_descriptor = read_descriptor
        self.write_descriptor = write_descriptor
        self.stdout_descriptor = stdout_descriptor
        self.stderr_descriptor = stderr_descriptor
        self.max_stdout_bytes = max_stdout_bytes
        self.max_stderr_bytes = max_stderr_bytes
        self.report: _ContainmentReport | None = None

    @classmethod
    def start(
        cls,
        arguments: list[str],
        *,
        cwd: Path,
        environment: dict[str, str],
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        max_work_file_bytes: int,
        pass_fds: tuple[int, ...],
        fault: str | None = None,
    ) -> _ContainedProcess:
        _require_containment_platform()
        if not 0 <= max_stdout_bytes <= _CONTAINMENT_MAX_STDOUT_BYTES or not (
            0 <= max_stderr_bytes <= _CONTAINMENT_MAX_STDERR_BYTES
        ):
            raise OmivInputError("contained process capture limit was unsupported")
        command_read, command_write = os.pipe2(os.O_CLOEXEC)
        response_read, response_write = os.pipe2(os.O_CLOEXEC)
        stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
        stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
        python_path = os.pathsep.join(item for item in sys.path if item)
        supervisor_environment = {
            "PYTHONPATH": python_path,
            "PYTHONUNBUFFERED": "1",
        }
        command = [
            sys.executable,
            "-c",
            (
                "from omiv.runtime_compatibility.operations import "
                "_containment_supervisor_main as m; import sys; "
                "m(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), "
                "int(sys.argv[4]), None if sys.argv[5] == '-' else sys.argv[5])"
            ),
            str(command_read),
            str(response_write),
            str(stdout_write),
            str(stderr_write),
            fault or "-",
        ]
        try:
            supervisor = subprocess.Popen(
                command,
                shell=False,
                env=supervisor_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(
                    command_read,
                    response_write,
                    stdout_write,
                    stderr_write,
                    *pass_fds,
                ),
            )
        except BaseException:
            for descriptor in (
                command_read,
                command_write,
                response_read,
                response_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
            ):
                os.close(descriptor)
            raise
        os.close(command_read)
        os.close(response_write)
        os.close(stdout_write)
        os.close(stderr_write)
        instance = cls(
            supervisor,
            response_read,
            command_write,
            stdout_read,
            stderr_read,
            max_stdout_bytes,
            max_stderr_bytes,
        )
        try:
            self_test = _receive_containment_message(response_read, timeout=5.0)
            _require_containment_fields(
                self_test,
                {
                    "status",
                    "stdout_bytes",
                    "stdout_sha256",
                    "stderr_bytes",
                    "stderr_sha256",
                },
            )
            probe_stdout = _receive_capture_frame(
                stdout_read,
                phase=b"P",
                stream=b"O",
                maximum=len(_CONTAINMENT_SELFTEST_STDOUT),
                timeout=5.0,
            )
            probe_stderr = _receive_capture_frame(
                stderr_read,
                phase=b"P",
                stream=b"E",
                maximum=len(_CONTAINMENT_SELFTEST_STDERR),
                timeout=5.0,
            )
            if (
                self_test["status"] != "SELF_TEST_COMPLETE"
                or probe_stdout != _CONTAINMENT_SELFTEST_STDOUT
                or probe_stderr != _CONTAINMENT_SELFTEST_STDERR
                or self_test["stdout_bytes"] != len(probe_stdout)
                or self_test["stderr_bytes"] != len(probe_stderr)
                or self_test["stdout_sha256"] != hashlib.sha256(probe_stdout).hexdigest()
                or self_test["stderr_sha256"] != hashlib.sha256(probe_stderr).hexdigest()
            ):
                raise RuntimeError("containment behavioral self-test report was incoherent")
            _send_containment_message(command_write, {"command": "SELF_TEST_ACK"})
            ready = _receive_containment_message(response_read, timeout=5.0)
            _require_containment_fields(
                ready,
                {
                    "behavioral_exercise",
                    "capture_protocol",
                    "control_protocol",
                    "mechanism",
                    "status",
                },
            )
            if ready != {
                "behavioral_exercise": True,
                "capture_protocol": _CONTAINMENT_CAPTURE_PROTOCOL,
                "control_protocol": _CONTAINMENT_CONTROL_PROTOCOL,
                "mechanism": _CONTAINMENT_MECHANISM,
                "status": "CONTAINMENT_READY",
            }:
                raise OmivInputError("controller-owned descendant containment setup failed")
            _send_containment_message(
                command_write,
                {
                    "command": "LAUNCH",
                    "arguments": arguments,
                    "cwd": str(cwd),
                    "environment": environment,
                    "max_stdout_bytes": max_stdout_bytes,
                    "max_stderr_bytes": max_stderr_bytes,
                    "max_work_file_bytes": max_work_file_bytes,
                    "pass_fds": list(pass_fds),
                },
            )
            armed = _receive_containment_message(response_read, timeout=5.0)
            _require_containment_fields(armed, {"status"})
            if armed["status"] != "LAUNCH_ARMED":
                raise OmivInputError("contained process launch was not atomically armed")
            _send_containment_message(command_write, {"command": "RELEASE"})
            launched = _receive_containment_message(response_read, timeout=5.0)
            _require_containment_fields(launched, {"status"})
            if launched["status"] != "LAUNCHED":
                raise OmivInputError("contained process launch failed closed")
            return instance
        except BaseException as exc:
            for descriptor in (command_write,):
                with suppress(OSError):
                    os.close(descriptor)
            try:
                supervisor.wait(timeout=8)
            except subprocess.TimeoutExpired as wait_exc:
                raise OmivInputError(
                    "containment supervisor did not complete emergency cleanup within bounds"
                ) from wait_exc
            finally:
                for descriptor in (response_read, stdout_read, stderr_read):
                    with suppress(OSError):
                        os.close(descriptor)
            if supervisor.returncode != 0:
                raise OmivInputError("containment supervisor failed during launch") from exc
            raise OmivInputError("contained process launch failed closed") from exc

    def _abort_protocol(self) -> None:
        with suppress(OSError):
            os.close(self.write_descriptor)
        try:
            self.supervisor.wait(timeout=8)
        except subprocess.TimeoutExpired as exc:
            raise OmivInputError(
                "containment supervisor did not complete emergency cleanup within bounds"
            ) from exc
        finally:
            for descriptor in (
                self.read_descriptor,
                self.stdout_descriptor,
                self.stderr_descriptor,
            ):
                with suppress(OSError):
                    os.close(descriptor)

    def status(self) -> tuple[int | None, bool, bool]:
        try:
            _send_containment_message(self.write_descriptor, {"command": "STATUS"})
            value = _receive_containment_message(self.read_descriptor, timeout=5.0)
            _require_containment_fields(
                value, {"status", "return_code", "stdout_overflow", "stderr_overflow"}
            )
            if (
                value["status"] != "RUNNING"
                or (value["return_code"] is not None and type(value["return_code"]) is not int)
                or type(value["stdout_overflow"]) is not bool
                or (type(value["stderr_overflow"]) is not bool)
            ):
                raise RuntimeError("contained process status was unavailable")
        except (OSError, RuntimeError, TimeoutError) as exc:
            self._abort_protocol()
            raise OmivInputError("contained process status was unavailable") from exc
        return (
            value.get("return_code"),
            bool(value["stdout_overflow"]),
            bool(value["stderr_overflow"]),
        )

    def finish(
        self, *, mode: str, timeout_seconds: float, grace_seconds: float
    ) -> _ContainmentReport:
        if self.report is not None:
            return self.report
        command: dict[str, Any] = {"command": mode, "grace_seconds": grace_seconds}
        if mode == "WAIT":
            command["timeout_seconds"] = timeout_seconds
        try:
            _send_containment_message(self.write_descriptor, command)
        except (OSError, RuntimeError) as exc:
            self._abort_protocol()
            raise OmivInputError("contained process cleanup command was unavailable") from exc
        os.close(self.write_descriptor)
        try:
            value = _receive_containment_message(
                self.read_descriptor, timeout=timeout_seconds + grace_seconds + 5.0
            )
            if value.get("status") == "CONTAINMENT_FAILED":
                _require_containment_fields(
                    value,
                    {
                        "descendants_remaining",
                        "emergency_cleanup_complete",
                        "reason",
                        "status",
                        "streams_eof",
                    },
                )
                raise RuntimeError("containment supervisor reported a lifecycle failure")
            expected_fields = {
                "adopted_children_reaped",
                "atomic_launch_tested",
                "capture_protocol",
                "control_protocol",
                "descendants_remaining",
                "identities_observed",
                "mechanism",
                "preexec_gate",
                "residual_after_leader",
                "return_code",
                "sigkill_sent",
                "sigterm_sent",
                "status",
                "stderr_captured_bytes",
                "stderr_observed_bytes",
                "stderr_overflow",
                "stderr_sha256",
                "stdout_captured_bytes",
                "stdout_observed_bytes",
                "stdout_overflow",
                "stdout_sha256",
                "streams_eof",
                "termination",
                "timed_out",
                "waitable_children_reaped",
            }
            _require_containment_fields(value, expected_fields)
            if value["status"] != "CLEANUP_COMPLETE" or type(value["return_code"]) is not int:
                raise RuntimeError("containment cleanup metadata was incomplete")
            count_fields = (
                "adopted_children_reaped",
                "descendants_remaining",
                "identities_observed",
                "sigkill_sent",
                "sigterm_sent",
                "waitable_children_reaped",
            )
            if any(type(value[field]) is not int for field in count_fields) or not (
                value["mechanism"] == _CONTAINMENT_MECHANISM
                and value["control_protocol"] == _CONTAINMENT_CONTROL_PROTOCOL
                and value["capture_protocol"] == _CONTAINMENT_CAPTURE_PROTOCOL
                and value["atomic_launch_tested"] is True
                and value["preexec_gate"] == "TRUSTED_BOOTSTRAP_EOF_RELEASE"
                and value["descendants_remaining"] == 0
                and value["streams_eof"] is True
                and type(value["timed_out"]) is bool
                and type(value["residual_after_leader"]) is bool
                and value["termination"] in {"GRACEFUL", "SIGTERM", "SIGKILL"}
                and 1 <= value["waitable_children_reaped"] <= value["identities_observed"]
                and 0 <= value["adopted_children_reaped"] < value["waitable_children_reaped"]
                and 0 <= value["sigterm_sent"] <= value["identities_observed"]
                and 0 <= value["sigkill_sent"] <= value["identities_observed"]
            ):
                raise RuntimeError("containment cleanup metadata was incoherent")
            if (
                (
                    value["termination"] == "GRACEFUL"
                    and (value["sigterm_sent"] or value["sigkill_sent"])
                )
                or (
                    value["termination"] == "SIGTERM"
                    and (value["sigterm_sent"] < 1 or value["sigkill_sent"])
                )
                or (value["termination"] == "SIGKILL" and value["sigkill_sent"] < 1)
            ):
                raise RuntimeError("containment termination metadata was incoherent")
            stdout = _receive_capture_frame(
                self.stdout_descriptor,
                phase=b"R",
                stream=b"O",
                maximum=self.max_stdout_bytes,
                timeout=timeout_seconds + grace_seconds + 5.0,
            )
            stderr = _receive_capture_frame(
                self.stderr_descriptor,
                phase=b"R",
                stream=b"E",
                maximum=self.max_stderr_bytes,
                timeout=timeout_seconds + grace_seconds + 5.0,
            )
            self.supervisor.wait(timeout=5)
            if self.supervisor.returncode != 0:
                raise RuntimeError("containment supervisor exited unsuccessfully")
            _require_containment_eof(self.read_descriptor, 1.0)
            _require_containment_eof(self.stdout_descriptor, 1.0)
            _require_containment_eof(self.stderr_descriptor, 1.0)
        except (OSError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as exc:
            with suppress(subprocess.TimeoutExpired):
                self.supervisor.wait(timeout=5)
            raise OmivInputError(
                "controller-owned descendant cleanup report was unavailable"
            ) from exc
        finally:
            for descriptor in (
                self.read_descriptor,
                self.stdout_descriptor,
                self.stderr_descriptor,
            ):
                with suppress(OSError):
                    os.close(descriptor)
        stdout_captured = value["stdout_captured_bytes"]
        stderr_captured = value["stderr_captured_bytes"]
        stdout_observed = value["stdout_observed_bytes"]
        stderr_observed = value["stderr_observed_bytes"]
        integer_values = (
            stdout_captured,
            stderr_captured,
            stdout_observed,
            stderr_observed,
        )
        if any(type(item) is not int or item < 0 for item in integer_values):
            raise OmivInputError("containment capture counts were malformed")
        stdout_overflow = bool(value["stdout_overflow"])
        stderr_overflow = bool(value["stderr_overflow"])
        if (
            type(value["stdout_overflow"]) is not bool
            or type(value["stderr_overflow"]) is not bool
            or stdout_captured != len(stdout)
            or stderr_captured != len(stderr)
            or value["stdout_sha256"] != hashlib.sha256(stdout).hexdigest()
            or value["stderr_sha256"] != hashlib.sha256(stderr).hexdigest()
            or stdout_observed < stdout_captured
            or stderr_observed < stderr_captured
            or stdout_overflow != (stdout_observed > self.max_stdout_bytes)
            or stderr_overflow != (stderr_observed > self.max_stderr_bytes)
            or (stdout_overflow and stdout_captured != self.max_stdout_bytes)
            or (stderr_overflow and stderr_captured != self.max_stderr_bytes)
            or (not stdout_overflow and stdout_observed != stdout_captured)
            or (not stderr_overflow and stderr_observed != stderr_captured)
        ):
            raise OmivInputError("containment capture metadata was incoherent")
        observation = {
            "mechanism": value["mechanism"],
            "established_before_launch": True,
            "stable_identity": "PID_NAMESPACE_INIT_PIDFD",
            "atomic_launch_tested": bool(value["atomic_launch_tested"]),
            "preexec_gate": value["preexec_gate"],
            "control_protocol": value["control_protocol"],
            "capture_protocol": value["capture_protocol"],
            "identities_observed": int(value["identities_observed"]),
            "waitable_children_reaped": int(value["waitable_children_reaped"]),
            "adopted_children_reaped": int(value["adopted_children_reaped"]),
            "sigterm_sent": int(value["sigterm_sent"]),
            "sigkill_sent": int(value["sigkill_sent"]),
            "descendants_remaining": int(value["descendants_remaining"]),
            "streams_eof": bool(value["streams_eof"]),
            "stdout_observed_bytes": stdout_observed,
            "stderr_observed_bytes": stderr_observed,
            "stdout_complete": not stdout_overflow,
            "stderr_complete": not stderr_overflow,
            "cleanup_complete": True,
        }
        self.report = _ContainmentReport(
            return_code=int(value["return_code"]),
            timed_out=bool(value["timed_out"]),
            termination=str(value["termination"]),
            stdout=stdout,
            stderr=stderr,
            stdout_overflow=stdout_overflow,
            stderr_overflow=stderr_overflow,
            stdout_observed_bytes=stdout_observed,
            stderr_observed_bytes=stderr_observed,
            observation=observation,
            residual_after_leader=bool(value["residual_after_leader"]),
        )
        return self.report


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
    pass_fds: tuple[int, ...] = (),
    containment_observation: dict[str, Any] | None = None,
    termination_observation: list[str] | None = None,
) -> ProcessCapture:
    started = time.monotonic()
    process = _ContainedProcess.start(
        actual_arguments,
        cwd=cwd,
        environment=environment,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        max_work_file_bytes=max_work_file_bytes,
        pass_fds=pass_fds,
    )
    report = process.finish(mode="WAIT", timeout_seconds=timeout_seconds, grace_seconds=1.0)
    if containment_observation is not None:
        containment_observation.update(report.observation)
    if termination_observation is not None:
        termination_observation.append(report.termination)
    if report.residual_after_leader:
        raise OmivInputError(
            "runtime descendants remained after the leader completed and were contained"
        )
    duration_ms = max(0, int((time.monotonic() - started) * 1000))
    return ProcessCapture(
        arguments=evidence_arguments,
        environment=evidence_environment,
        return_code=report.return_code,
        timed_out=report.timed_out,
        duration_ms=duration_ms,
        stdout=_bounded_capture(report.stdout, max_stdout_bytes, report.stdout_overflow),
        stderr=_bounded_capture(report.stderr, max_stderr_bytes, report.stderr_overflow),
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
        and artifact.execution_sha256 == artifact.expected_sha256 == artifact.preflight_sha256
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


def execute_plan(plan: Any, root: Path) -> Any:
    from omiv.runtime_compatibility.controlled_models import ControlledPlan

    if isinstance(plan, ControlledPlan):
        from omiv.runtime_compatibility.controlled_operations import execute_controlled_plan

        return execute_controlled_plan(plan, root)
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
                str(executable_path)
                if item == "{runtime_executable}"
                else str(artifact_path)
                if item == "{artifact}"
                else item
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


def concise_plan_summary(plan: Any) -> str:
    from omiv.runtime_compatibility.controlled_models import ControlledPlan

    if isinstance(plan, ControlledPlan):
        from omiv.runtime_compatibility.controlled_operations import concise_controlled_plan

        return concise_controlled_plan(plan)
    executable_present = plan.executable.availability == FileAvailability.AVAILABLE
    artifact_present = plan.artifact.availability == FileAvailability.AVAILABLE
    executable_pinned = (
        executable_present and plan.executable.observed_sha256 == plan.executable.expected_sha256
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


def concise_evidence_summary(evidence: Any) -> str:
    from omiv.runtime_compatibility.controlled_models import ControlledEvidence

    if isinstance(evidence, ControlledEvidence):
        from omiv.runtime_compatibility.controlled_operations import (
            concise_controlled_evidence,
        )

        return concise_controlled_evidence(evidence)
    rows: list[str] = [evidence.profile_name]
    rows.extend(f"{item.stage.value:<10} {item.status.value}" for item in evidence.stages)
    rows.extend(("", f"Runtime compatibility: {evidence.status.value}"))
    return "\n".join(rows)
