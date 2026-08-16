"""Strict Phase 7B.3 controlled llama.cpp server profile models."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_portable_path
from omiv.runtime_compatibility.external_operations import (
    _reject_sensitive_text,
)
from omiv.runtime_compatibility.models import (
    BoundedCapture,
    CompatibilityStatus,
    EnvironmentVariable,
    FileAvailability,
    FindingSeverity,
    LocalFileBinding,
    PlanStatus,
    StageName,
    StageResult,
    StageStatus,
)

CONTROLLED_PROFILE_ID = "omiv.runtime-compatibility-profile.llama-cpp-controlled-server.v1"
CONTROLLED_REQUEST_SCHEMA = "omiv.controlled-runtime-compatibility-request.v1"
CONTROLLED_PLAN_SCHEMA = "omiv.controlled-runtime-compatibility-plan.v1"
CONTROLLED_EVIDENCE_SCHEMA = "omiv.controlled-runtime-compatibility-evidence.v1"
CONTROLLED_ENVIRONMENT = (
    ("CUDA_VISIBLE_DEVICES", "0"),
    ("HOME", "{WORK_DIRECTORY}"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("NO_PROXY", "127.0.0.1,localhost"),
    ("PATH", "/usr/bin:/bin"),
    ("TMPDIR", "{WORK_DIRECTORY}"),
)
BOUNDARIES = ("PRE_START", "POST_READY", "POST_PROBES", "POST_SHUTDOWN")
STAGES = ("LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT")
CONTROLLED_TRUST_STATEMENT = (
    "This profile trusts the pinned executable's documented API behavior; it does not "
    "prove a non-malicious runtime or that particular weights mathematically caused an output."
)
CONTROLLED_LIMITATIONS = (
    "Phase 7B.3 is a candidate capability; Phase 7 scope remains unfrozen.",
    "VERIFIED_WITHIN_PROFILE applies only to the exact pinned request, plan, executable, "
    "payload bytes, invocation, device policy, protocol observations, limits, and probes.",
    "No source-to-GGUF, publisher, signer, origin, or inter-artifact cryptographic binding "
    "is established.",
    "No numerical quantization, semantic fidelity, safety, performance, production readiness, "
    "or cross-hardware claim is established.",
    "No Ollama compatibility or tokenizer/config parity with a source repository is established.",
    "A nonfatal TOKENIZER_EOT_EOG_WARNING records the runtime warning but does not establish "
    "or refute tokenizer/config parity.",
    "The profile trusts the pinned executable API; process controls are not proof against a "
    "malicious executable.",
)
CONTROLLED_BINDING_ISSUES = frozenset(
    {
        "Local input path is invalid.",
        "Explicitly supplied local file is missing.",
        "Local input could not be inspected under bounded controls.",
        "Observed SHA-256 does not match the explicitly supplied digest.",
        "Explicitly supplied runtime file is not executable.",
        "A locally observed executable SHA-256 pin is required.",
        "An exact locally observed runtime version is required.",
        "Observed byte size does not match the explicitly supplied size.",
    }
)
_PORT_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])([1-9][0-9]{3,4})(?![A-Za-z0-9])")


def reject_possible_selected_port(value: str) -> None:
    if any(1024 <= int(match.group(1)) <= 65535 for match in _PORT_TOKEN_RE.finditer(value)):
        raise ValueError("controlled retained source contains a possible selected port")


class ArtifactRole(StrEnum):
    MAIN = "MAIN"
    PROJECTOR = "PROJECTOR"
    DFLASH = "DFLASH"
    IMAGE = "IMAGE"
    REFERENCE = "REFERENCE"


class ProbeModality(StrEnum):
    TEXT = "TEXT"
    IMAGE = "IMAGE"


class BackendKind(StrEnum):
    CPU = "CPU"
    CUDA = "CUDA"
    METAL = "METAL"
    OTHER = "OTHER"
    SYNTHETIC = "SYNTHETIC"


class ControlledBackendRequirement(StrictModel):
    backend: BackendKind
    device_count: Literal[1] = 1
    device_index: Literal[0] = 0
    device_name: str = Field(min_length=1, max_length=128)
    main_model_gpu_layers: Literal["ALL", "NONE"]
    projector_offloaded: bool
    dflash_gpu_layers: Literal["ALL", "NONE"]

    @model_validator(mode="after")
    def validate_backend_policy(self) -> ControlledBackendRequirement:
        _reject_sensitive_text(self.device_name, "controlled device name")
        cuda = self.backend == BackendKind.CUDA
        if cuda != (self.main_model_gpu_layers == "ALL"):
            raise ValueError("CUDA policy requires all main-model layers offloaded")
        if cuda != self.projector_offloaded:
            raise ValueError("CUDA policy requires projector offload")
        if cuda != (self.dflash_gpu_layers == "ALL"):
            raise ValueError("CUDA policy requires all DFlash layers offloaded")
        return self


class ControlledLimits(StrictModel):
    startup_timeout_seconds: int = Field(default=5, ge=1, le=120)
    probe_timeout_seconds: int = Field(default=5, ge=1, le=120)
    shutdown_timeout_seconds: int = Field(default=2, ge=1, le=30)
    version_timeout_seconds: int = Field(default=3, ge=1, le=30)
    max_request_bytes: int = Field(default=256 * 1024, ge=256, le=4 * 1024 * 1024)
    max_response_bytes: int = Field(default=256 * 1024, ge=256, le=4 * 1024 * 1024)
    max_stdout_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_stderr_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)
    max_executable_bytes: int = Field(default=1024**3, ge=1, le=2**31)
    max_artifact_bytes: int = Field(default=32 * 1024**3, ge=1, le=1024**4)
    max_work_entries: int = Field(default=16, ge=0, le=256)
    max_work_file_bytes: int = Field(default=1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_work_total_bytes: int = Field(default=4 * 1024 * 1024, ge=1, le=256 * 1024 * 1024)
    max_json_tokens: int = Field(default=8192, ge=16, le=65536)


class ControlledArtifact(StrictModel):
    role: ArtifactRole
    path: str
    size: int = Field(ge=1, le=1024**4)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_path(self) -> ControlledArtifact:
        validate_portable_path(self.path)
        _reject_sensitive_text(self.path, "controlled artifact path")
        return self


class ControlledProbe(StrictModel):
    probe_id: str = Field(min_length=3, max_length=96, pattern=r"^[A-Za-z0-9._-]+$")
    modality: ProbeModality
    prompt: str = Field(min_length=1, max_length=32768)
    expected_content: str = Field(min_length=1, max_length=1024 * 1024)
    image_role: Literal[ArtifactRole.IMAGE] | None = None
    use_dflash: bool
    seed: Literal[0] = 0
    temperature: Literal[0] = 0
    context_size: int = Field(default=2048, ge=128, le=32768)
    max_generated_tokens: int = Field(default=16, ge=1, le=4096)

    @model_validator(mode="after")
    def validate_modality(self) -> ControlledProbe:
        if (self.modality == ProbeModality.IMAGE) != (self.image_role == ArtifactRole.IMAGE):
            raise ValueError("image probes require exactly the fixed IMAGE artifact role")
        return self


def controlled_image_completion_request_bytes(probe: ControlledProbe, image_size: int) -> int:
    """Return the exact canonical request size without allocating the encoded image."""
    prompt = f"[img-0]\n{probe.prompt}"
    body = {
        "prompt": prompt,
        "seed": 0,
        "temperature": 0,
        "n_predict": probe.max_generated_tokens,
        "cache_prompt": False,
        "image_data": [{"data": "", "id": 0}],
    }
    encoded_size = 4 * ((image_size + 2) // 3)
    return len(canonical_json_bytes(body)) + encoded_size


class ControlledRequest(StrictModel):
    schema_id: Literal["omiv.controlled-runtime-compatibility-request.v1"] = Field(
        default="omiv.controlled-runtime-compatibility-request.v1", alias="schema"
    )
    request_id: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    profile_id: Literal["omiv.runtime-compatibility-profile.llama-cpp-controlled-server.v1"] = (
        "omiv.runtime-compatibility-profile.llama-cpp-controlled-server.v1"
    )
    executable_path: str
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    expected_runtime_version: str | None = Field(default=None, min_length=1, max_length=512)
    runtime_commit: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-f]+$")
    backend_requirement: ControlledBackendRequirement
    artifacts: list[ControlledArtifact] = Field(min_length=1, max_length=8)
    probes: list[ControlledProbe] = Field(min_length=1, max_length=16)
    limits: ControlledLimits = Field(default_factory=ControlledLimits)

    @model_validator(mode="after")
    def validate_request(self) -> ControlledRequest:
        validate_portable_path(self.executable_path)
        _reject_sensitive_text(self.executable_path, "controlled executable path")
        roles = [item.role for item in self.artifacts]
        paths = [item.path for item in self.artifacts]
        if len(set(roles)) != len(roles) or len(set(paths)) != len(paths):
            raise ValueError("controlled artifact roles and paths must be unique")
        if ArtifactRole.MAIN not in roles:
            raise ValueError("controlled profile requires one MAIN artifact")
        if self.executable_path in paths:
            raise ValueError("controlled executable and artifacts must differ")
        if any(item.size > self.limits.max_artifact_bytes for item in self.artifacts):
            raise ValueError("artifact declared size exceeds the profile limit")
        if (
            self.expected_runtime_version is not None
            and self.runtime_commit not in self.expected_runtime_version
        ):
            raise ValueError("exact runtime version must contain the requested commit identity")
        probe_ids = [item.probe_id for item in self.probes]
        if len(set(probe_ids)) != len(probe_ids):
            raise ValueError("controlled probe identifiers must be unique")
        if any(item.modality == ProbeModality.IMAGE for item in self.probes) and (
            ArtifactRole.PROJECTOR not in roles or ArtifactRole.IMAGE not in roles
        ):
            raise ValueError("image probes require pinned PROJECTOR and IMAGE artifacts")
        image = next((item for item in self.artifacts if item.role == ArtifactRole.IMAGE), None)
        if image is not None:
            for probe in self.probes:
                if (
                    probe.modality == ProbeModality.IMAGE
                    and controlled_image_completion_request_bytes(probe, image.size)
                    > self.limits.max_request_bytes
                ):
                    raise ValueError(
                        "encoded IMAGE request exceeds the controlled request-body limit"
                    )
        if any(item.use_dflash for item in self.probes) and ArtifactRole.DFLASH not in roles:
            raise ValueError("DFlash probes require a pinned DFLASH artifact")
        for value, label in (
            (self.request_id, "controlled request identifier"),
            (self.expected_runtime_version, "controlled runtime version"),
            *((item.prompt, "controlled probe prompt") for item in self.probes),
            *((item.expected_content, "controlled expected content") for item in self.probes),
            *((item.probe_id, "controlled probe identifier") for item in self.probes),
        ):
            if value is not None:
                _reject_sensitive_text(value, label)
                reject_possible_selected_port(value)
        return self


class ControlledServerInvocation(StrictModel):
    use_dflash: bool
    probe_ids: list[str] = Field(min_length=1, max_length=16)
    arguments: list[str] = Field(min_length=10, max_length=80)


class ControlledInvocation(StrictModel):
    version_arguments: list[str] = Field(min_length=2, max_length=4)
    servers: list[ControlledServerInvocation] = Field(min_length=1, max_length=2)
    environment: list[EnvironmentVariable] = Field(min_length=1, max_length=16)
    working_directory: Literal["FRESH_EMPTY_TEMPORARY_DIRECTORY"] = (
        "FRESH_EMPTY_TEMPORARY_DIRECTORY"
    )
    bind_address: Literal["127.0.0.1"] = "127.0.0.1"
    port: Literal["OMIV_SELECTED_EPHEMERAL_LOOPBACK_PORT"] = "OMIV_SELECTED_EPHEMERAL_LOOPBACK_PORT"
    shell: Literal[False] = False
    stdin: Literal["CLOSED"] = "CLOSED"
    process_group: Literal["NEW_SESSION"] = "NEW_SESSION"
    request_sequence: list[str] = Field(min_length=3, max_length=64)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_identity(self) -> ControlledInvocation:
        if len({item.name for item in self.environment}) != len(self.environment):
            raise ValueError("controlled environment names must be unique")
        body = self.model_dump(mode="json", exclude={"command_digest"})
        if self.command_digest != canonical_sha256({"controlled-invocation": body}):
            raise ValueError("controlled invocation identity mismatch")
        return self


def build_controlled_invocation(request: ControlledRequest) -> ControlledInvocation:
    roles = {item.role: item for item in request.artifacts}
    argv = [
        "{runtime_executable}",
        "--model",
        "{artifact:MAIN}",
    ]
    if ArtifactRole.PROJECTOR in roles:
        argv.extend(["--mmproj", "{artifact:PROJECTOR}"])
    backend = request.backend_requirement
    argv.extend(
        [
            "--gpu-layers",
            "all" if backend.main_model_gpu_layers == "ALL" else "0",
        ]
    )
    if backend.backend == BackendKind.CUDA:
        argv.extend(["--device", f"CUDA{backend.device_index}"])
    if ArtifactRole.PROJECTOR in roles and not backend.projector_offloaded:
        argv.append("--no-mmproj-offload")
    argv.extend(
        [
            "--host",
            "127.0.0.1",
            "--port",
            "{OMIV_SELECTED_PORT}",
            "--ctx-size",
            str(max(item.context_size for item in request.probes)),
            "--parallel",
            "1",
            "--seed",
            "0",
        ]
    )
    servers: list[dict[str, Any]] = []
    sequence: list[str] = []
    for use_dflash in dict.fromkeys(probe.use_dflash for probe in request.probes):
        arguments = list(argv)
        if use_dflash:
            arguments.extend(
                ["--spec-type", "draft-dflash", "--spec-draft-model", "{artifact:DFLASH}"]
            )
            if backend.backend == BackendKind.CUDA:
                arguments.extend(
                    [
                        "--spec-draft-ngl",
                        "all",
                        "--spec-draft-device",
                        f"CUDA{backend.device_index}",
                    ]
                )
        probe_ids = [item.probe_id for item in request.probes if item.use_dflash == use_dflash]
        servers.append({"use_dflash": use_dflash, "probe_ids": probe_ids, "arguments": arguments})
        sequence.append(f"START SERVER [dflash={'on' if use_dflash else 'off'}]")
        sequence.append("GET /health")
        for probe_id in probe_ids:
            sequence.extend([f"POST /tokenize [{probe_id}]", f"POST /completion [{probe_id}]"])
        sequence.append(f"STOP SERVER [dflash={'on' if use_dflash else 'off'}]")
    body: dict[str, Any] = {
        "version_arguments": ["{runtime_executable}", "--version"],
        "servers": servers,
        "environment": [
            EnvironmentVariable(name=name, value=value).model_dump(mode="json")
            for name, value in CONTROLLED_ENVIRONMENT
        ],
        "working_directory": "FRESH_EMPTY_TEMPORARY_DIRECTORY",
        "bind_address": "127.0.0.1",
        "port": "OMIV_SELECTED_EPHEMERAL_LOOPBACK_PORT",
        "shell": False,
        "stdin": "CLOSED",
        "process_group": "NEW_SESSION",
        "request_sequence": sequence,
    }
    return ControlledInvocation.model_validate(
        {**body, "command_digest": canonical_sha256({"controlled-invocation": body})}
    )


class ControlledPlan(StrictModel):
    schema_id: Literal["omiv.controlled-runtime-compatibility-plan.v1"] = Field(
        default="omiv.controlled-runtime-compatibility-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_notice: Literal["PHASE_7B3_CANDIDATE_PHASE_7_UNFROZEN"] = (
        "PHASE_7B3_CANDIDATE_PHASE_7_UNFROZEN"
    )
    request: ControlledRequest
    status: PlanStatus
    executable: LocalFileBinding
    artifacts: list[LocalFileBinding] = Field(min_length=1, max_length=8)
    invocation: ControlledInvocation
    limitations: list[str] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_plan(self) -> ControlledPlan:
        body = self.model_dump(mode="json", by_alias=True, exclude={"plan_id", "plan_digest"})
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.plan_digest != digest or self.plan_id != f"controlled_runtime_plan_{digest[:32]}":
            raise ValueError("controlled plan canonical identity mismatch")
        request_value = self.request.model_dump(mode="json", by_alias=True)
        if self.request_digest != canonical_sha256(
            {"domain": self.request.schema_id, "body": request_value}
        ):
            raise ValueError("controlled request identity mismatch")
        if self.invocation != build_controlled_invocation(self.request):
            raise ValueError("controlled plan invocation is not profile-owned")
        if tuple(self.limitations) != CONTROLLED_LIMITATIONS:
            raise ValueError("controlled plan limitations are not profile-owned")
        issues = [
            *self.executable.issues,
            *(issue for item in self.artifacts for issue in item.issues),
        ]
        for issue in issues:
            if issue not in CONTROLLED_BINDING_ISSUES:
                raise ValueError("controlled plan binding issue is not profile-owned")
            _reject_sensitive_text(issue, "controlled plan binding issue")
        requested = [(item.path, item.sha256) for item in self.request.artifacts]
        bound = [(item.path, item.expected_sha256) for item in self.artifacts]
        if requested != bound or any(
            binding.size is not None and binding.size != declared.size
            for declared, binding in zip(self.request.artifacts, self.artifacts, strict=True)
        ):
            raise ValueError("controlled artifact plan bindings mismatch")
        if self.executable.path != self.request.executable_path or (
            self.request.executable_sha256 is not None
            and self.executable.expected_sha256 != self.request.executable_sha256
        ):
            raise ValueError("controlled executable plan binding mismatch")
        ready = (
            self.request.executable_sha256 is not None
            and self.request.expected_runtime_version is not None
            and self.executable.expected_sha256 == self.request.executable_sha256
            and self.executable.availability == FileAvailability.AVAILABLE
            and self.executable.observed_sha256 == self.request.executable_sha256
            and self.executable.executable is True
            and not self.executable.issues
            and all(
                item.availability == FileAvailability.AVAILABLE
                and item.observed_sha256 == item.expected_sha256
                and not item.issues
                for item in self.artifacts
            )
        )
        if (self.status == PlanStatus.READY) != ready:
            raise ValueError("controlled plan readiness mismatch")
        return self


class RehashBinding(StrictModel):
    role: str = Field(min_length=1, max_length=32)
    path: str
    size: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_path(self) -> RehashBinding:
        validate_portable_path(self.path)
        return self


class RehashBoundary(StrictModel):
    boundary: Literal["PRE_START", "POST_READY", "POST_PROBES", "POST_SHUTDOWN"]
    bindings: list[RehashBinding] = Field(min_length=2, max_length=9)


class HttpExchange(StrictModel):
    method: Literal["GET", "POST"]
    endpoint: Literal["/health", "/tokenize", "/completion"]
    request_headers: list[str] = Field(max_length=4)
    request_body: BoundedCapture
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status_code: int = Field(ge=100, le=599)
    response_content_type: str = Field(max_length=64)
    response_body: BoundedCapture
    response_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_exchange(self) -> HttpExchange:
        request_raw = base64.b64decode(self.request_body.captured_base64, validate=True)
        response_raw = base64.b64decode(self.response_body.captured_base64, validate=True)
        if self.request_digest != hashlib.sha256(request_raw).hexdigest():
            raise ValueError("loopback request identity mismatch")
        if self.response_digest != hashlib.sha256(response_raw).hexdigest():
            raise ValueError("loopback response identity mismatch")
        if self.request_body.overflow or self.response_body.overflow:
            raise ValueError("controlled loopback exchange cannot contain overflow")
        expected_headers = [] if self.method == "GET" else ["Content-Type: application/json"]
        if self.request_headers != expected_headers:
            raise ValueError("loopback headers are not profile-owned")
        if self.method == "GET" and self.request_body.captured_bytes != 0:
            raise ValueError("health request body must be empty")
        if self.method == "POST" and self.request_body.captured_bytes == 0:
            raise ValueError("POST request body must be present")
        return self


class BackendObservation(StrictModel):
    backend: BackendKind
    device_count: Literal[1] = 1
    device_index: Literal[0] = 0
    device_name: str = Field(min_length=1, max_length=128)
    main_model_gpu_layers: Literal["ALL", "NONE"]
    projector_offloaded: bool


class DFlashObservation(StrictModel):
    active: bool
    implementation: Literal["NONE", "draft-dflash"]
    draft_artifact_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    gpu_layers: Literal["ALL", "NONE"]
    draft_tokens: int = Field(ge=0, le=4096)
    accepted_tokens: int = Field(ge=0, le=4096)

    @model_validator(mode="after")
    def validate_counts(self) -> DFlashObservation:
        if self.accepted_tokens > self.draft_tokens:
            raise ValueError("accepted draft tokens cannot exceed generated draft tokens")
        if self.active:
            if self.implementation != "draft-dflash" or self.draft_artifact_sha256 is None:
                raise ValueError("active DFlash facts require implementation and artifact identity")
        elif (
            self.implementation != "NONE"
            or self.draft_artifact_sha256 is not None
            or self.gpu_layers != "NONE"
        ):
            raise ValueError("inactive DFlash facts cannot claim an implementation or artifact")
        return self


class ControlledServerObservation(StrictModel):
    use_dflash: bool
    probe_ids: list[str] = Field(min_length=1, max_length=16)
    readiness: HttpExchange
    process: ControlledProcess


class PrivacyBoundary(StrictModel):
    policy_version: Literal["omiv.external-runtime-privacy.v1"] = "omiv.external-runtime-privacy.v1"
    actual_root_screened: Literal[True] = True
    work_path_screened: Literal[True] = True
    selected_ports_screened: Literal[True] = True


class ProbeObservation(StrictModel):
    probe_id: str
    tokenize: HttpExchange
    completion: HttpExchange
    tokens: list[int] = Field(min_length=1, max_length=4096)
    content: BoundedCapture
    prompt_tokens: int = Field(ge=1, le=4096)
    predicted_tokens: int = Field(ge=1, le=4096)
    prompt_ms: int = Field(ge=0, le=3_600_000)
    predicted_ms: int = Field(ge=0, le=3_600_000)
    finish_reason: Literal["stop", "length"]
    backend: BackendObservation
    dflash: DFlashObservation
    predicate_type: Literal["EXACT_UTF8"] = "EXACT_UTF8"
    predicate_matched: bool


class ControlledFinding(StrictModel):
    code: str = Field(min_length=1, max_length=128)
    severity: FindingSeverity
    blocking: bool
    detail: str = Field(min_length=1, max_length=1000)


class ContainmentObservation(StrictModel):
    mechanism: Literal["LINUX_PID_NAMESPACE_INIT_PIDFD_V1"]
    established_before_launch: Literal[True] = True
    stable_identity: Literal["PID_NAMESPACE_INIT_PIDFD"] = "PID_NAMESPACE_INIT_PIDFD"
    atomic_launch_tested: Literal[True] = True
    preexec_gate: Literal["TRUSTED_BOOTSTRAP_EOF_RELEASE"] = "TRUSTED_BOOTSTRAP_EOF_RELEASE"
    control_protocol: Literal["LENGTH_DELIMITED_JSON_V2"] = "LENGTH_DELIMITED_JSON_V2"
    capture_protocol: Literal["INDEPENDENT_LENGTH_DELIMITED_BINARY_V1"] = (
        "INDEPENDENT_LENGTH_DELIMITED_BINARY_V1"
    )
    identities_observed: int = Field(ge=1, le=4096)
    waitable_children_reaped: int = Field(ge=1, le=4096)
    adopted_children_reaped: int = Field(ge=0, le=4095)
    sigterm_sent: int = Field(ge=0, le=4096)
    sigkill_sent: int = Field(ge=0, le=4096)
    descendants_remaining: Literal[0] = 0
    streams_eof: Literal[True] = True
    stdout_observed_bytes: int = Field(ge=0, le=2**31)
    stderr_observed_bytes: int = Field(ge=0, le=2**31)
    stdout_complete: bool
    stderr_complete: bool
    cleanup_complete: Literal[True] = True

    @model_validator(mode="after")
    def validate_observation(self) -> ContainmentObservation:
        if self.waitable_children_reaped > self.identities_observed:
            raise ValueError("containment reaped more stable identities than it observed")
        if self.adopted_children_reaped >= self.waitable_children_reaped:
            raise ValueError("containment adopted-child reap count excludes the leader")
        if self.sigterm_sent > self.identities_observed:
            raise ValueError("containment SIGTERM count exceeds observed stable identities")
        if self.sigkill_sent > self.identities_observed:
            raise ValueError("containment SIGKILL count exceeds observed stable identities")
        return self


class ControlledProcess(StrictModel):
    arguments: list[str] = Field(min_length=1, max_length=64)
    environment: list[EnvironmentVariable] = Field(min_length=1, max_length=16)
    started: bool
    alive_at_ready: bool
    ended: bool
    return_code: int | None
    startup_timed_out: bool
    probe_timed_out: bool
    termination: Literal["NOT_STARTED", "GRACEFUL", "SIGTERM", "SIGKILL"]
    containment: ContainmentObservation | None = None
    stdout: BoundedCapture
    stderr: BoundedCapture

    @model_validator(mode="after")
    def validate_containment_state(self) -> ControlledProcess:
        if self.termination == "NOT_STARTED":
            if self.containment is not None:
                raise ValueError("a process not started cannot claim containment cleanup")
            return self
        if self.containment is None:
            raise ValueError("a started process requires a complete containment observation")
        if self.termination == "GRACEFUL" and (
            self.containment.sigterm_sent or self.containment.sigkill_sent
        ):
            raise ValueError("graceful termination cannot contain signal observations")
        if self.termination == "SIGTERM" and (
            self.containment.sigterm_sent < 1 or self.containment.sigkill_sent
        ):
            raise ValueError("SIGTERM termination differs from containment observations")
        if self.termination == "SIGKILL" and self.containment.sigkill_sent < 1:
            raise ValueError("SIGKILL termination lacks a containment signal observation")
        if self.containment.stdout_observed_bytes < self.stdout.captured_bytes or (
            self.containment.stderr_observed_bytes < self.stderr.captured_bytes
        ):
            raise ValueError("containment observed fewer bytes than its bounded captures")
        if self.containment.stdout_complete != (not self.stdout.overflow) or (
            self.containment.stderr_complete != (not self.stderr.overflow)
        ):
            raise ValueError("containment stream completeness differs from capture overflow")
        if self.containment.stdout_complete and (
            self.containment.stdout_observed_bytes != self.stdout.captured_bytes
        ):
            raise ValueError("complete stdout observation differs from captured bytes")
        if self.containment.stderr_complete and (
            self.containment.stderr_observed_bytes != self.stderr.captured_bytes
        ):
            raise ValueError("complete stderr observation differs from captured bytes")
        if self.stdout.overflow and self.stdout.captured_bytes != self.stdout.limit_bytes:
            raise ValueError("overflowed stdout did not retain its full bounded prefix")
        if self.stderr.overflow and self.stderr.captured_bytes != self.stderr.limit_bytes:
            raise ValueError("overflowed stderr did not retain its full bounded prefix")
        if self.stdout.overflow and (
            self.containment.stdout_observed_bytes <= self.stdout.limit_bytes
        ):
            raise ValueError("stdout overflow lacks an over-limit observed byte count")
        if self.stderr.overflow and (
            self.containment.stderr_observed_bytes <= self.stderr.limit_bytes
        ):
            raise ValueError("stderr overflow lacks an over-limit observed byte count")
        return self


class WorkBoundary(StrictModel):
    entries: list[str] = Field(max_length=256)
    unexpected: bool
    cleanup_complete: bool

    @model_validator(mode="after")
    def validate_state(self) -> WorkBoundary:
        for path in self.entries:
            validate_portable_path(path)
            _reject_sensitive_text(path, "controlled work path")
        if self.unexpected != bool(self.entries):
            raise ValueError("controlled work boundary mismatch")
        return self


def _bounded_nodes(value: Any, limit: int) -> None:
    count = 0
    stack = [value]
    while stack:
        item = stack.pop()
        count += 1
        if count > limit:
            raise ValueError("controlled JSON value count exceeded its bound")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _json(exchange: HttpExchange, byte_limit: int, node_limit: int) -> dict[str, Any]:
    raw = base64.b64decode(exchange.response_body.captured_base64, validate=True)
    value = parse_bounded_json_bytes(
        raw, source_name="controlled loopback response", max_bytes=byte_limit
    )
    _bounded_nodes(value, node_limit)
    if not isinstance(value, dict):
        raise ValueError("controlled loopback response must be an object")
    return value


def _request_json(exchange: HttpExchange, byte_limit: int, node_limit: int) -> dict[str, Any]:
    raw = base64.b64decode(exchange.request_body.captured_base64, validate=True)
    value = parse_bounded_json_bytes(
        raw, source_name="controlled loopback request", max_bytes=byte_limit
    )
    _bounded_nodes(value, node_limit)
    if not isinstance(value, dict):
        raise ValueError("controlled loopback request must be an object")
    return value


def _image_artifact(request: ControlledRequest) -> ControlledArtifact:
    return next(item for item in request.artifacts if item.role == ArtifactRole.IMAGE)


def _image_prompt(probe: ControlledProbe) -> str:
    return f"[img-0]\n{probe.prompt}" if probe.modality == ProbeModality.IMAGE else probe.prompt


def _validate_image_data(value: Any, request: ControlledRequest) -> None:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise ValueError("image request does not contain one llama-server image_data item")
    if set(value[0]) != {"data", "id"} or value[0]["id"] != 0:
        raise ValueError("image request uses an unsupported llama-server image_data shape")
    data = value[0]["data"]
    if not isinstance(data, str):
        raise ValueError("image request data is not base64 text")
    try:
        raw = base64.b64decode(data, validate=True)
    except ValueError as exc:
        raise ValueError("image request data is not canonical base64") from exc
    artifact = _image_artifact(request)
    if len(raw) != artifact.size or hashlib.sha256(raw).hexdigest() != artifact.sha256:
        raise ValueError("image request bytes differ from the pinned IMAGE artifact")


def validate_observation(
    observation: ProbeObservation,
    probe: ControlledProbe,
    request: ControlledRequest,
) -> None:
    request_limit = request.limits.max_request_bytes
    response_limit = request.limits.max_response_bytes
    node_limit = request.limits.max_json_tokens
    if observation.probe_id != probe.probe_id:
        raise ValueError("probe observation identity mismatch")
    if (
        observation.tokenize.method != "POST"
        or observation.tokenize.endpoint != "/tokenize"
        or observation.tokenize.status_code != 200
        or observation.tokenize.response_content_type != "application/json"
        or observation.completion.method != "POST"
        or observation.completion.endpoint != "/completion"
        or observation.completion.status_code != 200
        or observation.completion.response_content_type != "application/json"
    ):
        raise ValueError("probe loopback method, endpoint, status, or content type is invalid")
    tokenize_request = _request_json(observation.tokenize, request_limit, node_limit)
    expected_tokenize: dict[str, Any] = {"content": _image_prompt(probe)}
    if tokenize_request != expected_tokenize:
        raise ValueError("tokenize request is not the profile-owned probe")
    token_value = _json(observation.tokenize, response_limit, node_limit)
    if set(token_value) != {"tokens"} or token_value["tokens"] != observation.tokens:
        raise ValueError("token projection does not match strict runtime response")
    if any(type(item) is not int or item < 0 or item > 2**31 - 1 for item in observation.tokens):
        raise ValueError("token array contains an invalid token identifier")
    completion_request = _request_json(observation.completion, request_limit, node_limit)
    expected_completion: dict[str, Any] = {
        "prompt": _image_prompt(probe),
        "seed": 0,
        "temperature": 0,
        "n_predict": probe.max_generated_tokens,
        "cache_prompt": False,
    }
    if probe.modality == ProbeModality.IMAGE:
        _validate_image_data(completion_request.get("image_data"), request)
        completion_request = dict(completion_request)
        completion_request.pop("image_data")
    if completion_request != expected_completion:
        raise ValueError("completion request is not the profile-owned probe")
    completion_value = _json(observation.completion, response_limit, node_limit)
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
        raise ValueError("completion response fields are malformed or unknown")
    try:
        backend = BackendObservation.model_validate(completion_value["backend"])
        dflash = DFlashObservation.model_validate(completion_value["dflash"])
    except (TypeError, ValueError) as exc:
        raise ValueError("completion typed runtime facts are invalid") from exc
    content_raw = base64.b64decode(observation.content.captured_base64, validate=True)
    try:
        projected_content = content_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("completion content is not UTF-8") from exc
    projected = {
        "content": projected_content,
        "prompt_tokens": observation.prompt_tokens,
        "predicted_tokens": observation.predicted_tokens,
        "prompt_ms": observation.prompt_ms,
        "predicted_ms": observation.predicted_ms,
        "finish_reason": observation.finish_reason,
        "backend": backend.model_dump(mode="json"),
        "dflash": dflash.model_dump(mode="json"),
    }
    if (
        completion_value != projected
        or observation.backend != backend
        or observation.dflash != dflash
    ):
        raise ValueError("completion projection does not match strict runtime response")
    requirement = request.backend_requirement
    expected_backend = {
        "backend": requirement.backend.value,
        "device_count": requirement.device_count,
        "device_index": requirement.device_index,
        "device_name": requirement.device_name,
        "main_model_gpu_layers": requirement.main_model_gpu_layers,
        "projector_offloaded": requirement.projector_offloaded,
    }
    if backend.model_dump(mode="json") != expected_backend:
        raise ValueError("backend, device, or offload facts differ from the request")
    if observation.prompt_tokens != len(observation.tokens):
        raise ValueError("prefill counter is incoherent with tokenize observation")
    if observation.predicted_tokens > probe.max_generated_tokens:
        raise ValueError("predicted-token count exceeds the requested bound")
    if dflash.active != probe.use_dflash:
        raise ValueError("DFlash activation does not match the profile-owned probe")
    if probe.use_dflash:
        draft = next(item for item in request.artifacts if item.role == ArtifactRole.DFLASH)
        if (
            dflash.implementation != "draft-dflash"
            or dflash.draft_artifact_sha256 != draft.sha256
            or dflash.gpu_layers != requirement.dflash_gpu_layers
        ):
            raise ValueError("DFlash implementation, artifact, or offload binding is incoherent")
        if dflash.draft_tokens <= 0:
            raise ValueError("DFlash probe lacks positive generated draft-token facts")
    elif dflash.draft_tokens != 0 or dflash.accepted_tokens != 0:
        raise ValueError("non-DFlash probe reported draft-token activity")
    if observation.predicate_matched != (projected_content == probe.expected_content):
        raise ValueError("output predicate projection mismatch")
    reject_possible_selected_port(projected_content)


def _require_capture_limit(capture: BoundedCapture, expected: int, label: str) -> None:
    if capture.limit_bytes != expected:
        raise ValueError(f"{label} capture limit differs from the controlled request")


def _server_process_complete(server: ControlledServerObservation) -> bool:
    process = server.process
    return (
        process.started
        and process.alive_at_ready
        and process.ended
        and process.return_code == 0
        and not process.startup_timed_out
        and not process.probe_timed_out
        and not process.stdout.overflow
        and not process.stderr.overflow
        and process.containment is not None
        and process.termination in {"GRACEFUL", "SIGTERM"}
    )


def controlled_decode_complete(
    servers: list[ControlledServerObservation], work: WorkBoundary
) -> bool:
    return (
        bool(servers)
        and all(_server_process_complete(server) for server in servers)
        and work.cleanup_complete
        and not work.unexpected
    )


class ControlledEvidence(StrictModel):
    schema_id: Literal["omiv.controlled-runtime-compatibility-evidence.v1"] = Field(
        default="omiv.controlled-runtime-compatibility-evidence.v1", alias="schema"
    )
    evidence_id: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_notice: Literal["PHASE_7B3_CANDIDATE_PHASE_7_UNFROZEN"] = (
        "PHASE_7B3_CANDIDATE_PHASE_7_UNFROZEN"
    )
    plan: ControlledPlan
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_id: Literal["omiv.runtime-compatibility-profile.llama-cpp-controlled-server.v1"] = (
        "omiv.runtime-compatibility-profile.llama-cpp-controlled-server.v1"
    )
    status: CompatibilityStatus
    version_execution: ControlledProcess
    observed_runtime_version: str | None = Field(default=None, max_length=512)
    rehash_boundaries: list[RehashBoundary] = Field(min_length=4, max_length=4)
    servers: list[ControlledServerObservation] = Field(min_length=1, max_length=2)
    probes: list[ProbeObservation] = Field(max_length=16)
    work_boundary: WorkBoundary
    privacy_boundary: PrivacyBoundary
    stages: list[StageResult] = Field(min_length=5, max_length=5)
    findings: list[ControlledFinding] = Field(max_length=256)
    limitations: list[str] = Field(min_length=1, max_length=32)
    trust_statement: Literal[
        "This profile trusts the pinned executable's documented API behavior; it does not "
        "prove a non-malicious runtime or that particular weights mathematically caused an "
        "output."
    ]

    @model_validator(mode="after")
    def validate_evidence(self) -> ControlledEvidence:
        body = self.model_dump(
            mode="json", by_alias=True, exclude={"evidence_id", "evidence_digest"}
        )
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if (
            self.evidence_digest != digest
            or self.evidence_id != f"controlled_runtime_evidence_{digest[:32]}"
        ):
            raise ValueError("controlled evidence canonical identity mismatch")
        if self.plan.status != PlanStatus.READY:
            raise ValueError("controlled evidence must embed a ready plan")
        if tuple(self.limitations) != CONTROLLED_LIMITATIONS:
            raise ValueError("controlled evidence limitations are not profile-owned")
        if (
            self.request_digest != self.plan.request_digest
            or self.plan_id != self.plan.plan_id
            or self.plan_digest != self.plan.plan_digest
            or self.profile_id != self.plan.request.profile_id
        ):
            raise ValueError("controlled evidence plan/request projection mismatch")
        if self.version_execution.arguments != self.plan.invocation.version_arguments:
            raise ValueError("version arguments differ from the controlled plan")
        if self.version_execution.environment != self.plan.invocation.environment or any(
            item.process.environment != self.plan.invocation.environment for item in self.servers
        ):
            raise ValueError("process environment differs from the controlled plan")
        expected_servers = self.plan.invocation.servers
        if len(self.servers) != len(expected_servers):
            raise ValueError("controlled evidence does not contain every server configuration")
        for observed_server, planned_server in zip(self.servers, expected_servers, strict=True):
            if (
                observed_server.use_dflash != planned_server.use_dflash
                or observed_server.probe_ids != planned_server.probe_ids
                or observed_server.process.arguments != planned_server.arguments
            ):
                raise ValueError("server configuration differs from the controlled plan")
        limits = self.plan.request.limits
        _require_capture_limit(
            self.version_execution.stdout, limits.max_stdout_bytes, "version stdout"
        )
        _require_capture_limit(
            self.version_execution.stderr, limits.max_stderr_bytes, "version stderr"
        )
        version_state = self.version_execution
        if not (
            version_state.started
            and not version_state.alive_at_ready
            and version_state.ended
            and version_state.return_code == 0
            and not version_state.startup_timed_out
            and not version_state.probe_timed_out
            and version_state.termination == "GRACEFUL"
            and version_state.containment is not None
            and not version_state.stdout.overflow
            and not version_state.stderr.overflow
        ):
            raise ValueError("version process state could not be emitted by the controller")
        version_raw = base64.b64decode(version_state.stdout.captured_base64, validate=True)
        try:
            projected_version = version_raw.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("version process stdout is not UTF-8") from exc
        if projected_version != self.observed_runtime_version:
            raise ValueError("observed runtime version differs from captured stdout")
        for server in self.servers:
            process = server.process
            _require_capture_limit(process.stdout, limits.max_stdout_bytes, "server stdout")
            _require_capture_limit(process.stderr, limits.max_stderr_bytes, "server stderr")
            _require_capture_limit(
                server.readiness.request_body, limits.max_request_bytes, "readiness request"
            )
            _require_capture_limit(
                server.readiness.response_body, limits.max_response_bytes, "readiness response"
            )
            if not (
                process.started
                and process.alive_at_ready
                and process.ended
                and process.return_code is not None
                and not process.startup_timed_out
                and not process.probe_timed_out
                and process.containment is not None
                and process.termination != "NOT_STARTED"
            ):
                raise ValueError("server process state could not be emitted by the controller")
        for observation in self.probes:
            _require_capture_limit(
                observation.content, limits.max_response_bytes, "completion content"
            )
            for exchange in (observation.tokenize, observation.completion):
                _require_capture_limit(
                    exchange.request_body, limits.max_request_bytes, "probe request"
                )
                _require_capture_limit(
                    exchange.response_body, limits.max_response_bytes, "probe response"
                )
        if tuple(item.boundary for item in self.rehash_boundaries) != BOUNDARIES:
            raise ValueError("controlled re-hash boundaries are incomplete or reordered")
        expected_bindings = [
            (
                "EXECUTABLE",
                self.plan.executable.path,
                self.plan.executable.expected_sha256,
                self.plan.executable.size,
            ),
            *[
                (request_artifact.role.value, binding.path, binding.expected_sha256, binding.size)
                for request_artifact, binding in zip(
                    self.plan.request.artifacts, self.plan.artifacts, strict=True
                )
            ],
        ]
        for boundary in self.rehash_boundaries:
            actual = [(item.role, item.path, item.sha256, item.size) for item in boundary.bindings]
            if actual != expected_bindings:
                raise ValueError("controlled boundary binding differs from pinned plan bytes")
        ready = True
        for server in self.servers:
            ready_value = _json(
                server.readiness,
                self.plan.request.limits.max_response_bytes,
                self.plan.request.limits.max_json_tokens,
            )
            ready = ready and (
                server.readiness.method == "GET"
                and server.readiness.endpoint == "/health"
                and server.readiness.status_code == 200
                and server.readiness.response_content_type == "application/json"
                and ready_value == {"status": "ok"}
                and server.process.alive_at_ready
            )
        if len(self.probes) != len(self.plan.request.probes):
            raise ValueError("controlled evidence does not contain every mandatory probe")
        for observation, probe in zip(self.probes, self.plan.request.probes, strict=True):
            validate_observation(observation, probe, self.plan.request)
        process_complete = (
            self.observed_runtime_version == self.plan.request.expected_runtime_version
            and all(_server_process_complete(server) for server in self.servers)
        )
        stderr = b"\n".join(
            base64.b64decode(item.process.stderr.captured_base64, validate=True)
            for item in self.servers
        ).lower()
        expected_findings: list[ControlledFinding] = []
        if b"tokenizer eot/eog" in stderr:
            expected_findings.append(
                ControlledFinding(
                    code="TOKENIZER_EOT_EOG_WARNING",
                    severity=FindingSeverity.WARN,
                    blocking=False,
                    detail=(
                        "The pinned runtime emitted its tokenizer EOT/EOG warning. This "
                        "profile records it as nonfatal and makes no tokenizer/config parity "
                        "claim."
                    ),
                )
            )
        if self.findings != expected_findings:
            raise ValueError("controlled findings do not match bounded process observations")
        stream_texts = [
            base64.b64decode(self.version_execution.stdout.captured_base64, validate=True).decode(
                "utf-8"
            ),
            base64.b64decode(self.version_execution.stderr.captured_base64, validate=True).decode(
                "utf-8"
            ),
            *[
                base64.b64decode(item.process.stdout.captured_base64, validate=True).decode("utf-8")
                for item in self.servers
            ],
            *[
                base64.b64decode(item.process.stderr.captured_base64, validate=True).decode("utf-8")
                for item in self.servers
            ],
        ]
        for item in stream_texts:
            reject_possible_selected_port(item)
        retained = [
            self.observed_runtime_version or "",
            *stream_texts,
        ]
        for server in self.servers:
            retained.extend(
                [
                    base64.b64decode(server.process.stdout.captured_base64, validate=True).decode(
                        "utf-8"
                    ),
                    base64.b64decode(server.process.stderr.captured_base64, validate=True).decode(
                        "utf-8"
                    ),
                    base64.b64decode(
                        server.readiness.request_body.captured_base64, validate=True
                    ).decode("utf-8"),
                    base64.b64decode(
                        server.readiness.response_body.captured_base64, validate=True
                    ).decode("utf-8"),
                ]
            )
        for observation in self.probes:
            for exchange in (observation.tokenize, observation.completion):
                retained.extend(
                    [
                        base64.b64decode(
                            exchange.request_body.captured_base64, validate=True
                        ).decode("utf-8"),
                        base64.b64decode(
                            exchange.response_body.captured_base64, validate=True
                        ).decode("utf-8"),
                    ]
                )
        for item in retained:
            try:
                parsed = json.loads(item) if item.startswith(("{", "[")) else item
            except (json.JSONDecodeError, ValueError):
                parsed = item
            pending: list[Any] = [parsed]
            while pending:
                value = pending.pop()
                if isinstance(value, dict):
                    pending.extend(value.keys())
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
                elif isinstance(value, str):
                    for line in value.splitlines() or [""]:
                        _reject_sensitive_text(line, "controlled retained source")
        all_predicates = bool(self.probes) and all(item.predicate_matched for item in self.probes)
        expected_stages = [
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
                status=StageStatus.PASS if self.probes else StageStatus.FAIL,
                basis=(
                    "Every mandatory profile-owned tokenize exchange returned a non-empty "
                    "bounded valid token array."
                ),
            ),
            StageResult(
                stage=StageName.PREFILL,
                status=StageStatus.PASS if self.probes else StageStatus.FAIL,
                basis=(
                    "Every completion reported a positive prompt counter coherent with its "
                    "tokenize response."
                ),
            ),
            StageResult(
                stage=StageName.DECODE,
                status=(
                    StageStatus.PASS
                    if self.probes and controlled_decode_complete(self.servers, self.work_boundary)
                    else StageStatus.FAIL
                ),
                basis=(
                    "Every completion reported positive bounded predicted tokens and a "
                    "supported terminal condition."
                ),
            ),
            StageResult(
                stage=StageName.OUTPUT,
                status=StageStatus.PASS if all_predicates else StageStatus.FAIL,
                basis=(
                    "Profile-owned EXACT_UTF8 predicates matched "
                    f"{sum(item.predicate_matched for item in self.probes)}/"
                    f"{len(self.plan.request.probes)} mandatory probes."
                ),
            ),
        ]
        if self.stages != expected_stages:
            raise ValueError("controlled stage projection is incoherent")
        verified = (
            ready
            and process_complete
            and all(item.status == StageStatus.PASS for item in self.stages)
            and self.work_boundary.cleanup_complete
            and not self.work_boundary.unexpected
            and not any(item.blocking for item in self.findings)
        )
        if (self.status == CompatibilityStatus.VERIFIED_WITHIN_PROFILE) != verified:
            raise ValueError("controlled compatibility verdict is incoherent")
        return self
