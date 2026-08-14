"""Strict models for the candidate Phase 7B runtime compatibility slice."""

from __future__ import annotations

import base64
import hashlib
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.models import StrictModel
from omiv.payload_integrity.paths import validate_portable_path

PROFILE_ID = "omiv.runtime-compatibility-profile.llama-cpp-native-output.v1"
PROFILE_NAME = "llama.cpp"
STAGE_ORDER = ("LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT")
PROFILE_ENVIRONMENT = (
    ("CUDA_VISIBLE_DEVICES", ""),
    ("HIP_VISIBLE_DEVICES", ""),
    ("HOME", "{WORK_DIRECTORY}"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("PATH", "/usr/bin:/bin"),
    ("TMPDIR", "{WORK_DIRECTORY}"),
)


class PlanStatus(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"


class CompatibilityStatus(StrEnum):
    VERIFIED_WITHIN_PROFILE = "VERIFIED_WITHIN_PROFILE"
    NOT_VERIFIED = "NOT_VERIFIED"


class StageName(StrEnum):
    LOAD = "LOAD"
    TOKENIZER = "TOKENIZER"
    PREFILL = "PREFILL"
    DECODE = "DECODE"
    OUTPUT = "OUTPUT"


class StageStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_TESTED = "NOT_TESTED"


class FindingSeverity(StrEnum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class FileAvailability(StrEnum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    INVALID = "INVALID"


class RuntimeCompatibilityLimits(StrictModel):
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    version_timeout_seconds: int = Field(default=5, ge=1, le=30)
    max_stdout_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_stderr_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)
    max_executable_bytes: int = Field(default=1024 * 1024 * 1024, ge=1, le=2**31)
    max_artifact_bytes: int = Field(default=16 * 1024**3, ge=1, le=1024**4)
    max_work_files: int = Field(default=16, ge=0, le=256)
    max_work_file_bytes: int = Field(default=1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_work_total_bytes: int = Field(default=4 * 1024 * 1024, ge=1, le=256 * 1024 * 1024)


class RuntimeTestVector(StrictModel):
    vector_id: str = Field(min_length=3, max_length=96, pattern=r"^[A-Za-z0-9._-]+$")
    prompt: str = Field(min_length=1, max_length=32_768)
    expected_output: str = Field(min_length=1, max_length=1024 * 1024)
    seed: int = Field(default=0, ge=0, le=2**31 - 1)
    max_generated_tokens: int = Field(default=16, ge=1, le=4096)


class RuntimeCompatibilityRequest(StrictModel):
    schema_id: Literal["omiv.runtime-compatibility-request.v1"] = Field(
        default="omiv.runtime-compatibility-request.v1", alias="schema"
    )
    request_id: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    profile_id: Literal["omiv.runtime-compatibility-profile.llama-cpp-native-output.v1"] = (
        "omiv.runtime-compatibility-profile.llama-cpp-native-output.v1"
    )
    executable_path: str
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_runtime_version: str = Field(min_length=1, max_length=512)
    artifact_path: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    test_vector: RuntimeTestVector
    limits: RuntimeCompatibilityLimits = Field(default_factory=RuntimeCompatibilityLimits)

    @model_validator(mode="after")
    def validate_request(self) -> RuntimeCompatibilityRequest:
        validate_portable_path(self.executable_path)
        validate_portable_path(self.artifact_path)
        if self.executable_path == self.artifact_path:
            raise ValueError("runtime executable and artifact paths must differ")
        if len(self.test_vector.expected_output.encode("utf-8")) > self.limits.max_stdout_bytes:
            raise ValueError("expected output exceeds the stdout capture limit")
        return self


class LocalFileBinding(StrictModel):
    path: str
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    availability: FileAvailability
    observed_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size: int | None = Field(default=None, ge=0)
    executable: bool | None = None
    issues: list[str] = Field(max_length=16)

    @model_validator(mode="after")
    def validate_binding(self) -> LocalFileBinding:
        validate_portable_path(self.path)
        if self.availability == FileAvailability.AVAILABLE:
            if self.observed_sha256 is None or self.size is None:
                raise ValueError("available file binding requires size and digest")
        elif self.observed_sha256 is not None or self.size is not None:
            raise ValueError("unavailable file binding cannot claim size or digest")
        return self


class EnvironmentVariable(StrictModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
    value: str = Field(max_length=1024)


class InvocationPlan(StrictModel):
    version_arguments: list[str] = Field(min_length=1, max_length=16)
    run_arguments: list[str] = Field(min_length=1, max_length=64)
    environment: list[EnvironmentVariable] = Field(min_length=1, max_length=16)
    working_directory: Literal["FRESH_EMPTY_TEMPORARY_DIRECTORY"] = (
        "FRESH_EMPTY_TEMPORARY_DIRECTORY"
    )
    shell: Literal[False] = False
    accelerator: Literal["CPU_ONLY"] = "CPU_ONLY"
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_invocation(self) -> InvocationPlan:
        if len({item.name for item in self.environment}) != len(self.environment):
            raise ValueError("invocation environment names must be unique")
        if any(
            "\x00" in argument or len(argument) > 32_768
            for argument in (*self.version_arguments, *self.run_arguments)
        ):
            raise ValueError("invocation arguments must be bounded and cannot contain NUL")
        body = self.model_dump(mode="json", exclude={"command_digest"})
        if self.command_digest != canonical_sha256({"invocation": body}):
            raise ValueError("invocation command identity mismatch")
        return self


def build_profile_invocation(request: RuntimeCompatibilityRequest) -> InvocationPlan:
    """Build the one bounded native argument array supported by this profile."""
    body: dict[str, Any] = {
        "version_arguments": ["{runtime_executable}", "--version"],
        "run_arguments": [
            "{runtime_executable}",
            "--model",
            "{artifact}",
            "--prompt",
            request.test_vector.prompt,
            "--seed",
            str(request.test_vector.seed),
            "--temp",
            "0",
            "--n-predict",
            str(request.test_vector.max_generated_tokens),
            "--gpu-layers",
            "0",
            "--simple-io",
            "--no-display-prompt",
        ],
        "environment": [
            EnvironmentVariable(name=name, value=value).model_dump(mode="json")
            for name, value in PROFILE_ENVIRONMENT
        ],
        "working_directory": "FRESH_EMPTY_TEMPORARY_DIRECTORY",
        "shell": False,
        "accelerator": "CPU_ONLY",
    }
    return InvocationPlan.model_validate(
        {**body, "command_digest": canonical_sha256({"invocation": body})}
    )


class RuntimeCostSummary(StrictModel):
    network: Literal[False] = False
    download: Literal[False] = False
    compilation: Literal[False] = False
    conversion: Literal[False] = False
    runtime_execution: Literal[True] = True
    gpu: Literal[False] = False


class RuntimeCompatibilityPlan(StrictModel):
    schema_id: Literal["omiv.runtime-compatibility-plan.v1"] = Field(
        default="omiv.runtime-compatibility-plan.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    request: RuntimeCompatibilityRequest
    status: PlanStatus
    profile_name: Literal["llama.cpp"] = "llama.cpp"
    executable: LocalFileBinding
    artifact: LocalFileBinding
    invocation: InvocationPlan
    available: list[str] = Field(max_length=16)
    missing: list[str] = Field(max_length=16)
    expected_work: list[str] = Field(max_length=16)
    costs: RuntimeCostSummary
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_identity_and_status(self) -> RuntimeCompatibilityPlan:
        body = self.model_dump(mode="json", by_alias=True, exclude={"plan_id", "plan_digest"})
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if self.plan_digest != digest or self.plan_id != f"runtime_compat_plan_{digest[:32]}":
            raise ValueError("runtime compatibility plan canonical identity mismatch")
        ready = (
            self.executable.availability == FileAvailability.AVAILABLE
            and self.artifact.availability == FileAvailability.AVAILABLE
            and self.executable.observed_sha256 == self.executable.expected_sha256
            and self.artifact.observed_sha256 == self.artifact.expected_sha256
            and self.executable.executable is True
            and not self.executable.issues
            and not self.artifact.issues
        )
        if (self.status == PlanStatus.READY) != ready:
            raise ValueError("runtime compatibility plan status does not match local bindings")
        if (
            self.executable.path != self.request.executable_path
            or self.executable.expected_sha256 != self.request.executable_sha256
            or self.artifact.path != self.request.artifact_path
            or self.artifact.expected_sha256 != self.request.artifact_sha256
        ):
            raise ValueError("runtime compatibility plan bindings do not match its request")
        if self.invocation != build_profile_invocation(self.request):
            raise ValueError("runtime compatibility plan invocation does not match its profile")
        expected_available = [
            label
            for label, binding in (
                ("runtime executable", self.executable),
                ("artifact", self.artifact),
            )
            if binding.availability == FileAvailability.AVAILABLE
        ]
        expected_missing = [
            f"{label}: {issue}"
            for label, binding in (
                ("runtime executable", self.executable),
                ("artifact", self.artifact),
            )
            for issue in binding.issues
        ]
        if self.available != expected_available or self.missing != expected_missing:
            raise ValueError("runtime compatibility plan availability summary is incoherent")
        return self


class BoundedCapture(StrictModel):
    encoding: Literal["BASE64"] = "BASE64"
    captured_base64: str
    captured_bytes: int = Field(ge=0)
    limit_bytes: int = Field(ge=1)
    overflow: bool
    captured_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_capture(self) -> BoundedCapture:
        try:
            raw = base64.b64decode(self.captured_base64, validate=True)
        except ValueError as exc:
            raise ValueError("captured stream is not canonical base64") from exc
        if len(raw) != self.captured_bytes or len(raw) > self.limit_bytes:
            raise ValueError("captured stream length is invalid")
        if hashlib.sha256(raw).hexdigest() != self.captured_sha256:
            raise ValueError("captured stream digest mismatch")
        return self


class ProcessCapture(StrictModel):
    arguments: list[str] = Field(min_length=1, max_length=64)
    environment: list[EnvironmentVariable] = Field(min_length=1, max_length=16)
    working_directory: Literal["FRESH_EMPTY_TEMPORARY_DIRECTORY"] = (
        "FRESH_EMPTY_TEMPORARY_DIRECTORY"
    )
    shell: Literal[False] = False
    return_code: int | None = None
    timed_out: bool
    duration_ms: int = Field(ge=0)
    stdout: BoundedCapture
    stderr: BoundedCapture


class WorkFileRecord(StrictModel):
    path: str
    size: int = Field(ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_path(self) -> WorkFileRecord:
        validate_portable_path(self.path)
        return self


class StageResult(StrictModel):
    stage: StageName
    status: StageStatus
    basis: str = Field(min_length=1, max_length=1000)


_UNOBSERVABLE_STAGE_BASIS = {
    StageName.LOAD: (
        "The native CLI observation does not independently establish that the runtime "
        "opened or consumed the pinned artifact."
    ),
    StageName.TOKENIZER: (
        "The native CLI observation does not independently expose tokenizer execution."
    ),
    StageName.PREFILL: (
        "The native CLI observation does not independently expose prefill execution."
    ),
    StageName.DECODE: (
        "The native CLI observation does not independently prove that emitted bytes were "
        "produced by model decoding."
    ),
}


def derive_native_stage_results(
    capture: ProcessCapture | None,
    expected_output: str,
) -> tuple[list[StageResult], list[tuple[str, str]]]:
    """Derive stage results only from the bounded native process observation."""
    if capture is None:
        return (
            [
                StageResult(
                    stage=StageName(stage),
                    status=StageStatus.NOT_TESTED,
                    basis="The native compatibility invocation was not executed.",
                )
                for stage in STAGE_ORDER
            ],
            [],
        )
    issue: tuple[str, str] | None = None
    if capture.timed_out:
        issue = ("NATIVE_EXECUTION_TIMEOUT", "The native compatibility execution timed out.")
    elif capture.stdout.overflow:
        issue = (
            "NATIVE_STDOUT_OVERFLOW",
            "The native compatibility execution exceeded the stdout capture bound.",
        )
    elif capture.stderr.overflow:
        issue = (
            "NATIVE_STDERR_OVERFLOW",
            "The native compatibility execution exceeded the stderr capture bound.",
        )
    elif capture.return_code != 0:
        issue = (
            "NATIVE_EXECUTION_NONZERO",
            f"The native compatibility execution exited with {capture.return_code}.",
        )
    try:
        stdout = base64.b64decode(capture.stdout.captured_base64, validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        stdout = None
        if issue is None:
            issue = (
                "NATIVE_STDOUT_NOT_UTF8",
                "The native compatibility stdout is not valid UTF-8.",
            )
    try:
        base64.b64decode(capture.stderr.captured_base64, validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        if issue is None:
            issue = (
                "NATIVE_STDERR_NOT_UTF8",
                "The native compatibility stderr is not valid UTF-8.",
            )
    if issue is not None:
        return (
            [
                StageResult(
                    stage=StageName(stage),
                    status=StageStatus.UNKNOWN,
                    basis=(
                        "The bounded native process observation was incomplete or invalid: "
                        f"{issue[1]}"
                    ),
                )
                for stage in STAGE_ORDER
            ],
            [issue],
        )
    if stdout != expected_output:
        return (
            [
                *[
                    StageResult(
                        stage=stage,
                        status=StageStatus.UNKNOWN,
                        basis=basis,
                    )
                    for stage, basis in _UNOBSERVABLE_STAGE_BASIS.items()
                ],
                StageResult(
                    stage=StageName.OUTPUT,
                    status=StageStatus.FAIL,
                    basis="Native stdout did not exactly match the supplied expected output.",
                ),
            ],
            [
                (
                    "EXPECTED_OUTPUT_MISMATCH",
                    "Native stdout did not exactly match the supplied test-vector output.",
                )
            ],
        )
    return (
        [
            *[
                StageResult(stage=stage, status=StageStatus.UNKNOWN, basis=basis)
                for stage, basis in _UNOBSERVABLE_STAGE_BASIS.items()
            ],
            StageResult(
                stage=StageName.OUTPUT,
                status=StageStatus.PASS,
                basis="Native stdout exactly matched the supplied expected output bytes.",
            ),
        ],
        [],
    )


class RuntimeCompatibilityFinding(StrictModel):
    code: str = Field(min_length=1, max_length=200)
    severity: FindingSeverity
    detail: str = Field(min_length=1, max_length=1000)


class ExecutionFileBinding(StrictModel):
    path: str
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preflight_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    execution_size: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_path(self) -> ExecutionFileBinding:
        validate_portable_path(self.path)
        if (self.execution_sha256 is None) != (self.execution_size is None):
            raise ValueError("execution file binding requires digest and size together")
        return self


class RuntimeIdentityEvidence(ExecutionFileBinding):
    expected_version: str = Field(min_length=1, max_length=512)
    observed_version: str | None = Field(default=None, max_length=512)
    identity_verified: bool

    @model_validator(mode="after")
    def validate_identity_state(self) -> RuntimeIdentityEvidence:
        verified = (
            self.execution_sha256 == self.expected_sha256 == self.preflight_sha256
            and self.observed_version == self.expected_version
        )
        if self.identity_verified != verified:
            raise ValueError("runtime identity verification state mismatch")
        return self


class RuntimeCompatibilityEvidence(StrictModel):
    schema_id: Literal["omiv.runtime-compatibility-evidence.v1"] = Field(
        default="omiv.runtime-compatibility-evidence.v1", alias="schema"
    )
    evidence_id: str
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_notice: Literal["PHASE_7B_CANDIDATE_PHASE_7_UNFROZEN"] = (
        "PHASE_7B_CANDIDATE_PHASE_7_UNFROZEN"
    )
    plan: RuntimeCompatibilityPlan
    request_id: str
    plan_id: str
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_id: Literal["omiv.runtime-compatibility-profile.llama-cpp-native-output.v1"]
    profile_name: Literal["llama.cpp"]
    status: CompatibilityStatus
    artifact: ExecutionFileBinding
    runtime: RuntimeIdentityEvidence
    invocation: InvocationPlan
    test_vector: RuntimeTestVector
    test_vector_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    limits: RuntimeCompatibilityLimits
    version_execution: ProcessCapture | None
    compatibility_execution: ProcessCapture | None
    work_files: list[WorkFileRecord] = Field(max_length=256)
    stages: list[StageResult] = Field(min_length=5, max_length=5)
    findings: list[RuntimeCompatibilityFinding] = Field(max_length=256)
    unknowns: list[str] = Field(max_length=32)
    limitations: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_evidence(self) -> RuntimeCompatibilityEvidence:
        body = self.model_dump(
            mode="json", by_alias=True, exclude={"evidence_id", "evidence_digest"}
        )
        digest = canonical_sha256({"domain": self.schema_id, "body": body})
        if (
            self.evidence_digest != digest
            or self.evidence_id != f"runtime_compat_evidence_{digest[:32]}"
        ):
            raise ValueError("runtime compatibility evidence canonical identity mismatch")
        if self.plan.status != PlanStatus.READY:
            raise ValueError("runtime compatibility evidence must embed an executable plan")
        if self.plan_id != self.plan.plan_id or self.plan_digest != self.plan.plan_digest:
            raise ValueError("runtime compatibility evidence plan identity mismatch")
        if self.request_id != self.plan.request.request_id:
            raise ValueError("runtime compatibility evidence request identity mismatch")
        if (
            self.profile_id != self.plan.request.profile_id
            or self.profile_name != self.plan.profile_name
        ):
            raise ValueError("runtime compatibility evidence profile mismatch")
        if self.invocation != self.plan.invocation:
            raise ValueError("runtime compatibility evidence invocation mismatch")
        if self.test_vector != self.plan.request.test_vector:
            raise ValueError("runtime compatibility evidence test vector mismatch")
        if self.limits != self.plan.request.limits:
            raise ValueError("runtime compatibility evidence limits mismatch")
        if (
            self.artifact.path != self.plan.artifact.path
            or self.artifact.expected_sha256 != self.plan.artifact.expected_sha256
            or self.artifact.preflight_sha256 != self.plan.artifact.observed_sha256
        ):
            raise ValueError("runtime compatibility evidence artifact binding mismatch")
        if (
            self.runtime.path != self.plan.executable.path
            or self.runtime.expected_sha256 != self.plan.executable.expected_sha256
            or self.runtime.preflight_sha256 != self.plan.executable.observed_sha256
            or self.runtime.expected_version != self.plan.request.expected_runtime_version
        ):
            raise ValueError("runtime compatibility evidence executable binding mismatch")
        if self.test_vector_digest != canonical_sha256(
            {"runtime-test-vector": self.test_vector.model_dump(mode="json")}
        ):
            raise ValueError("runtime test vector digest mismatch")
        if tuple(item.stage.value for item in self.stages) != STAGE_ORDER:
            raise ValueError("runtime evidence must contain every stage exactly once in order")

        def capture_matches(capture: ProcessCapture, arguments: list[str]) -> bool:
            return (
                capture.arguments == arguments
                and capture.environment == self.invocation.environment
                and capture.working_directory == self.invocation.working_directory
                and capture.shell == self.invocation.shell
                and capture.stdout.limit_bytes == self.limits.max_stdout_bytes
                and capture.stderr.limit_bytes == self.limits.max_stderr_bytes
            )

        version_capture_valid = False
        if self.version_execution is not None:
            try:
                observed_version = base64.b64decode(
                    self.version_execution.stdout.captured_base64, validate=True
                ).decode("utf-8").strip()
                base64.b64decode(
                    self.version_execution.stderr.captured_base64, validate=True
                ).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                observed_version = ""
            version_capture_valid = (
                capture_matches(self.version_execution, self.invocation.version_arguments)
                and self.version_execution.return_code == 0
                and not self.version_execution.timed_out
                and not self.version_execution.stdout.overflow
                and not self.version_execution.stderr.overflow
                and observed_version == self.runtime.expected_version
                and observed_version == self.runtime.observed_version
            )
        if self.version_execution is not None and not capture_matches(
            self.version_execution, self.invocation.version_arguments
        ):
            raise ValueError("runtime version capture does not match the canonical plan")
        if self.runtime.identity_verified != version_capture_valid:
            raise ValueError("runtime identity does not match its captured version observation")
        if self.compatibility_execution is not None and not capture_matches(
            self.compatibility_execution, self.invocation.run_arguments
        ):
            raise ValueError("native runtime capture does not match the canonical plan")
        if self.compatibility_execution is not None and not version_capture_valid:
            raise ValueError("native execution lacks a valid pinned version observation")
        derived_stages, derived_issues = derive_native_stage_results(
            self.compatibility_execution, self.test_vector.expected_output
        )
        if self.stages != derived_stages:
            raise ValueError("runtime stages do not match the raw native observation")
        expected_unknowns = [
            f"{item.stage.value} was {item.status.value}; compatibility is not established."
            for item in derived_stages
            if item.status in {StageStatus.UNKNOWN, StageStatus.NOT_TESTED}
        ]
        if self.unknowns != expected_unknowns:
            raise ValueError("runtime unknowns do not match the derived stage results")
        finding_by_code = {item.code: item for item in self.findings}
        for code, detail in derived_issues:
            finding = finding_by_code.get(code)
            if (
                finding is None
                or finding.severity != FindingSeverity.ERROR
                or finding.detail != detail
            ):
                raise ValueError("native observation finding is missing or incoherent")
        if self.compatibility_execution is not None and not derived_issues:
            finding = finding_by_code.get("INTERNAL_STAGES_UNOBSERVABLE")
            if finding is None or finding.severity != FindingSeverity.WARN:
                raise ValueError("unobservable native stages must remain explicit")
        artifact_binding_valid = (
            self.artifact.execution_sha256
            == self.artifact.expected_sha256
            == self.artifact.preflight_sha256
            and self.artifact.execution_size == self.plan.artifact.size
        )
        if not artifact_binding_valid and not any(
            item.code.startswith("ARTIFACT_CHANGED_") and item.severity == FindingSeverity.ERROR
            for item in self.findings
        ):
            raise ValueError("changed artifact binding lacks a fail-closed finding")
        runtime_file_binding_valid = (
            self.runtime.execution_sha256
            == self.runtime.expected_sha256
            == self.runtime.preflight_sha256
            and self.runtime.execution_size == self.plan.executable.size
        )
        if not runtime_file_binding_valid and not any(
            item.code.startswith("RUNTIME_CHANGED_") and item.severity == FindingSeverity.ERROR
            for item in self.findings
        ):
            raise ValueError("changed executable binding lacks a fail-closed finding")
        native_capture_valid = (
            self.compatibility_execution is not None
            and capture_matches(self.compatibility_execution, self.invocation.run_arguments)
            and self.compatibility_execution.return_code == 0
            and not self.compatibility_execution.timed_out
            and not self.compatibility_execution.stdout.overflow
            and not self.compatibility_execution.stderr.overflow
        )
        verified = (
            version_capture_valid
            and native_capture_valid
            and self.runtime.identity_verified
            and artifact_binding_valid
            and runtime_file_binding_valid
            and self.compatibility_execution is not None
            and self.compatibility_execution.return_code == 0
            and not self.compatibility_execution.timed_out
            and not self.compatibility_execution.stdout.overflow
            and not self.compatibility_execution.stderr.overflow
            and all(item.status == StageStatus.PASS for item in self.stages)
            and not any(item.severity == FindingSeverity.ERROR for item in self.findings)
            and not self.unknowns
            and not self.work_files
        )
        if (self.status == CompatibilityStatus.VERIFIED_WITHIN_PROFILE) != verified:
            raise ValueError("runtime compatibility status does not match bounded evidence")
        return self
