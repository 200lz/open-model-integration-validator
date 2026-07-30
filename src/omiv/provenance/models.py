"""Strict, model-independent conversion provenance models."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from omiv.canonical import canonical_sha256

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
REDACTION_MARKER = "[REDACTED]"
SENSITIVE_ARGUMENTS = frozenset(
    {"--token", "--password", "--api-key", "--secret", "--credential", "--auth"}
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Operation(StrEnum):
    CONVERT = "convert"
    QUANTIZE = "quantize"
    EXPORT = "export"
    COMPILE = "compile"
    PACK = "pack"
    MERGE = "merge"
    SHARD = "shard"


class ProvenanceStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class ProvenanceSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ProvenanceResult(StrEnum):
    PASS = "pass"
    PASS_WITH_WARNINGS = "pass_with_warnings"
    FAIL = "fail"


class RevisionKind(StrEnum):
    GIT_COMMIT = "git_commit"
    IMMUTABLE_VERSION = "immutable_version"
    CONTENT_DIGEST = "content_digest"


class ArtifactDigestEvidence(StrEnum):
    DESCRIPTOR_ONLY = "descriptor_only"
    FULL_ARTIFACT = "full_artifact"


def contains_absolute_path(value: str) -> bool:
    """Return whether a canonical string contains an absolute filesystem path."""
    if "\0" in value:
        return True
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        return True
    return bool(re.search(r"(^|[=\s])(?:/[A-Za-z0-9_.-]|[A-Za-z]:[\\/])", value))


def safe_canonical_string(value: str) -> str:
    if contains_absolute_path(value):
        raise ValueError("canonical provenance must not contain absolute paths")
    if "\r" in value or "\n" in value:
        raise ValueError("canonical provenance strings must be single-line")
    return value


class ModelPackIdentity(StrictModel):
    pack_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    pack_version: int = Field(ge=1)
    metadata_sha256: str = Field(pattern=SHA256_PATTERN)


class InterpretationModelPack(ModelPackIdentity):
    pack_schema_version: int = Field(ge=1)


class ArtifactIdentity(StrictModel):
    role: str = Field(min_length=1, max_length=128, pattern=ID_PATTERN)
    artifact_id: str = Field(min_length=1, max_length=512)
    byte_size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    required: bool
    digest_evidence: ArtifactDigestEvidence

    @field_validator("artifact_id")
    @classmethod
    def artifact_id_is_stable(cls, value: str) -> str:
        safe_canonical_string(value)
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("artifact_id must be a basename or stable opaque ID")
        return value


class SourceProvenance(StrictModel):
    format: str = Field(min_length=1, max_length=128)
    inventory_schema: str = Field(min_length=1, max_length=128)
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    model_family: str = Field(min_length=1, max_length=128)
    model_pack: ModelPackIdentity
    repository: str | None = Field(default=None, min_length=1, max_length=1000)
    revision: str | None = Field(default=None, min_length=1, max_length=256)
    artifacts: list[ArtifactIdentity] = Field(min_length=1, max_length=10000)

    @field_validator("format", "inventory_schema", "model_family", "repository", "revision")
    @classmethod
    def safe_strings(cls, value: str | None) -> str | None:
        return None if value is None else safe_canonical_string(value)

    @model_validator(mode="after")
    def unique_artifact_roles(self) -> SourceProvenance:
        roles = [item.role for item in self.artifacts]
        if len(roles) != len(set(roles)):
            raise ValueError("source artifact roles must be unique")
        return self


class MappingIdentity(StrictModel):
    mapping_schema: str = Field(min_length=1, max_length=128)
    mapping_id: str = Field(min_length=1, max_length=128, pattern=ID_PATTERN)
    canonical_sha256: str = Field(pattern=SHA256_PATTERN)


class PolicyIdentity(StrictModel):
    policy_id: str = Field(min_length=1, max_length=128, pattern=ID_PATTERN)
    schema_version: str = Field(min_length=1, max_length=128)
    canonical_sha256: str = Field(pattern=SHA256_PATTERN)


class InterpretationProvenance(StrictModel):
    model_pack: InterpretationModelPack
    mapping: MappingIdentity
    policies: list[PolicyIdentity] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_policies(self) -> InterpretationProvenance:
        ids = [item.policy_id for item in self.policies]
        if len(ids) != len(set(ids)):
            raise ValueError("policy IDs must be unique")
        return self


class ToolIdentity(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    repository: str | None = Field(default=None, min_length=1, max_length=1000)
    revision: str = Field(min_length=1, max_length=256)
    revision_kind: RevisionKind
    entrypoint: str = Field(min_length=1, max_length=512)

    @field_validator("name", "repository", "revision")
    @classmethod
    def safe_strings(cls, value: str | None) -> str | None:
        return None if value is None else safe_canonical_string(value)

    @field_validator("entrypoint")
    @classmethod
    def safe_entrypoint(cls, value: str) -> str:
        safe_canonical_string(value)
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError("tool entrypoint must be a safe relative path")
        return value


class Invocation(StrictModel):
    executable: str = Field(min_length=1, max_length=256)
    arguments: list[str] = Field(max_length=10000)
    working_tree_policy: Literal["require_clean", "allow_dirty", "not_applicable"]
    redacted_arguments: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("executable")
    @classmethod
    def executable_is_name(cls, value: str) -> str:
        safe_canonical_string(value)
        if "/" in value or "\\" in value:
            raise ValueError("canonical executable must be a command name, not a path")
        return value

    @field_validator("arguments")
    @classmethod
    def arguments_are_safe(cls, values: list[str]) -> list[str]:
        for value in values:
            safe_canonical_string(value)
        return values

    @model_validator(mode="after")
    def secrets_are_redacted(self) -> Invocation:
        expected: set[str] = set()
        for index, argument in enumerate(self.arguments):
            name, separator, inline_value = argument.partition("=")
            if name in SENSITIVE_ARGUMENTS:
                expected.add(name)
                if separator and inline_value != REDACTION_MARKER:
                    raise ValueError(f"sensitive argument {name} is not redacted")
                if not separator and (
                    index + 1 >= len(self.arguments)
                    or self.arguments[index + 1] != REDACTION_MARKER
                ):
                    raise ValueError(f"sensitive argument {name} is not redacted")
        if set(self.redacted_arguments) != expected:
            raise ValueError("redacted_arguments does not match sensitive invocation arguments")
        return self


class ProcessResult(StrictModel):
    exit_code: int
    success: bool


class RuntimeIdentity(StrictModel):
    python_version: str | None = Field(default=None, max_length=128)
    package_versions: dict[str, str] = Field(default_factory=dict, max_length=100)


class ToolSourceIdentity(StrictModel):
    clean_worktree: bool | None = None
    repository_head: str | None = Field(default=None, max_length=256)
    source_tree_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)


class ProcessProvenance(StrictModel):
    operation: Operation
    tool: ToolIdentity
    invocation: Invocation
    result: ProcessResult
    declared_outputs: list[str] = Field(min_length=1, max_length=1000)
    runtime: RuntimeIdentity | None = None
    tool_source: ToolSourceIdentity | None = None

    @field_validator("declared_outputs")
    @classmethod
    def output_roles_are_safe(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("declared output roles must be unique")
        if any(not re.fullmatch(ID_PATTERN, value) for value in values):
            raise ValueError("declared output role is invalid")
        return values


class TargetArtifact(StrictModel):
    role: str = Field(min_length=1, max_length=128, pattern=ID_PATTERN)
    artifact_id: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=SHA256_PATTERN)
    byte_size: int = Field(ge=0)
    output_success: bool

    @field_validator("artifact_id")
    @classmethod
    def stable_id(cls, value: str) -> str:
        safe_canonical_string(value)
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("target artifact_id must be a basename or stable opaque ID")
        return value


class TargetProvenance(StrictModel):
    format: str = Field(min_length=1, max_length=128)
    inventory_schema: str = Field(min_length=1, max_length=128)
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    architecture: str | None = Field(default=None, min_length=1, max_length=128)
    artifact_type: str | None = Field(default=None, min_length=1, max_length=128)
    artifacts: list[TargetArtifact] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def coherent(self) -> TargetProvenance:
        if self.architecture is None and self.artifact_type is None:
            raise ValueError("target requires architecture or artifact_type")
        roles = [item.role for item in self.artifacts]
        if len(roles) != len(set(roles)):
            raise ValueError("target artifact roles must be unique")
        return self


class CaptureMetadata(StrictModel):
    tool_name: str = Field(min_length=1, max_length=256)
    omiv_version: str = Field(min_length=1, max_length=128)
    capture_schema_version: Literal[1]
    redaction_count: int = Field(ge=0)
    offline: bool
    payload_access: Literal["descriptor_only", "full_file_hashing"]
    artifact_hashing: Literal["none", "requested_full_sha256"]


class ConversionProvenance(StrictModel):
    provenance_schema: Literal["omiv.conversion-provenance.v1"]
    provenance_id: str = Field(min_length=1, max_length=256, pattern=ID_PATTERN)
    operation: Operation
    source: SourceProvenance
    interpretation: InterpretationProvenance
    process: ProcessProvenance
    target: TargetProvenance
    capture: CaptureMetadata

    @model_validator(mode="after")
    def basic_cross_links(self) -> ConversionProvenance:
        if self.capture.redaction_count != len(self.process.invocation.redacted_arguments):
            raise ValueError("capture redaction_count does not match invocation")
        prohibited_keys = {
            "timestamp",
            "duration",
            "hostname",
            "username",
            "process_id",
            "pid",
            "environment",
        }

        def inspect(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if str(key).lower() in prohibited_keys:
                        raise ValueError(
                            f"canonical provenance contains prohibited field {key!r}"
                        )
                    inspect(child)
            elif isinstance(value, list):
                for child in value:
                    inspect(child)
            elif isinstance(value, str) and contains_absolute_path(value):
                raise ValueError("canonical provenance contains an absolute path")

        inspect(self.model_dump(mode="python"))
        return self


class Integrity(StrictModel):
    canonicalization: Literal["omiv-json-v1"]
    sha256: str = Field(pattern=SHA256_PATTERN)


class ProvenanceEnvelope(StrictModel):
    provenance: ConversionProvenance
    integrity: Integrity


class ProvenanceFinding(StrictModel):
    rule_id: str
    severity: ProvenanceSeverity
    status: ProvenanceStatus
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class ProvenanceSummary(StrictModel):
    pass_count: int = Field(ge=0)
    warn_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)
    source_identity_status: ProvenanceStatus
    source_artifact_status: ProvenanceStatus
    source_inventory_status: ProvenanceStatus
    model_pack_status: ProvenanceStatus
    mapping_status: ProvenanceStatus
    tool_identity_status: ProvenanceStatus
    invocation_status: ProvenanceStatus
    target_artifact_status: ProvenanceStatus
    target_inventory_status: ProvenanceStatus
    exact_lineage_status: ProvenanceStatus


class ProvenanceValidationReport(StrictModel):
    findings: list[ProvenanceFinding]
    summary: ProvenanceSummary

    @property
    def passed(self) -> bool:
        return not any(item.status == ProvenanceStatus.FAIL for item in self.findings)

    @property
    def exact_lineage_status(self) -> ProvenanceStatus:
        return self.summary.exact_lineage_status


class ObservedArtifact(StrictModel):
    artifact_id: str
    byte_size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    full_artifact_digest: bool


class InventoryEvidence(StrictModel):
    """Generic identity extracted by a format adapter from a validated inventory."""

    format: str
    inventory_schema: str
    inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    model_family: str | None = None
    architecture: str | None = None
    repository: str | None = None
    revision: str | None = None
    artifacts: dict[str, ObservedArtifact] = Field(default_factory=dict)


class ProvenanceReportTool(StrictModel):
    name: Literal["open-model-integration-validator"]
    version: str


class ProvenanceReportExecution(StrictModel):
    result: ProvenanceResult
    exit_code: Literal[0, 1]


class ProvenanceReportPayload(StrictModel):
    report_schema: Literal["omiv.conversion-provenance-report.v1"]
    tool: ProvenanceReportTool
    execution: ProvenanceReportExecution
    provenance_sha256: str = Field(pattern=SHA256_PATTERN)
    provenance: ConversionProvenance
    summary: ProvenanceSummary
    findings: list[ProvenanceFinding]
    limitations: list[str]

    @model_validator(mode="after")
    def consistent(self) -> ProvenanceReportPayload:
        expected_ids = [f"PROV-{number:03d}" for number in range(1, 13)]
        if [item.rule_id for item in self.findings] != expected_ids:
            raise ValueError("findings must contain PROV-001 through PROV-012 in order")
        expected_result = (
            ProvenanceResult.FAIL
            if self.summary.fail_count
            else ProvenanceResult.PASS_WITH_WARNINGS
            if self.summary.warn_count
            else ProvenanceResult.PASS
        )
        if self.execution.result != expected_result:
            raise ValueError("report execution result does not match summary")
        if self.execution.exit_code != (1 if expected_result == ProvenanceResult.FAIL else 0):
            raise ValueError("report exit code does not match result")
        if self.provenance_sha256 != canonical_sha256(
            self.provenance.model_dump(mode="json")
        ):
            raise ValueError("report provenance digest does not match provenance")
        statuses = [item.status for item in self.findings]
        if self.summary.pass_count != statuses.count(ProvenanceStatus.PASS):
            raise ValueError("report PASS count does not match findings")
        if self.summary.warn_count != statuses.count(ProvenanceStatus.WARN):
            raise ValueError("report WARN count does not match findings")
        if self.summary.fail_count != statuses.count(ProvenanceStatus.FAIL):
            raise ValueError("report FAIL count does not match findings")
        summary_statuses = (
            self.summary.source_identity_status,
            self.summary.source_artifact_status,
            self.summary.source_inventory_status,
            self.summary.model_pack_status,
            self.summary.mapping_status,
            self.summary.tool_identity_status,
            self.summary.invocation_status,
            self.summary.target_artifact_status,
            self.summary.target_inventory_status,
            self.summary.exact_lineage_status,
        )
        finding_statuses = tuple(
            self.findings[index].status
            for index in (0, 1, 2, 3, 4, 5, 6, 8, 9, 11)
        )
        if summary_statuses != finding_statuses:
            raise ValueError("report summary statuses do not match findings")
        expected_severity = {
            ProvenanceStatus.PASS: ProvenanceSeverity.INFO,
            ProvenanceStatus.WARN: ProvenanceSeverity.WARNING,
            ProvenanceStatus.FAIL: ProvenanceSeverity.ERROR,
        }
        if any(
            item.severity != expected_severity[item.status] for item in self.findings
        ):
            raise ValueError("report finding severity does not match status")
        return self


class ProvenanceReportEnvelope(StrictModel):
    report: ProvenanceReportPayload
    integrity: Integrity
