"""Strict schemas for remote snapshots and bounded probe evidence."""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import Field, JsonValue, model_validator

from omiv.models import StrictModel

SNAPSHOT_SCHEMA: Final = "omiv.remote-repository-snapshot.v1"
SNAPSHOT_REPORT_SCHEMA: Final = "omiv.remote-snapshot-report.v1"
RANGE_REPORT_SCHEMA: Final = "omiv.remote-range-probe-report.v1"
PREFIX_REPORT_SCHEMA: Final = "omiv.remote-gguf-prefix-report.v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
COMMIT_PATTERN = r"^[0-9a-f]{40,64}$"


class RemoteResult(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class RemoteSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class StorageClass(StrEnum):
    XET = "xet"
    LFS = "lfs"
    GIT = "git"
    UNKNOWN = "unknown"


class RepositoryIdentity(StrictModel):
    repo_id: str = Field(min_length=3, max_length=256)
    repo_type: Literal["model"]
    requested_revision: str = Field(min_length=1, max_length=256)
    resolved_revision: str = Field(pattern=COMMIT_PATTERN)


class RepositoryMetadata(StrictModel):
    private: bool | None = None
    gated: bool | Literal["auto", "manual"] | None = None
    security_status: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$",
    )


class SnapshotSelection(StrictModel):
    path_prefix: str | None = None
    patterns: list[str] = Field(default_factory=list, max_length=64)
    strict_subtree: bool = True


class RemoteFile(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    byte_size: int = Field(ge=0)
    storage: StorageClass
    etag: str | None = Field(default=None, max_length=512)
    oid: str | None = Field(default=None, max_length=256)
    xet_hash: str | None = Field(default=None, max_length=256)
    lfs_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def identifiers_are_not_urls(self) -> RemoteFile:
        for value in (self.etag, self.oid, self.xet_hash):
            if value is not None and (
                "://" in value
                or "?" in value
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise ValueError("remote file identifier contains unsafe URL or control data")
        return self


class SplitCandidate(StrictModel):
    stem: str
    declared_shard_count: int = Field(ge=1)
    observed_ordinals: list[int]
    duplicate_ordinals: list[int]
    missing_ordinals: list[int]
    inconsistent_declared_counts: list[int]
    non_contiguous: bool
    files: list[str]
    complete: bool

    @model_validator(mode="after")
    def consistent(self) -> SplitCandidate:
        expected = list(range(1, self.declared_shard_count + 1))
        calculated_complete = (
            not self.duplicate_ordinals
            and not self.missing_ordinals
            and not self.inconsistent_declared_counts
            and self.observed_ordinals == expected
        )
        if self.complete != calculated_complete:
            raise ValueError("candidate completeness does not match ordinal evidence")
        return self


class SnapshotSummary(StrictModel):
    file_count: int = Field(ge=0)
    total_byte_size: int = Field(ge=0)
    gguf_file_count: int = Field(ge=0)
    candidate_split_sets: list[SplitCandidate]
    extra_gguf_files: list[str]


class RepositorySnapshot(StrictModel):
    snapshot_schema: Literal["omiv.remote-repository-snapshot.v1"]
    provider: Literal["huggingface"]
    repository: RepositoryIdentity
    repository_metadata: RepositoryMetadata
    selection: SnapshotSelection
    files: list[RemoteFile]
    summary: SnapshotSummary

    @model_validator(mode="after")
    def summary_and_order_match(self) -> RepositorySnapshot:
        paths = [item.path for item in self.files]
        if paths != sorted(paths):
            raise ValueError("snapshot files must be sorted by path")
        if len(paths) != len(set(paths)):
            raise ValueError("snapshot contains duplicate paths")
        if self.summary.file_count != len(self.files):
            raise ValueError("snapshot file_count does not match files")
        if self.summary.total_byte_size != sum(item.byte_size for item in self.files):
            raise ValueError("snapshot total_byte_size does not match files")
        if self.summary.gguf_file_count != sum(
            item.path.lower().endswith(".gguf") for item in self.files
        ):
            raise ValueError("snapshot gguf_file_count does not match files")
        return self


class Integrity(StrictModel):
    canonicalization: Literal["omiv-json-v1"]
    sha256: str = Field(pattern=SHA256_PATTERN)


class SnapshotEnvelope(StrictModel):
    snapshot: RepositorySnapshot
    integrity: Integrity


class RemoteFinding(StrictModel):
    rule_id: str
    severity: RemoteSeverity
    status: RemoteResult
    message: str
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


class ReportExecution(StrictModel):
    result: RemoteResult
    exit_code: Literal[0, 1]

    @model_validator(mode="after")
    def consistent(self) -> ReportExecution:
        if self.exit_code != (1 if self.result == RemoteResult.FAIL else 0):
            raise ValueError("report result and exit code disagree")
        return self


class SnapshotReport(StrictModel):
    report_schema: Literal["omiv.remote-snapshot-report.v1"]
    execution: ReportExecution
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    repository: RepositoryIdentity
    selection: SnapshotSelection
    summary: SnapshotSummary
    findings: list[RemoteFinding]
    limitations: list[str]


class ValidatedRange(StrictModel):
    offset: int = Field(ge=0)
    length: int = Field(ge=1)
    end: int = Field(ge=0)

    @model_validator(mode="after")
    def end_matches(self) -> ValidatedRange:
        if self.end != self.offset + self.length - 1:
            raise ValueError("range end does not match offset and length")
        return self


class RangeEvidence(StrictModel):
    path: str
    requested_range: ValidatedRange
    http_status: int
    content_range: str | None
    total_artifact_size: int | None = Field(default=None, ge=0)
    response_byte_count: int = Field(ge=0)
    response_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    etag: str | None = None
    redirect_count: int = Field(ge=0)
    provider: Literal["huggingface"]
    storage: StorageClass
    result: RemoteResult


class RangeProbeReport(StrictModel):
    report_schema: Literal["omiv.remote-range-probe-report.v1"]
    execution: ReportExecution
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    repository: RepositoryIdentity
    evidence: RangeEvidence
    findings: list[RemoteFinding]
    hex_preview: str | None = Field(default=None, pattern=r"^[0-9a-f]{2,32}$")
    limitations: list[str]


class PrefixProbeReport(StrictModel):
    report_schema: Literal["omiv.remote-gguf-prefix-report.v1"]
    execution: ReportExecution
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    repository: RepositoryIdentity
    path: str
    gguf_magic_valid: bool
    version: int | None = Field(default=None, ge=0)
    bounded_range_evidence: RangeEvidence
    findings: list[RemoteFinding]
    claim: Literal["bounded GGUF prefix identity only; no payload claim"]
    limitations: list[str]


class ReportEnvelope(StrictModel):
    report: SnapshotReport | RangeProbeReport | PrefixProbeReport
    integrity: Integrity
