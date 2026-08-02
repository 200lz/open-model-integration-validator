"""Strict, portable Phase 5F artifact-security evidence models."""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.models import StrictModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"
ID_PATTERN = r"^[a-z][a-z0-9_.-]{2,127}$"
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")
MAX_TEXT = 512
MAX_EXCERPT = 256


def _unsafe(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        forbidden = (
            "authorization:",
            "bearer ",
            "github_pat_",
            "ghp_",
            "x-amz-",
            "signature=",
            "key-pair-id=",
            "access_token=",
            "begin private key",
            "begin rsa private key",
            "begin ec private key",
            "begin openssh private key",
            "private seed",
            "secret scalar",
        )
        return (
            value.startswith(("/", "~/", "git@"))
            or "\\" in value
            or "${" in value
            or "$HOME" in value
            or bool(UUID_PATTERN.fullmatch(value))
            or bool(TIMESTAMP_PATTERN.match(value))
            or any(item in lowered for item in forbidden)
            or (value.startswith(("http://", "https://")) and "?" in value)
        )
    if isinstance(value, list):
        return any(_unsafe(item) for item in value)
    if isinstance(value, dict):
        forbidden_fields = {"private_key", "credential", "token", "executable_code"}
        return bool(forbidden_fields.intersection(value)) or any(_unsafe(v) for v in value.values())
    return False


def _unbounded(value: object) -> bool:
    if isinstance(value, str):
        return len(value) > MAX_TEXT
    if isinstance(value, list):
        return any(_unbounded(item) for item in value)
    if isinstance(value, dict):
        return any(_unbounded(item) for item in value.values())
    return False


class SecurityModel(StrictModel):
    """Immutable record rejecting machine-local or credential-bearing values."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    @model_validator(mode="after")
    def portable(self) -> SecurityModel:
        if _unsafe(self.model_dump(mode="json", by_alias=True)):
            raise ValueError(
                "security record contains a local path, UUID, credential, or private material"
            )
        if _unbounded(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("security record contains an unbounded string value")
        return self


class InspectionMethod(StrEnum):
    METADATA_INSPECTION = "METADATA_INSPECTION"
    FORMAT_STRUCTURE_INSPECTION = "FORMAT_STRUCTURE_INSPECTION"
    MANIFEST_INSPECTION = "MANIFEST_INSPECTION"
    FILE_NAME_POLICY_CHECK = "FILE_NAME_POLICY_CHECK"
    FILE_TYPE_POLICY_CHECK = "FILE_TYPE_POLICY_CHECK"
    MAGIC_BYTE_INSPECTION = "MAGIC_BYTE_INSPECTION"
    ARCHIVE_STRUCTURE_INSPECTION = "ARCHIVE_STRUCTURE_INSPECTION"
    STATIC_PATTERN_INSPECTION = "STATIC_PATTERN_INSPECTION"
    SERIALIZATION_FORMAT_INSPECTION = "SERIALIZATION_FORMAT_INSPECTION"
    DEPENDENCY_MANIFEST_INSPECTION = "DEPENDENCY_MANIFEST_INSPECTION"
    SCRIPT_CONTENT_INSPECTION = "SCRIPT_CONTENT_INSPECTION"
    EXECUTABLE_CONTENT_INSPECTION = "EXECUTABLE_CONTENT_INSPECTION"
    BOUNDED_PAYLOAD_INSPECTION = "BOUNDED_PAYLOAD_INSPECTION"
    CONTROLLED_DYNAMIC_ANALYSIS_RESERVED = "CONTROLLED_DYNAMIC_ANALYSIS_RESERVED"


class FindingClassification(StrEnum):
    UNSAFE_SERIALIZATION_FORMAT = "UNSAFE_SERIALIZATION_FORMAT"
    EXECUTABLE_CODE_PRESENT = "EXECUTABLE_CODE_PRESENT"
    SCRIPT_CONTENT_PRESENT = "SCRIPT_CONTENT_PRESENT"
    NATIVE_BINARY_PRESENT = "NATIVE_BINARY_PRESENT"
    UNEXPECTED_FILE_TYPE = "UNEXPECTED_FILE_TYPE"
    UNEXPECTED_ARCHIVE_ENTRY = "UNEXPECTED_ARCHIVE_ENTRY"
    PATH_TRAVERSAL_ENTRY = "PATH_TRAVERSAL_ENTRY"
    SYMLINK_ENTRY = "SYMLINK_ENTRY"
    DEVICE_OR_SPECIAL_FILE = "DEVICE_OR_SPECIAL_FILE"
    EMBEDDED_CREDENTIAL_PATTERN = "EMBEDDED_CREDENTIAL_PATTERN"
    PRIVATE_KEY_MATERIAL_PATTERN = "PRIVATE_KEY_MATERIAL_PATTERN"
    SIGNED_URL_PATTERN = "SIGNED_URL_PATTERN"
    SUSPICIOUS_NETWORK_REFERENCE = "SUSPICIOUS_NETWORK_REFERENCE"
    DYNAMIC_IMPORT_PATTERN = "DYNAMIC_IMPORT_PATTERN"
    SUBPROCESS_EXECUTION_PATTERN = "SUBPROCESS_EXECUTION_PATTERN"
    SHELL_EXECUTION_PATTERN = "SHELL_EXECUTION_PATTERN"
    DESERIALIZATION_EXECUTION_PATTERN = "DESERIALIZATION_EXECUTION_PATTERN"
    INSTALL_OR_BUILD_SCRIPT_PRESENT = "INSTALL_OR_BUILD_SCRIPT_PRESENT"
    DEPENDENCY_MANIFEST_PRESENT = "DEPENDENCY_MANIFEST_PRESENT"
    UNPINNED_DEPENDENCY_REFERENCE = "UNPINNED_DEPENDENCY_REFERENCE"
    REMOTE_CODE_REFERENCE = "REMOTE_CODE_REFERENCE"
    MODEL_CUSTOM_CODE_DECLARATION = "MODEL_CUSTOM_CODE_DECLARATION"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    MALFORMED_CONTAINER = "MALFORMED_CONTAINER"
    OVERLAPPING_PAYLOAD_RANGE = "OVERLAPPING_PAYLOAD_RANGE"
    TRUNCATED_FILE = "TRUNCATED_FILE"
    INCONSISTENT_MANIFEST = "INCONSISTENT_MANIFEST"
    SCAN_LIMIT_EXCEEDED = "SCAN_LIMIT_EXCEEDED"
    SCANNER_ERROR = "SCANNER_ERROR"
    OTHER_NORMALIZED_FINDING = "OTHER_NORMALIZED_FINDING"


class FindingSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class FindingConfidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    HEURISTIC = "HEURISTIC"
    UNKNOWN = "UNKNOWN"


class FindingExploitability(StrEnum):
    DIRECTLY_EXECUTABLE = "DIRECTLY_EXECUTABLE"
    REQUIRES_UNSAFE_LOADER = "REQUIRES_UNSAFE_LOADER"
    REQUIRES_USER_ACTION = "REQUIRES_USER_ACTION"
    REQUIRES_EXTERNAL_COMPONENT = "REQUIRES_EXTERNAL_COMPONENT"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"
    SUPPRESSED_RESERVED = "SUPPRESSED_RESERVED"


class ScanExecutionStatus(StrEnum):
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_LIMITATIONS = "COMPLETED_WITH_LIMITATIONS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_RUN = "NOT_RUN"


class CoverageStatus(StrEnum):
    COMPLETE_FOR_DECLARED_SCOPE = "COMPLETE_FOR_DECLARED_SCOPE"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    NOT_ASSESSED = "NOT_ASSESSED"


class CoverageItemStatus(StrEnum):
    INSPECTED = "INSPECTED"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    ERRORED = "ERRORED"
    NOT_CHECKED = "NOT_CHECKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SecurityVerdict(StrEnum):
    PASS = "PASS"
    PASS_WITH_LIMITATIONS = "PASS_WITH_LIMITATIONS"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    FAIL = "FAIL"
    NOT_EVALUATED = "NOT_EVALUATED"
    EVIDENCE_BROKEN = "EVIDENCE_BROKEN"
    SCANNER_UNTRUSTED = "SCANNER_UNTRUSTED"
    COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"


class InspectionIntegrity(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    BROKEN = "BROKEN"
    UNVERIFIED = "UNVERIFIED"


class ScannerTrust(StrEnum):
    TRUSTED_BY_POLICY = "TRUSTED_BY_POLICY"
    UNTRUSTED_BY_POLICY = "UNTRUSTED_BY_POLICY"
    UNKNOWN = "UNKNOWN"
    PARTIAL = "PARTIAL"
    NOT_EVALUATED = "NOT_EVALUATED"


class CoverageResult(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    NOT_EVALUATED = "NOT_EVALUATED"


class FindingResult(StrEnum):
    NO_BLOCKING_FINDINGS = "NO_BLOCKING_FINDINGS"
    BLOCKING_FINDINGS_PRESENT = "BLOCKING_FINDINGS_PRESENT"
    NON_BLOCKING_FINDINGS_PRESENT = "NON_BLOCKING_FINDINGS_PRESENT"
    UNKNOWN_FINDINGS_PRESENT = "UNKNOWN_FINDINGS_PRESENT"
    NOT_EVALUATED = "NOT_EVALUATED"


class SecurityInspectionScope(SecurityModel):
    logical_paths: list[str]
    mandatory_paths: list[str]
    declared_file_count: int = Field(ge=0)
    declared_total_bytes: int = Field(ge=0)
    include_archive_metadata: bool = False

    @model_validator(mode="after")
    def safe_paths(self) -> SecurityInspectionScope:
        for value in self.logical_paths + self.mandatory_paths:
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts or "\\" in value:
                raise ValueError("inspection scope paths must be relative POSIX paths")
        if not set(self.mandatory_paths).issubset(self.logical_paths):
            raise ValueError("mandatory paths must be within logical scope")
        if self.logical_paths != sorted(set(self.logical_paths)):
            raise ValueError("scope paths must be unique and ordered")
        if self.declared_file_count != len(self.logical_paths):
            raise ValueError("declared file count must match logical scope")
        return self


class InspectionBounds(SecurityModel):
    maximum_file_count: int = Field(ge=1, le=100000)
    maximum_total_bytes_read: int = Field(ge=1, le=1024 * 1024 * 1024)
    maximum_bytes_per_file: int = Field(ge=1, le=64 * 1024 * 1024)
    maximum_archive_entry_count: int = Field(ge=1, le=100000)
    maximum_metadata_bytes: int = Field(ge=1, le=16 * 1024 * 1024)
    maximum_finding_count: int = Field(ge=1, le=10000)
    maximum_evidence_snippet_length: int = Field(ge=1, le=MAX_EXCERPT)
    maximum_recursion_depth: int = Field(ge=0, le=32)


class SecurityInspectionPlan(SecurityModel):
    schema_id: Literal["omiv.security-inspection-plan.v1"] = Field(
        default="omiv.security-inspection-plan.v1", alias="schema"
    )
    plan_id: str = Field(pattern=r"^inspection_plan_[0-9a-f]{32}$")
    subject: ArtifactReference
    scope: SecurityInspectionScope
    methods: list[InspectionMethod]
    bounds: InspectionBounds
    follow_symlinks: Literal[False] = False
    allow_decompression: Literal[False] = False
    allow_code_execution: Literal[False] = False
    allow_network_access: Literal[False] = False
    limitations: list[str]
    plan_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityInspectionPlan:
        if not self.methods or self.methods != sorted(set(self.methods), key=lambda x: x.value):
            raise ValueError("inspection methods must be non-empty, unique, and ordered")
        if InspectionMethod.CONTROLLED_DYNAMIC_ANALYSIS_RESERVED in self.methods:
            raise ValueError("controlled dynamic analysis is reserved")
        _check_identity(self, "plan_id", "inspection_plan_", "plan_digest")
        return self


class ScannerCapability(SecurityModel):
    methods: list[InspectionMethod]
    finding_categories: list[FindingClassification]
    payload_bytes_read: bool
    archive_metadata_only: bool
    code_execution: Literal[False] = False
    network_access: Literal[False] = False
    limitations: list[str]

    @model_validator(mode="after")
    def canonical(self) -> ScannerCapability:
        if self.methods != sorted(set(self.methods), key=lambda item: item.value):
            raise ValueError("scanner capability methods must be unique and ordered")
        if self.finding_categories != sorted(
            set(self.finding_categories), key=lambda item: item.value
        ):
            raise ValueError("scanner finding capabilities must be unique and ordered")
        return self


class ScannerIdentity(SecurityModel):
    schema_id: Literal["omiv.scanner-identity.v1"] = Field(
        default="omiv.scanner-identity.v1", alias="schema"
    )
    scanner_id: str = Field(pattern=r"^scanner_[0-9a-f]{32}$")
    scanner_name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=64)
    revision: str | None = Field(default=None, max_length=128)
    implementation_digest: str = Field(pattern=SHA256_PATTERN)
    capability: ScannerCapability
    configuration_digest: str = Field(pattern=SHA256_PATTERN)
    synthetic_builtin: bool
    trust_references: list[str]
    limitations: list[str]
    scanner_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> ScannerIdentity:
        _check_identity(self, "scanner_id", "scanner_", "scanner_digest")
        return self


class SecurityScanExecutionInput(SecurityModel):
    schema_id: Literal["omiv.security-scan-execution-input.v1"] = Field(
        default="omiv.security-scan-execution-input.v1", alias="schema"
    )
    plan_id: str
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    scanner_id: str
    scanner_digest: str = Field(pattern=SHA256_PATTERN)
    configuration_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ArtifactReference


class UnsupportedItem(SecurityModel):
    logical_path: str
    reason: str = Field(min_length=1, max_length=MAX_TEXT)
    mandatory: bool

    @model_validator(mode="after")
    def safe_path(self) -> UnsupportedItem:
        _relative(self.logical_path)
        return self


class ScanError(SecurityModel):
    logical_path: str | None = None
    error_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    message: str = Field(min_length=1, max_length=MAX_TEXT)
    recoverable: bool

    @model_validator(mode="after")
    def safe_path(self) -> ScanError:
        if self.logical_path is not None:
            _relative(self.logical_path)
        return self


class RawScannerResultReference(SecurityModel):
    schema_id: str = Field(alias="schema")
    digest: str = Field(pattern=SHA256_PATTERN)
    verification_mode: Literal["FULL", "DIGEST_LINKED", "UNVERIFIED"]
    relative_path: str | None = None

    @model_validator(mode="after")
    def coherent(self) -> RawScannerResultReference:
        if self.relative_path is not None:
            _relative(self.relative_path)
        if self.verification_mode == "FULL" and self.relative_path is None:
            raise ValueError("full raw-result verification requires a relative path")
        return self


class SecurityScanExecutionRecord(SecurityModel):
    schema_id: Literal["omiv.security-scan-execution-record.v1"] = Field(
        default="omiv.security-scan-execution-record.v1", alias="schema"
    )
    execution_id: str = Field(pattern=r"^scan_exec_[0-9a-f]{32}$")
    plan_id: str
    plan_digest: str = Field(pattern=SHA256_PATTERN)
    scanner_id: str
    scanner_digest: str = Field(pattern=SHA256_PATTERN)
    configuration_digest: str = Field(pattern=SHA256_PATTERN)
    subject: ArtifactReference
    methods_executed: list[InspectionMethod]
    files_considered: int = Field(ge=0)
    files_inspected: int = Field(ge=0)
    bytes_considered: int = Field(ge=0)
    bytes_inspected: int = Field(ge=0)
    payload_bytes_read: bool
    decompression_occurred: Literal[False] = False
    code_execution_occurred: Literal[False] = False
    network_access_occurred: Literal[False] = False
    unsupported_items: list[UnsupportedItem]
    errors: list[ScanError]
    status: ScanExecutionStatus
    raw_result_references: list[RawScannerResultReference]
    limitations: list[str]
    execution_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityScanExecutionRecord:
        if (
            self.files_inspected > self.files_considered
            or self.bytes_inspected > self.bytes_considered
        ):
            raise ValueError("execution inspected counts exceed considered counts")
        if self.methods_executed != sorted(set(self.methods_executed), key=lambda x: x.value):
            raise ValueError("executed methods must be unique and ordered")
        if self.status == ScanExecutionStatus.COMPLETED and (self.unsupported_items or self.errors):
            raise ValueError("completed execution cannot hide unsupported items or errors")
        _check_identity(self, "execution_id", "scan_exec_", "execution_digest")
        return self


class FindingLocation(SecurityModel):
    logical_path: str
    byte_offset: int | None = Field(default=None, ge=0)
    byte_length: int | None = Field(default=None, ge=0)
    archive_entry: str | None = None

    @model_validator(mode="after")
    def safe(self) -> FindingLocation:
        _relative(self.logical_path)
        if self.archive_entry is not None:
            _relative(self.archive_entry)
        if (self.byte_offset is None) != (self.byte_length is None):
            raise ValueError("finding byte location requires both offset and length")
        return self


class FindingEvidence(SecurityModel):
    role: str = Field(min_length=1, max_length=64)
    evidence_digest: str = Field(pattern=SHA256_PATTERN)
    indicator: str = Field(min_length=1, max_length=MAX_EXCERPT)
    redacted_fingerprint: str | None = Field(default=None, pattern=SHA256_PATTERN)
    sensitive_value_redacted: bool


class SecurityFinding(SecurityModel):
    schema_id: Literal["omiv.security-finding.v1"] = Field(
        default="omiv.security-finding.v1", alias="schema"
    )
    finding_id: str = Field(pattern=r"^security_finding_[0-9a-f]{32}$")
    category: FindingClassification
    severity: FindingSeverity
    confidence: FindingConfidence
    exploitability: FindingExploitability
    status: FindingStatus
    subject_identity_digest: str = Field(pattern=SHA256_PATTERN)
    location: FindingLocation
    evidence: FindingEvidence
    scanner_id: str
    scan_execution_id: str
    applicable_policy_ids: list[str]
    governance_evidence_ids: list[str]
    limitations: list[str]
    remediation_guidance: str = Field(min_length=1, max_length=MAX_TEXT)
    finding_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityFinding:
        governed = {
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.MITIGATED,
        }
        if self.status in governed and not self.governance_evidence_ids:
            raise ValueError("governed finding status requires explicit governance evidence")
        if self.status == FindingStatus.NOT_APPLICABLE and not self.governance_evidence_ids:
            raise ValueError("not-applicable finding requires explicit evidence")
        if self.status == FindingStatus.SUPPRESSED_RESERVED:
            raise ValueError("arbitrary finding suppression is reserved")
        _check_identity(self, "finding_id", "security_finding_", "finding_digest")
        return self


class CoverageItem(SecurityModel):
    logical_path: str
    declared_bytes: int = Field(ge=0)
    inspected_bytes: int = Field(ge=0)
    methods: list[InspectionMethod]
    status: CoverageItemStatus
    payload_read: bool
    rationale: str | None = Field(default=None, max_length=MAX_TEXT)
    not_applicable_evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent(self) -> CoverageItem:
        _relative(self.logical_path)
        if self.inspected_bytes > self.declared_bytes:
            raise ValueError("coverage inspected bytes exceed declared bytes")
        if (
            self.status == CoverageItemStatus.INSPECTED
            and self.inspected_bytes == 0
            and self.declared_bytes
        ):
            raise ValueError("non-empty inspected item requires inspected bytes")
        if self.status == CoverageItemStatus.NOT_APPLICABLE and not self.not_applicable_evidence:
            raise ValueError("not-applicable coverage requires evidence")
        if self.methods != sorted(set(self.methods), key=lambda item: item.value):
            raise ValueError("coverage methods must be unique and ordered")
        return self


class CoverageSummary(SecurityModel):
    schema_id: Literal["omiv.security-coverage.v1"] = Field(
        default="omiv.security-coverage.v1", alias="schema"
    )
    coverage_id: str = Field(pattern=r"^security_coverage_[0-9a-f]{32}$")
    subject_identity_digest: str = Field(pattern=SHA256_PATTERN)
    items: list[CoverageItem]
    declared_files: int = Field(ge=0)
    discovered_files: int = Field(ge=0)
    inspected_files: int = Field(ge=0)
    unsupported_files: int = Field(ge=0)
    skipped_files: int = Field(ge=0)
    errored_files: int = Field(ge=0)
    total_declared_bytes: int = Field(ge=0)
    total_discovered_bytes: int = Field(ge=0)
    total_inspected_bytes: int = Field(ge=0)
    bytes_not_inspected: int = Field(ge=0)
    archive_entries_considered: int = Field(ge=0)
    archive_entries_inspected: int = Field(ge=0)
    status: CoverageStatus
    limitations: list[str]
    coverage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> CoverageSummary:
        if self.items != sorted(self.items, key=lambda x: x.logical_path):
            raise ValueError("coverage items must be deterministically ordered")
        if len({x.logical_path for x in self.items}) != len(self.items):
            raise ValueError("duplicate coverage item")
        counts = {s: sum(x.status == s for x in self.items) for s in CoverageItemStatus}
        if self.discovered_files != len(self.items):
            raise ValueError("discovered-file count conflicts with coverage items")
        if self.inspected_files != counts[CoverageItemStatus.INSPECTED]:
            raise ValueError("inspected-file count conflicts with coverage items")
        if self.unsupported_files != counts[CoverageItemStatus.UNSUPPORTED]:
            raise ValueError("unsupported-file count conflicts with coverage items")
        if (
            self.skipped_files
            != counts[CoverageItemStatus.SKIPPED] + counts[CoverageItemStatus.NOT_CHECKED]
        ):
            raise ValueError("skipped-file count conflicts with coverage items")
        if self.errored_files != counts[CoverageItemStatus.ERRORED]:
            raise ValueError("errored-file count conflicts with coverage items")
        if self.total_discovered_bytes != sum(x.declared_bytes for x in self.items):
            raise ValueError("discovered bytes conflict with coverage items")
        if self.total_inspected_bytes != sum(x.inspected_bytes for x in self.items):
            raise ValueError("inspected bytes conflict with coverage items")
        if self.bytes_not_inspected != self.total_discovered_bytes - self.total_inspected_bytes:
            raise ValueError("uninspected byte count is inconsistent")
        if self.archive_entries_inspected > self.archive_entries_considered:
            raise ValueError("inspected archive entries exceed considered entries")
        complete = (
            self.declared_files == self.discovered_files == self.inspected_files
            and self.total_declared_bytes
            == self.total_discovered_bytes
            == self.total_inspected_bytes
            and not self.unsupported_files
            and not self.skipped_files
            and not self.errored_files
        )
        if self.status == CoverageStatus.COMPLETE_FOR_DECLARED_SCOPE and not complete:
            raise ValueError("false complete coverage")
        _check_identity(self, "coverage_id", "security_coverage_", "coverage_digest")
        return self


class SecurityEvidenceBundle(SecurityModel):
    schema_id: Literal["omiv.security-evidence-bundle.v1"] = Field(
        default="omiv.security-evidence-bundle.v1", alias="schema"
    )
    bundle_id: str = Field(pattern=r"^security_bundle_[0-9a-f]{32}$")
    subject: ArtifactReference
    inspection_plan: SecurityInspectionPlan
    scanner_identities: list[ScannerIdentity]
    execution_records: list[SecurityScanExecutionRecord]
    findings: list[SecurityFinding]
    coverage: CoverageSummary
    unsupported_items: list[UnsupportedItem]
    scan_errors: list[ScanError]
    evidence_references: list[RawScannerResultReference]
    policy_references: list[str]
    limitations: list[str]
    bundle_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityEvidenceBundle:
        scanners = [item.scanner_id for item in self.scanner_identities]
        executions = [item.execution_id for item in self.execution_records]
        findings = [item.finding_id for item in self.findings]
        if scanners != sorted(set(scanners)):
            raise ValueError("scanner records must be unique and ordered")
        if executions != sorted(set(executions)):
            raise ValueError("execution records must be unique and ordered")
        if findings != sorted(set(findings)):
            raise ValueError("finding records must be unique and ordered")
        subject = self.subject.identity_digest
        if (
            self.inspection_plan.subject.identity_digest != subject
            or self.coverage.subject_identity_digest != subject
        ):
            raise ValueError("security bundle subject mismatch")
        scope = self.inspection_plan.scope
        if (
            [item.logical_path for item in self.coverage.items] != scope.logical_paths
            or self.coverage.declared_files != scope.declared_file_count
            or self.coverage.total_declared_bytes != scope.declared_total_bytes
        ):
            raise ValueError("security bundle coverage conflicts with inspection-plan scope")
        scanner_records = {x.scanner_id: x for x in self.scanner_identities}
        execution_records = {x.execution_id: x for x in self.execution_records}
        for record in self.execution_records:
            if (
                record.subject.identity_digest != subject
                or record.scanner_id not in scanner_records
                or record.plan_id != self.inspection_plan.plan_id
                or record.plan_digest != self.inspection_plan.plan_digest
            ):
                raise ValueError("execution subject, scanner, or plan mismatch")
            if scanner_records[record.scanner_id].scanner_digest != record.scanner_digest:
                raise ValueError("execution scanner digest mismatch")
            if (
                record.configuration_digest
                != scanner_records[record.scanner_id].configuration_digest
                or not set(record.methods_executed).issubset(
                    scanner_records[record.scanner_id].capability.methods
                )
                or not set(record.methods_executed).issubset(self.inspection_plan.methods)
            ):
                raise ValueError("execution configuration or method capability mismatch")
        for finding in self.findings:
            if (
                finding.subject_identity_digest != subject
                or finding.scanner_id not in scanner_records
                or finding.scan_execution_id not in execution_records
                or finding.location.logical_path not in scope.logical_paths
                or execution_records[finding.scan_execution_id].scanner_id != finding.scanner_id
            ):
                raise ValueError("finding subject, location, scanner, or execution mismatch")
        if self.unsupported_items != [
            x for r in self.execution_records for x in r.unsupported_items
        ]:
            raise ValueError("bundle unsupported scope conflicts with executions")
        if self.scan_errors != [x for r in self.execution_records for x in r.errors]:
            raise ValueError("bundle errors conflict with executions")
        _check_identity(self, "bundle_id", "security_bundle_", "bundle_digest")
        return self


class SecurityRequirementProfile(StrEnum):
    PERSONAL_LOCAL_SECURITY_REVIEW = "personal_local_security_review"
    TEAM_ARTIFACT_SECURITY_INTAKE = "team_artifact_security_intake"
    TEAM_RELEASE_SECURITY_GATE = "team_release_security_gate"
    ENTERPRISE_ARTIFACT_SECURITY_GATE = "enterprise_artifact_security_gate"
    REGULATED_ARTIFACT_SECURITY_GATE = "regulated_artifact_security_gate"


class SecurityEvidencePolicy(SecurityModel):
    schema_id: Literal["omiv.security-evidence-policy.v1"] = Field(
        default="omiv.security-evidence-policy.v1", alias="schema"
    )
    policy_id: str = Field(pattern=ID_PATTERN)
    version: Literal[1] = 1
    profile: SecurityRequirementProfile
    accepted_scanner_ids: list[str]
    accepted_scanner_trust_levels: list[ScannerTrust]
    required_methods: list[InspectionMethod]
    required_coverage: CoverageStatus
    allowed_unsupported_items: int = Field(ge=0)
    blocking_severities: list[FindingSeverity]
    blocking_categories: list[FindingClassification]
    minimum_blocking_confidence: FindingConfidence
    blocking_exploitability: list[FindingExploitability]
    maximum_scanner_errors: int = Field(ge=0)
    unknown_finding_behavior: Literal["FAIL", "REVIEW", "ALLOW_WITH_LIMITATIONS"]
    incomplete_coverage_behavior: Literal["FAIL", "REVIEW", "ALLOW_WITH_LIMITATIONS"]
    accepted_risk_behavior: Literal["FAIL", "REVIEW", "ALLOW_WITH_LIMITATIONS"]
    freshness_seconds: int | None = Field(default=None, ge=0)
    signed_evidence_required: bool
    fail_closed_reserved: bool
    decision_precedence: list[SecurityVerdict]
    governance_allow_limitations: bool
    limitations: list[str]
    policy_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityEvidencePolicy:
        required = [
            SecurityVerdict.EVIDENCE_BROKEN,
            SecurityVerdict.FAIL,
            SecurityVerdict.SCANNER_UNTRUSTED,
            SecurityVerdict.COVERAGE_INCOMPLETE,
            SecurityVerdict.NOT_EVALUATED,
            SecurityVerdict.REVIEW_REQUIRED,
            SecurityVerdict.PASS_WITH_LIMITATIONS,
            SecurityVerdict.PASS,
        ]
        if self.decision_precedence != required:
            raise ValueError("security decision precedence is invalid")
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("policy_digest")
        if digest != canonical_sha256(body):
            raise ValueError("security policy digest mismatch")
        return self


class SecurityEvaluationResult(SecurityModel):
    schema_id: Literal["omiv.security-evaluation.v1"] = Field(
        default="omiv.security-evaluation.v1", alias="schema"
    )
    evaluation_id: str = Field(pattern=r"^security_eval_[0-9a-f]{32}$")
    subject_identity_digest: str = Field(pattern=SHA256_PATTERN)
    bundle_id: str
    bundle_digest: str = Field(pattern=SHA256_PATTERN)
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_context_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    inspection_integrity: InspectionIntegrity
    scanner_identity_status: Literal["KNOWN"]
    scan_execution_integrity: InspectionIntegrity
    scanner_trust: ScannerTrust
    signature_trust: str
    scanner_correctness_independently_proven: Literal["NOT_ESTABLISHED"]
    coverage_result: CoverageResult
    finding_result: FindingResult
    required_methods_satisfied: bool
    unresolved_error_count: int = Field(ge=0)
    blocking_finding_ids: list[str]
    verdict: SecurityVerdict
    blockers: list[str]
    limitations: list[str]
    uninspected_scope: list[str]
    evaluation_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityEvaluationResult:
        if self.verdict == SecurityVerdict.PASS and (
            self.inspection_integrity != InspectionIntegrity.VALID
            or self.scanner_trust != ScannerTrust.TRUSTED_BY_POLICY
            or self.coverage_result != CoverageResult.COMPLETE
            or self.finding_result != FindingResult.NO_BLOCKING_FINDINGS
            or not self.required_methods_satisfied
            or self.unresolved_error_count
            or self.blockers
        ):
            raise ValueError("PASS does not satisfy mandatory security conditions")
        _check_identity(self, "evaluation_id", "security_eval_", "evaluation_digest")
        return self


class SecurityReport(SecurityModel):
    schema_id: Literal["omiv.security-report.v1"] = Field(
        default="omiv.security-report.v1", alias="schema"
    )
    report_id: str = Field(pattern=r"^security_report_[0-9a-f]{32}$")
    bundle_id: str
    bundle_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation: SecurityEvaluationResult
    scanner_ids: list[str]
    scanner_trust: ScannerTrust
    scanner_correctness_independently_proven: Literal["NOT_ESTABLISHED"]
    methods: list[InspectionMethod]
    execution_statuses: list[ScanExecutionStatus]
    declared_scope_paths: list[str]
    declared_scope_coverage: CoverageStatus
    scanner_capability_coverage: CoverageResult
    declared_files: int = Field(ge=0)
    discovered_files: int = Field(ge=0)
    files_inspected: int = Field(ge=0)
    total_declared_bytes: int = Field(ge=0)
    total_discovered_bytes: int = Field(ge=0)
    bytes_inspected: int = Field(ge=0)
    bytes_not_inspected: int = Field(ge=0)
    payload_bytes_read: bool
    code_execution: Literal[False] = False
    network_access: Literal[False] = False
    finding_counts: dict[FindingSeverity, int]
    blocking_findings: int = Field(ge=0)
    unsupported_items: list[UnsupportedItem]
    scan_errors: list[ScanError]
    signature_status: str
    payload_integrity: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    behavioral_runtime_safety: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    no_findings_warning: Literal[
        "No findings does not prove safety or absence of vulnerabilities."
    ] = "No findings does not prove safety or absence of vulnerabilities."
    limitations: list[str]
    next_required_actions: list[str]
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityReport:
        _check_identity(self, "report_id", "security_report_", "report_digest")
        return self


class SignedSecurityEvidenceLinkage(SecurityModel):
    schema_id: Literal["omiv.signed-security-evidence-linkage.v1"] = Field(
        default="omiv.signed-security-evidence-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=r"^signed_security_[0-9a-f]{32}$")
    object_id: str
    object_digest: str = Field(pattern=SHA256_PATTERN)
    envelope_id: str
    envelope_digest: str = Field(pattern=SHA256_PATTERN)
    signature_purpose: str
    trust_status: str
    coverage_unchanged: Literal[True] = True
    verdict_unchanged: Literal[True] = True
    limitations: list[str]
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SignedSecurityEvidenceLinkage:
        _check_identity(self, "linkage_id", "signed_security_", "linkage_digest")
        return self


class GovernanceSecurityEvidenceAdapter(SecurityModel):
    schema_id: Literal["omiv.governance-security-evidence-adapter.v1"] = Field(
        default="omiv.governance-security-evidence-adapter.v1", alias="schema"
    )
    adapter_id: str = Field(pattern=r"^governance_security_[0-9a-f]{32}$")
    subject_id: str
    subject_identity_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_id: str
    evaluation_digest: str = Field(pattern=SHA256_PATTERN)
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    requirement_outcome: str
    evidence_reference_id: str
    verdict: SecurityVerdict
    coverage_result: CoverageResult
    scanner_trust: ScannerTrust
    signature_trust: str
    blocking_findings: int = Field(ge=0)
    unresolved_errors: int = Field(ge=0)
    limitations: list[str]
    adapter_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> GovernanceSecurityEvidenceAdapter:
        _check_identity(self, "adapter_id", "governance_security_", "adapter_digest")
        return self


class PassportSecuritySummary(SecurityModel):
    schema_id: Literal["omiv.passport-security-summary.v1"] = Field(
        default="omiv.passport-security-summary.v1", alias="schema"
    )
    summary_id: str = Field(pattern=r"^passport_security_[0-9a-f]{32}$")
    passport_id: str
    passport_digest: str = Field(pattern=SHA256_PATTERN)
    subject_identity_digest: str = Field(pattern=SHA256_PATTERN)
    evidence_availability: Literal["AVAILABLE", "UNAVAILABLE"]
    policy_id: str
    policy_digest: str = Field(pattern=SHA256_PATTERN)
    inspection_methods: list[InspectionMethod]
    scanner_ids: list[str]
    scanner_trust: ScannerTrust
    coverage_result: CoverageResult
    finding_counts: dict[FindingSeverity, int]
    blocking_finding_count: int = Field(ge=0)
    verdict: SecurityVerdict
    signed_evidence_status: str
    freshness_status: str
    payload_integrity: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    runtime_safety: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    approval_status: Literal["SEPARATE"] = "SEPARATE"
    deployment_status: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    limitations: list[str]
    uninspected_scope: list[str]
    next_required_evidence: list[str]
    summary_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> PassportSecuritySummary:
        _check_identity(self, "summary_id", "passport_security_", "summary_digest")
        return self


class CustodySecurityLinkage(SecurityModel):
    schema_id: Literal["omiv.custody-security-linkage.v1"] = Field(
        default="omiv.custody-security-linkage.v1", alias="schema"
    )
    linkage_id: str = Field(pattern=r"^custody_security_[0-9a-f]{32}$")
    custody_ledger_id: str
    custody_ledger_digest: str = Field(pattern=SHA256_PATTERN)
    event_type: Literal["SECURITY_INSPECTION_RECORDED", "SECURITY_EVALUATION_RECORDED"]
    bundle_id: str
    bundle_digest: str = Field(pattern=SHA256_PATTERN)
    evaluation_id: str | None = None
    evaluation_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    scanner_ids: list[str]
    coverage_result: CoverageResult
    verdict: SecurityVerdict
    signature_trust_summary: str
    lifecycle_completeness: Literal["UNCHANGED_INCOMPLETE"] = "UNCHANGED_INCOMPLETE"
    limitations: list[str]
    linkage_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> CustodySecurityLinkage:
        if self.event_type == "SECURITY_EVALUATION_RECORDED" and not (
            self.evaluation_id and self.evaluation_digest
        ):
            raise ValueError("evaluation custody linkage requires evaluation identity")
        _check_identity(self, "linkage_id", "custody_security_", "linkage_digest")
        return self


class SecurityArtifactIndexEntry(SecurityModel):
    relative_path: str
    schema_id: str = Field(alias="schema")
    object_id: str
    digest: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def safe(self) -> SecurityArtifactIndexEntry:
        _relative(self.relative_path)
        return self


class SecurityArtifactIndex(SecurityModel):
    schema_id: Literal["omiv.security-artifact-index.v1"] = Field(
        default="omiv.security-artifact-index.v1", alias="schema"
    )
    index_id: str = Field(pattern=r"^security_index_[0-9a-f]{32}$")
    entries: list[SecurityArtifactIndexEntry]
    limitations: list[str]
    index_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> SecurityArtifactIndex:
        if self.entries != sorted(self.entries, key=lambda x: x.relative_path):
            raise ValueError("security index entries must be ordered")
        if len({x.relative_path for x in self.entries}) != len(self.entries):
            raise ValueError("duplicate security index entry")
        _check_identity(self, "index_id", "security_index_", "index_digest")
        return self


def _relative(value: str) -> None:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ValueError("path must be a non-traversing relative POSIX path")


def _check_identity(model: StrictModel, id_field: str, prefix: str, digest_field: str) -> None:
    body = model.model_dump(mode="json", by_alias=True)
    digest = body.pop(digest_field)
    object_id = body.pop(id_field)
    expected = canonical_sha256(body)
    if object_id != prefix + expected[:32]:
        raise ValueError(f"{id_field} mismatch")
    body[id_field] = object_id
    if digest != canonical_sha256(body):
        raise ValueError(f"{digest_field} mismatch")
