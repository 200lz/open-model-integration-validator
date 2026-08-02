"""Safe, bounded, deterministic OMIV-native static inspection."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.security.building import artifact_reference, build_coverage, build_finding, identified
from omiv.security.models import (
    CoverageItem,
    CoverageItemStatus,
    FindingClassification,
    FindingConfidence,
    FindingExploitability,
    FindingSeverity,
    InspectionMethod,
    ScanError,
    ScanExecutionStatus,
    ScannerIdentity,
    SecurityEvidenceBundle,
    SecurityFinding,
    SecurityInspectionPlan,
    SecurityScanExecutionRecord,
    UnsupportedItem,
)


@dataclass(frozen=True)
class _LocalItem:
    path: Path
    logical_path: str
    size: int


SAFE_EXTENSIONS = {
    ".json",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".safetensors",
    ".gguf",
    ".onnx",
    ".zip",
    ".tar",
    ".tgz",
    ".gz",
    ".bin",
    ".model",
    ".index",
    ".toml",
}
SCRIPT_EXTENSIONS = {".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".js"}
NATIVE_EXTENSIONS = {".so", ".dll", ".dylib", ".exe", ".elf"}
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt"}


def _regular_root(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise OmivInputError(f"cannot inspect local artifact: {exc}") from exc
    if stat.S_ISLNK(mode):
        raise OmivInputError("artifact path must not be a symlink")
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise OmivInputError("artifact path must be a regular file or directory")
    resolved = path.resolve(strict=True)
    if str(resolved).startswith(("/proc/", "/sys/")):
        raise OmivInputError("proc/sys traversal is prohibited")


def enumerate_local_artifact(
    path: Path, plan: SecurityInspectionPlan | None = None
) -> list[_LocalItem]:
    """Enumerate regular files without following links and with explicit bounds."""
    _regular_root(path)
    max_files = plan.bounds.maximum_file_count if plan else 10000
    max_depth = plan.bounds.maximum_recursion_depth if plan else 16
    root = path.resolve(strict=True)
    result: list[_LocalItem] = []

    def visit(current: Path, depth: int) -> None:
        if depth > max_depth:
            raise OmivInputError("artifact recursion depth limit exceeded")
        if len(result) >= max_files:
            raise OmivInputError("artifact file-count limit exceeded")
        mode = current.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise OmivInputError("symlink encountered in artifact scope")
        if stat.S_ISREG(mode):
            relative = current.relative_to(root.parent if root.is_file() else root).as_posix()
            result.append(
                _LocalItem(current, relative, current.stat(follow_symlinks=False).st_size)
            )
            return
        if not stat.S_ISDIR(mode):
            raise OmivInputError("device, FIFO, socket, or special file encountered")
        try:
            children = sorted(current.iterdir(), key=lambda child: child.name)
        except OSError as exc:
            raise OmivInputError(f"cannot enumerate artifact directory: {exc}") from exc
        for child in children:
            visit(child, depth + 1)

    visit(root, 0)
    return result


def describe_local_artifact(
    path: Path, *, plan: SecurityInspectionPlan | None = None
) -> tuple[Any, list[_LocalItem]]:
    items = enumerate_local_artifact(path, plan)
    total = sum(item.size for item in items)
    limit = plan.bounds.maximum_total_bytes_read if plan else 1024 * 1024 * 1024
    if total > limit:
        raise OmivInputError("artifact bytes exceed the bounded identity limit")
    file_records: list[dict[str, object]] = []
    for item in items:
        digest = hashlib.sha256()
        with item.path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        file_records.append(
            {"logical_path": item.logical_path, "size": item.size, "sha256": digest.hexdigest()}
        )
    set_digest = canonical_sha256(file_records)
    suffix = path.suffix.lower() if path.is_file() else None
    fmt = {
        ".safetensors": "safetensors",
        ".gguf": "gguf",
        ".onnx": "onnx",
        ".zip": "archive",
        ".json": "json",
    }.get(suffix or "", "artifact-set" if path.is_dir() else "generic-file")
    subject = artifact_reference(
        origin_type="local",
        variant=path.name,
        file_count=len(items),
        total_declared_bytes=total,
        content_digest=file_records[0]["sha256"] if len(items) == 1 else None,  # type: ignore[arg-type]
        artifact_set_digest=set_digest,
        format=fmt,
        selection=path.name,
    )
    return subject, items


def _read_prefix(item: _LocalItem, maximum: int, remaining: int) -> bytes:
    length = min(item.size, maximum, remaining)
    try:
        with item.path.open("rb") as handle:
            return handle.read(length)
    except OSError as exc:
        raise OmivInputError(
            f"cannot read bounded artifact file {item.logical_path}: {exc}"
        ) from exc


def _indicator(
    category: FindingClassification,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    exploitability: FindingExploitability,
    item: _LocalItem,
    content: bytes,
    scanner_id: str,
    execution_id: str,
    subject_digest: str,
    *,
    offset: int = 0,
    label: str,
    sensitive: bool = False,
    archive_entry: str | None = None,
) -> SecurityFinding:
    evidence_digest = hashlib.sha256(content).hexdigest()
    return build_finding(
        category=category,
        severity=severity,
        confidence=confidence,
        exploitability=exploitability,
        subject_identity_digest=subject_digest,
        logical_path=item.logical_path,
        indicator=label,
        evidence_digest=evidence_digest,
        scanner_id=scanner_id,
        execution_id=execution_id,
        byte_offset=None if archive_entry else offset,
        byte_length=None if archive_entry else max(1, min(len(content), 64)),
        archive_entry=archive_entry,
        sensitive=sensitive,
    )


def _archive_findings(
    item: _LocalItem,
    content: bytes,
    plan: SecurityInspectionPlan,
    scanner: ScannerIdentity,
    execution_id: str,
    subject_digest: str,
) -> tuple[list[SecurityFinding], int, list[ScanError]]:
    if item.path.suffix.lower() != ".zip":
        return [], 0, []
    findings: list[SecurityFinding] = []
    try:
        if len(content) != item.size:
            raise ValueError("bounded prefix does not contain the complete archive metadata")
        eocd_offset = content.rfind(b"PK\x05\x06", max(0, len(content) - 65557))
        if eocd_offset < 0 or eocd_offset + 22 > len(content):
            raise ValueError("end-of-central-directory record is unavailable")
        (
            _,
            disk_number,
            central_disk,
            disk_entries,
            entry_count,
            central_size,
            central_offset,
            comment_length,
        ) = struct.unpack_from("<4s4H2LH", content, eocd_offset)
        if disk_number or central_disk or disk_entries != entry_count:
            raise ValueError("multi-disk or inconsistent archive metadata is unsupported")
        if eocd_offset + 22 + comment_length > len(content):
            raise ValueError("archive comment is truncated")
        if entry_count > plan.bounds.maximum_archive_entry_count:
            return (
                [],
                entry_count,
                [
                    ScanError(
                        logical_path=item.logical_path,
                        error_code="ARCHIVE_ENTRY_LIMIT_EXCEEDED",
                        message="Archive entry count exceeds the configured bound.",
                        recoverable=False,
                    )
                ],
            )
        if central_size > plan.bounds.maximum_metadata_bytes:
            return (
                [],
                entry_count,
                [
                    ScanError(
                        logical_path=item.logical_path,
                        error_code="ARCHIVE_METADATA_LIMIT_EXCEEDED",
                        message="Archive metadata exceeds the configured bound.",
                        recoverable=False,
                    )
                ],
            )
        central_end = central_offset + central_size
        if central_end > len(content) or central_end > eocd_offset:
            raise ValueError("archive central directory is truncated or overlapping")
        offset = central_offset
        entries_seen = 0
        while offset < central_end:
            if offset + 46 > central_end or content[offset : offset + 4] != b"PK\x01\x02":
                raise ValueError("archive central-directory entry is malformed")
            fields = struct.unpack_from("<4s6H3L5H2L", content, offset)
            name_length, extra_length, entry_comment_length = fields[10:13]
            external_attributes = fields[15]
            entry_end = offset + 46 + name_length + extra_length + entry_comment_length
            if entry_end > central_end:
                raise ValueError("archive central-directory entry is truncated")
            raw_name = content[offset + 46 : offset + 46 + name_length]
            name = raw_name.decode("utf-8", errors="replace")
            entries_seen += 1
            if entries_seen > plan.bounds.maximum_archive_entry_count:
                return (
                    [],
                    entries_seen,
                    [
                        ScanError(
                            logical_path=item.logical_path,
                            error_code="ARCHIVE_ENTRY_LIMIT_EXCEEDED",
                            message="Archive entry count exceeds the configured bound.",
                            recoverable=False,
                        )
                    ],
                )
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                findings.append(
                    _indicator(
                        FindingClassification.PATH_TRAVERSAL_ENTRY,
                        FindingSeverity.HIGH,
                        FindingConfidence.CONFIRMED,
                        FindingExploitability.REQUIRES_UNSAFE_LOADER,
                        item,
                        raw_name,
                        scanner.scanner_id,
                        execution_id,
                        subject_digest,
                        label="archive-path-traversal",
                        archive_entry="redacted-entry",
                    )
                )
            unix_mode = external_attributes >> 16
            if stat.S_ISLNK(unix_mode):
                findings.append(
                    _indicator(
                        FindingClassification.SYMLINK_ENTRY,
                        FindingSeverity.MEDIUM,
                        FindingConfidence.CONFIRMED,
                        FindingExploitability.REQUIRES_USER_ACTION,
                        item,
                        raw_name,
                        scanner.scanner_id,
                        execution_id,
                        subject_digest,
                        label="archive-symlink-entry",
                        archive_entry="redacted-entry",
                    )
                )
            offset = entry_end
        if entries_seen != entry_count:
            raise ValueError("archive entry count conflicts with central-directory metadata")
        return findings, entries_seen, []
    except (OSError, ValueError, struct.error) as exc:
        return (
            [],
            0,
            [
                ScanError(
                    logical_path=item.logical_path,
                    error_code="MALFORMED_ARCHIVE",
                    message=f"Archive central-directory inspection failed: {type(exc).__name__}.",
                    recoverable=False,
                )
            ],
        )


def _archive_manifest_findings(
    item: _LocalItem,
    content: bytes,
    plan: SecurityInspectionPlan,
    scanner: ScannerIdentity,
    execution_id: str,
    subject_digest: str,
) -> tuple[list[SecurityFinding], int, list[ScanError]]:
    if not item.path.name.endswith(".archive-manifest.json"):
        return [], 0, []
    try:
        value = json.loads(content.decode("utf-8"))
        entries = value.get("entries") if isinstance(value, dict) else None
        if not isinstance(entries, list) or not all(isinstance(x, dict) for x in entries):
            raise ValueError("archive manifest entries must be a list of objects")
        if len(entries) > plan.bounds.maximum_archive_entry_count:
            raise OverflowError("archive manifest entry limit exceeded")
        if len(content) > plan.bounds.maximum_metadata_bytes:
            raise OverflowError("archive manifest metadata limit exceeded")
        findings: list[SecurityFinding] = []
        for entry in entries:
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("archive manifest entry name is missing")
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                findings.append(
                    _indicator(
                        FindingClassification.PATH_TRAVERSAL_ENTRY,
                        FindingSeverity.HIGH,
                        FindingConfidence.CONFIRMED,
                        FindingExploitability.REQUIRES_UNSAFE_LOADER,
                        item,
                        name.encode("utf-8"),
                        scanner.scanner_id,
                        execution_id,
                        subject_digest,
                        label="archive-manifest-path-traversal",
                        archive_entry="redacted-entry",
                    )
                )
            if entry.get("kind") == "symlink":
                findings.append(
                    _indicator(
                        FindingClassification.SYMLINK_ENTRY,
                        FindingSeverity.MEDIUM,
                        FindingConfidence.CONFIRMED,
                        FindingExploitability.REQUIRES_USER_ACTION,
                        item,
                        name.encode("utf-8"),
                        scanner.scanner_id,
                        execution_id,
                        subject_digest,
                        label="archive-manifest-symlink-entry",
                        archive_entry="redacted-entry",
                    )
                )
        return findings, len(entries), []
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        return (
            [],
            0,
            [
                ScanError(
                    logical_path=item.logical_path,
                    error_code="MALFORMED_ARCHIVE_MANIFEST",
                    message=f"Archive manifest inspection failed: {type(exc).__name__}.",
                    recoverable=False,
                )
            ],
        )


def inspect_local_artifact(
    path: Path,
    plan: SecurityInspectionPlan,
    scanner: ScannerIdentity,
) -> SecurityEvidenceBundle:
    """Inspect local bytes without deserialization, extraction, execution, or network access."""
    subject, items = describe_local_artifact(path, plan=plan)
    if subject.identity_digest != plan.subject.identity_digest:
        raise OmivInputError("local artifact does not match inspection-plan subject")
    if [item.logical_path for item in items] != plan.scope.logical_paths:
        raise OmivInputError("discovered local files do not match declared inspection scope")
    unsupported_methods = set(plan.methods) - set(scanner.capability.methods)
    if unsupported_methods:
        raise OmivInputError("inspection plan requests a method unsupported by the scanner")

    configuration_digest = scanner.configuration_digest
    execution_seed = {
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "scanner_id": scanner.scanner_id,
        "scanner_digest": scanner.scanner_digest,
        "configuration_digest": configuration_digest,
        "subject_identity_digest": subject.identity_digest,
    }
    execution_id = "scan_exec_" + canonical_sha256(execution_seed)[:32]
    coverage_items: list[CoverageItem] = []
    findings: list[SecurityFinding] = []
    errors: list[ScanError] = []
    unsupported: list[UnsupportedItem] = []
    bytes_read = 0
    archive_entries = 0
    limit_hit = False

    for item in items:
        remaining = plan.bounds.maximum_total_bytes_read - bytes_read
        if remaining <= 0:
            limit_hit = True
            coverage_items.append(
                CoverageItem(
                    logical_path=item.logical_path,
                    declared_bytes=item.size,
                    inspected_bytes=0,
                    methods=[],
                    status=CoverageItemStatus.NOT_CHECKED,
                    payload_read=False,
                    rationale="Total byte-read bound was exhausted.",
                )
            )
            continue
        content = _read_prefix(item, plan.bounds.maximum_bytes_per_file, remaining)
        bytes_read += len(content)
        full = len(content) == item.size
        if not full:
            limit_hit = True
        suffix = item.path.suffix.lower()
        lower_name = item.path.name.lower()
        format_structure_supported = False
        if suffix == ".safetensors":
            format_structure_supported = True
            if len(content) < 10:
                errors.append(
                    ScanError(
                        logical_path=item.logical_path,
                        error_code="TRUNCATED_SAFETENSORS_HEADER",
                        message="Safetensors-like file is too short for a bounded header.",
                        recoverable=False,
                    )
                )
            else:
                header_length = int.from_bytes(content[:8], "little")
                if (
                    header_length > plan.bounds.maximum_metadata_bytes
                    or 8 + header_length > item.size
                ):
                    errors.append(
                        ScanError(
                            logical_path=item.logical_path,
                            error_code="MALFORMED_SAFETENSORS_HEADER",
                            message="Safetensors-like header length is invalid or exceeds bounds.",
                            recoverable=False,
                        )
                    )
        elif suffix == ".gguf":
            format_structure_supported = True
            if len(content) < 8 or not content.startswith(b"GGUF"):
                errors.append(
                    ScanError(
                        logical_path=item.logical_path,
                        error_code="MALFORMED_GGUF_PREFIX",
                        message="GGUF-like file has a missing or truncated magic prefix.",
                        recoverable=False,
                    )
                )
        elif suffix == ".zip" or lower_name.endswith(".archive-manifest.json"):
            format_structure_supported = True
        item_methods = set(plan.methods)
        if (
            InspectionMethod.FORMAT_STRUCTURE_INSPECTION in item_methods
            and not format_structure_supported
        ):
            item_methods.remove(InspectionMethod.FORMAT_STRUCTURE_INSPECTION)
            unsupported.append(
                UnsupportedItem(
                    logical_path=item.logical_path,
                    reason="Built-in scanner has no structure parser for this file type.",
                    mandatory=item.logical_path in plan.scope.mandatory_paths,
                )
            )
        if suffix != ".zip" and not lower_name.endswith(".archive-manifest.json"):
            item_methods.discard(InspectionMethod.ARCHIVE_STRUCTURE_INSPECTION)
        manifest_like = lower_name in {"manifest.json", "model-index.json"} or lower_name.endswith(
            ".index.json"
        )
        dependency_like = lower_name in {
            "requirements.txt",
            "pyproject.toml",
            "package.json",
            "environment.yml",
            "environment.yaml",
        }
        if not manifest_like:
            item_methods.discard(InspectionMethod.MANIFEST_INSPECTION)
        if not dependency_like:
            item_methods.discard(InspectionMethod.DEPENDENCY_MANIFEST_INSPECTION)
        methods = sorted(item_methods, key=lambda x: x.value)
        coverage_items.append(
            CoverageItem(
                logical_path=item.logical_path,
                declared_bytes=item.size,
                inspected_bytes=len(content),
                methods=methods,
                status=CoverageItemStatus.INSPECTED,
                payload_read=bool(content),
                rationale=None if full else "Only a bounded prefix was inspected.",
            )
        )
        lower = content.lower()

        if manifest_like and suffix == ".json":
            try:
                manifest = json.loads(content.decode("utf-8"))
                if not isinstance(manifest, dict):
                    raise ValueError("manifest root is not an object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                findings.append(
                    _indicator(
                        FindingClassification.INCONSISTENT_MANIFEST,
                        FindingSeverity.MEDIUM,
                        FindingConfidence.HIGH,
                        FindingExploitability.NOT_ESTABLISHED,
                        item,
                        content[:64],
                        scanner.scanner_id,
                        execution_id,
                        subject.identity_digest,
                        label="malformed-or-inconsistent-manifest",
                    )
                )
        if dependency_like:
            findings.append(
                _indicator(
                    FindingClassification.DEPENDENCY_MANIFEST_PRESENT,
                    FindingSeverity.INFO,
                    FindingConfidence.CONFIRMED,
                    FindingExploitability.NOT_APPLICABLE,
                    item,
                    lower_name.encode("utf-8"),
                    scanner.scanner_id,
                    execution_id,
                    subject.identity_digest,
                    label="dependency-manifest-present",
                )
            )

        if suffix in PICKLE_EXTENSIONS or content.startswith(b"\x80"):
            findings.append(
                _indicator(
                    FindingClassification.UNSAFE_SERIALIZATION_FORMAT,
                    FindingSeverity.HIGH,
                    FindingConfidence.HIGH,
                    FindingExploitability.REQUIRES_UNSAFE_LOADER,
                    item,
                    content[:16] or suffix.encode(),
                    scanner.scanner_id,
                    execution_id,
                    subject.identity_digest,
                    label="unsafe-serialization-format-indicator",
                )
            )
        if suffix in SCRIPT_EXTENSIONS:
            findings.append(
                _indicator(
                    FindingClassification.SCRIPT_CONTENT_PRESENT,
                    FindingSeverity.MEDIUM,
                    FindingConfidence.CONFIRMED,
                    FindingExploitability.REQUIRES_USER_ACTION,
                    item,
                    content[:64] or suffix.encode(),
                    scanner.scanner_id,
                    execution_id,
                    subject.identity_digest,
                    label="script-file-type-indicator",
                )
            )
        if suffix in NATIVE_EXTENSIONS or content.startswith((b"\x7fELF", b"MZ")):
            findings.append(
                _indicator(
                    FindingClassification.NATIVE_BINARY_PRESENT,
                    FindingSeverity.HIGH,
                    FindingConfidence.HIGH,
                    FindingExploitability.DIRECTLY_EXECUTABLE,
                    item,
                    content[:16],
                    scanner.scanner_id,
                    execution_id,
                    subject.identity_digest,
                    label="native-binary-magic-indicator",
                )
            )
        if lower_name in {"setup.py", "setup.cfg", "pyproject.toml", "makefile"}:
            findings.append(
                _indicator(
                    FindingClassification.INSTALL_OR_BUILD_SCRIPT_PRESENT,
                    FindingSeverity.MEDIUM,
                    FindingConfidence.CONFIRMED,
                    FindingExploitability.REQUIRES_USER_ACTION,
                    item,
                    lower_name.encode(),
                    scanner.scanner_id,
                    execution_id,
                    subject.identity_digest,
                    label="install-or-build-script-name",
                )
            )
        patterns = [
            (
                rb"begin (?:rsa |ec |openssh )?private key",
                FindingClassification.PRIVATE_KEY_MATERIAL_PATTERN,
                FindingSeverity.CRITICAL,
                "private-key-marker-redacted",
                True,
            ),
            (
                rb"x-amz-[a-z0-9_-]+",
                FindingClassification.SIGNED_URL_PATTERN,
                FindingSeverity.HIGH,
                "signed-url-marker-redacted",
                True,
            ),
            (
                rb"signature=[^\s&]+",
                FindingClassification.SIGNED_URL_PATTERN,
                FindingSeverity.HIGH,
                "signed-url-parameter-redacted",
                True,
            ),
            (
                rb"\bsubprocess\.(?:run|popen|call|check_call|check_output)\s*\(",
                FindingClassification.SUBPROCESS_EXECUTION_PATTERN,
                FindingSeverity.MEDIUM,
                "subprocess-pattern",
                False,
            ),
            (
                rb"\bos\.system\s*\(",
                FindingClassification.SHELL_EXECUTION_PATTERN,
                FindingSeverity.HIGH,
                "shell-execution-pattern",
                False,
            ),
            (
                rb"\b__import__\s*\(",
                FindingClassification.DYNAMIC_IMPORT_PATTERN,
                FindingSeverity.MEDIUM,
                "dynamic-import-pattern",
                False,
            ),
            (
                rb"\bpickle\.loads?\s*\(",
                FindingClassification.DESERIALIZATION_EXECUTION_PATTERN,
                FindingSeverity.HIGH,
                "unsafe-deserialization-pattern",
                False,
            ),
            (
                rb"(?:download_url|remote_code|endpoint|source_url)\s*[:=]\s*['\"]http://",
                FindingClassification.SUSPICIOUS_NETWORK_REFERENCE,
                FindingSeverity.LOW,
                "network-reference-pattern",
                False,
            ),
            (
                rb"(?:download_url|remote_code|endpoint|source_url)\s*[:=]\s*['\"]https://",
                FindingClassification.SUSPICIOUS_NETWORK_REFERENCE,
                FindingSeverity.LOW,
                "network-reference-pattern",
                False,
            ),
        ]
        for pattern, category, severity, label, sensitive in patterns:
            for match in re.finditer(pattern, lower):
                offset = match.start()
                matched = match.group(0)
                findings.append(
                    _indicator(
                        category,
                        severity,
                        (
                            FindingConfidence.HIGH
                            if category
                            in {
                                FindingClassification.PRIVATE_KEY_MATERIAL_PATTERN,
                                FindingClassification.SIGNED_URL_PATTERN,
                                FindingClassification.SHELL_EXECUTION_PATTERN,
                                FindingClassification.DESERIALIZATION_EXECUTION_PATTERN,
                            }
                            else FindingConfidence.HEURISTIC
                        ),
                        FindingExploitability.REQUIRES_USER_ACTION,
                        item,
                        matched,
                        scanner.scanner_id,
                        execution_id,
                        subject.identity_digest,
                        offset=offset,
                        label=label,
                        sensitive=sensitive,
                    )
                )
                if len(findings) >= plan.bounds.maximum_finding_count:
                    limit_hit = True
                    break
            if len(findings) >= plan.bounds.maximum_finding_count:
                break
        archive_findings, entry_count, archive_errors = _archive_findings(
            item, content, plan, scanner, execution_id, subject.identity_digest
        )
        manifest_archive_findings, manifest_entry_count, manifest_archive_errors = (
            _archive_manifest_findings(
                item, content, plan, scanner, execution_id, subject.identity_digest
            )
        )
        archive_findings.extend(manifest_archive_findings)
        entry_count += manifest_entry_count
        archive_errors.extend(manifest_archive_errors)
        archive_entries += entry_count
        errors.extend(archive_errors)
        for finding in archive_findings:
            if len(findings) < plan.bounds.maximum_finding_count:
                findings.append(finding)
            else:
                limit_hit = True

    coverage = build_coverage(
        subject,
        coverage_items,
        declared_files=plan.scope.declared_file_count,
        declared_bytes=plan.scope.declared_total_bytes,
        archive_entries_considered=archive_entries,
        archive_entries_inspected=archive_entries if not errors else 0,
        limitations=["Coverage is limited to the plan's declared files and methods."],
    )
    if errors:
        status = ScanExecutionStatus.FAILED
    elif limit_hit:
        status = ScanExecutionStatus.LIMIT_EXCEEDED
    elif coverage.status.value != "COMPLETE_FOR_DECLARED_SCOPE":
        status = ScanExecutionStatus.PARTIAL
    elif unsupported:
        status = ScanExecutionStatus.COMPLETED_WITH_LIMITATIONS
    else:
        status = ScanExecutionStatus.COMPLETED
    execution_body = {
        "schema": "omiv.security-scan-execution-record.v1",
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "scanner_id": scanner.scanner_id,
        "scanner_digest": scanner.scanner_digest,
        "configuration_digest": configuration_digest,
        "subject": subject.model_dump(mode="json"),
        "methods_executed": sorted(
            {method.value for item in coverage_items for method in item.methods}
        ),
        "files_considered": len(items),
        "files_inspected": sum(
            item.inspected_bytes > 0 or item.declared_bytes == 0 for item in coverage_items
        ),
        "bytes_considered": sum(item.size for item in items),
        "bytes_inspected": bytes_read,
        "payload_bytes_read": bool(bytes_read),
        "decompression_occurred": False,
        "code_execution_occurred": False,
        "network_access_occurred": False,
        "unsupported_items": [x.model_dump(mode="json") for x in unsupported],
        "errors": [x.model_dump(mode="json") for x in errors],
        "status": status.value,
        "raw_result_references": [],
        "limitations": [
            "Static bounded inspection does not establish runtime safety or universal artifact "
            "safety.",
            "No artifact code was executed and no network access occurred.",
        ],
    }
    execution_id = "scan_exec_" + canonical_sha256(execution_body)[:32]
    execution = SecurityScanExecutionRecord.model_validate(
        {
            **execution_body,
            "execution_id": execution_id,
            "execution_digest": canonical_sha256({**execution_body, "execution_id": execution_id}),
        }
    )
    rebound_findings: list[SecurityFinding] = []
    for finding in findings:
        finding_body = finding.model_dump(mode="json", by_alias=True)
        finding_body.pop("finding_id")
        finding_body.pop("finding_digest")
        finding_body["scan_execution_id"] = execution_id
        rebound_findings.append(
            SecurityFinding.model_validate(
                identified(finding_body, "finding_id", "security_finding_", "finding_digest")
            )
        )
    ordered_findings = sorted(rebound_findings, key=lambda x: x.finding_id)
    bundle_body = {
        "schema": "omiv.security-evidence-bundle.v1",
        "subject": subject.model_dump(mode="json"),
        "inspection_plan": plan.model_dump(mode="json", by_alias=True),
        "scanner_identities": [scanner.model_dump(mode="json", by_alias=True)],
        "execution_records": [execution.model_dump(mode="json", by_alias=True)],
        "findings": [x.model_dump(mode="json", by_alias=True) for x in ordered_findings],
        "coverage": coverage.model_dump(mode="json", by_alias=True),
        "unsupported_items": [x.model_dump(mode="json") for x in unsupported],
        "scan_errors": [x.model_dump(mode="json") for x in errors],
        "evidence_references": [],
        "policy_references": [],
        "limitations": [
            "No findings does not prove absence of vulnerabilities.",
            "Static inspection does not establish runtime safety, behavior, integrity, or "
            "fidelity.",
        ],
    }
    return SecurityEvidenceBundle.model_validate(
        identified(bundle_body, "bundle_id", "security_bundle_", "bundle_digest")
    )
