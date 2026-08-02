"""Safe bounded local inventory and streaming byte hashing."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.payload_integrity.building import artifact_set_digest, identified
from omiv.payload_integrity.models import (
    ArtifactRole,
    CompletionState,
    Coverage,
    FindingKind,
    ObservedPayloadManifest,
    PayloadFileRecord,
    PayloadHashExecutionRecord,
    PayloadInventoryPlan,
    PrimaryContentDigest,
    RootMode,
)
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path


@dataclass(frozen=True)
class _Entry:
    path: Path
    logical: str
    size: int
    identity: tuple[int, int] | None
    stability: tuple[int, int, int]


def _identity(value: os.stat_result) -> tuple[int, int] | None:
    dev, ino = getattr(value, "st_dev", 0), getattr(value, "st_ino", 0)
    return (int(dev), int(ino)) if dev and ino else None


def _stability(value: os.stat_result) -> tuple[int, int, int]:
    return (
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", 0)),
        int(getattr(value, "st_ctime_ns", 0)),
    )


def _inventory(root: Path, plan: PayloadInventoryPlan) -> tuple[list[_Entry], list[str]]:
    root_stat = root.lstat()
    if stat.S_ISLNK(root_stat.st_mode):
        raise OmivInputError("payload root must not be a symlink")
    if plan.root_mode == RootMode.SINGLE_FILE_ROOT:
        if not stat.S_ISREG(root_stat.st_mode):
            raise OmivInputError("SINGLE_FILE_ROOT requires a regular file")
        assert plan.single_file_logical_name is not None
        _enforce_plan_path_limits(plan.single_file_logical_name, plan)
        return [
            _Entry(
                root,
                validate_portable_path(plan.single_file_logical_name),
                root_stat.st_size,
                _identity(root_stat),
                _stability(root_stat),
            )
        ], []
    if not stat.S_ISDIR(root_stat.st_mode):
        raise OmivInputError("DIRECTORY_ROOT requires a directory")
    entries: list[_Entry] = []
    unsupported: list[str] = []
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > plan.limits.maximum_depth:
            raise OmivInputError("LIMIT_EXCEEDED:DIRECTORY_DEPTH")
        try:
            children = sorted(os.scandir(current), key=lambda x: os.fsencode(x.name), reverse=True)
        except OSError as exc:
            raise OmivInputError("payload directory is inaccessible") from exc
        for child in children:
            relative = Path(child.path).relative_to(root).as_posix()
            try:
                validate_portable_path(relative)
                _enforce_plan_path_limits(relative, plan)
                info = child.stat(follow_symlinks=False)
            except (OSError, UnicodeError, ValueError) as exc:
                raise OmivInputError("unsafe or inaccessible payload path") from exc
            if stat.S_ISDIR(info.st_mode):
                stack.append((Path(child.path), depth + 1))
                continue
            if stat.S_ISREG(info.st_mode):
                entries.append(
                    _Entry(
                        Path(child.path), relative, info.st_size, _identity(info), _stability(info)
                    )
                )
                if len(entries) > plan.limits.maximum_files:
                    raise OmivInputError("LIMIT_EXCEEDED:FILE_COUNT")
            else:
                unsupported.append(relative)
    validate_path_set(tuple(x.logical for x in entries) + tuple(unsupported))
    metadata = sum(len(x.logical.encode()) + 192 for x in entries)
    if metadata > plan.limits.maximum_metadata_bytes:
        raise OmivInputError("LIMIT_EXCEEDED:METADATA_BYTES")
    return sorted(entries, key=lambda x: x.logical.encode()), sorted(
        unsupported, key=lambda x: x.encode()
    )


def _enforce_plan_path_limits(path: str, plan: PayloadInventoryPlan) -> None:
    if len(path) > plan.limits.maximum_path_length:
        raise OmivInputError("LIMIT_EXCEEDED:PATH_LENGTH")
    if any(len(component) > plan.limits.maximum_component_length for component in path.split("/")):
        raise OmivInputError("LIMIT_EXCEEDED:PATH_COMPONENT_LENGTH")


def _hash_file(
    entry: _Entry, chunk_size: int
) -> tuple[PrimaryContentDigest, int, list[FindingKind]]:
    findings: list[FindingKind] = []
    before_path = entry.path.lstat()
    if not stat.S_ISREG(before_path.st_mode):
        return (
            PrimaryContentDigest(value=hashlib.sha256(b"").hexdigest()),
            0,
            [FindingKind.PATH_REBOUND_DURING_OBSERVATION],
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(entry.path, flags)
        opened = os.fstat(descriptor)
        if entry.identity is not None and _identity(opened) != entry.identity:
            findings.append(FindingKind.PATH_REBOUND_DURING_OBSERVATION)
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(descriptor, chunk_size)
            if not block:
                break
            digest.update(block)
            count += len(block)
        after_open = os.fstat(descriptor)
        if (
            _identity(after_open) != _identity(opened)
            or _stability(after_open) != _stability(opened)
            or count != opened.st_size
        ):
            findings.append(FindingKind.OPENED_FILE_CHANGED_DURING_HASH)
        try:
            after_path = entry.path.lstat()
        except OSError:
            findings.append(FindingKind.PATH_REBOUND_DURING_OBSERVATION)
        else:
            if not stat.S_ISREG(after_path.st_mode) or (
                _identity(opened) is not None and _identity(after_path) != _identity(opened)
            ):
                findings.append(FindingKind.PATH_REBOUND_DURING_OBSERVATION)
        return PrimaryContentDigest(value=digest.hexdigest()), count, list(dict.fromkeys(findings))
    except OSError as exc:
        raise OmivInputError(
            f"local payload hashing failed for canonical path {entry.logical}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def observe_payload(
    root: Path,
    plan: PayloadInventoryPlan,
    *,
    roles: dict[str, tuple[ArtifactRole, str | None]] | None = None,
    available_at: str = "NOT_RECORDED",
    observed_at: str = "NOT_RECORDED",
) -> tuple[ObservedPayloadManifest, PayloadHashExecutionRecord]:
    root_before = root.lstat()
    initial, unsupported = _inventory(root, plan)
    excluded = set(plan.exclusions)
    records: list[PayloadFileRecord] = []
    findings: list[FindingKind] = []
    excluded_paths: list[str] = []
    hardlinks: list[str] = []
    unstable: list[str] = []
    identities: dict[tuple[int, int], str] = {}
    hardlink_detection_available = all(entry.identity is not None for entry in initial)
    if not hardlink_detection_available:
        findings.append(FindingKind.HARDLINK_DETECTION_UNAVAILABLE)
    total_discovered = sum(x.size for x in initial)
    hashed_bytes = 0
    for entry in initial:
        if entry.logical in excluded:
            excluded_paths.append(entry.logical)
            continue
        if entry.identity is not None and entry.identity in identities:
            hardlinks.append(entry.logical)
            findings.append(FindingKind.HARDLINK_ALIAS_REJECTED)
            continue
        if entry.identity is not None:
            identities[entry.identity] = entry.logical
        digest, count, local_findings = _hash_file(entry, plan.chunk_size)
        findings.extend(local_findings)
        if local_findings:
            unstable.append(entry.logical)
        if (
            plan.limits.maximum_logical_bytes is not None
            and hashed_bytes + count > plan.limits.maximum_logical_bytes
        ):
            raise OmivInputError("LIMIT_EXCEEDED:LOGICAL_BYTES")
        hashed_bytes += count
        role, detail = (roles or {}).get(entry.logical, (ArtifactRole.ABSENT_ROLE, None))
        records.append(
            PayloadFileRecord(
                path=entry.logical,
                logical_file_kind="regular.file",
                size=count,
                primary_content_digest=digest,
                artifact_role=role,
                declared_role_detail=detail,
                limitations=(),
            )
        )
    final, final_unsupported = _inventory(root, plan)
    root_after = root.lstat()
    initial_map = {x.logical: (x.size, x.identity) for x in initial}
    final_map = {x.logical: (x.size, x.identity) for x in final}
    if (
        initial_map != final_map
        or unsupported != final_unsupported
        or _identity(root_before) != _identity(root_after)
        or stat.S_IFMT(root_before.st_mode) != stat.S_IFMT(root_after.st_mode)
    ):
        findings.append(FindingKind.ROOT_CHANGED_DURING_OBSERVATION)
    coverage = Coverage(
        discovered_regular_files=len(initial),
        hashed_files=len(records),
        discovered_bytes=total_discovered,
        hashed_bytes=hashed_bytes,
        excluded_paths=tuple(sorted(excluded_paths)),
        unsupported_paths=tuple(unsupported),
        rejected_hardlink_paths=tuple(sorted(hardlinks)),
        unstable_paths=tuple(sorted(unstable)),
        hardlink_detection=("AVAILABLE" if hardlink_detection_available else "UNAVAILABLE"),
    )
    completion = (
        CompletionState.COMPLETE_FOR_DECLARED_LOCAL_SCOPE
        if not findings
        and not excluded_paths
        and not unsupported
        and len(records) == len(initial)
        and hashed_bytes == total_discovered
        else CompletionState.INCOMPLETE
    )
    execution_body = {
        "schema": "omiv.payload-hash-execution-record.v1",
        "tool_id": "omiv.payload.local-hasher.v1",
        "tool_version": "1",
        "implementation_digest": canonical_sha256(
            {"implementation": "omiv.payload.local-hasher.v1"}
        ),
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "subject_id": plan.subject.subject_id,
        "root_mode": plan.root_mode.value,
        "primary_digest_algorithm": "SHA256",
        "chunk_size": plan.chunk_size,
        "limits": plan.limits.model_dump(mode="json"),
        "available_at": available_at,
        "observed_at": observed_at,
        "result_reference_status": "LINKED_DOWNSTREAM_BY_MANIFEST",
        "coverage": coverage.model_dump(mode="json"),
        "local_path_disclosure": "OMITTED_FROM_CANONICAL_RECORD",
        "network_use": "NONE",
        "model_deserialization": "NOT_PERFORMED",
        "model_execution": "NOT_PERFORMED",
        "limitations": [
            "Filesystem race resistance is strongest available locally; verification is not "
            "continuously TOCTOU-free."
        ],
    }
    execution = PayloadHashExecutionRecord.model_validate(
        identified(execution_body, "execution_id", "payload_execution_", "execution_digest")
    )
    ordered = tuple(sorted(records, key=lambda x: x.path.encode()))
    manifest_body = {
        "schema": "omiv.observed-payload-manifest.v1",
        "subject": plan.subject.model_dump(mode="json", by_alias=True),
        "root_mode": plan.root_mode.value,
        "logical_root": plan.logical_root,
        "plan_id": plan.plan_id,
        "plan_digest": plan.plan_digest,
        "files": [x.model_dump(mode="json") for x in ordered],
        "artifact_set_payload_digest": artifact_set_digest(
            plan.root_mode, plan.logical_root, ordered
        ),
        "coverage": coverage.model_dump(mode="json"),
        "findings": sorted({x.value for x in findings}),
        "completion_state": completion.value,
        "observation_provenance": "SYSTEM_OBSERVED",
        "execution_id": execution.execution_id,
        "execution_digest": execution.execution_digest,
        "available_at": available_at,
        "observed_at": observed_at,
        "limitations": [
            "COMPLETE means complete only for the declared stable local inventory scope.",
            "Local byte identity does not establish remote completeness, semantics, authenticity, "
            "or safety.",
        ],
    }
    manifest = ObservedPayloadManifest.model_validate(
        identified(manifest_body, "manifest_id", "observed_payload_", "manifest_digest")
    )
    return manifest, execution
