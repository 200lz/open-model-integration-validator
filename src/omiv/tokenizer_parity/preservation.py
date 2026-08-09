"""Deterministic exhaustive Phase 6D baseline preservation discovery."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.quantization.preservation import EXHAUSTIVE_ROOTS as PHASE6C_ROOTS

BASELINE_REVISION = "d64cb7a9de54cf395db05ccd47b2788fb838a1ee"
EXHAUSTIVE_ROOTS = PHASE6C_ROOTS | {"quantization-fidelity"}


@dataclass(frozen=True)
class PreservationEntry:
    relative_path: str
    git_blob_identity: str
    baseline_size: int
    baseline_sha256: str
    current_size: int
    current_sha256: str
    classification: str
    inclusion_reason: str


@dataclass(frozen=True)
class ExclusionEntry:
    relative_path: str
    git_blob_identity: str
    baseline_size: int
    reason: str


def audit_baseline(repository: Path) -> dict[str, Any]:
    blobs = _tree(repository, BASELINE_REVISION)
    indexes = tuple(
        sorted(
            path
            for path in blobs
            if path.endswith("artifact-index.json") and path.split("/", 1)[0] in EXHAUSTIVE_ROOTS
        )
    )
    indexed: dict[str, tuple[int, str]] = {}
    for index_path in indexes:
        value = json.loads(_blob(repository, blobs[index_path][0]))
        for item in value.get("entries", value.get("artifacts", [])):
            if not isinstance(item, dict):
                continue
            path = item.get("path") or item.get("artifact_path") or item.get("relative_path")
            size = item.get("size", item.get("size_bytes"))
            digest = item.get("sha256", item.get("digest"))
            if (
                not isinstance(path, str)
                or not isinstance(size, int)
                or not isinstance(digest, str)
            ):
                continue
            identity = (size, digest)
            if path in indexed and indexed[path] != identity:
                raise ValueError(f"conflicting prior index declarations for {path}")
            indexed[path] = identity
    included = tuple(
        sorted(
            {
                *(path for path in blobs if path.split("/", 1)[0] in EXHAUSTIVE_ROOTS),
                *indexed,
            },
            key=lambda value: value.encode(),
        )
    )
    inventory: list[PreservationEntry] = []
    changed: list[str] = []
    missing: list[str] = []
    for path in included:
        if path in blobs:
            blob, size = blobs[path]
            baseline = _blob(repository, blob)
            digest = hashlib.sha256(baseline).hexdigest()
            reason = (
                "SCHEMA_REGISTRY"
                if path.startswith("schemas/")
                else "ESTABLISHED_CANONICAL_GENERATED_ROOT"
            )
        else:
            blob = "NOT_TRACKED_AT_BASELINE"
            size, digest = indexed[path]
            baseline = None
            reason = "PRIOR_ARTIFACT_INDEX_MEMBER_EXTERNAL_TO_GIT_TREE"
        current_path = repository / path
        current = current_path.read_bytes() if current_path.is_file() else b""
        current_digest = hashlib.sha256(current).hexdigest()
        if not current_path.is_file():
            missing.append(path)
        elif (
            len(current) != size
            or current_digest != digest
            or (baseline is not None and current != baseline)
        ):
            changed.append(path)
        inventory.append(
            PreservationEntry(
                relative_path=path,
                git_blob_identity=blob,
                baseline_size=size,
                baseline_sha256=digest,
                current_size=len(current),
                current_sha256=current_digest,
                classification=(
                    "PHASE_6C" if path.startswith("quantization-fidelity/") else "PRIOR_PHASE"
                ),
                inclusion_reason=reason,
            )
        )
    exclusions = tuple(
        ExclusionEntry(path, blobs[path][0], blobs[path][1], _exclusion_reason(path))
        for path in sorted(set(blobs) - set(included), key=lambda value: value.encode())
    )
    inventory_json = [asdict(item) for item in inventory]
    return {
        "schema": "omiv.phase6d-preservation-audit-temporary.v1",
        "baseline_revision": BASELINE_REVISION,
        "methodology": {
            "included_roots": sorted(EXHAUSTIVE_ROOTS),
            "rule": (
                "Every baseline blob under every established canonical/generated root, "
                "plus every prior artifact-index member, without an extension filter."
            ),
        },
        "counts": {
            "included": len(inventory),
            "excluded": len(exclusions),
            "prior_indexes": len(indexes),
            "prior_indexed_members": len(indexed),
        },
        "path_set_digest": canonical_sha256(
            {"domain": "omiv.phase6d-prior-artifact-path-set.v1", "paths": included}
        ),
        "inventory_digest": canonical_sha256(
            {"domain": "omiv.phase6d-prior-artifact-inventory.v1", "entries": inventory_json}
        ),
        "prior_artifact_indexes": indexes,
        "changed_paths": changed,
        "missing_paths": missing,
        "unexpected_omissions": sorted(set(indexed) - set(included)),
        "inventory": inventory_json,
        "exclusions": [asdict(item) for item in exclusions],
    }


def _tree(repository: Path, revision: str) -> dict[str, tuple[str, int]]:
    raw = subprocess.check_output(["git", "ls-tree", "-r", "-l", "-z", revision], cwd=repository)
    result: dict[str, tuple[str, int]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        _mode, kind, blob, raw_size = metadata.decode("ascii").split()
        if kind == "blob":
            result[raw_path.decode("utf-8", errors="strict")] = (blob, int(raw_size))
    return result


def _blob(repository: Path, blob: str) -> bytes:
    return subprocess.check_output(["git", "cat-file", "blob", blob], cwd=repository)


def _exclusion_reason(path: str) -> str:
    root = path.split("/", 1)[0]
    if root == "src":
        return "IMPLEMENTATION_SOURCE_NOT_CANONICAL_GENERATED_ARTIFACT"
    if root == "tests":
        return "TEST_SOURCE_NOT_CANONICAL_GENERATED_ARTIFACT"
    if root == "tools":
        return "GENERATOR_OR_AUDIT_TOOL_SOURCE_NOT_GENERATED_OUTPUT"
    if root == "docs" or path == "README.md":
        return "MUTABLE_RELEASE_DOCUMENTATION_NOT_CANONICAL_EVIDENCE"
    if root == "examples":
        return "DECLARATIVE_TOOL_INPUT_OUTSIDE_ESTABLISHED_CANONICAL_ROOTS"
    if path in {"pyproject.toml", ".gitignore"}:
        return "PROJECT_OR_VERSION_CONTROL_CONFIGURATION"
    return "IMPLEMENTATION_OR_PROJECT_FILE_OUTSIDE_ESTABLISHED_CANONICAL_ROOTS"
