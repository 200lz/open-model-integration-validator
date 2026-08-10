"""Deterministic baseline preservation discovery for the Phase 6B release audit."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.external_artifacts import (
    ExternalArtifactStatus,
    expected_external_artifact,
    observe_external_artifact,
)

BASELINE_REVISION = "944dafd1d3667e21bbeda6bd7b01e60e651fe7c3"
PRE_PHASE6A_REVISION = "e2a80e60be70c275dbefd8fda7ded7f65f4e933d"
PRE_PHASE5A_REVISION = "cfdd89ece74219aea96df0ce386f8bb9a1f0458f"

# The Phase 6A release audit counted every tracked file under these established
# canonical/generated roots. Phase 6B retains that whole-tree rule, adds the new
# Phase 6A root, and explicitly includes the repository schema registry.
PHASE6A_RELEASE_ROOTS = frozenset(
    {
        "articles",
        "attestations",
        "comparisons",
        "continuous-trust",
        "custody",
        "fixtures",
        "governance",
        "inventories",
        "mappings",
        "passports",
        "policies",
        "provenance",
        "reports",
        "runtime",
        "security",
        "snapshots",
        "trust",
        "validations",
    }
)
EXHAUSTIVE_ROOTS = PHASE6A_RELEASE_ROOTS | {"payload-integrity", "schemas"}


@dataclass(frozen=True)
class PreservationEntry:
    relative_path: str
    git_blob_identity: str
    baseline_size: int
    baseline_sha256: str
    current_size: int | None
    current_sha256: str | None
    phase_root_classification: str
    inclusion_reason: str


@dataclass(frozen=True)
class ExclusionEntry:
    relative_path: str
    git_blob_identity: str
    baseline_size: int
    reason: str


@dataclass(frozen=True)
class ExternalArtifactAudit:
    relative_path: str
    expected_identity_status: str
    availability_status: str
    expected_size_bytes: int
    expected_sha256: str
    observed_size_bytes: int | None
    observed_sha256: str | None


@dataclass(frozen=True)
class PreservationAudit:
    baseline_revision: str
    inventory: tuple[PreservationEntry, ...]
    exclusions: tuple[ExclusionEntry, ...]
    path_set_digest: str
    inventory_digest: str
    prior_artifact_indexes: tuple[str, ...]
    prior_index_member_count: int
    phase6a_generated_count: int
    missing_prior_index_members: tuple[str, ...]
    missing_phase6a_generated_paths: tuple[str, ...]
    changed_or_missing_paths: tuple[str, ...]
    external_artifacts: tuple[ExternalArtifactAudit, ...]

    def json_value(self) -> dict[str, Any]:
        return {
            "schema": "omiv.phase6b-preservation-audit-temporary.v1",
            "baseline_revision": self.baseline_revision,
            "methodology": {
                "included_roots": sorted(EXHAUSTIVE_ROOTS),
                "rule": (
                    "Every baseline blob below an established canonical/generated root, plus "
                    "the schema registry; no extension filter."
                ),
                "path_set_digest_domain": "omiv.phase6b-prior-artifact-path-set.v1",
            },
            "counts": {
                "inventory": len(self.inventory),
                "exclusions": len(self.exclusions),
                "prior_artifact_indexes": len(self.prior_artifact_indexes),
                "prior_index_members": self.prior_index_member_count,
                "phase6a_generated": self.phase6a_generated_count,
            },
            "path_set_digest": self.path_set_digest,
            "inventory_digest": self.inventory_digest,
            "prior_artifact_indexes": list(self.prior_artifact_indexes),
            "missing_prior_index_members": list(self.missing_prior_index_members),
            "missing_phase6a_generated_paths": list(self.missing_phase6a_generated_paths),
            "changed_or_missing_paths": list(self.changed_or_missing_paths),
            "external_artifacts": [asdict(item) for item in self.external_artifacts],
            "inventory": [asdict(item) for item in self.inventory],
            "exclusions": [asdict(item) for item in self.exclusions],
        }


def audit_baseline(repository: Path, revision: str = BASELINE_REVISION) -> PreservationAudit:
    blobs = _git_tree(repository, revision)
    indexes = tuple(
        sorted(
            path
            for path in blobs
            if path.endswith("artifact-index.json") and path.split("/", 1)[0] in EXHAUSTIVE_ROOTS
        )
    )
    index_members: dict[str, tuple[int, str]] = {}
    for path in indexes:
        value = json.loads(_git_blob(repository, blobs[path][0]))
        for item in value.get("entries", value.get("artifacts", [])):
            member = (
                item
                if isinstance(item, str)
                else item.get("path") or item.get("artifact_path") or item.get("relative_path")
            )
            if not isinstance(member, str) or isinstance(item, str):
                continue
            size = item.get("size", item.get("size_bytes"))
            digest = item.get("sha256", item.get("digest"))
            if not isinstance(size, int) or not isinstance(digest, str):
                continue
            declared = (size, digest)
            if member in index_members and index_members[member] != declared:
                raise ValueError(f"conflicting prior index declarations for {member}")
            index_members[member] = declared
    included_paths = tuple(
        sorted(
            {
                *(path for path in blobs if path.split("/", 1)[0] in EXHAUSTIVE_ROOTS),
                *index_members,
            },
            key=lambda value: value.encode(),
        )
    )
    entries = []
    changed = []
    external_artifacts = []
    for path in included_paths:
        if path in blobs:
            blob, baseline_size = blobs[path]
            baseline = _git_blob(repository, blob)
            baseline_sha256 = hashlib.sha256(baseline).hexdigest()
            inclusion_reason = (
                "SCHEMA_REGISTRY"
                if path.startswith("schemas/")
                else "ESTABLISHED_CANONICAL_GENERATED_ROOT"
            )
        else:
            blob = "NOT_TRACKED_AT_BASELINE"
            baseline_size, baseline_sha256 = index_members[path]
            baseline = None
            inclusion_reason = "PRIOR_ARTIFACT_INDEX_MEMBER_EXTERNAL_TO_GIT_TREE"
        current_path = repository / path
        expected_external = expected_external_artifact(path)
        if expected_external is not None:
            if (
                baseline_size != expected_external.size_bytes
                or baseline_sha256 != expected_external.sha256
            ):
                raise ValueError(f"external artifact expected identity mismatch: {path}")
            observation = observe_external_artifact(repository, expected_external)
            current_size = observation.observed_size_bytes
            current_sha256 = observation.observed_sha256
            external_artifacts.append(
                ExternalArtifactAudit(
                    relative_path=path,
                    expected_identity_status=expected_external.identity_status.value,
                    availability_status=observation.status.value,
                    expected_size_bytes=expected_external.size_bytes,
                    expected_sha256=expected_external.sha256,
                    observed_size_bytes=current_size,
                    observed_sha256=current_sha256,
                )
            )
            if observation.status == ExternalArtifactStatus.INVALID:
                changed.append(path)
        else:
            current = current_path.read_bytes() if current_path.is_file() else b""
            current_size = len(current)
            current_sha256 = hashlib.sha256(current).hexdigest()
            if (
                not current_path.is_file()
                or current_size != baseline_size
                or current_sha256 != baseline_sha256
                or (baseline is not None and baseline != current)
            ):
                changed.append(path)
        classification = _classification(path)
        entries.append(
            PreservationEntry(
                relative_path=path,
                git_blob_identity=blob,
                baseline_size=baseline_size,
                baseline_sha256=baseline_sha256,
                current_size=current_size,
                current_sha256=current_sha256,
                phase_root_classification=classification,
                inclusion_reason=inclusion_reason,
            )
        )
    exclusions = tuple(
        ExclusionEntry(path, blobs[path][0], blobs[path][1], _exclusion_reason(path))
        for path in sorted(set(blobs) - set(included_paths), key=lambda value: value.encode())
    )
    path_set_digest = canonical_sha256(
        {"domain": "omiv.phase6b-prior-artifact-path-set.v1", "paths": included_paths}
    )
    inventory_body = [asdict(item) for item in entries]
    inventory_digest = canonical_sha256(
        {"domain": "omiv.phase6b-prior-artifact-inventory.v1", "entries": inventory_body}
    )
    phase6a_paths = set(_git_diff_names(repository, PRE_PHASE6A_REVISION, revision))
    phase6a_generated = {
        path
        for path in phase6a_paths
        if path.startswith("payload-integrity/") or path.startswith("reports/payload-integrity/")
    }
    return PreservationAudit(
        baseline_revision=revision,
        inventory=tuple(entries),
        exclusions=exclusions,
        path_set_digest=path_set_digest,
        inventory_digest=inventory_digest,
        prior_artifact_indexes=indexes,
        prior_index_member_count=len(index_members),
        phase6a_generated_count=len(phase6a_generated),
        missing_prior_index_members=tuple(sorted(set(index_members) - set(included_paths))),
        missing_phase6a_generated_paths=tuple(sorted(phase6a_generated - set(included_paths))),
        changed_or_missing_paths=tuple(changed),
        external_artifacts=tuple(external_artifacts),
    )


def reconstruct_reported_counts(repository: Path) -> dict[str, int]:
    pre6a = _git_tree(repository, PRE_PHASE6A_REVISION)
    phase6a_release_count = sum(path.split("/", 1)[0] in PHASE6A_RELEASE_ROOTS for path in pre6a)
    changed = _git_diff_names(repository, PRE_PHASE5A_REVISION, BASELINE_REVISION)
    excluded_roots = {"src", "tests", "docs", "tools"}
    excluded_files = {"README.md", ".gitignore", "pyproject.toml"}
    narrow_phase_count = sum(
        path.split("/", 1)[0] not in excluded_roots and path not in excluded_files
        for path in changed
    )
    return {
        "phase6a_release_audit_pre_phase6a": phase6a_release_count,
        "narrow_phase5a_through_phase6a_delta": narrow_phase_count,
        "exhaustive_phase6b_baseline": len(audit_baseline(repository).inventory),
    }


def _git_tree(repository: Path, revision: str) -> dict[str, tuple[str, int]]:
    raw = subprocess.check_output(["git", "ls-tree", "-r", "-l", "-z", revision], cwd=repository)
    result: dict[str, tuple[str, int]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        _mode, object_type, blob, raw_size = metadata.decode("ascii").split()
        if object_type != "blob":
            continue
        path = raw_path.decode("utf-8", errors="strict")
        result[path] = (blob, int(raw_size))
    return result


def _git_blob(repository: Path, blob: str) -> bytes:
    return subprocess.check_output(["git", "cat-file", "blob", blob], cwd=repository)


def _git_diff_names(repository: Path, before: str, after: str) -> tuple[str, ...]:
    raw = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", f"{before}..{after}"], cwd=repository
    )
    return tuple(item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item)


def _classification(path: str) -> str:
    root, _, rest = path.partition("/")
    if root == "schemas":
        return "SCHEMA_REGISTRY"
    phase_roots = {
        "passports": "PHASE_5A",
        "custody": "PHASE_5B",
        "attestations": "PHASE_5C",
        "trust": "PHASE_5D",
        "governance": "PHASE_5E",
        "security": "PHASE_5F",
        "runtime": "PHASE_5G",
        "continuous-trust": "PHASE_5H",
        "payload-integrity": "PHASE_6A",
    }
    if root == "reports":
        report_root = rest.split("/", 1)[0]
        return phase_roots.get(report_root, "PRE_PHASE_5_ASSOCIATED_REPORT")
    return phase_roots.get(root, "PRE_PHASE_5_CANONICAL_GENERATED")


def _exclusion_reason(path: str) -> str:
    root = path.split("/", 1)[0]
    if root == "src":
        return "IMPLEMENTATION_SOURCE_NOT_CANONICAL_GENERATED_ARTIFACT"
    if root == "tests":
        return "TEST_SOURCE_NOT_CANONICAL_GENERATED_ARTIFACT"
    if root == "tools":
        return "GENERATOR_TOOL_SOURCE_NOT_GENERATED_OUTPUT"
    if root == "docs" or path == "README.md":
        return "MUTABLE_RELEASE_DOCUMENTATION_NOT_CANONICAL_EVIDENCE"
    if root == "examples":
        return "DECLARATIVE_TOOL_INPUT_OUTSIDE_ESTABLISHED_CANONICAL_ROOTS"
    if path == "pyproject.toml":
        return "PROJECT_CONFIGURATION"
    if path == ".gitignore":
        return "VERSION_CONTROL_CONFIGURATION"
    return "IMPLEMENTATION_OR_PROJECT_FILE_OUTSIDE_ESTABLISHED_CANONICAL_ROOTS"
