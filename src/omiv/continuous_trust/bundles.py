"""Safe deterministic directory-form audit bundles and offline verification."""

from __future__ import annotations

import hashlib
import json
import stat
import unicodedata
from pathlib import Path

from pydantic import BaseModel

from omiv.continuous_trust.building import build_completeness, build_verification, identified
from omiv.continuous_trust.models import (
    MAX_BUNDLE_MEMBERS,
    MAX_BUNDLE_METADATA_BYTES,
    MAX_BUNDLE_TOTAL_BYTES,
    AuditBundleGap,
    AuditBundleManifest,
    AuditBundleMember,
    AuditBundleVerificationResult,
    BundlePurpose,
    ContinuousTrustArtifactIndex,
    TimelineCompleteness,
    normalized_portable_path,
)
from omiv.continuous_trust.schema import SCHEMA_MODELS
from omiv.errors import OmivInputError
from omiv.runtime.reporting import pretty_json as pretty_runtime_json
from omiv.safe_write import atomic_write_text


def _safe_relative(value: str) -> Path:
    try:
        normalized_portable_path(value)
    except ValueError as exc:
        raise OmivInputError("unsafe audit-bundle member path") from exc
    return Path(value)


def assert_acyclic_dependency_graph(edges: dict[str, set[str]]) -> None:
    """Reject a canonical dependency graph containing a direct or indirect cycle."""
    nodes = set(edges).union(*(set(values) for values in edges.values())) if edges else set()
    incoming = {node: 0 for node in nodes}
    for dependencies in edges.values():
        for dependency in dependencies:
            incoming[dependency] += 1
    ready = sorted(node for node, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        node = ready.pop(0)
        visited += 1
        for dependency in sorted(edges.get(node, set())):
            incoming[dependency] -= 1
            if incoming[dependency] == 0:
                ready.append(dependency)
                ready.sort()
    if visited != len(nodes):
        raise OmivInputError("canonical dependency graph contains a cycle")


def bundle_dependency_graph(manifest: AuditBundleManifest) -> dict[str, set[str]]:
    member_nodes = {f"member:{member.object_id}" for member in manifest.members}
    return {
        **{node: {"unsigned-manifest"} for node in member_nodes},
        "unsigned-manifest": {"signed-manifest-wrapper", "verification-result"},
        "signed-manifest-wrapper": {"artifact-index", "derived-report"},
        "verification-result": {"signed-verification-wrapper", "artifact-index", "derived-report"},
        "signed-verification-wrapper": {"artifact-index", "derived-report"},
    }


def build_bundle_manifest(
    purpose: BundlePurpose,
    subject: BaseModel,
    members: list[AuditBundleMember],
    exclusions: list[AuditBundleGap],
    *,
    start: int,
    end: int,
    completeness_policy_id: str,
    completeness_policy_digest: str,
) -> AuditBundleManifest:
    if len(members) > MAX_BUNDLE_MEMBERS:
        raise OmivInputError("LIMIT_EXCEEDED:BUNDLE_MEMBERS")
    if sum(member.size for member in members) > MAX_BUNDLE_TOTAL_BYTES:
        raise OmivInputError("LIMIT_EXCEEDED:BUNDLE_TOTAL_BYTES")
    body = {
        "schema": "omiv.audit-bundle-manifest.v1",
        "purpose": purpose.value,
        "subject": subject.model_dump(mode="json", by_alias=True),
        "range_start_sequence": start,
        "range_end_sequence": end,
        "members": [
            x.model_dump(mode="json", by_alias=True)
            for x in sorted(members, key=lambda x: x.relative_path)
        ],
        "exclusions": [
            x.model_dump(mode="json", by_alias=True)
            for x in sorted(exclusions, key=lambda x: x.category)
        ],
        "completeness_policy_id": completeness_policy_id,
        "completeness_policy_digest": completeness_policy_digest,
        "model_payload_included": False,
        "limitations": [
            "Directory bundle contains canonical references, not model payloads.",
            "A valid bundle signature does not prove every contained claim.",
        ],
    }
    if len(json.dumps(body, sort_keys=True).encode("utf-8")) > MAX_BUNDLE_METADATA_BYTES:
        raise OmivInputError("LIMIT_EXCEEDED:BUNDLE_METADATA_BYTES")
    manifest = AuditBundleManifest.model_validate(
        identified(body, "bundle_id", "audit_bundle_", "manifest_digest")
    )
    assert_acyclic_dependency_graph(bundle_dependency_graph(manifest))
    return manifest


def materialize_bundle(root: Path, manifest: AuditBundleManifest, sources: dict[str, Path]) -> None:
    root.mkdir(parents=True, exist_ok=False)
    for member in manifest.members:
        relative = _safe_relative(member.relative_path)
        source = sources.get(member.relative_path)
        if source is None or source.is_symlink() or not source.is_file():
            raise OmivInputError("bundle source is missing, unsafe, or not a regular file")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        if len(data) != member.size or hashlib.sha256(data).hexdigest() != member.sha256:
            raise OmivInputError("bundle source size or digest mismatch")
        target.write_bytes(data)
    atomic_write_text(root / "manifest.json", pretty_runtime_json(manifest))
    atomic_write_text(
        root / "README.md",
        "# OMIV offline audit bundle\n\nModel payload included: NO\n"
        "Continuous monitoring: NOT_IMPLEMENTED\n",
    )


def verify_bundle_directory(
    root: Path, manifest: AuditBundleManifest
) -> AuditBundleVerificationResult:
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("bundle root must be a real directory")
    declared = {x.relative_path: x for x in manifest.members}
    assert_acyclic_dependency_graph(bundle_dependency_graph(manifest))
    if sum(member.size for member in manifest.members) > MAX_BUNDLE_TOTAL_BYTES:
        raise OmivInputError("LIMIT_EXCEEDED:BUNDLE_TOTAL_BYTES")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise OmivInputError("bundle manifest is missing or unsafe")
    supplied_manifest = AuditBundleManifest.model_validate_json(manifest_path.read_text())
    if supplied_manifest != manifest:
        raise OmivInputError("supplied bundle manifest does not match bundle manifest file")
    allowed = set(declared) | {"manifest.json", "README.md"}
    actual: set[str] = set()
    normalized_actual: set[str] = set()
    canonical_ids: set[str] = set()
    timeline_states: list[TimelineCompleteness] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise OmivInputError("symlink is not allowed in an audit bundle")
        mode = path.stat().st_mode
        if not path.is_file():
            if not path.is_dir():
                raise OmivInputError("special files are not allowed in an audit bundle")
            continue
        if not stat.S_ISREG(mode):
            raise OmivInputError("bundle member is not a regular file")
        relative = path.relative_to(root).as_posix()
        _safe_relative(relative)
        collision_key = unicodedata.normalize("NFC", relative).casefold()
        if collision_key in normalized_actual:
            raise OmivInputError("duplicate normalized audit-bundle member path")
        normalized_actual.add(collision_key)
        actual.add(relative)
        if relative not in allowed:
            raise OmivInputError(f"undeclared bundle member: {relative}")
        if relative in declared:
            expected = declared[relative]
            data = path.read_bytes()
            if len(data) != expected.size or hashlib.sha256(data).hexdigest() != expected.sha256:
                raise OmivInputError(f"bundle member mismatch: {relative}")
            parsed = json.loads(data)
            if parsed.get("schema") != expected.schema_id:
                raise OmivInputError("bundle member schema mismatch")
            model = SCHEMA_MODELS.get(expected.schema_id)
            if model is None:
                raise OmivInputError(f"unknown bundle member schema: {expected.schema_id}")
            try:
                canonical = model.model_validate(parsed)
            except ValueError as exc:
                raise OmivInputError(f"invalid canonical bundle member: {relative}") from exc
            values = {str(v) for k, v in parsed.items() if k.endswith("_id") and isinstance(v, str)}
            if expected.object_id not in values:
                raise OmivInputError("bundle member canonical identity mismatch")
            canonical_values = canonical.model_dump(mode="json", by_alias=True)
            owned_digests = {
                str(value)
                for key, value in canonical_values.items()
                if key.endswith("_digest")
                and key
                not in {
                    "evaluation_context_digest",
                    "policy_set_digest",
                    "trust_bundle_digest",
                }
                and isinstance(value, str)
            }
            if owned_digests and expected.object_digest not in owned_digests:
                raise OmivInputError("bundle member canonical digest mismatch")
            if expected.schema_id == "omiv.trust-timeline.v1":
                timeline_states.append(TimelineCompleteness(parsed["completeness"]))
            if expected.object_id in canonical_ids:
                raise OmivInputError("duplicate canonical identity in bundle")
            canonical_ids.add(expected.object_id)
    missing = set(declared) - actual
    if missing:
        raise OmivInputError(f"missing bundle members: {sorted(missing)}")
    completeness = build_completeness(manifest, timeline_states=timeline_states)
    snapshots = [x.object_id for x in manifest.members if x.schema_id == "omiv.trust-snapshot.v1"]
    timelines = [x.object_id for x in manifest.members if x.schema_id == "omiv.trust-timeline.v1"]
    return build_verification(manifest, completeness, snapshots, timelines)


def verify_continuous_trust_index(
    index: ContinuousTrustArtifactIndex, root: Path
) -> ContinuousTrustArtifactIndex:
    indexed = {x.relative_path: x for x in index.entries}
    actual = {
        p.relative_to(root).as_posix()
        for base in (root / "continuous-trust", root / "reports" / "continuous-trust")
        if base.exists()
        for p in base.rglob("*")
        if p.is_file() and p != root / "continuous-trust" / "artifact-index.json"
    }
    if set(indexed) != actual:
        raise OmivInputError("continuous trust artifact index inventory mismatch")
    for relative, entry in indexed.items():
        data = (root / relative).read_bytes()
        if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.sha256:
            raise OmivInputError(f"continuous trust artifact index mismatch: {relative}")
    return index
