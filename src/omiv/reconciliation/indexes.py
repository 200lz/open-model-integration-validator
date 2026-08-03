"""Safe bounded interpretation of supplied shard-index JSON evidence."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.reconciliation.building import identified
from omiv.reconciliation.models import (
    MAX_INDEX_MAPPINGS,
    CollectionLimits,
    RemoteSnapshotManifest,
    ShardGroup,
    ShardTopology,
    TopologySource,
    TopologyStatus,
)


@dataclass(frozen=True)
class ParsedShardIndex:
    source_name: str
    source_sha256: str
    mappings: tuple[tuple[str, str], ...]
    declared_shards: tuple[str, ...]
    metadata_present: bool


def parse_shard_index_bytes(
    raw: bytes,
    *,
    source_name: str = "supplied-index.json",
    maximum_bytes: int = 64 * 1024 * 1024,
    maximum_mappings: int = MAX_INDEX_MAPPINGS,
    maximum_logical_key_bytes: int = 4096,
) -> ParsedShardIndex:
    value = parse_bounded_json_bytes(
        raw, source_name=source_name, max_bytes=maximum_bytes, require_object=True
    )
    return _interpret_index(
        value,
        raw,
        source_name=source_name,
        maximum_mappings=maximum_mappings,
        maximum_logical_key_bytes=maximum_logical_key_bytes,
    )


def load_shard_index(
    path: Path,
    *,
    maximum_bytes: int = 64 * 1024 * 1024,
    maximum_mappings: int = MAX_INDEX_MAPPINGS,
) -> ParsedShardIndex:
    value, raw = load_bounded_json(path, max_bytes=maximum_bytes)
    return _interpret_index(
        value,
        raw,
        source_name=path.name,
        maximum_mappings=maximum_mappings,
        maximum_logical_key_bytes=4096,
    )


def _interpret_index(
    value: dict[str, Any],
    raw: bytes,
    *,
    source_name: str,
    maximum_mappings: int,
    maximum_logical_key_bytes: int,
) -> ParsedShardIndex:
    weight_map = value.get("weight_map")
    if not isinstance(weight_map, dict):
        raise OmivInputError("index must contain an object-valued weight_map")
    if len(weight_map) > maximum_mappings:
        raise OmivInputError("LIMIT_EXCEEDED:INDEX_LOGICAL_MAPPINGS")
    mappings: list[tuple[str, str]] = []
    for logical_key, shard_path in weight_map.items():
        if not isinstance(logical_key, str) or not logical_key:
            raise OmivInputError("index logical keys must be non-empty strings")
        if len(logical_key.encode("utf-8")) > maximum_logical_key_bytes:
            raise OmivInputError("LIMIT_EXCEEDED:INDEX_LOGICAL_KEY_BYTES")
        if not isinstance(shard_path, str):
            raise OmivInputError("index shard paths must be strings")
        try:
            validate_portable_path(shard_path)
        except ValueError as exc:
            raise OmivInputError(f"unsafe shard path in index: {exc}") from exc
        mappings.append((logical_key, shard_path))
    mappings.sort(key=lambda item: (item[0].encode(), item[1].encode()))
    shards = tuple(sorted({path for _, path in mappings}, key=lambda item: item.encode()))
    validate_path_set(shards)
    return ParsedShardIndex(
        source_name=source_name,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        mappings=tuple(mappings),
        declared_shards=shards,
        metadata_present="metadata" in value,
    )


def build_topology_from_indexes(
    snapshot: RemoteSnapshotManifest,
    indexes: Iterable[ParsedShardIndex],
    *,
    index_member_ids: Iterable[str] = (),
    companion_artifacts: Iterable[str] = (),
    limits: CollectionLimits | None = None,
) -> ShardTopology:
    supplied = tuple(indexes)
    if not supplied:
        return build_unavailable_topology(snapshot, limits=limits)
    if (
        sum(len(index.mappings) for index in supplied)
        > (limits or CollectionLimits()).maximum_index_mappings
    ):
        return _topology(
            snapshot,
            TopologySource.EXPLICIT_INDEX,
            TopologyStatus.LIMIT_EXCEEDED,
            supplied,
            tuple(index_member_ids),
            (),
            (),
            tuple(companion_artifacts),
            (limits or CollectionLimits()).maximum_index_mappings,
            (),
            (),
            ("Index mapping limit was exceeded; no authoritative membership was established.",),
            limits or CollectionLimits(),
        )
    by_key: dict[str, set[str]] = {}
    duplicate: set[str] = set()
    for index in supplied:
        for logical, shard in index.mappings:
            values = by_key.setdefault(logical, set())
            if shard in values:
                duplicate.add(logical)
            values.add(shard)
    conflicts = tuple(sorted(key for key, paths in by_key.items() if len(paths) > 1))
    required = tuple(
        sorted(
            {path for index in supplied for path in index.declared_shards}, key=lambda x: x.encode()
        )
    )
    remote_paths = {member.path for member in snapshot.members}
    missing = tuple(sorted(set(required) - remote_paths))
    status = (
        TopologyStatus.CONFLICTING_INDEXES
        if conflicts
        else TopologyStatus.EXPLICIT_TOPOLOGY_AVAILABLE
    )
    return _topology(
        snapshot,
        TopologySource.EXPLICIT_INDEX,
        status,
        supplied,
        tuple(index_member_ids),
        required,
        missing,
        tuple(companion_artifacts),
        len(by_key),
        tuple(sorted(duplicate)),
        conflicts,
        (
            "Index declares logical-key-to-shard relationships only; keys and tensors were not "
            "opened or verified.",
        ),
        limits or CollectionLimits(),
    )


def build_declared_topology(
    snapshot: RemoteSnapshotManifest,
    *,
    source: TopologySource,
    required_shards: Iterable[str],
    optional_shards: Iterable[str] = (),
    companion_artifacts: Iterable[str] = (),
    source_member_ids: Iterable[str] = (),
) -> ShardTopology:
    if source not in {
        TopologySource.EXPLICIT_PROVIDER_MANIFEST,
        TopologySource.EXPLICIT_USER_DECLARATION,
    }:
        raise OmivInputError("declared topology requires an explicit source")
    required = tuple(sorted(set(required_shards), key=lambda x: x.encode()))
    optional = tuple(sorted(set(optional_shards), key=lambda x: x.encode()))
    companions = tuple(sorted(set(companion_artifacts), key=lambda x: x.encode()))
    validate_path_set(required + optional + companions)
    remote_paths = {member.path for member in snapshot.members}
    missing = tuple(sorted((set(required) | set(companions)) - remote_paths))
    body = {
        "schema": "omiv.shard-topology.v1",
        "subject": snapshot.subject.model_dump(mode="json", by_alias=True),
        "snapshot_id": snapshot.manifest_id,
        "snapshot_digest": snapshot.manifest_digest,
        "topology_source": source.value,
        "source_member_ids": sorted(source_member_ids),
        "declared_index_files": [],
        "shard_groups": [
            ShardGroup(
                group_id="group.primary",
                required_shards=required,
                optional_shards=optional,
                logical_key_count=0,
            ).model_dump(mode="json")
        ],
        "required_shards": required,
        "optional_shards": optional,
        "companion_artifacts": companions,
        "referenced_logical_key_count": 0,
        "duplicate_references": [],
        "conflicting_references": [],
        "missing_referenced_remote_members": missing,
        "unreferenced_shard_like_members": [],
        "limits": CollectionLimits().model_dump(mode="json"),
        "coverage": "EXPLICIT_DECLARED_MEMBERSHIP_ONLY",
        "status": TopologyStatus.EXPLICIT_TOPOLOGY_AVAILABLE.value,
        "limitations": [
            "Explicit membership does not establish tensor-semantic completeness or shard "
            "correctness."
        ],
    }
    return ShardTopology.model_validate(
        identified(body, "topology_id", "shard_topology_", "topology_digest")
    )


def build_heuristic_hints(snapshot: RemoteSnapshotManifest, hints: Iterable[str]) -> ShardTopology:
    hint_paths = tuple(sorted(set(hints), key=lambda x: x.encode()))
    validate_path_set(hint_paths)
    body = {
        "schema": "omiv.shard-topology.v1",
        "subject": snapshot.subject.model_dump(mode="json", by_alias=True),
        "snapshot_id": snapshot.manifest_id,
        "snapshot_digest": snapshot.manifest_digest,
        "topology_source": TopologySource.FILENAME_HEURISTIC.value,
        "source_member_ids": [],
        "declared_index_files": [],
        "shard_groups": [],
        "required_shards": [],
        "optional_shards": [],
        "companion_artifacts": [],
        "referenced_logical_key_count": 0,
        "duplicate_references": [],
        "conflicting_references": [],
        "missing_referenced_remote_members": [],
        "unreferenced_shard_like_members": hint_paths,
        "limits": CollectionLimits().model_dump(mode="json"),
        "coverage": "DISCOVERY_HINTS_ONLY",
        "status": TopologyStatus.HEURISTIC_ONLY.value,
        "limitations": ["Filename heuristics are non-authoritative discovery hints only."],
    }
    return ShardTopology.model_validate(
        identified(body, "topology_id", "shard_topology_", "topology_digest")
    )


def build_unavailable_topology(
    snapshot: RemoteSnapshotManifest, *, limits: CollectionLimits | None = None
) -> ShardTopology:
    body = {
        "schema": "omiv.shard-topology.v1",
        "subject": snapshot.subject.model_dump(mode="json", by_alias=True),
        "snapshot_id": snapshot.manifest_id,
        "snapshot_digest": snapshot.manifest_digest,
        "topology_source": TopologySource.UNAVAILABLE.value,
        "source_member_ids": [],
        "declared_index_files": [],
        "shard_groups": [],
        "required_shards": [],
        "optional_shards": [],
        "companion_artifacts": [],
        "referenced_logical_key_count": 0,
        "duplicate_references": [],
        "conflicting_references": [],
        "missing_referenced_remote_members": [],
        "unreferenced_shard_like_members": [],
        "limits": (limits or CollectionLimits()).model_dump(mode="json"),
        "coverage": "UNAVAILABLE",
        "status": TopologyStatus.TOPOLOGY_UNAVAILABLE.value,
        "limitations": ["No explicit topology evidence was supplied."],
    }
    return ShardTopology.model_validate(
        identified(body, "topology_id", "shard_topology_", "topology_digest")
    )


def _topology(
    snapshot: RemoteSnapshotManifest,
    source: TopologySource,
    status: TopologyStatus,
    indexes: tuple[ParsedShardIndex, ...],
    source_member_ids: tuple[str, ...],
    required: tuple[str, ...],
    missing: tuple[str, ...],
    companions: tuple[str, ...],
    logical_count: int,
    duplicates: tuple[str, ...],
    conflicts: tuple[str, ...],
    limitations_text: tuple[str, ...],
    limits: CollectionLimits,
) -> ShardTopology:
    remote_paths = {member.path for member in snapshot.members}
    declared = set(required)
    unreferenced = tuple(
        sorted(
            path
            for path in remote_paths - declared
            if path.endswith((".safetensors", ".bin", ".gguf", ".ckpt"))
        )
    )
    body = {
        "schema": "omiv.shard-topology.v1",
        "subject": snapshot.subject.model_dump(mode="json", by_alias=True),
        "snapshot_id": snapshot.manifest_id,
        "snapshot_digest": snapshot.manifest_digest,
        "topology_source": source.value,
        "source_member_ids": sorted(source_member_ids),
        "declared_index_files": sorted(index.source_name for index in indexes),
        "shard_groups": (
            [
                ShardGroup(
                    group_id="group.primary",
                    required_shards=required,
                    logical_key_count=logical_count,
                ).model_dump(mode="json")
            ]
            if required
            else []
        ),
        "required_shards": required,
        "optional_shards": [],
        "companion_artifacts": sorted(companions),
        "referenced_logical_key_count": logical_count,
        "duplicate_references": duplicates,
        "conflicting_references": conflicts,
        "missing_referenced_remote_members": missing,
        "unreferenced_shard_like_members": unreferenced,
        "limits": limits.model_dump(mode="json"),
        "coverage": "ALL_SUPPLIED_INDEX_MAPPINGS"
        if status != TopologyStatus.LIMIT_EXCEEDED
        else "LIMIT_EXCEEDED",
        "status": status.value,
        "limitations": list(limitations_text),
    }
    return ShardTopology.model_validate(
        identified(body, "topology_id", "shard_topology_", "topology_digest")
    )
