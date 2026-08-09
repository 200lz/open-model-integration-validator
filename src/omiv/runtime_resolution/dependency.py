"""Bounded dependency-graph reconstruction and cycle rejection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.runtime_resolution.models import (
    IDENTITY_SPECS,
    RuntimeResolutionArtifactIndex,
    RuntimeResolutionLimits,
)


def assert_acyclic(
    edges: dict[str, set[str]], limits: RuntimeResolutionLimits | None = None
) -> None:
    bounds = limits or RuntimeResolutionLimits()
    nodes = set(edges) | {target for targets in edges.values() for target in targets}
    if len(nodes) > bounds.maximum_dependency_nodes:
        raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_NODES")
    if sum(len(targets) for targets in edges.values()) > bounds.maximum_dependency_edges:
        raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_EDGES")
    state: dict[str, int] = {}

    def visit(node: str, depth: int) -> None:
        if depth > bounds.maximum_dependency_depth:
            raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_DEPTH")
        if state.get(node) == 1:
            raise ValueError("runtime-resolution dependency graph contains a cycle")
        if state.get(node) == 2:
            return
        state[node] = 1
        for target in sorted(edges.get(node, ())):
            visit(target, depth + 1)
        state[node] = 2

    for node in sorted(nodes):
        visit(node, 0)


def verify_generated_dependency_graph(root: Path, index: RuntimeResolutionArtifactIndex) -> None:
    objects: dict[str, dict[str, Any]] = {}
    for entry in index.entries:
        if entry.path.endswith(".json"):
            value = json.loads((root / entry.path).read_bytes())
            _verify_canonical_identity(value)
            objects[entry.canonical_id] = value
    edges: dict[str, set[str]] = {identity: set() for identity in objects}

    def walk(value: Any, owner: str) -> None:
        if isinstance(value, dict):
            if set(value) == {"schema_id", "object_id", "object_digest"}:
                target_id = value["object_id"]
                if target_id in objects:
                    target = objects[target_id]
                    spec = IDENTITY_SPECS.get(value["schema_id"])
                    if spec is None:
                        id_fields = [
                            key
                            for key, item in target.items()
                            if key.endswith("_id") and item == target_id
                        ]
                        digest_fields = [
                            key
                            for key, item in target.items()
                            if key.endswith("_digest") and item == value["object_digest"]
                        ]
                        if len(id_fields) != 1 or len(digest_fields) != 1:
                            raise ValueError("ambiguous generated reference identity")
                        id_field, digest_field = id_fields[0], digest_fields[0]
                    else:
                        id_field, digest_field, _prefix = spec
                    if (
                        target.get("schema") != value["schema_id"]
                        or target.get(id_field) != target_id
                        or target.get(digest_field) != value["object_digest"]
                    ):
                        raise ValueError("generated reference identity or digest mismatch")
                    edges[owner].add(target_id)
            for child in value.values():
                walk(child, owner)
        elif isinstance(value, list):
            for child in value:
                walk(child, owner)

    for owner, value in objects.items():
        walk(value, owner)
    assert_acyclic(edges)


def _verify_canonical_identity(value: dict[str, Any]) -> None:
    schema = value.get("schema")
    if not isinstance(schema, str):
        return
    spec = IDENTITY_SPECS.get(schema)
    if spec is None:
        profiles = {
            "omiv.xai-runtime-resolution-readiness.v1": (
                "readiness_id",
                "readiness_digest",
                "xai_runtime_readiness_",
            ),
            "omiv.anthropic-provable-inference-readiness.v1": (
                "readiness_id",
                "readiness_digest",
                "anthropic_runtime_readiness_",
            ),
        }
        spec = profiles.get(str(schema))
    if spec is None:
        return
    id_field, digest_field, prefix = spec
    body = dict(value)
    try:
        digest = body.pop(digest_field)
        identity = body.pop(id_field)
    except KeyError as exc:
        raise ValueError("generated canonical object lacks its identity pair") from exc
    expected_id = prefix + canonical_sha256(body)[:32]
    expected_digest = canonical_sha256({**body, id_field: expected_id})
    if identity != expected_id or digest != expected_digest:
        raise ValueError("generated canonical object identity or digest is not recomputable")
