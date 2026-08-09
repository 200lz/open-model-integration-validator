"""Bounded dependency graph reconstruction and cycle rejection for Phase 6D."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from omiv.tokenizer_parity.models import (
    IDENTITY_SPECS,
    TokenizerConfigurationArtifactIndex,
    TokenizerConfigurationLimits,
)


def assert_acyclic(
    edges: dict[str, set[str]], limits: TokenizerConfigurationLimits | None = None
) -> None:
    bounds = limits or TokenizerConfigurationLimits()
    nodes = set(edges) | {target for values in edges.values() for target in values}
    if len(nodes) > bounds.maximum_dependency_nodes:
        raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_NODES")
    if sum(len(values) for values in edges.values()) > bounds.maximum_dependency_edges:
        raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_EDGES")
    state: dict[str, int] = {}

    def visit(node: str, depth: int) -> None:
        if depth > bounds.maximum_dependency_depth:
            raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_DEPTH")
        if state.get(node) == 1:
            raise ValueError("tokenizer/configuration dependency graph contains a cycle")
        if state.get(node) == 2:
            return
        state[node] = 1
        for target in sorted(edges.get(node, ())):
            visit(target, depth + 1)
        state[node] = 2

    for node in sorted(nodes):
        visit(node, 0)


def verify_generated_dependency_graph(
    root: Path, index: TokenizerConfigurationArtifactIndex
) -> None:
    objects: dict[str, dict[str, Any]] = {}
    for entry in index.entries:
        if entry.path.endswith(".json"):
            objects[entry.canonical_id] = json.loads((root / entry.path).read_bytes())
    edges: dict[str, set[str]] = {key: set() for key in objects}

    def walk(value: Any, owner: str) -> None:
        if isinstance(value, dict):
            if (
                set(value) == {"schema_id", "object_id", "object_digest"}
                and value["object_id"] in objects
            ):
                target = objects[value["object_id"]]
                spec = IDENTITY_SPECS.get(value["schema_id"])
                if spec is None:
                    id_fields = [
                        key
                        for key, item in target.items()
                        if key.endswith("_id") and item == value["object_id"]
                    ]
                    digest_fields = [
                        key
                        for key, item in target.items()
                        if key.endswith("_digest") and item == value["object_digest"]
                    ]
                    if len(id_fields) != 1 or len(digest_fields) != 1:
                        raise ValueError(
                            "referenced generated schema has ambiguous identity specification"
                        )
                    id_field, digest_field = id_fields[0], digest_fields[0]
                else:
                    id_field, digest_field, _prefix = spec
                if (
                    target.get("schema") != value["schema_id"]
                    or target.get(id_field) != value["object_id"]
                    or target.get(digest_field) != value["object_digest"]
                ):
                    raise ValueError("generated canonical reference identity or digest mismatch")
                edges[owner].add(value["object_id"])
            for child in value.values():
                walk(child, owner)
        elif isinstance(value, list):
            for child in value:
                walk(child, owner)

    for owner, value in objects.items():
        walk(value, owner)
    assert_acyclic(edges)
