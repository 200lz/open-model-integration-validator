"""Bounded dependency-graph reconstruction and cycle rejection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from omiv.quantization.models import QuantizationArtifactIndex, QuantizationLimits


def assert_acyclic(edges: dict[str, set[str]], limits: QuantizationLimits | None = None) -> None:
    bounds = limits or QuantizationLimits()
    nodes = set(edges) | {target for targets in edges.values() for target in targets}
    if len(nodes) > bounds.maximum_dependency_graph_nodes:
        raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_GRAPH_NODES")
    if sum(map(len, edges.values())) > bounds.maximum_dependency_graph_edges:
        raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_GRAPH_EDGES")
    state: dict[str, int] = {}

    def visit(node: str, depth: int) -> None:
        if depth > bounds.maximum_traversal_depth:
            raise ValueError("LIMIT_EXCEEDED:DEPENDENCY_GRAPH_DEPTH")
        if state.get(node) == 1:
            raise ValueError("quantization dependency graph contains a cycle")
        if state.get(node) == 2:
            return
        state[node] = 1
        for target in sorted(edges.get(node, ())):
            visit(target, depth + 1)
        state[node] = 2

    for node in sorted(nodes):
        visit(node, 0)


def verify_generated_dependency_graph(root: Path, index: QuantizationArtifactIndex) -> None:
    objects: dict[str, dict[str, Any]] = {}
    for entry in index.entries:
        if not entry.path.endswith(".json"):
            continue
        value = json.loads((root / entry.path).read_bytes())
        objects[entry.canonical_id] = value
    edges: dict[str, set[str]] = {identity: set() for identity in objects}

    def walk(value: Any, owner: str) -> None:
        if isinstance(value, dict):
            if set(value) == {"schema_id", "object_id", "object_digest"}:
                target = value["object_id"]
                if target in objects:
                    edges[owner].add(target)
            for child in value.values():
                walk(child, owner)
        elif isinstance(value, list):
            for child in value:
                walk(child, owner)

    for owner, value in objects.items():
        walk(value, owner)
    assert_acyclic(edges)
