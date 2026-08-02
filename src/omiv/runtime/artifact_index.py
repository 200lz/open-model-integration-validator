"""Strict verification for the deterministic Phase 5G generated-artifact index."""

from __future__ import annotations

import hashlib
from pathlib import Path

from omiv.errors import OmivInputError
from omiv.runtime.models import RuntimeArtifactIndex


def verify_runtime_artifact_index(index: RuntimeArtifactIndex, root: Path) -> RuntimeArtifactIndex:
    indexed = {x.relative_path for x in index.entries}
    if "runtime/artifact-index.json" in indexed:
        raise OmivInputError("runtime artifact index must not include itself")
    actual = {
        path.relative_to(root).as_posix()
        for base in (root / "runtime", root / "reports" / "runtime")
        if base.exists()
        for path in base.rglob("*")
        if path.is_file() and path != root / "runtime" / "artifact-index.json"
    }
    if indexed != actual:
        raise OmivInputError(
            f"runtime artifact index inventory mismatch: missing={sorted(actual - indexed)}, "
            f"unexpected={sorted(indexed - actual)}"
        )
    seen_hashes: set[str] = set()
    seen_ids: set[str] = set()
    for entry in index.entries:
        path = root / entry.relative_path
        if path.is_symlink() or not path.is_file() or path.resolve().parent == root.resolve():
            raise OmivInputError("indexed runtime artifact is missing or unsafe")
        raw = path.read_bytes()
        if len(raw) != entry.size or hashlib.sha256(raw).hexdigest() != entry.sha256:
            raise OmivInputError(f"runtime artifact index mismatch: {entry.relative_path}")
        if entry.sha256 in seen_hashes or entry.canonical_id in seen_ids:
            raise OmivInputError("duplicate runtime artifact content or canonical ID")
        seen_hashes.add(entry.sha256)
        seen_ids.add(entry.canonical_id)
    return index
