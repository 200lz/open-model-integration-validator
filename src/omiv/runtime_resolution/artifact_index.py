"""External self-excluding Phase 6E artifact-index verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from omiv.payload_integrity.paths import validate_path_set
from omiv.runtime_resolution.models import RuntimeResolutionArtifactIndex


def verify_runtime_resolution_artifact_index(
    root: Path, index: RuntimeResolutionArtifactIndex
) -> None:
    paths = tuple(entry.path for entry in index.entries)
    validate_path_set(paths)
    if "runtime-resolution-parity/artifact-index.json" in paths:
        raise ValueError("Phase 6E artifact index must exclude itself")
    actual = {
        path.relative_to(root).as_posix()
        for directory in (
            root / "runtime-resolution-parity",
            root / "reports" / "runtime-resolution-parity",
        )
        if directory.exists()
        for path in directory.rglob("*")
        if path.is_file() and path.name != "artifact-index.json"
    }
    if actual != set(paths):
        raise ValueError("Phase 6E artifact-index path set mismatch")
    hashes: set[str] = set()
    identities: set[str] = set()
    total = 0
    for entry in index.entries:
        path = root / entry.path
        if path.is_symlink() or not path.is_file():
            raise ValueError("indexed Phase 6E member must be a regular file")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != entry.size or digest != entry.sha256:
            raise ValueError("indexed Phase 6E size or digest mismatch")
        if digest in hashes or entry.canonical_id in identities:
            raise ValueError("duplicate Phase 6E content or canonical identity")
        hashes.add(digest)
        identities.add(entry.canonical_id)
        total += len(raw)
        if path.suffix == ".json" and json.loads(raw).get("schema") != entry.schema_id:
            raise ValueError("indexed Phase 6E schema mismatch")
    if total != index.total_size:
        raise ValueError("indexed Phase 6E total size mismatch")
