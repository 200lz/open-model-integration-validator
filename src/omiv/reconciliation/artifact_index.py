"""External deterministic Phase 6B artifact-index verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from omiv.payload_integrity.paths import validate_path_set
from omiv.reconciliation.models import ReconciliationArtifactIndex


def verify_reconciliation_artifact_index(root: Path, index: ReconciliationArtifactIndex) -> None:
    paths = tuple(entry.path for entry in index.entries)
    validate_path_set(paths)
    if "reconciliation/artifact-index.json" in paths:
        raise ValueError("reconciliation artifact index must exclude itself")
    expected = set(paths)
    actual = {
        path.relative_to(root).as_posix()
        for directory in (root / "reconciliation", root / "reports" / "reconciliation")
        if directory.exists()
        for path in directory.rglob("*")
        if path.is_file() and path.name != "artifact-index.json"
    }
    if actual != expected:
        raise ValueError("reconciliation artifact index file set mismatch")
    identities: set[str] = set()
    contents: set[str] = set()
    total = 0
    for entry in index.entries:
        path = root / entry.path
        if path.is_symlink() or not path.is_file():
            raise ValueError("reconciliation index member is not a regular file")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != entry.size or digest != entry.sha256:
            raise ValueError("reconciliation index member size or digest mismatch")
        if digest in contents or entry.canonical_id in identities:
            raise ValueError("duplicate generated content or canonical identity")
        contents.add(digest)
        identities.add(entry.canonical_id)
        if path.suffix == ".json" and json.loads(data).get("schema") != entry.schema_id:
            raise ValueError("reconciliation index schema mismatch")
        total += len(data)
    if total != index.total_size:
        raise ValueError("reconciliation artifact index total size mismatch")
