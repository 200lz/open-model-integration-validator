"""Offline verification of the deterministic Phase 5F artifact index."""

from __future__ import annotations

import hashlib
from pathlib import Path

from omiv.errors import OmivInputError
from omiv.security.models import SecurityArtifactIndex


def verify_security_artifact_index(
    index: SecurityArtifactIndex,
    root: Path,
) -> SecurityArtifactIndex:
    root = root.resolve(strict=True)
    indexed_paths = {entry.relative_path for entry in index.entries}
    if "security/artifact-index.json" in indexed_paths:
        raise OmivInputError("security artifact index must not include itself")
    actual_paths = {
        path.relative_to(root).as_posix()
        for base in (root / "security", root / "reports" / "security")
        if base.is_dir()
        for path in base.rglob("*")
        if path.is_file() and path != root / "security" / "artifact-index.json"
    }
    if actual_paths != indexed_paths:
        missing = sorted(indexed_paths - actual_paths)
        unexpected = sorted(actual_paths - indexed_paths)
        raise OmivInputError(
            f"security artifact index inventory mismatch: missing={missing}, "
            f"unexpected={unexpected}"
        )
    for entry in index.entries:
        path = root / entry.relative_path
        if path.is_symlink() or not path.is_file():
            raise OmivInputError(
                f"indexed security artifact is missing or unsafe: {entry.relative_path}"
            )
        if not path.resolve(strict=True).is_relative_to(root):
            raise OmivInputError("indexed security artifact escapes the repository root")
        raw = path.read_bytes()
        if len(raw) != entry.size_bytes or hashlib.sha256(raw).hexdigest() != entry.digest:
            raise OmivInputError(
                f"indexed security artifact digest mismatch: {entry.relative_path}"
            )
    return index
