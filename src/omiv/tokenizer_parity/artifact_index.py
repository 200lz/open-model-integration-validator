"""External self-excluding Phase 6D artifact-index verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from omiv.payload_integrity.paths import validate_path_set
from omiv.tokenizer_parity.models import TokenizerConfigurationArtifactIndex


def verify_tokenizer_configuration_artifact_index(
    root: Path, index: TokenizerConfigurationArtifactIndex
) -> None:
    paths = tuple(entry.path for entry in index.entries)
    validate_path_set(paths)
    if "tokenizer-configuration-parity/artifact-index.json" in paths:
        raise ValueError("Phase 6D artifact index must exclude itself")
    actual = {
        path.relative_to(root).as_posix()
        for directory in (
            root / "tokenizer-configuration-parity",
            root / "reports" / "tokenizer-configuration-parity",
        )
        if directory.exists()
        for path in directory.rglob("*")
        if path.is_file() and path.name != "artifact-index.json"
    }
    if actual != set(paths):
        raise ValueError("Phase 6D artifact-index path set mismatch")
    hashes: set[str] = set()
    identities: set[str] = set()
    total = 0
    for entry in index.entries:
        path = root / entry.path
        if path.is_symlink() or not path.is_file():
            raise ValueError("indexed Phase 6D member must be a regular file")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != entry.size or digest != entry.sha256:
            raise ValueError("indexed Phase 6D size or digest mismatch")
        if digest in hashes or entry.canonical_id in identities:
            raise ValueError("duplicate Phase 6D content or canonical identity")
        hashes.add(digest)
        identities.add(entry.canonical_id)
        total += len(raw)
        if path.suffix == ".json" and json.loads(raw).get("schema") != entry.schema_id:
            raise ValueError("indexed Phase 6D schema mismatch")
    if total != index.total_size:
        raise ValueError("indexed Phase 6D total size mismatch")
