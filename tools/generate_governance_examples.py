"""Generate deterministic public-only Phase 5E governance examples."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from omiv.canonical import canonical_sha256
from omiv.governance.examples import build_examples
from omiv.governance.reporting import pretty_json
from omiv.safe_write import atomic_write_text


def generate(repository: Path, output_root: Path) -> list[Path]:
    artifacts = build_examples(repository)
    serialized = {
        relative: value if isinstance(value, str) else pretty_json(value)
        for relative, value in artifacts.items()
    }
    entries = [
        {
            "relative_path": relative,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "size_bytes": len(content.encode("utf-8")),
        }
        for relative, content in sorted(serialized.items())
    ]
    index_body = {
        "schema": "omiv.governance-artifact-index.v1",
        "artifacts": entries,
        "limitations": [
            "Index covers public deterministic Phase 5E fixtures only; no model payloads."
        ],
    }
    index_with_id = {
        **index_body,
        "index_id": "governance_index_" + canonical_sha256(index_body)[:32],
    }
    serialized["governance/artifact-index.json"] = pretty_json(
        {**index_with_id, "index_digest": canonical_sha256(index_with_id)}
    )
    paths: list[Path] = []
    for relative, content in sorted(serialized.items()):
        path = output_root / relative
        atomic_write_text(path, content)
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--output-root", type=Path, default=Path("."))
    args = parser.parse_args()
    paths = generate(args.repository.resolve(), args.output_root.resolve())
    print(f"generated {len(paths)} deterministic public-only Phase 5E artifacts")


if __name__ == "__main__":
    main()
