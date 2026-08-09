"""Generate deterministic offline Phase 6E runtime-resolution evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

from omiv.runtime_resolution_profiles.examples import generate_all_runtime_resolution_examples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=Path.cwd())
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()
    index = generate_all_runtime_resolution_examples(args.output_root, repository=args.repository)
    print(
        f"generated {len(index.entries) + 1} files; "
        f"{len(index.entries)} indexed artifacts; "
        "the external artifact index excludes itself"
    )


if __name__ == "__main__":
    main()
