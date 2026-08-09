"""Generate deterministic offline Phase 6C artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from omiv.quantization_profiles.examples import generate_all_quantization_examples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=Path.cwd())
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()
    generate_all_quantization_examples(args.output_root, repository=args.repository)


if __name__ == "__main__":
    main()
