"""Write deterministic temporary Phase 6C preservation inventories."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from omiv.quantization.preservation import audit_baseline
from omiv.safe_write import atomic_write_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--tsv-output", type=Path, required=True)
    parser.add_argument("--exclusions-output", type=Path, required=True)
    args = parser.parse_args()
    value = audit_baseline(args.repository)
    atomic_write_text(args.json_output, json.dumps(value, indent=2, sort_keys=True) + "\n")
    headings = (
        "relative_path",
        "git_blob_identity",
        "baseline_size",
        "baseline_sha256",
        "current_size",
        "current_sha256",
        "classification",
        "inclusion_reason",
    )
    rows = ["\t".join(headings)]
    rows.extend("\t".join(str(item[key]) for key in headings) for item in value["inventory"])
    atomic_write_text(args.tsv_output, "\n".join(rows) + "\n")
    exclusion_headings = ("relative_path", "git_blob_identity", "baseline_size", "reason")
    exclusion_rows = ["\t".join(exclusion_headings)]
    exclusion_rows.extend(
        "\t".join(str(item[key]) for key in exclusion_headings) for item in value["exclusions"]
    )
    atomic_write_text(args.exclusions_output, "\n".join(exclusion_rows) + "\n")


if __name__ == "__main__":
    main()
