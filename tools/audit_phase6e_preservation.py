"""Audit preservation of all Phase 6E baseline evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from omiv.runtime_resolution.preservation import BASELINE_REVISION, audit_baseline


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--baseline", default=BASELINE_REVISION)
    args = parser.parse_args()
    if args.baseline != BASELINE_REVISION:
        raise SystemExit(f"Phase 6E preservation baseline must be {BASELINE_REVISION}")
    print(json.dumps(audit_baseline(args.repository), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
