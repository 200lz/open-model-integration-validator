#!/usr/bin/env python3
"""Synthetic llama.cpp-compatible native CLI fixture; never performs inference."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

VERSION = "llama.cpp synthetic-runner 1.0"


def main() -> int:
    if sys.argv[1:] == ["--version"]:
        print(VERSION)
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--temp", required=True)
    parser.add_argument("--n-predict", required=True)
    parser.add_argument("--gpu-layers", required=True)
    parser.add_argument("--simple-io", action="store_true")
    parser.add_argument("--no-display-prompt", action="store_true")
    arguments = parser.parse_args()
    Path(arguments.model).read_bytes()
    if arguments.gpu_layers != "0" or arguments.temp != "0":
        print("synthetic profile requires CPU-only deterministic arguments", file=sys.stderr)
        return 4
    sys.stdout.write("Paris")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
