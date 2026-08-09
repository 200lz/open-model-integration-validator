#!/usr/bin/env python3
"""Bounded public-release audit that never reports private source values."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "ffa57d385ffe465b6418daaa8a2530ff8d76e5fa"
EXPECTED_VERSION = "0.10.0"
APPROVED_AUTHOR_IDENTITY_SHA256 = "15bee5fe614b2c133c0b901de5873ba2f0cfa6fc9a5f1d65f0ec6072a59b68eb"
APPROVED_PATH_FINGERPRINTS = {
    "5ba5e619bbec7b9f",
    "8c8ba75aa027ee39",
    "449183090d324eb6",
    "f807b9e7bf9968a8",
    "5b3b9cf7f8eeca6",
}
SYNTHETIC_HOME_USERS = {"example", "synthetic", "user"}
MAX_PUBLIC_FILE_BYTES = 5 * 1024 * 1024
MAX_PAYLOAD_FIXTURE_BYTES = 1024
REQUIRED_PUBLIC_FILES = {
    "CHANGELOG.md",
    "CITATION.cff",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "THIRD_PARTY_NOTICES.md",
    "TRADEMARKS.md",
    "docs/public-commercial-boundary.md",
    "docs/public-release-security-and-privacy.md",
    "docs/releasing.md",
}


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _git(*args: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        input=input_bytes,
        check=True,
        capture_output=True,
    ).stdout


def _candidate_files() -> list[Path]:
    return [
        ROOT / os.fsdecode(item)
        for item in _git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(
            b"\0"
        )
        if item
    ]


def _safe_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _is_safe_regular_file(path: Path) -> bool:
    """Reject symlinks before any stat or content read."""

    return not path.is_symlink() and path.is_file()


def _candidate_symlink_checks(files: list[Path]) -> list[Check]:
    symlink_count = sum(path.is_symlink() for path in files)
    return [
        Check(
            "candidate_symlink_safety",
            symlink_count == 0,
            f"candidate_symlinks={symlink_count}",
        )
    ]


def _history_inventory() -> list[Check]:
    commits = _git("rev-list", "--all", "--count").decode().strip()
    tags = _git("tag", "--list").decode().splitlines()
    identity_fields = [
        field.strip(b"\n")
        for field in _git("log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce%x00").split(b"\0")
        if field.strip(b"\n")
    ]
    identities = {
        identity_fields[index] + b"\0" + identity_fields[index + 1]
        for index in range(0, len(identity_fields), 2)
    }
    tag_rows = _git(
        "for-each-ref",
        "--format=%(objecttype)%00%(taggername)%00%(taggeremail)",
        "refs/tags",
    ).splitlines()
    for row in tag_rows:
        fields = row.split(b"\0")
        if fields[0] == b"tag":
            identities.add(fields[1] + b"\0" + fields[2].strip(b"<>"))
    identity_hashes = {hashlib.sha256(row).hexdigest() for row in identities}
    return [
        Check("reachable_history", int(commits) >= 36, f"commits={commits}"),
        Check("historical_tags", len(tags) == 9, f"tags={len(tags)}"),
        Check(
            "approved_author_identity",
            identity_hashes == {APPROVED_AUTHOR_IDENTITY_SHA256},
            f"identities={len(identity_hashes)} approval=owner-recorded",
        ),
    ]


def _history_paths_and_credentials() -> list[Check]:
    history_parts = [_git("log", "--all", "-p", "--format=%B%x00", "--", ".")]
    tag_rows = _git(
        "for-each-ref", "--format=%(objecttype)%00%(objectname)", "refs/tags"
    ).splitlines()
    for row in tag_rows:
        kind, object_id = row.split(b"\0", maxsplit=1)
        if kind == b"tag":
            history_parts.append(_git("cat-file", "tag", object_id.decode("ascii")))
    history = b"\0".join(history_parts).decode("utf-8", errors="replace")
    unix_paths = re.findall(r"/home/([A-Za-z0-9._-]+)/[A-Za-z0-9._/@+%=,~-]+", history)
    full_paths = re.findall(r"/home/[A-Za-z0-9._-]+/[A-Za-z0-9._/@+%=,~-]+", history)
    candidate_fingerprints: set[str] = set()
    for user, path in zip(unix_paths, full_paths, strict=True):
        if user in SYNTHETIC_HOME_USERS:
            continue
        digest = hashlib.sha256(path.encode()).hexdigest()
        approved_match = next(
            (
                fingerprint
                for fingerprint in APPROVED_PATH_FINGERPRINTS
                if digest.startswith(fingerprint)
            ),
            None,
        )
        candidate_fingerprints.add(approved_match or digest[:16])
    credential_patterns = {
        "aws_access_key": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
        "hugging_face_token": r"\bhf_[A-Za-z0-9]{20,}\b",
        "openai_style_token": r"\bsk-[A-Za-z0-9_-]{20,}\b",
        "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    }
    credential_hits = {
        name: len(re.findall(pattern, history))
        for name, pattern in credential_patterns.items()
        if re.search(pattern, history)
    }
    return [
        Check(
            "approved_historical_machine_paths",
            candidate_fingerprints == APPROVED_PATH_FINGERPRINTS,
            f"reviewed_fingerprints={len(candidate_fingerprints)} approval=owner-recorded",
        ),
        Check(
            "history_common_credentials",
            not credential_hits,
            "no common credential signatures" if not credential_hits else str(credential_hits),
        ),
    ]


def _current_content_checks(files: list[Path]) -> list[Check]:
    machine_fingerprints: set[str] = set()
    credential_hits = 0
    machine_pattern = re.compile(r"/home/([A-Za-z0-9._-]+)/[A-Za-z0-9._/@+%=,~-]+")
    credential_patterns = (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    )
    for path in files:
        if not _is_safe_regular_file(path) or path.stat().st_size > MAX_PUBLIC_FILE_BYTES:
            continue
        text = _safe_text(path)
        for match in machine_pattern.finditer(text):
            if match.group(1) not in SYNTHETIC_HOME_USERS:
                machine_fingerprints.add(hashlib.sha256(match.group(0).encode()).hexdigest()[:16])
        credential_hits += sum(len(pattern.findall(text)) for pattern in credential_patterns)
    return [
        Check(
            "current_machine_specific_paths",
            not machine_fingerprints,
            f"unapproved_path_fingerprints={len(machine_fingerprints)}",
        ),
        Check(
            "current_common_credentials",
            credential_hits == 0,
            f"credential_signatures={credential_hits}",
        ),
    ]


def _blob_and_payload_checks(files: list[Path]) -> list[Check]:
    object_rows = _git("rev-list", "--objects", "--all").splitlines()
    object_ids = [row.split(maxsplit=1)[0] for row in object_rows]
    batch = _git(
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_bytes=b"\n".join(object_ids) + b"\n",
    ).decode()
    oversized_blobs = []
    for row in batch.splitlines():
        _oid, kind, size = row.split()
        if kind == "blob" and int(size) > MAX_PUBLIC_FILE_BYTES:
            oversized_blobs.append(int(size))

    payload_suffixes = {".gguf", ".safetensors", ".bin", ".onnx", ".pt", ".pth", ".ckpt"}
    forbidden_payloads = [
        path.relative_to(ROOT).as_posix()
        for path in files
        if _is_safe_regular_file(path)
        and path.suffix.lower() in payload_suffixes
        and path.stat().st_size > MAX_PAYLOAD_FIXTURE_BYTES
    ]
    changed = {
        item.decode() for item in _git("diff", "--name-only", BASELINE, "--").splitlines() if item
    }
    changed.update(
        item.decode()
        for item in _git("ls-files", "--others", "--exclude-standard").splitlines()
        if item
    )
    oversized_readiness_files = [
        relative
        for relative in changed
        if _is_safe_regular_file(ROOT / relative)
        and (ROOT / relative).stat().st_size > MAX_PUBLIC_FILE_BYTES
    ]
    return [
        Check("reachable_large_blobs", not oversized_blobs, f"over_5_mib={len(oversized_blobs)}"),
        Check(
            "forbidden_model_payloads",
            not forbidden_payloads,
            f"payload_files_over_fixture_limit={len(forbidden_payloads)}",
        ),
        Check(
            "readiness_file_size_limit",
            not oversized_readiness_files,
            f"changed_files_over_5_mib={len(oversized_readiness_files)}",
        ),
    ]


def _metadata_and_legal_checks() -> list[Check]:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    missing = sorted(
        path for path in REQUIRED_PUBLIC_FILES if not _is_safe_regular_file(ROOT / path)
    )
    authors = metadata.get("authors", [])
    author_emails = [author.get("email") for author in authors if author.get("email")]
    return [
        Check("public_legal_files", not missing, f"missing={len(missing)}"),
        Check(
            "package_name", metadata.get("name") == "open-model-integration-validator", "expected"
        ),
        Check("package_version", metadata.get("version") == EXPECTED_VERSION, EXPECTED_VERSION),
        Check("package_license", metadata.get("license") == "Apache-2.0", "Apache-2.0"),
        Check("python_requirement", metadata.get("requires-python") == ">=3.11", ">=3.11"),
        Check("author_email_omitted", not author_emails, f"metadata_emails={len(author_emails)}"),
    ]


def _workflow_checks() -> list[Check]:
    path = ROOT / ".github/workflows/ci.yml"
    if not _is_safe_regular_file(path):
        return [Check("workflow_static_safety", False, "workflow missing")]
    text = path.read_text(encoding="utf-8")
    pins = re.findall(r"uses:\s*[^\s@]+@([^\s#]+)", text)
    forbidden = [
        token
        for token in (
            "pull_request_target",
            "self-hosted",
            "permissions: write-all",
            'OMIV_RUN_REMOTE_INTEGRATION: "1"',
            "twine upload",
            "gh release create",
        )
        if token in text
    ]
    matrix_ok = all(f'"3.{minor}"' in text for minor in range(11, 15))
    return [
        Check(
            "workflow_static_safety",
            not forbidden
            and bool(re.search(r"permissions:\s*\n\s+contents:\s*read", text))
            and bool(pins)
            and all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins),
            f"immutable_action_pins={len(pins)} forbidden_controls={len(forbidden)}",
        ),
        Check("workflow_python_matrix", matrix_ok, "python=3.11,3.12,3.13,3.14"),
    ]


def _repository_hygiene(files: list[Path]) -> list[Check]:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    required_ignores = {".venv/", "__pycache__/", ".pytest_cache/", "*.gguf", "*.safetensors"}
    missing_ignores = sorted(required_ignores - set(ignore.splitlines()))
    suspicious = [
        path.relative_to(ROOT).as_posix()
        for path in files
        if any(
            part in {".venv", "__pycache__", ".pytest_cache", ".mypy_cache"} for part in path.parts
        )
    ]
    return [
        Check(
            "repository_hygiene",
            not missing_ignores and not suspicious,
            f"missing_ignore_rules={len(missing_ignores)} tracked_cache_paths={len(suspicious)}",
        )
    ]


def _strict_data_parsing(files: list[Path]) -> list[Check]:
    failures = 0
    json_count = 0
    yaml_count = 0
    for path in files:
        if not _is_safe_regular_file(path):
            continue
        try:
            if path.suffix == ".json":
                json.loads(path.read_text(encoding="utf-8"))
                json_count += 1
            elif path.suffix in {".cff", ".yaml", ".yml"}:
                yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
                yaml_count += 1
        except (OSError, UnicodeError, ValueError, yaml.YAMLError):
            failures += 1
    return [
        Check(
            "strict_json_yaml_parsing",
            failures == 0,
            f"json={json_count} yaml={yaml_count} failures={failures}",
        )
    ]


def audit() -> list[Check]:
    files = _candidate_files()
    return [
        *_candidate_symlink_checks(files),
        *_history_inventory(),
        *_history_paths_and_credentials(),
        *_current_content_checks(files),
        *_blob_and_payload_checks(files),
        *_metadata_and_legal_checks(),
        *_workflow_checks(),
        *_repository_hygiene(files),
        *_strict_data_parsing(files),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit a privacy-safe JSON result")
    args = parser.parse_args()
    checks = audit()
    passed = all(check.passed for check in checks)
    result = {
        "schema": "omiv.public-release-readiness-audit.v1",
        "baseline": BASELINE,
        "classification": "PASS" if passed else "FAIL",
        "checks": [asdict(check) for check in checks],
        "coverage": {
            "candidate_files": len(_candidate_files()),
            "credential_pattern_classes": 6,
            "history_surfaces": [
                "annotated_tag_messages",
                "commit_messages",
                "reachable_blob_sizes",
                "reachable_commit_patches",
            ],
            "maximum_text_file_bytes": MAX_PUBLIC_FILE_BYTES,
        },
        "limitations": [
            "Pattern-based secret scanning is heuristic and is not a substitute for a "
            "dedicated secret scanner.",
            "Binary content is audited by type and size but is not decoded as text.",
            "Files excluded by Git ignore rules are outside the candidate-public file set.",
        ],
        "privacy": {
            "approved_author_identity": "OWNER_APPROVED",
            "approved_historical_path_fingerprints": len(APPROVED_PATH_FINGERPRINTS),
            "sensitive_values_serialized": 0,
        },
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for check in checks:
            print(f"{'PASS' if check.passed else 'FAIL'} {check.name}: {check.detail}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
