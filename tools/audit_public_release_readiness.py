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
IDENTITY_FINGERPRINT_DOMAIN = b"omiv.identity.v1\0"
OWNER_APPROVED_HUMAN_IDENTITY_SHA256 = (
    "93ee44c41ca32a3d205a425abccb8c7f10f4802185dc02016a8f8da1348ab0d3"
)
IDENTITY_CATEGORIES = (
    "INVALID_IDENTITY_RECORD",
    "OWNER_APPROVED_HUMAN_IDENTITY",
    "SYNTHETIC_TEST_IDENTITY",
    "UNKNOWN_AUTOMATION_IDENTITY",
    "UNKNOWN_HUMAN_IDENTITY",
    "VERIFIED_PLATFORM_SERVICE_IDENTITY",
)
IDENTITY_ROLES = frozenset({"AUTHOR", "COMMITTER", "TAGGER"})
REF_CLASSIFICATIONS = frozenset(
    {
        "ANNOTATED_TAG",
        "GIT_NOTE_OR_OTHER_REF",
        "LOCAL_BRANCH",
        "MAIN_HISTORY",
        "PULL_REQUEST_REF",
        "REMOTE_AUTOMATION_BRANCH",
        "REMOTE_OTHER_BRANCH",
        "TAG_HISTORY",
    }
)
NO_PLATFORM_AUTHORITY = "NO_OWNER_PUBLISHER_MAINTAINER_RELEASE_OR_REPOSITORY_AUTHORITY"
REQUIRED_PLATFORM_PROVENANCE = frozenset(
    {
        "GITHUB_OFFICIAL_SERVICE_DOCUMENTATION",
        "GITHUB_REST_COMMIT_ACTOR_ASSOCIATION",
        "GITHUB_REST_COMMIT_SIGNATURE_VERIFIED_VALID",
    }
)
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


@dataclass(frozen=True)
class IdentityObservation:
    fingerprint: str
    roles: tuple[str, ...]
    reachable_ref_classifications: tuple[str, ...]
    valid_record: bool = True


@dataclass(frozen=True)
class PlatformIdentityPolicy:
    fingerprint: str
    allowed_roles: tuple[str, ...]
    allowed_ref_classifications: tuple[str, ...]
    purpose: str
    evidence_sources: tuple[str, ...]
    authority_limit: str = NO_PLATFORM_AUTHORITY


VERIFIED_PLATFORM_SERVICE_POLICIES = {
    "5f65310d79860e79e1e7015a5f25bc4e49eebbfaa2a53fb79490481c8010f832": (
        PlatformIdentityPolicy(
            fingerprint=("5f65310d79860e79e1e7015a5f25bc4e49eebbfaa2a53fb79490481c8010f832"),
            allowed_roles=("AUTHOR",),
            allowed_ref_classifications=("REMOTE_AUTOMATION_BRANCH",),
            purpose="GITHUB_DEPENDABOT_UPDATE_AUTHOR",
            evidence_sources=tuple(sorted(REQUIRED_PLATFORM_PROVENANCE)),
        )
    ),
    "5a85c6139ec6780f0c4d38ea5c6a032076101b8871c956a3032bdcfaf480bc9a": (
        PlatformIdentityPolicy(
            fingerprint=("5a85c6139ec6780f0c4d38ea5c6a032076101b8871c956a3032bdcfaf480bc9a"),
            allowed_roles=("COMMITTER",),
            allowed_ref_classifications=("REMOTE_AUTOMATION_BRANCH",),
            purpose="GITHUB_WEB_FLOW_SIGNED_DEPENDABOT_COMMITTER",
            evidence_sources=tuple(sorted(REQUIRED_PLATFORM_PROVENANCE)),
        )
    ),
}


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


def _identity_fingerprint(name: bytes, email: bytes) -> str:
    return hashlib.sha256(IDENTITY_FINGERPRINT_DOMAIN + name + b"\0" + email).hexdigest()


def _ref_classification(refname: str) -> str:
    if refname == "refs/heads/main" or re.fullmatch(r"refs/remotes/[^/]+/main", refname):
        return "MAIN_HISTORY"
    if refname.startswith("refs/pull/"):
        return "PULL_REQUEST_REF"
    if re.match(r"refs/remotes/[^/]+/dependabot/", refname):
        return "REMOTE_AUTOMATION_BRANCH"
    if refname.startswith("refs/remotes/"):
        return "REMOTE_OTHER_BRANCH"
    if refname.startswith("refs/heads/"):
        return "LOCAL_BRANCH"
    if refname.startswith("refs/tags/"):
        return "TAG_HISTORY"
    return "GIT_NOTE_OR_OTHER_REF"


def _commit_ref_classifications() -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    refnames = sorted(
        row.decode("utf-8", errors="strict")
        for row in _git("for-each-ref", "--format=%(refname)").splitlines()
        if row
    )
    for refname in refnames:
        classification = _ref_classification(refname)
        for commit in _git("rev-list", refname).decode("ascii").splitlines():
            result.setdefault(commit, set()).add(classification)
    return result


def _history_identity_observations() -> list[IdentityObservation]:
    commit_classes = _commit_ref_classifications()
    records: dict[str, dict[str, Any]] = {}

    def add(name: bytes, email: bytes, role: str, refs: set[str]) -> None:
        fingerprint = _identity_fingerprint(name, email)
        record = records.setdefault(
            fingerprint,
            {"roles": set(), "refs": set(), "valid": True},
        )
        record["roles"].add(role)
        record["refs"].update(refs)
        record["valid"] = bool(record["valid"] and name and email and role in IDENTITY_ROLES)

    commit_rows = _git(
        "log",
        "--all",
        "--format=%H%x00%an%x00%ae%x00%cn%x00%ce",
    ).splitlines()
    for row in commit_rows:
        fields = row.split(b"\0")
        if len(fields) != 5:
            fingerprint = hashlib.sha256(IDENTITY_FINGERPRINT_DOMAIN + row).hexdigest()
            records[fingerprint] = {"roles": set(), "refs": set(), "valid": False}
            continue
        commit = fields[0].decode("ascii")
        refs = commit_classes.get(commit, {"GIT_NOTE_OR_OTHER_REF"})
        add(fields[1], fields[2], "AUTHOR", refs)
        add(fields[3], fields[4], "COMMITTER", refs)

    tag_rows = _git(
        "for-each-ref",
        "--format=%(objecttype)%00%(taggername)%00%(taggeremail)",
        "refs/tags",
    ).splitlines()
    for row in tag_rows:
        fields = row.split(b"\0")
        if len(fields) != 3 or fields[0] != b"tag":
            continue
        add(fields[1], fields[2].strip(b"<>"), "TAGGER", {"ANNOTATED_TAG"})

    return [
        IdentityObservation(
            fingerprint=fingerprint,
            roles=tuple(sorted(record["roles"])),
            reachable_ref_classifications=tuple(sorted(record["refs"])),
            valid_record=bool(record["valid"]),
        )
        for fingerprint, record in sorted(records.items())
    ]


def _platform_policy_is_valid(policy: PlatformIdentityPolicy) -> bool:
    return bool(
        re.fullmatch(r"[0-9a-f]{64}", policy.fingerprint)
        and set(policy.allowed_roles).issubset(IDENTITY_ROLES)
        and policy.allowed_roles
        and set(policy.allowed_ref_classifications).issubset(REF_CLASSIFICATIONS)
        and policy.allowed_ref_classifications
        and REQUIRED_PLATFORM_PROVENANCE.issubset(policy.evidence_sources)
        and policy.authority_limit == NO_PLATFORM_AUTHORITY
    )


def _classify_identity(
    observation: IdentityObservation,
    *,
    platform_policies: dict[str, PlatformIdentityPolicy] | None = None,
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> str:
    policies = (
        VERIFIED_PLATFORM_SERVICE_POLICIES if platform_policies is None else platform_policies
    )
    if (
        not observation.valid_record
        or not re.fullmatch(r"[0-9a-f]{64}", observation.fingerprint)
        or not observation.roles
        or not set(observation.roles).issubset(IDENTITY_ROLES)
        or not observation.reachable_ref_classifications
        or not set(observation.reachable_ref_classifications).issubset(REF_CLASSIFICATIONS)
    ):
        return "INVALID_IDENTITY_RECORD"
    if observation.fingerprint == OWNER_APPROVED_HUMAN_IDENTITY_SHA256:
        return "OWNER_APPROVED_HUMAN_IDENTITY"
    if observation.fingerprint in synthetic_test_fingerprints:
        return "SYNTHETIC_TEST_IDENTITY"
    policy = policies.get(observation.fingerprint)
    if (
        policy is not None
        and _platform_policy_is_valid(policy)
        and set(observation.roles).issubset(policy.allowed_roles)
        and set(observation.reachable_ref_classifications).issubset(
            policy.allowed_ref_classifications
        )
    ):
        return "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    if policy is not None or set(observation.reachable_ref_classifications) == {
        "REMOTE_AUTOMATION_BRANCH"
    }:
        return "UNKNOWN_AUTOMATION_IDENTITY"
    return "UNKNOWN_HUMAN_IDENTITY"


def _identity_report_records(
    observations: list[IdentityObservation],
    *,
    platform_policies: dict[str, PlatformIdentityPolicy] | None = None,
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    policies = (
        VERIFIED_PLATFORM_SERVICE_POLICIES if platform_policies is None else platform_policies
    )
    result: list[dict[str, Any]] = []
    for observation in observations:
        category = _classify_identity(
            observation,
            platform_policies=policies,
            synthetic_test_fingerprints=synthetic_test_fingerprints,
        )
        policy = policies.get(observation.fingerprint)
        if category == "OWNER_APPROVED_HUMAN_IDENTITY":
            purpose = "OWNER_APPROVED_PUBLIC_IDENTITY_DISCLOSURE"
            evidence_sources = ("OWNER_RECORDED_IDENTITY_FINGERPRINT",)
            authority_limit = "IDENTITY_DISCLOSURE_APPROVAL_ONLY"
        elif category == "VERIFIED_PLATFORM_SERVICE_IDENTITY" and policy is not None:
            purpose = policy.purpose
            evidence_sources = policy.evidence_sources
            authority_limit = policy.authority_limit
        elif category == "SYNTHETIC_TEST_IDENTITY":
            purpose = "EXPLICIT_TEST_FIXTURE_ONLY"
            evidence_sources = ("TEST_CALLER_EXPLICIT_FINGERPRINT",)
            authority_limit = "NO_AUTHORITY"
        else:
            purpose = "UNCLASSIFIED"
            evidence_sources = ()
            authority_limit = "NO_AUTHORITY"
        result.append(
            {
                "authority_limit": authority_limit,
                "category": category,
                "evidence_sources": list(evidence_sources),
                "fingerprint": observation.fingerprint,
                "purpose": purpose,
                "reachable_ref_classifications": list(observation.reachable_ref_classifications),
                "roles": list(observation.roles),
            }
        )
    return sorted(result, key=lambda record: record["fingerprint"])


def _identity_classification_check(
    observations: list[IdentityObservation],
    *,
    platform_policies: dict[str, PlatformIdentityPolicy] | None = None,
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> Check:
    records = _identity_report_records(
        observations,
        platform_policies=platform_policies,
        synthetic_test_fingerprints=synthetic_test_fingerprints,
    )
    categories = [record["category"] for record in records]
    human_count = categories.count("OWNER_APPROVED_HUMAN_IDENTITY")
    service_count = categories.count("VERIFIED_PLATFORM_SERVICE_IDENTITY")
    unknown_count = categories.count("UNKNOWN_HUMAN_IDENTITY") + categories.count(
        "UNKNOWN_AUTOMATION_IDENTITY"
    )
    invalid_count = categories.count("INVALID_IDENTITY_RECORD")
    synthetic_count = categories.count("SYNTHETIC_TEST_IDENTITY")
    passed = bool(
        human_count == 1 and unknown_count == 0 and invalid_count == 0 and synthetic_count == 0
    )
    return Check(
        "approved_author_identity",
        passed,
        " ".join(
            (
                f"approved_humans={human_count}",
                f"verified_platform_services={service_count}",
                f"unknown={unknown_count}",
                f"invalid={invalid_count}",
            )
        ),
    )


def _history_inventory() -> list[Check]:
    commits = _git("rev-list", "--all", "--count").decode().strip()
    tags = _git("tag", "--list").decode().splitlines()
    observations = _history_identity_observations()
    return [
        Check("reachable_history", int(commits) >= 36, f"commits={commits}"),
        Check("historical_tags", len(tags) == 9, f"tags={len(tags)}"),
        _identity_classification_check(observations),
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
    identity_records = _identity_report_records(_history_identity_observations())
    identity_counts = {
        category: sum(record["category"] == category for record in identity_records)
        for category in IDENTITY_CATEGORIES
    }
    reviewed_platform_policies = [
        {
            "allowed_ref_classifications": list(policy.allowed_ref_classifications),
            "allowed_roles": list(policy.allowed_roles),
            "authority_limit": policy.authority_limit,
            "evidence_sources": list(policy.evidence_sources),
            "fingerprint": policy.fingerprint,
            "purpose": policy.purpose,
        }
        for policy in sorted(
            VERIFIED_PLATFORM_SERVICE_POLICIES.values(), key=lambda item: item.fingerprint
        )
    ]
    result = {
        "schema": "omiv.public-release-readiness-audit.v1",
        "baseline": BASELINE,
        "classification": "PASS" if passed else "FAIL",
        "checks": [asdict(check) for check in checks],
        "coverage": {
            "candidate_files": len(_candidate_files()),
            "credential_pattern_classes": 6,
            "history_surfaces": [
                "all_local_remote_and_tag_refs",
                "annotated_tag_messages",
                "annotated_tag_tagger_identities",
                "commit_author_identities",
                "commit_committer_identities",
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
            "identity_category_counts": identity_counts,
            "identity_fingerprint_domain": "omiv.identity.v1",
            "identity_records": identity_records,
            "identity_taxonomy": list(IDENTITY_CATEGORIES),
            "reviewed_platform_service_policies": reviewed_platform_policies,
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
