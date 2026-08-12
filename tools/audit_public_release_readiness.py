#!/usr/bin/env python3
"""Bounded public-release audit that never reports private source values."""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
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
    "INVALID_IDENTITY",
    "OWNER_APPROVED_HUMAN_IDENTITY",
    "SYNTHETIC_TEST_IDENTITY",
    "UNVERIFIED_PLATFORM_SERVICE_CLAIM",
    "UNKNOWN_AUTOMATION_IDENTITY",
    "UNKNOWN_HUMAN_IDENTITY",
    "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
    "VERIFIED_PLATFORM_SERVICE_IDENTITY",
)
IDENTITY_ROLES = frozenset({"AUTHOR", "COMMITTER", "TAGGER"})
PULL_REQUEST_EVIDENCE_STATUSES = (
    "AVAILABLE",
    "INDETERMINATE",
    "INVALID",
    "NOT_AVAILABLE",
)
PULL_REQUEST_MERGE_DISCREPANCIES = (
    "EVENT_TEST_MERGE_SHA_DIFFERS_FROM_CURRENT_CHECKOUT",
    "EVENT_TEST_MERGE_SHA_MATCHES_CURRENT_CHECKOUT",
    "EVENT_TEST_MERGE_SHA_NOT_RECORDED",
    "NOT_EVALUATED",
)
PULL_REQUEST_REQUIRED_EVENT_FIELDS = (
    "number",
    "pull_request.base.ref",
    "pull_request.base.sha",
    "pull_request.head.ref",
    "pull_request.head.sha",
    "pull_request.user.id",
    "repository.full_name",
    "repository.id",
)
PULL_REQUEST_ADVISORY_EVENT_FIELDS = ("pull_request.merge_commit_sha",)
PULL_REQUEST_EVIDENCE_REASON_CODES = (
    "ACTOR_EVIDENCE_NOT_AVAILABLE",
    "AVAILABLE",
    "BASE_REF_MISMATCH",
    "BASE_SHA_MISMATCH",
    "CHECKOUT_SHA_MISMATCH",
    "EVENT_FIELDS_INCOMPLETE",
    "EVENT_JSON_INVALID",
    "EVENT_NOT_PULL_REQUEST",
    "EVENT_PATH_NOT_AVAILABLE",
    "GIT_OBJECT_NOT_AVAILABLE",
    "HEAD_REF_MISMATCH",
    "HEAD_SHA_MISMATCH",
    "INTERNAL_VALIDATION_ERROR",
    "LIMIT_EXCEEDED",
    "MERGE_SHA_MISMATCH",
    "NOT_GITHUB_ACTIONS",
    "PARENT_COUNT_INVALID",
    "PARENT_ORDER_MISMATCH",
    "PR_METADATA_NOT_AVAILABLE",
    "PR_NUMBER_MISMATCH",
    "REF_SCOPE_MISMATCH",
    "REPOSITORY_MISMATCH",
    "SIGNATURE_NOT_VERIFIED",
    "SIGNER_MISMATCH",
)
REF_CLASSIFICATIONS = frozenset(
    {
        "ANNOTATED_TAG",
        "LOCAL_MAIN",
        "LOCAL_RELEASE_BRANCH",
        "PULL_REQUEST_HEAD_REF",
        "PULL_REQUEST_MERGE_REF",
        "REMOTE_DEPENDABOT_BRANCH",
        "REMOTE_MAIN",
        "REMOTE_OTHER_BRANCH",
        "REMOTE_RELEASE_BRANCH",
        "UNKNOWN_REF_SCOPE",
    }
)
NO_PLATFORM_AUTHORITY = "NO_OWNER_PUBLISHER_MAINTAINER_RELEASE_OR_REPOSITORY_AUTHORITY"
REQUIRED_PLATFORM_PROVENANCE = frozenset(
    {
        "GITHUB_OFFICIAL_SERVICE_DOCUMENTATION",
        "GITHUB_REST_COMMIT_ACTOR_ASSOCIATION",
        "GITHUB_REST_COMMIT_SIGNATURE_VERIFIED_VALID",
        "LOCAL_COMMIT_PARENT_TOPOLOGY",
        "LOCAL_SIGNATURE_SIGNER_KEY_ID",
    }
)
REQUIRED_PULL_REQUEST_PROVENANCE = REQUIRED_PLATFORM_PROVENANCE | frozenset(
    {
        "GITHUB_ACTIONS_PULL_REQUEST_EVENT",
        "GITHUB_REST_PULL_REQUEST_ASSOCIATION",
    }
)
REQUIRED_SIGNED_SQUASH_PROVENANCE = frozenset(
    {
        "AUTHORITATIVE_MAIN_REACHABILITY",
        "EXACT_AUTHOR_COMMITTER_FINGERPRINT_PAIR",
        "LOCAL_COMMIT_PARENT_TOPOLOGY",
        "LOCAL_CRYPTOGRAPHIC_SIGNATURE_VERIFICATION",
        "NORMALIZED_ORIGIN_REPOSITORY_IDENTITY",
        "REVIEWED_GITHUB_ACTOR_ASSOCIATION_POLICY",
        "SQUASH_PR_SUBJECT_ASSOCIATION_SIGNAL",
    }
)
GITHUB_REPOSITORY_FULL_NAME = "200lz/open-model-integration-validator"
GITHUB_REPOSITORY_ID = 1316060005
GITHUB_OWNER_ACTOR_ID = 145014769
GITHUB_DEPENDABOT_ACTOR_ID = 49699333
GITHUB_WEB_FLOW_ACTOR_ID = 19864447
GITHUB_WEB_FLOW_SIGNING_KEY_ID = "B5690EEEBB952194"
GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT = "968479A1AFF927E37D1A566BB5690EEEBB952194"
GITHUB_WEB_FLOW_SIGNING_KEY_PROFILE = ROOT / "docs/security/github-web-flow-signing-key.asc"
GITHUB_SQUASH_AUTHOR_FINGERPRINT = (
    "b71cf77f9b542abf081d730983ff66d44c6e26d949e55f9fb4db43f70779ddec"
)
GITHUB_SQUASH_COMMITTER_FINGERPRINT = (
    "5a85c6139ec6780f0c4d38ea5c6a032076101b8871c956a3032bdcfaf480bc9a"
)
PR1_NUMBER = 1
PR1_HEAD_REF = "dependabot/pip/main/cryptography-gte-46.0.1-and-lt-51"
PR1_HEAD_SHA = "fe0c7001fa769097357bbd3f003eac650a1b6910"
PR1_HEAD_PARENT = "69b04688ba3d77a5dc74e22d80f3309e9becbf79"
PR1_MERGE_SHA = "c05445c3940f90e49cf6b33cbe71560eccb54767"
PR1_MERGE_BASE_SHA = "d5c53eeda9cf41dbb5f5b93a295cab9cd63d20fd"
PR2_NUMBER = 2
PR2_BASE_SHA = "d5c53eeda9cf41dbb5f5b93a295cab9cd63d20fd"
PR2_HEAD_REF = "release/v0.10.0-public-preview"
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
class IdentityOccurrence:
    object_sha: str
    role: str
    refnames: tuple[str, ...]
    ref_classifications: tuple[str, ...]
    parents: tuple[str, ...] = ()
    signature_key_ids: tuple[str, ...] = ()
    valid_record: bool = True


@dataclass(frozen=True)
class IdentityObservation:
    fingerprint: str
    roles: tuple[str, ...]
    reachable_ref_classifications: tuple[str, ...]
    occurrences: tuple[IdentityOccurrence, ...] = ()
    valid_record: bool = True


@dataclass(frozen=True)
class StaticPlatformOccurrencePolicy:
    object_sha: str
    role: str
    allowed_refnames: tuple[str, ...]
    parents: tuple[str, ...]
    actor_id: int
    signature_key_ids: tuple[str, ...]


@dataclass(frozen=True)
class PullRequestRolePolicy:
    repository_full_name: str
    repository_id: int
    pr_number: int | None
    base_ref: str
    base_sha: str | None
    head_ref: str | None
    role: str
    actor_id: int
    signer_actor_id: int
    signature_key_id: str
    current_event_scope: bool = False


@dataclass(frozen=True)
class SignedSquashRolePolicy:
    repository_full_name: str
    authoritative_ref_classifications: tuple[str, ...]
    role: str
    reviewed_actor_id: int
    paired_fingerprint: str
    signer_key_id: str
    signer_fingerprint: str
    parent_count: int = 1


@dataclass(frozen=True)
class PlatformIdentityPolicy:
    fingerprint: str
    purpose: str
    evidence_sources: tuple[str, ...]
    static_occurrences: tuple[StaticPlatformOccurrencePolicy, ...] = ()
    pull_request_roles: tuple[PullRequestRolePolicy, ...] = ()
    signed_squash_roles: tuple[SignedSquashRolePolicy, ...] = ()
    identity_category: str = "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    authority_limit: str = NO_PLATFORM_AUTHORITY

    @property
    def allowed_roles(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {item.role for item in self.static_occurrences}
                | {item.role for item in self.pull_request_roles}
                | {item.role for item in self.signed_squash_roles}
            )
        )

    @property
    def allowed_ref_classifications(self) -> tuple[str, ...]:
        result: set[str] = set()
        for static_item in self.static_occurrences:
            result.update(_ref_classification(refname) for refname in static_item.allowed_refnames)
        if self.pull_request_roles:
            result.add("PULL_REQUEST_MERGE_REF")
        for squash_item in self.signed_squash_roles:
            result.update(squash_item.authoritative_ref_classifications)
        return tuple(sorted(result))


@dataclass(frozen=True)
class PullRequestEvidence:
    valid: bool
    repository_full_name: str
    repository_id: int
    pr_number: int
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    merge_sha: str
    merge_ref: str
    parents: tuple[str, ...]
    author_actor_id: int
    committer_actor_id: int
    signature_verified: bool
    signature_reason: str
    signature_key_ids: tuple[str, ...]
    evidence_sources: tuple[str, ...]


@dataclass(frozen=True)
class PullRequestEvidenceResult:
    status: str
    reason_code: str
    merge_discrepancy: str
    safe_facts: dict[str, bool | int]
    missing_required_fields: tuple[str, ...] = ()
    missing_advisory_fields: tuple[str, ...] = ()
    null_required_fields: tuple[str, ...] = ()
    null_advisory_fields: tuple[str, ...] = ()
    evidence: PullRequestEvidence | None = None


@dataclass(frozen=True)
class GithubSignedSquashCommitIdentityEvidence:
    valid: bool
    repository_full_name: str
    commit_sha: str
    tree_sha: str
    parents: tuple[str, ...]
    pr_number: int
    author_fingerprint: str
    committer_fingerprint: str
    signature_key_id: str
    signer_fingerprint: str
    authoritative_ref_classifications: tuple[str, ...]
    observed_git_identity: bool
    reviewed_github_actor_association: bool
    live_actor_observation_supplied: bool
    authority_limit: str = NO_PLATFORM_AUTHORITY


@dataclass(frozen=True)
class GithubSignedSquashEvidenceResult:
    status: str
    reason_code: str
    safe_facts: dict[str, bool | int]
    evidence: tuple[GithubSignedSquashCommitIdentityEvidence, ...] = ()


@dataclass(frozen=True)
class ProtectedPullRequestSquashMergeEvidenceResult:
    status: str
    reason_code: str
    safe_facts: dict[str, bool | int]


@dataclass(frozen=True)
class GitHubJsonResult:
    available: bool
    reason_code: str
    status_code: int
    payload: dict[str, Any] | None = None


PR1_HEAD_ALLOWED_REFS = (
    f"refs/remotes/origin/{PR1_HEAD_REF}",
    "refs/pull/1/head",
    "refs/remotes/pull/1/head",
    "refs/pull/1/merge",
    "refs/remotes/pull/1/merge",
)
PR1_MERGE_ALLOWED_REFS = ("refs/pull/1/merge", "refs/remotes/pull/1/merge")
PR2_COMMITTER_POLICY = PullRequestRolePolicy(
    repository_full_name=GITHUB_REPOSITORY_FULL_NAME,
    repository_id=GITHUB_REPOSITORY_ID,
    pr_number=PR2_NUMBER,
    base_ref="main",
    base_sha=PR2_BASE_SHA,
    head_ref=PR2_HEAD_REF,
    role="COMMITTER",
    actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
    signer_actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
    signature_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
)
PR2_AUTHOR_POLICY = PullRequestRolePolicy(
    repository_full_name=GITHUB_REPOSITORY_FULL_NAME,
    repository_id=GITHUB_REPOSITORY_ID,
    pr_number=PR2_NUMBER,
    base_ref="main",
    base_sha=PR2_BASE_SHA,
    head_ref=PR2_HEAD_REF,
    role="AUTHOR",
    actor_id=GITHUB_OWNER_ACTOR_ID,
    signer_actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
    signature_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
)
CURRENT_PULL_REQUEST_COMMITTER_POLICY = PullRequestRolePolicy(
    repository_full_name=GITHUB_REPOSITORY_FULL_NAME,
    repository_id=GITHUB_REPOSITORY_ID,
    pr_number=None,
    base_ref="main",
    base_sha=None,
    head_ref=None,
    role="COMMITTER",
    actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
    signer_actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
    signature_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
    current_event_scope=True,
)
CURRENT_PULL_REQUEST_AUTHOR_POLICY = PullRequestRolePolicy(
    repository_full_name=GITHUB_REPOSITORY_FULL_NAME,
    repository_id=GITHUB_REPOSITORY_ID,
    pr_number=None,
    base_ref="main",
    base_sha=None,
    head_ref=None,
    role="AUTHOR",
    actor_id=GITHUB_OWNER_ACTOR_ID,
    signer_actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
    signature_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
    current_event_scope=True,
)
VERIFIED_PLATFORM_IDENTITY_POLICIES = {
    "5f65310d79860e79e1e7015a5f25bc4e49eebbfaa2a53fb79490481c8010f832": PlatformIdentityPolicy(
        fingerprint="5f65310d79860e79e1e7015a5f25bc4e49eebbfaa2a53fb79490481c8010f832",
        purpose="GITHUB_DEPENDABOT_UPDATE_AND_PR_MERGE_AUTHOR",
        evidence_sources=tuple(sorted(REQUIRED_PLATFORM_PROVENANCE)),
        static_occurrences=(
            StaticPlatformOccurrencePolicy(
                object_sha=PR1_HEAD_SHA,
                role="AUTHOR",
                allowed_refnames=PR1_HEAD_ALLOWED_REFS,
                parents=(PR1_HEAD_PARENT,),
                actor_id=GITHUB_DEPENDABOT_ACTOR_ID,
                signature_key_ids=(GITHUB_WEB_FLOW_SIGNING_KEY_ID,),
            ),
            StaticPlatformOccurrencePolicy(
                object_sha=PR1_MERGE_SHA,
                role="AUTHOR",
                allowed_refnames=PR1_MERGE_ALLOWED_REFS,
                parents=(PR1_MERGE_BASE_SHA, PR1_HEAD_SHA),
                actor_id=GITHUB_DEPENDABOT_ACTOR_ID,
                signature_key_ids=(GITHUB_WEB_FLOW_SIGNING_KEY_ID,),
            ),
        ),
    ),
    "5a85c6139ec6780f0c4d38ea5c6a032076101b8871c956a3032bdcfaf480bc9a": PlatformIdentityPolicy(
        fingerprint="5a85c6139ec6780f0c4d38ea5c6a032076101b8871c956a3032bdcfaf480bc9a",
        purpose="GITHUB_WEB_FLOW_SIGNED_DEPENDABOT_AND_PR_MERGE_COMMITTER",
        evidence_sources=tuple(
            sorted(REQUIRED_PULL_REQUEST_PROVENANCE | REQUIRED_SIGNED_SQUASH_PROVENANCE)
        ),
        static_occurrences=(
            StaticPlatformOccurrencePolicy(
                object_sha=PR1_HEAD_SHA,
                role="COMMITTER",
                allowed_refnames=PR1_HEAD_ALLOWED_REFS,
                parents=(PR1_HEAD_PARENT,),
                actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
                signature_key_ids=(GITHUB_WEB_FLOW_SIGNING_KEY_ID,),
            ),
            StaticPlatformOccurrencePolicy(
                object_sha=PR1_MERGE_SHA,
                role="COMMITTER",
                allowed_refnames=PR1_MERGE_ALLOWED_REFS,
                parents=(PR1_MERGE_BASE_SHA, PR1_HEAD_SHA),
                actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
                signature_key_ids=(GITHUB_WEB_FLOW_SIGNING_KEY_ID,),
            ),
        ),
        pull_request_roles=(PR2_COMMITTER_POLICY, CURRENT_PULL_REQUEST_COMMITTER_POLICY),
        signed_squash_roles=(
            SignedSquashRolePolicy(
                repository_full_name=GITHUB_REPOSITORY_FULL_NAME,
                authoritative_ref_classifications=("LOCAL_MAIN", "REMOTE_MAIN"),
                role="COMMITTER",
                reviewed_actor_id=GITHUB_WEB_FLOW_ACTOR_ID,
                paired_fingerprint=GITHUB_SQUASH_AUTHOR_FINGERPRINT,
                signer_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
                signer_fingerprint=GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT,
            ),
        ),
    ),
    "b71cf77f9b542abf081d730983ff66d44c6e26d949e55f9fb4db43f70779ddec": PlatformIdentityPolicy(
        fingerprint="b71cf77f9b542abf081d730983ff66d44c6e26d949e55f9fb4db43f70779ddec",
        purpose="GITHUB_MEDIATED_ACCOUNT_PR_MERGE_AND_MAIN_SQUASH_AUTHOR",
        evidence_sources=tuple(
            sorted(REQUIRED_PULL_REQUEST_PROVENANCE | REQUIRED_SIGNED_SQUASH_PROVENANCE)
        ),
        pull_request_roles=(PR2_AUTHOR_POLICY, CURRENT_PULL_REQUEST_AUTHOR_POLICY),
        signed_squash_roles=(
            SignedSquashRolePolicy(
                repository_full_name=GITHUB_REPOSITORY_FULL_NAME,
                authoritative_ref_classifications=("LOCAL_MAIN", "REMOTE_MAIN"),
                role="AUTHOR",
                reviewed_actor_id=GITHUB_OWNER_ACTOR_ID,
                paired_fingerprint=GITHUB_SQUASH_COMMITTER_FINGERPRINT,
                signer_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
                signer_fingerprint=GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT,
            ),
        ),
        identity_category="VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
    ),
}


class UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
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
    if refname == "refs/heads/main":
        return "LOCAL_MAIN"
    if refname == f"refs/heads/{PR2_HEAD_REF}":
        return "LOCAL_RELEASE_BRANCH"
    if re.fullmatch(r"refs/(?:pull|remotes/pull)/[0-9]+/head", refname):
        return "PULL_REQUEST_HEAD_REF"
    if re.fullmatch(r"refs/(?:pull|remotes/pull)/[0-9]+/merge", refname):
        return "PULL_REQUEST_MERGE_REF"
    if re.match(r"refs/remotes/[^/]+/dependabot/", refname):
        return "REMOTE_DEPENDABOT_BRANCH"
    if re.fullmatch(r"refs/remotes/[^/]+/(?:main|HEAD)", refname):
        return "REMOTE_MAIN"
    if refname == f"refs/remotes/origin/{PR2_HEAD_REF}":
        return "REMOTE_RELEASE_BRANCH"
    if refname.startswith("refs/remotes/"):
        return "REMOTE_OTHER_BRANCH"
    if refname.startswith("refs/tags/"):
        return "ANNOTATED_TAG"
    return "UNKNOWN_REF_SCOPE"


def _commit_ref_inventory() -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    refnames = sorted(
        row.decode("utf-8", errors="strict")
        for row in _git("for-each-ref", "--format=%(refname)").splitlines()
        if row
    )
    for refname in refnames:
        for commit in _git("rev-list", refname).decode("ascii").splitlines():
            result.setdefault(commit, set()).add(refname)
    return result


@functools.cache
def _commit_signature_key_ids(commit_sha: str) -> tuple[str, ...]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        return ()
    raw = _git("cat-file", "commit", commit_sha)
    signature: list[bytes] = []
    collecting = False
    for line in raw.splitlines():
        if line.startswith(b"gpgsig "):
            collecting = True
            signature.append(line[len(b"gpgsig ") :])
        elif collecting and line.startswith(b" "):
            signature.append(line[1:])
        elif collecting:
            break
    if not signature:
        return ()
    try:
        packets = subprocess.run(
            ["gpg", "--batch", "--list-packets"],
            cwd=ROOT,
            input=b"\n".join(signature) + b"\n",
            check=True,
            capture_output=True,
        ).stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.CalledProcessError):
        return ()
    return tuple(sorted(set(re.findall(r"issuer key ID ([0-9A-F]{16})", packets))))


@functools.lru_cache(maxsize=1)
def _history_identity_observations() -> list[IdentityObservation]:
    commit_refs = _commit_ref_inventory()
    records: dict[str, dict[str, Any]] = {}

    def add(
        name: bytes,
        email: bytes,
        *,
        object_sha: str,
        role: str,
        refnames: set[str],
        parents: tuple[str, ...] = (),
        signature_key_ids: tuple[str, ...] = (),
    ) -> None:
        fingerprint = _identity_fingerprint(name, email)
        record = records.setdefault(
            fingerprint,
            {"roles": set(), "refs": set(), "occurrences": [], "valid": True},
        )
        classifications = {_ref_classification(refname) for refname in refnames}
        record["roles"].add(role)
        record["refs"].update(classifications)
        record["occurrences"].append(
            IdentityOccurrence(
                object_sha=object_sha,
                role=role,
                refnames=tuple(sorted(refnames)),
                ref_classifications=tuple(sorted(classifications)),
                parents=parents,
                signature_key_ids=signature_key_ids,
                valid_record=bool(name and email and role in IDENTITY_ROLES),
            )
        )
        record["valid"] = bool(record["valid"] and name and email and role in IDENTITY_ROLES)

    commit_rows = _git(
        "log",
        "--all",
        "--format=%H%x00%P%x00%an%x00%ae%x00%cn%x00%ce",
    ).splitlines()
    for row in commit_rows:
        fields = row.split(b"\0")
        if len(fields) != 6:
            fingerprint = hashlib.sha256(IDENTITY_FINGERPRINT_DOMAIN + row).hexdigest()
            records[fingerprint] = {
                "roles": set(),
                "refs": set(),
                "occurrences": [],
                "valid": False,
            }
            continue
        commit = fields[0].decode("ascii")
        parents = tuple(item.decode("ascii") for item in fields[1].split() if item)
        refnames = commit_refs.get(commit, set())
        author_fingerprint = _identity_fingerprint(fields[2], fields[3])
        committer_fingerprint = _identity_fingerprint(fields[4], fields[5])
        needs_signature = bool(
            author_fingerprint in VERIFIED_PLATFORM_IDENTITY_POLICIES
            or committer_fingerprint in VERIFIED_PLATFORM_IDENTITY_POLICIES
        )
        signature_key_ids = _commit_signature_key_ids(commit) if needs_signature else ()
        add(
            fields[2],
            fields[3],
            object_sha=commit,
            role="AUTHOR",
            refnames=refnames,
            parents=parents,
            signature_key_ids=signature_key_ids,
        )
        add(
            fields[4],
            fields[5],
            object_sha=commit,
            role="COMMITTER",
            refnames=refnames,
            parents=parents,
            signature_key_ids=signature_key_ids,
        )

    tag_rows = _git(
        "for-each-ref",
        "--format=%(objecttype)%00%(objectname)%00%(refname)%00%(taggername)%00%(taggeremail)",
        "refs/tags",
    ).splitlines()
    for row in tag_rows:
        fields = row.split(b"\0")
        if len(fields) != 5 or fields[0] != b"tag":
            continue
        add(
            fields[3],
            fields[4].strip(b"<>"),
            object_sha=fields[1].decode("ascii"),
            role="TAGGER",
            refnames={fields[2].decode("utf-8", errors="strict")},
        )

    return [
        IdentityObservation(
            fingerprint=fingerprint,
            roles=tuple(sorted(record["roles"])),
            reachable_ref_classifications=tuple(sorted(record["refs"])),
            occurrences=tuple(
                sorted(
                    record["occurrences"],
                    key=lambda item: (item.object_sha, item.role, item.refnames),
                )
            ),
            valid_record=bool(record["valid"]),
        )
        for fingerprint, record in sorted(records.items())
    ]


def _github_json(url: str) -> GitHubJsonResult:
    if not url.startswith("https://api.github.com/"):
        return GitHubJsonResult(False, "URL_REJECTED", 0)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "omiv-public-release-readiness-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(
            request, timeout=10, context=ssl.create_default_context()
        ) as response:
            payload = response.read(1_048_577)
            if response.status != 200:
                return GitHubJsonResult(False, "HTTP_STATUS_NOT_SUCCESS", response.status)
            if len(payload) > 1_048_576:
                return GitHubJsonResult(False, "RESPONSE_LIMIT_EXCEEDED", response.status)
        parsed = json.loads(payload)
    except urllib.error.HTTPError as exc:
        return GitHubJsonResult(False, "HTTP_STATUS_NOT_SUCCESS", exc.code)
    except (OSError, urllib.error.URLError):
        return GitHubJsonResult(False, "NETWORK_ERROR", 0)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return GitHubJsonResult(False, "RESPONSE_JSON_INVALID", 200)
    if not isinstance(parsed, dict):
        return GitHubJsonResult(False, "RESPONSE_SHAPE_INVALID", 200)
    return GitHubJsonResult(True, "AVAILABLE", 200, parsed)


def _pull_request_evidence_result(
    status: str,
    reason_code: str,
    safe_facts: dict[str, bool | int],
    evidence: PullRequestEvidence | None = None,
    merge_discrepancy: str = "NOT_EVALUATED",
    *,
    missing_required_fields: tuple[str, ...] = (),
    missing_advisory_fields: tuple[str, ...] = (),
    null_required_fields: tuple[str, ...] = (),
    null_advisory_fields: tuple[str, ...] = (),
) -> PullRequestEvidenceResult:
    if status not in PULL_REQUEST_EVIDENCE_STATUSES:
        raise ValueError("invalid pull-request evidence status")
    if reason_code not in PULL_REQUEST_EVIDENCE_REASON_CODES:
        raise ValueError("invalid pull-request evidence reason code")
    if merge_discrepancy not in PULL_REQUEST_MERGE_DISCREPANCIES:
        raise ValueError("invalid pull-request merge discrepancy")
    if any(not isinstance(value, (bool, int)) for value in safe_facts.values()):
        raise ValueError("pull-request evidence safe facts must be booleans or integers")
    if (status == "AVAILABLE") != (evidence is not None):
        raise ValueError("pull-request evidence availability mismatch")
    if (status == "AVAILABLE") != (merge_discrepancy != "NOT_EVALUATED"):
        raise ValueError("pull-request merge discrepancy availability mismatch")
    diagnostic_sets = (
        (missing_required_fields, PULL_REQUEST_REQUIRED_EVENT_FIELDS),
        (missing_advisory_fields, PULL_REQUEST_ADVISORY_EVENT_FIELDS),
        (null_required_fields, PULL_REQUEST_REQUIRED_EVENT_FIELDS),
        (null_advisory_fields, PULL_REQUEST_ADVISORY_EVENT_FIELDS),
    )
    if any(
        tuple(sorted(fields)) != fields or not set(fields).issubset(allowed)
        for fields, allowed in diagnostic_sets
    ):
        raise ValueError("invalid pull-request event field diagnostics")
    return PullRequestEvidenceResult(
        status=status,
        reason_code=reason_code,
        merge_discrepancy=merge_discrepancy,
        safe_facts=dict(sorted(safe_facts.items())),
        missing_required_fields=missing_required_fields,
        missing_advisory_fields=missing_advisory_fields,
        null_required_fields=null_required_fields,
        null_advisory_fields=null_advisory_fields,
        evidence=evidence,
    )


_MISSING_EVENT_FIELD = object()


def _event_field(payload: object, dotted_path: str) -> object:
    current = payload
    for component in dotted_path.split("."):
        if not isinstance(current, dict) or component not in current:
            return _MISSING_EVENT_FIELD
        current = current[component]
    return current


def _local_merge_ref_matches(pr_number: int, merge_sha: str) -> bool:
    local_merge_refs = (
        f"refs/pull/{pr_number}/merge",
        f"refs/remotes/pull/{pr_number}/merge",
    )
    return any(
        _git("rev-parse", "--verify", refname).decode("ascii").strip() == merge_sha
        for refname in local_merge_refs
        if subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", refname], cwd=ROOT, check=False
        ).returncode
        == 0
    )


@functools.lru_cache(maxsize=1)
def _current_pull_request_evidence() -> PullRequestEvidenceResult:
    facts: dict[str, bool | int] = {}
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return _pull_request_evidence_result(
            "NOT_AVAILABLE", "NOT_GITHUB_ACTIONS", {"github_actions": False}
        )
    facts["github_actions"] = True
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return _pull_request_evidence_result("NOT_AVAILABLE", "EVENT_NOT_PULL_REQUEST", facts)
    facts["pull_request_event"] = True
    if os.environ.get("GITHUB_REPOSITORY") != GITHUB_REPOSITORY_FULL_NAME:
        return _pull_request_evidence_result("INVALID", "REPOSITORY_MISMATCH", facts)
    facts["environment_repository_matches"] = True
    event_path_value = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path_value:
        return _pull_request_evidence_result("NOT_AVAILABLE", "EVENT_PATH_NOT_AVAILABLE", facts)
    event_path = Path(event_path_value)
    try:
        event_stat = event_path.lstat()
    except OSError:
        return _pull_request_evidence_result("NOT_AVAILABLE", "EVENT_PATH_NOT_AVAILABLE", facts)
    if event_path.is_symlink() or not event_path.is_file():
        return _pull_request_evidence_result("INVALID", "EVENT_PATH_NOT_AVAILABLE", facts)
    facts["event_path_regular"] = True
    if event_stat.st_size > 1_048_576:
        return _pull_request_evidence_result("INVALID", "LIMIT_EXCEEDED", facts)
    facts["event_size_within_limit"] = True
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError):
        return _pull_request_evidence_result("INVALID", "EVENT_JSON_INVALID", facts)
    except OSError:
        return _pull_request_evidence_result("NOT_AVAILABLE", "EVENT_PATH_NOT_AVAILABLE", facts)
    required_values = {
        field: _event_field(event, field) for field in PULL_REQUEST_REQUIRED_EVENT_FIELDS
    }
    advisory_values = {
        field: _event_field(event, field) for field in PULL_REQUEST_ADVISORY_EVENT_FIELDS
    }
    missing_required_fields = tuple(
        sorted(field for field, value in required_values.items() if value is _MISSING_EVENT_FIELD)
    )
    missing_advisory_fields = tuple(
        sorted(field for field, value in advisory_values.items() if value is _MISSING_EVENT_FIELD)
    )
    null_required_fields = tuple(
        sorted(field for field, value in required_values.items() if value is None)
    )
    null_advisory_fields = tuple(
        sorted(field for field, value in advisory_values.items() if value is None)
    )
    facts["missing_required_field_count"] = len(missing_required_fields)
    facts["missing_advisory_field_count"] = len(missing_advisory_fields)
    facts["null_required_field_count"] = len(null_required_fields)
    facts["null_advisory_field_count"] = len(null_advisory_fields)

    def event_result(
        status: str,
        reason_code: str,
        *,
        evidence: PullRequestEvidence | None = None,
        merge_discrepancy: str = "NOT_EVALUATED",
    ) -> PullRequestEvidenceResult:
        return _pull_request_evidence_result(
            status,
            reason_code,
            facts,
            evidence=evidence,
            merge_discrepancy=merge_discrepancy,
            missing_required_fields=missing_required_fields,
            missing_advisory_fields=missing_advisory_fields,
            null_required_fields=null_required_fields,
            null_advisory_fields=null_advisory_fields,
        )

    if missing_required_fields or null_required_fields:
        return event_result("INVALID", "EVENT_FIELDS_INCOMPLETE")
    try:
        pr_number = int(str(required_values["number"]))
        base_ref = str(required_values["pull_request.base.ref"])
        base_sha = str(required_values["pull_request.base.sha"])
        head_ref = str(required_values["pull_request.head.ref"])
        head_sha = str(required_values["pull_request.head.sha"])
        repository_id = int(str(required_values["repository.id"]))
        repository_full_name = str(required_values["repository.full_name"])
        event_author_actor_id = int(str(required_values["pull_request.user.id"]))
    except (TypeError, ValueError):
        return event_result("INVALID", "EVENT_FIELDS_INCOMPLETE")
    if not all(re.fullmatch(r"[0-9a-f]{40}", item) for item in (base_sha, head_sha)):
        return event_result("INVALID", "EVENT_FIELDS_INCOMPLETE")
    event_merge_value = advisory_values["pull_request.merge_commit_sha"]
    event_merge_sha: str | None = None
    if event_merge_value is not _MISSING_EVENT_FIELD and event_merge_value is not None:
        if (
            not isinstance(event_merge_value, str)
            or re.fullmatch(r"[0-9a-f]{40}", event_merge_value) is None
        ):
            facts["advisory_merge_sha_malformed"] = True
            return event_result("INVALID", "EVENT_FIELDS_INCOMPLETE")
        event_merge_sha = event_merge_value
    facts["event_test_merge_recorded"] = event_merge_sha is not None
    facts["event_fields_complete"] = True
    if repository_full_name != GITHUB_REPOSITORY_FULL_NAME or repository_id != GITHUB_REPOSITORY_ID:
        return _pull_request_evidence_result("INVALID", "REPOSITORY_MISMATCH", facts)
    facts["event_repository_matches"] = True
    if pr_number <= 0:
        return event_result("INVALID", "PR_NUMBER_MISMATCH")
    facts["pr_number_valid"] = True
    if base_ref != "main" or os.environ.get("GITHUB_BASE_REF") != base_ref:
        return _pull_request_evidence_result("INVALID", "BASE_REF_MISMATCH", facts)
    facts["base_ref_matches"] = True
    if os.environ.get("GITHUB_HEAD_REF") != head_ref:
        return event_result("INVALID", "HEAD_REF_MISMATCH")
    facts["head_ref_matches"] = True
    merge_ref = os.environ.get("GITHUB_REF", "")
    merge_ref_match = re.fullmatch(r"refs/pull/([1-9][0-9]*)/merge", merge_ref)
    if merge_ref_match is None:
        return _pull_request_evidence_result("INVALID", "REF_SCOPE_MISMATCH", facts)
    if int(merge_ref_match.group(1)) != pr_number:
        return _pull_request_evidence_result("INVALID", "PR_NUMBER_MISMATCH", facts)
    facts["environment_ref_matches"] = True
    checkout_sha = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", checkout_sha) is None:
        return _pull_request_evidence_result("INVALID", "CHECKOUT_SHA_MISMATCH", facts)
    facts["environment_sha_valid"] = True
    try:
        _git("cat-file", "-e", f"{checkout_sha}^{{commit}}")
        local_head = _git("rev-parse", "HEAD").decode("ascii").strip()
        local_parents = tuple(
            _git("show", "-s", "--format=%P", checkout_sha).decode("ascii").strip().split()
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return _pull_request_evidence_result("INVALID", "GIT_OBJECT_NOT_AVAILABLE", facts)
    facts["git_object_available"] = True
    if local_head != checkout_sha:
        return _pull_request_evidence_result("INVALID", "CHECKOUT_SHA_MISMATCH", facts)
    facts["detached_head_matches"] = True
    facts["parent_count"] = len(local_parents)
    if len(local_parents) != 2:
        return _pull_request_evidence_result("INVALID", "PARENT_COUNT_INVALID", facts)
    if local_parents == (head_sha, base_sha):
        return _pull_request_evidence_result("INVALID", "PARENT_ORDER_MISMATCH", facts)
    if local_parents != (base_sha, head_sha):
        return _pull_request_evidence_result("INVALID", "CHECKOUT_SHA_MISMATCH", facts)
    facts["parent_order_matches"] = True
    try:
        local_ref_matches = _local_merge_ref_matches(pr_number, checkout_sha)
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return _pull_request_evidence_result("INDETERMINATE", "INTERNAL_VALIDATION_ERROR", facts)
    if not local_ref_matches:
        return _pull_request_evidence_result("INVALID", "REF_SCOPE_MISMATCH", facts)
    facts["local_merge_ref_matches"] = True
    signature_key_ids = _commit_signature_key_ids(checkout_sha)
    if signature_key_ids != (GITHUB_WEB_FLOW_SIGNING_KEY_ID,):
        return _pull_request_evidence_result("INVALID", "SIGNER_MISMATCH", facts)
    facts["local_signer_matches"] = True

    pr_api_result = _github_json(
        f"https://api.github.com/repos/{GITHUB_REPOSITORY_FULL_NAME}/pulls/{pr_number}"
    )
    facts["pr_metadata_available"] = pr_api_result.available
    facts["pr_metadata_status_code"] = pr_api_result.status_code
    if not pr_api_result.available or pr_api_result.payload is None:
        return _pull_request_evidence_result("INDETERMINATE", "PR_METADATA_NOT_AVAILABLE", facts)
    commit_api_result = _github_json(
        f"https://api.github.com/repos/{GITHUB_REPOSITORY_FULL_NAME}/commits/{checkout_sha}"
    )
    facts["actor_evidence_available"] = commit_api_result.available
    facts["actor_evidence_status_code"] = commit_api_result.status_code
    if not commit_api_result.available or commit_api_result.payload is None:
        return _pull_request_evidence_result("INDETERMINATE", "ACTOR_EVIDENCE_NOT_AVAILABLE", facts)
    pr_api = pr_api_result.payload
    commit_api = commit_api_result.payload
    try:
        api_parents = tuple(item["sha"] for item in commit_api["parents"])
        author_actor_id = int(commit_api["author"]["id"])
        committer_actor_id = int(commit_api["committer"]["id"])
        signature_verified = bool(commit_api["commit"]["verification"]["verified"])
        signature_reason = str(commit_api["commit"]["verification"]["reason"])
        pr_api_number = int(pr_api["number"])
        pr_repository_id = int(pr_api["base"]["repo"]["id"])
        pr_author_actor_id = int(pr_api["user"]["id"])
        pr_base_ref = str(pr_api["base"]["ref"])
        pr_base_sha = str(pr_api["base"]["sha"])
        pr_head_ref = str(pr_api["head"]["ref"])
        pr_head_sha = str(pr_api["head"]["sha"])
        api_commit_sha = str(commit_api["sha"])
    except (KeyError, TypeError, ValueError):
        return _pull_request_evidence_result("INDETERMINATE", "ACTOR_EVIDENCE_NOT_AVAILABLE", facts)
    if pr_repository_id != GITHUB_REPOSITORY_ID:
        return _pull_request_evidence_result("INVALID", "REPOSITORY_MISMATCH", facts)
    if pr_api_number != pr_number:
        return _pull_request_evidence_result("INVALID", "PR_NUMBER_MISMATCH", facts)
    if pr_base_ref != base_ref:
        return _pull_request_evidence_result("INVALID", "BASE_REF_MISMATCH", facts)
    if pr_base_sha != base_sha:
        return _pull_request_evidence_result("INVALID", "BASE_SHA_MISMATCH", facts)
    if pr_head_ref != head_ref:
        return _pull_request_evidence_result("INVALID", "HEAD_REF_MISMATCH", facts)
    if pr_head_sha != head_sha:
        return _pull_request_evidence_result("INVALID", "HEAD_SHA_MISMATCH", facts)
    pr_merge_value = pr_api.get("merge_commit_sha", _MISSING_EVENT_FIELD)
    pr_merge_sha: str | None = None
    if pr_merge_value is not _MISSING_EVENT_FIELD and pr_merge_value is not None:
        if (
            not isinstance(pr_merge_value, str)
            or re.fullmatch(r"[0-9a-f]{40}", pr_merge_value) is None
        ):
            return _pull_request_evidence_result("INVALID", "MERGE_SHA_MISMATCH", facts)
        pr_merge_sha = pr_merge_value
    facts["api_test_merge_recorded"] = pr_merge_sha is not None
    if api_commit_sha != checkout_sha:
        return _pull_request_evidence_result("INVALID", "MERGE_SHA_MISMATCH", facts)
    if len(api_parents) != 2:
        facts["api_parent_count"] = len(api_parents)
        return _pull_request_evidence_result("INVALID", "PARENT_COUNT_INVALID", facts)
    if api_parents != local_parents:
        return _pull_request_evidence_result("INVALID", "PARENT_ORDER_MISMATCH", facts)
    facts["api_parent_order_matches"] = True
    if event_author_actor_id != pr_author_actor_id or pr_author_actor_id != author_actor_id:
        return _pull_request_evidence_result("INVALID", "SIGNER_MISMATCH", facts)
    facts["author_actor_matches"] = True
    if committer_actor_id != GITHUB_WEB_FLOW_ACTOR_ID:
        return _pull_request_evidence_result("INVALID", "SIGNER_MISMATCH", facts)
    facts["committer_actor_matches"] = True
    if not signature_verified or signature_reason != "valid":
        return _pull_request_evidence_result("INVALID", "SIGNATURE_NOT_VERIFIED", facts)
    facts["signature_verified"] = True
    facts["event_merge_matches_current_checkout"] = event_merge_sha == checkout_sha
    facts["api_test_merge_matches_current_checkout"] = pr_merge_sha == checkout_sha
    if event_merge_sha is None:
        merge_discrepancy = "EVENT_TEST_MERGE_SHA_NOT_RECORDED"
    elif event_merge_sha == checkout_sha:
        merge_discrepancy = "EVENT_TEST_MERGE_SHA_MATCHES_CURRENT_CHECKOUT"
    else:
        merge_discrepancy = "EVENT_TEST_MERGE_SHA_DIFFERS_FROM_CURRENT_CHECKOUT"
    evidence = PullRequestEvidence(
        valid=True,
        repository_full_name=repository_full_name,
        repository_id=repository_id,
        pr_number=pr_number,
        base_ref=base_ref,
        base_sha=base_sha,
        head_ref=head_ref,
        head_sha=head_sha,
        merge_sha=checkout_sha,
        merge_ref=merge_ref,
        parents=local_parents,
        author_actor_id=author_actor_id,
        committer_actor_id=committer_actor_id,
        signature_verified=signature_verified,
        signature_reason=signature_reason,
        signature_key_ids=signature_key_ids,
        evidence_sources=tuple(sorted(REQUIRED_PULL_REQUEST_PROVENANCE)),
    )
    return event_result(
        "AVAILABLE",
        "AVAILABLE",
        evidence=evidence,
        merge_discrepancy=merge_discrepancy,
    )


def _normalized_origin_repository() -> str | None:
    try:
        value = _git("remote", "get-url", "origin").decode("utf-8", errors="strict").strip()
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return None
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?",
        value,
    )
    return None if match is None else match.group(1)


@functools.cache
def _cryptographically_verified_signer(commit_sha: str) -> str | None:
    if re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None:
        return None
    if not _is_safe_regular_file(GITHUB_WEB_FLOW_SIGNING_KEY_PROFILE):
        return None
    try:
        raw_commit = _git("cat-file", "commit", commit_sha)
        payload_lines: list[bytes] = []
        signature_lines: list[bytes] = []
        lines = raw_commit.splitlines(keepends=True)
        index = 0
        while index < len(lines):
            line = lines[index]
            if line.startswith(b"gpgsig "):
                signature_lines.append(line[len(b"gpgsig ") :])
                index += 1
                while index < len(lines) and lines[index].startswith(b" "):
                    signature_lines.append(lines[index][1:])
                    index += 1
                continue
            payload_lines.append(line)
            index += 1
        if not signature_lines:
            return None
        inspected = subprocess.run(
            [
                "gpg",
                "--batch",
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                str(GITHUB_WEB_FLOW_SIGNING_KEY_PROFILE),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        profile_fingerprints = {
            row.split(":")[9]
            for row in inspected.stdout.splitlines()
            if row.startswith("fpr:") and len(row.split(":")) > 9
        }
        if profile_fingerprints != {GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT}:
            return None
        with tempfile.TemporaryDirectory(prefix="omiv-signature-verification-") as directory:
            temporary = Path(directory)
            signature_path = temporary / "signature.asc"
            payload_path = temporary / "signed-commit-payload"
            keyring_path = temporary / "reviewed-keyring.gpg"
            signature_path.write_bytes(b"".join(signature_lines))
            payload_path.write_bytes(b"".join(payload_lines))
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--yes",
                    "--dearmor",
                    "--output",
                    str(keyring_path),
                    str(GITHUB_WEB_FLOW_SIGNING_KEY_PROFILE),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            verification = subprocess.run(
                [
                    "gpgv",
                    "--status-fd",
                    "1",
                    "--keyring",
                    str(keyring_path),
                    str(signature_path),
                    str(payload_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
    except (OSError, subprocess.CalledProcessError):
        return None
    valid = re.findall(r"\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) ", verification.stdout)
    return (
        GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT
        if verification.returncode == 0 and valid == [GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT]
        else None
    )


def _github_signed_squash_commit_identity_evidence(
    observations: list[IdentityObservation] | None = None,
) -> GithubSignedSquashEvidenceResult:
    facts: dict[str, bool | int] = {}
    repository = _normalized_origin_repository()
    facts["repository_matches"] = repository == GITHUB_REPOSITORY_FULL_NAME
    if repository != GITHUB_REPOSITORY_FULL_NAME:
        return GithubSignedSquashEvidenceResult(
            "INVALID", "REPOSITORY_MISMATCH", dict(sorted(facts.items()))
        )
    selected = _history_identity_observations() if observations is None else observations
    by_fingerprint = {item.fingerprint: item for item in selected}
    author = by_fingerprint.get(GITHUB_SQUASH_AUTHOR_FINGERPRINT)
    committer = by_fingerprint.get(GITHUB_SQUASH_COMMITTER_FINGERPRINT)
    if author is None or committer is None:
        facts["reviewed_pair_observed"] = False
        return GithubSignedSquashEvidenceResult(
            "AVAILABLE", "AVAILABLE", dict(sorted(facts.items()))
        )
    facts["reviewed_pair_observed"] = True
    author_occurrences = {
        item.object_sha: item for item in author.occurrences if item.role == "AUTHOR"
    }
    committer_occurrences = {
        item.object_sha: item for item in committer.occurrences if item.role == "COMMITTER"
    }
    result: list[GithubSignedSquashCommitIdentityEvidence] = []
    for commit_sha in sorted(set(author_occurrences) & set(committer_occurrences)):
        author_occurrence = author_occurrences[commit_sha]
        committer_occurrence = committer_occurrences[commit_sha]
        authoritative = tuple(
            sorted(
                set(author_occurrence.ref_classifications)
                & set(committer_occurrence.ref_classifications)
                & {"LOCAL_MAIN", "REMOTE_MAIN"}
            )
        )
        if not authoritative:
            continue
        if (
            not author_occurrence.valid_record
            or not committer_occurrence.valid_record
            or author_occurrence.parents != committer_occurrence.parents
            or len(author_occurrence.parents) != 1
            or author_occurrence.signature_key_ids != (GITHUB_WEB_FLOW_SIGNING_KEY_ID,)
            or committer_occurrence.signature_key_ids != (GITHUB_WEB_FLOW_SIGNING_KEY_ID,)
        ):
            continue
        try:
            subject = (
                _git("show", "-s", "--format=%s", commit_sha)
                .decode("utf-8", errors="strict")
                .strip()
            )
            tree_sha = _git("show", "-s", "--format=%T", commit_sha).decode("ascii").strip()
        except (OSError, UnicodeError, subprocess.CalledProcessError):
            continue
        association = re.search(r"\(#([1-9][0-9]*)\)$", subject)
        signer = _cryptographically_verified_signer(commit_sha)
        if (
            association is None
            or re.fullmatch(r"[0-9a-f]{40}", tree_sha) is None
            or signer != GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT
        ):
            continue
        result.append(
            GithubSignedSquashCommitIdentityEvidence(
                valid=True,
                repository_full_name=repository,
                commit_sha=commit_sha,
                tree_sha=tree_sha,
                parents=author_occurrence.parents,
                pr_number=int(association.group(1)),
                author_fingerprint=author.fingerprint,
                committer_fingerprint=committer.fingerprint,
                signature_key_id=GITHUB_WEB_FLOW_SIGNING_KEY_ID,
                signer_fingerprint=signer,
                authoritative_ref_classifications=authoritative,
                observed_git_identity=True,
                reviewed_github_actor_association=True,
                live_actor_observation_supplied=False,
            )
        )
    facts["verified_squash_commits"] = len(result)
    return GithubSignedSquashEvidenceResult(
        "AVAILABLE" if result else "INVALID",
        "AVAILABLE" if result else "REVIEWED_SQUASH_IDENTITY_NOT_VERIFIED",
        dict(sorted(facts.items())),
        tuple(result),
    )


def _protected_pull_request_squash_merge_evidence(
    observation: dict[str, Any] | None = None,
) -> ProtectedPullRequestSquashMergeEvidenceResult:
    if observation is None:
        return ProtectedPullRequestSquashMergeEvidenceResult(
            "NOT_SUPPLIED", "REMOTE_OBSERVATION_NOT_SUPPLIED", {"supplied": False}
        )
    facts: dict[str, bool | int] = {"supplied": True}
    try:
        checks = observation["required_checks"]
        protection = observation["branch_protection"]
        valid = bool(
            observation["repository_full_name"] == GITHUB_REPOSITORY_FULL_NAME
            and int(observation["pr_number"]) > 0
            and observation["pr_state"] == "MERGED"
            and observation["merged"] is True
            and observation["base_ref"] == "main"
            and re.fullmatch(r"[0-9a-f]{40}", observation["base_sha"])
            and re.fullmatch(r"[0-9a-f]{40}", observation["head_sha"])
            and re.fullmatch(r"[0-9a-f]{40}", observation["head_tree"])
            and re.fullmatch(r"[0-9a-f]{40}", observation["result_sha"])
            and observation["associated_result_sha"] == observation["result_sha"]
            and observation["result_parent"] == observation["base_sha"]
            and observation["result_tree"] == observation["head_tree"]
            and observation["merge_method"] == "squash"
            and observation["author_actor_id"] == GITHUB_OWNER_ACTOR_ID
            and observation["author_role"] == "AUTHOR"
            and observation["committer_actor_id"] == GITHUB_WEB_FLOW_ACTOR_ID
            and observation["committer_role"] == "COMMITTER"
            and observation["signature_verified"] is True
            and observation["signature_reason"] == "valid"
            and observation["signature_key_id"] == GITHUB_WEB_FLOW_SIGNING_KEY_ID
            and set(checks) == {"Python 3.11", "Python 3.12", "Python 3.13", "Python 3.14"}
            and all(item["conclusion"] == "success" for item in checks.values())
            and all(item["app_id"] == 15368 for item in checks.values())
            and protection["strict"] is True
            and set(protection["required_checks"]) == set(checks)
            and isinstance(observation["observed_at"], str)
            and bool(observation["observed_at"])
        )
    except (KeyError, TypeError, ValueError):
        return ProtectedPullRequestSquashMergeEvidenceResult(
            "INDETERMINATE", "REMOTE_OBSERVATION_INCOMPLETE", dict(sorted(facts.items()))
        )
    facts["all_bindings_match"] = valid
    return ProtectedPullRequestSquashMergeEvidenceResult(
        "AVAILABLE" if valid else "INVALID",
        "AVAILABLE" if valid else "REMOTE_BINDING_MISMATCH",
        dict(sorted(facts.items())),
    )


def _platform_policy_is_valid(policy: PlatformIdentityPolicy) -> bool:
    return bool(
        re.fullmatch(r"[0-9a-f]{64}", policy.fingerprint)
        and policy.allowed_roles
        and set(policy.allowed_roles).issubset(IDENTITY_ROLES)
        and policy.allowed_ref_classifications
        and set(policy.allowed_ref_classifications).issubset(REF_CLASSIFICATIONS)
        and REQUIRED_PLATFORM_PROVENANCE.issubset(policy.evidence_sources)
        and (
            not policy.pull_request_roles
            or REQUIRED_PULL_REQUEST_PROVENANCE.issubset(policy.evidence_sources)
        )
        and (
            not policy.signed_squash_roles
            or REQUIRED_SIGNED_SQUASH_PROVENANCE.issubset(policy.evidence_sources)
        )
        and policy.identity_category
        in {
            "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
            "VERIFIED_PLATFORM_SERVICE_IDENTITY",
        }
        and all(
            re.fullmatch(r"[0-9a-f]{40}", item.object_sha)
            and item.role in IDENTITY_ROLES
            and item.allowed_refnames
            and all(
                _ref_classification(refname) in REF_CLASSIFICATIONS
                for refname in item.allowed_refnames
            )
            and all(re.fullmatch(r"[0-9a-f]{40}", parent) for parent in item.parents)
            and item.actor_id > 0
            and item.signature_key_ids == (GITHUB_WEB_FLOW_SIGNING_KEY_ID,)
            for item in policy.static_occurrences
        )
        and all(
            item.repository_full_name == GITHUB_REPOSITORY_FULL_NAME
            and item.repository_id == GITHUB_REPOSITORY_ID
            and item.base_ref == "main"
            and (
                (
                    item.current_event_scope
                    and item.pr_number is None
                    and item.base_sha is None
                    and item.head_ref is None
                )
                or (
                    not item.current_event_scope
                    and item.pr_number is not None
                    and item.pr_number > 0
                    and item.base_sha is not None
                    and re.fullmatch(r"[0-9a-f]{40}", item.base_sha)
                    and item.head_ref is not None
                    and bool(item.head_ref)
                )
            )
            and item.role in {"AUTHOR", "COMMITTER"}
            and item.actor_id > 0
            and item.signer_actor_id == GITHUB_WEB_FLOW_ACTOR_ID
            and item.signature_key_id == GITHUB_WEB_FLOW_SIGNING_KEY_ID
            for item in policy.pull_request_roles
        )
        and all(
            item.repository_full_name == GITHUB_REPOSITORY_FULL_NAME
            and item.authoritative_ref_classifications == ("LOCAL_MAIN", "REMOTE_MAIN")
            and item.role in {"AUTHOR", "COMMITTER"}
            and item.reviewed_actor_id > 0
            and re.fullmatch(r"[0-9a-f]{64}", item.paired_fingerprint)
            and item.signer_key_id == GITHUB_WEB_FLOW_SIGNING_KEY_ID
            and item.signer_fingerprint == GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT
            and item.parent_count == 1
            for item in policy.signed_squash_roles
        )
        and policy.authority_limit == NO_PLATFORM_AUTHORITY
    )


def _static_occurrence_matches(
    occurrence: IdentityOccurrence, policy: StaticPlatformOccurrencePolicy
) -> bool:
    return bool(
        occurrence.valid_record
        and occurrence.object_sha == policy.object_sha
        and occurrence.role == policy.role
        and occurrence.parents == policy.parents
        and occurrence.signature_key_ids == policy.signature_key_ids
        and occurrence.refnames
        and set(occurrence.refnames).issubset(policy.allowed_refnames)
        and occurrence.ref_classifications
        == tuple(sorted({_ref_classification(refname) for refname in occurrence.refnames}))
    )


def _pull_request_occurrence_matches(
    occurrence: IdentityOccurrence,
    policy: PullRequestRolePolicy,
    evidence: PullRequestEvidence | None,
) -> bool:
    if evidence is None:
        return False
    allowed_merge_refs = {
        f"refs/pull/{evidence.pr_number}/merge",
        f"refs/remotes/pull/{evidence.pr_number}/merge",
    }
    actor_id = (
        evidence.author_actor_id if occurrence.role == "AUTHOR" else evidence.committer_actor_id
    )
    return bool(
        evidence.valid
        and REQUIRED_PULL_REQUEST_PROVENANCE.issubset(evidence.evidence_sources)
        and evidence.repository_full_name == policy.repository_full_name
        and evidence.repository_id == policy.repository_id
        and evidence.base_ref == policy.base_ref
        and (
            policy.current_event_scope
            or (
                evidence.pr_number == policy.pr_number
                and evidence.base_sha == policy.base_sha
                and evidence.head_ref == policy.head_ref
            )
        )
        and occurrence.object_sha == evidence.merge_sha
        and occurrence.role == policy.role
        and actor_id == policy.actor_id
        and evidence.committer_actor_id == policy.signer_actor_id
        and occurrence.parents == evidence.parents == (evidence.base_sha, evidence.head_sha)
        and occurrence.signature_key_ids == evidence.signature_key_ids == (policy.signature_key_id,)
        and evidence.signature_verified
        and evidence.signature_reason == "valid"
        and occurrence.refnames
        and set(occurrence.refnames).issubset(allowed_merge_refs)
        and occurrence.ref_classifications == ("PULL_REQUEST_MERGE_REF",)
        and evidence.merge_ref == f"refs/pull/{evidence.pr_number}/merge"
    )


def _platform_occurrence_matches(
    occurrence: IdentityOccurrence,
    policy: PlatformIdentityPolicy,
    evidence: PullRequestEvidence | None,
    signed_squash_evidence: tuple[GithubSignedSquashCommitIdentityEvidence, ...] = (),
) -> bool:
    return (
        any(_static_occurrence_matches(occurrence, item) for item in policy.static_occurrences)
        or any(
            _pull_request_occurrence_matches(occurrence, item, evidence)
            for item in policy.pull_request_roles
        )
        or any(
            squash.valid
            and squash.repository_full_name == item.repository_full_name
            and occurrence.object_sha == squash.commit_sha
            and occurrence.role == item.role
            and occurrence.parents == squash.parents
            and len(occurrence.parents) == item.parent_count
            and occurrence.signature_key_ids == (item.signer_key_id,)
            and set(squash.authoritative_ref_classifications).issubset(
                occurrence.ref_classifications
            )
            and set(squash.authoritative_ref_classifications).intersection(
                item.authoritative_ref_classifications
            )
            and squash.signature_key_id == item.signer_key_id
            and squash.signer_fingerprint == item.signer_fingerprint
            and (
                squash.author_fingerprint if item.role == "AUTHOR" else squash.committer_fingerprint
            )
            == policy.fingerprint
            and (
                squash.committer_fingerprint if item.role == "AUTHOR" else squash.author_fingerprint
            )
            == item.paired_fingerprint
            and squash.observed_git_identity
            and squash.reviewed_github_actor_association
            and not squash.live_actor_observation_supplied
            and squash.authority_limit == NO_PLATFORM_AUTHORITY
            for item in policy.signed_squash_roles
            for squash in signed_squash_evidence
        )
    )


def _classify_identity(
    observation: IdentityObservation,
    *,
    platform_policies: dict[str, PlatformIdentityPolicy] | None = None,
    pull_request_evidence: PullRequestEvidence | None = None,
    signed_squash_evidence: tuple[GithubSignedSquashCommitIdentityEvidence, ...] = (),
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> str:
    policies = (
        VERIFIED_PLATFORM_IDENTITY_POLICIES if platform_policies is None else platform_policies
    )
    if (
        not observation.valid_record
        or not re.fullmatch(r"[0-9a-f]{64}", observation.fingerprint)
        or not observation.roles
        or not set(observation.roles).issubset(IDENTITY_ROLES)
        or not observation.reachable_ref_classifications
        or not set(observation.reachable_ref_classifications).issubset(REF_CLASSIFICATIONS)
        or any(not item.valid_record for item in observation.occurrences)
    ):
        return "INVALID_IDENTITY"
    if observation.fingerprint == OWNER_APPROVED_HUMAN_IDENTITY_SHA256:
        return "OWNER_APPROVED_HUMAN_IDENTITY"
    if observation.fingerprint in synthetic_test_fingerprints:
        return "SYNTHETIC_TEST_IDENTITY"
    policy = policies.get(observation.fingerprint)
    if (
        policy is not None
        and _platform_policy_is_valid(policy)
        and observation.occurrences
        and all(
            _platform_occurrence_matches(item, policy, pull_request_evidence)
            if not signed_squash_evidence
            else _platform_occurrence_matches(
                item, policy, pull_request_evidence, signed_squash_evidence
            )
            for item in observation.occurrences
        )
    ):
        return policy.identity_category
    if policy is not None:
        return "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    if set(observation.reachable_ref_classifications).intersection(
        {
            "PULL_REQUEST_HEAD_REF",
            "PULL_REQUEST_MERGE_REF",
            "REMOTE_DEPENDABOT_BRANCH",
            "REMOTE_OTHER_BRANCH",
        }
    ):
        return "UNKNOWN_AUTOMATION_IDENTITY"
    return "UNKNOWN_HUMAN_IDENTITY"


def _identity_report_records(
    observations: list[IdentityObservation],
    *,
    platform_policies: dict[str, PlatformIdentityPolicy] | None = None,
    pull_request_evidence: PullRequestEvidence | None = None,
    signed_squash_evidence: tuple[GithubSignedSquashCommitIdentityEvidence, ...] = (),
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    policies = (
        VERIFIED_PLATFORM_IDENTITY_POLICIES if platform_policies is None else platform_policies
    )
    result: list[dict[str, Any]] = []
    for observation in observations:
        category = _classify_identity(
            observation,
            platform_policies=policies,
            pull_request_evidence=pull_request_evidence,
            signed_squash_evidence=signed_squash_evidence,
            synthetic_test_fingerprints=synthetic_test_fingerprints,
        )
        policy = policies.get(observation.fingerprint)
        purpose: str
        evidence_sources: tuple[str, ...]
        authority_limit: str
        if category == "OWNER_APPROVED_HUMAN_IDENTITY":
            purpose = "OWNER_APPROVED_PUBLIC_IDENTITY_DISCLOSURE"
            evidence_sources = ("OWNER_RECORDED_IDENTITY_FINGERPRINT",)
            authority_limit = "IDENTITY_DISCLOSURE_APPROVAL_ONLY"
        elif (
            category
            in {
                "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
                "VERIFIED_PLATFORM_SERVICE_IDENTITY",
            }
            and policy is not None
        ):
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
                "occurrence_count": len(observation.occurrences),
                "occurrences": (
                    []
                    if category == "OWNER_APPROVED_HUMAN_IDENTITY"
                    else [
                        {
                            "object_sha": item.object_sha,
                            "parents": list(item.parents),
                            "ref_classifications": list(item.ref_classifications),
                            "role": item.role,
                            "signature_key_ids": list(item.signature_key_ids),
                        }
                        for item in observation.occurrences
                    ]
                ),
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
    pull_request_evidence: PullRequestEvidence | None = None,
    signed_squash_evidence: tuple[GithubSignedSquashCommitIdentityEvidence, ...] = (),
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> Check:
    records = _identity_report_records(
        observations,
        platform_policies=platform_policies,
        pull_request_evidence=pull_request_evidence,
        signed_squash_evidence=signed_squash_evidence,
        synthetic_test_fingerprints=synthetic_test_fingerprints,
    )
    categories = [record["category"] for record in records]
    human_count = categories.count("OWNER_APPROVED_HUMAN_IDENTITY")
    mediated_count = categories.count("VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY")
    service_count = categories.count("VERIFIED_PLATFORM_SERVICE_IDENTITY")
    unknown_count = categories.count("UNKNOWN_HUMAN_IDENTITY") + categories.count(
        "UNKNOWN_AUTOMATION_IDENTITY"
    )
    unverified_count = categories.count("UNVERIFIED_PLATFORM_SERVICE_CLAIM")
    invalid_count = categories.count("INVALID_IDENTITY")
    synthetic_count = categories.count("SYNTHETIC_TEST_IDENTITY")
    passed = bool(
        human_count == 1
        and unknown_count == 0
        and unverified_count == 0
        and invalid_count == 0
        and synthetic_count == 0
    )
    return Check(
        "approved_author_identity",
        passed,
        " ".join(
            (
                f"approved_humans={human_count}",
                f"verified_platform_mediated_accounts={mediated_count}",
                f"verified_platform_services={service_count}",
                f"unverified_platform_claims={unverified_count}",
                f"unknown={unknown_count}",
                f"invalid={invalid_count}",
            )
        ),
    )


def _history_inventory() -> list[Check]:
    commits = _git("rev-list", "--all", "--count").decode().strip()
    tags = _git("tag", "--list").decode().splitlines()
    expected_tags = {f"v0.{minor}.0" for minor in range(1, 11)}
    release_tag_type = _git("cat-file", "-t", "refs/tags/v0.10.0").decode().strip()
    release_tag_object = _git("rev-parse", "refs/tags/v0.10.0").decode().strip()
    release_tag_commit = _git("rev-parse", "refs/tags/v0.10.0^{commit}").decode().strip()
    release_tag_subject = (
        _git(
            "for-each-ref",
            "--format=%(contents:subject)",
            "refs/tags/v0.10.0",
        )
        .decode()
        .strip()
    )
    observations = _history_identity_observations()
    pull_request_evidence = _current_pull_request_evidence()
    squash_evidence = _github_signed_squash_commit_identity_evidence(observations)
    return [
        Check("reachable_history", int(commits) >= 36, f"commits={commits}"),
        Check(
            "historical_tags",
            set(tags) == expected_tags,
            f"tags={len(tags)} expected={len(expected_tags)}",
        ),
        Check(
            "v0_10_0_tag_identity",
            release_tag_type == "tag"
            and release_tag_object == "d26468e050f4f0aea11e1d1631c92e1e1fbb7bcc"
            and release_tag_commit == "09f8265d62f2ea1dfda7da2cd3eb4b3e89639222"
            and release_tag_subject == "OMIV v0.10.0 — Public Preview",
            "exact annotated tag object, target, and subject",
        ),
        _identity_classification_check(
            observations,
            pull_request_evidence=pull_request_evidence.evidence,
            signed_squash_evidence=squash_evidence.evidence,
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
    pull_request_evidence_result = _current_pull_request_evidence()
    pull_request_evidence = pull_request_evidence_result.evidence
    squash_evidence_result = _github_signed_squash_commit_identity_evidence()
    protected_merge_evidence_result = _protected_pull_request_squash_merge_evidence()
    identity_records = _identity_report_records(
        _history_identity_observations(),
        pull_request_evidence=pull_request_evidence,
        signed_squash_evidence=squash_evidence_result.evidence,
    )
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
            "identity_category": policy.identity_category,
            "pull_request_roles": [
                {
                    "actor_id": item.actor_id,
                    "base_ref": item.base_ref,
                    "base_sha": item.base_sha,
                    "current_event_scope": item.current_event_scope,
                    "head_ref": item.head_ref,
                    "pr_number": item.pr_number,
                    "repository_full_name": item.repository_full_name,
                    "repository_id": item.repository_id,
                    "role": item.role,
                    "signature_key_id": item.signature_key_id,
                    "signer_actor_id": item.signer_actor_id,
                }
                for item in policy.pull_request_roles
            ],
            "purpose": policy.purpose,
            "signed_squash_roles": [
                {
                    "authoritative_ref_classifications": list(
                        item.authoritative_ref_classifications
                    ),
                    "live_actor_observation_required": False,
                    "paired_fingerprint": item.paired_fingerprint,
                    "parent_count": item.parent_count,
                    "repository_full_name": item.repository_full_name,
                    "reviewed_actor_id": item.reviewed_actor_id,
                    "role": item.role,
                    "signer_fingerprint": item.signer_fingerprint,
                    "signer_key_id": item.signer_key_id,
                }
                for item in policy.signed_squash_roles
            ],
            "static_occurrences": [
                {
                    "actor_id": item.actor_id,
                    "object_sha": item.object_sha,
                    "parents": list(item.parents),
                    "ref_classifications": sorted(
                        {_ref_classification(refname) for refname in item.allowed_refnames}
                    ),
                    "role": item.role,
                    "signature_key_ids": list(item.signature_key_ids),
                }
                for item in policy.static_occurrences
            ],
        }
        for policy in sorted(
            VERIFIED_PLATFORM_IDENTITY_POLICIES.values(), key=lambda item: item.fingerprint
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
                "exact_local_and_remote_ref_scopes",
                "github_actions_pull_request_event_binding",
                "github_rest_actor_and_signature_binding",
                "github_signed_authoritative_main_squash_identity",
                "pull_request_base_head_merge_parent_topology",
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
            "When a GitHub Actions pull-request merge ref is present, the identity gate "
            "performs bounded read-only GitHub REST checks and fails closed if provenance "
            "cannot be established.",
            "Offline GitHub-signed squash identity evidence proves only a reviewed Git "
            "identity occurrence and never proves PR approval, branch protection, checks, "
            "owner authority, release authority, or publication authority.",
        ],
        "privacy": {
            "approved_author_identity": "OWNER_APPROVED",
            "approved_historical_path_fingerprints": len(APPROVED_PATH_FINGERPRINTS),
            "identity_category_counts": identity_counts,
            "identity_fingerprint_domain": "omiv.identity.v1",
            "identity_records": identity_records,
            "identity_taxonomy": list(IDENTITY_CATEGORIES),
            "github_signed_squash_commit_identity_evidence": {
                "status": squash_evidence_result.status,
                "reason_code": squash_evidence_result.reason_code,
                "safe_facts": squash_evidence_result.safe_facts,
                "evidence": [
                    {
                        "author_fingerprint": item.author_fingerprint,
                        "authoritative_ref_classifications": list(
                            item.authoritative_ref_classifications
                        ),
                        "authority_limit": item.authority_limit,
                        "commit_sha": item.commit_sha,
                        "committer_fingerprint": item.committer_fingerprint,
                        "live_actor_observation_supplied": (item.live_actor_observation_supplied),
                        "observed_git_identity": item.observed_git_identity,
                        "parents": list(item.parents),
                        "pr_number": item.pr_number,
                        "repository_full_name": item.repository_full_name,
                        "reviewed_github_actor_association": (
                            item.reviewed_github_actor_association
                        ),
                        "signature_key_id": item.signature_key_id,
                        "signer_fingerprint": item.signer_fingerprint,
                        "tree_sha": item.tree_sha,
                        "valid": item.valid,
                    }
                    for item in squash_evidence_result.evidence
                ],
            },
            "protected_pull_request_squash_merge_evidence": {
                "status": protected_merge_evidence_result.status,
                "reason_code": protected_merge_evidence_result.reason_code,
                "safe_facts": protected_merge_evidence_result.safe_facts,
            },
            "pull_request_evidence": {
                "status": pull_request_evidence_result.status,
                "reason_code": pull_request_evidence_result.reason_code,
                "merge_discrepancy": pull_request_evidence_result.merge_discrepancy,
                "missing_required_fields": list(
                    pull_request_evidence_result.missing_required_fields
                ),
                "missing_advisory_fields": list(
                    pull_request_evidence_result.missing_advisory_fields
                ),
                "null_required_fields": list(pull_request_evidence_result.null_required_fields),
                "null_advisory_fields": list(pull_request_evidence_result.null_advisory_fields),
                "safe_facts": pull_request_evidence_result.safe_facts,
                "evidence": (
                    None
                    if pull_request_evidence is None
                    else {
                        "author_actor_id": pull_request_evidence.author_actor_id,
                        "base_ref": pull_request_evidence.base_ref,
                        "base_sha": pull_request_evidence.base_sha,
                        "committer_actor_id": pull_request_evidence.committer_actor_id,
                        "evidence_sources": list(pull_request_evidence.evidence_sources),
                        "head_ref": pull_request_evidence.head_ref,
                        "head_sha": pull_request_evidence.head_sha,
                        "merge_sha": pull_request_evidence.merge_sha,
                        "parents": list(pull_request_evidence.parents),
                        "pr_number": pull_request_evidence.pr_number,
                        "repository_full_name": pull_request_evidence.repository_full_name,
                        "repository_id": pull_request_evidence.repository_id,
                        "signature_key_ids": list(pull_request_evidence.signature_key_ids),
                        "signature_reason": pull_request_evidence.signature_reason,
                        "signature_verified": pull_request_evidence.signature_verified,
                        "valid": pull_request_evidence.valid,
                    }
                ),
            },
            "reviewed_platform_identity_policies": reviewed_platform_policies,
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
