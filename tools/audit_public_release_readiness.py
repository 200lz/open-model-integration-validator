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
    "VERIFIED_PLATFORM_SERVICE_IDENTITY",
)
IDENTITY_ROLES = frozenset({"AUTHOR", "COMMITTER", "TAGGER"})
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
GITHUB_REPOSITORY_FULL_NAME = "200lz/open-model-integration-validator"
GITHUB_REPOSITORY_ID = 1316060005
GITHUB_OWNER_ACTOR_ID = 145014769
GITHUB_DEPENDABOT_ACTOR_ID = 49699333
GITHUB_WEB_FLOW_ACTOR_ID = 19864447
GITHUB_WEB_FLOW_SIGNING_KEY_ID = "B5690EEEBB952194"
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
    pr_number: int
    base_ref: str
    base_sha: str
    head_ref: str
    role: str
    actor_id: int
    signer_actor_id: int
    signature_key_id: str


@dataclass(frozen=True)
class PlatformIdentityPolicy:
    fingerprint: str
    purpose: str
    evidence_sources: tuple[str, ...]
    static_occurrences: tuple[StaticPlatformOccurrencePolicy, ...] = ()
    pull_request_roles: tuple[PullRequestRolePolicy, ...] = ()
    authority_limit: str = NO_PLATFORM_AUTHORITY

    @property
    def allowed_roles(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {item.role for item in self.static_occurrences}
                | {item.role for item in self.pull_request_roles}
            )
        )

    @property
    def allowed_ref_classifications(self) -> tuple[str, ...]:
        result: set[str] = set()
        for item in self.static_occurrences:
            result.update(_ref_classification(refname) for refname in item.allowed_refnames)
        if self.pull_request_roles:
            result.add("PULL_REQUEST_MERGE_REF")
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
VERIFIED_PLATFORM_SERVICE_POLICIES = {
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
        evidence_sources=tuple(sorted(REQUIRED_PULL_REQUEST_PROVENANCE)),
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
        pull_request_roles=(PR2_COMMITTER_POLICY,),
    ),
    "b71cf77f9b542abf081d730983ff66d44c6e26d949e55f9fb4db43f70779ddec": PlatformIdentityPolicy(
        fingerprint="b71cf77f9b542abf081d730983ff66d44c6e26d949e55f9fb4db43f70779ddec",
        purpose="GITHUB_PR2_SYNTHETIC_MERGE_AUTHOR",
        evidence_sources=tuple(sorted(REQUIRED_PULL_REQUEST_PROVENANCE)),
        pull_request_roles=(PR2_AUTHOR_POLICY,),
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
            author_fingerprint in VERIFIED_PLATFORM_SERVICE_POLICIES
            or committer_fingerprint in VERIFIED_PLATFORM_SERVICE_POLICIES
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


def _github_json(url: str) -> dict[str, Any] | None:
    if not url.startswith("https://api.github.com/"):
        return None
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
            if response.status != 200 or len(payload) > 1_048_576:
                return None
        parsed = json.loads(payload)
    except (OSError, UnicodeError, ValueError, urllib.error.URLError):
        return None
    return parsed if isinstance(parsed, dict) else None


@functools.lru_cache(maxsize=1)
def _current_pull_request_evidence() -> PullRequestEvidence | None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return None
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return None
    if os.environ.get("GITHUB_REPOSITORY") != GITHUB_REPOSITORY_FULL_NAME:
        return None
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    if event_path.is_symlink() or not event_path.is_file() or event_path.stat().st_size > 1_048_576:
        return None
    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
        pull = event["pull_request"]
        repository = event["repository"]
        pr_number = int(event["number"])
        base_ref = str(pull["base"]["ref"])
        base_sha = str(pull["base"]["sha"])
        head_ref = str(pull["head"]["ref"])
        head_sha = str(pull["head"]["sha"])
        merge_sha = str(pull["merge_commit_sha"])
        repository_id = int(repository["id"])
        repository_full_name = str(repository["full_name"])
        event_author_actor_id = int(pull["user"]["id"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError, UnicodeError):
        return None
    merge_ref = os.environ.get("GITHUB_REF", "")
    if merge_ref != f"refs/pull/{pr_number}/merge":
        return None
    if os.environ.get("GITHUB_SHA") != merge_sha:
        return None
    pr_api = _github_json(
        f"https://api.github.com/repos/{GITHUB_REPOSITORY_FULL_NAME}/pulls/{pr_number}"
    )
    commit_api = _github_json(
        f"https://api.github.com/repos/{GITHUB_REPOSITORY_FULL_NAME}/commits/{merge_sha}"
    )
    if pr_api is None or commit_api is None:
        return None
    try:
        parents = tuple(item["sha"] for item in commit_api["parents"])
        author_actor_id = int(commit_api["author"]["id"])
        committer_actor_id = int(commit_api["committer"]["id"])
        signature_verified = bool(commit_api["commit"]["verification"]["verified"])
        signature_reason = str(commit_api["commit"]["verification"]["reason"])
        pr_repository_id = int(pr_api["base"]["repo"]["id"])
        pr_author_actor_id = int(pr_api["user"]["id"])
        pr_base_ref = str(pr_api["base"]["ref"])
        pr_base_sha = str(pr_api["base"]["sha"])
        pr_head_ref = str(pr_api["head"]["ref"])
        pr_head_sha = str(pr_api["head"]["sha"])
        pr_merge_sha = str(pr_api["merge_commit_sha"])
        api_commit_sha = str(commit_api["sha"])
    except (KeyError, TypeError, ValueError):
        return None
    local_merge_refs = (
        f"refs/pull/{pr_number}/merge",
        f"refs/remotes/pull/{pr_number}/merge",
    )
    local_ref_matches = any(
        _git("rev-parse", "--verify", refname).decode("ascii").strip() == merge_sha
        for refname in local_merge_refs
        if subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", refname], cwd=ROOT, check=False
        ).returncode
        == 0
    )
    local_head = _git("rev-parse", "HEAD").decode("ascii").strip()
    signature_key_ids = _commit_signature_key_ids(merge_sha)
    valid = bool(
        repository_full_name == GITHUB_REPOSITORY_FULL_NAME
        and repository_id == GITHUB_REPOSITORY_ID
        and pr_repository_id == GITHUB_REPOSITORY_ID
        and pr_number == PR2_NUMBER
        and base_ref == pr_base_ref == "main"
        and base_sha == pr_base_sha == PR2_BASE_SHA
        and head_ref == pr_head_ref == PR2_HEAD_REF
        and head_sha == pr_head_sha
        and merge_sha == pr_merge_sha == api_commit_sha
        and parents == (base_sha, head_sha)
        and local_head == merge_sha
        and local_ref_matches
        and event_author_actor_id == pr_author_actor_id == author_actor_id
        and committer_actor_id == GITHUB_WEB_FLOW_ACTOR_ID
        and signature_verified
        and signature_reason == "valid"
        and signature_key_ids == (GITHUB_WEB_FLOW_SIGNING_KEY_ID,)
    )
    return PullRequestEvidence(
        valid=valid,
        repository_full_name=repository_full_name,
        repository_id=repository_id,
        pr_number=pr_number,
        base_ref=base_ref,
        base_sha=base_sha,
        head_ref=head_ref,
        head_sha=head_sha,
        merge_sha=merge_sha,
        merge_ref=merge_ref,
        parents=parents,
        author_actor_id=author_actor_id,
        committer_actor_id=committer_actor_id,
        signature_verified=signature_verified,
        signature_reason=signature_reason,
        signature_key_ids=signature_key_ids,
        evidence_sources=tuple(sorted(REQUIRED_PULL_REQUEST_PROVENANCE)) if valid else (),
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
            and item.pr_number > 0
            and item.base_ref == "main"
            and re.fullmatch(r"[0-9a-f]{40}", item.base_sha)
            and item.head_ref
            and item.role in {"AUTHOR", "COMMITTER"}
            and item.actor_id > 0
            and item.signer_actor_id == GITHUB_WEB_FLOW_ACTOR_ID
            and item.signature_key_id == GITHUB_WEB_FLOW_SIGNING_KEY_ID
            for item in policy.pull_request_roles
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
        f"refs/pull/{policy.pr_number}/merge",
        f"refs/remotes/pull/{policy.pr_number}/merge",
    }
    actor_id = (
        evidence.author_actor_id if occurrence.role == "AUTHOR" else evidence.committer_actor_id
    )
    return bool(
        evidence.valid
        and REQUIRED_PULL_REQUEST_PROVENANCE.issubset(evidence.evidence_sources)
        and evidence.repository_full_name == policy.repository_full_name
        and evidence.repository_id == policy.repository_id
        and evidence.pr_number == policy.pr_number
        and evidence.base_ref == policy.base_ref
        and evidence.base_sha == policy.base_sha
        and evidence.head_ref == policy.head_ref
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
        and evidence.merge_ref == f"refs/pull/{policy.pr_number}/merge"
    )


def _platform_occurrence_matches(
    occurrence: IdentityOccurrence,
    policy: PlatformIdentityPolicy,
    evidence: PullRequestEvidence | None,
) -> bool:
    return any(
        _static_occurrence_matches(occurrence, item) for item in policy.static_occurrences
    ) or any(
        _pull_request_occurrence_matches(occurrence, item, evidence)
        for item in policy.pull_request_roles
    )


def _classify_identity(
    observation: IdentityObservation,
    *,
    platform_policies: dict[str, PlatformIdentityPolicy] | None = None,
    pull_request_evidence: PullRequestEvidence | None = None,
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
            for item in observation.occurrences
        )
    ):
        return "VERIFIED_PLATFORM_SERVICE_IDENTITY"
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
            pull_request_evidence=pull_request_evidence,
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
    synthetic_test_fingerprints: frozenset[str] = frozenset(),
) -> Check:
    records = _identity_report_records(
        observations,
        platform_policies=platform_policies,
        pull_request_evidence=pull_request_evidence,
        synthetic_test_fingerprints=synthetic_test_fingerprints,
    )
    categories = [record["category"] for record in records]
    human_count = categories.count("OWNER_APPROVED_HUMAN_IDENTITY")
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
    observations = _history_identity_observations()
    return [
        Check("reachable_history", int(commits) >= 36, f"commits={commits}"),
        Check("historical_tags", len(tags) == 9, f"tags={len(tags)}"),
        _identity_classification_check(
            observations, pull_request_evidence=_current_pull_request_evidence()
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
    pull_request_evidence = _current_pull_request_evidence()
    identity_records = _identity_report_records(
        _history_identity_observations(), pull_request_evidence=pull_request_evidence
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
            "pull_request_roles": [
                {
                    "actor_id": item.actor_id,
                    "base_ref": item.base_ref,
                    "base_sha": item.base_sha,
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
                "exact_local_and_remote_ref_scopes",
                "github_actions_pull_request_event_binding",
                "github_rest_actor_and_signature_binding",
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
        ],
        "privacy": {
            "approved_author_identity": "OWNER_APPROVED",
            "approved_historical_path_fingerprints": len(APPROVED_PATH_FINGERPRINTS),
            "identity_category_counts": identity_counts,
            "identity_fingerprint_domain": "omiv.identity.v1",
            "identity_records": identity_records,
            "identity_taxonomy": list(IDENTITY_CATEGORIES),
            "pull_request_evidence": (
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
