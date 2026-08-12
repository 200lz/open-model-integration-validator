#!/usr/bin/env python3
"""Offline, fail-closed audit for the OMIV v0.10.0 preview preparation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.10.0"
DIST = "open-model-integration-validator"
TAG = "v0.10.0"
TAG_OBJECT = "d26468e050f4f0aea11e1d1631c92e1e1fbb7bcc"
TAG_COMMIT = "09f8265d62f2ea1dfda7da2cd3eb4b3e89639222"
PRIMARY_FINGERPRINT = "D8AA580BD3A5B619C6F663C1E849B65FA766CEDA"
SIGNING_FINGERPRINT = "5DFBDC652DE15A90C675185D302F9F71138BD5FA"
KEY_SHA256 = "36a96661f85b925778c18fbef717f98dcd1b7f18b05d5b4a984ce3239f02fc01"
ACTION_SHA = "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
REQUIRED_FAILURES = (
    "RELEASE_PREPARATION_COMPLETE",
    "RELEASE_SIGNING_KEY_NOT_CONFIGURED",
    "TRUSTED_PUBLISHER_NOT_CONFIGURED",
    "SIGNED_TAG_CREATION_FAILED",
    "TAG_PUSH_FAILED",
    "GITHUB_DRAFT_RELEASE_FAILED",
    "GITHUB_PRERELEASE_PUBLICATION_FAILED",
    "RELEASE_ASSET_IDENTITY_MISMATCH",
    "PYPI_TRUSTED_PUBLISHING_FAILED",
    "PYPI_VERSION_ALREADY_EXISTS",
    "PYPI_HASH_MISMATCH",
    "PYPI_METADATA_MISMATCH",
    "POST_PUBLICATION_INSTALL_FAILED",
    "PARTIAL_RELEASE_REQUIRES_MANUAL_REMEDIATION",
    "RELEASE_COMPLETE",
)
REQUIRED_FILES = (
    "README.md",
    "CHANGELOG.md",
    "CITATION.cff",
    "SECURITY.md",
    "docs/v0.10.0-release-notes.md",
    "docs/v0.10.0-publication-recovery.md",
    "docs/releasing.md",
    ".github/release-keys/omiv-release-signing-2026.asc",
    ".github/release-tools/verify_release.py",
    ".github/workflows/publish-pypi.yml",
)
PLACEHOLDERS = ("TODO", "TBD", "INSERT_HASH", "REPLACE_ME", "<hash>", "<date>")


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


class UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _read(root: Path, relative: str) -> str:
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise ValueError(f"unsafe release file: {relative}")
    return path.read_text(encoding="utf-8")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _git_optional(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True
    ).stdout


def _check(name: str, passed: bool, detail: str) -> Check:
    return Check(name, bool(passed), detail)


def _signed_tag_matches(root: Path) -> bool:
    key = root / ".github/release-keys/omiv-release-signing-2026.asc"
    with tempfile.TemporaryDirectory(prefix="omiv-release-audit-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        env = {**os.environ, "GNUPGHOME": str(home)}
        imported = subprocess.run(
            ["gpg", "--batch", "--no-autostart", "--import", str(key)],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        verified = subprocess.run(
            ["git", "verify-tag", "--raw", TAG],
            cwd=root,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
    raw = verified.stderr + verified.stdout
    return (
        imported.returncode == 0
        and verified.returncode == 0
        and bool(
            re.search(
                rf"\[GNUPG:\] VALIDSIG {SIGNING_FINGERPRINT} [^\n]* {PRIMARY_FINGERPRINT}\s*$",
                raw,
                re.MULTILINE,
            )
        )
    )


def validate(root: Path = ROOT) -> list[Check]:
    project = tomllib.loads(_read(root, "pyproject.toml"))["project"]
    citation = _read(root, "CITATION.cff")
    changelog = _read(root, "CHANGELOG.md")
    readme = _read(root, "README.md")
    notes = _read(root, "docs/v0.10.0-release-notes.md")
    releasing = _read(root, "docs/releasing.md")
    recovery = _read(root, "docs/v0.10.0-publication-recovery.md")
    workflow_text = _read(root, ".github/workflows/publish-pypi.yml")
    verifier_text = _read(root, ".github/release-tools/verify_release.py")
    key_bytes = (root / ".github/release-keys/omiv-release-signing-2026.asc").read_bytes()
    workflow = yaml.load(workflow_text, Loader=UniqueLoader)
    if not isinstance(workflow, dict):
        raise ValueError("workflow is not a mapping")

    checks: list[Check] = []
    checks.append(
        _check(
            "version_and_distribution",
            project.get("version") == VERSION and project.get("name") == DIST,
            f"version={project.get('version')} distribution={project.get('name')}",
        )
    )
    checks.append(
        _check(
            "import_and_python_metadata",
            "requires-python" in project
            and project["requires-python"] == ">=3.11"
            and "Development Status :: 3 - Alpha" in project.get("classifiers", []),
            "python>=3.11 alpha",
        )
    )
    checks.append(
        _check(
            "license_metadata",
            project.get("license") == "Apache-2.0" and "license: Apache-2.0" in citation,
            "Apache-2.0",
        )
    )
    checks.append(
        _check(
            "public_preview_language",
            all(
                token in notes
                for token in (
                    "Public Preview",
                    "pre-1.0 Alpha",
                    "first installable public-preview baseline",
                )
            ),
            "alpha preview wording",
        )
    )
    checks.append(
        _check(
            "public_repository_language",
            "repository is public" in readme.lower() and "publicly readable" in notes,
            "public state is stated",
        )
    )
    checks.append(
        _check(
            "pypi_not_yet_available",
            all(
                token in notes
                for token in (
                    "PYPI_PROJECT_NOT_YET_CREATED",
                    "TRUSTED_PUBLISHER_NOT_YET_CONFIGURED",
                    "PYPI_VERSION_NOT_YET_PUBLISHED",
                )
            )
            and "AVAILABLE_AFTER_VERIFIED_PYPI_PUBLICATION" in notes,
            "conditional PyPI command",
        )
    )
    checks.append(
        _check(
            "immutable_signed_tag",
            _git_optional(root, "cat-file", "-t", f"refs/tags/{TAG}").strip() == "tag"
            and _git_optional(root, "rev-parse", f"refs/tags/{TAG}").strip() == TAG_OBJECT
            and _git_optional(root, "rev-parse", f"refs/tags/{TAG}^{{commit}}").strip()
            == TAG_COMMIT
            and _signed_tag_matches(root),
            "exact annotated tag object, commit, and VALIDSIG",
        )
    )
    checks.append(
        _check(
            "signed_tag_contract",
            all(
                token in notes + releasing
                for token in (
                    "annotated",
                    "cryptographically signed",
                    TAG,
                    "OMIV v0.10.0 — Public Preview",
                    "immutable",
                )
            ),
            "signed annotated tag contract",
        )
    )
    checks.append(
        _check(
            "public_key_bootstrap",
            hashlib.sha256(key_bytes).hexdigest() == KEY_SHA256
            and key_bytes.count(b"BEGIN PGP PUBLIC KEY BLOCK") == 1
            and b"PRIVATE KEY" not in key_bytes
            and all(value in verifier_text for value in (PRIMARY_FINGERPRINT, SIGNING_FINGERPRINT)),
            "one reviewed public key with exact digest and fingerprints",
        )
    )
    checks.append(
        _check(
            "publisher_tuple",
            all(
                token in notes
                for token in (
                    "owner: 200lz",
                    "repository: open-model-integration-validator",
                    "workflow: .github/workflows/publish-pypi.yml",
                    "environment: pypi",
                    "distribution: open-model-integration-validator",
                )
            ),
            "exact Trusted Publisher tuple",
        )
    )
    checks.append(
        _check(
            "workflow_release_trigger",
            (workflow.get("on") or workflow.get(True))
            == {
                "release": {"types": ["published"]},
                "workflow_dispatch": {
                    "inputs": {
                        "tag": {
                            "description": "Existing signed prerelease tag to recover",
                            "required": True,
                            "type": "string",
                        }
                    }
                },
            },
            "published release plus explicit required-tag recovery",
        )
    )
    workflow_all = workflow_text.lower()
    checks.append(
        _check(
            "workflow_no_untrusted_triggers",
            not any(
                term in workflow_all
                for term in (
                    "pull_request_target",
                    "pull_request:",
                    "push:",
                    "workflow_run",
                    "repository_dispatch",
                    "schedule:",
                )
            ),
            "no automatic recovery or untrusted trigger",
        )
    )
    checks.append(
        _check(
            "workflow_least_privilege",
            "permissions: {}" in workflow_text
            and "id-token: write" in workflow_text
            and "contents: read" in workflow_text
            and "contents: write" not in workflow_text,
            "read-only plus publish OIDC",
        )
    )
    checks.append(
        _check(
            "workflow_environment",
            "environment: pypi" in workflow_text
            and "self-hosted" not in workflow_all
            and "actions/cache" not in workflow_all,
            "pypi environment, hosted runner, no cache",
        )
    )
    checks.append(
        _check(
            "workflow_action_pins",
            f"pypa/gh-action-pypi-publish@{ACTION_SHA}" in workflow_text
            and f"actions/checkout@{CHECKOUT_SHA}" in workflow_text
            and not re.search(r"uses:\s*[^\n]+@(main|master|v[0-9])(?:\s|$)", workflow_text),
            "immutable official Action commits",
        )
    )
    checks.append(
        _check(
            "workflow_publish_separation",
            "verify-release-assets" in workflow_text
            and "needs: verify-release-assets" in workflow_text
            and "python -m build" not in workflow_text
            and "skip-existing" not in workflow_all,
            "publish consumes release assets without rebuilding",
        )
    )
    checks.append(
        _check(
            "workflow_no_long_lived_credentials",
            not any(
                term in workflow_all
                for term in (
                    "password",
                    "username",
                    "pypi_token",
                    "secrets.",
                    "repository_dispatch",
                    "custom-index",
                )
            ),
            "OIDC only",
        )
    )
    checks.append(
        _check(
            "workflow_exact_artifacts",
            all(
                term in workflow_text + verifier_text
                for term in ("SHA256SUMS", "Version: 0.10.0", "sha256", "727953", "713907")
            ),
            "one wheel, one sdist, manifest and metadata",
        )
    )
    checks.append(
        _check(
            "artifact_identity_chain",
            all(
                token in notes + releasing
                for token in (
                    "release commit",
                    "signed annotated",
                    "SHA256SUMS",
                    "same bytes",
                    "PyPI",
                )
            ),
            "commit-tag-artifact-PyPI binding",
        )
    )
    checks.append(
        _check(
            "failure_taxonomy",
            all(state in notes + releasing for state in REQUIRED_FAILURES),
            "typed release failure states",
        )
    )
    checks.append(
        _check(
            "phase_boundaries",
            "Phase 6F" in notes and "unimplemented" in notes and "Phase 7" in notes,
            "Phase 6F/7 remain outside release",
        )
    )
    checks.append(
        _check(
            "non_claims",
            all(
                term in notes.lower()
                for term in (
                    "production readiness",
                    "provider authenticity",
                    "publisher authority",
                    "safety",
                )
            ),
            "explicit non-claims",
        )
    )
    checks.append(
        _check(
            "security_link",
            "SECURITY.md" in notes and "SECURITY.md" in readme,
            "security reporting route",
        )
    )
    checks.append(
        _check(
            "roadmap_order",
            all(
                term in (readme + notes + _read(root, "docs/roadmap.md"))
                for term in ("v0.11.0", "DeepSeek", "Meta Muse", "Phase 7")
            ),
            "future roadmap ordering",
        )
    )
    combined = "\n".join((notes, recovery, workflow_text, verifier_text, readme, releasing))
    checks.append(
        _check(
            "no_unresolved_placeholders",
            not any(token in combined for token in PLACEHOLDERS if token != "<date>"),
            "no unresolved placeholders",
        )
    )
    checks.append(
        _check(
            "no_credentials_or_absolute_paths",
            not re.search(
                r"(?i)(gh[pousr]_[A-Za-z0-9]{20,}|BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY|"
                r"/home/|/Users/)",
                combined,
            ),
            "no secrets or machine paths",
        )
    )
    checks.append(
        _check(
            "sdist_includes_release_notes",
            '"/docs"' in _read(root, "pyproject.toml") or "/docs" in _read(root, "pyproject.toml"),
            "documentation is packaged through sdist include",
        )
    )
    checks.append(
        _check(
            "preparation_status",
            "Release preparation is therefore not release completion" in notes
            and "PyPI publication" in changelog + readme + releasing,
            "preparation remains distinct",
        )
    )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        checks = validate()
    except (OSError, ValueError, tomllib.TOMLDecodeError, yaml.YAMLError) as exc:
        print(f"FAIL release-preparation-audit: {type(exc).__name__}", file=sys.stderr)
        return 2
    report = {
        "classification": "PASS" if all(item.passed for item in checks) else "FAIL",
        "checks": [asdict(item) for item in checks],
        "count": {"passed": sum(item.passed for item in checks), "total": len(checks)},
    }
    if args.json:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(f"{report['classification']} {report['count']['passed']}/{report['count']['total']}")
        for item in checks:
            print(f"{'PASS' if item.passed else 'FAIL'} {item.name}: {item.detail}")
    return 0 if report["classification"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
