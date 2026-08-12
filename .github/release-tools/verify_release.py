#!/usr/bin/env python3
"""Fail-closed verification for OMIV's reviewed GitHub release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

REPOSITORY = "200lz/open-model-integration-validator"
TAG = "v0.10.0"
TAG_OBJECT = "d26468e050f4f0aea11e1d1631c92e1e1fbb7bcc"
COMMIT = "09f8265d62f2ea1dfda7da2cd3eb4b3e89639222"
SUBJECT = "OMIV v0.10.0 — Public Preview"
RELEASE_ID = 368959083
KEY_RELATIVE = Path(".github/release-keys/omiv-release-signing-2026.asc")
KEY_SHA256 = "36a96661f85b925778c18fbef717f98dcd1b7f18b05d5b4a984ce3239f02fc01"
PRIMARY_FINGERPRINT = "D8AA580BD3A5B619C6F663C1E849B65FA766CEDA"
SIGNING_FINGERPRINT = "5DFBDC652DE15A90C675185D302F9F71138BD5FA"
WHEEL = "open_model_integration_validator-0.10.0-py3-none-any.whl"
SDIST = "open_model_integration_validator-0.10.0.tar.gz"
SUMS = "SHA256SUMS"
ASSETS = {
    WHEEL: (727953, "caa4040175105fc65be3206ceff16e5916258c113de28af5b0242361aa3dc277"),
    SDIST: (713907, "a659d14f36dfa61bd2170ac84685312ceefb27f7e60e3f80ef8c84344c7eb640"),
    SUMS: (236, "1759937df7696e764aff6ea5ebfe4fcecb4f8c3062390369dd2471301d834bc4"),
}
EXPECTED_MANIFEST = (f"{ASSETS[WHEEL][1]}  {WHEEL}\n{ASSETS[SDIST][1]}  {SDIST}\n").encode()
TAG_PATTERN = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class VerificationError(RuntimeError):
    """An invariant in the release identity chain did not hold."""


@dataclass(frozen=True)
class KeyInventory:
    primary_fingerprint: str
    signing_fingerprint: str
    primary_capabilities: str
    signing_capabilities: str


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    *args: str, cwd: Path | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, check=False, capture_output=True, text=True)


def require_success(result: subprocess.CompletedProcess[str], label: str) -> str:
    if result.returncode != 0:
        fail(f"{label} failed")
    return result.stdout.strip()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.name} is not a JSON object")
    return value


def select_tag(event_name: str, release_tag: str, dispatch_tag: str) -> str:
    if event_name == "release":
        if not release_tag or dispatch_tag:
            fail("release event tag selection is ambiguous")
        selected = release_tag
    elif event_name == "workflow_dispatch":
        if not dispatch_tag or release_tag:
            fail("workflow_dispatch requires exactly one tag input")
        selected = dispatch_tag
    else:
        fail("automatic recovery from this event is prohibited")
    if not TAG_PATTERN.fullmatch(selected):
        fail("selected tag is not a strict semantic release tag")
    if selected != TAG:
        fail("this reviewed recovery contract is restricted to v0.10.0")
    return selected


def verify_invocation(
    event_name: str,
    selected_tag: str,
    github_ref: str,
    github_sha: str,
    workflow_sha: str,
) -> None:
    if event_name == "release":
        if github_ref != f"refs/tags/{selected_tag}" or github_sha != COMMIT:
            fail("release event ref or source commit differs from the signed release")
    elif event_name == "workflow_dispatch":
        if github_ref == f"refs/tags/{selected_tag}":
            if github_sha != COMMIT:
                fail("tag-ref dispatch source commit differs from the signed release")
        elif github_ref != "refs/heads/main":
            fail("manual recovery must be dispatched at the signed tag or reviewed main")
        elif github_sha != workflow_sha:
            fail("main-ref dispatch is not bound to the exact workflow revision")


def verify_workflow_revision(workflow_root: Path, workflow_sha: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}", workflow_sha):
        fail("workflow SHA cannot be resolved exactly")
    actual = require_success(
        run("git", "rev-parse", "HEAD", cwd=workflow_root), "workflow revision"
    )
    if actual != workflow_sha:
        fail("trusted resources were not checked out from the workflow revision")
    key_path = workflow_root / KEY_RELATIVE
    if not key_path.is_file() or key_path.is_symlink():
        fail("pinned public key is absent or unsafe")
    return key_path


def _colon_records(text: str, record_type: str) -> list[list[str]]:
    return [line.split(":") for line in text.splitlines() if line.startswith(f"{record_type}:")]


def inspect_public_key(key_path: Path, gnupghome: Path, *, now: int | None = None) -> KeyInventory:
    if not gnupghome.is_dir() or stat.S_IMODE(gnupghome.stat().st_mode) != 0o700:
        fail("GNUPGHOME must be an isolated mode-0700 directory")
    if sha256(key_path) != KEY_SHA256:
        fail("public-key digest differs from the reviewed digest")
    armor = key_path.read_text(encoding="ascii")
    if (
        armor.count("-----BEGIN PGP PUBLIC KEY BLOCK-----") != 1
        or armor.count("-----END PGP PUBLIC KEY BLOCK-----") != 1
    ):
        fail("public-key resource must contain exactly one public-key block")
    if "PRIVATE KEY" in armor or "SECRET KEY" in armor:
        fail("private-key armor is prohibited")
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    packets = require_success(
        run("gpg", "--batch", "--no-autostart", "--list-packets", str(key_path), env=env),
        "key packet inspection",
    )
    if re.search(r"(?i)secret (?:key|sub key) packet", packets):
        fail("secret-key packet is prohibited")
    shown = require_success(
        run(
            "gpg",
            "--batch",
            "--no-autostart",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            str(key_path),
            env=env,
        ),
        "public-key inventory",
    )
    primary = _colon_records(shown, "pub")
    subkeys = _colon_records(shown, "sub")
    fingerprints = [row[9] for row in _colon_records(shown, "fpr")]
    if (
        len(primary) != 1
        or len(subkeys) != 1
        or fingerprints != [PRIMARY_FINGERPRINT, SIGNING_FINGERPRINT]
    ):
        fail("public-key fingerprint set differs from the reviewed set")
    timestamp = int(time.time()) if now is None else now
    for label, row in (("primary", primary[0]), ("signing subkey", subkeys[0])):
        if row[1] in {"r", "e"}:
            fail(f"{label} is revoked or expired")
        if row[6] and int(row[6]) <= timestamp:
            fail(f"{label} is expired")
    primary_caps, signing_caps = primary[0][11], subkeys[0][11]
    primary_own_caps = {value for value in primary_caps if value.islower()}
    signing_own_caps = {value for value in signing_caps if value.islower()}
    if primary_own_caps != {"c"} or signing_own_caps != {"s"}:
        fail("public-key capabilities differ from certification/signing contract")
    imported = run("gpg", "--batch", "--no-autostart", "--import", str(key_path), env=env)
    if imported.returncode != 0:
        fail("public-key import failed")
    secret = run(
        "gpg",
        "--batch",
        "--no-autostart",
        "--with-colons",
        "--list-secret-keys",
        env=env,
    )
    if secret.returncode not in {0, 2} or _colon_records(secret.stdout, "sec"):
        fail("secret key was imported")
    return KeyInventory(fingerprints[0], fingerprints[1], primary_caps, signing_caps)


def verify_signed_tag(source_root: Path, selected_tag: str, gnupghome: Path) -> None:
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    tag_ref = f"refs/tags/{selected_tag}"
    if require_success(run("git", "cat-file", "-t", tag_ref, cwd=source_root), "tag type") != "tag":
        fail("release tag is lightweight")
    if (
        require_success(run("git", "rev-parse", tag_ref, cwd=source_root), "tag object")
        != TAG_OBJECT
    ):
        fail("local tag object differs from the reviewed object")
    subject = require_success(
        run("git", "for-each-ref", "--format=%(contents:subject)", tag_ref, cwd=source_root),
        "tag annotation",
    )
    if subject != SUBJECT:
        fail("tag annotation differs from the reviewed subject")
    peeled = require_success(
        run("git", "rev-parse", f"{tag_ref}^{{commit}}", cwd=source_root), "tag target"
    )
    head = require_success(run("git", "rev-parse", "HEAD", cwd=source_root), "checked-out source")
    if peeled != COMMIT or head != COMMIT:
        fail("tag target or checked-out package source differs from the release commit")
    verified = run("git", "verify-tag", "--raw", selected_tag, cwd=source_root, env=env)
    raw = verified.stderr + verified.stdout
    valid = re.findall(
        r"\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) [^\n]* ([0-9A-F]{40})\s*$", raw, re.MULTILINE
    )
    if verified.returncode != 0 or valid != [(SIGNING_FINGERPRINT, PRIMARY_FINGERPRINT)]:
        fail("tag lacks the exact reviewed VALIDSIG identity")


def verify_remote_identity(
    release: dict[str, Any], tag_ref: dict[str, Any], tag_object: dict[str, Any]
) -> None:
    if release.get("id") != RELEASE_ID or release.get("tag_name") != TAG:
        fail("GitHub Release identity differs")
    if (
        release.get("name") != SUBJECT
        or release.get("draft") is not False
        or release.get("prerelease") is not True
        or not isinstance(release.get("published_at"), str)
        or not release["published_at"]
    ):
        fail("GitHub Release is missing, draft, or not the reviewed prerelease")
    ref_object = tag_ref.get("object")
    if (
        tag_ref.get("ref") != f"refs/tags/{TAG}"
        or not isinstance(ref_object, dict)
        or ref_object.get("type") != "tag"
        or ref_object.get("sha") != TAG_OBJECT
    ):
        fail("remote annotated tag object differs")
    target = tag_object.get("object")
    verification = tag_object.get("verification")
    if (
        tag_object.get("sha") != TAG_OBJECT
        or tag_object.get("tag") != TAG
        or tag_object.get("message", "").splitlines()[0] != SUBJECT
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != COMMIT
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        fail("remote tag, commit, annotation, or signature status differs")


def verify_assets(release: dict[str, Any], assets_dir: Path) -> None:
    assets = release.get("assets")
    if not isinstance(assets, list) or len(assets) != len(ASSETS):
        fail("GitHub Release assets are absent")
    remote: dict[str, tuple[int, str]] = {}
    for asset in assets:
        if (
            not isinstance(asset, dict)
            or not isinstance(asset.get("name"), str)
            or asset.get("state") != "uploaded"
        ):
            fail("invalid GitHub Release asset record")
        digest = asset.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            fail("GitHub Release asset lacks a SHA-256 digest")
        remote[asset["name"]] = (asset.get("size"), digest.removeprefix("sha256:"))
    if remote != ASSETS:
        fail("GitHub Release has missing, extra, or changed assets")
    local_names = {path.name for path in assets_dir.iterdir() if path.is_file()}
    if local_names != set(ASSETS):
        fail("downloaded release has missing or extra assets")
    for name, (size, digest) in ASSETS.items():
        path = assets_dir / name
        if path.is_symlink() or path.stat().st_size != size or sha256(path) != digest:
            fail(f"release asset bytes differ: {name}")
    if (assets_dir / SUMS).read_bytes() != EXPECTED_MANIFEST:
        fail("SHA256SUMS is not the exact deterministic reviewed manifest")
    with zipfile.ZipFile(assets_dir / WHEEL) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            fail("wheel metadata inventory differs")
        metadata = archive.read(metadata_names[0]).decode("utf-8")
    for field in (
        "Name: open-model-integration-validator",
        "Version: 0.10.0",
        "Requires-Python: >=3.11",
    ):
        if field not in metadata:
            fail("wheel package metadata differs")


def verify_pypi_absent(status: str) -> None:
    if status != "404":
        fail("PyPI project/version is not provably absent")


def write_output(path: Path, name: str, value: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"{name}={value}\n")


def command_select(args: argparse.Namespace) -> None:
    tag = select_tag(args.event_name, args.release_tag, args.dispatch_tag)
    verify_invocation(args.event_name, tag, args.github_ref, args.github_sha, args.workflow_sha)
    verify_workflow_revision(args.workflow_root, args.workflow_sha)
    write_output(args.output, "tag", tag)


def command_verify(args: argparse.Namespace) -> None:
    tag = select_tag(args.event_name, args.release_tag, args.dispatch_tag)
    verify_invocation(args.event_name, tag, args.github_ref, args.github_sha, args.workflow_sha)
    key_path = verify_workflow_revision(args.workflow_root, args.workflow_sha)
    inventory = inspect_public_key(key_path, args.gnupghome)
    verify_signed_tag(args.source_root, tag, args.gnupghome)
    release = read_json(args.release_json)
    verify_remote_identity(release, read_json(args.tag_ref_json), read_json(args.tag_object_json))
    verify_assets(release, args.assets_dir)
    verify_pypi_absent(args.pypi_status)
    write_output(args.output, "tag", tag)
    write_output(args.output, "wheel", WHEEL)
    write_output(args.output, "sdist", SDIST)
    write_output(args.output, "wheel_sha256", ASSETS[WHEEL][1])
    write_output(args.output, "sdist_sha256", ASSETS[SDIST][1])
    print(
        json.dumps(
            {
                "classification": "RELEASE_ASSETS_VERIFIED_FOR_TRUSTED_PUBLICATION",
                "key_sha256": KEY_SHA256,
                "primary_fingerprint": inventory.primary_fingerprint,
                "signing_subkey_fingerprint": inventory.signing_fingerprint,
                "tag": tag,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    for name in ("select", "verify"):
        child = subparsers.add_parser(name)
        child.add_argument("--event-name", required=True)
        child.add_argument("--release-tag", default="")
        child.add_argument("--dispatch-tag", default="")
        child.add_argument("--github-ref", required=True)
        child.add_argument("--github-sha", required=True)
        child.add_argument("--workflow-sha", required=True)
        child.add_argument("--workflow-root", required=True, type=Path)
        child.add_argument("--output", required=True, type=Path)
    verify = subparsers.choices["verify"]
    verify.add_argument("--source-root", required=True, type=Path)
    verify.add_argument("--gnupghome", required=True, type=Path)
    verify.add_argument("--release-json", required=True, type=Path)
    verify.add_argument("--tag-ref-json", required=True, type=Path)
    verify.add_argument("--tag-object-json", required=True, type=Path)
    verify.add_argument("--assets-dir", required=True, type=Path)
    verify.add_argument("--pypi-status", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "select":
            command_select(args)
        else:
            command_verify(args)
    except (OSError, ValueError, json.JSONDecodeError, VerificationError) as exc:
        print(f"RELEASE_VERIFICATION_FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
