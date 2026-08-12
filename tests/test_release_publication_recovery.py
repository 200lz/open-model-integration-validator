from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/release-tools/verify_release.py"
SPEC = importlib.util.spec_from_file_location("omiv_release_verifier", SCRIPT)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)


def _result(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess((), returncode, stdout, stderr)


def _release() -> dict[str, object]:
    return {
        "id": VERIFIER.RELEASE_ID,
        "tag_name": VERIFIER.TAG,
        "name": VERIFIER.SUBJECT,
        "draft": False,
        "prerelease": True,
        "published_at": "2026-08-11T00:00:00Z",
        "assets": [
            {
                "name": name,
                "size": size,
                "digest": f"sha256:{digest}",
                "state": "uploaded",
            }
            for name, (size, digest) in VERIFIER.ASSETS.items()
        ],
    }


def _tag_ref() -> dict[str, object]:
    return {
        "ref": f"refs/tags/{VERIFIER.TAG}",
        "object": {"type": "tag", "sha": VERIFIER.TAG_OBJECT},
    }


def _tag_object() -> dict[str, object]:
    return {
        "sha": VERIFIER.TAG_OBJECT,
        "tag": VERIFIER.TAG,
        "message": f"{VERIFIER.SUBJECT}\n",
        "object": {"type": "commit", "sha": VERIFIER.COMMIT},
        "verification": {"verified": True, "reason": "valid"},
    }


def _key_home(tmp_path: Path) -> Path:
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    os.chmod(home, 0o700)
    return home


def _key_inventory(
    primary: str | None = None,
    subkey: str | None = None,
    *,
    validity: str = "u",
    expiry: int = 2_000_000_000,
    primary_caps: str = "cSC",
    subkey_caps: str = "s",
) -> str:
    primary = primary or VERIFIER.PRIMARY_FINGERPRINT
    subkey = subkey or VERIFIER.SIGNING_FINGERPRINT
    return "\n".join(
        (
            f"pub:{validity}:255:22:E849B65FA766CEDA:1:{expiry}::u:::{primary_caps}:::::ed25519:::0:",
            f"fpr:::::::::{primary}:",
            "uid:u::::::::REDACTED:::::::::",
            f"sub:{validity}:255:22:302F9F71138BD5FA:1:{expiry}:::::{subkey_caps}:::::ed25519::",
            f"fpr:::::::::{subkey}:",
        )
    )


def _mock_gpg(
    monkeypatch: pytest.MonkeyPatch, inventory: str, *, packets: str = ":public key packet:"
) -> None:
    def fake_run(*args: str, **_: object) -> subprocess.CompletedProcess[str]:
        joined = " ".join(args)
        if "--list-packets" in joined:
            return _result(packets)
        if "show-only" in joined:
            return _result(inventory)
        if "--list-secret-keys" in joined:
            return _result("")
        return _result("")

    monkeypatch.setattr(VERIFIER, "run", fake_run)


def test_pinned_key_digest_and_typed_inventory(tmp_path: Path) -> None:
    key = ROOT / VERIFIER.KEY_RELATIVE
    assert VERIFIER.sha256(key) == VERIFIER.KEY_SHA256
    inventory = VERIFIER.inspect_public_key(key, _key_home(tmp_path))
    assert inventory.primary_fingerprint == VERIFIER.PRIMARY_FINGERPRINT
    assert inventory.signing_fingerprint == VERIFIER.SIGNING_FINGERPRINT
    assert "c" in inventory.primary_capabilities.lower()
    assert "s" in inventory.signing_capabilities.lower()


def test_key_rejects_missing_file_and_unisolated_home(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True
    )
    marker = tmp_path / "marker"
    marker.write_text("test\n", encoding="utf-8")
    subprocess.run(["git", "add", "marker"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=tmp_path, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    with pytest.raises(VERIFIER.VerificationError, match="absent"):
        VERIFIER.verify_workflow_revision(tmp_path, revision)
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o755)
    with pytest.raises(VERIFIER.VerificationError, match="mode-0700"):
        VERIFIER.inspect_public_key(ROOT / VERIFIER.KEY_RELATIVE, home)


def test_key_rejects_wrong_digest_and_private_armor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "key.asc"
    key.write_text(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n"
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n",
        encoding="ascii",
    )
    with pytest.raises(VERIFIER.VerificationError, match="digest"):
        VERIFIER.inspect_public_key(key, _key_home(tmp_path))
    monkeypatch.setattr(VERIFIER, "KEY_SHA256", hashlib.sha256(key.read_bytes()).hexdigest())
    with pytest.raises(VERIFIER.VerificationError, match="private-key armor"):
        VERIFIER.inspect_public_key(key, tmp_path / "gnupg")


@pytest.mark.parametrize(
    ("inventory", "message"),
    [
        (_key_inventory(primary="A" * 40), "fingerprint"),
        (_key_inventory(subkey="B" * 40), "fingerprint"),
        (_key_inventory(primary_caps="s"), "capabilities"),
        (_key_inventory(primary_caps="cs"), "capabilities"),
        (_key_inventory(subkey_caps="c"), "capabilities"),
        (_key_inventory(expiry=2), "expired"),
        (_key_inventory(validity="r"), "revoked"),
    ],
)
def test_key_rejects_wrong_identity_lifetime_or_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inventory: str, message: str
) -> None:
    _mock_gpg(monkeypatch, inventory)
    with pytest.raises(VERIFIER.VerificationError, match=message):
        VERIFIER.inspect_public_key(ROOT / VERIFIER.KEY_RELATIVE, _key_home(tmp_path), now=100)


def test_key_rejects_secret_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_gpg(monkeypatch, _key_inventory(), packets=":secret key packet:")
    with pytest.raises(VERIFIER.VerificationError, match="secret-key packet"):
        VERIFIER.inspect_public_key(ROOT / VERIFIER.KEY_RELATIVE, _key_home(tmp_path))


def test_event_selection_requires_explicit_exact_tag() -> None:
    assert VERIFIER.select_tag("release", VERIFIER.TAG, "") == VERIFIER.TAG
    assert VERIFIER.select_tag("workflow_dispatch", "", VERIFIER.TAG) == VERIFIER.TAG
    for event, release_tag, dispatch_tag in (
        ("workflow_dispatch", "", ""),
        ("workflow_dispatch", "", "main"),
        ("push", "", VERIFIER.TAG),
        ("release", VERIFIER.TAG, VERIFIER.TAG),
    ):
        with pytest.raises(VERIFIER.VerificationError):
            VERIFIER.select_tag(event, release_tag, dispatch_tag)


def test_invocation_rejects_branch_or_commit_substitution() -> None:
    with pytest.raises(VERIFIER.VerificationError):
        VERIFIER.verify_invocation(
            "release", VERIFIER.TAG, "refs/heads/main", VERIFIER.COMMIT, VERIFIER.COMMIT
        )
    with pytest.raises(VERIFIER.VerificationError):
        VERIFIER.verify_invocation(
            "workflow_dispatch", VERIFIER.TAG, "refs/heads/topic", "f" * 40, "f" * 40
        )
    with pytest.raises(VERIFIER.VerificationError):
        VERIFIER.verify_invocation(
            "workflow_dispatch",
            VERIFIER.TAG,
            f"refs/tags/{VERIFIER.TAG}",
            "f" * 40,
            "f" * 40,
        )
    with pytest.raises(VERIFIER.VerificationError, match="workflow revision"):
        VERIFIER.verify_invocation(
            "workflow_dispatch", VERIFIER.TAG, "refs/heads/main", "e" * 40, "f" * 40
        )


def _mock_tag_commands(
    monkeypatch: pytest.MonkeyPatch,
    *,
    kind: str = "tag",
    subject: str | None = None,
    target: str | None = None,
    head: str | None = None,
    verification: str | None = None,
) -> None:
    subject = VERIFIER.SUBJECT if subject is None else subject
    target = VERIFIER.COMMIT if target is None else target
    head = VERIFIER.COMMIT if head is None else head
    verification = (
        f"[GNUPG:] VALIDSIG {VERIFIER.SIGNING_FINGERPRINT} 2026-01-01 0 4 0 22 8 00 "
        f"{VERIFIER.PRIMARY_FINGERPRINT}\n"
        if verification is None
        else verification
    )

    def fake_run(*args: str, **_: object) -> subprocess.CompletedProcess[str]:
        joined = " ".join(args)
        if "cat-file -t" in joined:
            return _result(kind)
        if "for-each-ref" in joined:
            return _result(subject)
        if "^{commit}" in joined:
            return _result(target)
        if "rev-parse HEAD" in joined:
            return _result(head)
        if "rev-parse refs/tags" in joined:
            return _result(VERIFIER.TAG_OBJECT)
        if "verify-tag --raw" in joined:
            return _result(stderr=verification)
        raise AssertionError(joined)

    monkeypatch.setattr(VERIFIER, "run", fake_run)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"kind": "commit"}, "lightweight"),
        ({"subject": "wrong"}, "annotation"),
        ({"target": "f" * 40}, "package source"),
        ({"head": "f" * 40}, "package source"),
        ({"verification": "[GNUPG:] GOODSIG 302F9F71138BD5FA redacted\n"}, "VALIDSIG"),
        (
            {
                "verification": (
                    "[GNUPG:] VALIDSIG "
                    + "A" * 40
                    + " 2026-01-01 0 4 0 22 8 00 "
                    + VERIFIER.PRIMARY_FINGERPRINT
                    + "\n"
                )
            },
            "VALIDSIG",
        ),
    ],
)
def test_local_tag_rejects_identity_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, str],
    message: str,
) -> None:
    _mock_tag_commands(monkeypatch, **changes)
    with pytest.raises(VERIFIER.VerificationError, match=message):
        VERIFIER.verify_signed_tag(tmp_path, VERIFIER.TAG, tmp_path)


def test_remote_identity_rejects_missing_draft_stable_or_wrong_tag() -> None:
    cases: list[dict[str, object]] = [{}]
    for field, value in (("draft", True), ("prerelease", False), ("tag_name", "v0.10.1")):
        release = _release()
        release[field] = value
        cases.append(release)
    for release in cases:
        with pytest.raises(VERIFIER.VerificationError):
            VERIFIER.verify_remote_identity(release, _tag_ref(), _tag_object())


def test_remote_identity_rejects_lightweight_or_wrong_target() -> None:
    lightweight = _tag_ref()
    lightweight["object"]["type"] = "commit"  # type: ignore[index]
    with pytest.raises(VERIFIER.VerificationError, match="annotated"):
        VERIFIER.verify_remote_identity(_release(), lightweight, _tag_object())
    target = _tag_object()
    target["object"]["sha"] = "f" * 40  # type: ignore[index]
    with pytest.raises(VERIFIER.VerificationError, match="tag, commit"):
        VERIFIER.verify_remote_identity(_release(), _tag_ref(), target)


def test_release_rejects_extra_or_missing_asset(tmp_path: Path) -> None:
    for mutate in ("extra", "missing"):
        release = _release()
        assets = release["assets"]
        assert isinstance(assets, list)
        if mutate == "extra":
            assets.append({"name": "unexpected", "size": 0, "digest": "sha256:" + "0" * 64})
        else:
            assets.pop()
        with pytest.raises(VERIFIER.VerificationError, match="assets"):
            VERIFIER.verify_assets(release, tmp_path)


def test_release_rejects_tampered_sha256sums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / VERIFIER.WHEEL
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "x.dist-info/METADATA",
            "Name: open-model-integration-validator\nVersion: 0.10.0\nRequires-Python: >=3.11\n",
        )
    (tmp_path / VERIFIER.SDIST).write_bytes(b"sdist")
    (tmp_path / VERIFIER.SUMS).write_bytes(b"tampered\n")
    dynamic = {
        name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        for name, path in (
            (VERIFIER.WHEEL, wheel),
            (VERIFIER.SDIST, tmp_path / VERIFIER.SDIST),
            (VERIFIER.SUMS, tmp_path / VERIFIER.SUMS),
        )
    }
    monkeypatch.setattr(VERIFIER, "ASSETS", dynamic)
    release = _release()
    release["assets"] = [
        {
            "name": name,
            "size": size,
            "digest": f"sha256:{digest}",
            "state": "uploaded",
        }
        for name, (size, digest) in dynamic.items()
    ]
    with pytest.raises(VERIFIER.VerificationError, match="SHA256SUMS"):
        VERIFIER.verify_assets(release, tmp_path)


def test_pypi_must_be_absent() -> None:
    VERIFIER.verify_pypi_absent("404")
    for status in ("200", "000", "500"):
        with pytest.raises(VERIFIER.VerificationError, match="absent"):
            VERIFIER.verify_pypi_absent(status)


def test_workflow_is_manual_or_published_release_only_and_fail_closed() -> None:
    text = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    assert set(workflow["on"]) == {"release", "workflow_dispatch"}
    assert workflow["on"]["release"] == {"types": ["published"]}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["tag"] == {
        "description": "Existing signed prerelease tag to recover",
        "required": True,
        "type": "string",
    }
    for forbidden in (
        "pull_request_target",
        "pull_request:",
        "push:",
        "workflow_run",
        "repository_dispatch",
        "schedule:",
        "skip-existing",
        "password:",
        "secrets.",
        "recv-keys",
        "keyserver",
        "python -m build",
        "twine upload",
    ):
        assert forbidden not in text


def test_workflow_source_permissions_environment_and_cleanup() -> None:
    text = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    verify, publish = text.split("  publish:", 1)
    verify_job = workflow["jobs"]["verify-release-assets"]
    assert "ref: ${{ github.workflow_sha }}" in verify
    assert "ref: refs/tags/${{ steps.select.outputs.tag }}" in verify
    assert "persist-credentials: false" in verify
    assert "install -d -m 0700" in verify
    assert "if: always()" in verify and 'rm -rf -- "$GNUPGHOME"' in verify
    assert "runner.temp" not in text
    assert all("${{ runner." not in str(value) for value in verify_job["env"].values())
    keyring_steps = {
        step["name"]: step["run"]
        for step in verify_job["steps"]
        if step["name"]
        in {
            "Create isolated public-key keyring",
            "Download and verify immutable release state",
            "Remove isolated public-key keyring",
        }
    }
    assert len(keyring_steps) == 3
    assert all("$RUNNER_TEMP/omiv-release-gnupg" in run for run in keyring_steps.values())
    assert "id-token: write" not in verify
    assert publish.count("id-token: write") == 1
    assert "environment: pypi" in publish
    assert "gh release download" in publish and "python -m build" not in publish
    assert "attestations: true" in publish


def test_key_material_is_not_sourced_from_network_or_account_api() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "KEY_RELATIVE" in text and "KEY_SHA256" in text
    for forbidden in ("keyserver", "recv-keys", "/users/", "api.github.com/users"):
        assert forbidden not in text
    assert stat.S_ISREG((ROOT / VERIFIER.KEY_RELATIVE).stat().st_mode)


def test_no_goodsig_only_or_rebuilt_artifact_fallback() -> None:
    verifier = SCRIPT.read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "VALIDSIG" in verifier and "GOODSIG" not in verifier
    assert "release-assets" in workflow and "shutil.copyfile" in workflow
    assert "build" not in workflow.lower().replace("public-key bootstrap", "")
