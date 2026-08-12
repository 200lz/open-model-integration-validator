from __future__ import annotations

import json
import runpy
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _audit() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "tools/audit_v0_10_0_release_preparation.py"))


def test_release_preparation_audit_passes_and_is_deterministic() -> None:
    command = ["python", "tools/audit_v0_10_0_release_preparation.py", "--json"]
    first = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    second = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    assert first.stdout == second.stdout
    report = json.loads(first.stdout)
    assert report["classification"] == "PASS"
    assert report["count"]["passed"] == report["count"]["total"]


def test_distribution_and_metadata_contract() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "open-model-integration-validator"
    assert project["version"] == "0.10.0"
    assert project["requires-python"] == ">=3.11"
    assert project["license"] == "Apache-2.0"
    assert "Development Status :: 3 - Alpha" in project["classifiers"]


def test_existing_tag_is_immutable_and_pypi_remains_absent() -> None:
    assert (
        subprocess.run(["git", "cat-file", "-e", "refs/tags/v0.10.0^{tag}"], cwd=ROOT).returncode
        == 0
    )
    assert (
        subprocess.run(
            ["git", "rev-parse", "refs/tags/v0.10.0"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == "d26468e050f4f0aea11e1d1631c92e1e1fbb7bcc"
    )
    recovery = (ROOT / "docs/v0.10.0-publication-recovery.md").read_text(encoding="utf-8")
    assert "PyPI has no project or" in recovery


def test_workflow_has_explicit_recovery_and_least_privilege() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "types: [published]" in workflow
    assert "workflow_dispatch:" in workflow
    assert "required: true" in workflow
    assert "pull_request" not in workflow
    assert "pull_request_target" not in workflow
    assert "push:" not in workflow
    assert "permissions: {}" in workflow
    assert "id-token: write" in workflow
    assert "contents: write" not in workflow
    assert "secrets." not in workflow
    assert "skip-existing" not in workflow
    assert "environment: pypi" in workflow


def test_workflow_actions_are_full_sha_pinned() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in workflow
    assert "@main" not in workflow and "@master" not in workflow


def test_publish_job_does_not_build_or_use_a_mutable_path() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    publish = workflow.split("  publish:", 1)[1]
    assert "needs: verify-release-assets" in publish
    assert "python -m build" not in publish
    assert "packages-dir: dist/" in publish


def test_exact_asset_and_manifest_invariants_are_present() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    verifier = (ROOT / ".github/release-tools/verify_release.py").read_text(encoding="utf-8")
    for marker in (
        "SHA256SUMS",
        "727953",
        "713907",
        "caa4040175105fc65be3206ceff16e5916258c113de28af5b0242361aa3dc277",
        "a659d14f36dfa61bd2170ac84685312ceefb27f7e60e3f80ef8c84344c7eb640",
    ):
        assert marker in workflow + verifier


def test_signed_tag_contract_and_legacy_limitation_are_explicit() -> None:
    releasing = (ROOT / "docs/releasing.md").read_text(encoding="utf-8")
    recovery = (ROOT / "docs/v0.10.0-publication-recovery.md").read_text(encoding="utf-8")
    assert "annotated, cryptographically signed, and immutable" in releasing
    assert "v0.1.0 through v0.9.0" in releasing
    assert "LEGACY_UNSIGNED_TAGS_ACCEPTED_WITH_LIMITATION" in releasing
    assert "TAG_SIGNATURE_PUBLIC_KEY_BOOTSTRAP_MISSING" in recovery


def test_trusted_publisher_tuple_and_unconfigured_state() -> None:
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8")
    for value in (
        "owner: 200lz",
        "repository: open-model-integration-validator",
        "workflow: .github/workflows/publish-pypi.yml",
        "environment: pypi",
        "distribution: open-model-integration-validator",
    ):
        assert value in notes
    assert "TRUSTED_PUBLISHER_NOT_YET_CONFIGURED" in notes


def test_release_failure_taxonomy_is_complete() -> None:
    namespace = _audit()
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8")
    assert all(state in notes for state in namespace["REQUIRED_FAILURES"])


def test_phase_boundaries_and_nonclaims() -> None:
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8").lower()
    assert "phase 6f" in notes and "unimplemented" in notes
    assert "phase 7" in notes
    for term in ("provider authenticity", "publisher authority", "safety", "production readiness"):
        assert term in notes


def test_conditional_pypi_command_is_not_active_default() -> None:
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8")
    assert "AVAILABLE_AFTER_VERIFIED_PYPI_PUBLICATION" in notes
    quickstart = (ROOT / "docs/quickstart.md").read_text(encoding="utf-8")
    assert "pip install -e ." in quickstart


def test_hash_manifest_contract_is_deterministic() -> None:
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8")
    assert "lowercase SHA-256" in notes
    assert "two spaces between digest and filename" in notes
    assert "LF line endings" in notes
    assert "same bytes later published to PyPI" in notes


def test_no_release_or_pypi_mutation_commands_are_committed() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "gh release create" not in workflow
    assert "twine upload" not in workflow
    assert "visibility" not in workflow.lower()


def test_duplicate_yaml_keys_are_rejected() -> None:
    namespace = _audit()
    with pytest.raises(ValueError, match="duplicate YAML key"):
        yaml.load("x: 1\nx: 2\n", Loader=namespace["UniqueLoader"])


def test_release_workflow_has_no_absolute_paths_or_controls() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "/home/" not in workflow and "/Users/" not in workflow
    assert "\x1b" not in workflow
    assert "private_key" not in workflow.lower()


def test_release_notes_links_required_surfaces() -> None:
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8")
    for link in (
        "architecture.md",
        "quickstart.md",
        "../CHANGELOG.md",
        "roadmap.md",
        "../SECURITY.md",
    ):
        assert link in notes


def test_public_state_wording_is_transition_safe() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    assert "repository is public" in readme.lower()
    assert "signed annotated `v0.10.0` tag" in readme
    assert "PyPI project/version remain absent" in roadmap


def test_action_metadata_is_recorded_without_raw_response() -> None:
    notes = (ROOT / "docs/v0.10.0-release-notes.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "pypa/gh-action-pypi-publish" in workflow
    assert "v1.14.2" in workflow
    assert "Apache-2.0" in workflow
    assert "raw HTTP" not in notes


def test_no_model_or_provider_execution_in_publisher() -> None:
    workflow = (ROOT / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8").lower()
    for term in (
        "inference",
        "model provider",
        "tokenizer",
        "curl https://api.openai",
        "huggingface",
    ):
        assert term not in workflow


def test_release_preparation_audit_is_offline() -> None:
    source = (ROOT / "tools/audit_v0_10_0_release_preparation.py").read_text(encoding="utf-8")
    assert "gh api" not in source and "requests" not in source and "urllib.request" not in source


def test_candidate_files_are_regular_and_bounded() -> None:
    for relative in (
        "docs/v0.10.0-release-notes.md",
        ".github/workflows/publish-pypi.yml",
        ".github/release-keys/omiv-release-signing-2026.asc",
        ".github/release-tools/verify_release.py",
        "docs/v0.10.0-publication-recovery.md",
        "tools/audit_v0_10_0_release_preparation.py",
        "tests/test_v0_10_0_release_preparation.py",
    ):
        path = ROOT / relative
        assert path.is_file() and not path.is_symlink() and path.stat().st_size < 1_048_576
