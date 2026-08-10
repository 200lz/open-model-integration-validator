from __future__ import annotations

import hashlib
import json
import re
import runpy
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from omiv.cli import app

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "tools/audit_public_launch_ux.py"
INPUT = ROOT / "runtime-resolution-parity/scenarios/immutable-pinned.json"
COMMAND = "omiv runtime-resolution verify runtime-resolution-parity/scenarios/immutable-pinned.json"
EXPECTED = (
    "VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.runtime-resolution-scenario-result.v1"
)
REQUIRED_HEADINGS = {
    "Why OMIV",
    "What OMIV verifies",
    "30-second quickstart",
    "Evidence chain",
    "Current capabilities",
    "Practice-profile limitations",
    "Public and future commercial boundary",
    "Documentation",
    "Project status and roadmap",
    "Contributing, security, support, and license",
}
REQUIRED_LIMITATIONS = {
    "a provider request occurred",
    "a live alias was resolved",
    "a deployment was observed",
    "runtime-loaded weights were observed",
    "the selected model produced an inference",
    "provider authenticity was established",
    "publisher authority was established",
    "safety or production readiness was established",
}


def _audit_namespace() -> dict[str, Any]:
    return runpy.run_path(str(AUDIT))


def _git_status() -> str:
    return subprocess.run(
        ["git", "status", "--short", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def test_launch_audit_passes_and_is_deterministic() -> None:
    first = subprocess.run(
        [sys.executable, str(AUDIT), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [sys.executable, str(AUDIT), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert first.stdout == second.stdout
    report = json.loads(first.stdout)
    assert report["classification"] == "PASS"
    assert report["summary"]["failed"] == 0
    assert report["summary"]["passed"] == report["summary"]["total"]
    assert report["summary"]["total"] == len(report["checks"])
    assert "/home/" not in first.stdout
    assert "/Users/" not in first.stdout
    assert "\x1b" not in first.stdout


def test_link_audit_rejects_missing_unsafe_and_unknown_fragments(tmp_path: Path) -> None:
    namespace = _audit_namespace()
    source = tmp_path / "README.md"
    source.write_text("[missing](docs/missing.md)", encoding="utf-8")
    ok, detail = namespace["relative_links_are_safe"](
        source.read_text(encoding="utf-8"), source, tmp_path
    )
    assert not ok
    assert detail == "invalid_links=1"

    target = tmp_path / "target.md"
    target.write_text("# Existing heading\n", encoding="utf-8")
    source.write_text("[unknown](target.md#missing-heading)", encoding="utf-8")
    ok, detail = namespace["relative_links_are_safe"](
        source.read_text(encoding="utf-8"), source, tmp_path
    )
    assert not ok
    assert detail == "invalid_links=1"

    source.write_text("[unsafe](/home/user/secret)", encoding="utf-8")
    ok, detail = namespace["relative_links_are_safe"](
        source.read_text(encoding="utf-8"), source, tmp_path
    )
    assert not ok
    assert detail == "invalid_links=1"


def test_overclaim_audit_distinguishes_negative_statements() -> None:
    scan = _audit_namespace()["affirmative_overclaims"]
    assert scan("Phase 6F is implemented") == ("phase6f_complete",)
    assert scan("The repository is public") == ("public_repository",)
    assert scan("OMIV is available on PyPI") == ("pypi_available",)
    assert scan("OMIV is not available on PyPI") == ()
    assert scan("Version 0.10.0 is not released; Phase 6F is not implemented") == ()


def test_demo_label_audit_rejects_an_incomplete_label_set() -> None:
    check = _audit_namespace()["demo_labels_are_complete"]
    assert check("SYNTHETIC")[0] is False
    complete = " ".join(
        (
            "SYNTHETIC",
            "DEMONSTRATION_ONLY",
            "NOT_PROVIDER_EVIDENCE",
            "NOT_A_SAFETY_OR_AUTHENTICITY_RESULT",
        )
    )
    assert check(complete) == (True, "missing_labels=0")


def test_readme_structure_and_first_screen_are_independent() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    headings = {
        match.group(1) for line in readme.splitlines() if (match := re.match(r"^## (.+)$", line))
    }
    assert headings >= REQUIRED_HEADINGS
    assert 250 <= len(readme.splitlines()) <= 600
    first_screen = "\n".join(readme.splitlines()[:100])
    for phrase in (
        "offline-first",
        "public-preview candidate",
        "Python 3.11+",
        "Apache-2.0",
        "What OMIV verifies",
        "30-second quickstart",
        "```mermaid",
    ):
        assert phrase in first_screen
    assert "A model name is not a model identity" in first_screen
    assert "Canonical validity is not authenticity" in first_screen


def test_quickstart_limitations_and_roadmap_state_are_independent() -> None:
    quickstart = (ROOT / "docs/quickstart.md").read_text(encoding="utf-8")
    assert "means only that strict parsing succeeded" in quickstart
    found_limitations = {phrase for phrase in REQUIRED_LIMITATIONS if phrase in quickstart}
    assert found_limitations >= REQUIRED_LIMITATIONS

    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    for row in (
        "Phase 5 | RELEASED",
        "Phase 6A | RELEASED",
        "Phase 6B | RELEASED",
        "Phase 6C | RELEASED",
        "Phase 6D | RELEASED",
        "Phase 6E | RELEASED",
        "Phase 6F | PLANNED, NOT IMPLEMENTED",
        "Phase 7 | FUTURE, SCOPE NOT FROZEN",
        "R1C launch UX | IMPLEMENTED, RELEASE PENDING",
    ):
        assert row in roadmap
    assert "does not mean the repository is public" in roadmap
    assert "untagged and unreleased `v0.10.0`" in roadmap
    assert "visibility change requires separate authorization" in roadmap


def test_documentation_links_resolve_independently() -> None:
    files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    files.extend(sorted((ROOT / "examples/offline-quickstart").rglob("*.md")))
    pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for source in files:
        for target in pattern.findall(source.read_text(encoding="utf-8")):
            path = target.split("#", 1)[0].split("?", 1)[0]
            if not path or path.startswith(("https://", "http://")):
                continue
            assert not path.startswith(("/", "file:", "javascript:", "data:"))
            resolved = source.parent / path
            assert resolved.is_file(), f"broken link in {source.relative_to(ROOT)}: {target}"
            assert not resolved.is_symlink()


def test_documentation_contains_no_affirmative_release_or_public_claims() -> None:
    combined = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "docs/README.md",
            "docs/quickstart.md",
            "docs/roadmap.md",
            "examples/offline-quickstart/README.md",
        )
    )
    for false_claim in (
        "OMIV is available on PyPI",
        "The repository is public",
        "Phase 6F is implemented",
        "v0.10.0 is released",
    ):
        assert false_claim not in combined


def test_launch_audit_rejects_required_adversarial_mutations(tmp_path: Path) -> None:
    fixture = tmp_path / "repository"
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.split(b"\0")
    paths = {Path(item.decode()) for item in tracked if item}
    paths.update(Path(path) for path in _audit_namespace()["LAUNCH_PATHS"])
    for relative in sorted(paths):
        source = ROOT / relative
        if source.is_file():
            destination = fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    build_report = _audit_namespace()["build_report"]

    def rejected() -> bool:
        try:
            return build_report(fixture)["classification"] == "FAIL"
        except (OSError, UnicodeError, ValueError):
            return True

    mutations = (
        ("README.md", "## Why OMIV", "Why OMIV"),
        ("README.md", "## Documentation", "## Documentation\n[broken](docs/missing.md)"),
        ("README.md", "## Documentation", "## Documentation\nOMIV is available on PyPI."),
        ("README.md", "## Documentation", "## Documentation\nThe repository is public."),
        ("README.md", "## Documentation", "## Documentation\nPhase 6F is implemented."),
        (
            "examples/offline-quickstart/README.md",
            "`NOT_PROVIDER_EVIDENCE`",
            "provider evidence label omitted",
        ),
        ("README.md", "```mermaid", "```mermaid\n```mermaid"),
        ("README.md", "## Documentation", "## Documentation\n/home/user/project"),
    )
    for relative, old, new in mutations:
        path = fixture / relative
        original = path.read_text(encoding="utf-8")
        assert old in original
        path.write_text(original.replace(old, new, 1), encoding="utf-8")
        assert rejected(), relative
        path.write_text(original, encoding="utf-8")

    binary = fixture / "docs/assets/unexpected.png"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert rejected()

    binary.unlink()
    collision = fixture / "docs/QuickStart.md"
    shutil.copy2(fixture / "docs/quickstart.md", collision)
    assert rejected()


def test_documented_quickstart_command_is_real_tracked_and_offline(
    monkeypatch, tmp_path: Path
) -> None:
    for relative in (
        "README.md",
        "docs/quickstart.md",
        "examples/offline-quickstart/README.md",
    ):
        assert COMMAND in (ROOT / relative).read_text(encoding="utf-8")

    subprocess.run(
        ["git", "ls-files", "--error-unmatch", INPUT.relative_to(ROOT).as_posix()],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    isolated_input = tmp_path / INPUT.relative_to(ROOT)
    isolated_input.parent.mkdir(parents=True)
    isolated_input.write_bytes(INPUT.read_bytes())
    tampered = tmp_path / "tampered.json"
    value = json.loads(INPUT.read_text(encoding="utf-8"))
    value["case_id"] = "immutable-tampered"
    tampered.write_text(json.dumps(value), encoding="utf-8")
    assert not (tmp_path / "reports/raw/kimi_k3_tensors.json").exists()

    before_status = _git_status()
    before_digest = hashlib.sha256(INPUT.read_bytes()).hexdigest()

    def deny_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("quickstart attempted network access")

    def deny_write(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("quickstart attempted a filesystem write")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(Path, "write_text", deny_write)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "runtime-resolution",
            "verify",
            "runtime-resolution-parity/scenarios/immutable-pinned.json",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == EXPECTED
    assert len(result.stdout.encode("utf-8")) < 200
    assert hashlib.sha256(INPUT.read_bytes()).hexdigest() == before_digest
    assert _git_status() == before_status

    version = CliRunner().invoke(app, ["--version"])
    assert version.exit_code == 0
    assert version.stdout.strip() == "0.10.0"

    invalid = CliRunner().invoke(app, ["runtime-resolution", "verify", str(tampered)])
    assert invalid.exit_code == 2


def test_quickstart_inspection_is_deterministic_and_bounded() -> None:
    runner = CliRunner()
    args = [
        "runtime-resolution",
        "inspect",
        "runtime-resolution-parity/scenarios/immutable-pinned.json",
    ]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert len(first.stdout.encode("utf-8")) < 4096
    inspected = json.loads(first.stdout)
    assert inspected["case_id"] == "immutable-pinned"
    assert inspected["limitations"] == [
        "Synthetic scenario is not production model or runtime evidence."
    ]
