from __future__ import annotations

import json
import runpy
import subprocess
import tomllib
from pathlib import Path

from typer.testing import CliRunner

from omiv import __version__
from omiv.cli import app

ROOT = Path(__file__).resolve().parents[1]


def test_public_preview_version_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert project["version"] == __version__ == "0.10.0"
    assert "version: 0.10.0" in citation
    assert project["license"] == "Apache-2.0"
    assert project["authors"] == [{"name": "Linzhang Chen"}]


def test_cli_reports_public_preview_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.10.0"


def test_required_public_files_are_substantive() -> None:
    paths = [
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "SUPPORT.md",
        "THIRD_PARTY_NOTICES.md",
        "TRADEMARKS.md",
        "docs/public-commercial-boundary.md",
        "docs/public-release-security-and-privacy.md",
        "docs/releasing.md",
    ]
    for relative in paths:
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert len(text) >= 200, relative
    assert "Apache License" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_public_document_fixtures_are_bounded_and_attributed() -> None:
    root = ROOT / "fixtures/runtime-resolution/public-documents"
    for path in root.glob("*.normalized.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["source_url"].startswith("https://")
        assert len(document["response_body_sha256"]) == 64
        assert sum(claim["body_byte_length"] for claim in document["claims"]) <= 512
        assert all(len(claim["body_region_sha256"]) == 64 for claim in document["claims"])
        assert "raw response is not stored" in " ".join(document["limitations"]).lower()


def test_ci_has_read_only_permissions_and_immutable_action_pins() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "pull_request_target" not in workflow
    assert "self-hosted" not in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow


def test_public_release_audit_is_privacy_safe_and_passes() -> None:
    result = subprocess.run(
        ["python", "tools/audit_public_release_readiness.py", "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(result.stdout)
    assert report["classification"] == "PASS"
    assert report["privacy"]["sensitive_values_serialized"] == 0
    assert report["privacy"]["approved_historical_path_fingerprints"] == 5
    assert "@" not in result.stdout
    assert "/home/" not in result.stdout
    assert "/tmp/" not in result.stdout
    assert "\x1b" not in result.stdout
    assert report["coverage"]["history_surfaces"] == sorted(report["coverage"]["history_surfaces"])
    assert any("heuristic" in limitation for limitation in report["limitations"])

    repeated = subprocess.run(
        ["python", "tools/audit_public_release_readiness.py", "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert repeated.stdout == result.stdout


def test_public_release_audit_never_follows_candidate_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "sensitive-value"
    target.write_text("must not be read", encoding="utf-8")
    link = tmp_path / "candidate"
    link.symlink_to(target)
    namespace = runpy.run_path(str(ROOT / "tools/audit_public_release_readiness.py"))
    assert namespace["_is_safe_regular_file"](link) is False
