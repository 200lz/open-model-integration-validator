from __future__ import annotations

import copy
import hashlib
import json
import re
import runpy
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools/run_offline_evidence_walkthrough.py"
AUDIT = ROOT / "tools/audit_offline_evidence_walkthrough.py"
MANIFEST = ROOT / "examples/offline-evidence-walkthrough/walkthrough.json"
BASELINE = "053707c03bb8bf5ed3277b680ca27934b42ec9e5"


def _runner() -> dict[str, Any]:
    return runpy.run_path(str(RUNNER))


def _auditor() -> dict[str, Any]:
    return runpy.run_path(str(AUDIT))


def _manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _source_paths(namespace: dict[str, Any]) -> tuple[Path, ...]:
    paths = {
        token
        for command in namespace["ALLOWED_COMMANDS"].values()
        for token in command
        if token.endswith(".json")
    }
    return tuple(ROOT / path for path in sorted(paths))


def _digests(paths: Sequence[Path]) -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def _fake_executor(namespace: dict[str, Any]):
    command_to_id = {
        tuple(command): step_id for step_id, command in namespace["ALLOWED_COMMANDS"].items()
    }

    def execute(command: Sequence[str], _repository: Path) -> tuple[int, str, str]:
        step_id = command_to_id[tuple(command)]
        return (
            namespace["EXPECTED_EXITS"][step_id],
            namespace["EXPECTED_EXACT_STDOUT"][step_id],
            "",
        )

    return execute


def test_exact_r1d_path_inventory_and_manifest_labels() -> None:
    namespace = _runner()
    manifest = _manifest()
    assert tuple(manifest["r1d_paths"]) == namespace["R1D_PATHS"]
    assert manifest["classification"] == "NON_CANONICAL_DEMONSTRATION_MANIFEST"
    assert tuple(manifest["labels"]) == namespace["LABELS"]
    assert len(namespace["R1D_PATHS"]) == 13


def test_manifest_parser_is_strict_and_rejects_duplicate_keys(tmp_path: Path) -> None:
    namespace = _runner()
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"version": 1, "version": 1}', encoding="utf-8")
    with pytest.raises(namespace["WalkthroughError"], match="duplicate JSON key"):
        namespace["load_manifest"](duplicate)


def test_manifest_rejects_unknown_commands_and_step_reordering() -> None:
    namespace = _runner()
    manifest = _manifest()
    namespace["validate_manifest"](manifest)

    unknown = copy.deepcopy(manifest)
    unknown["steps"][0]["command"] = ["omiv", "remote-snapshot"]
    with pytest.raises(namespace["WalkthroughError"], match="allowlist"):
        namespace["validate_manifest"](unknown)

    reordered = copy.deepcopy(manifest)
    reordered["steps"][0], reordered["steps"][1] = (
        reordered["steps"][1],
        reordered["steps"][0],
    )
    with pytest.raises(namespace["WalkthroughError"], match="step order"):
        namespace["validate_manifest"](reordered)

    extra_field = copy.deepcopy(manifest)
    extra_field["execute"] = "omiv --version"
    with pytest.raises(namespace["WalkthroughError"], match="manifest keys"):
        namespace["validate_manifest"](extra_field)

    malformed_type = copy.deepcopy(manifest)
    malformed_type["steps"] = ["omiv --version"]
    with pytest.raises(namespace["WalkthroughError"], match="step"):
        namespace["validate_manifest"](malformed_type)

    absolute_next = copy.deepcopy(manifest)
    absolute_next["steps"][0]["next_evidence"] = "/tmp/substitute.json"
    with pytest.raises(namespace["WalkthroughError"], match="next-evidence"):
        namespace["validate_manifest"](absolute_next)


def test_allowlist_is_offline_and_has_deterministic_semantic_exits() -> None:
    namespace = _runner()
    commands = namespace["ALLOWED_COMMANDS"]
    assert tuple(commands) == namespace["STEP_ORDER"]
    assert all(command[0] == "omiv" for command in commands.values())
    combined = " ".join(token for command in commands.values() for token in command)
    for forbidden in (
        "collect-hf-metadata",
        "remote-snapshot",
        "remote-range-probe",
        "conversion-run",
        "--allow-network",
    ):
        assert forbidden not in combined
    exits = tuple(namespace["EXPECTED_EXITS"].values())
    assert exits.count(0) == 8
    assert exits.count(1) == 2


def test_subprocess_invocation_isolated_from_path_and_pythonpath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _runner()
    monkeypatch.setenv("PATH", "/nonexistent/malicious-path")
    monkeypatch.setenv("PYTHONPATH", "/nonexistent/substituted-package")
    code, stdout, stderr = namespace["execute_offline_command"](("omiv", "--version"), ROOT)
    assert (code, stdout, stderr) == (0, "0.10.0", "")
    child_environment = namespace["_child_environment"]()
    assert "PATH" not in child_environment
    assert "PYTHONPATH" not in child_environment
    source = RUNNER.read_text(encoding="utf-8")
    assert '[sys.executable, "-I", "-m", "omiv"' in source
    assert "shell=False" in source


def test_timeout_and_output_limits_fail_closed() -> None:
    namespace = _runner()
    with pytest.raises(namespace["WalkthroughError"], match="size limit"):
        namespace["sanitize_output"](b"x" * (namespace["MAX_PROCESS_OUTPUT_BYTES"] + 1), ROOT)

    with pytest.raises(namespace["WalkthroughError"], match="timed out and was terminated"):
        namespace["_capture_process"](
            [sys.executable, "-I", "-c", "import time; time.sleep(2)"],
            ROOT,
            timeout_seconds=0.1,
            output_limit=1024,
        )
    with pytest.raises(namespace["WalkthroughError"], match="capture limit"):
        namespace["_capture_process"](
            [sys.executable, "-I", "-c", "print('x' * 4096)"],
            ROOT,
            timeout_seconds=2,
            output_limit=128,
        )


def test_ansi_is_sanitized_but_unsafe_raw_output_is_rejected() -> None:
    namespace = _runner()
    result = namespace["sanitize_output"](b"\x1b[31mVALID\x1b[0m\n", ROOT)
    assert result == "VALID"
    assert "\x1b" not in result
    for raw, message in (
        (b"VALID\x00\n", "unsafe control"),
        (f"VALID {ROOT}/input.json\n".encode(), "absolute machine path"),
        (b"VALID /home/user/input.json\n", "absolute machine path"),
        (b"VALID /tmp/substituted/input.json\n", "absolute machine path"),
        (b"Traceback (most recent call last):\n", "traceback"),
        (b"WARNING: substituted result\n", "warning"),
    ):
        with pytest.raises(namespace["WalkthroughError"], match=message):
            namespace["sanitize_output"](raw, ROOT)


def test_expected_exit_one_is_semantic_not_runner_failure() -> None:
    namespace = _runner()
    output = namespace["run_walkthrough"](ROOT, executor=_fake_executor(namespace))
    assert output.count("semantic=EXPECTED_SEMANTIC_LIMITATION") == 2
    assert "id=phase6b-incomplete-local" in output
    assert "id=phase6e-partial-runtime" in output
    assert "WALKTHROUGH_COMPLETE steps=10 expected_exit_1=2" in output


def test_unexpected_stdout_or_stderr_cannot_be_hidden() -> None:
    namespace = _runner()
    normal = _fake_executor(namespace)

    def extra_stdout(command: Sequence[str], repository: Path) -> tuple[int, str, str]:
        code, stdout, stderr = normal(command, repository)
        if tuple(command) == namespace["ALLOWED_COMMANDS"]["version"]:
            stdout += "\nunexpected"
        return code, stdout, stderr

    with pytest.raises(namespace["WalkthroughError"], match="unexpected output"):
        namespace["run_walkthrough"](ROOT, executor=extra_stdout)

    def traceback_stderr(command: Sequence[str], repository: Path) -> tuple[int, str, str]:
        code, stdout, _stderr = normal(command, repository)
        return code, stdout, "Traceback (most recent call last):"

    with pytest.raises(namespace["WalkthroughError"], match="unexpected stderr"):
        namespace["run_walkthrough"](ROOT, executor=traceback_stderr)


def test_clean_checkout_shape_needs_no_kimi_or_environment_paths(tmp_path: Path) -> None:
    namespace = _runner()
    clean = tmp_path / "clean"
    manifest_destination = clean / namespace["MANIFEST_PATH"]
    manifest_destination.parent.mkdir(parents=True)
    shutil.copy2(MANIFEST, manifest_destination)
    for source in _source_paths(namespace):
        destination = clean / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    assert not (clean / "reports/raw/kimi_k3_tensors.json").exists()
    output = namespace["run_walkthrough"](clean, executor=_fake_executor(namespace))
    assert "clean_checkout=NOT_AVAILABLE required=NO" in output
    assert str(clean) not in output
    assert "/home/" not in output


def test_source_digest_schema_and_trust_substitution_fail_closed(tmp_path: Path) -> None:
    namespace = _runner()
    clean = tmp_path / "clean"
    manifest_destination = clean / namespace["MANIFEST_PATH"]
    manifest_destination.parent.mkdir(parents=True)
    shutil.copy2(MANIFEST, manifest_destination)
    for source in _source_paths(namespace):
        destination = clean / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    scenario = clean / "runtime-resolution-parity/scenarios/immutable-pinned.json"
    scenario.write_bytes(scenario.read_bytes() + b"\n")
    with pytest.raises(namespace["WalkthroughError"], match="source identity"):
        namespace["run_walkthrough"](clean, executor=_fake_executor(namespace))

    scenario.write_bytes((ROOT / scenario.relative_to(clean)).read_bytes())
    trust_bundle = clean / "trust/examples/project-trust-bundle.json"
    trust_bundle.write_bytes(trust_bundle.read_bytes() + b"\n")
    with pytest.raises(namespace["WalkthroughError"], match="source identity"):
        namespace["run_walkthrough"](clean, executor=_fake_executor(namespace))

    trust_bundle.write_bytes((ROOT / trust_bundle.relative_to(clean)).read_bytes())
    value = json.loads(scenario.read_text(encoding="utf-8"))
    value["schema"] = "omiv.wrong-schema.v1"
    scenario.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    namespace["EXPECTED_SOURCE_SHA256"][scenario.relative_to(clean).as_posix()] = hashlib.sha256(
        scenario.read_bytes()
    ).hexdigest()
    with pytest.raises(namespace["WalkthroughError"], match="source schema"):
        namespace["run_walkthrough"](clean, executor=_fake_executor(namespace))


def test_actual_runner_is_deterministic_and_preserves_canonical_sources() -> None:
    namespace = _runner()
    sources = _source_paths(namespace)
    before = _digests(sources)
    command = [sys.executable, str(RUNNER)]
    first = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    second = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    assert first.stdout.startswith("OMIV_OFFLINE_EVIDENCE_WALKTHROUGH version=1\n")
    assert first.stdout.endswith(
        "WALKTHROUGH_COMPLETE steps=10 expected_exit_1=2 malformed_demo=NOT_RUN "
        "network=NONE model_execution=NONE repository_writes=NONE\n"
    )
    assert len(first.stdout.encode("utf-8")) <= 16 * 1024
    assert str(ROOT) not in first.stdout
    assert _digests(sources) == before


def test_malformed_demo_uses_temporary_copy_and_returns_exit_two(tmp_path: Path) -> None:
    namespace = _runner()
    source = ROOT / "runtime-resolution-parity/scenarios/immutable-pinned.json"
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    result = namespace["_run_tamper_demo"](ROOT, tmp_path)
    assert result == (
        "MALFORMED_INPUT_DETECTED exit=2 source_unchanged=YES temporary_files_removed=YES"
    )
    assert list(tmp_path.iterdir()) == []
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_manifest_and_runner_reject_symlinks(tmp_path: Path) -> None:
    namespace = _runner()
    target = tmp_path / "manifest.json"
    target.write_bytes(MANIFEST.read_bytes())
    link = tmp_path / "manifest-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(namespace["WalkthroughError"], match="unsafe or missing"):
        namespace["load_manifest"](link)


def test_documentation_labels_nonclaims_and_exit_contract() -> None:
    walkthrough = (ROOT / "docs/offline-evidence-walkthrough.md").read_text(encoding="utf-8")
    normalized = re.sub(r"\s+", " ", walkthrough)
    for label in (
        "NON_CANONICAL_DEMONSTRATION_MANIFEST",
        "SYNTHETIC",
        "DEMONSTRATION_ONLY",
        "NOT_PROVIDER_EVIDENCE",
        "NOT_AN_ASSURANCE_BUNDLE",
        "NOT_A_SAFETY_OR_AUTHENTICITY_RESULT",
    ):
        assert label in walkthrough
    for nonclaim in (
        "provider authenticity",
        "publisher authority",
        "current provider state",
        "runtime-loaded weights",
        "inference execution",
        "behavioral equivalence",
        "safety or security certification",
        "production readiness",
        "complete model assurance",
        "Phase 6F Assurance Bundle support",
    ):
        assert nonclaim in normalized
    assert walkthrough.count("**Input:**") == 10
    assert walkthrough.count("**Command:**") == 10
    assert walkthrough.count("**What it establishes:**") == 10
    assert walkthrough.count("**What it does not establish:**") == 10
    assert walkthrough.count("**Next evidence link:**") == 10
    for code in (0, 1, 2):
        assert f"| `{code}` |" in walkthrough


def test_markdown_links_and_local_fragments_resolve() -> None:
    namespace = _runner()
    markdown_paths = [path for path in namespace["R1D_PATHS"] if path.endswith(".md")]
    pattern = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
    for relative in markdown_paths:
        source = ROOT / relative
        text = source.read_text(encoding="utf-8")
        for raw_target in pattern.findall(text):
            target = urlsplit(raw_target.strip("<>"))
            if target.scheme in {"http", "https"}:
                continue
            assert not target.scheme and not target.netloc and not target.path.startswith("/")
            destination = source if not target.path else source.parent / unquote(target.path)
            assert destination.is_file(), f"broken link in {relative}: {raw_target}"
            assert not destination.is_symlink()
            if target.fragment and destination == source:
                anchors = {
                    re.sub(
                        r"-+",
                        "-",
                        re.sub(r"[^\w\- ]", "", line.lstrip("# ").lower()).replace(" ", "-"),
                    ).strip("-")
                    for line in text.splitlines()
                    if line.startswith("#")
                }
                assert unquote(target.fragment).lower() in anchors


def test_phase6f_and_public_commercial_boundary_remain_narrow() -> None:
    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    assert "| Phase 6F | COMPLETE; NOT RELEASED |" in roadmap
    assert "| Phase 7 | FUTURE, SCOPE NOT FROZEN |" in roadmap
    boundary = (ROOT / "docs/public-commercial-boundary.md").read_text(encoding="utf-8")
    assert "portable public\nverification boundary" in boundary
    assert "without claiming a hosted service" in boundary


def test_audit_is_deterministic_and_passes() -> None:
    command = [sys.executable, str(AUDIT)]
    first = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    second = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    assert " failed=0 " in first.stdout.splitlines()[-1]
    assert "/home/" not in first.stdout
    assert "\x1b" not in first.stdout


def test_audit_safe_reader_fails_closed_on_symlink(tmp_path: Path) -> None:
    namespace = _auditor()
    target = tmp_path / "target.md"
    target.write_text("safe", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert namespace["_safe_file"](tmp_path, "link.md") is None
    with pytest.raises(namespace["AuditError"], match="unsafe-or-missing"):
        namespace["_text"](tmp_path, "link.md")


def test_runner_source_has_no_network_or_general_executor_surface() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import urllib",
        "import requests",
        "import httpx",
        "shell=True",
        "os.system",
        "eval(",
        "exec(",
    ):
        assert forbidden not in source
    assert "shell=False" in source
    assert "subprocess.Popen" in source
    assert "selectors.DefaultSelector" in source
    assert "process.kill()" in source
    assert "process.wait" in source
    assert '[sys.executable, "-I", "-m", "omiv"' in source
    assert "ALLOWED_COMMANDS" in source
    assert "EXPECTED_SOURCE_SHA256" in source
    assert "EXPECTED_EXACT_STDOUT" in source
    assert "--temporary-directory" in source
    assert "--command" not in source
