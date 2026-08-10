#!/usr/bin/env python3
"""Fail-closed static audit for the bounded R1D offline walkthrough."""

from __future__ import annotations

import argparse
import ast
import json
import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

MAX_FILE_BYTES = 1024 * 1024
BASELINE = "053707c03bb8bf5ed3277b680ca27934b42ec9e5"
MANIFEST = "examples/offline-evidence-walkthrough/walkthrough.json"

R1D_PATHS = (
    "README.md",
    "docs/README.md",
    "docs/offline-evidence-walkthrough.md",
    "docs/quickstart.md",
    "docs/roadmap.md",
    "examples/offline-evidence-walkthrough/README.md",
    MANIFEST,
    "examples/offline-quickstart/README.md",
    "tests/test_offline_evidence_walkthrough.py",
    "tests/test_public_launch_ux.py",
    "tools/audit_offline_evidence_walkthrough.py",
    "tools/audit_public_launch_ux.py",
    "tools/run_offline_evidence_walkthrough.py",
)

STEP_ORDER = (
    "version",
    "canonical-runtime-scenario",
    "phase6a-local-payload",
    "phase6b-remote-metadata",
    "phase6b-incomplete-local",
    "phase6c-sampled-fidelity",
    "phase6d-tokenizer-scope",
    "phase5-trust-boundary",
    "phase6e-resolution-receipt",
    "phase6e-partial-runtime",
)

ALLOWED_COMMANDS = {
    "version": ("omiv", "--version"),
    "canonical-runtime-scenario": (
        "omiv",
        "runtime-resolution",
        "verify",
        "runtime-resolution-parity/scenarios/immutable-pinned.json",
    ),
    "phase6a-local-payload": (
        "omiv",
        "payload",
        "verify-manifest",
        "payload-integrity/observations/local.manifest.json",
    ),
    "phase6b-remote-metadata": (
        "omiv",
        "reconcile",
        "verify",
        "reconciliation/snapshots/metadata-only.snapshot.json",
    ),
    "phase6b-incomplete-local": (
        "omiv",
        "reconcile",
        "verify",
        "reconciliation/comparisons/incomplete.json",
    ),
    "phase6c-sampled-fidelity": (
        "omiv",
        "quantization",
        "verify",
        "quantization-fidelity/evidence/sampled.json",
    ),
    "phase6d-tokenizer-scope": (
        "omiv",
        "tokenizer-config",
        "verify",
        "tokenizer-configuration-parity/evidence/synthetic.json",
    ),
    "phase5-trust-boundary": (
        "omiv",
        "trust",
        "verify",
        "--input",
        "trust/examples/trusted-transformation.signed-envelope.json",
        "--trust-bundle",
        "trust/examples/project-trust-bundle.json",
        "--policy",
        "trust/examples/project-trust-policy.json",
        "--evaluation-context",
        "trust/examples/evaluation-context.json",
    ),
    "phase6e-resolution-receipt": (
        "omiv",
        "runtime-resolution",
        "verify",
        "runtime-resolution-parity/receipts/t0.json",
    ),
    "phase6e-partial-runtime": (
        "omiv",
        "runtime-resolution",
        "verify",
        "runtime-resolution-parity/evidence.json",
    ),
}


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


class AuditError(RuntimeError):
    """A bounded audit failure with no sensitive detail."""


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate-key")
        result[key] = value
    return result


def _safe_file(root: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    current = root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            return None
    try:
        if not current.is_file() or current.stat().st_size > MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    return current


def _text(root: Path, relative: str) -> str:
    path = _safe_file(root, relative)
    if path is None:
        raise AuditError("unsafe-or-missing-r1d-file")
    try:
        return path.read_bytes().decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise AuditError("invalid-r1d-text") from exc


def _manifest(root: Path) -> dict[str, Any]:
    try:
        value = json.loads(_text(root, MANIFEST), object_pairs_hook=_duplicate_keys)
    except (json.JSONDecodeError, AuditError) as exc:
        raise AuditError("invalid-manifest") from exc
    if not isinstance(value, dict):
        raise AuditError("manifest-not-object")
    return value


def _links(text: str) -> tuple[str, ...]:
    return tuple(match.group(1).strip() for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", text))


def _heading_inventory(text: str) -> tuple[str, ...]:
    return tuple(
        match.group(2).strip()
        for line in text.splitlines()
        if (match := re.match(r"^(#{1,6})\s+(.+?)\s*$", line))
    )


def _anchors(text: str) -> set[str]:
    result: set[str] = set()
    occurrences: dict[str, int] = {}
    for heading in _heading_inventory(text):
        value = re.sub(r"<[^>]+>", "", heading).lower()
        value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
        base = re.sub(r"-+", "-", value.replace(" ", "-")).strip("-")
        index = occurrences.get(base, 0)
        occurrences[base] = index + 1
        result.add(base if index == 0 else f"{base}-{index}")
    return result


def _link_failures(root: Path, texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    for source_relative, text in sorted(texts.items()):
        for target in _links(text):
            parsed = urlsplit(target.strip("<>"))
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                continue
            if parsed.scheme or parsed.netloc or parsed.path.startswith("/"):
                failures.append("unsafe-target")
                continue
            joined = posixpath.join(posixpath.dirname(source_relative), unquote(parsed.path))
            normalized = posixpath.normpath(joined)
            if normalized == ".." or normalized.startswith("../"):
                failures.append("repository-escape")
                continue
            target_relative = normalized if parsed.path else source_relative
            target_path = _safe_file(root, target_relative)
            if target_path is None:
                failures.append("missing-target")
                continue
            if (
                parsed.fragment
                and target_relative in texts
                and unquote(parsed.fragment).lower() not in _anchors(texts[target_relative])
            ):
                failures.append("missing-fragment")
    return failures


def _python_imports(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise AuditError("invalid-python") from exc
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    return imports


def _negative_or_detector_line(line: str) -> bool:
    lowered = line.lower()
    return any(
        marker in lowered
        for marker in (
            "not ",
            "no ",
            "does not",
            "never ",
            "forbidden",
            "reject",
            "pattern",
            "assert",
        )
    )


def run_audit(root: Path) -> list[Check]:
    if root.is_symlink() or not root.is_dir():
        raise AuditError("unsafe-root")
    root = root.resolve(strict=True)
    texts = {path: _text(root, path) for path in R1D_PATHS}
    manifest = _manifest(root)
    steps = manifest.get("steps")
    step_list = steps if isinstance(steps, list) else []
    documentation = "\n".join(texts[path] for path in R1D_PATHS if path.endswith(".md"))
    python_source = texts["tools/run_offline_evidence_walkthrough.py"]

    checks: list[Check] = []
    checks.append(Check("r1d_paths", len(texts) == len(R1D_PATHS), f"paths={len(texts)}"))
    over_limit = [path for path in R1D_PATHS if (root / path).stat().st_size > MAX_FILE_BYTES]
    checks.append(Check("bounded_assets", not over_limit, f"over_limit={len(over_limit)}"))

    labels = tuple(manifest.get("labels", []))
    checks.append(
        Check(
            "manifest_labels",
            manifest.get("classification") == "NON_CANONICAL_DEMONSTRATION_MANIFEST"
            and labels
            == (
                "SYNTHETIC",
                "DEMONSTRATION_ONLY",
                "NOT_PROVIDER_EVIDENCE",
                "NOT_AN_ASSURANCE_BUNDLE",
                "NOT_A_SAFETY_OR_AUTHENTICITY_RESULT",
            ),
            "classification_and_labels",
        )
    )
    checks.append(
        Check(
            "manifest_path_inventory",
            tuple(manifest.get("r1d_paths", [])) == R1D_PATHS,
            f"paths={len(manifest.get('r1d_paths', []))}",
        )
    )
    observed_order = tuple(step.get("id") for step in step_list if isinstance(step, dict))
    checks.append(
        Check("deterministic_step_order", observed_order == STEP_ORDER, f"steps={len(step_list)}")
    )
    command_ok = len(step_list) == len(STEP_ORDER)
    if command_ok:
        for step in step_list:
            step_id = step.get("id")
            command_ok = command_ok and tuple(step.get("command", ())) == ALLOWED_COMMANDS.get(
                step_id
            )
    checks.append(Check("fixed_command_allowlist", command_ok, f"commands={len(step_list)}"))
    exits = [step.get("expected_exit") for step in step_list if isinstance(step, dict)]
    checks.append(
        Check(
            "semantic_exit_contract",
            exits.count(0) == 8 and exits.count(1) == 2 and set(exits) == {0, 1},
            f"exit0={exits.count(0)} exit1={exits.count(1)}",
        )
    )

    input_paths = {
        token
        for command in ALLOWED_COMMANDS.values()
        for token in command
        if token.endswith(".json")
    }
    unsafe_inputs = [path for path in sorted(input_paths) if _safe_file(root, path) is None]
    checks.append(
        Check("tracked_input_availability", not unsafe_inputs, f"inputs={len(input_paths)}")
    )
    forbidden_commands = (
        "collect-hf-metadata",
        "remote-snapshot",
        "remote-range-probe",
        "conversion-run",
        "normalize",
        "inspect",
        "sign",
    )
    command_tokens = {token for command in ALLOWED_COMMANDS.values() for token in command}
    checks.append(
        Check(
            "offline_command_surface",
            not command_tokens.intersection(forbidden_commands),
            "network_or_write_commands=0",
        )
    )

    imports = _python_imports(python_source)
    forbidden_imports = imports.intersection(
        {"socket", "urllib", "http", "requests", "httpx", "aiohttp"}
    )
    checks.append(
        Check(
            "runner_network_imports",
            not forbidden_imports,
            f"forbidden={len(forbidden_imports)}",
        )
    )
    checks.append(
        Check(
            "runner_subprocess_safety",
            "shell=False" in python_source
            and "subprocess.Popen" in python_source
            and "selectors.DefaultSelector" in python_source
            and "process.kill()" in python_source
            and "process.wait" in python_source
            and "MAX_PROCESS_OUTPUT_BYTES" in python_source
            and "stdin=subprocess.DEVNULL" in python_source,
            "shell_false_stream_bound_timeout_kill_wait",
        )
    )
    checks.append(
        Check(
            "runner_executable_isolation",
            '[sys.executable, "-I", "-m", "omiv"' in python_source
            and '"PYTHONNOUSERSITE": "1"' in python_source
            and '"PYTHONHASHSEED": "0"' in python_source
            and 'environment["PYTHONPATH"]' not in python_source
            and '"PATH"' not in python_source,
            "current_interpreter_isolated_module_no_path_override",
        )
    )
    checks.append(
        Check(
            "runner_source_identity",
            "EXPECTED_SOURCE_SHA256" in python_source
            and "tracked source identity does not match the audited contract" in python_source
            and "EXPECTED_SCHEMAS" in python_source
            and "command produced unexpected output" in python_source,
            "source_digests_schemas_and_exact_output_pinned",
        )
    )
    checks.append(
        Check(
            "runner_default_read_only",
            "temporary_directory is None" in python_source
            and "default_mode=READ_ONLY" in python_source
            and "TemporaryDirectory" in python_source,
            "temporary_write_requires_explicit_directory",
        )
    )
    checks.append(
        Check(
            "runner_output_sanitization",
            "ANSI_ESCAPE.sub" in python_source
            and "subprocess output contains an absolute machine path" in python_source
            and "subprocess output contains a traceback" in python_source
            and "subprocess output contains a warning" in python_source
            and '.replace(str(repository), ".")' not in python_source,
            "raw_rejection_before_ansi_presentation",
        )
    )
    forbidden_execution = re.search(r"\b(?:eval|exec|os\.system)\s*\(", python_source)
    checks.append(
        Check(
            "runner_no_general_executor",
            forbidden_execution is None
            and "--command" not in python_source
            and "ALLOWED_COMMANDS.values()" in python_source,
            "eval_exec_shell_and_command_override_absent",
        )
    )

    walkthrough = texts["docs/offline-evidence-walkthrough.md"]
    per_step_fields = all(
        walkthrough.count(label) >= 10
        for label in (
            "**Input:**",
            "**Command:**",
            "**Expected exit code:**",
            "**What it establishes:**",
            "**What it does not establish:**",
            "**Next evidence link:**",
        )
    )
    checks.append(Check("per_step_documentation", per_step_fields, "documented_steps=10"))
    boundaries = (
        "declaration != observation",
        "metadata identity != payload identity",
        "artifact identity != runtime-loaded identity",
        "signature validity != publisher authority",
        "policy satisfaction != safety or deployment approval",
        "finite probes != behavioral equivalence",
        "output digest != weight attribution",
        "unavailable evidence != invalid evidence",
        "absent evidence != PASS",
    )
    checks.append(
        Check(
            "semantic_boundaries",
            all(boundary in walkthrough for boundary in boundaries),
            f"required={len(boundaries)}",
        )
    )
    nonclaims = (
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
    )
    normalized_walkthrough = re.sub(r"\s+", " ", walkthrough)
    checks.append(
        Check(
            "explicit_nonclaims",
            all(nonclaim in normalized_walkthrough for nonclaim in nonclaims),
            f"required={len(nonclaims)}",
        )
    )
    checks.append(
        Check(
            "exit_code_documentation",
            all(f"| `{code}` |" in walkthrough for code in (0, 1, 2))
            and "expected semantic result" in walkthrough,
            "exit_codes=0,1,2",
        )
    )
    checks.append(
        Check(
            "kimi_not_available",
            "clean_checkout=NOT_AVAILABLE" in walkthrough
            and "required=NO" in walkthrough
            and "never opened, copied, generated, downloaded, or required" in walkthrough,
            "clean_checkout_not_available",
        )
    )

    markdown_texts = {path: text for path, text in texts.items() if path.endswith(".md")}
    link_failures = _link_failures(root, markdown_texts)
    checks.append(
        Check("r1d_markdown_links", not link_failures, f"invalid_links={len(link_failures)}")
    )
    navigation_targets = (
        "docs/quickstart.md",
        "docs/offline-evidence-walkthrough.md",
        "docs/architecture.md",
        "docs/reference/technical-reference.md",
        "docs/roadmap.md",
    )
    navigation_ok = all(target in documentation for target in navigation_targets)
    checks.append(Check("launch_navigation", navigation_ok, f"targets={len(navigation_targets)}"))

    roadmap = texts["docs/roadmap.md"]
    roadmap_terms = (
        "| R1C launch UX | COMPLETE |",
        "| R1D offline walkthrough | COMPLETE |",
        "| R1E GitHub metadata/security | IMPLEMENTED, RELEASE PENDING |",
        "| R1F final publication audit | PLANNED |",
        "| Phase 6F | PLANNED, NOT IMPLEMENTED |",
    )
    checks.append(
        Check(
            "roadmap_status",
            all(term in roadmap for term in roadmap_terms),
            f"required={len(roadmap_terms)}",
        )
    )
    phase6f_complete = any(
        re.search(r"Phase 6F.{0,30}\b(COMPLETE|IMPLEMENTED)\b", line, re.IGNORECASE)
        and "not implemented" not in line.lower()
        for line in documentation.splitlines()
    )
    checks.append(Check("phase6f_unimplemented", not phase6f_complete, "completion_claims=0"))

    forbidden_claim_patterns = (
        r"repository is (?:now )?public",
        r"available on PyPI",
        r"released v0\.10\.0",
        r"certified (?:safe|secure|authentic)",
        r"runtime[- ]loaded weights (?:are|were) verified",
        r"provider[- ]endorsed",
    )
    claim_matches: list[str] = []
    for line in documentation.splitlines():
        if any(
            re.search(pattern, line, re.IGNORECASE) for pattern in forbidden_claim_patterns
        ) and not _negative_or_detector_line(line):
            claim_matches.append("claim")
    checks.append(Check("release_and_evidence_nonclaims", not claim_matches, "overclaims=0"))

    controls = [
        character
        for text in texts.values()
        for character in text
        if ord(character) < 32 and character not in "\n\r\t"
    ]
    checks.append(Check("hidden_controls", not controls, f"controls={len(controls)}"))
    unsafe_markup = re.search(r"<\s*(script|iframe|object|embed)\b", documentation, re.IGNORECASE)
    remote_exec = re.search(r"\b(curl|wget)\b[^\n]*https?://", documentation, re.IGNORECASE)
    checks.append(
        Check(
            "markdown_and_remote_execution",
            unsafe_markup is None and remote_exec is None,
            "unsafe_markup=0 remote_execution=0",
        )
    )
    credential_patterns = (
        r"gh[oprsu]_[A-Za-z0-9]{20,}",
        r"hf_[A-Za-z0-9]{20,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"Authorization\s*:\s*(?:Bearer|Basic)\s+\S+",
        r"https?://\S+[?&](?:X-Amz-Signature|Signature|token)=",
    )
    credential_hits = sum(
        bool(re.search(pattern, text, re.IGNORECASE))
        for pattern in credential_patterns
        for text in texts.values()
    )
    checks.append(Check("credential_scan", credential_hits == 0, "credential_patterns=0"))
    checks.append(
        Check(
            "audit_fail_closed",
            "except (AuditError, KeyError, OSError, TypeError, UnicodeError, ValueError)"
            in texts["tools/audit_offline_evidence_walkthrough.py"]
            and "AUDIT_ERROR" in texts["tools/audit_offline_evidence_walkthrough.py"],
            "bounded_exception_boundary",
        )
    )
    return checks


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        checks = run_audit(arguments.root)
    except (AuditError, KeyError, OSError, TypeError, UnicodeError, ValueError) as exc:
        print(f"AUDIT_ERROR class={type(exc).__name__}")
        return 2
    for check in checks:
        state = "PASS" if check.passed else "FAIL"
        print(f"{state} {check.name} {check.detail}")
    passed = sum(check.passed for check in checks)
    print(f"PASS_SUMMARY passed={passed} failed={len(checks) - passed} total={len(checks)}")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
