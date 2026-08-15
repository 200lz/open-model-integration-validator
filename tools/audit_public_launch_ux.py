#!/usr/bin/env python3
"""Deterministic, dependency-free audit of OMIV's GitHub launch documentation."""

from __future__ import annotations

import argparse
import json
import posixpath
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
README_MIN_LINES = 250
README_MAX_LINES = 600
MAX_LAUNCH_FILE_BYTES = 1024 * 1024

REQUIRED_HEADINGS = (
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
)
REQUIRED_LINK_TARGETS = (
    "docs/README.md",
    "docs/architecture.md",
    "docs/quickstart.md",
    "docs/public-commercial-boundary.md",
    "docs/roadmap.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "LICENSE",
)
QUICKSTART_INPUT = "runtime-resolution-parity/scenarios/immutable-pinned.json"
QUICKSTART_COMMAND = f"omiv runtime-resolution verify {QUICKSTART_INPUT}"
SYNTHETIC_LABELS = (
    "SYNTHETIC",
    "DEMONSTRATION_ONLY",
    "NOT_PROVIDER_EVIDENCE",
    "NOT_A_SAFETY_OR_AUTHENTICITY_RESULT",
)
HISTORICAL_HEADINGS = (
    "Open Model Integration Validator",
    "Install",
    "Model Passports",
    "Model Chain of Custody ledgers",
    "Core, format adapters, and model packs",
    "Normalize",
    "Validate",
    "Evidence provenance",
    "Limitations",
    "Optional GGUF structural inventories",
    "Deterministic reports and hashes",
    "Output safety",
    "Local Hugging Face Safetensors inventories",
    "Semantic mapping manifests",
    "Conversion provenance and lineage",
    "Conservative conversion capture",
    "Logical target realizations",
    "Pinned remote repository snapshots and bounded Range probes",
    "Incremental remote GGUF v3 headers",
    "Deterministic split GGUF aggregation",
    "Kimi K3 target-side GGUF ontology",
    "Phase 4F-5 grouped semantic mapping",
    "Phase 4F-6 independent validation bundles",
    "Phase 4F-7 cross-quantization structural comparison",
    "Phase 4F evidence-linked publication case study",
    "Artifact acquisition and transformation attestations",
    "Phase 5D: signed attestations and trust roots",
    "Phase 5E: policy decisions, approval, and promotion gates",
    "Governance semantics",
    "Governance schemas",
    "Policy profiles and precedence",
    "Offline governance CLI",
    "Phase 5F: artifact security evidence",
    "Safe inspection boundary",
    "Schemas, policies, and verdicts",
    "Governance, Passport, and custody",
    "Offline security CLI",
    "Phase 5G: deployment and runtime snapshot verification",
    "Phase 5H: historical trust and audit bundles",
    "Phase 6A: local payload integrity",
    "Phase 6B: shard completeness and remote/local reconciliation",
    "Phase 6C: quantization representation and numerical fidelity",
    "Phase 6D: tokenizer and configuration parity",
    "Phase 6E: runtime resolution, deployment binding, and output provenance",
)
QUICKSTART_NONCLAIMS = (
    "a provider request occurred",
    "a live alias was resolved",
    "a deployment was observed",
    "runtime-loaded weights were observed",
    "the selected model produced an inference",
    "provider authenticity was established",
    "publisher authority was established",
    "safety or production readiness was established",
)
LAUNCH_PATHS = (
    "README.md",
    "docs/README.md",
    "docs/architecture.md",
    "docs/quickstart.md",
    "docs/roadmap.md",
    "docs/reference/readme-migration-map.md",
    "docs/reference/technical-reference.md",
    "examples/offline-quickstart/README.md",
    "tools/audit_public_launch_ux.py",
    "tests/test_public_launch_ux.py",
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def _is_safe_regular_file(root: Path, relative: str) -> bool:
    normalized = posixpath.normpath(relative)
    if normalized in ("", ".") or normalized == ".." or normalized.startswith("../"):
        return False
    path = root
    for part in Path(normalized).parts:
        path /= part
        if path.is_symlink():
            return False
    return path.is_file()


def _text(root: Path, relative: str) -> str:
    path = root / relative
    if not _is_safe_regular_file(root, relative):
        raise ValueError(f"unsafe or missing regular file: {relative}")
    if path.stat().st_size > MAX_LAUNCH_FILE_BYTES:
        raise ValueError(f"launch file exceeds size limit: {relative}")
    return path.read_text(encoding="utf-8")


def markdown_links(text: str) -> tuple[str, ...]:
    """Return Markdown link targets without interpreting or fetching them."""

    return tuple(match.group(1).strip() for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", text))


def _github_anchors(text: str) -> set[str]:
    anchors: set[str] = set()
    occurrences: dict[str, int] = {}
    for heading in _heading_inventory(text):
        value = re.sub(r"<[^>]+>", "", heading).lower()
        value = re.sub(r"[^\w\- ]", "", value, flags=re.UNICODE)
        base = re.sub(r"-+", "-", value.replace(" ", "-")).strip("-")
        index = occurrences.get(base, 0)
        occurrences[base] = index + 1
        anchors.add(base if index == 0 else f"{base}-{index}")
    return anchors


def relative_links_are_safe(text: str, source: Path, root: Path) -> tuple[bool, str]:
    failures: list[str] = []
    for raw_target in markdown_links(text):
        parsed = urlsplit(raw_target.strip("<>"))
        if parsed.scheme in ("https", "http") and parsed.netloc:
            continue
        if parsed.scheme or parsed.netloc or parsed.path.startswith("/"):
            failures.append("unsafe-target")
            continue
        try:
            source_relative = source.relative_to(root).as_posix()
        except ValueError:
            failures.append("outside-root")
            continue
        target_path = unquote(parsed.path) or source_relative
        if parsed.path:
            target_path = posixpath.join(posixpath.dirname(source_relative), target_path)
        normalized = posixpath.normpath(target_path)
        if normalized == ".." or normalized.startswith("../"):
            failures.append("outside-root")
            continue
        if not _is_safe_regular_file(root, normalized):
            failures.append("missing-target")
            continue
        if parsed.fragment and (root / normalized).suffix.lower() == ".md":
            target_text = _text(root, normalized)
            if unquote(parsed.fragment) not in _github_anchors(target_text):
                failures.append("missing-fragment")
    return not failures, f"invalid_links={len(failures)}"


def unsafe_machine_paths(text: str) -> tuple[str, ...]:
    patterns = (r"/home/[A-Za-z0-9._-]+/", r"/Users/[A-Za-z0-9._-]+/", r"[A-Za-z]:\\")
    return tuple(pattern for pattern in patterns if re.search(pattern, text))


def affirmative_overclaims(text: str) -> tuple[str, ...]:
    patterns = {
        "released_v0_10_0": (
            r"(?i)\b(?:(?:released|tagged)\s+v?0\.10\.0|"
            r"v?0\.10\.0\s+is\s+(?:released|tagged))\b"
        ),
        "pypi_available": (
            r"(?i)\b(?:(?:available|published)\s+(?:on|to)\s+PyPI|"
            r"PyPI\s+(?:package\s+)?is\s+available)\b"
        ),
        "phase6f_complete": (
            r"(?i)\bPhase\s+6F\s+(?:is\s+)?"
            r"(?:complete|completed|released|implemented)\b"
        ),
    }
    matches: list[str] = []
    for name, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            prefix = text[max(0, match.start() - 80) : match.start()]
            if re.search(r"(?i)(?:\bnot\b|\bnever\b|\bdoes\s+not\s+mean\b)[^.!\n]{0,48}$", prefix):
                continue
            matches.append(name)
            break
    return tuple(matches)


def demo_labels_are_complete(text: str) -> tuple[bool, str]:
    missing = tuple(label for label in SYNTHETIC_LABELS if label not in text)
    return not missing, f"missing_labels={len(missing)}"


def _heading_inventory(text: str) -> tuple[str, ...]:
    return tuple(
        match.group(1).strip()
        for line in text.splitlines()
        if (match := re.match(r"^#{1,6}\s+(.+?)\s*$", line))
    )


def _migration_is_complete(reference: str, migration: str) -> tuple[bool, str]:
    reference_headings = list(_heading_inventory(reference))
    if reference_headings and reference_headings[0] == "OMIV technical reference":
        reference_headings[0] = "Open Model Integration Validator"
    rows: list[tuple[str, str, str]] = []
    for line in migration.splitlines():
        if not line.startswith("|"):
            continue
        cells = tuple(cell.strip() for cell in line.strip("|").split("|"))
        if len(cells) == 3 and cells[0] not in ("Original heading", "---"):
            rows.append(cells)
    row_headings = [row[0] for row in rows]
    dispositions = {
        "RETAIN_IN_README",
        "MOVE_TO_EXISTING_DOCUMENT",
        "MOVE_TO_NEW_REFERENCE_DOCUMENT",
        "ALREADY_DOCUMENTED_ELSEWHERE",
        "REMOVE_AS_OBSOLETE_WITH_JUSTIFICATION",
    }
    missing = [heading for heading in HISTORICAL_HEADINGS if row_headings.count(heading) != 1]
    invalid_rows = [row for row in rows if row[1] not in dispositions or not row[2]]
    preserved = tuple(reference_headings) == HISTORICAL_HEADINGS
    passed = (
        not missing and not invalid_rows and len(rows) == len(HISTORICAL_HEADINGS) and preserved
    )
    return passed, (
        f"baseline_headings={len(HISTORICAL_HEADINGS)} routes={len(rows)} "
        f"invalid_or_duplicate={len(missing) + len(invalid_rows)} "
        f"reference_preserved={str(preserved).lower()}"
    )


def _markdown_structure_is_valid(text: str) -> bool:
    fences = [line for line in text.splitlines() if line.startswith("```")]
    malformed_links = re.search(r"\[[^\]]+\]\([^\n)]*$", text, flags=re.MULTILINE)
    return len(fences) % 2 == 0 and malformed_links is None


def run_audit(root: Path = ROOT) -> list[Check]:
    readme = _text(root, "README.md")
    docs_index = _text(root, "docs/README.md")
    roadmap = _text(root, "docs/roadmap.md")
    quickstart = _text(root, "docs/quickstart.md")
    demo = _text(root, "examples/offline-quickstart/README.md")
    reference = _text(root, "docs/reference/technical-reference.md")
    migration = _text(root, "docs/reference/readme-migration-map.md")
    combined = "\n".join((readme, docs_index, roadmap, quickstart, demo, migration))
    headings = _heading_inventory(readme)
    line_count = len(readme.splitlines())
    links_ok = True
    markdown_ok = True
    invalid_links = 0
    for relative in LAUNCH_PATHS[:8]:
        text = _text(root, relative)
        ok, detail = relative_links_are_safe(text, root / relative, root)
        links_ok &= ok
        markdown_ok &= _markdown_structure_is_valid(text)
        invalid_links += int(detail.split("=", 1)[1])
    migration_ok, migration_detail = _migration_is_complete(reference, migration)
    labels_ok, labels_detail = demo_labels_are_complete(demo)
    mermaid_fences = len(re.findall(r"^```mermaid\s*$", readme, flags=re.MULTILINE))
    all_fences = len(re.findall(r"^```", readme, flags=re.MULTILINE))
    missing_files = [
        relative for relative in LAUNCH_PATHS if not _is_safe_regular_file(root, relative)
    ]
    oversized = [
        relative
        for relative in LAUNCH_PATHS
        if _is_safe_regular_file(root, relative)
        and (root / relative).stat().st_size > MAX_LAUNCH_FILE_BYTES
    ]
    binary_suffixes = {".gif", ".jpg", ".jpeg", ".png", ".webp", ".exe", ".wasm"}
    asset_paths = sorted(
        (*root.glob("*"), *root.glob("docs/**/*"), *root.glob("examples/offline-quickstart/**/*")),
        key=lambda path: path.as_posix(),
    )
    binaries = sorted(
        path.relative_to(root).as_posix()
        for path in asset_paths
        if path.is_file() and path.suffix.lower() in binary_suffixes
    )
    actual_launch_assets = sorted(
        {
            path.relative_to(root).as_posix()
            for path in asset_paths
            if path.is_file() or path.is_symlink()
        }
    )
    declared_and_actual = sorted({*LAUNCH_PATHS, *actual_launch_assets})
    normalized_paths = [posixpath.normpath(path) for path in declared_and_actual]
    unique_paths = set(normalized_paths)
    path_collisions = len(unique_paths) != len(normalized_paths) or len(
        {path.casefold() for path in unique_paths}
    ) != len(unique_paths)
    private_links = [
        target
        for target in markdown_links(combined)
        if "github.com/200lz/open-model-integration-validator" in target
        and "/actions/workflows/ci.yml" not in target
    ]
    remote_executable = re.findall(
        r"(?i)<script|javascript:|data:text/html|curl\s+https?://.*\|", combined
    )
    statuses = (
        "Phase 5 | RELEASED",
        "Phase 6A | RELEASED",
        "Phase 6B | RELEASED",
        "Phase 6C | RELEASED",
        "Phase 6D | RELEASED",
        "Phase 6E | RELEASED",
        "Phase 6F | COMPLETE; NOT RELEASED",
        "Phase 7 | FUTURE, SCOPE NOT FROZEN",
        "R1A readiness | COMPLETE",
        "R1B private clean-clone CI | COMPLETE",
        "R1C launch UX | COMPLETE",
        "R1D offline walkthrough | COMPLETE",
        "R1E GitHub metadata/security | COMPLETE",
        "R1F final publication audit | COMPLETE; public controls verified",
    )
    return [
        Check(
            "required_readme_headings",
            all(item in headings for item in REQUIRED_HEADINGS),
            f"required={len(REQUIRED_HEADINGS)}",
        ),
        Check(
            "readme_length_budget",
            README_MIN_LINES <= line_count <= README_MAX_LINES,
            f"lines={line_count} range={README_MIN_LINES}-{README_MAX_LINES}",
        ),
        Check(
            "ci_badge_target",
            "actions/workflows/ci.yml/badge.svg?branch=main" in readme,
            "workflow=ci.yml branch=main",
        ),
        Check("minimal_badges", readme.count("[![") == 4, f"badges={readme.count('[![')}"),
        Check("relative_documentation_links", links_ok, f"invalid_links={invalid_links}"),
        Check("launch_markdown_structure", markdown_ok, "balanced_fences_and_links"),
        Check(
            "required_link_targets",
            all(target in readme for target in REQUIRED_LINK_TARGETS),
            f"required={len(REQUIRED_LINK_TARGETS)}",
        ),
        Check("launch_files_exist", not missing_files, f"missing={len(missing_files)}"),
        Check(
            "machine_path_safety",
            not unsafe_machine_paths(combined),
            f"matches={len(unsafe_machine_paths(combined))}",
        ),
        Check(
            "release_and_phase_overclaims",
            not affirmative_overclaims(combined),
            f"matches={len(affirmative_overclaims(combined))}",
        ),
        Check(
            "private_only_documentation_links",
            not private_links,
            f"unexpected={len(private_links)}",
        ),
        Check(
            "mermaid_fences",
            mermaid_fences == 1 and all_fences % 2 == 0 and _markdown_structure_is_valid(readme),
            f"mermaid={mermaid_fences} fences={all_fences}",
        ),
        Check(
            "quickstart_input",
            (root / QUICKSTART_INPUT).is_file() and not (root / QUICKSTART_INPUT).is_symlink(),
            QUICKSTART_INPUT,
        ),
        Check(
            "quickstart_command",
            QUICKSTART_COMMAND in readme
            and QUICKSTART_COMMAND in quickstart
            and QUICKSTART_COMMAND in demo,
            "represented=3",
        ),
        Check(
            "quickstart_scoped_meaning",
            all(phrase in quickstart for phrase in QUICKSTART_NONCLAIMS)
            and "means only that strict parsing succeeded" in quickstart,
            f"required_limitations={len(QUICKSTART_NONCLAIMS)}",
        ),
        Check("synthetic_demo_labels", labels_ok, labels_detail),
        Check(
            "roadmap_statuses",
            all(status in roadmap for status in statuses),
            f"required={len(statuses)}",
        ),
        Check("readme_migration", migration_ok, migration_detail),
        Check("launch_file_size", not oversized, f"over_1_mib={len(oversized)}"),
        Check("unexpected_binary_assets", not binaries, f"binaries={len(binaries)}"),
        Check(
            "launch_path_uniqueness",
            not path_collisions,
            f"actual_assets={len(actual_launch_assets)}",
        ),
        Check(
            "remote_executable_content", not remote_executable, f"matches={len(remote_executable)}"
        ),
    ]


def build_report(root: Path = ROOT) -> dict[str, object]:
    checks = run_audit(root)
    passed = all(check.passed for check in checks)
    return {
        "classification": "PASS" if passed else "FAIL",
        "checks": [asdict(check) for check in checks],
        "summary": {
            "failed": sum(not check.passed for check in checks),
            "passed": sum(check.passed for check in checks),
            "total": len(checks),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit deterministic JSON")
    args = parser.parse_args()
    try:
        report = build_report()
    except (OSError, UnicodeError, ValueError):
        print("FAIL launch_audit_input unsafe_or_unreadable")
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for check in report["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"{status} {check['name']} {check['detail']}")
        summary = report["summary"]
        print(
            f"{report['classification']} passed={summary['passed']} "
            f"failed={summary['failed']} total={summary['total']}"
        )
    return 0 if report["classification"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
