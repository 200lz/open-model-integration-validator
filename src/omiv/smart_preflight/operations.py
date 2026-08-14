"""Bounded local discovery and conservative Phase 6F request generation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from omiv.assurance.models import (
    AssuranceDimension,
    AssuranceRequest,
    AssuranceRequirement,
    EvidencePhase,
    VerdictRole,
)
from omiv.assurance.registry import PHASE_SCHEMAS
from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.payload_integrity.paths import validate_portable_path
from omiv.safe_write import atomic_write_text
from omiv.smart_preflight.models import (
    MAX_CANDIDATES,
    MAX_FINDINGS,
    CoverageStatus,
    DimensionCoverage,
    DiscoveryCandidate,
    DiscoveryFinding,
    FindingSeverity,
    SmartCostSummary,
    SmartPreflightIntent,
    SmartPreflightPlan,
    SmartPreflightStatus,
)

MAX_CONTROL_BYTES = 8 * 1024 * 1024
MAX_DISCOVERY_ENTRIES = 10_000
MAX_DISCOVERY_JSON_FILES = 4_096
MAX_DISCOVERY_JSON_BYTES = 256 * 1024 * 1024
MAX_DISCOVERY_MEMBER_BYTES = 64 * 1024 * 1024
MAX_DISCOVERY_DEPTH = 16

_DIMENSION_BY_PHASE = {
    EvidencePhase.PHASE_5: AssuranceDimension.OTHER,
    EvidencePhase.PHASE_6A: AssuranceDimension.STRUCTURE,
    EvidencePhase.PHASE_6B: AssuranceDimension.STRUCTURE,
    EvidencePhase.PHASE_6C: AssuranceDimension.FIDELITY,
    EvidencePhase.PHASE_6D: AssuranceDimension.TOKENIZER_CONFIGURATION,
    EvidencePhase.PHASE_6E: AssuranceDimension.RUNTIME,
}

# Only final, phase-native evidence records are eligible for automatic verdict use.
# Everything else remains visible as supporting evidence and is not auto-selected.
_VERDICT_SCHEMAS = {
    "omiv.payload-integrity-evidence.v1",
    "omiv.remote-local-reconciliation-evidence.v1",
    "omiv.quantization-fidelity-evidence.v1",
    "omiv.tokenizer-configuration-parity-evidence.v1",
    "omiv.runtime-resolution-parity-evidence.v1",
}


@dataclass
class _Counters:
    entries: int = 0
    json_files: int = 0
    json_bytes: int = 0
    limit_exceeded: bool = False


@dataclass(frozen=True)
class _Observed:
    source_path: str
    schema_id: str
    phase: EvidencePhase
    dimension: AssuranceDimension
    verdict_role: VerdictRole
    size: int
    sha256: str


def _pretty(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def load_intent(path: Path) -> SmartPreflightIntent:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return SmartPreflightIntent.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid Smart Preflight intent: {exc}") from exc


def write_plan(plan: SmartPreflightPlan, output: Path) -> None:
    atomic_write_text(output, _pretty(plan))


def write_assurance_request(request: AssuranceRequest, output: Path) -> None:
    atomic_write_text(output, _pretty(request))


def _registry_by_schema() -> dict[str, tuple[EvidencePhase, type[BaseModel]]]:
    result: dict[str, tuple[EvidencePhase, type[BaseModel]]] = {}
    for phase, registry in PHASE_SCHEMAS.items():
        for schema_id, model in registry.items():
            existing = result.get(schema_id)
            if existing is not None and existing != (phase, model):
                raise RuntimeError(f"schema is ambiguous across phases: {schema_id}")
            result[schema_id] = (phase, model)
    return result


def _finding(
    findings: list[DiscoveryFinding],
    code: str,
    severity: FindingSeverity,
    detail: str,
    source_path: str | None = None,
) -> None:
    if len(findings) < MAX_FINDINGS:
        findings.append(
            DiscoveryFinding(
                code=code,
                severity=severity,
                detail=detail[:1000],
                source_path=source_path,
            )
        )


def _portable_relative(root: Path, path: Path) -> str | None:
    try:
        relative = path.relative_to(root).as_posix()
        validate_portable_path(relative)
    except (ValueError, OSError):
        return None
    return relative


def _inspect_json(
    root: Path,
    path: Path,
    registry: dict[str, tuple[EvidencePhase, type[BaseModel]]],
    counters: _Counters,
    findings: list[DiscoveryFinding],
) -> _Observed | None:
    source_path = _portable_relative(root, path)
    if source_path is None:
        _finding(
            findings,
            "UNSAFE_DISCOVERY_PATH",
            FindingSeverity.ERROR,
            "The local path is not portable and was not inspected.",
        )
        return None
    try:
        size = path.stat().st_size
    except OSError as exc:
        _finding(findings, "LOCAL_STAT_FAILED", FindingSeverity.ERROR, str(exc), source_path)
        return None
    counters.json_files += 1
    counters.json_bytes += size
    if counters.json_files > MAX_DISCOVERY_JSON_FILES:
        counters.limit_exceeded = True
        _finding(
            findings,
            "LIMIT_EXCEEDED:DISCOVERY_JSON_FILES",
            FindingSeverity.ERROR,
            "Smart Preflight stopped after reaching its JSON file limit.",
            source_path,
        )
        return None
    if counters.json_bytes > MAX_DISCOVERY_JSON_BYTES:
        counters.limit_exceeded = True
        _finding(
            findings,
            "LIMIT_EXCEEDED:DISCOVERY_JSON_BYTES",
            FindingSeverity.ERROR,
            "Smart Preflight stopped after reaching its cumulative JSON byte limit.",
            source_path,
        )
        return None
    if size > MAX_DISCOVERY_MEMBER_BYTES:
        _finding(
            findings,
            "LIMIT_EXCEEDED:DISCOVERY_MEMBER_BYTES",
            FindingSeverity.WARN,
            "The JSON object exceeds the bounded local discovery member limit.",
            source_path,
        )
        return None
    try:
        value, raw = load_bounded_json(path, max_bytes=MAX_DISCOVERY_MEMBER_BYTES)
    except OmivInputError as exc:
        _finding(findings, "DISCOVERY_JSON_INVALID", FindingSeverity.WARN, str(exc), source_path)
        return None
    if not isinstance(value, dict):
        return None
    schema_id = value.get("schema")
    if not isinstance(schema_id, str):
        return None
    registered = registry.get(schema_id)
    if registered is None:
        if schema_id.startswith("omiv."):
            _finding(
                findings,
                "DISCOVERY_SCHEMA_UNSUPPORTED",
                FindingSeverity.INFO,
                f"No Phase 5/6A-6E Assurance registry entry exists for {schema_id}.",
                source_path,
            )
        return None
    phase, model = registered
    try:
        model.model_validate(value)
    except (ValidationError, ValueError) as exc:
        _finding(
            findings,
            "DISCOVERY_SCHEMA_VALIDATION_FAILED",
            FindingSeverity.WARN,
            f"{schema_id} failed canonical validation: {exc}",
            source_path,
        )
        return None
    role = (
        VerdictRole.DIMENSION_VERDICT
        if schema_id in _VERDICT_SCHEMAS
        else VerdictRole.SUPPORTING
    )
    return _Observed(
        source_path=source_path,
        schema_id=schema_id,
        phase=phase,
        dimension=_DIMENSION_BY_PHASE[phase],
        verdict_role=role,
        size=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _walk(
    root: Path,
    target: Path,
    registry: dict[str, tuple[EvidencePhase, type[BaseModel]]],
    counters: _Counters,
    findings: list[DiscoveryFinding],
    observed: list[_Observed],
    depth: int = 0,
) -> None:
    if counters.limit_exceeded:
        return
    relative = _portable_relative(root, target)
    display_path = relative or target.name
    if target.is_symlink():
        _finding(
            findings,
            "DISCOVERY_SYMLINK_SKIPPED",
            FindingSeverity.WARN,
            "Smart Preflight does not follow local symlinks.",
            relative,
        )
        return
    if target.is_file():
        counters.entries += 1
        if target.suffix == ".json":
            item = _inspect_json(root, target, registry, counters, findings)
            if item is not None:
                observed.append(item)
        return
    if not target.is_dir():
        _finding(
            findings,
            "DISCOVERY_OBJECT_SKIPPED",
            FindingSeverity.WARN,
            "Only regular files and directories are inspected.",
            relative,
        )
        return
    if depth > MAX_DISCOVERY_DEPTH:
        counters.limit_exceeded = True
        _finding(
            findings,
            "LIMIT_EXCEEDED:DISCOVERY_DEPTH",
            FindingSeverity.ERROR,
            f"Discovery depth exceeded at {display_path}.",
            relative,
        )
        return
    try:
        children = sorted(target.iterdir(), key=lambda item: item.name.encode("utf-8"))
    except OSError as exc:
        _finding(findings, "LOCAL_DIRECTORY_READ_FAILED", FindingSeverity.ERROR, str(exc), relative)
        return
    for child in children:
        counters.entries += 1
        if counters.entries > MAX_DISCOVERY_ENTRIES:
            counters.limit_exceeded = True
            _finding(
                findings,
                "LIMIT_EXCEEDED:DISCOVERY_ENTRIES",
                FindingSeverity.ERROR,
                "Smart Preflight stopped after reaching its directory-entry limit.",
                _portable_relative(root, child),
            )
            return
        if child.is_symlink():
            _finding(
                findings,
                "DISCOVERY_SYMLINK_SKIPPED",
                FindingSeverity.WARN,
                "Smart Preflight does not follow local symlinks.",
                _portable_relative(root, child),
            )
            continue
        if child.is_dir():
            _walk(root, child, registry, counters, findings, observed, depth + 1)
        elif child.is_file() and child.suffix == ".json":
            item = _inspect_json(root, child, registry, counters, findings)
            if item is not None:
                observed.append(item)
        if counters.limit_exceeded:
            return


def _resolve_search_path(root: Path, portable_path: str) -> Path:
    target = root if portable_path == "." else root / Path(*portable_path.split("/"))
    cursor = root
    if portable_path != ".":
        for component in portable_path.split("/"):
            cursor /= component
            if cursor.is_symlink():
                raise OmivInputError(
                    f"Smart Preflight search path contains a symlink: {portable_path}"
                )
    resolved = target.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise OmivInputError(f"Smart Preflight search path escapes root: {portable_path}")
    if not target.exists():
        raise OmivInputError(f"Smart Preflight search path does not exist: {portable_path}")
    return target


def _member_path(item: _Observed) -> str:
    return f"evidence/{item.phase.value.lower()}/{item.sha256}.json"


def build_smart_preflight(intent: SmartPreflightIntent, root: Path) -> SmartPreflightPlan:
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("Smart Preflight root must be a regular local directory")
    resolved_root = root.resolve()
    registry = _registry_by_schema()
    counters = _Counters()
    findings: list[DiscoveryFinding] = []
    observed: list[_Observed] = []
    for search_path in intent.search_paths:
        _walk(
            resolved_root,
            _resolve_search_path(resolved_root, search_path),
            registry,
            counters,
            findings,
            observed,
        )
        if counters.limit_exceeded:
            break

    observed.sort(key=lambda item: item.source_path.encode("utf-8"))
    if len(observed) > MAX_CANDIDATES:
        counters.limit_exceeded = True
        observed = observed[:MAX_CANDIDATES]
        _finding(
            findings,
            "LIMIT_EXCEEDED:DISCOVERY_CANDIDATES",
            FindingSeverity.ERROR,
            "Smart Preflight stopped after reaching its validated-candidate limit.",
        )
    verdict_candidates = [
        item for item in observed if item.verdict_role == VerdictRole.DIMENSION_VERDICT
    ]
    desired = (
        list(intent.required_dimensions)
        if intent.required_dimensions
        else sorted({item.dimension for item in verdict_candidates}, key=lambda item: item.value)
    )
    if not desired:
        _finding(
            findings,
            "NO_AUTO_VERDICT_EVIDENCE",
            FindingSeverity.WARN,
            "No final Phase 6A-6E evidence was available for automatic selection.",
        )
    selected_sources: set[str] = set()
    coverage: list[DimensionCoverage] = []
    for dimension in desired:
        dimension_items = [item for item in verdict_candidates if item.dimension == dimension]
        by_digest: dict[str, list[_Observed]] = {}
        for item in dimension_items:
            by_digest.setdefault(item.sha256, []).append(item)
        paths = [item.source_path for item in dimension_items]
        if not dimension_items:
            coverage_status = CoverageStatus.MISSING
            selected_path = None
            _finding(
                findings,
                "REQUIRED_DIMENSION_MISSING",
                FindingSeverity.WARN,
                f"No auto-verdict evidence was discovered for {dimension.value}.",
            )
        elif len(by_digest) > 1:
            coverage_status = CoverageStatus.AMBIGUOUS
            selected_path = None
            _finding(
                findings,
                "VERDICT_CANDIDATE_AMBIGUOUS",
                FindingSeverity.WARN,
                f"Multiple distinct verdict records were discovered for {dimension.value}; "
                "none was selected.",
            )
        else:
            coverage_status = CoverageStatus.COVERED
            selected_path = dimension_items[0].source_path
            selected_sources.add(selected_path)
            if len(dimension_items) > 1:
                _finding(
                    findings,
                    "DUPLICATE_VERDICT_BYTES_DEDUPLICATED",
                    FindingSeverity.INFO,
                    f"Identical {dimension.value} verdict bytes were deduplicated "
                    "deterministically.",
                    selected_path,
                )
        coverage.append(
            DimensionCoverage(
                dimension=dimension,
                status=coverage_status,
                candidate_paths=paths,
                selected_path=selected_path,
            )
        )

    candidates = [
        DiscoveryCandidate(
            source_path=item.source_path,
            schema_id=item.schema_id,
            phase=item.phase,
            dimension=item.dimension,
            proposed_verdict_role=item.verdict_role,
            member_path=_member_path(item),
            size=item.size,
            sha256=item.sha256,
            selected=item.source_path in selected_sources,
            selection_reason=(
                "Unique final evidence record for the requested dimension."
                if item.source_path in selected_sources
                else (
                    "Supporting, duplicate, out-of-scope, or ambiguous evidence was not "
                    "auto-selected."
                )
            ),
        )
        for item in observed
    ]
    selected = [item for item in candidates if item.selected]
    assurance_request: AssuranceRequest | None = None
    if selected:
        assurance_request = AssuranceRequest(
            request_id=f"smart-{intent.intent_id}",
            subject=intent.subject,
            requirements=[
                AssuranceRequirement(
                    member_path=item.member_path,
                    source_path=item.source_path,
                    phase=item.phase,
                    required=True,
                    expected_schema=item.schema_id,
                    dimension=item.dimension,
                    verdict_role=VerdictRole.DIMENSION_VERDICT,
                )
                for item in selected
            ],
            planned_operations=[],
        )
    gaps = any(item.status != CoverageStatus.COVERED for item in coverage)
    if counters.limit_exceeded or not selected:
        plan_status = SmartPreflightStatus.BLOCKED
    elif gaps:
        plan_status = SmartPreflightStatus.READY_WITH_GAPS
    else:
        plan_status = SmartPreflightStatus.READY
    limitations = [
        "Phase 7A is a candidate slice; Phase 7 scope is not frozen.",
        "Discovery is bounded, local, and read-only; it does not download, convert, "
        "contact a remote collector, or use a GPU.",
        "Only unique final Phase 6A-6E evidence records are auto-selected as dimension verdicts.",
        "The generated request remains subject to the unchanged Phase 6F Assurance "
        "preflight and verification semantics.",
    ]
    body: dict[str, Any] = {
        "schema": "omiv.smart-preflight-plan.v1",
        "intent": intent.model_dump(mode="json", by_alias=True),
        "status": plan_status.value,
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "coverage": [item.model_dump(mode="json") for item in coverage],
        "assurance_request": (
            assurance_request.model_dump(mode="json", by_alias=True)
            if assurance_request is not None
            else None
        ),
        "findings": [item.model_dump(mode="json") for item in findings],
        "costs": SmartCostSummary(
            inspected_entries=counters.entries,
            inspected_json_files=counters.json_files,
            inspected_json_bytes=counters.json_bytes,
        ).model_dump(mode="json"),
        "limitations": limitations,
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return SmartPreflightPlan.model_validate(
        {**body, "plan_id": f"smart_plan_{digest[:32]}", "plan_digest": digest}
    )


def concise_plan_summary(plan: SmartPreflightPlan) -> str:
    selected = sum(item.selected for item in plan.candidates)
    gaps = sum(item.status != CoverageStatus.COVERED for item in plan.coverage)
    return (
        f"{plan.status.value} candidates={len(plan.candidates)} selected={selected} "
        f"gaps={gaps} costly=none"
    )
