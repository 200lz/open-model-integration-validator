"""Candidate Phase 7A Smart Preflight / Auto Planner vertical-slice tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from omiv.assurance.models import PreflightStatus, VerdictRole
from omiv.assurance.operations import build_preflight, load_request
from omiv.cli import app
from omiv.smart_preflight.models import (
    CoverageStatus,
    SmartPreflightIntent,
    SmartPreflightStatus,
)
from omiv.smart_preflight.operations import build_smart_preflight

ROOT = Path(__file__).parents[1]
runner = CliRunner()


def _intent(search_paths: list[str], dimensions: list[str]) -> SmartPreflightIntent:
    return SmartPreflightIntent(
        intent_id="phase7a-test",
        subject="synthetic local Phase 7A candidate",
        search_paths=search_paths,
        required_dimensions=dimensions,
    )


def test_tracked_example_generates_phase6f_handoff_without_costly_work() -> None:
    plan = build_smart_preflight(
        _intent(
            ["payload-integrity/evidence/authorized-complete.json"],
            ["STRUCTURE"],
        ),
        ROOT,
    )

    assert plan.status == SmartPreflightStatus.READY
    assert plan.coverage[0].status == CoverageStatus.COVERED
    assert len(plan.candidates) == 1
    assert plan.candidates[0].selected is True
    assert plan.candidates[0].proposed_verdict_role == VerdictRole.DIMENSION_VERDICT
    assert plan.assurance_request is not None
    assert plan.assurance_request.planned_operations == []
    assert not any(
        (
            plan.costs.download,
            plan.costs.network,
            plan.costs.conversion,
            plan.costs.remote_collector,
            plan.costs.gpu,
        )
    )

    assurance_plan = build_preflight(plan.assurance_request, ROOT)
    assert assurance_plan.status == PreflightStatus.READY
    # Phase 7A does not extend the Phase 6F semantic-value allowlist or promote a
    # canonical-but-unrecognized outcome to PASS.
    assert assurance_plan.members[0].semantic_status.value == "UNKNOWN"


def test_cli_vertical_slice_writes_request_consumed_by_unchanged_assurance_plan(
    tmp_path: Path,
) -> None:
    smart_plan = tmp_path / "smart-plan.json"
    assurance_request = tmp_path / "assurance-request.json"
    result = runner.invoke(
        app,
        [
            "smart-preflight",
            "plan",
            "--intent",
            str(ROOT / "examples/smart-preflight/intent.json"),
            "--root",
            str(ROOT),
            "--output",
            str(smart_plan),
            "--assurance-request-output",
            str(assurance_request),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "READY candidates=1 selected=1 gaps=0 costly=none" in result.stdout

    request = load_request(assurance_request)
    assert request.schema_id == "omiv.assurance-request.v1"
    assert request.requirements[0].source_path == (
        "payload-integrity/evidence/authorized-complete.json"
    )
    phase6f_plan = tmp_path / "assurance-plan.json"
    handoff = runner.invoke(
        app,
        [
            "assurance",
            "plan",
            "--request",
            str(assurance_request),
            "--root",
            str(ROOT),
            "--output",
            str(phase6f_plan),
        ],
    )
    assert handoff.exit_code == 0, handoff.output
    assert handoff.stdout.startswith("READY ")


def test_distinct_verdict_candidates_are_ambiguous_and_not_auto_selected() -> None:
    first = build_smart_preflight(
        _intent(["quantization-fidelity/evidence"], ["FIDELITY"]), ROOT
    )
    second = build_smart_preflight(
        _intent(["quantization-fidelity/evidence"], ["FIDELITY"]), ROOT
    )

    assert first == second
    assert first.status == SmartPreflightStatus.BLOCKED
    assert first.coverage[0].status == CoverageStatus.AMBIGUOUS
    assert first.assurance_request is None
    assert not any(item.selected for item in first.candidates)
    assert "VERDICT_CANDIDATE_AMBIGUOUS" in {item.code for item in first.findings}


def test_invalid_canonical_object_is_reported_without_becoming_evidence(tmp_path: Path) -> None:
    source = ROOT / "payload-integrity/evidence/authorized-complete.json"
    value = json.loads(source.read_text(encoding="utf-8"))
    value["outcome"] = "NOT_A_CANONICAL_OUTCOME"
    (tmp_path / "invalid.json").write_text(json.dumps(value), encoding="utf-8")

    plan = build_smart_preflight(_intent(["invalid.json"], ["STRUCTURE"]), tmp_path)

    assert plan.status == SmartPreflightStatus.BLOCKED
    assert plan.candidates == []
    assert plan.assurance_request is None
    assert {item.code for item in plan.findings} >= {
        "DISCOVERY_SCHEMA_VALIDATION_FAILED",
        "REQUIRED_DIMENSION_MISSING",
    }


def test_phase7b_candidate_evidence_is_not_auto_selected(tmp_path: Path) -> None:
    (tmp_path / "runtime-compatibility.json").write_text(
        json.dumps({"schema": "omiv.runtime-compatibility-evidence.v1"}),
        encoding="utf-8",
    )

    plan = build_smart_preflight(_intent(["."], ["RUNTIME"]), tmp_path)

    assert plan.status == SmartPreflightStatus.BLOCKED
    assert plan.candidates == []
    assert plan.assurance_request is None
    assert {item.code for item in plan.findings} >= {
        "DISCOVERY_SCHEMA_UNSUPPORTED",
        "REQUIRED_DIMENSION_MISSING",
    }


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes((ROOT / "payload-integrity/evidence/authorized-complete.json").read_bytes())
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    plan = build_smart_preflight(_intent(["."], ["STRUCTURE"]), tmp_path)

    assert plan.status == SmartPreflightStatus.READY
    assert len(plan.candidates) == 1
    assert plan.candidates[0].source_path == "target.json"
    assert "DISCOVERY_SYMLINK_SKIPPED" in {item.code for item in plan.findings}


def test_discovery_limit_blocks_partial_auto_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = (ROOT / "payload-integrity/evidence/authorized-complete.json").read_bytes()
    (tmp_path / "a.json").write_bytes(raw)
    (tmp_path / "b.json").write_bytes(raw)
    monkeypatch.setattr("omiv.smart_preflight.operations.MAX_DISCOVERY_JSON_FILES", 1)

    plan = build_smart_preflight(_intent(["."], ["STRUCTURE"]), tmp_path)

    assert plan.status == SmartPreflightStatus.BLOCKED
    assert plan.costs.download is False
    assert "LIMIT_EXCEEDED:DISCOVERY_JSON_FILES" in {item.code for item in plan.findings}


def test_cli_refuses_to_overwrite_discovered_evidence() -> None:
    evidence = ROOT / "payload-integrity/evidence/authorized-complete.json"
    before = evidence.read_bytes()
    result = runner.invoke(
        app,
        [
            "smart-preflight",
            "plan",
            "--intent",
            str(ROOT / "examples/smart-preflight/intent.json"),
            "--root",
            str(ROOT),
            "--output",
            str(evidence),
        ],
    )

    assert result.exit_code == 2
    assert "collides with an input path" in result.output
    assert evidence.read_bytes() == before
