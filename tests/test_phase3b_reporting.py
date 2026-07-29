from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.gguf.compare import compare_gguf_inventories
from omiv.gguf.models import GGUFInventory
from omiv.gguf.policy import load_gguf_policy
from omiv.gguf.reporting import (
    REPORT_SCHEMA_ID,
    ReportResult,
    build_report_envelope,
    inventory_sha256,
    policy_sha256,
    pretty_report_json,
    render_markdown,
    report_integrity_matches,
)
from omiv.safe_write import atomic_write_text

runner = CliRunner()
SOURCE_PATH = Path("fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json")
TARGET_PATH = Path("fixtures/gguf/qwen2_5_0_5b_q8_0.inventory.json")
POLICY_PATH = Path("policies/qwen2_5_0_5b_fp16_to_q8_0.yaml")


def _inventory(path: Path) -> GGUFInventory:
    return GGUFInventory.model_validate_json(path.read_text(encoding="utf-8"))


def _envelope(
    *,
    target: GGUFInventory | None = None,
) -> Any:
    source = _inventory(SOURCE_PATH)
    actual_target = target or _inventory(TARGET_PATH)
    policy = load_gguf_policy(POLICY_PATH)
    comparison = compare_gguf_inventories(source, actual_target, policy)
    return build_report_envelope(source, actual_target, policy, comparison)


def _invoke_diff(*outputs: str) -> Any:
    return runner.invoke(
        app,
        [
            "gguf-diff",
            "--source",
            str(SOURCE_PATH),
            "--target",
            str(TARGET_PATH),
            "--policy",
            str(POLICY_PATH),
            *outputs,
        ],
    )


def test_report_warning_result_summary_and_stable_finding_order() -> None:
    envelope = _envelope()
    assert envelope.report.execution.result == ReportResult.PASS_WITH_WARNINGS
    assert envelope.report.execution.exit_code == 0
    assert envelope.report.summary.model_dump() == {
        "pass_count": 4,
        "warn_count": 1,
        "fail_count": 0,
        "finding_count": 5,
    }
    assert [item.rule_id for item in envelope.report.findings] == [
        "GGUF-DIFF-001",
        "GGUF-DIFF-002",
        "GGUF-DIFF-003",
        "GGUF-DIFF-004",
        "GGUF-DIFF-005",
    ]


def test_report_all_pass_and_fail_results() -> None:
    source = _inventory(SOURCE_PATH)
    target = _inventory(TARGET_PATH).model_copy(
        update={
            "metadata": source.metadata,
            "header": _inventory(TARGET_PATH).header.model_copy(
                update={"metadata_kv_count": len(source.metadata)}
            ),
        }
    )
    assert _envelope(target=target).report.execution.result == ReportResult.PASS
    failed = target.model_copy(
        update={"identity": target.identity.model_copy(update={"architecture": "bad"})}
    )
    envelope = _envelope(target=failed)
    assert envelope.report.execution.result == ReportResult.FAIL
    assert envelope.report.execution.exit_code == 1


def test_canonical_hash_ignores_object_and_file_formatting() -> None:
    raw = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    reformatted = json.loads(json.dumps(raw, indent=7))
    reversed_dict = dict(reversed(list(raw.items())))
    assert canonical_sha256(raw) == canonical_sha256(reformatted)
    assert canonical_sha256(raw) == canonical_sha256(reversed_dict)
    assert inventory_sha256(_inventory(SOURCE_PATH)) == canonical_sha256(raw)


def test_canonical_hash_preserves_list_order_and_rejects_non_finite() -> None:
    assert canonical_sha256([1, 2]) != canonical_sha256([2, 1])
    with pytest.raises(OmivInputError):
        canonical_sha256({"bad": float("nan")})
    with pytest.raises(OmivInputError):
        canonical_sha256({"bad": float("inf")})


def test_policy_semantics_change_digest_and_digest_domains_are_distinct() -> None:
    policy = load_gguf_policy(POLICY_PATH)
    changed = policy.model_copy(update={"unknown_metadata_drift": "fail"})
    assert policy_sha256(policy) != policy_sha256(changed)
    envelope = _envelope()
    digests = {
        envelope.report.source.artifact_sha256,
        envelope.report.source.inventory_sha256,
        envelope.report.policy.policy_sha256,
        envelope.integrity.sha256,
    }
    assert len(digests) == 4


def test_integrity_covers_report_only() -> None:
    envelope = _envelope()
    original = envelope.integrity.sha256
    changed_integrity = envelope.model_copy(
        update={
            "integrity": envelope.integrity.model_copy(update={"sha256": "f" * 64})
        }
    )
    assert canonical_sha256(envelope.report.model_dump(mode="json")) == original
    assert (
        canonical_sha256(changed_integrity.report.model_dump(mode="json")) == original
    )
    assert not report_integrity_matches(changed_integrity)


def test_json_output_is_deterministic_and_machine_neutral(tmp_path: Path) -> None:
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    assert _invoke_diff("--json-output", str(first)).exit_code == 0
    assert _invoke_diff("--json-output", str(second)).exit_code == 0
    assert first.read_bytes() == second.read_bytes()
    text = first.read_text(encoding="utf-8")
    assert str(Path.cwd()) not in text
    assert "timestamp" not in text.lower()
    assert REPORT_SCHEMA_ID in text


def test_malformed_inventory_provenance_leaves_output_unchanged(
    tmp_path: Path,
) -> None:
    source = _inventory(SOURCE_PATH)
    malformed = source.model_copy(
        update={
            "header": source.header.model_copy(
                update={"tensor_count": source.header.tensor_count + 1}
            )
        }
    )
    bad_source = tmp_path / "bad.json"
    bad_source.write_text(malformed.model_dump_json(), encoding="utf-8")
    output = tmp_path / "report.json"
    output.write_text("existing", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "gguf-diff",
            "--source",
            str(bad_source),
            "--target",
            str(TARGET_PATH),
            "--policy",
            str(POLICY_PATH),
            "--json-output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert output.read_text(encoding="utf-8") == "existing"


def test_policy_requires_explicit_identity(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        POLICY_PATH.read_text(encoding="utf-8").replace(
            "policy_id: qwen2.5-0.5b-fp16-to-q8_0\n", ""
        ),
        encoding="utf-8",
    )
    with pytest.raises(OmivInputError, match="explicit"):
        load_gguf_policy(policy)


def test_policy_rejects_duplicate_identity(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        POLICY_PATH.read_text(encoding="utf-8").replace(
            "policy_id: qwen2.5-0.5b-fp16-to-q8_0\n",
            "policy_id: first\npolicy_id: second\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(OmivInputError, match="duplicate mapping key"):
        load_gguf_policy(policy)


def test_markdown_is_deterministic_complete_and_bounded() -> None:
    envelope = _envelope()
    first = render_markdown(envelope)
    assert first == render_markdown(envelope)
    for section in (
        "# Open Model Integration Validator Report",
        "## Result",
        "## Artifacts",
        "## Policy",
        "## Summary",
        "## Findings",
        "## Integrity",
    ):
        assert section in first
    assert "qwen2.context_length" in first
    assert "Accepted transition groups" in first
    transition = next(
        item
        for item in envelope.report.findings
        if item.rule_id == "GGUF-DIFF-004"
    )
    groups = transition.evidence["accepted_transition_groups"]
    assert isinstance(groups, list)
    assert all(len(group["tensor_examples"]) <= 10 for group in groups)


def test_markdown_escapes_control_characters_and_raw_html() -> None:
    envelope = _envelope()
    finding = envelope.report.findings[-1]
    injected = finding.model_copy(
        update={
            "message": "unsafe | *value* <script>alert(1)</script>",
            "evidence": {"value": "<img src=x onerror=alert(1)>"},
        }
    )
    findings = [*envelope.report.findings[:-1], injected]
    report = envelope.report.model_copy(
        update={
            "findings": findings,
            "summary": envelope.report.summary,
        }
    )
    unsafe = envelope.model_copy(update={"report": report})
    markdown = render_markdown(unsafe)
    assert "<script>" not in markdown
    assert "<img" not in markdown
    assert "\\|" in markdown
    assert "\\*" in markdown


def test_cli_json_markdown_and_verify_exit_codes(tmp_path: Path) -> None:
    report_path, markdown_path = tmp_path / "report.json", tmp_path / "report.md"
    result = _invoke_diff(
        "--json-output",
        str(report_path),
        "--markdown-output",
        str(markdown_path),
    )
    assert result.exit_code == 0
    assert report_path.is_file() and markdown_path.is_file()
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 0

    raw = json.loads(report_path.read_text(encoding="utf-8"))
    raw["report"]["findings"][0]["message"] = "changed"
    report_path.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 1

    report_path.write_text("{}", encoding="utf-8")
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 2


def test_report_verify_detects_evidence_hash_and_schema_changes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "report.json"
    path.write_text(pretty_report_json(_envelope()), encoding="utf-8")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["report"]["findings"][0]["evidence"]["required"] = False
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(app, ["report-verify", "--input", str(path)]).exit_code == 1
    raw["report"]["report_schema"] = "omiv.unsupported.v9"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(app, ["report-verify", "--input", str(path)]).exit_code == 2


def test_report_render_command(tmp_path: Path) -> None:
    report_path, markdown_path = tmp_path / "report.json", tmp_path / "report.md"
    report_path.write_text(pretty_report_json(_envelope()), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "report",
            "--input",
            str(report_path),
            "--format",
            "markdown",
            "--output",
            str(markdown_path),
        ],
    )
    assert result.exit_code == 0
    assert markdown_path.read_text(encoding="utf-8") == render_markdown(_envelope())


def test_safe_write_creates_parents_replaces_and_cleans_temps(
    tmp_path: Path,
) -> None:
    output = tmp_path / "nested" / "report.json"
    atomic_write_text(output, "first")
    atomic_write_text(output, "second")
    assert output.read_text(encoding="utf-8") == "second"
    assert list(output.parent.glob(f".{output.name}.*.tmp")) == []


def test_safe_write_failure_preserves_existing_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    output.write_text("existing", encoding="utf-8")

    def fail_replace(source: Path, target: Path) -> None:
        raise OSError("simulated")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OmivInputError):
        atomic_write_text(output, "replacement")
    assert output.read_text(encoding="utf-8") == "existing"
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []


def test_safe_write_rejects_symlink_directory_and_input_collision(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    source.write_text("source", encoding="utf-8")
    symlink = tmp_path / "link.json"
    symlink.symlink_to(source)
    with pytest.raises(OmivInputError, match="symlink"):
        atomic_write_text(symlink, "bad")
    with pytest.raises(OmivInputError, match="regular"):
        atomic_write_text(tmp_path, "bad")
    with pytest.raises(OmivInputError, match="collides"):
        atomic_write_text(source, "bad", forbidden_inputs=(source,))
    assert source.read_text(encoding="utf-8") == "source"
