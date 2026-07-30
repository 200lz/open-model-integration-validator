from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from omiv.cli import app
from omiv.remote.header_reporting import (
    build_header_inventory_envelope,
    build_header_report,
    header_inventory_integrity_matches,
    header_report_integrity_matches,
    load_header_report,
    pretty_header_json,
    render_header_markdown,
)
from omiv.remote.models import (
    RemoteFile,
    RepositoryIdentity,
    RepositoryMetadata,
    RepositorySnapshot,
    SnapshotSelection,
    SnapshotSummary,
    StorageClass,
)
from omiv.remote.reporting import pretty_json, snapshot_envelope
from tests.remote_gguf_helpers import (
    SliceClient,
    build_gguf,
    metadata_entry,
    parse_fixture,
    tensor_descriptor,
)


def fixture_data() -> bytes:
    return build_gguf(
        metadata=[
            metadata_entry("general.alignment", "UINT32", 32),
            metadata_entry("unsafe|key", "STRING", "<value>*"),
        ],
        tensors=[tensor_descriptor("tensor|name", [2, 2], 0, 0)],
    )[0]


def fixture_snapshot(data: bytes) -> object:
    file = RemoteFile(
        path="q/fixture.gguf",
        byte_size=len(data),
        storage=StorageClass.LFS,
        lfs_sha256="b" * 64,
    )
    snapshot = RepositorySnapshot(
        snapshot_schema="omiv.remote-repository-snapshot.v1",
        provider="huggingface",
        repository=RepositoryIdentity(
            repo_id="owner/repo",
            repo_type="model",
            requested_revision="main",
            resolved_revision="a" * 40,
        ),
        repository_metadata=RepositoryMetadata(private=False),
        selection=SnapshotSelection(
            path_prefix="q",
            patterns=["*.gguf"],
            strict_subtree=True,
        ),
        files=[file],
        summary=SnapshotSummary(
            file_count=1,
            total_byte_size=len(data),
            gguf_file_count=1,
            candidate_split_sets=[],
            extra_gguf_files=["q/fixture.gguf"],
        ),
    )
    return snapshot_envelope(snapshot)


def test_inventory_report_determinism_integrity_and_markdown(tmp_path: Path) -> None:
    inventory = parse_fixture(fixture_data()).inventory
    inventory_envelope = build_header_inventory_envelope(inventory)
    report = build_header_report(inventory_envelope)
    assert header_inventory_integrity_matches(inventory_envelope)
    assert header_report_integrity_matches(report)
    assert pretty_header_json(report) == pretty_header_json(
        build_header_report(inventory_envelope)
    )
    assert report.report.inventory_sha256 == inventory_envelope.integrity.sha256
    assert report.report.inventory.parser_policy_sha256 == inventory.parser_policy.digest
    markdown = render_header_markdown(report)
    assert "<value>" not in markdown
    assert "\\|" in markdown
    assert "HEADER\\-008" in markdown

    encoded = pretty_header_json(report)
    for forbidden in (
        "https://",
        "X-Amz-",
        "Authorization",
        "Bearer ",
        "/home/",
        "timestamp",
        "PPPP",
    ):
        assert forbidden not in encoded

    path = tmp_path / "header.report.json"
    path.write_text(encoded, encoding="utf-8")
    loaded = load_header_report(path)
    assert header_report_integrity_matches(loaded)
    raw = json.loads(encoded)
    raw["integrity"]["sha256"] = "f" * 64
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert not header_report_integrity_matches(load_header_report(path))


def test_report_strict_schema_and_reconstructed_findings(tmp_path: Path) -> None:
    report = build_header_report(
        build_header_inventory_envelope(parse_fixture(fixture_data()).inventory)
    )
    raw = report.model_dump(mode="json")
    raw["report"]["unknown"] = True
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    import pytest

    with pytest.raises(Exception, match="unknown"):
        load_header_report(path)

    raw = report.model_dump(mode="json")
    raw["report"]["findings"][0]["status"] = "fail"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(Exception, match="reconstruct"):
        load_header_report(path)


def test_remote_header_cli_and_report_verify_exit_codes(
    tmp_path: Path, monkeypatch: object
) -> None:
    data = fixture_data()
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(pretty_json(fixture_snapshot(data)), encoding="utf-8")
    output = tmp_path / "inventory.json"
    report = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    client = SliceClient(data)
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "omiv.cli.BoundedRangeClient",
        lambda **kwargs: client,
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "remote-gguf-header",
            "--snapshot",
            str(snapshot_path),
            "--file",
            "q/fixture.gguf",
            "--output",
            str(output),
            "--report-output",
            str(report),
            "--markdown-output",
            str(markdown),
            "--max-request-bytes",
            "64",
            "--read-ahead-bytes",
            "64",
        ],
    )
    assert result.exit_code == 0, result.output
    assert output.is_file() and report.is_file() and markdown.is_file()
    assert "PASS remote GGUF header" in result.output
    assert runner.invoke(
        app, ["report-verify", "--input", str(report)]
    ).exit_code == 0

    raw = json.loads(report.read_text(encoding="utf-8"))
    raw["integrity"]["sha256"] = "f" * 64
    report.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(
        app, ["report-verify", "--input", str(report)]
    ).exit_code == 1

    offline = runner.invoke(
        app,
        [
            "remote-gguf-header",
            "--snapshot",
            str(snapshot_path),
            "--file",
            "q/fixture.gguf",
            "--output",
            str(tmp_path / "offline.inventory.json"),
            "--report-output",
            str(tmp_path / "offline.report.json"),
            "--markdown-output",
            str(tmp_path / "offline.md"),
            "--offline",
        ],
    )
    assert offline.exit_code == 2
