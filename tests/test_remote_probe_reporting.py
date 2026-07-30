from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from typer.testing import CliRunner

from omiv.cli import app
from omiv.remote.models import (
    RemoteFile,
    RepositoryIdentity,
    RepositoryMetadata,
    RepositorySnapshot,
    SnapshotSelection,
    SnapshotSummary,
    StorageClass,
)
from omiv.remote.probe import gguf_prefix_probe, range_probe
from omiv.remote.range_client import BoundedRangeClient
from omiv.remote.reporting import (
    build_snapshot_report,
    load_remote_report,
    pretty_json,
    render_markdown,
    report_integrity_matches,
    snapshot_envelope,
)
from omiv.remote.split import detect_split_candidates


class Response:
    status = 206

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.position = 0
        self.headers = {
            "Content-Range": "bytes 0-7/100",
            "Content-Length": "8",
            "ETag": '"safe"',
        }

    def read(self, amount: int = -1) -> bytes:
        assert amount >= 0
        value = self.body[self.position : self.position + amount]
        self.position += len(value)
        return value

    def close(self) -> None:
        return None


class Transport:
    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies
        self.calls = 0

    def request(
        self, url: str, *, headers: Mapping[str, str], timeout: float
    ) -> Response:
        self.calls += 1
        return Response(self.bodies.pop(0))


def envelope() -> object:
    paths = [f"q/m-{item:05d}-of-00002.gguf" for item in (1, 2)]
    candidates, extras = detect_split_candidates(paths)
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
            path_prefix="q", patterns=["*.gguf"], strict_subtree=True
        ),
        files=[
            RemoteFile(
                path=path,
                byte_size=100,
                storage=StorageClass.XET,
                xet_hash=f"xet-{index}",
            )
            for index, path in enumerate(paths)
        ],
        summary=SnapshotSummary(
            file_count=2,
            total_byte_size=200,
            gguf_file_count=2,
            candidate_split_sets=candidates,
            extra_gguf_files=extras,
        ),
    )
    return snapshot_envelope(snapshot)


def test_range_and_prefix_reports_do_not_store_raw_bytes_or_urls() -> None:
    snapshot = envelope()
    transport = Transport([b"GGUF\x03\x00\x00\x00"])
    client = BoundedRangeClient(transport=transport, max_response_bytes=8)
    report = range_probe(
        snapshot,
        path="q/m-00001-of-00002.gguf",
        offset=0,
        length=8,
        client=client,
    )
    encoded = pretty_json(report)
    assert "47475546" not in encoded
    assert "resolve/" not in encoded
    assert "X-Amz" not in encoded
    assert report_integrity_matches(report)

    prefix_transport = Transport([b"GGUF\x03\x00\x00\x00"])
    prefix = gguf_prefix_probe(
        snapshot,
        path="q/m-00001-of-00002.gguf",
        client=BoundedRangeClient(
            transport=prefix_transport,
            max_response_bytes=8,
        ),
    )
    assert prefix.report.gguf_magic_valid
    assert prefix.report.version == 3
    assert prefix_transport.calls == 1
    assert "47475546" not in pretty_json(prefix)


def test_bad_magic_fails_without_second_request_and_truncated_prefix_fails() -> None:
    snapshot = envelope()
    transport = Transport([b"NOPE\x03\x00\x00\x00", b"unused!!!"])
    report = gguf_prefix_probe(
        snapshot,
        path="q/m-00001-of-00002.gguf",
        client=BoundedRangeClient(transport=transport, max_response_bytes=8),
    )
    assert report.report.execution.exit_code == 1
    assert not report.report.gguf_magic_valid
    assert report.report.version is None
    assert transport.calls == 1

    short = Transport([b"GGUF"])
    short_response_client = BoundedRangeClient(
        transport=short,
        max_response_bytes=8,
    )
    import pytest

    with pytest.raises(RuntimeError, match="length"):
        gguf_prefix_probe(
            snapshot,
            path="q/m-00001-of-00002.gguf",
            client=short_response_client,
        )


def test_reports_are_deterministic_escaped_and_tamper_detected(tmp_path: Path) -> None:
    snapshot = envelope()
    report = build_snapshot_report(snapshot)
    assert pretty_json(report) == pretty_json(build_snapshot_report(snapshot))
    markdown = render_markdown(report)
    assert "\\|" not in markdown  # ordinary evidence has no unsafe pipe
    unsafe = report.model_copy(deep=True)
    unsafe.report.findings[0].message = "<script>|*"
    escaped = render_markdown(unsafe)
    assert "<script>" not in escaped
    assert "\\|" in escaped and "\\*" in escaped
    assert "/home/" not in pretty_json(report)
    assert "token" not in pretty_json(report).lower()
    assert "timestamp" not in pretty_json(report).lower()

    path = tmp_path / "report.json"
    path.write_text(pretty_json(report), encoding="utf-8")
    loaded = load_remote_report(path)
    assert report_integrity_matches(loaded)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["report"]["summary"]["file_count"] = 7
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert not report_integrity_matches(load_remote_report(path))


def test_remote_cli_offline_and_report_exit_codes(tmp_path: Path) -> None:
    runner = CliRunner()
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(pretty_json(envelope()), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "remote-range-probe",
            "--snapshot",
            str(snapshot_path),
            "--file",
            "q/m-00001-of-00002.gguf",
            "--offset",
            "0",
            "--length",
            "8",
            "--output",
            str(tmp_path / "probe.json"),
            "--offline",
        ],
    )
    assert result.exit_code == 2
    assert "cannot run with --offline" in result.output

    report_path = tmp_path / "report.json"
    report_path.write_text(
        pretty_json(build_snapshot_report(envelope())),
        encoding="utf-8",
    )
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 0
    raw = json.loads(report_path.read_text(encoding="utf-8"))
    raw["integrity"]["sha256"] = "f" * 64
    report_path.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(
        app, ["report-verify", "--input", str(report_path)]
    ).exit_code == 1

    bad_input = tmp_path / "bad.json"
    bad_input.write_text("{}", encoding="utf-8")
    assert runner.invoke(
        app, ["report-verify", "--input", str(bad_input)]
    ).exit_code == 2
