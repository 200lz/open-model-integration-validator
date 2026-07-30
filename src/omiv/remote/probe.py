"""Snapshot-bound bounded range and GGUF prefix probes."""

from __future__ import annotations

from urllib.parse import quote

from omiv.errors import OmivInputError
from omiv.remote.models import (
    PrefixProbeReport,
    RangeEvidence,
    RangeProbeReport,
    RemoteFile,
    RemoteFinding,
    RemoteResult,
    RemoteSeverity,
    ReportEnvelope,
    ReportExecution,
    SnapshotEnvelope,
    ValidatedRange,
)
from omiv.remote.paths import validate_remote_path
from omiv.remote.range_client import BoundedRangeClient
from omiv.remote.reporting import report_envelope


def selected_snapshot_file(snapshot: SnapshotEnvelope, path: str) -> RemoteFile:
    safe_path = validate_remote_path(path)
    matches = [item for item in snapshot.snapshot.files if item.path == safe_path]
    if len(matches) != 1:
        raise OmivInputError("requested file is not uniquely present in the snapshot")
    return matches[0]


def resolved_file_url(snapshot: SnapshotEnvelope, path: str) -> str:
    repo = quote(snapshot.snapshot.repository.repo_id, safe="/")
    revision = quote(snapshot.snapshot.repository.resolved_revision, safe="")
    encoded_path = "/".join(quote(component, safe="") for component in path.split("/"))
    return f"https://huggingface.co/{repo}/resolve/{revision}/{encoded_path}"


def _finding(rule_id: str, status: RemoteResult, message: str) -> RemoteFinding:
    return RemoteFinding(
        rule_id=rule_id,
        severity=(
            RemoteSeverity.ERROR if status == RemoteResult.FAIL else RemoteSeverity.INFO
        ),
        status=status,
        message=message,
    )


def _range_evidence(
    snapshot: SnapshotEnvelope,
    file: RemoteFile,
    *,
    offset: int,
    length: int,
    client: BoundedRangeClient,
) -> tuple[RangeEvidence, bytes]:
    result = client.read(
        resolved_file_url(snapshot, file.path),
        offset=offset,
        length=length,
        expected_total_size=file.byte_size,
    )
    evidence = RangeEvidence(
        path=file.path,
        requested_range=ValidatedRange(
            offset=offset,
            length=length,
            end=offset + length - 1,
        ),
        http_status=result.http_status,
        content_range=result.content_range,
        total_artifact_size=result.total_size,
        response_byte_count=len(result.data),
        response_sha256=result.response_sha256,
        etag=result.etag or file.etag or file.oid,
        redirect_count=result.redirect_count,
        provider="huggingface",
        storage=file.storage,
        result=RemoteResult.PASS,
    )
    return evidence, result.data


def range_probe(
    snapshot: SnapshotEnvelope,
    *,
    path: str,
    offset: int,
    length: int,
    client: BoundedRangeClient,
    include_hex_preview: bool = False,
) -> ReportEnvelope:
    if include_hex_preview and length > 16:
        raise OmivInputError("hex preview is limited to ranges of at most 16 bytes")
    file = selected_snapshot_file(snapshot, path)
    evidence, data = _range_evidence(
        snapshot, file, offset=offset, length=length, client=client
    )
    findings = [
        _finding("RANGE-001", RemoteResult.PASS, "HTTPS and provider host policy validated."),
        _finding("RANGE-002", RemoteResult.PASS, "Response body remained within the byte cap."),
        _finding("RANGE-003", RemoteResult.PASS, "Content-Range matched the requested interval."),
        _finding("RANGE-004", RemoteResult.PASS, "Response body length matched the request."),
        _finding("RANGE-005", RemoteResult.PASS, "Content-Range total matched snapshot metadata."),
        _finding(
            "RANGE-006",
            RemoteResult.PASS,
            "Selected response has a bounded cryptographic byte identity.",
        ),
    ]
    report = RangeProbeReport(
        report_schema="omiv.remote-range-probe-report.v1",
        execution=ReportExecution(result=RemoteResult.PASS, exit_code=0),
        snapshot_sha256=snapshot.integrity.sha256,
        repository=snapshot.snapshot.repository,
        evidence=evidence,
        findings=findings,
        hex_preview=data.hex() if include_hex_preview else None,
        limitations=[
            "This probe validates only the requested HTTP byte range.",
            "It does not validate a complete GGUF header or any tensor payload.",
        ],
    )
    return report_envelope(report)


def gguf_prefix_probe(
    snapshot: SnapshotEnvelope,
    *,
    path: str,
    client: BoundedRangeClient,
) -> ReportEnvelope:
    file = selected_snapshot_file(snapshot, path)
    evidence, data = _range_evidence(
        snapshot, file, offset=0, length=8, client=client
    )
    magic_valid = data[:4] == b"GGUF"
    version = int.from_bytes(data[4:8], "little") if magic_valid else None
    status = RemoteResult.PASS if magic_valid else RemoteResult.FAIL
    findings = [
        _finding("RANGE-001", RemoteResult.PASS, "HTTPS and provider host policy validated."),
        _finding("RANGE-002", RemoteResult.PASS, "Exactly eight response bytes were accepted."),
        _finding("RANGE-003", RemoteResult.PASS, "Content-Range matched bytes 0 through 7."),
        _finding("RANGE-004", RemoteResult.PASS, "Response body length was eight bytes."),
        _finding("RANGE-005", RemoteResult.PASS, "Artifact size matched snapshot metadata."),
        _finding(
            "RANGE-006",
            status,
            "GGUF magic and little-endian version prefix are present."
            if magic_valid
            else "The first four bytes do not contain GGUF magic.",
        ),
    ]
    report = PrefixProbeReport(
        report_schema="omiv.remote-gguf-prefix-report.v1",
        execution=ReportExecution(
            result=status,
            exit_code=0 if magic_valid else 1,
        ),
        snapshot_sha256=snapshot.integrity.sha256,
        repository=snapshot.snapshot.repository,
        path=file.path,
        gguf_magic_valid=magic_valid,
        version=version,
        bounded_range_evidence=evidence,
        findings=findings,
        claim="bounded GGUF prefix identity only; no payload claim",
        limitations=[
            "Only bytes 0 through 7 were requested.",
            "Complete metadata, tensors, split headers, and payloads were not inspected.",
        ],
    )
    return report_envelope(report)
