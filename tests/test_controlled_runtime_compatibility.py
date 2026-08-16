"""Phase 7B.3 controlled loopback runtime profile tests."""

from __future__ import annotations

import base64
import copy
import errno
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

import pytest
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.hf import json_loader
from omiv.runtime_compatibility.controlled_models import (
    ControlledEvidence,
    ControlledPlan,
    ControlledRequest,
    build_controlled_invocation,
    controlled_image_completion_request_bytes,
)
from omiv.runtime_compatibility.controlled_operations import _http_exchange
from omiv.runtime_compatibility.operations import (
    _CONTAINMENT_CAPTURE_MAGIC,
    MAX_RUNTIME_COMPAT_EVIDENCE_BYTES,
    MAX_RUNTIME_COMPAT_PLAN_BYTES,
    MAX_RUNTIME_COMPAT_REQUEST_BYTES,
    _ContainedProcess,
    _receive_capture_frame,
    _receive_containment_message,
    _require_containment_eof,
    build_plan,
    execute_plan,
    load_evidence,
    load_plan,
    load_request,
    write_evidence,
)

ROOT = Path(__file__).parents[1]
REQUEST = ROOT / "examples/runtime-compatibility/controlled-request.json"
RUNNER = CliRunner()


def _rehash(value: dict[str, object]) -> None:
    body = {
        key: item for key, item in value.items() if key not in {"evidence_id", "evidence_digest"}
    }
    digest = canonical_sha256({"domain": value["schema"], "body": body})
    value["evidence_id"] = f"controlled_runtime_evidence_{digest[:32]}"
    value["evidence_digest"] = digest


def _rehash_plan(value: dict[str, object]) -> None:
    body = {key: item for key, item in value.items() if key not in {"plan_id", "plan_digest"}}
    digest = canonical_sha256({"domain": value["schema"], "body": body})
    value["plan_id"] = f"controlled_runtime_plan_{digest[:32]}"
    value["plan_digest"] = digest


def _replace_response(exchange: dict[str, object], raw: bytes) -> None:
    digest = hashlib.sha256(raw).hexdigest()
    body = exchange["response_body"]
    assert isinstance(body, dict)
    body.update(
        {
            "captured_base64": base64.b64encode(raw).decode(),
            "captured_bytes": len(raw),
            "captured_sha256": digest,
        }
    )
    exchange["response_digest"] = digest


def _replace_request(exchange: dict[str, object], raw: bytes) -> None:
    digest = hashlib.sha256(raw).hexdigest()
    body = exchange["request_body"]
    assert isinstance(body, dict)
    body.update(
        {
            "captured_base64": base64.b64encode(raw).decode(),
            "captured_bytes": len(raw),
            "captured_sha256": digest,
        }
    )
    exchange["request_digest"] = digest


def _replace_capture(capture: dict[str, object], raw: bytes) -> None:
    capture.update(
        {
            "captured_base64": base64.b64encode(raw).decode(),
            "captured_bytes": len(raw),
            "captured_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )


@pytest.fixture(scope="module")
def evidence() -> ControlledEvidence:
    request = load_request(REQUEST)
    plan = build_plan(request, ROOT)
    result = execute_plan(plan, ROOT)
    assert isinstance(result, ControlledEvidence)
    return result


def test_four_probe_profile_derives_every_stage_and_scoped_verdict(
    evidence: ControlledEvidence,
) -> None:
    assert evidence.status.value == "VERIFIED_WITHIN_PROFILE"
    assert [item.status.value for item in evidence.stages] == ["PASS"] * 5
    assert [item.probe_id for item in evidence.probes] == [
        "text-without-dflash",
        "image-without-dflash",
        "text-with-dflash",
        "image-with-dflash",
    ]
    assert [item.dflash.active for item in evidence.probes] == [False, False, True, True]
    assert all(item.dflash.draft_tokens > 0 for item in evidence.probes if item.dflash.active)
    assert [item.use_dflash for item in evidence.servers] == [False, True]
    assert all(item.backend.backend.value == "SYNTHETIC" for item in evidence.probes)
    assert [item.boundary for item in evidence.rehash_boundaries] == [
        "PRE_START",
        "POST_READY",
        "POST_PROBES",
        "POST_SHUTDOWN",
    ]
    assert evidence.work_boundary.cleanup_complete
    assert not evidence.work_boundary.unexpected
    processes = [evidence.version_execution, *(item.process for item in evidence.servers)]
    assert all(item.containment is not None for item in processes)
    assert all(item.containment.cleanup_complete for item in processes if item.containment)
    assert all(
        item.containment.descendants_remaining == 0 for item in processes if item.containment
    )
    assert all(item.containment.streams_eof for item in processes if item.containment)
    assert all(
        item.containment.stable_identity == "PID_NAMESPACE_INIT_PIDFD"
        for item in processes
        if item.containment
    )


def test_repeated_generation_is_byte_identical(evidence: ControlledEvidence) -> None:
    second = execute_plan(build_plan(load_request(REQUEST), ROOT), ROOT)
    assert second.model_dump_json(by_alias=True) == evidence.model_dump_json(by_alias=True)


def test_offline_load_executes_nothing(
    evidence: ControlledEvidence, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence.model_dump(mode="json", by_alias=True)), encoding="utf-8")

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline verification must execute and open nothing")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    assert load_evidence(path) == evidence


def _padded_json(value: object, maximum: int) -> bytes:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    assert len(raw) <= maximum
    return raw + b" " * (maximum - len(raw))


def _maximum_controlled_evidence(evidence: ControlledEvidence) -> ControlledEvidence:
    mebibyte = 1024 * 1024
    plan_value = evidence.plan.model_dump(mode="json", by_alias=True)
    request_value = plan_value["request"]
    request_value["limits"].update(
        {
            "max_request_bytes": 4 * mebibyte,
            "max_response_bytes": 4 * mebibyte,
            "max_stdout_bytes": 16 * mebibyte,
            "max_stderr_bytes": 4 * mebibyte,
        }
    )
    base_probes = request_value["probes"]
    request_probes: list[dict[str, object]] = []
    probe_sources: list[dict[str, object]] = []
    for repetition in range(4):
        for source_request, source_observation in zip(base_probes, evidence.probes, strict=True):
            probe = copy.deepcopy(source_request)
            probe["probe_id"] = f"{source_request['probe_id']}-{repetition}"
            probe["expected_content"] = "z" * mebibyte
            request_probes.append(probe)
            probe_sources.append(source_observation.model_dump(mode="json"))
    request_value["probes"] = request_probes
    request = ControlledRequest.model_validate(request_value)
    invocation = build_controlled_invocation(request)
    request_dump = request.model_dump(mode="json", by_alias=True)
    request_digest = canonical_sha256({"domain": request.schema_id, "body": request_dump})
    plan_body = {
        key: item for key, item in plan_value.items() if key not in {"plan_id", "plan_digest"}
    }
    plan_body.update(
        {
            "request": request_dump,
            "request_digest": request_digest,
            "invocation": invocation.model_dump(mode="json"),
        }
    )
    plan_digest = canonical_sha256({"domain": plan_body["schema"], "body": plan_body})
    plan = ControlledPlan.model_validate(
        {
            **plan_body,
            "plan_id": f"controlled_runtime_plan_{plan_digest[:32]}",
            "plan_digest": plan_digest,
        }
    )

    observations: list[dict[str, object]] = []
    request_limit = request.limits.max_request_bytes
    response_limit = request.limits.max_response_bytes
    for probe, source in zip(request.probes, probe_sources, strict=True):
        observation = copy.deepcopy(source)
        observation["probe_id"] = probe.probe_id
        observation["predicate_matched"] = True
        for name in ("tokenize", "completion"):
            exchange = observation[name]
            request_body = exchange["request_body"]
            response_body = exchange["response_body"]
            request_body["limit_bytes"] = request_limit
            response_body["limit_bytes"] = response_limit
            request_json = json.loads(base64.b64decode(request_body["captured_base64"]))
            response_json = json.loads(base64.b64decode(response_body["captured_base64"]))
            if name == "completion":
                response_json["content"] = probe.expected_content
            _replace_request(exchange, _padded_json(request_json, request_limit))
            _replace_response(exchange, _padded_json(response_json, response_limit))
        content = observation["content"]
        content["limit_bytes"] = response_limit
        _replace_capture(content, probe.expected_content.encode("utf-8"))
        observations.append(observation)

    value = evidence.model_dump(mode="json", by_alias=True)
    servers = value["servers"]
    for server, planned in zip(servers, invocation.servers, strict=True):
        server["probe_ids"] = planned.probe_ids
        server["process"]["arguments"] = planned.arguments
        readiness = server["readiness"]
        readiness["request_body"]["limit_bytes"] = request_limit
        readiness["response_body"]["limit_bytes"] = response_limit
        readiness_json = json.loads(base64.b64decode(readiness["response_body"]["captured_base64"]))
        _replace_response(readiness, _padded_json(readiness_json, response_limit))
        stdout = b"s" * request.limits.max_stdout_bytes
        stderr = b"e" * request.limits.max_stderr_bytes
        _replace_capture(server["process"]["stdout"], stdout)
        _replace_capture(server["process"]["stderr"], stderr)
        server["process"]["stdout"]["limit_bytes"] = request.limits.max_stdout_bytes
        server["process"]["stderr"]["limit_bytes"] = request.limits.max_stderr_bytes
        containment = server["process"]["containment"]
        containment["stdout_observed_bytes"] = len(stdout)
        containment["stderr_observed_bytes"] = len(stderr)
    value["version_execution"]["stdout"]["limit_bytes"] = request.limits.max_stdout_bytes
    value["version_execution"]["stderr"]["limit_bytes"] = request.limits.max_stderr_bytes
    value["plan"] = plan.model_dump(mode="json", by_alias=True)
    value["request_digest"] = plan.request_digest
    value["plan_id"] = plan.plan_id
    value["plan_digest"] = plan.plan_digest
    value["servers"] = servers
    value["probes"] = observations
    value["stages"][4]["basis"] = (
        "Profile-owned EXACT_UTF8 predicates matched 16/16 mandatory probes."
    )
    _rehash(value)
    return ControlledEvidence.model_validate(value)


def test_full_schema_limit_evidence_write_load_verify_round_trip(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    maximum = _maximum_controlled_evidence(evidence)
    path = tmp_path / "full-schema-limit-evidence.json"
    write_evidence(maximum, path)
    measured = path.stat().st_size
    print(f"FULL_SCHEMA_LIMIT_EVIDENCE_BYTES={measured}")
    assert measured > 64 * 1024 * 1024
    assert measured < MAX_RUNTIME_COMPAT_EVIDENCE_BYTES
    loaded = load_evidence(path)
    assert loaded.status.value == "VERIFIED_WITHIN_PROFILE"
    assert len(loaded.probes) == 16
    assert all(len(item.plan.request.probes) == 16 for item in [loaded])
    assert all(
        item.process.stdout.captured_bytes == 16 * 1024 * 1024
        and item.process.stderr.captured_bytes == 4 * 1024 * 1024
        for item in loaded.servers
    )
    with pytest.raises(OmivInputError, match="exceeds byte limit"):
        load_request(path)
    path.unlink()


def test_bounded_loader_exact_limit_uses_fixed_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limit = 2 * json_loader._JSON_READ_CHUNK_BYTES + 31
    prefix = b'{"value":"'
    suffix = b'"}'
    payload = prefix + b"x" * (limit - len(prefix) - len(suffix)) + suffix
    path = tmp_path / "exact-limit.json"
    path.write_bytes(payload)
    real_read = os.read
    requests: list[int] = []
    observed = 0

    def bounded_read(descriptor: int, count: int) -> bytes:
        nonlocal observed
        requests.append(count)
        chunk = real_read(descriptor, count)
        observed += len(chunk)
        assert observed <= limit
        return chunk

    monkeypatch.setattr(json_loader.os, "read", bounded_read)
    value, raw = json_loader.load_bounded_json(path, max_bytes=limit)
    assert value == {"value": "x" * (limit - len(prefix) - len(suffix))}
    assert raw == payload
    assert len(requests) >= 4
    assert max(requests) == json_loader._JSON_READ_CHUNK_BYTES
    assert requests[-1] == 1


@pytest.mark.parametrize("size_factor", [1, 128])
def test_bounded_loader_known_oversize_never_reads_or_allocates_from_reported_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size_factor: int,
) -> None:
    limit = 4096
    size = limit + 1 if size_factor == 1 else limit * size_factor
    path = tmp_path / "oversize.json"
    with path.open("wb") as handle:
        handle.seek(size - 1)
        handle.write(b"x")

    def forbidden_read(_descriptor: int, _count: int) -> bytes:
        raise AssertionError("known oversized input must be rejected before reading")

    monkeypatch.setattr(json_loader.os, "read", forbidden_read)
    with pytest.raises(OmivInputError, match="exceeds byte limit"):
        json_loader.load_bounded_json(path, max_bytes=limit)
    path.unlink()


def test_bounded_loader_growth_after_fstat_observes_only_limit_plus_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limit = 2 * json_loader._JSON_READ_CHUNK_BYTES + 17
    path = tmp_path / "growing.json"
    path.write_bytes(b"{}")
    real_fstat = os.fstat
    real_read = os.read
    fstat_calls = 0
    requests: list[int] = []
    retained_observation = 0

    def grow_after_fstat(descriptor: int) -> os.stat_result:
        nonlocal fstat_calls
        snapshot = real_fstat(descriptor)
        fstat_calls += 1
        if fstat_calls == 1:
            with path.open("ab") as handle:
                handle.write(b"x" * (4 * limit))
        return snapshot

    def tracked_read(descriptor: int, count: int) -> bytes:
        nonlocal retained_observation
        requests.append(count)
        chunk = real_read(descriptor, count)
        retained_observation += len(chunk)
        assert retained_observation <= limit + 1
        return chunk

    monkeypatch.setattr(json_loader.os, "fstat", grow_after_fstat)
    monkeypatch.setattr(json_loader.os, "read", tracked_read)
    with pytest.raises(OmivInputError, match="exceeds byte limit"):
        json_loader.load_bounded_json(path, max_bytes=limit)
    assert retained_observation == limit + 1
    assert max(requests) <= json_loader._JSON_READ_CHUNK_BYTES
    path.unlink()


def test_bounded_loader_path_swap_after_open_cannot_substitute_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "candidate.json"
    saved = tmp_path / "opened.json"
    original = b'{"source":"opened-descriptor"}'
    replacement = b'{"source":"replacement-path"}'
    path.write_bytes(original)
    real_open = os.open
    swapped = False
    open_calls = 0

    def swap_after_open(candidate: os.PathLike[str] | str, flags: int) -> int:
        nonlocal open_calls, swapped
        descriptor = real_open(candidate, flags)
        if Path(candidate) == path:
            open_calls += 1
            if not swapped:
                path.rename(saved)
                path.write_bytes(replacement)
                swapped = True
        return descriptor

    monkeypatch.setattr(json_loader.os, "open", swap_after_open)
    try:
        value, raw = json_loader.load_bounded_json(path, max_bytes=1024)
        assert value == {"source": "opened-descriptor"}
        assert raw == original
        assert path.read_bytes() == replacement
        assert open_calls == 1
    finally:
        path.unlink(missing_ok=True)
        saved.rename(path)


def test_bounded_loader_rejects_same_size_in_place_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "mutated.json"
    payload = b'{"value":"' + b"x" * json_loader._JSON_READ_CHUNK_BYTES + b'"}'
    path.write_bytes(payload)
    real_read = os.read
    mutated = False

    def mutate_after_first_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = real_read(descriptor, count)
        if chunk and not mutated:
            before = path.stat()
            with path.open("r+b") as handle:
                handle.seek(len(payload) - 3)
                handle.write(b"y")
            os.utime(
                path,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )
            mutated = True
        return chunk

    monkeypatch.setattr(json_loader.os, "read", mutate_after_first_read)
    with pytest.raises(OmivInputError, match="changed during bounded read"):
        json_loader.load_bounded_json(path, max_bytes=len(payload))
    assert mutated


@pytest.mark.parametrize("failure", ["truncate", "premature-eof"])
def test_bounded_loader_rejects_truncation_and_incoherent_short_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    path = tmp_path / "short.json"
    payload = b'{"value":"' + b"x" * json_loader._JSON_READ_CHUNK_BYTES + b'"}'
    path.write_bytes(payload)
    real_read = os.read
    calls = 0

    def shortened_read(descriptor: int, count: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2 and failure == "premature-eof":
            return b""
        chunk = real_read(descriptor, count)
        if calls == 1 and failure == "truncate":
            os.truncate(path, len(chunk))
        return chunk

    monkeypatch.setattr(json_loader.os, "read", shortened_read)
    with pytest.raises(OmivInputError, match="changed during bounded read"):
        json_loader.load_bounded_json(path, max_bytes=len(payload))


def test_bounded_loader_rejects_nonregular_and_symlink_without_reflection(
    tmp_path: Path,
) -> None:
    private = "PRIVATE_LOADER_PATH_TOKEN"
    directory = tmp_path / private
    directory.mkdir()
    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    link = tmp_path / f"{private}-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    candidates = [directory, link]
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / f"{private}-fifo"
        os.mkfifo(fifo)
        candidates.append(fifo)
    for candidate in candidates:
        with pytest.raises(OmivInputError) as caught:
            json_loader.load_bounded_json(candidate, max_bytes=1024)
        assert private not in str(caught.value)


@pytest.mark.parametrize(
    "removal", ["zero", "absent", "fractional", "boolean", "negative", "non-numeric"]
)
def test_bounded_loader_without_atomic_no_follow_fails_before_open_or_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, removal: str
) -> None:
    path = tmp_path / "unsupported-platform.json"
    path.write_bytes(b"{}")

    def forbidden_open(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("no open may occur without atomic no-follow support")

    def forbidden_read(_descriptor: int, _count: int) -> bytes:
        raise AssertionError("no read may occur without atomic no-follow support")

    def forbidden_stat(*_args: object, **_kwargs: object) -> os.stat_result:
        raise AssertionError("the raceable stat fallback must not exist")

    # "fractional" and "boolean" are truthy yet cannot contribute a usable
    # no-follow bit, so a truthiness-only gate would admit them.
    unusable: dict[str, object] = {
        "zero": 0,
        "fractional": 0.5,
        "boolean": True,
        "negative": -1,
        "non-numeric": "O_NOFOLLOW",
    }
    if removal == "absent":
        monkeypatch.delattr(json_loader.os, "O_NOFOLLOW")
    else:
        monkeypatch.setattr(json_loader.os, "O_NOFOLLOW", unusable[removal])
    monkeypatch.setattr(json_loader.os, "open", forbidden_open)
    monkeypatch.setattr(json_loader.os, "read", forbidden_read)
    monkeypatch.setattr(json_loader.os, "stat", forbidden_stat)
    monkeypatch.setattr(json_loader.os, "lstat", forbidden_stat)
    with pytest.raises(OmivInputError, match="without atomic no-follow support"):
        json_loader.load_bounded_json(path, max_bytes=1024)


@pytest.mark.parametrize("errno_value", [errno.EINVAL, errno.EOPNOTSUPP, errno.ELOOP])
def test_bounded_loader_kernel_rejection_never_retries_a_weaker_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, errno_value: int
) -> None:
    private = "PRIVATE_NOFOLLOW_PATH_TOKEN"
    path = tmp_path / f"{private}.json"
    path.write_bytes(b"{}")
    attempts: list[int] = []

    def rejecting_open(_candidate: object, flags: int) -> int:
        attempts.append(flags)
        raise OSError(errno_value, os.strerror(errno_value))

    monkeypatch.setattr(json_loader.os, "open", rejecting_open)
    with pytest.raises(OmivInputError, match="cannot safely open JSON input") as caught:
        json_loader.load_bounded_json(path, max_bytes=1024)
    assert len(attempts) == 1
    assert attempts[0] & os.O_NOFOLLOW
    assert private not in str(caught.value)


def test_bounded_loader_rejects_symlink_swap_to_the_same_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = tmp_path / "symlink-probe"
    try:
        probe.symlink_to(tmp_path)
    except OSError:
        pytest.skip("symlinks unavailable")
    probe.unlink()
    path = tmp_path / "candidate.json"
    moved = tmp_path / "moved.json"
    path.write_bytes(b'{"source":"original"}')
    original_metadata = path.stat()
    real_open = os.open
    attempts = 0
    swapped = False

    def swap_to_symlink_before_open(candidate: os.PathLike[str] | str, flags: int) -> int:
        # Emulates the R8 race window: the regular file is renamed and the
        # pathname is replaced by a symlink resolving to the very same inode,
        # so a device/inode comparison would have accepted the substitution.
        nonlocal attempts, swapped
        attempts += 1
        if Path(candidate) == path and not swapped:
            path.rename(moved)
            path.symlink_to(moved)
            swapped = True
        return real_open(candidate, flags)

    monkeypatch.setattr(json_loader.os, "open", swap_to_symlink_before_open)
    with pytest.raises(OmivInputError, match="cannot safely open JSON input"):
        json_loader.load_bounded_json(path, max_bytes=1024)
    assert swapped
    assert attempts == 1
    assert path.is_symlink()
    assert moved.stat().st_ino == original_metadata.st_ino


@pytest.mark.parametrize("raw", [b"", b'{"unfinished":'])
def test_bounded_loader_empty_and_malformed_inputs_fail_finitely(
    tmp_path: Path, raw: bytes
) -> None:
    path = tmp_path / "finite-rejection.json"
    path.write_bytes(raw)
    with pytest.raises(OmivInputError, match="invalid JSON"):
        json_loader.load_bounded_json(path, max_bytes=1024)


def test_request_plan_and_evidence_loaders_route_distinct_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from omiv.runtime_compatibility import operations

    observed: list[int] = []

    def record_limit(
        _path: Path, *, max_bytes: int, require_object: bool = True
    ) -> tuple[object, bytes]:
        assert require_object
        observed.append(max_bytes)
        return {}, b"{}"

    monkeypatch.setattr(operations, "load_bounded_json", record_limit)
    path = tmp_path / "input.json"
    for loader in (operations.load_request, operations.load_plan, operations.load_evidence):
        with pytest.raises(OmivInputError, match="invalid runtime compatibility"):
            loader(path)
    assert observed == [
        MAX_RUNTIME_COMPAT_REQUEST_BYTES,
        MAX_RUNTIME_COMPAT_PLAN_BYTES,
        MAX_RUNTIME_COMPAT_EVIDENCE_BYTES,
    ]
    assert len(set(observed)) == 3
    assert observed == sorted(observed)


@pytest.mark.parametrize("loader", [load_request, load_plan, load_evidence])
def test_schema_loaders_reject_truncation_without_partial_output(
    tmp_path: Path, loader: object
) -> None:
    path = tmp_path / "truncated.json"
    path.write_bytes(b'{"schema":"omiv.controlled-runtime')
    with pytest.raises(OmivInputError, match="invalid JSON"):
        loader(path)  # type: ignore[operator]


def test_rehashed_stage_and_projection_mutations_are_rejected(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    value["stages"][0]["status"] = "FAIL"
    _rehash(value)
    path = tmp_path / "tampered-stage.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_offline_reapplies_json_node_bound(evidence: ControlledEvidence, tmp_path: Path) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    tokens = list(range(1500))
    tokenize = value["probes"][0]["tokenize"]
    _replace_response(
        tokenize,
        json.dumps({"tokens": tokens}, separators=(",", ":"), sort_keys=True).encode(),
    )
    value["probes"][0]["tokens"] = tokens
    completion = value["probes"][0]["completion"]
    completion_value = json.loads(base64.b64decode(completion["response_body"]["captured_base64"]))
    completion_value["prompt_tokens"] = len(tokens)
    _replace_response(
        completion,
        json.dumps(completion_value, separators=(",", ":"), sort_keys=True).encode(),
    )
    value["probes"][0]["prompt_tokens"] = len(tokens)
    _rehash(value)
    path = tmp_path / "excessive-json-nodes.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


@pytest.mark.parametrize("mutation", ["version-termination", "version-ready", "capture-limit"])
def test_offline_rejects_unemittable_process_and_capture_states(
    evidence: ControlledEvidence, tmp_path: Path, mutation: str
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    if mutation == "version-termination":
        value["version_execution"]["termination"] = "SIGKILL"
    elif mutation == "version-ready":
        value["version_execution"]["alive_at_ready"] = True
    else:
        value["probes"][0]["tokenize"]["response_body"]["limit_bytes"] += 1
    _rehash(value)
    path = tmp_path / f"unemittable-{mutation}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_offline_binds_version_projection_to_captured_stdout(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    _replace_capture(value["version_execution"]["stdout"], b"different safe version\n")
    _rehash(value)
    path = tmp_path / "version-projection.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_evidence_limitations_are_profile_owned(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    value["limitations"] = ["establishes performance and production readiness"]
    _rehash(value)
    path = tmp_path / "upgraded-nonclaims.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_plan_limitations_are_profile_owned(tmp_path: Path) -> None:
    plan = build_plan(load_request(REQUEST), ROOT)
    value = json.loads(json.dumps(plan.model_dump(mode="json", by_alias=True)))
    value["limitations"] = ["establishes performance and production readiness"]
    body = {key: item for key, item in value.items() if key not in {"plan_id", "plan_digest"}}
    digest = canonical_sha256({"domain": value["schema"], "body": body})
    value["plan_id"] = f"controlled_runtime_plan_{digest[:32]}"
    value["plan_digest"] = digest
    path = tmp_path / "upgraded-plan-nonclaims.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime plan"):
        load_plan(path)


def test_offline_privacy_rejects_sensitive_work_path(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    value["work_boundary"] = {
        "entries": ["adversarial-secret.txt"],
        "unexpected": True,
        "cleanup_complete": True,
    }
    value["stages"][3]["status"] = "FAIL"
    value["status"] = "NOT_VERIFIED"
    _rehash(value)
    path = tmp_path / "private-work-path.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


@pytest.mark.parametrize("target", ["executable", "artifact"])
def test_request_paths_apply_controlled_privacy_policy(tmp_path: Path, target: str) -> None:
    value = json.loads(REQUEST.read_text(encoding="utf-8"))
    private_path = "examples/runtime-compatibility/adversarial-secret.gguf"
    if target == "executable":
        value["executable_path"] = private_path
    else:
        value["artifacts"][0]["path"] = private_path
    path = tmp_path / f"private-{target}-path.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime request"):
        load_request(path)


@pytest.mark.parametrize("mutation", ["nonzero", "sigkill", "work-entry"])
def test_decode_cannot_pass_a_blocking_execution_or_work_state(
    evidence: ControlledEvidence, tmp_path: Path, mutation: str
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    if mutation == "nonzero":
        value["servers"][0]["process"]["return_code"] = 7
    elif mutation == "sigkill":
        value["servers"][0]["process"]["termination"] = "SIGKILL"
        value["servers"][0]["process"]["return_code"] = -9
    else:
        value["work_boundary"] = {
            "entries": ["bounded.txt"],
            "unexpected": True,
            "cleanup_complete": True,
        }
    value["status"] = "NOT_VERIFIED"
    _rehash(value)
    path = tmp_path / f"passing-decode-{mutation}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_backend_device_and_offload_facts_are_request_bound_offline(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    replacement = {
        "backend": "CPU",
        "device_count": 1,
        "device_index": 0,
        "device_name": "generic CPU",
        "main_model_gpu_layers": "NONE",
        "projector_offloaded": False,
    }
    exchange = value["probes"][0]["completion"]
    response = json.loads(base64.b64decode(exchange["response_body"]["captured_base64"]))
    response["backend"] = replacement
    _replace_response(
        exchange,
        json.dumps(response, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(),
    )
    value["probes"][0]["backend"] = replacement
    _rehash(value)
    path = tmp_path / "backend-policy-bypass.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_image_completion_transports_and_offline_binds_exact_png(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    image_probe = evidence.probes[1]
    request = json.loads(base64.b64decode(image_probe.completion.request_body.captured_base64))
    assert set(request) == {
        "cache_prompt",
        "image_data",
        "n_predict",
        "prompt",
        "seed",
        "temperature",
    }
    raw_image = base64.b64decode(request["image_data"][0]["data"], validate=True)
    assert len(raw_image) == 4246
    assert hashlib.sha256(raw_image).hexdigest() == (
        "53bf31df09c932233812a2c7b61c89a0ecbbaee90ab63f36058099e5d008e852"
    )

    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    exchange = value["probes"][1]["completion"]
    body = json.loads(base64.b64decode(exchange["request_body"]["captured_base64"]))
    body["image_data"][0]["data"] = base64.b64encode(b"not-the-pinned-image").decode()
    _replace_request(
        exchange,
        json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(),
    )
    _rehash(value)
    path = tmp_path / "different-image.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_dflash_servers_and_response_facts_bind_implementation_and_artifact(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    off, on = evidence.plan.invocation.servers
    assert "--spec-type" not in off.arguments
    assert "--spec-draft-model" not in off.arguments
    assert on.arguments[
        on.arguments.index("--spec-type") : on.arguments.index("--spec-type") + 2
    ] == ["--spec-type", "draft-dflash"]
    assert "--spec-draft-model" in on.arguments
    assert all(item.dflash.implementation == "NONE" for item in evidence.probes[:2])
    assert all(item.dflash.implementation == "draft-dflash" for item in evidence.probes[2:])

    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    exchange = value["probes"][2]["completion"]
    response = json.loads(base64.b64decode(exchange["response_body"]["captured_base64"]))
    response["dflash"]["draft_artifact_sha256"] = "f" * 64
    _replace_response(
        exchange,
        json.dumps(response, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(),
    )
    value["probes"][2]["dflash"]["draft_artifact_sha256"] = "f" * 64
    _rehash(value)
    path = tmp_path / "different-dflash.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_api_pass_field_never_upgrades_or_survives_strict_schema(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    exchange = value["probes"][0]["completion"]
    raw = base64.b64decode(exchange["response_body"]["captured_base64"])
    response = json.loads(raw)
    response["PASS"] = True
    changed = json.dumps(
        response, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    digest = hashlib.sha256(changed).hexdigest()
    exchange["response_body"].update(
        {
            "captured_base64": base64.b64encode(changed).decode(),
            "captured_bytes": len(changed),
            "captured_sha256": digest,
        }
    )
    exchange["response_digest"] = digest
    _rehash(value)
    path = tmp_path / "pass-injection.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


@pytest.mark.parametrize(
    ("target", "replacement"),
    [
        ("token-empty", {"tokens": []}),
        ("token-negative", {"tokens": [-1]}),
        ("token-string", {"tokens": ["PASS"]}),
        ("completion-missing-counter", {"prompt_tokens": None}),
        ("completion-zero-predicted", {"predicted_tokens": 0}),
        ("completion-bad-finish", {"finish_reason": "PASS"}),
        ("completion-empty-output", {"content": ""}),
        ("dflash-inactive", {"dflash": {"active": False, "draft_tokens": 0, "accepted_tokens": 0}}),
        (
            "dflash-zero-generated",
            {"dflash": {"active": True, "draft_tokens": 0, "accepted_tokens": 0}},
        ),
        (
            "dflash-impossible-counts",
            {"dflash": {"active": True, "draft_tokens": 1, "accepted_tokens": 2}},
        ),
    ],
)
def test_rehashed_malformed_token_counter_finish_output_and_dflash_responses_fail_closed(
    evidence: ControlledEvidence,
    tmp_path: Path,
    target: str,
    replacement: dict[str, object],
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    probe_index = 2 if target.startswith("dflash") else 0
    exchange_name = "tokenize" if target.startswith("token-") else "completion"
    exchange = value["probes"][probe_index][exchange_name]
    raw = base64.b64decode(exchange["response_body"]["captured_base64"])
    response = json.loads(raw)
    if exchange_name == "tokenize":
        response = replacement
    else:
        response.update(replacement)
    changed = json.dumps(
        response, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    _replace_response(exchange, changed)
    _rehash(value)
    path = tmp_path / f"{target}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_duplicate_json_keys_and_truncated_utf8_fail_closed(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    for name, raw in (
        ("duplicate", b'{"tokens":[1],"tokens":[2]}'),
        ("utf8", b'{"tokens":[1],"x":"\xff"}'),
    ):
        value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
        exchange = value["probes"][0]["tokenize"]
        _replace_response(exchange, raw)
        _rehash(value)
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
            load_evidence(path)


@pytest.mark.parametrize(
    "mutation",
    [
        "method",
        "endpoint",
        "header",
        "environment",
        "boundary_digest",
        "boundary_size",
        "boundary_order",
        "process_return",
        "process_timeout",
        "process_overflow",
        "cleanup",
        "finding",
    ],
)
def test_rehashed_protocol_environment_boundary_process_and_cleanup_mutations_fail(
    evidence: ControlledEvidence, tmp_path: Path, mutation: str
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    if mutation == "method":
        value["probes"][0]["tokenize"]["method"] = "GET"
    elif mutation == "endpoint":
        value["probes"][0]["tokenize"]["endpoint"] = "/completion"
    elif mutation == "header":
        value["probes"][0]["tokenize"]["request_headers"] = ["Authorization: PASS"]
    elif mutation == "environment":
        value["servers"][0]["process"]["environment"][0]["name"] = "HTTP_PROXY"
    elif mutation == "boundary_digest":
        value["rehash_boundaries"][1]["bindings"][0]["sha256"] = "f" * 64
    elif mutation == "boundary_size":
        value["rehash_boundaries"][2]["bindings"][1]["size"] += 1
    elif mutation == "boundary_order":
        value["rehash_boundaries"].reverse()
    elif mutation == "process_return":
        value["servers"][0]["process"]["return_code"] = 7
    elif mutation == "process_timeout":
        value["servers"][0]["process"]["probe_timed_out"] = True
    elif mutation == "process_overflow":
        value["servers"][0]["process"]["stderr"]["overflow"] = True
    elif mutation == "cleanup":
        value["work_boundary"]["cleanup_complete"] = False
    else:
        value["findings"] = [
            {"blocking": False, "code": "PASS", "detail": "PASS", "severity": "INFO"}
        ]
    _rehash(value)
    path = tmp_path / f"projection-{mutation}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_output_predicate_mismatch_is_coherent_not_verified() -> None:
    request = load_request(REQUEST)
    probes = list(request.probes)
    probes[0] = probes[0].model_copy(update={"expected_content": "not-alpha"})
    changed = request.model_copy(update={"request_id": "predicate-mismatch", "probes": probes})
    result = execute_plan(build_plan(changed, ROOT), ROOT)
    assert result.status.value == "NOT_VERIFIED"
    assert result.stages[-1].status.value == "FAIL"
    assert result.probes[0].predicate_matched is False


def test_request_rejects_remote_and_caller_owned_protocol_fields(tmp_path: Path) -> None:
    value = json.loads(REQUEST.read_text(encoding="utf-8"))
    for field, item in (
        ("url", "https://example.invalid"),
        ("headers", {"Authorization": "Bearer secret"}),
        ("bind_address", "0.0.0.0"),
        ("port", 8080),
        ("environment", {"HTTP_PROXY": "https://example.invalid"}),
    ):
        attacked = dict(value)
        attacked[field] = item
        path = tmp_path / f"attack-{field}.json"
        path.write_text(json.dumps(attacked), encoding="utf-8")
        result = RUNNER.invoke(
            app,
            [
                "runtime-compat",
                "plan",
                "--request",
                str(path),
                "--root",
                str(ROOT),
                "--output",
                str(tmp_path / f"{field}-plan.json"),
            ],
        )
        assert result.exit_code == 2
        assert not (tmp_path / f"{field}-plan.json").exists()
        assert "secret" not in result.output
        assert "example.invalid" not in result.output


def test_portable_evidence_has_no_host_path_endpoint_or_credentials(
    evidence: ControlledEvidence,
) -> None:
    raw = json.dumps(evidence.model_dump(mode="json", by_alias=True))
    for forbidden in (
        str(ROOT),
        "/home/",
        "http://",
        "https://",
        "Authorization",
        "Bearer ",
        "HTTP_PROXY",
        "HTTPS_PROXY",
    ):
        assert forbidden not in raw
    assert evidence.plan.invocation.bind_address == "127.0.0.1"
    assert evidence.plan.invocation.port == "OMIV_SELECTED_EPHEMERAL_LOOPBACK_PORT"
    assert os.access(
        ROOT / "examples/runtime-compatibility/synthetic-controlled-server.py", os.X_OK
    )


@pytest.mark.parametrize(
    "private_value",
    [
        b"loaded " + b"/" + b"opt/private/model.gguf\n",
        b"Authorization: " + b"Bearer " + b"adversarial-value\n",
        f"listening on {54_000 + 321}\n".encode(),
    ],
)
def test_offline_privacy_policy_rejects_rehashed_retained_streams(
    evidence: ControlledEvidence, tmp_path: Path, private_value: bytes
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    _replace_capture(value["servers"][0]["process"]["stdout"], private_value)
    _rehash(value)
    path = tmp_path / "private-stream.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_muse_future_closure_is_exact_and_intentionally_blocked() -> None:
    path = ROOT / "examples/runtime-compatibility/muse-glimmer-controlled-request.json"
    request = load_request(path)
    plan = build_plan(request, ROOT)
    assert plan.status.value == "BLOCKED"
    assert request.executable_sha256 is None
    assert request.expected_runtime_version is None
    assert request.runtime_commit == "f8def7fe168bab245fbf15d3f18b26dbb1ef73c8"
    assert [(item.role.value, item.size, item.sha256) for item in request.artifacts[:3]] == [
        (
            "MAIN",
            16_756_683_904,
            "4cc57c0f51040a226e5a72cc47b7613f7772950e460a665f7083de89f183f60e",
        ),
        (
            "PROJECTOR",
            1_400_328_928,
            "f48b452316f9b213758e8659444029b961a24a07f99a1abb2a9f88b06f7c00c6",
        ),
        (
            "DFLASH",
            1_631_208_128,
            "b2e808bf656086fe86bd0d0bd990f01d33e377537a07c02d45371517c8b264ef",
        ),
    ]
    assert [item.use_dflash for item in request.probes] == [False, False, True, True]
    assert request.backend_requirement.backend.value == "CUDA"
    assert request.backend_requirement.device_name == "NVIDIA GeForce RTX 5090"
    assert request.backend_requirement.main_model_gpu_layers == "ALL"
    assert request.backend_requirement.projector_offloaded
    assert request.backend_requirement.dflash_gpu_layers == "ALL"
    assert len(plan.invocation.servers) == 2
    assert "--spec-type" not in plan.invocation.servers[0].arguments
    assert plan.invocation.servers[1].arguments[-4:] == [
        "--spec-draft-ngl",
        "all",
        "--spec-draft-device",
        "CUDA0",
    ]
    dflash_arguments = plan.invocation.servers[1].arguments
    position = dflash_arguments.index("--spec-type")
    assert dflash_arguments[position : position + 2] == ["--spec-type", "draft-dflash"]


def _isolated_request(tmp_path: Path, replacement: tuple[str, str]) -> object:
    request = load_request(REQUEST)
    source = (ROOT / "examples/runtime-compatibility/synthetic-controlled-server.py").read_text(
        encoding="utf-8"
    )
    source = source.replace(*replacement)
    executable = tmp_path / "server.py"
    executable.write_text(source, encoding="utf-8")
    executable.chmod(0o755)
    artifacts = []
    for item in request.artifacts:
        source_path = ROOT / item.path
        target = tmp_path / source_path.name
        shutil.copyfile(source_path, target)
        artifacts.append(item.model_copy(update={"path": target.name}))
    limits = request.limits.model_copy(
        update={
            "startup_timeout_seconds": 1,
            "probe_timeout_seconds": 1,
            "shutdown_timeout_seconds": 1,
            "max_stdout_bytes": 1024,
            "max_stderr_bytes": 1024,
        }
    )
    return request.model_copy(
        update={
            "request_id": "adversarial-process-fixture",
            "executable_path": executable.name,
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "artifacts": artifacts,
            "limits": limits,
        }
    )


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    status = Path(f"/proc/{pid}/stat")
    if status.exists():
        with suppress(OSError, IndexError):
            return status.read_text(encoding="utf-8").split()[2] != "Z"
    return True


def _fault_process(
    tmp_path: Path, fault: str, *, spawn_tree: bool
) -> tuple[_ContainedProcess | None, Path]:
    pid_directory = tmp_path / f"fault-{fault}"
    pid_directory.mkdir()
    code = (
        "import os,pathlib,time; "
        f"root=pathlib.Path({str(pid_directory)!r}); "
        "host=lambda:next(x for x in open('/proc/self/status') "
        "if x.startswith('NSpid:')).split()[1]; "
        "root.joinpath('leader').write_text(host()); "
    )
    if spawn_tree:
        code += (
            "pid=os.fork(); "
            "(os.setsid(),root.joinpath('setsid').write_text(host()),"
            "os.fork() and os._exit(0),"
            "root.joinpath('double-fork').write_text(host()),time.sleep(30)) "
            "if pid==0 else time.sleep(30)"
        )
    else:
        code += "time.sleep(30)"
    process: _ContainedProcess | None = None
    with suppress(OmivInputError):
        process = _ContainedProcess.start(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            environment={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"},
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
            max_work_file_bytes=1024,
            pass_fds=(),
            fault=fault,
        )
    return process, pid_directory


def _assert_fault_tree_empty(pid_directory: Path) -> None:
    for path in pid_directory.iterdir():
        assert not _pid_is_running(int(path.read_text(encoding="utf-8")))


def _wait_for_fault_pids(pid_directory: Path, minimum: int) -> None:
    deadline = time.monotonic() + 1
    while len(list(pid_directory.iterdir())) < minimum and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(list(pid_directory.iterdir())) >= minimum


@pytest.mark.parametrize(
    "fault",
    [
        "leader_pidfd",
        "collector_construct",
        "collector_start",
        "post_launch_enumeration",
        "protocol_result",
    ],
)
def test_atomic_launch_faults_use_bounded_emergency_cleanup(tmp_path: Path, fault: str) -> None:
    process, pid_directory = _fault_process(
        tmp_path,
        fault,
        spawn_tree=fault in {"post_launch_enumeration", "protocol_result"},
    )
    assert process is None
    if fault in {"leader_pidfd", "collector_construct", "collector_start"}:
        assert not any(pid_directory.iterdir())
    else:
        _wait_for_fault_pids(pid_directory, 3)
    _assert_fault_tree_empty(pid_directory)


def test_emergency_cleanup_fallback_and_primary_assertion_failure_leave_no_tree(
    tmp_path: Path,
) -> None:
    process, pid_directory = _fault_process(tmp_path, "emergency_cleanup", spawn_tree=True)
    assert process is not None
    _wait_for_fault_pids(pid_directory, 3)
    try:
        raise AssertionError("injected primary assertion failure")
    except AssertionError:
        with pytest.raises(OmivInputError, match="cleanup report"):
            process.finish(mode="TERMINATE", timeout_seconds=0, grace_seconds=0.1)
    _assert_fault_tree_empty(pid_directory)


def test_fault_cleanup_never_signals_unrelated_process(tmp_path: Path) -> None:
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        process, pid_directory = _fault_process(
            tmp_path, "post_launch_enumeration", spawn_tree=True
        )
        assert process is None
        _wait_for_fault_pids(pid_directory, 3)
        _assert_fault_tree_empty(pid_directory)
        assert unrelated.poll() is None
    finally:
        if unrelated.poll() is None:
            unrelated.kill()
        unrelated.wait(timeout=2)


def _persistent_enumeration_process(
    tmp_path: Path,
    *,
    leader_action: str,
    fault: str = "persistent_enumeration",
) -> tuple[_ContainedProcess, Path]:
    pid_directory = tmp_path / ("persistent-" + fault.replace("+", "-"))
    pid_directory.mkdir()
    code = (
        "import os,pathlib,signal,sys,time; "
        f"root=pathlib.Path({str(pid_directory)!r}); "
        "host=lambda:next(x for x in open('/proc/self/status') "
        "if x.startswith('NSpid:')).split()[1]; "
        "root.joinpath('leader').write_text(host()); "
        "pid=os.fork(); "
        "(os.setsid(),os.fork() and os._exit(0),"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN),"
        "root.joinpath('double-fork').write_text(host()),time.sleep(30)) "
        "if pid==0 else None; "
        "time.sleep(0.2); " + leader_action
    )
    process = _ContainedProcess.start(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        environment={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"},
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
        max_work_file_bytes=1024,
        pass_fds=(),
        fault=fault,
    )
    _wait_for_fault_pids(pid_directory, 2)
    time.sleep(0.3)
    return process, pid_directory


@pytest.mark.parametrize(
    ("leader_action", "mode", "timeout", "expected_termination"),
    [
        ("None", "WAIT", 2, "GRACEFUL"),
        ("time.sleep(30)", "WAIT", 0.05, "SIGKILL"),
        (
            "signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); time.sleep(30)",
            "TERMINATE",
            0,
            "SIGTERM",
        ),
        (
            "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)",
            "TERMINATE",
            0,
            "SIGKILL",
        ),
    ],
)
def test_pid_namespace_kill_survives_persistent_enumeration_failure(
    tmp_path: Path,
    leader_action: str,
    mode: str,
    timeout: float,
    expected_termination: str,
) -> None:
    process, pid_directory = _persistent_enumeration_process(tmp_path, leader_action=leader_action)
    try:
        report = process.finish(mode=mode, timeout_seconds=timeout, grace_seconds=1.0)
        assert report.termination == expected_termination
        assert report.observation["mechanism"] == "LINUX_PID_NAMESPACE_INIT_PIDFD_V1"
        assert report.observation["descendants_remaining"] == 0
        assert report.observation["streams_eof"] is True
    finally:
        if process.supervisor.poll() is None:
            with suppress(OmivInputError):
                process.finish(mode="TERMINATE", timeout_seconds=0, grace_seconds=0.1)
    _assert_fault_tree_empty(pid_directory)


@pytest.mark.parametrize(
    "fault",
    [
        "persistent_enumeration+collector_failure",
        "persistent_enumeration+capture_truncated",
        "persistent_enumeration+whole_tree_kill_failure",
        "persistent_enumeration+stale_containment_handle",
    ],
)
def test_fault_cleanup_uses_kernel_handle_when_enumeration_never_recovers(
    tmp_path: Path, fault: str
) -> None:
    process, pid_directory = _persistent_enumeration_process(
        tmp_path, leader_action="time.sleep(30)", fault=fault
    )
    try:
        with pytest.raises(OmivInputError, match="cleanup report"):
            process.finish(mode="TERMINATE", timeout_seconds=0, grace_seconds=0.1)
    finally:
        if process.supervisor.poll() is None:
            process._abort_protocol()
    _assert_fault_tree_empty(pid_directory)


def test_persistent_enumeration_kernel_kill_does_not_touch_unrelated_process(
    tmp_path: Path,
) -> None:
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        process, pid_directory = _persistent_enumeration_process(
            tmp_path, leader_action="time.sleep(30)"
        )
        process.finish(mode="TERMINATE", timeout_seconds=0, grace_seconds=0.1)
        _assert_fault_tree_empty(pid_directory)
        assert unrelated.poll() is None
    finally:
        if unrelated.poll() is None:
            unrelated.kill()
        unrelated.wait(timeout=2)


@pytest.mark.parametrize(
    ("stdout_size", "stderr_size"),
    [
        (16 * 1024 * 1024, 0),
        (0, 4 * 1024 * 1024),
        (16 * 1024 * 1024, 4 * 1024 * 1024),
    ],
)
def test_capture_protocol_accepts_request_schema_limits(
    tmp_path: Path, stdout_size: int, stderr_size: int
) -> None:
    code = (
        "import sys; "
        f"sys.stdout.buffer.write(b'o'*{stdout_size}); sys.stdout.buffer.flush(); "
        f"sys.stderr.buffer.write(b'e'*{stderr_size}); sys.stderr.buffer.flush()"
    )
    process = _ContainedProcess.start(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        environment={"PATH": "/usr/bin:/bin"},
        max_stdout_bytes=max(1024, stdout_size),
        max_stderr_bytes=max(1024, stderr_size),
        max_work_file_bytes=1024,
        pass_fds=(),
    )
    report = process.finish(mode="WAIT", timeout_seconds=10, grace_seconds=0.2)
    assert len(report.stdout) == stdout_size
    assert len(report.stderr) == stderr_size
    assert report.stdout_observed_bytes == stdout_size
    assert report.stderr_observed_bytes == stderr_size
    assert not report.stdout_overflow
    assert not report.stderr_overflow


def test_capture_protocol_one_byte_over_limit_is_bounded_and_incomplete(tmp_path: Path) -> None:
    process = _ContainedProcess.start(
        [sys.executable, "-c", "import os; os.write(1,b'x'*1025)"],
        cwd=tmp_path,
        environment={"PATH": "/usr/bin:/bin"},
        max_stdout_bytes=1024,
        max_stderr_bytes=1024,
        max_work_file_bytes=1024,
        pass_fds=(),
    )
    report = process.finish(mode="WAIT", timeout_seconds=3, grace_seconds=0.2)
    assert len(report.stdout) == 1024
    assert report.stdout_observed_bytes == 1025
    assert report.stdout_overflow
    assert report.observation["stdout_complete"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "capture_oversized",
        "capture_truncated",
        "capture_trailing",
        "capture_reordered",
        "capture_inconsistent",
        "control_duplicate",
    ],
)
def test_malformed_result_protocol_fails_after_cleanup_without_survivors(
    tmp_path: Path, fault: str
) -> None:
    process, pid_directory = _fault_process(tmp_path, fault, spawn_tree=True)
    assert process is not None
    _wait_for_fault_pids(pid_directory, 3)
    with pytest.raises(OmivInputError, match="cleanup report|capture metadata"):
        process.finish(mode="TERMINATE", timeout_seconds=0, grace_seconds=0.1)
    _assert_fault_tree_empty(pid_directory)


def test_capture_and_control_framing_reject_lengths_truncation_trailing_and_duplicates() -> None:
    for name in ("oversized", "truncated", "reordered"):
        read_descriptor, write_descriptor = os.pipe()
        declared = 5 if name != "oversized" else 1025
        stream = b"E" if name == "reordered" else b"O"
        os.write(
            write_descriptor,
            _CONTAINMENT_CAPTURE_MAGIC + b"R" + stream + declared.to_bytes(8, "big") + b"xx",
        )
        os.close(write_descriptor)
        with pytest.raises(RuntimeError):
            _receive_capture_frame(
                read_descriptor,
                phase=b"R",
                stream=b"O",
                maximum=1024,
                timeout=1,
            )
        os.close(read_descriptor)

    read_descriptor, write_descriptor = os.pipe()
    payload = b"ok"
    os.write(
        write_descriptor,
        _CONTAINMENT_CAPTURE_MAGIC
        + b"RO"
        + len(payload).to_bytes(8, "big")
        + payload
        + b"duplicate-or-trailing",
    )
    os.close(write_descriptor)
    assert (
        _receive_capture_frame(read_descriptor, phase=b"R", stream=b"O", maximum=1024, timeout=1)
        == payload
    )
    with pytest.raises(RuntimeError, match="trailing"):
        _require_containment_eof(read_descriptor, 1)
    os.close(read_descriptor)

    read_descriptor, write_descriptor = os.pipe()
    raw = b'{"status":"one","status":"two"}'
    os.write(write_descriptor, len(raw).to_bytes(4, "big") + raw)
    os.close(write_descriptor)
    with pytest.raises(RuntimeError, match="malformed"):
        _receive_containment_message(read_descriptor, timeout=1)
    os.close(read_descriptor)


def test_rehashes_match_aggregate_server_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _isolated_request(
        tmp_path,
        (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)\n    "
            "Path(f\"server-{'on' if active_dflash else 'off'}.pid\").write_text(\n        "
            "next(x for x in open('/proc/self/status') if "
            "x.startswith('NSpid:')).split()[1], encoding='utf-8'\n    )",
        ),
    )
    request = request.model_copy(
        update={"limits": request.limits.model_copy(update={"max_work_entries": 4})}
    )
    observed: list[tuple[str, int]] = []
    from omiv.runtime_compatibility import controlled_operations

    original = controlled_operations._rehash

    def observe(plan: object, root: Path, boundary: str) -> object:
        active = 0
        for path in root.glob(".omiv-controlled-runtime-*/server-*.pid"):
            if _pid_is_running(int(path.read_text(encoding="utf-8"))):
                active += 1
        observed.append((boundary, active))
        return original(plan, root, boundary)  # type: ignore[arg-type]

    monkeypatch.setattr(controlled_operations, "_rehash", observe)
    execute_plan(build_plan(request, tmp_path), tmp_path)
    assert observed == [
        ("PRE_START", 0),
        ("POST_READY", 2),
        ("POST_PROBES", 2),
        ("POST_SHUTDOWN", 0),
    ]


def test_cleanup_kills_descendants_and_requires_collector_eof(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    child_code = (
        "import os,pathlib,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(pid_path)!r}).write_text(next(x for x in "
        "open('/proc/self/status') if x.startswith('NSpid:')).split()[1], "
        "encoding='utf-8'); "
        "time.sleep(30)"
    )
    request = _isolated_request(
        tmp_path,
        (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)\n    "
            f"child = __import__('subprocess').Popen([sys.executable, '-c', {child_code!r}])\n    "
            f"ready = Path({str(pid_path)!r})\n    "
            "while not ready.exists():\n        __import__('time').sleep(0.01)",
        ),
    )
    child_pid: int | None = None
    try:
        result = execute_plan(build_plan(request, tmp_path), tmp_path)
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while _pid_is_running(child_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _pid_is_running(child_pid)
        assert result.status.value == "NOT_VERIFIED"
        assert all(item.process.termination == "SIGKILL" for item in result.servers)
        assert result.stages[3].status.value == "FAIL"
    finally:
        if child_pid is None and pid_path.exists():
            child_pid = int(pid_path.read_text(encoding="utf-8"))
        if child_pid is not None and _pid_is_running(child_pid):
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


@pytest.mark.parametrize(
    "failure",
    [
        "version",
        "version-timeout",
        "early-exit",
        "startup-timeout",
        "probe-timeout",
        "stdout-overflow",
    ],
)
def test_version_startup_probe_exit_and_stream_failures_cleanup_without_partial_evidence(
    tmp_path: Path, failure: str
) -> None:
    replacements = {
        "version": ("print(VERSION)", "print('wrong ' + VERSION)"),
        "version-timeout": (
            "print(VERSION)",
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n        "
            "__import__('time').sleep(4)\n        print(VERSION)",
        ),
        "early-exit": (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "return 7",
        ),
        "startup-timeout": (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "__import__('time').sleep(3)\n    return 8",
        ),
        "probe-timeout": (
            "def do_POST(self) -> None:  # noqa: N802\n",
            "def do_POST(self) -> None:  # noqa: N802\n        __import__('time').sleep(3)\n",
        ),
        "stdout-overflow": (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "sys.stdout.write('x' * 2048)\n    sys.stdout.flush()\n    return 9",
        ),
    }
    request = _isolated_request(tmp_path, replacements[failure])
    plan = build_plan(request, tmp_path)
    assert plan.status.value == "READY"
    with pytest.raises(OmivInputError):
        execute_plan(plan, tmp_path)
    assert not list(tmp_path.glob(".omiv-controlled-runtime-*"))


def test_kill_escalation_and_unexpected_work_file_are_coherent_not_verified(
    tmp_path: Path,
) -> None:
    ignored = _isolated_request(
        tmp_path,
        (
            "signal.signal(signal.SIGTERM, stop)",
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
        ),
    )
    killed = execute_plan(build_plan(ignored, tmp_path), tmp_path)
    assert killed.status.value == "NOT_VERIFIED"
    assert all(item.process.termination == "SIGKILL" for item in killed.servers)
    assert all(item.process.return_code != 0 for item in killed.servers)
    assert killed.work_boundary.cleanup_complete
    assert killed.stages[3].status.value == "FAIL"

    work_root = tmp_path / "work-file"
    work_root.mkdir()
    creates_file = _isolated_request(
        work_root,
        (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "open('unexpected.txt', 'w').write('bounded')\n    "
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
        ),
    )
    creates_file = creates_file.model_copy(
        update={"limits": creates_file.limits.model_copy(update={"max_work_entries": 4})}
    )
    observed = execute_plan(build_plan(creates_file, work_root), work_root)
    assert observed.status.value == "NOT_VERIFIED"
    assert observed.work_boundary.entries == ["unexpected.txt"]
    assert observed.work_boundary.cleanup_complete
    assert observed.stages[3].status.value == "FAIL"


def test_shutdown_created_file_is_inspected_after_full_reap(tmp_path: Path) -> None:
    request = _isolated_request(
        tmp_path,
        (
            "def stop(_signum: int, _frame: object) -> None:\n",
            "def stop(_signum: int, _frame: object) -> None:\n        "
            "open('created-during-shutdown.txt', 'w').write('bounded')\n",
        ),
    )
    request = request.model_copy(
        update={"limits": request.limits.model_copy(update={"max_work_entries": 4})}
    )
    result = execute_plan(build_plan(request, tmp_path), tmp_path)
    assert result.status.value == "NOT_VERIFIED"
    assert result.work_boundary.entries == ["created-during-shutdown.txt"]
    assert result.work_boundary.cleanup_complete
    assert result.stages[3].status.value == "FAIL"


def test_server_launch_enforces_declared_work_file_size_limit(tmp_path: Path) -> None:
    request = _isolated_request(
        tmp_path,
        (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "resource = __import__('resource')\n    "
            "assert resource.getrlimit(resource.RLIMIT_FSIZE)[0] == 1024\n    "
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
        ),
    )
    result = execute_plan(build_plan(request, tmp_path), tmp_path)
    assert result.status.value == "VERIFIED_WITHIN_PROFILE"
    assert not result.work_boundary.unexpected


@pytest.mark.parametrize("leak", ["port", "work-path"])
def test_runtime_dynamic_path_and_port_leaks_fail_before_evidence(
    tmp_path: Path, leak: str
) -> None:
    injected = (
        "print(arguments.port, flush=True)"
        if leak == "port"
        else "print(__import__('os').getcwd(), flush=True)"
    )
    request = _isolated_request(
        tmp_path,
        (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            f"{injected}\n    server = "
            "ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
        ),
    )
    with pytest.raises(OmivInputError, match="private runtime value|private or path-like"):
        execute_plan(build_plan(request, tmp_path), tmp_path)
    assert not list(tmp_path.glob(".omiv-controlled-runtime-*"))


def test_cli_runtime_error_does_not_reflect_oserror_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = "/" + "opt/private/runtime-secret"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(private)

    monkeypatch.setattr("omiv.cli.build_runtime_compatibility_plan", fail)
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(REQUEST),
            "--root",
            str(ROOT),
            "--output",
            str(tmp_path / "plan.json"),
        ],
    )
    assert result.exit_code == 2
    assert private not in result.output
    assert "operation failed" in result.output


def test_cli_loader_rejection_has_no_traceback_reflection_or_partial_output(
    tmp_path: Path,
) -> None:
    private_path = "PRIVATE_UNSAFE_REQUEST_PATH"
    private_content = "PRIVATE_UNSAFE_JSON_CONTENT"
    request_path = tmp_path / f"{private_path}.json"
    output = tmp_path / "must-not-exist.json"
    request_path.write_text(
        json.dumps({private_content: "first"})[:-1] + f',"{private_content}":"second"}}',
        encoding="utf-8",
    )
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(request_path),
            "--root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert result.output.strip() == "ERROR Runtime compatibility operation failed"
    assert "Traceback" not in result.output
    assert private_path not in result.output
    assert private_content not in result.output
    assert not output.exists()


def test_cli_symlinked_request_fails_closed_without_reflection_or_partial_output(
    tmp_path: Path,
) -> None:
    private_path = "PRIVATE_SYMLINKED_REQUEST_PATH"
    target = tmp_path / "target-request.json"
    target.write_text(json.dumps({"schema": "omiv.controlled-runtime"}), encoding="utf-8")
    request_path = tmp_path / f"{private_path}.json"
    try:
        request_path.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    output = tmp_path / "must-not-exist.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "plan",
            "--request",
            str(request_path),
            "--root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert result.output.strip() == "ERROR Runtime compatibility operation failed"
    assert "Traceback" not in result.output
    assert private_path not in result.output
    assert not output.exists()


def test_executed_and_loaded_bytes_survive_path_swap_symlink_and_restoration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _isolated_request(
        tmp_path,
        (
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
            "for bound_path in [arguments.model, arguments.mmproj, "
            "arguments.spec_draft_model]:\n        "
            "if bound_path and b'replacement-bytes' in Path(bound_path).read_bytes():\n"
            "            return 70\n    "
            "server = ThreadingHTTPServer((arguments.host, arguments.port), Handler)",
        ),
    )
    request = request.model_copy(
        update={
            "executable_sha256": hashlib.sha256(
                (tmp_path / request.executable_path).read_bytes()
            ).hexdigest()
        }
    )
    plan = build_plan(request, tmp_path)
    from omiv.runtime_compatibility import controlled_operations

    original_rehash = controlled_operations._rehash
    originals: list[tuple[Path, Path]] = []

    def replace_paths() -> None:
        paths = [
            tmp_path / request.executable_path,
            *(tmp_path / item.path for item in request.artifacts),
        ]
        for index, path in enumerate(paths):
            saved = path.with_name(f"{path.name}.pinned")
            replacement = path.with_name(f"{path.name}.replacement")
            path.rename(saved)
            if index == 0:
                replacement.write_text("#!/bin/sh\necho replacement-version\n", encoding="utf-8")
                replacement.chmod(0o755)
            else:
                replacement.write_bytes(b"replacement-bytes")
            path.symlink_to(replacement.name)
            originals.append((path, saved))

    def restore_paths() -> None:
        for path, saved in reversed(originals):
            path.unlink()
            saved.rename(path)
        originals.clear()

    def attack(plan_value: object, root: Path, boundary: str) -> object:
        if boundary == "POST_READY" and originals:
            restore_paths()
        result = original_rehash(plan_value, root, boundary)  # type: ignore[arg-type]
        if boundary == "PRE_START":
            replace_paths()
        return result

    monkeypatch.setattr(controlled_operations, "_rehash", attack)
    try:
        result = execute_plan(plan, tmp_path)
    finally:
        if originals:
            restore_paths()
    assert result.status.value == "VERIFIED_WITHIN_PROFILE"
    assert [item.status.value for item in result.stages] == ["PASS"] * 5


def test_execution_snapshots_are_write_sealed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _isolated_request(
        tmp_path,
        ("VERSION = ", "VERSION = "),
    )
    plan = build_plan(request, tmp_path)
    from omiv.runtime_compatibility import controlled_operations

    original = controlled_operations._start_server_configuration
    checked = False

    def attempt_mutation(*args: object, **kwargs: object) -> object:
        nonlocal checked
        inputs = args[2]
        descriptors = inputs.pass_fds  # type: ignore[union-attr]
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.write(descriptor, b"mutation")
        checked = True
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(controlled_operations, "_start_server_configuration", attempt_mutation)
    result = execute_plan(plan, tmp_path)
    assert checked
    assert result.status.value == "VERIFIED_WITHIN_PROFILE"


def test_version_setsid_descendant_closing_streams_is_killed_and_never_recorded(
    tmp_path: Path,
) -> None:
    pid_path = tmp_path / "version-descendant.pid"
    child_code = (
        "import os,pathlib,time; "
        f"pathlib.Path({str(pid_path)!r}).write_text(next(x for x in "
        "open('/proc/self/status') if x.startswith('NSpid:')).split()[1], "
        "encoding='utf-8'); "
        "time.sleep(30)"
    )
    request = _isolated_request(
        tmp_path,
        (
            "print(VERSION)\n        return 0",
            "__import__('subprocess').Popen([sys.executable, '-c', "
            f"{child_code!r}], stdin=__import__('subprocess').DEVNULL, "
            "stdout=__import__('subprocess').DEVNULL, "
            "stderr=__import__('subprocess').DEVNULL, start_new_session=True)\n        "
            "while not Path(" + repr(str(pid_path)) + ").exists():\n            "
            "__import__('time').sleep(0.01)\n        print(VERSION)\n        return 0",
        ),
    )
    request = request.model_copy(
        update={
            "executable_sha256": hashlib.sha256(
                (tmp_path / request.executable_path).read_bytes()
            ).hexdigest()
        }
    )
    child_pid: int | None = None
    try:
        plan = build_plan(request, tmp_path)
        with pytest.raises(OmivInputError, match="descendants remained.*were contained"):
            execute_plan(plan, tmp_path)
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        assert not _pid_is_running(child_pid)
        assert not list(tmp_path.glob(".omiv-controlled-runtime-*"))
    finally:
        if child_pid is None and pid_path.exists():
            child_pid = int(pid_path.read_text(encoding="utf-8"))
        if child_pid is not None and _pid_is_running(child_pid):
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_server_setsid_descendants_closing_streams_are_bounded_and_reaped(
    tmp_path: Path,
) -> None:
    pid_directory = tmp_path / "server-descendants"
    pid_directory.mkdir()
    child_code = (
        "import os,pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(pid_directory)!r}, next(x for x in "
        "open('/proc/self/status') if x.startswith('NSpid:')).split()[1]).write_text('live'); "
        "time.sleep(30)"
    )
    request = _isolated_request(
        tmp_path,
        (
            "def do_GET(self) -> None:  # noqa: N802\n",
            "def do_GET(self) -> None:  # noqa: N802\n        "
            "__import__('subprocess').Popen([sys.executable, '-c', "
            f"{child_code!r}], stdin=__import__('subprocess').DEVNULL, "
            "stdout=__import__('subprocess').DEVNULL, "
            "stderr=__import__('subprocess').DEVNULL, start_new_session=True)\n",
        ),
    )
    observed_pids: list[int] = []
    try:
        result = execute_plan(build_plan(request, tmp_path), tmp_path)
        observed_pids = [int(item.name) for item in pid_directory.iterdir()]
        assert len(observed_pids) == 2
        assert all(not _pid_is_running(pid) for pid in observed_pids)
        assert result.status.value == "NOT_VERIFIED"
        assert all(item.process.termination == "SIGKILL" for item in result.servers)
        assert all(
            item.process.containment is not None
            and item.process.containment.identities_observed >= 2
            and item.process.containment.waitable_children_reaped >= 1
            and item.process.containment.descendants_remaining == 0
            and item.process.containment.streams_eof
            for item in result.servers
        )
    finally:
        observed_pids.extend(
            int(item.name)
            for item in pid_directory.iterdir()
            if int(item.name) not in observed_pids
        )
        for pid in observed_pids:
            if _pid_is_running(pid):
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)


def test_version_double_fork_session_escape_is_adopted_and_reaped(tmp_path: Path) -> None:
    pid_path = tmp_path / "double-fork-descendant.pid"
    daemon_code = (
        "import os,pathlib,time; "
        "pid=os.fork(); "
        "os._exit(0) if pid else None; "
        "os.setsid(); "
        "pid=os.fork(); "
        "os._exit(0) if pid else None; "
        f"pathlib.Path({str(pid_path)!r}).write_text(next(x for x in "
        "open('/proc/self/status') if x.startswith('NSpid:')).split()[1]); "
        "time.sleep(30)"
    )
    request = _isolated_request(
        tmp_path,
        (
            "print(VERSION)\n        return 0",
            "__import__('subprocess').Popen([sys.executable, '-c', "
            f"{daemon_code!r}], stdin=__import__('subprocess').DEVNULL, "
            "stdout=__import__('subprocess').DEVNULL, "
            "stderr=__import__('subprocess').DEVNULL)\n        "
            f"ready = Path({str(pid_path)!r})\n        "
            "while not ready.exists():\n            __import__('time').sleep(0.01)\n        "
            "print(VERSION)\n        return 0",
        ),
    )
    daemon_pid: int | None = None
    try:
        with pytest.raises(OmivInputError, match="descendants remained.*were contained"):
            execute_plan(build_plan(request, tmp_path), tmp_path)
        daemon_pid = int(pid_path.read_text(encoding="utf-8"))
        assert not _pid_is_running(daemon_pid)
    finally:
        if daemon_pid is None and pid_path.exists():
            daemon_pid = int(pid_path.read_text(encoding="utf-8"))
        if daemon_pid is not None and _pid_is_running(daemon_pid):
            with suppress(ProcessLookupError):
                os.kill(daemon_pid, signal.SIGKILL)


def test_containment_setup_unavailable_fails_before_controlled_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "leader-started"
    request = _isolated_request(
        tmp_path,
        (
            "print(VERSION)\n        return 0",
            f"Path({str(marker)!r}).write_text('started')\n        "
            "print(VERSION)\n        return 0",
        ),
    )
    plan = build_plan(request, tmp_path)

    def unavailable() -> None:
        raise OmivInputError("controller-owned descendant containment is unavailable")

    monkeypatch.setattr(
        "omiv.runtime_compatibility.operations._require_containment_platform", unavailable
    )
    with pytest.raises(OmivInputError, match="containment is unavailable"):
        execute_plan(plan, tmp_path)
    assert not marker.exists()
    assert not list(tmp_path.glob(".omiv-controlled-runtime-*"))


def test_unrelated_preexisting_process_remains_alive_and_unreaped(tmp_path: Path) -> None:
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        request = _isolated_request(tmp_path, ("VERSION = ", "VERSION = "))
        result = execute_plan(build_plan(request, tmp_path), tmp_path)
        assert result.status.value == "VERIFIED_WITHIN_PROFILE"
        assert unrelated.poll() is None
    finally:
        if unrelated.poll() is None:
            unrelated.kill()
        unrelated.wait(timeout=2)


def test_offline_rehash_cannot_claim_cleanup_with_retained_descendant(
    evidence: ControlledEvidence, tmp_path: Path
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    containment = value["servers"][0]["process"]["containment"]
    containment["descendants_remaining"] = 1
    containment["cleanup_complete"] = True
    value["status"] = "VERIFIED_WITHIN_PROFILE"
    _rehash(value)
    path = tmp_path / "retained-descendant-claimed-clean.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("atomic_launch_tested", False),
        ("preexec_gate", "NONE"),
        ("control_protocol", "UNBOUNDED_JSON"),
        ("capture_protocol", "BASE64_CONTROL_FRAME"),
        ("stdout_complete", False),
        ("stdout_observed_bytes", 1),
    ],
)
def test_offline_cleanup_requires_coherent_atomic_launch_and_stream_observations(
    evidence: ControlledEvidence,
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    value = json.loads(json.dumps(evidence.model_dump(mode="json", by_alias=True)))
    value["servers"][0]["process"]["containment"][field] = replacement
    _rehash(value)
    path = tmp_path / f"incoherent-containment-{field}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(OmivInputError, match="invalid controlled runtime evidence"):
        load_evidence(path)


def test_http_exchange_uses_one_absolute_deadline_against_dribble_peer() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = int(listener.getsockname()[1])

    def dribble() -> None:
        connection, _address = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 20\r\nConnection: close\r\n\r\n"
            )
            for byte in b'{"status":"ok"}     ':
                try:
                    connection.send(bytes([byte]))
                except OSError:
                    return
                time.sleep(0.15)

    worker = threading.Thread(target=dribble, daemon=True)
    worker.start()
    started = time.monotonic()
    try:
        with pytest.raises(OmivInputError, match="within bounds"):
            _http_exchange(
                port,
                "GET",
                "/health",
                None,
                deadline=time.monotonic() + 1,
                request_maximum=256,
                response_maximum=256,
                max_nodes=16,
            )
    finally:
        listener.close()
    assert time.monotonic() - started < 1.8


def test_image_declaration_and_encoded_envelope_are_validated_before_execution() -> None:
    value = json.loads(REQUEST.read_text(encoding="utf-8"))
    value["limits"]["max_artifact_bytes"] = 1024**4
    value["limits"]["max_request_bytes"] = 4 * 1024 * 1024
    image = next(item for item in value["artifacts"] if item["role"] == "IMAGE")
    image["size"] = 1024**4
    with pytest.raises(ValueError, match="encoded IMAGE request"):
        ControlledRequest.model_validate(value)

    value = json.loads(REQUEST.read_text(encoding="utf-8"))
    value["limits"]["max_request_bytes"] = 256
    image = next(item for item in value["artifacts"] if item["role"] == "IMAGE")
    probe_value = next(item for item in value["probes"] if item["modality"] == "IMAGE")
    probe = load_request(REQUEST).probes[1]
    first_rejected = next(
        size
        for size in range(1, 512)
        if controlled_image_completion_request_bytes(probe, size) > 256
    )
    image["size"] = first_rejected - 1
    value["limits"]["max_artifact_bytes"] = first_rejected
    accepted = ControlledRequest.model_validate(value)
    assert controlled_image_completion_request_bytes(accepted.probes[1], first_rejected - 1) <= 256
    image["size"] = first_rejected
    with pytest.raises(ValueError, match="encoded IMAGE request"):
        ControlledRequest.model_validate(value)
    assert probe_value["probe_id"] == accepted.probes[1].probe_id


def test_image_actual_size_drift_and_whole_file_parent_reads_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _isolated_request(tmp_path, ("VERSION = ", "VERSION = "))
    plan = build_plan(request, tmp_path)
    image = next(item for item in request.artifacts if item.role.value == "IMAGE")
    with (tmp_path / image.path).open("ab") as handle:
        handle.write(b"drift")
    with pytest.raises(OmivInputError, match="size differs"):
        execute_plan(plan, tmp_path)

    clean_root = tmp_path / "clean"
    clean_root.mkdir()
    clean_request = _isolated_request(clean_root, ("VERSION = ", "VERSION = "))
    clean_plan = build_plan(clean_request, clean_root)

    def forbidden_read_bytes(_path: Path) -> bytes:
        raise AssertionError("controller must not use whole-file Path.read_bytes")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    result = execute_plan(clean_plan, clean_root)
    assert result.status.value == "VERIFIED_WITHIN_PROFILE"


@pytest.mark.parametrize(
    "unsafe_issue",
    [
        "/" + "home/private/operator-secret/runtime",
        "https://private.example.invalid/runtime",
        "Authorization: Bearer operator-secret-value",
        "internal operator incident detail",
    ],
)
def test_binding_issues_are_canonical_private_safe_and_rehashed_injections_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_issue: str
) -> None:
    request = load_request(REQUEST)
    private = "/" + "home/private/operator-secret/runtime"

    def fail_hash(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise OSError(private)

    monkeypatch.setattr("omiv.runtime_compatibility.operations._hash_regular_file", fail_hash)
    blocked = build_plan(request, ROOT)
    assert blocked.status.value == "BLOCKED"
    assert private not in json.dumps(blocked.model_dump(mode="json", by_alias=True))
    assert set(blocked.executable.issues) == {
        "Local input could not be inspected under bounded controls."
    }

    value = json.loads(json.dumps(blocked.model_dump(mode="json", by_alias=True)))
    value["executable"]["issues"] = [unsafe_issue]
    _rehash_plan(value)
    path = tmp_path / "private-issue-plan.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "must-not-exist.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "run",
            "--plan",
            str(path),
            "--root",
            str(ROOT),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert unsafe_issue not in result.output
    assert not output.exists()
