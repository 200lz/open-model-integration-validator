"""Offline import and verification of reviewed llama.cpp/CUDA observations."""

from __future__ import annotations

import codecs
import csv
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypedDict

from pydantic import BaseModel, ValidationError

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path
from omiv.reference_preflight.models import ReferencePreflightEvidence
from omiv.runtime.models import _unsafe as _canonical_runtime_value_is_unsafe
from omiv.runtime_compatibility.external_models import (
    CAPTURE_PROFILE,
    ArtifactControl,
    ArtifactIdentityObservation,
    ArtifactSourceRecord,
    AttemptControl,
    AttemptDisposition,
    AttemptKind,
    AttemptObservation,
    AttemptSourceRecord,
    CanonicalSourceRecord,
    DFlashActivationObservation,
    EnvironmentObservation,
    ExternalFinding,
    ExternalObservationControl,
    ExternalOverallStatus,
    ExternalProjection,
    ExternalRuntimeObservationEvidence,
    ExternalSkip,
    ExternalStatus,
    FindingSourceFact,
    InputBindingObservation,
    ManifestObservation,
    PredicateSourceFact,
    RuntimeIdentityObservation,
    RuntimeSourceRecord,
    SourceIdentityObservation,
    SourceMemberBinding,
    StageObservation,
    StreamObservation,
    TelemetrySample,
    TelemetrySummary,
)
from omiv.safe_write import atomic_write_text

MAX_CONTROL_BYTES = 2 * 1024 * 1024
_READ_CHUNK = 64 * 1024
_MAX_TELEMETRY_ROWS = 10_000
_MAX_TELEMETRY_COLUMNS = 8
_MAX_REFERENCE_BYTES = 2 * 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_ARGV_BYTES = 128 * 1024
_MAX_STREAM_BYTES = 2 * 1024 * 1024
_MAX_TELEMETRY_BYTES = 1024 * 1024
_MAX_SMALL_TEXT_BYTES = 64 * 1024
_MAX_BUILD_TEXT_BYTES = 512 * 1024
_MAX_FINDING_SOURCE_BYTES = 512 * 1024
_PROCESS_DURATION_TOLERANCE_MS = 25
_MANIFEST_RE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9._/-]+)\n")
_UTC_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\.(\d{9})Z")
_TELEMETRY_TIME_RE = re.compile(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{3}")
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:^|[^a-z])(?:secret|token|password|passwd|credential|private[_-]?key|"
    r"access[_-]?key|api[_-]?key)(?:$|[^a-z])"
)
_URL_RE = re.compile(r"(?i)(?:https?|ssh|ftp|wss?)://")
# A slash begins an absolute POSIX path when it is at the start of the value or
# follows anything outside the portable path-token alphabet.  This is a lexical
# boundary definition, not a delimiter allowlist: whitespace and every punctuation
# character not named here (including comma, semicolon, colon, brackets, quotes,
# and equals) are boundaries.  A slash within ``artifacts/model.gguf`` is not.
_PATH_TOKEN_ALPHABET = r"A-Za-z0-9._~+@%/-"
_ABSOLUTE_POSIX_PATH_RE = re.compile(rf"(?<![{_PATH_TOKEN_ALPHABET}])/(?:$|[^\s])")
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(rf"(?i)(?<![{_PATH_TOKEN_ALPHABET}])(?:[a-z]:[\\/]|\\\\)")

# Bounded external-runtime credential signatures.  The first six inventory groups
# mirror tools/audit_public_release_readiness.py::_history_paths_and_credentials;
# the remaining groups incorporate the stricter credential/privacy signatures used
# by OMIV's publication, walkthrough, trust, runtime, and security scans.  Production
# code deliberately does not import a tool module.
EXTERNAL_PRIVACY_POLICY_VERSION = "omiv.external-runtime-privacy.v1"


def _word_bounded_credential(body: str) -> str:
    """Apply the release audit's Unicode-aware ``\\b...\\b`` token boundary."""

    return rf"\b(?:{body})\b"


def _left_word_bounded_credential(body: str) -> str:
    """Apply the release audit's Unicode-aware leading ``\\b`` boundary."""

    return rf"\b(?:{body})"


EXTERNAL_CREDENTIAL_FAMILY_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        "aws_access_key",
        _word_bounded_credential(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ),
    (
        "github_token",
        _word_bounded_credential(r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    ),
    (
        "hugging_face_token",
        _word_bounded_credential(r"hf_[A-Za-z0-9]{20,}"),
    ),
    (
        "openai_style_token",
        _word_bounded_credential(r"sk-[A-Za-z0-9_-]{20,}"),
    ),
    (
        "slack_token",
        _word_bounded_credential(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ),
    (
        "private_key",
        r"(?i:-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)* )?PRIVATE KEY-----)",
    ),
    (
        "authorization_header",
        _left_word_bounded_credential(
            r"(?i:(?:authorization\s*:\s*(?:bearer|basic)|bearer)\s+\S+)"
        ),
    ),
    (
        "signed_url_or_access_field",
        _left_word_bounded_credential(
            r"(?i:(?:x-amz-[a-z0-9_-]+|signature|key-pair-id|access[_-]?token|"
            r"refresh[_-]?token|token|expires)\s*=\s*[^\s&]+)"
        ),
    ),
    (
        "generic_credential_assignment",
        _left_word_bounded_credential(
            r"(?i:(?:x-api-key|api[_-]?key|apikey|password|passwd|client[_-]?secret|"
            r"secret[_-]?key|access[_-]?key|credential)\s*[:=]\s*\S+)"
        ),
    ),
    (
        "google_api_key",
        _word_bounded_credential(r"AIza[0-9A-Za-z_-]{35}"),
    ),
    (
        "google_oauth_credential",
        _word_bounded_credential(r"(?:ya29\.[A-Za-z0-9_-]{20,}|GOCSPX-[A-Za-z0-9_-]{20,})"),
    ),
)
_EXTERNAL_CREDENTIAL_SIGNATURES = tuple(
    (name, re.compile(pattern)) for name, pattern in EXTERNAL_CREDENTIAL_FAMILY_PATTERNS
)
_PRIVATE_HOST_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:private[_-]?host|localhost|"
    r"[a-z0-9.-]*\.(?:internal|local)|"
    r"10(?:\.[0-9]{1,3}){3}|192\.168(?:\.[0-9]{1,3}){2}|"
    r"172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2})(?:$|[^a-z0-9])"
)
_USER_HOME_RE = re.compile(r"(?i)(?:^|[^a-z0-9])(?:home|users?)(?:$|[^a-z0-9])")
_CORRECTION_TEXT = (
    "added --single-turn per pinned executable help after preserved attempt hit stdout cap "
    "in auto-enabled conversation mode"
)
_DIAGNOSTIC_TEXT = (
    "default verbosity did not emit positive DFlash load identity; pinned source logs it at INFO"
)

_VALUE_OPTIONS = {
    "--model",
    "--prompt",
    "--seed",
    "--temp",
    "--n-predict",
    "--ctx-size",
    "--gpu-layers",
    "--device",
    "--color",
    "--mmproj",
    "--image",
    "--spec-type",
    "--spec-draft-model",
    "--spec-draft-ngl",
    "--spec-draft-device",
    "--spec-draft-n-max",
    "--log-verbosity",
    "--log-colors",
}
_BOOLEAN_OPTIONS = {
    "--simple-io",
    "--no-display-prompt",
    "--no-warmup",
    "--single-turn",
    "--no-mmproj",
    "--log-prefix",
    "--log-timestamps",
}
_PATH_OPTIONS = {"--model", "--mmproj", "--image", "--spec-draft-model"}


class _ProcessFacts(TypedDict):
    return_code: int
    timed_out: bool
    duration_ms: int
    start_utc: str
    end_utc: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_complete: bool | None
    stdout_overflow: bool | None
    stderr_complete: bool | None
    stderr_overflow: bool | None


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


def _contains_external_credential_signature(value: str) -> bool:
    return any(pattern.search(value) for _, pattern in _EXTERNAL_CREDENTIAL_SIGNATURES)


def _reject_sensitive_text(value: str, label: str) -> None:
    if (
        _canonical_runtime_value_is_unsafe(value)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or _SECRET_KEY_RE.search(value)
        or _contains_external_credential_signature(value)
        or _URL_RE.search(value)
        or _ABSOLUTE_POSIX_PATH_RE.search(value)
        or _WINDOWS_ABSOLUTE_PATH_RE.search(value)
        or _PRIVATE_HOST_RE.search(value)
        or _USER_HOME_RE.search(value)
        or "known_hosts" in value.casefold()
        or "endpoint" in value.casefold()
        or "../" in value
        or "..\\" in value
    ):
        raise OmivInputError(f"{label} contains forbidden private or path-like content")


def _validate_control_privacy(control: ExternalObservationControl) -> None:
    _reject_sensitive_text(control.control_id, "control identifier")
    _reject_sensitive_text(control.plan_id, "plan identifier")
    _reject_sensitive_text(control.runtime.version, "runtime version")
    _reject_sensitive_text(control.runtime.cuda_version, "CUDA version")
    for artifact in control.artifacts:
        _reject_sensitive_text(artifact.artifact_id, "artifact identifier")
    for attempt in control.attempts:
        _reject_sensitive_text(attempt.attempt_id, "attempt identifier")
        if attempt.supersedes is not None:
            _reject_sensitive_text(attempt.supersedes, "retry target")
        if attempt.retry_reason is not None:
            _reject_sensitive_text(attempt.retry_reason, "retry reason")
        if attempt.output_predicate.value is not None:
            _reject_sensitive_text(attempt.output_predicate.value, "output predicate")
    for finding in control.findings:
        _reject_sensitive_text(finding.code, "finding code")
        _reject_sensitive_text(finding.exact_text, "finding text")
        _reject_sensitive_text(finding.detail, "finding detail")
    for skip in control.skips:
        _reject_sensitive_text(skip.target, "skip target")
        _reject_sensitive_text(skip.reason, "skip reason")
    for member in _required_members(control):
        _reject_sensitive_text(member, "evidence member path")


def load_external_control(path: Path) -> ExternalObservationControl:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        control = ExternalObservationControl.model_validate(value)
        _validate_control_privacy(control)
        return control
    except (ValidationError, ValueError) as exc:
        raise OmivInputError("invalid external runtime observation control") from exc


def load_external_evidence(path: Path) -> ExternalRuntimeObservationEvidence:
    value, _ = load_bounded_json(path, max_bytes=64 * 1024 * 1024)
    try:
        evidence = ExternalRuntimeObservationEvidence.model_validate(value)
        verify_external_evidence(evidence)
        return evidence
    except OmivInputError:
        raise
    except (ValidationError, ValueError) as exc:
        raise OmivInputError("invalid external runtime observation evidence") from exc


def write_external_evidence(evidence: ExternalRuntimeObservationEvidence, output: Path) -> None:
    atomic_write_text(output, _pretty(evidence))


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
    return (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns)


def _directory_identity(item: os.stat_result) -> tuple[int, int, int]:
    return (item.st_dev, item.st_ino, item.st_mode)


def _open_root(root: Path) -> tuple[int, tuple[int, int, int]]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OmivInputError("safe descriptor-relative manifest traversal is unsupported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
        opened = os.fstat(descriptor)
        named = root.lstat()
    except OSError as exc:
        raise OmivInputError("cannot safely open manifest root") from exc
    if not stat.S_ISDIR(opened.st_mode) or _directory_identity(opened) != _directory_identity(
        named
    ):
        os.close(descriptor)
        raise OmivInputError("manifest root identity is unstable or not a directory")
    return descriptor, _directory_identity(opened)


def _revalidate_root(root: Path, root_fd: int, expected: tuple[int, int, int]) -> None:
    try:
        opened = os.fstat(root_fd)
        named = root.lstat()
    except OSError as exc:
        raise OmivInputError("manifest root identity changed during verification") from exc
    if _directory_identity(opened) != expected or _directory_identity(named) != expected:
        raise OmivInputError("manifest root identity changed during verification")


@contextmanager
def _regular_fd_at(
    root_fd: int, portable: str, label: str
) -> Iterator[tuple[int, int, str, os.stat_result]]:
    validate_portable_path(portable)
    components = portable.split("/")
    parent_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = next_fd
        leaf = components[-1]
        file_fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise OmivInputError(f"{label} is not a regular file")
            yield file_fd, parent_fd, leaf, before
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise OmivInputError(f"cannot safely read {label}") from exc
    finally:
        os.close(parent_fd)


def _check_stable_read(
    file_fd: int,
    parent_fd: int,
    leaf: str,
    before: os.stat_result,
    observed: int,
    label: str,
) -> None:
    after = os.fstat(file_fd)
    member_now = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    if _identity(before) != _identity(after) or _identity(after) != _identity(member_now):
        raise OmivInputError(f"{label} identity changed while being read")
    if observed != after.st_size:
        raise OmivInputError(f"{label} size changed while being read")


def _read_regular_at(root_fd: int, portable: str, limit: int, label: str) -> bytes:
    with _regular_fd_at(root_fd, portable, label) as (file_fd, parent_fd, leaf, before):
        if before.st_size > limit:
            raise OmivInputError(f"{label} exceeds byte limit {limit}: {before.st_size}")
        retained = bytearray()
        observed = 0
        while True:
            chunk = os.read(file_fd, _READ_CHUNK)
            if not chunk:
                break
            observed += len(chunk)
            if observed > limit:
                raise OmivInputError(f"{label} grew beyond byte limit {limit}")
            retained.extend(chunk)
        _check_stable_read(file_fd, parent_fd, leaf, before, observed, label)
        return bytes(retained)


def _hash_regular_at(root_fd: int, portable: str, limit: int, label: str) -> SourceMemberBinding:
    with _regular_fd_at(root_fd, portable, label) as (file_fd, parent_fd, leaf, before):
        if before.st_size > limit:
            raise OmivInputError(f"{label} exceeds byte limit {limit}: {before.st_size}")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(file_fd, _READ_CHUNK)
            if not chunk:
                break
            observed += len(chunk)
            if observed > limit:
                raise OmivInputError(f"{label} grew beyond byte limit {limit}")
            digest.update(chunk)
        _check_stable_read(file_fd, parent_fd, leaf, before, observed, label)
        return SourceMemberBinding(path=portable, size=observed, sha256=digest.hexdigest())


def _read_bound_member(
    root_fd: int,
    binding: SourceMemberBinding,
    control: ExternalObservationControl,
    role_limit: int,
    label: str,
) -> bytes:
    raw = _read_regular_at(
        root_fd,
        binding.path,
        min(control.max_member_bytes, role_limit),
        label,
    )
    if len(raw) != binding.size or hashlib.sha256(raw).hexdigest() != binding.sha256:
        raise OmivInputError(f"{label} changed after manifest verification")
    return raw


def _parse_manifest(raw: bytes, maximum_files: int) -> list[tuple[str, str]]:
    if not raw or not raw.endswith(b"\n"):
        raise OmivInputError("manifest must be nonempty and newline terminated")
    entries: list[tuple[str, str]] = []
    offset = 0
    for match in _MANIFEST_RE.finditer(raw):
        if match.start() != offset:
            raise OmivInputError("manifest contains a malformed entry")
        path = match.group(2).decode("ascii")
        if path == "SHA256SUMS":
            raise OmivInputError("manifest cannot list itself")
        _reject_sensitive_text(path, "manifest member path")
        entries.append((path, match.group(1).decode("ascii")))
        if len(entries) > maximum_files:
            raise OmivInputError("manifest exceeds file-count bound")
        offset = match.end()
    if offset != len(raw):
        raise OmivInputError("manifest contains a malformed entry")
    try:
        ordered = validate_path_set(tuple(path for path, _ in entries))
    except ValueError as exc:
        raise OmivInputError(f"unsafe manifest member set: {exc}") from exc
    if tuple(path for path, _ in entries) != ordered:
        raise OmivInputError("manifest entries are not in canonical portable order")
    return entries


def _actual_files_fd(root_fd: int, maximum_files: int) -> set[str]:
    files: set[str] = set()
    stack: list[tuple[int, str]] = [(os.dup(root_fd), "")]
    seen_entries = 0
    entry_limit = maximum_files * 4 + 64
    try:
        while stack:
            directory_fd, prefix = stack.pop()
            try:
                try:
                    iterator = os.scandir(directory_fd)
                except OSError as exc:
                    raise OmivInputError("cannot enumerate manifest root") from exc
                with iterator:
                    for entry in iterator:
                        seen_entries += 1
                        if seen_entries > entry_limit:
                            raise OmivInputError("manifest root exceeds bounded entry count")
                        relative = f"{prefix}/{entry.name}" if prefix else entry.name
                        try:
                            validate_portable_path(relative)
                            item = entry.stat(follow_symlinks=False)
                        except (OSError, ValueError) as exc:
                            raise OmivInputError("manifest root contains an unsafe entry") from exc
                        if stat.S_ISLNK(item.st_mode):
                            raise OmivInputError("manifest root contains a symlink")
                        if stat.S_ISDIR(item.st_mode):
                            try:
                                child_fd = os.open(
                                    entry.name,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory_fd,
                                )
                            except OSError as exc:
                                raise OmivInputError("manifest directory identity changed") from exc
                            if _directory_identity(os.fstat(child_fd)) != _directory_identity(item):
                                os.close(child_fd)
                                raise OmivInputError("manifest directory identity changed")
                            stack.append((child_fd, relative))
                        elif stat.S_ISREG(item.st_mode):
                            files.add(relative)
                        else:
                            raise OmivInputError("manifest root contains a nonregular object")
            finally:
                os.close(directory_fd)
    finally:
        for descriptor, _ in stack:
            os.close(descriptor)
    return files


def _verify_manifest_root_fd(
    control: ExternalObservationControl, root_fd: int
) -> tuple[ManifestObservation, dict[str, SourceMemberBinding], bytes, set[str]]:
    manifest_raw = _read_regular_at(
        root_fd,
        control.manifest_member,
        min(control.max_member_bytes, _MAX_MANIFEST_BYTES),
        "manifest",
    )
    if hashlib.sha256(manifest_raw).hexdigest() != control.manifest_sha256:
        raise OmivInputError("manifest digest mismatch")
    entries = _parse_manifest(manifest_raw, control.max_files)
    listed = {path for path, _ in entries}
    expected_actual = listed | {control.manifest_member}
    if control.complete_set and _actual_files_fd(root_fd, control.max_files) != expected_actual:
        raise OmivInputError("manifest complete-set mismatch")
    binding_by_path: dict[str, SourceMemberBinding] = {}
    total = 0
    for portable, expected_digest in entries:
        binding = _hash_regular_at(
            root_fd, portable, control.max_member_bytes, f"manifest member {portable}"
        )
        if binding.sha256 != expected_digest:
            raise OmivInputError(f"manifest member digest mismatch: {portable}")
        total += binding.size
        if total > control.max_total_bytes:
            raise OmivInputError("manifest members exceed cumulative byte bound")
        binding_by_path[portable] = binding
    members = sorted(binding_by_path.values(), key=lambda item: item.path.encode("utf-8"))
    return (
        ManifestObservation(
            manifest_sha256=control.manifest_sha256,
            member_count=len(members),
            total_bytes=total,
            members=members,
        ),
        binding_by_path,
        manifest_raw,
        expected_actual,
    )


def verify_manifest_root(
    control: ExternalObservationControl, root: Path
) -> tuple[ManifestObservation, dict[str, SourceMemberBinding]]:
    root_fd, root_identity = _open_root(root)
    try:
        manifest, bindings, manifest_raw, expected_actual = _verify_manifest_root_fd(
            control, root_fd
        )
        if control.complete_set and _actual_files_fd(root_fd, control.max_files) != expected_actual:
            raise OmivInputError("manifest membership changed during verification")
        if (
            _read_regular_at(
                root_fd,
                control.manifest_member,
                min(control.max_member_bytes, _MAX_MANIFEST_BYTES),
                "manifest",
            )
            != manifest_raw
        ):
            raise OmivInputError("manifest changed during verification")
        _revalidate_root(root, root_fd, root_identity)
        return manifest, bindings
    finally:
        os.close(root_fd)


def _text(raw: bytes, member: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OmivInputError(f"selected evidence member is not UTF-8: {member}") from exc


def _key_values(raw: bytes, member: str, *, maximum_lines: int = 32) -> dict[str, str]:
    text = _text(raw, member)
    result: dict[str, str] = {}
    lines = text.splitlines()
    if not lines or len(lines) > maximum_lines:
        raise OmivInputError(f"malformed key-value evidence in {member}")
    for line in lines:
        if not line or "=" not in line:
            raise OmivInputError(f"malformed key-value evidence in {member}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key) or key in result or len(value) > 4096:
            raise OmivInputError(f"malformed or duplicate key-value evidence in {member}")
        result[key] = value
    return result


def _parse_source_identity(
    control: ExternalObservationControl, raw: bytes, source: SourceMemberBinding
) -> SourceIdentityObservation:
    lines = _text(raw, source.path).splitlines()
    if len(lines) < 4 or not re.fullmatch(r"https://[^\s]{1,2000}", lines[0]):
        raise OmivInputError("source identity has an unsupported grammar")
    if lines[1] != control.source_commit or lines[2] != control.source_commit:
        raise OmivInputError("source commit binding mismatch")
    if lines[3] != control.source_tree or f"tree {control.source_tree}" not in lines:
        raise OmivInputError("source tree binding mismatch")
    return SourceIdentityObservation(
        commit=control.source_commit,
        tree=control.source_tree,
        signature=control.source_signature,
        source=source,
    )


def _parse_artifact(
    control: ArtifactControl,
    raw: bytes,
    source: SourceMemberBinding,
    payload_source: SourceMemberBinding | None,
    planned: Any,
) -> ArtifactSourceRecord:
    lines = _text(raw, source.path).splitlines()
    expected_keys: tuple[str, ...]
    if control.observation_format == "BARE_FILENAME_V1":
        expected_keys = ("observed_bytes", "observed_sha256", "transfer_exit", "source_url")
        if len(lines) != 5 or lines[0] != planned.path:
            raise OmivInputError(f"artifact filename mismatch for {control.artifact_id}")
        field_lines = lines[1:]
        filename = lines[0]
    else:
        expected_keys = (
            "artifact_role",
            "filename",
            "source_repository",
            "pinned_revision",
            "source_url",
            "transfer_exit",
            "observed_bytes",
            "expected_bytes",
            "observed_sha256",
            "expected_sha256",
        )
        if len(lines) != 11 or lines[-1] != "MATCH":
            raise OmivInputError(
                f"malformed labeled artifact observation for {control.artifact_id}"
            )
        field_lines = lines[:-1]
        filename = ""
    values: dict[str, str] = {}
    for expected_key, line in zip(expected_keys, field_lines, strict=True):
        if "=" not in line:
            raise OmivInputError(f"malformed artifact observation for {control.artifact_id}")
        key, value = line.split("=", 1)
        if key != expected_key or not value or key in values:
            raise OmivInputError(f"artifact observation grammar mismatch for {control.artifact_id}")
        values[key] = value
    if control.observation_format == "LABELED_V1":
        filename = values["filename"]
        if (
            values["artifact_role"] != control.role
            or re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", values["source_repository"]) is None
            or re.fullmatch(r"[0-9a-f]{40}", values["pinned_revision"]) is None
            or values["expected_bytes"] != values["observed_bytes"]
            or values["expected_sha256"] != values["observed_sha256"]
        ):
            raise OmivInputError(
                f"labeled artifact fields are incoherent for {control.artifact_id}"
            )
    if re.fullmatch(r"https://[^\s]{1,4096}", values["source_url"]) is None or values[
        "transfer_exit"
    ] not in {"0", "transfer_exit=0"}:
        raise OmivInputError(f"artifact transfer fields are invalid for {control.artifact_id}")
    try:
        size = int(values["observed_bytes"])
    except ValueError as exc:
        raise OmivInputError("artifact size is not an integer") from exc
    digest = values["observed_sha256"]
    if (
        control.role != planned.role.value
        or filename != planned.path
        or size != planned.declared_size
        or digest != planned.provider_identity
    ):
        raise OmivInputError(f"artifact report differs from plan for {control.artifact_id}")
    if payload_source is not None and (
        payload_source.size != planned.declared_size
        or payload_source.sha256 != planned.provider_identity
    ):
        raise OmivInputError(f"artifact payload differs from plan for {control.artifact_id}")
    return ArtifactSourceRecord(
        artifact_id=control.artifact_id,
        role=control.role,
        reported_filename=filename,
        reported_size=size,
        reported_sha256=digest,
        report_source=source,
        payload_source=payload_source,
    )


def _parse_runtime(
    control: ExternalObservationControl,
    build_raw: bytes,
    version_raw: bytes,
    bindings: dict[str, SourceMemberBinding],
) -> RuntimeSourceRecord:
    runtime = control.runtime
    build = _text(build_raw, runtime.build_identity_member)
    version = _text(version_raw, runtime.version_member)
    required = (
        f"\n{runtime.runtime_commit}\n",
        f"\n{runtime.version}\n",
        f"V{runtime.cuda_version}",
        "LLAMA_BUILD_UI:BOOL=OFF",
        "LLAMA_USE_PREBUILT_UI:BOOL=OFF",
        f"{runtime.executable_sha256}  ",
    )
    if any(item not in build for item in required):
        raise OmivInputError("runtime build identity does not match its exact pins")
    if f"({runtime.runtime_commit[:7]})" not in version:
        raise OmivInputError("runtime version output does not match runtime commit")
    return RuntimeSourceRecord(
        name=runtime.name,
        version=runtime.version,
        commit=runtime.runtime_commit,
        executable_sha256=runtime.executable_sha256,
        cuda_version=runtime.cuda_version,
        backend=runtime.backend,
        ui_disabled=True,
        build_source=bindings[runtime.build_identity_member],
        version_source=bindings[runtime.version_member],
    )


def _parse_digest_record(raw: bytes, member: str) -> str:
    match = re.fullmatch(r"([0-9a-f]{64})  [^\n]{1,4096}\n?", _text(raw, member))
    if match is None:
        raise OmivInputError(f"malformed digest record: {member}")
    return match.group(1)


def _path_basename(value: str) -> str:
    if (
        not value
        or "\x00" in value
        or _URL_RE.search(value)
        or _contains_external_credential_signature(value)
        or "../" in value
        or "..\\" in value
    ):
        raise OmivInputError("captured path value is unsafe")
    parts = re.split(r"[\\/]", value)
    if any(part == ".." for part in parts) or not parts[-1]:
        raise OmivInputError("captured path value is unsafe")
    return parts[-1]


def _bind_path(value: str, expected_basename: str, label: str) -> str:
    if _path_basename(value) != expected_basename:
        raise OmivInputError(f"captured {label} path does not match its reviewed identity")
    return value


def _parse_environment(raw: bytes, member: str, control: AttemptControl) -> EnvironmentObservation:
    values = _key_values(raw, member)
    allowed = {
        "CUDA_VISIBLE_DEVICES",
        "LANG",
        "LC_ALL",
        "stdout_stderr_file_cap_bytes",
        "correction",
        "diagnostic_reason",
    }
    if set(values) - allowed:
        raise OmivInputError("captured environment contains an unsupported key")
    required = {"CUDA_VISIBLE_DEVICES", "LANG", "LC_ALL", "stdout_stderr_file_cap_bytes"}
    if not required.issubset(values):
        raise OmivInputError("captured environment lacks required typed facts")
    if (
        values["CUDA_VISIBLE_DEVICES"] != "UNSET"
        or values["LANG"] != "C.UTF-8"
        or values["LC_ALL"] != "C.UTF-8"
    ):
        raise OmivInputError("captured environment has unsupported values")
    try:
        cap = int(values["stdout_stderr_file_cap_bytes"])
    except ValueError as exc:
        raise OmivInputError("captured environment has an invalid stream cap") from exc
    correction: Literal["SINGLE_TURN_RETRY"] | None = None
    if "correction" in values:
        if control.supersedes is None or values["correction"] != _CORRECTION_TEXT:
            raise OmivInputError("captured environment has an unsupported correction fact")
        correction = "SINGLE_TURN_RETRY"
    if (control.supersedes is None) != (correction is None):
        raise OmivInputError("retry requires typed single-turn correction evidence")
    diagnostic_reason: Literal["DFLASH_INFO_ACTIVATION_CAPTURE"] | None = None
    if "diagnostic_reason" in values:
        if (
            control.positive_activation_member is None
            or values["diagnostic_reason"] != _DIAGNOSTIC_TEXT
        ):
            raise OmivInputError("captured environment has an unsupported diagnostic fact")
        diagnostic_reason = "DFLASH_INFO_ACTIVATION_CAPTURE"
    try:
        return EnvironmentObservation(
            cuda_visible_devices="UNSET",
            lang="C.UTF-8",
            lc_all="C.UTF-8",
            stream_cap_bytes=cap,
            correction=correction,
            correction_target=control.supersedes if correction is not None else None,
            diagnostic_reason=diagnostic_reason,
        )
    except ValidationError as exc:
        raise OmivInputError("captured stream cap is outside supported bounds") from exc


def _artifact_by_role(planned: dict[str, Any], role: str) -> Any:
    found = [item for item in planned.values() if item.role.value == role]
    if len(found) != 1:
        raise OmivInputError(f"canonical plan lacks exactly one {role} artifact")
    return found[0]


def _parse_input_bindings(
    raw: bytes,
    member: str,
    control: AttemptControl,
    planned: dict[str, Any],
    runtime: RuntimeSourceRecord,
    image_fixture: str,
    image_fixture_bytes: int,
    image_sha256: str,
) -> tuple[InputBindingObservation, dict[str, str]]:
    values = _key_values(raw, member)
    main = _artifact_by_role(planned, "MAIN_MODEL")
    projector = _artifact_by_role(planned, "PERCEPTION_ENCODER")
    draft = _artifact_by_role(planned, "DRAFTER")
    dflash = (
        control.kind == AttemptKind.DFLASH_TEXT or control.positive_activation_member is not None
    )
    image = control.kind == AttemptKind.IMAGE
    required = {
        "model_path",
        "model_bytes",
        "model_sha256",
        "projector_path",
        "draft_path",
        "executable_sha256",
    }
    optional = {"model_basename"}
    if image:
        required |= {
            "projector_bytes",
            "projector_sha256",
            "image_path",
            "image_bytes",
            "image_sha256",
        }
    if dflash:
        required |= {"draft_bytes", "draft_sha256", "spec_type"}
    if set(values) - required - optional or not required.issubset(values):
        raise OmivInputError("attempt input identities have missing or extra fields")
    try:
        main_size = int(values["model_bytes"])
    except ValueError as exc:
        raise OmivInputError("attempt main artifact size is invalid") from exc
    _bind_path(values["model_path"], main.path, "model")
    if values.get("model_basename", main.path) != main.path:
        raise OmivInputError("attempt main artifact basename mismatch")
    if (
        main_size != main.declared_size
        or values["model_sha256"] != main.provider_identity
        or values["executable_sha256"] != runtime.executable_sha256
    ):
        raise OmivInputError("attempt executable or main artifact identity mismatch")
    raw_paths = {"--model": values["model_path"]}
    projector_id = None
    draft_id = None
    fixture = None
    image_bytes = None
    if image:
        _bind_path(values["projector_path"], projector.path, "projector")
        _bind_path(values["image_path"], image_fixture.rsplit("/", 1)[-1], "image")
        try:
            projector_size = int(values["projector_bytes"])
            image_bytes = int(values["image_bytes"])
        except ValueError as exc:
            raise OmivInputError("attempt image/projector size is invalid") from exc
        if (
            projector_size != projector.declared_size
            or values["projector_sha256"] != projector.provider_identity
            or image_bytes != image_fixture_bytes
            or values["image_sha256"] != image_sha256
        ):
            raise OmivInputError("attempt projector or image identity mismatch")
        if values["draft_path"] != "NONE":
            raise OmivInputError("image attempt contains an unexpected draft input")
        raw_paths.update({"--mmproj": values["projector_path"], "--image": values["image_path"]})
        projector_id = projector.artifact_id
        fixture = image_fixture
    elif dflash:
        if values["projector_path"] != "NONE" or values["spec_type"] != "draft-dflash":
            raise OmivInputError("DFlash attempt has incoherent projector/spec inputs")
        _bind_path(values["draft_path"], draft.path, "draft")
        try:
            draft_size = int(values["draft_bytes"])
        except ValueError as exc:
            raise OmivInputError("attempt draft artifact size is invalid") from exc
        if draft_size != draft.declared_size or values["draft_sha256"] != draft.provider_identity:
            raise OmivInputError("attempt draft artifact identity mismatch")
        raw_paths["--spec-draft-model"] = values["draft_path"]
        draft_id = draft.artifact_id
    elif values["projector_path"] != "NONE" or values["draft_path"] != "NONE":
        raise OmivInputError("text attempt contains an unexpected role input")
    return (
        InputBindingObservation(
            executable_sha256=runtime.executable_sha256,
            main_artifact_id=main.artifact_id,
            projector_artifact_id=projector_id,
            draft_artifact_id=draft_id,
            image_fixture=fixture,
            image_bytes=image_bytes,
            image_sha256=image_sha256 if image else None,
        ),
        raw_paths,
    )


def _parse_option(argument: str) -> tuple[str, str | None]:
    if "=" in argument:
        option, value = argument.split("=", 1)
        if option not in _VALUE_OPTIONS or not value:
            raise OmivInputError("captured argv contains an unsupported option form")
        return option, value
    return argument, None


def _validate_scalar_option(option: str, value: str, expected_prompt: str) -> None:
    # This is the single path used for every non-member argv value during both
    # import normalization and offline reconstruction.
    _reject_sensitive_text(value, "argv scalar value")
    if option == "--prompt":
        if value != expected_prompt:
            raise OmivInputError("captured prompt differs from the reviewed plan")
        return
    if option in {"--seed", "--n-predict", "--ctx-size", "--spec-draft-n-max", "--log-verbosity"}:
        if not re.fullmatch(r"[0-9]{1,10}", value):
            raise OmivInputError("captured argv numeric option is invalid")
        return
    if option == "--temp":
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
            raise OmivInputError("captured temperature option is invalid")
        return
    allowed_tokens = {
        "--gpu-layers": r"(?:all|[0-9]{1,4})",
        "--device": r"[A-Za-z0-9._-]{1,64}",
        "--spec-type": r"draft-dflash",
        "--spec-draft-ngl": r"(?:all|[0-9]{1,4})",
        "--spec-draft-device": r"[A-Za-z0-9._-]{1,64}",
        "--log-colors": r"(?:on|off)",
        "--color": r"(?:on|off)",
    }
    pattern = allowed_tokens.get(option)
    if pattern is None or re.fullmatch(pattern, value) is None:
        raise OmivInputError("captured argv option value is unsupported")


def _parse_argv(
    raw_argv: list[str],
    control: AttemptControl,
    input_paths: dict[str, str],
    planned: dict[str, Any],
    expected_prompt: str,
) -> list[str]:
    if not raw_argv or len(raw_argv) > 128:
        raise OmivInputError("captured argv must be a bounded JSON string array")
    _bind_path(raw_argv[0], "llama-cli", "executable")
    normalized = ["{runtime:llama-cli}"]
    seen: set[str] = set()
    index = 1
    while index < len(raw_argv):
        argument = raw_argv[index]
        if "\x00" in argument or len(argument) > 32_768 or not argument.startswith("--"):
            raise OmivInputError("captured argv contains an unsafe positional argument")
        option, inline = _parse_option(argument)
        if option in seen:
            raise OmivInputError("captured argv contains a duplicate option")
        seen.add(option)
        if option in _BOOLEAN_OPTIONS:
            if inline is not None:
                raise OmivInputError("captured argv boolean option has a value")
            normalized.append(option)
            index += 1
            continue
        if option not in _VALUE_OPTIONS:
            raise OmivInputError("captured argv contains an unsupported option")
        if inline is None:
            index += 1
            if index >= len(raw_argv):
                raise OmivInputError("captured argv option is missing its value")
            value = raw_argv[index]
        else:
            value = inline
        if "\x00" in value or len(value) > 32_768:
            raise OmivInputError("captured argv contains an unsafe value")
        normalized.append(option)
        if option in _PATH_OPTIONS:
            expected_raw = input_paths.get(option)
            if expected_raw is None or value != expected_raw:
                raise OmivInputError("captured argv path differs from its typed input identity")
            if option == "--model":
                item = _artifact_by_role(planned, "MAIN_MODEL")
                normalized.append(f"{{artifact:{item.artifact_id}}}")
            elif option == "--mmproj":
                item = _artifact_by_role(planned, "PERCEPTION_ENCODER")
                normalized.append(f"{{artifact:{item.artifact_id}}}")
            elif option == "--spec-draft-model":
                item = _artifact_by_role(planned, "DRAFTER")
                normalized.append(f"{{artifact:{item.artifact_id}}}")
            else:
                normalized.append("{image:plan-fixture}")
        else:
            _validate_scalar_option(option, value, expected_prompt)
            normalized.append(value)
        index += 1
    image = control.kind == AttemptKind.IMAGE
    dflash = (
        control.kind == AttemptKind.DFLASH_TEXT or control.positive_activation_member is not None
    )
    required = {"--model", "--prompt"}
    if image:
        required |= {"--mmproj", "--image"}
    else:
        required.add("--no-mmproj")
    if dflash:
        required |= {"--spec-type", "--spec-draft-model"}
    if control.require_single_turn:
        required.add("--single-turn")
    forbidden = set()
    if not image:
        forbidden |= {"--mmproj", "--image"}
    if not dflash:
        forbidden |= {"--spec-type", "--spec-draft-model"}
    if image:
        forbidden.add("--no-mmproj")
    if not required.issubset(seen) or forbidden & seen:
        raise OmivInputError("captured argv role options differ from the attempt kind")
    return normalized


def _strict_utc_ns(value: str) -> int:
    match = _UTC_RE.fullmatch(value)
    if match is None:
        raise OmivInputError("process timestamp is invalid")
    try:
        base = datetime.strptime(f"{match.group(1)}T{match.group(2)}", "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise OmivInputError("process timestamp is invalid") from exc
    return int(base.timestamp()) * 1_000_000_000 + int(match.group(3))


def _parse_process(raw: bytes, member: str) -> _ProcessFacts:
    values = _key_values(raw, member, maximum_lines=12)
    required = {
        "exit_status",
        "timeout",
        "elapsed_ms",
        "start_utc",
        "end_utc",
        "stdout_bytes",
        "stderr_bytes",
    }
    completeness = {
        "stdout_complete",
        "stdout_overflow",
        "stderr_complete",
        "stderr_overflow",
    }
    if set(values) - required - completeness or not required.issubset(values):
        raise OmivInputError("process observation has an unsupported grammar")
    present = completeness & set(values)
    if present and present != completeness:
        raise OmivInputError("process completeness facts are only partially present")
    if values["timeout"] not in {"true", "false"}:
        raise OmivInputError("process timeout fact is invalid")
    try:
        return_code = int(values["exit_status"])
        duration_ms = int(values["elapsed_ms"])
        stdout_bytes = int(values["stdout_bytes"])
        stderr_bytes = int(values["stderr_bytes"])
        result: _ProcessFacts = {
            "return_code": return_code,
            "timed_out": values["timeout"] == "true",
            "duration_ms": duration_ms,
            "start_utc": values["start_utc"],
            "end_utc": values["end_utc"],
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "stdout_complete": None,
            "stdout_overflow": None,
            "stderr_complete": None,
            "stderr_overflow": None,
        }
    except ValueError as exc:
        raise OmivInputError("process numeric fact is invalid") from exc
    if duration_ms < 0 or stdout_bytes < 0 or stderr_bytes < 0:
        raise OmivInputError("process numeric fact is negative")
    start_ns = _strict_utc_ns(str(result["start_utc"]))
    end_ns = _strict_utc_ns(str(result["end_utc"]))
    if end_ns < start_ns:
        raise OmivInputError("process end timestamp precedes start")
    elapsed_ns = end_ns - start_ns
    if abs(elapsed_ns - int(result["duration_ms"]) * 1_000_000) > (
        _PROCESS_DURATION_TOLERANCE_MS * 1_000_000
    ):
        raise OmivInputError("process duration disagrees with timestamps")
    for stream in ("stdout", "stderr"):
        if present:
            complete = values[f"{stream}_complete"]
            overflow = values[f"{stream}_overflow"]
            if complete not in {"true", "false"} or overflow not in {"true", "false"}:
                raise OmivInputError("process stream completeness fact is invalid")
            if stream == "stdout":
                result["stdout_complete"] = complete == "true"
                result["stdout_overflow"] = overflow == "true"
            else:
                result["stderr_complete"] = complete == "true"
                result["stderr_overflow"] = overflow == "true"
    return result


def _iter_utf8_lines_at(
    root_fd: int,
    binding: SourceMemberBinding,
    control: ExternalObservationControl,
    label: str,
) -> Iterator[str]:
    limit = min(control.max_member_bytes, _MAX_TELEMETRY_BYTES)
    with _regular_fd_at(root_fd, binding.path, label) as (file_fd, parent_fd, leaf, before):
        if before.st_size > limit:
            raise OmivInputError(f"{label} exceeds byte limit {limit}: {before.st_size}")
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        digest = hashlib.sha256()
        observed = 0
        pending = ""
        while True:
            chunk = os.read(file_fd, _READ_CHUNK)
            if not chunk:
                break
            observed += len(chunk)
            if observed > limit:
                raise OmivInputError(f"{label} grew beyond byte limit {limit}")
            digest.update(chunk)
            pending += decoder.decode(chunk)
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                if len(line) > 1024:
                    raise OmivInputError("GPU telemetry line exceeds parser bound")
                yield line
            if len(pending) > 1024:
                raise OmivInputError("GPU telemetry line exceeds parser bound")
        pending += decoder.decode(b"", final=True)
        if pending:
            if len(pending) > 1024:
                raise OmivInputError("GPU telemetry line exceeds parser bound")
            yield pending
        _check_stable_read(file_fd, parent_fd, leaf, before, observed, label)
        if observed != binding.size or digest.hexdigest() != binding.sha256:
            raise OmivInputError(f"{label} changed after manifest verification")


def _parse_telemetry(
    root_fd: int,
    source: SourceMemberBinding,
    control: ExternalObservationControl,
    process_start: str,
    process_end: str,
) -> list[TelemetrySample]:
    field_limits = (64, 16, 200, 200, 32, 32, 16, 16)
    samples: list[TelemetrySample] = []
    try:
        for line in _iter_utf8_lines_at(root_fd, source, control, "GPU telemetry"):
            if len(samples) >= _MAX_TELEMETRY_ROWS:
                raise OmivInputError("GPU telemetry exceeds row bound")
            rows = list(csv.reader([line], skipinitialspace=True, strict=True))
            if len(rows) != 1:
                raise OmivInputError("GPU telemetry row grammar is invalid")
            row = rows[0]
            if len(row) != _MAX_TELEMETRY_COLUMNS or any(
                len(field) > field_limits[index] for index, field in enumerate(row)
            ):
                raise OmivInputError("GPU telemetry row/field bounds are invalid")
            timestamp, index_raw, name, identity, used_raw, total_raw, util_raw, _memory_util = row
            if _TELEMETRY_TIME_RE.fullmatch(timestamp) is None:
                raise OmivInputError("GPU telemetry timestamp is invalid")
            _reject_sensitive_text(name, "GPU device name")
            used_match = re.fullmatch(r"([0-9]+) MiB", used_raw)
            total_match = re.fullmatch(r"([0-9]+) MiB", total_raw)
            util_match = re.fullmatch(r"([0-9]+) %", util_raw)
            if used_match is None or total_match is None or util_match is None:
                raise OmivInputError("GPU telemetry has an unsupported grammar")
            sample_iso = timestamp.replace("/", "-", 2).replace(" ", "T") + "000000Z"
            sample_ns = _strict_utc_ns(sample_iso)
            if not (_strict_utc_ns(process_start) <= sample_ns <= _strict_utc_ns(process_end)):
                raise OmivInputError("GPU telemetry is not temporally bound to its attempt")
            samples.append(
                TelemetrySample(
                    sample_utc=sample_iso,
                    device_index=int(index_raw),
                    device_name_digest=hashlib.sha256(name.encode("utf-8")).hexdigest(),
                    device_identity_digest=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                    memory_used_mib=int(used_match.group(1)),
                    memory_total_mib=int(total_match.group(1)),
                    gpu_utilization_percent=int(util_match.group(1)),
                )
            )
    except OmivInputError:
        raise
    except (csv.Error, UnicodeError, ValueError, OverflowError) as exc:
        raise OmivInputError("GPU telemetry is malformed or exceeds parser bounds") from exc
    if not samples:
        raise OmivInputError("GPU telemetry sample count is invalid")
    if [item.sample_utc for item in samples] != sorted(item.sample_utc for item in samples):
        raise OmivInputError("GPU telemetry sample order is invalid")
    identities = {
        (
            item.device_index,
            item.device_name_digest,
            item.device_identity_digest,
            item.memory_total_mib,
        )
        for item in samples
    }
    if len(identities) != 1:
        raise OmivInputError("GPU telemetry changes device identity within an attempt")
    return samples


def _parse_dflash_activation(
    raw: bytes,
    source: SourceMemberBinding,
    draft_path: str,
    draft_sha256: str,
) -> DFlashActivationObservation:
    text = _text(raw, source.path)
    path_match = re.search(r"loading draft model '([^'\n]+)'", text)
    count_match = re.search(r"([0-9]+) accepted /\s+([0-9]+) generated", text)
    if (
        "draft-dflash" not in text
        or path_match is None
        or path_match.group(1) != draft_path
        or count_match is None
    ):
        raise OmivInputError("DFlash positive activation evidence is absent or unbound")
    try:
        return DFlashActivationObservation(
            implementation="draft-dflash",
            accepted_draft_tokens=int(count_match.group(1)),
            generated_draft_tokens=int(count_match.group(2)),
            draft_artifact_sha256=draft_sha256,
            source=source,
        )
    except ValidationError as exc:
        raise OmivInputError("DFlash token acceptance evidence is inconsistent") from exc


def _required_members(control: ExternalObservationControl) -> set[str]:
    members = {
        control.reference_evidence_member,
        control.source_identity_member,
        control.runtime.build_identity_member,
        control.runtime.version_member,
        *(item.observation_member for item in control.artifacts),
        *(item.payload_member for item in control.artifacts if item.payload_member is not None),
        *(item.member for item in control.findings),
        *(item.member for item in control.skips if item.member is not None),
    }
    for item in control.attempts:
        members.update(item.member_paths())
    return members


def _parser_role_limits(control: ExternalObservationControl) -> dict[str, int]:
    limits: dict[str, int] = {}

    def add(path: str, limit: int) -> None:
        limits[path] = min(limits.get(path, limit), limit)

    add(control.reference_evidence_member, _MAX_REFERENCE_BYTES)
    add(control.source_identity_member, _MAX_SMALL_TEXT_BYTES)
    add(control.runtime.build_identity_member, _MAX_BUILD_TEXT_BYTES)
    add(control.runtime.version_member, _MAX_SMALL_TEXT_BYTES)
    for artifact in control.artifacts:
        add(artifact.observation_member, _MAX_SMALL_TEXT_BYTES)
    for finding in control.findings:
        add(finding.member, _MAX_FINDING_SOURCE_BYTES)
    for attempt in control.attempts:
        add(attempt.argv_member, _MAX_ARGV_BYTES)
        add(attempt.process_member, _MAX_SMALL_TEXT_BYTES)
        add(attempt.environment_member, _MAX_SMALL_TEXT_BYTES)
        add(attempt.input_identities_member, _MAX_SMALL_TEXT_BYTES)
        add(attempt.stdout_member, _MAX_STREAM_BYTES)
        add(attempt.stderr_member, _MAX_STREAM_BYTES)
        add(attempt.stdout_digest_member, _MAX_SMALL_TEXT_BYTES)
        add(attempt.stderr_digest_member, _MAX_SMALL_TEXT_BYTES)
        if attempt.telemetry_member is not None:
            add(attempt.telemetry_member, _MAX_TELEMETRY_BYTES)
        if attempt.positive_activation_member is not None:
            add(attempt.positive_activation_member, _MAX_SMALL_TEXT_BYTES)
    return limits


def _source_list(
    control: AttemptControl, bindings: dict[str, SourceMemberBinding]
) -> list[SourceMemberBinding]:
    return sorted(
        {bindings[path].path: bindings[path] for path in control.member_paths()}.values(),
        key=lambda item: item.path.encode("utf-8"),
    )


def _parse_attempt_source(
    control: AttemptControl,
    root_fd: int,
    external_control: ExternalObservationControl,
    bindings: dict[str, SourceMemberBinding],
    planned: dict[str, Any],
    runtime: RuntimeSourceRecord,
    image_fixture: str,
    image_fixture_bytes: int,
    image_sha256: str,
    text_probe: str,
    image_probe: str,
) -> AttemptSourceRecord:
    def read(member: str, role_limit: int, label: str) -> bytes:
        return _read_bound_member(root_fd, bindings[member], external_control, role_limit, label)

    raw_argv = parse_bounded_json_bytes(
        read(control.argv_member, _MAX_ARGV_BYTES, "attempt argv"),
        source_name=control.argv_member,
        max_bytes=_MAX_ARGV_BYTES,
        require_object=False,
    )
    if (
        not isinstance(raw_argv, list)
        or any(not isinstance(item, str) for item in raw_argv)
        or not raw_argv
        or len(raw_argv) > 128
    ):
        raise OmivInputError("captured argv must be a bounded JSON string array")
    environment = _parse_environment(
        read(control.environment_member, _MAX_SMALL_TEXT_BYTES, "attempt environment"),
        control.environment_member,
        control,
    )
    input_bindings, input_paths = _parse_input_bindings(
        read(control.input_identities_member, _MAX_SMALL_TEXT_BYTES, "attempt input identities"),
        control.input_identities_member,
        control,
        planned,
        runtime,
        image_fixture,
        image_fixture_bytes,
        image_sha256,
    )
    argv = _parse_argv(
        raw_argv,
        control,
        input_paths,
        planned,
        image_probe if control.kind == AttemptKind.IMAGE else text_probe,
    )
    process = _parse_process(
        read(control.process_member, _MAX_SMALL_TEXT_BYTES, "attempt process observation"),
        control.process_member,
    )
    stdout_raw = read(control.stdout_member, _MAX_STREAM_BYTES, "attempt stdout")
    stderr_raw = read(control.stderr_member, _MAX_STREAM_BYTES, "attempt stderr")
    if int(process["stdout_bytes"]) != len(stdout_raw) or int(process["stderr_bytes"]) != len(
        stderr_raw
    ):
        raise OmivInputError("process stream byte counts do not match captured members")
    stdout_hash = hashlib.sha256(stdout_raw).hexdigest()
    stderr_hash = hashlib.sha256(stderr_raw).hexdigest()
    if stdout_hash != _parse_digest_record(
        read(control.stdout_digest_member, _MAX_SMALL_TEXT_BYTES, "stdout digest record"),
        control.stdout_digest_member,
    ) or stderr_hash != _parse_digest_record(
        read(control.stderr_digest_member, _MAX_SMALL_TEXT_BYTES, "stderr digest record"),
        control.stderr_digest_member,
    ):
        raise OmivInputError("captured stream digest record mismatch")
    try:
        stdout = StreamObservation(
            captured_bytes=len(stdout_raw),
            limit_bytes=environment.stream_cap_bytes,
            sha256=stdout_hash,
            complete=process["stdout_complete"],
            overflow=process["stdout_overflow"],
            source=bindings[control.stdout_member],
            digest_source=bindings[control.stdout_digest_member],
        )
        stderr = StreamObservation(
            captured_bytes=len(stderr_raw),
            limit_bytes=environment.stream_cap_bytes,
            sha256=stderr_hash,
            complete=process["stderr_complete"],
            overflow=process["stderr_overflow"],
            source=bindings[control.stderr_member],
            digest_source=bindings[control.stderr_digest_member],
        )
    except ValidationError as exc:
        raise OmivInputError("captured stream completeness facts are incoherent") from exc
    predicate_value = control.output_predicate.value
    occurrence_count = 0
    value_sha256 = None
    if predicate_value is not None:
        stdout_text = _text(stdout_raw, control.stdout_member)
        occurrence_count = stdout_text.count(predicate_value)
        if occurrence_count < 1:
            raise OmivInputError("captured output does not satisfy its reviewed exact predicate")
        value_sha256 = hashlib.sha256(predicate_value.encode("utf-8")).hexdigest()
    telemetry = (
        _parse_telemetry(
            root_fd,
            bindings[control.telemetry_member],
            external_control,
            str(process["start_utc"]),
            str(process["end_utc"]),
        )
        if control.telemetry_member is not None
        else None
    )
    dflash = None
    if control.positive_activation_member is not None:
        draft = _artifact_by_role(planned, "DRAFTER")
        dflash = _parse_dflash_activation(
            read(
                control.positive_activation_member,
                _MAX_SMALL_TEXT_BYTES,
                "DFlash activation evidence",
            ),
            bindings[control.positive_activation_member],
            input_paths["--spec-draft-model"],
            draft.provider_identity,
        )
    return AttemptSourceRecord(
        attempt_id=control.attempt_id,
        argv=argv,
        argv_source=bindings[control.argv_member],
        environment=environment,
        environment_source=bindings[control.environment_member],
        input_bindings=input_bindings,
        input_identities_source=bindings[control.input_identities_member],
        process_source=bindings[control.process_member],
        return_code=int(process["return_code"]),
        timed_out=bool(process["timed_out"]),
        duration_ms=int(process["duration_ms"]),
        start_utc=str(process["start_utc"]),
        end_utc=str(process["end_utc"]),
        stdout=stdout,
        stderr=stderr,
        telemetry_samples=telemetry,
        telemetry_source=(
            bindings[control.telemetry_member] if control.telemetry_member is not None else None
        ),
        predicate=PredicateSourceFact(
            kind=control.output_predicate.kind,
            value_sha256=value_sha256,
            occurrence_count=occurrence_count,
        ),
        dflash_activation=dflash,
        sources=_source_list(control, bindings),
    )


def _normalized_option_value(argv: list[str], option: str) -> str | None:
    try:
        index = argv.index(option)
    except ValueError:
        return None
    if option in _BOOLEAN_OPTIONS:
        return "true"
    if index + 1 >= len(argv):
        raise OmivInputError("normalized argv option lacks a value")
    return argv[index + 1]


def _validate_normalized_argv(argv: list[str], control: AttemptControl, plan: Any) -> None:
    if not argv or argv[0] != "{runtime:llama-cli}" or len(argv) > 128:
        raise OmivInputError("normalized argv executable binding is invalid")
    seen: set[str] = set()
    planned = {item.artifact_id: item for item in plan.artifacts}
    role_tokens = {
        role: f"{{artifact:{_artifact_by_role(planned, role).artifact_id}}}"
        for role in ("MAIN_MODEL", "PERCEPTION_ENCODER", "DRAFTER")
    }
    index = 1
    while index < len(argv):
        option = argv[index]
        if option in seen or option not in _VALUE_OPTIONS | _BOOLEAN_OPTIONS:
            raise OmivInputError("normalized argv option structure is invalid")
        seen.add(option)
        if option in _BOOLEAN_OPTIONS:
            index += 1
            continue
        if index + 1 >= len(argv):
            raise OmivInputError("normalized argv option lacks a value")
        value = argv[index + 1]
        if option == "--model":
            _reject_sensitive_text(value, "normalized argv path binding")
            if value != role_tokens["MAIN_MODEL"]:
                raise OmivInputError("normalized model binding differs from plan")
        elif option == "--mmproj":
            _reject_sensitive_text(value, "normalized argv path binding")
            if value != role_tokens["PERCEPTION_ENCODER"]:
                raise OmivInputError("normalized projector binding differs from plan")
        elif option == "--spec-draft-model":
            _reject_sensitive_text(value, "normalized argv path binding")
            if value != role_tokens["DRAFTER"]:
                raise OmivInputError("normalized draft binding differs from plan")
        elif option == "--image":
            _reject_sensitive_text(value, "normalized argv path binding")
            if value != "{image:plan-fixture}":
                raise OmivInputError("normalized image binding differs from plan")
        elif option == "--prompt":
            expected_prompt = (
                plan.image_probe if control.kind == AttemptKind.IMAGE else plan.text_probe
            )
            _validate_scalar_option(option, value, expected_prompt)
        else:
            _validate_scalar_option(option, value, "")
        index += 2
    image = control.kind == AttemptKind.IMAGE
    dflash = (
        control.kind == AttemptKind.DFLASH_TEXT or control.positive_activation_member is not None
    )
    required = (
        {"--model", "--prompt", "--mmproj", "--image"}
        if image
        else {"--model", "--prompt", "--no-mmproj"}
    )
    if dflash:
        required |= {"--spec-type", "--spec-draft-model"}
    if control.require_single_turn:
        required.add("--single-turn")
    forbidden = {"--no-mmproj"} if image else {"--mmproj", "--image"}
    if not dflash:
        forbidden |= {"--spec-type", "--spec-draft-model"}
    if not required.issubset(seen) or forbidden & seen:
        raise OmivInputError("normalized argv roles differ from attempt kind")


def _telemetry_summary(
    record: AttemptSourceRecord, runtime: RuntimeSourceRecord
) -> TelemetrySummary | None:
    samples = record.telemetry_samples
    if samples is None:
        if record.telemetry_source is not None:
            raise OmivInputError("telemetry source/sample presence is incoherent")
        return None
    if not samples or record.telemetry_source is None:
        raise OmivInputError("telemetry source/sample presence is incoherent")
    identities = {
        (
            item.device_index,
            item.device_name_digest,
            item.device_identity_digest,
            item.memory_total_mib,
        )
        for item in samples
    }
    if len(identities) != 1:
        raise OmivInputError("telemetry normalized identity changes within an attempt")
    if [item.sample_utc for item in samples] != sorted(item.sample_utc for item in samples):
        raise OmivInputError("telemetry normalized samples are not ordered")
    start_ns = _strict_utc_ns(record.start_utc)
    end_ns = _strict_utc_ns(record.end_utc)
    if any(not start_ns <= _strict_utc_ns(item.sample_utc) <= end_ns for item in samples):
        raise OmivInputError("telemetry normalized samples are outside process time")
    index, name_digest, identity, total = next(iter(identities))
    return TelemetrySummary(
        backend=runtime.backend,
        device_index=index,
        device_name_digest=name_digest,
        device_identity_digest=identity,
        sample_count=len(samples),
        first_sample_utc=samples[0].sample_utc,
        last_sample_utc=samples[-1].sample_utc,
        memory_total_mib=total,
        memory_used_peak_mib=max(item.memory_used_mib for item in samples),
        gpu_utilization_peak_percent=max(item.gpu_utilization_percent for item in samples),
        source=record.telemetry_source,
    )


def _process_status(record: AttemptSourceRecord) -> ExternalStatus:
    streams = (record.stdout, record.stderr)
    if any(item.complete is None or item.overflow is None for item in streams):
        return ExternalStatus.INCOMPLETE
    if any(item.complete is False or item.overflow is True for item in streams):
        return ExternalStatus.INCOMPLETE
    if record.return_code == 0 and not record.timed_out:
        return ExternalStatus.PASS
    return ExternalStatus.FAIL


def _expected_artifacts(
    control: ExternalObservationControl, plan: Any, records: list[ArtifactSourceRecord]
) -> list[ArtifactIdentityObservation]:
    planned = {item.artifact_id: item for item in plan.artifacts}
    if [item.artifact_id for item in records] != [item.artifact_id for item in control.artifacts]:
        raise OmivInputError("artifact source-record ordering differs from control")
    result: list[ArtifactIdentityObservation] = []
    for item, artifact_control in zip(records, control.artifacts, strict=True):
        pin = planned.get(item.artifact_id)
        if pin is None or (
            item.role,
            item.reported_filename,
            item.reported_size,
            item.reported_sha256,
        ) != (pin.role.value, pin.path, pin.declared_size, pin.provider_identity):
            raise OmivInputError("artifact normalized report differs from canonical plan")
        if artifact_control.role != item.role:
            raise OmivInputError("artifact source-record role differs from control")
        payload_source = item.payload_source
        verified = payload_source is not None
        if payload_source is not None and (
            payload_source.size != pin.declared_size
            or payload_source.sha256 != pin.provider_identity
        ):
            raise OmivInputError("artifact payload source differs from canonical plan")
        result.append(
            ArtifactIdentityObservation(
                artifact_id=item.artifact_id,
                role=item.role,
                filename=item.reported_filename,
                size=item.reported_size,
                sha256=item.reported_sha256,
                status=(
                    ExternalStatus.VERIFIED if verified else ExternalStatus.MATCHED_PLAN_OBSERVATION
                ),
                payload_verified=verified,
                report_source=item.report_source,
                payload_source=item.payload_source,
            )
        )
    return result


def _expected_attempts(
    control: ExternalObservationControl,
    plan: Any,
    source_record: CanonicalSourceRecord,
    bindings: dict[str, SourceMemberBinding],
) -> list[AttemptObservation]:
    if [item.attempt_id for item in source_record.attempts] != [
        item.attempt_id for item in control.attempts
    ]:
        raise OmivInputError("attempt source-record ordering differs from control")
    draft = _artifact_by_role({item.artifact_id: item for item in plan.artifacts}, "DRAFTER")
    result: list[AttemptObservation] = []
    prior_controls: dict[str, AttemptControl] = {}
    for record, attempt_control in zip(source_record.attempts, control.attempts, strict=True):
        _validate_normalized_argv(record.argv, attempt_control, plan)
        if attempt_control.supersedes is not None:
            target = prior_controls.get(attempt_control.supersedes)
            if (
                target is None
                or target.disposition != AttemptDisposition.RETAINED_FAILED
                or attempt_control.disposition != AttemptDisposition.ACCEPTED
                or not attempt_control.require_single_turn
                or _normalized_option_value(record.argv, "--single-turn") != "true"
                or record.environment.correction != "SINGLE_TURN_RETRY"
                or record.environment.correction_target != attempt_control.supersedes
            ):
                raise OmivInputError("normalized retry invariants are incoherent")
        elif (
            record.environment.correction is not None
            or record.environment.correction_target is not None
        ):
            raise OmivInputError("non-retry attempt contains contradictory correction evidence")
        _strict_utc_ns(record.start_utc)
        start_ns = _strict_utc_ns(record.start_utc)
        end_ns = _strict_utc_ns(record.end_utc)
        if (
            end_ns < start_ns
            or abs(end_ns - start_ns - record.duration_ms * 1_000_000)
            > _PROCESS_DURATION_TOLERANCE_MS * 1_000_000
        ):
            raise OmivInputError("normalized process time facts are incoherent")
        expected_sources = _source_list(attempt_control, bindings)
        if record.sources != expected_sources:
            raise OmivInputError("attempt normalized source set differs from control")
        expected_direct = {
            attempt_control.argv_member: record.argv_source,
            attempt_control.environment_member: record.environment_source,
            attempt_control.input_identities_member: record.input_identities_source,
            attempt_control.process_member: record.process_source,
            attempt_control.stdout_member: record.stdout.source,
            attempt_control.stdout_digest_member: record.stdout.digest_source,
            attempt_control.stderr_member: record.stderr.source,
            attempt_control.stderr_digest_member: record.stderr.digest_source,
        }
        if any(value != bindings[path] for path, value in expected_direct.items()):
            raise OmivInputError("attempt normalized source binding is incoherent")
        if attempt_control.telemetry_member is None:
            if record.telemetry_source is not None or record.telemetry_samples is not None:
                raise OmivInputError("unexpected telemetry normalized source")
        elif record.telemetry_source != bindings[attempt_control.telemetry_member]:
            raise OmivInputError("telemetry normalized source binding is incoherent")
        if attempt_control.positive_activation_member is None:
            if record.dflash_activation is not None:
                raise OmivInputError("unexpected DFlash normalized source")
        else:
            if (
                record.dflash_activation is None
                or record.dflash_activation.source
                != bindings[attempt_control.positive_activation_member]
                or record.dflash_activation.draft_artifact_sha256 != draft.provider_identity
                or record.dflash_activation.accepted_draft_tokens
                > record.dflash_activation.generated_draft_tokens
            ):
                raise OmivInputError("DFlash normalized digest/count/source is incoherent")
        expected_binding = InputBindingObservation(
            executable_sha256=source_record.runtime.executable_sha256,
            main_artifact_id=_artifact_by_role(
                {item.artifact_id: item for item in plan.artifacts}, "MAIN_MODEL"
            ).artifact_id,
            projector_artifact_id=(
                _artifact_by_role(
                    {item.artifact_id: item for item in plan.artifacts}, "PERCEPTION_ENCODER"
                ).artifact_id
                if attempt_control.kind == AttemptKind.IMAGE
                else None
            ),
            draft_artifact_id=(
                draft.artifact_id
                if attempt_control.kind == AttemptKind.DFLASH_TEXT
                or attempt_control.positive_activation_member is not None
                else None
            ),
            image_fixture=plan.image_fixture if attempt_control.kind == AttemptKind.IMAGE else None,
            image_bytes=(
                control.image_fixture_bytes if attempt_control.kind == AttemptKind.IMAGE else None
            ),
            image_sha256=(
                plan.image_fixture_sha256 if attempt_control.kind == AttemptKind.IMAGE else None
            ),
        )
        if record.input_bindings != expected_binding:
            raise OmivInputError("attempt normalized input bindings differ from plan")
        predicate = attempt_control.output_predicate
        expected_predicate_hash = (
            hashlib.sha256(predicate.value.encode("utf-8")).hexdigest()
            if predicate.value is not None
            else None
        )
        if (
            record.predicate.kind != predicate.kind
            or record.predicate.value_sha256 != expected_predicate_hash
            or (predicate.value is None and record.predicate.occurrence_count != 0)
            or (predicate.value is not None and record.predicate.occurrence_count < 1)
        ):
            raise OmivInputError("fixed predicate normalized fact is incoherent")
        process_status = _process_status(record)
        if (
            attempt_control.disposition == AttemptDisposition.RETAINED_FAILED
            and process_status == ExternalStatus.PASS
        ):
            raise OmivInputError("retained failed attempt unexpectedly completed")
        predicate_status: Literal[ExternalStatus.UNKNOWN, ExternalStatus.OBSERVED] = (
            ExternalStatus.UNKNOWN
        )
        if predicate.value is not None:
            predicate_status = ExternalStatus.OBSERVED
        result.append(
            AttemptObservation(
                attempt_id=record.attempt_id,
                kind=attempt_control.kind,
                disposition=attempt_control.disposition,
                argv=record.argv,
                normalized_argv_sha256=canonical_sha256(
                    {"capture_profile": CAPTURE_PROFILE, "argv": record.argv}
                ),
                environment=record.environment,
                input_bindings=record.input_bindings,
                return_code=record.return_code,
                timed_out=record.timed_out,
                duration_ms=record.duration_ms,
                start_utc=record.start_utc,
                end_utc=record.end_utc,
                stdout=record.stdout,
                stderr=record.stderr,
                telemetry=_telemetry_summary(record, source_record.runtime),
                supersedes=attempt_control.supersedes,
                retry_reason=attempt_control.retry_reason,
                process_status=process_status,
                output_predicate_status=predicate_status,
                dflash_activation=record.dflash_activation,
                sources=record.sources,
            )
        )
        prior_controls[attempt_control.attempt_id] = attempt_control
    return result


def _stages() -> list[StageObservation]:
    return [
        StageObservation(
            stage=stage,
            status=ExternalStatus.UNKNOWN,
            basis=(
                "External process completion and captured bytes do not independently "
                f"establish {stage}."
            ),
        )
        for stage in ("LOAD", "TOKENIZER", "PREFILL", "DECODE", "OUTPUT")
    ]


def _derive_components(
    control: ExternalObservationControl,
    manifest: ManifestObservation,
    reference: ReferencePreflightEvidence,
    source_record: CanonicalSourceRecord,
) -> tuple[
    SourceIdentityObservation,
    list[ArtifactIdentityObservation],
    RuntimeIdentityObservation,
    ExternalProjection,
]:
    _validate_control_privacy(control)
    for member in manifest.members:
        _reject_sensitive_text(member.path, "manifest member path")
    if control.capture_profile != CAPTURE_PROFILE:
        raise OmivInputError("unsupported external capture profile")
    bindings = {item.path: item for item in manifest.members}
    canonical_manifest = "".join(
        f"{item.sha256}  {item.path}\n" for item in manifest.members
    ).encode("ascii")
    if (
        manifest.member_count > control.max_files
        or any(item.size > control.max_member_bytes for item in manifest.members)
        or len(canonical_manifest) > min(control.max_member_bytes, _MAX_MANIFEST_BYTES)
        or manifest.total_bytes > control.max_total_bytes
        or control.manifest_member in bindings
    ):
        raise OmivInputError("offline manifest projection exceeds embedded control limits")
    role_limits = _parser_role_limits(control)
    if any(
        bindings[path].size > min(control.max_member_bytes, role_limit)
        for path, role_limit in role_limits.items()
        if path in bindings
    ):
        raise OmivInputError("offline parser source exceeds its role-specific byte limit")
    if hashlib.sha256(canonical_manifest).hexdigest() != control.manifest_sha256:
        raise OmivInputError("offline manifest projection does not reconstruct")
    if manifest.manifest_sha256 != control.manifest_sha256:
        raise OmivInputError("external manifest binding mismatch")
    missing = _required_members(control) - set(bindings)
    if missing:
        raise OmivInputError("control maps an unbound evidence member")
    if source_record.reference_source != bindings[control.reference_evidence_member]:
        raise OmivInputError("reference normalized source binding mismatch")
    expected_reference_hash = canonical_sha256(reference.model_dump(mode="json", by_alias=True))
    if source_record.reference_canonical_sha256 != expected_reference_hash:
        raise OmivInputError("reference normalized record does not reconstruct")
    plan = reference.future_runtime_plan
    if (
        plan.plan_id != control.plan_id
        or plan.plan_digest != control.plan_digest
        or reference.profile_digest != control.profile_digest
    ):
        raise OmivInputError("reference plan id/digest/profile mismatch")
    source_identity = source_record.source_identity
    if (
        source_identity.commit != control.source_commit
        or source_identity.tree != control.source_tree
        or source_identity.signature != control.source_signature
        or source_identity.source != bindings[control.source_identity_member]
    ):
        raise OmivInputError("source identity normalized record mismatch")
    planned = {item.artifact_id: item for item in plan.artifacts}
    if set(planned) != {item.artifact_id for item in control.artifacts}:
        raise OmivInputError("control artifact set differs from canonical plan")
    artifacts = _expected_artifacts(control, plan, source_record.artifacts)
    for item, artifact_control in zip(source_record.artifacts, control.artifacts, strict=True):
        _reject_sensitive_text(item.reported_filename, "artifact filename")
        if item.report_source != bindings[artifact_control.observation_member]:
            raise OmivInputError("artifact report normalized source binding mismatch")
        expected_payload = (
            bindings[artifact_control.payload_member]
            if artifact_control.payload_member is not None
            else None
        )
        if item.payload_source != expected_payload:
            raise OmivInputError("artifact payload normalized source binding mismatch")
    planned_runtime = next(
        (item for item in plan.runtime_requirements if item.runtime == control.runtime.name), None
    )
    runtime_source = source_record.runtime
    if (
        planned_runtime is None
        or planned_runtime.exact_release != runtime_source.version
        or planned_runtime.exact_commit != runtime_source.commit
        or runtime_source.name != control.runtime.name
        or runtime_source.executable_sha256 != control.runtime.executable_sha256
        or runtime_source.cuda_version != control.runtime.cuda_version
        or runtime_source.backend != control.runtime.backend
        or runtime_source.build_source != bindings[control.runtime.build_identity_member]
        or runtime_source.version_source != bindings[control.runtime.version_member]
    ):
        raise OmivInputError("runtime normalized record differs from plan/control")
    runtime = RuntimeIdentityObservation.model_validate(runtime_source.model_dump(mode="json"))
    attempts = _expected_attempts(control, plan, source_record, bindings)
    finding_facts = {item.code: item for item in source_record.findings}
    if list(finding_facts) != [item.code for item in control.findings]:
        raise OmivInputError("finding normalized record ordering differs from control")
    findings: list[ExternalFinding] = []
    for finding_control in control.findings:
        fact = finding_facts[finding_control.code]
        if (
            fact.exact_text_sha256
            != hashlib.sha256(finding_control.exact_text.encode("utf-8")).hexdigest()
            or fact.occurrence_count < 1
            or fact.source != bindings[finding_control.member]
        ):
            raise OmivInputError("finding normalized fact is incoherent")
        findings.append(
            ExternalFinding(
                code=finding_control.code,
                severity=finding_control.severity,
                detail=finding_control.detail,
                source=fact.source,
            )
        )
    skips = [
        ExternalSkip(
            target=item.target,
            reason=item.reason,
            source=bindings[item.member] if item.member is not None else None,
        )
        for item in control.skips
    ]
    stages = _stages()
    unknowns = [
        f"{item.stage} remains UNKNOWN from external black-box observations." for item in stages
    ]
    unknowns.extend(
        f"{item.attempt_id} capture completeness is absent or incomplete."
        for item in attempts
        if item.process_status == ExternalStatus.INCOMPLETE
    )
    unknowns.extend(
        [
            "Source-to-artifact binding is NOT_ESTABLISHED.",
            "Companion-artifact publisher binding is NOT_ESTABLISHED.",
            "Numerical and semantic fidelity are NOT_EVALUATED.",
            "Performance, safety, and production readiness are NOT_EVALUATED.",
            "Source origin authenticity remains UNKNOWN even when the commit lacks a signature.",
        ]
    )
    limitations = [
        "A runner PASS, stage label, prose claim, filename, or report is untrusted input.",
        "A matched artifact report does not verify artifact payload bytes.",
        "Artifact VERIFIED requires a safely opened manifest-bound payload member.",
        "A completed invocation establishes only the exact process and captured-byte observation.",
        "The fixed PNG predicate is one output observation, not general vision fidelity.",
        "DFlash activation and token counts establish no performance or fidelity conclusion.",
        "Phase 6F Assurance semantics and its UNKNOWN verdict are unchanged.",
    ]
    observation_digest = canonical_sha256(
        {
            "manifest": manifest.model_dump(mode="json"),
            "source_record": source_record.model_dump(mode="json"),
            "source_identity": source_identity.model_dump(mode="json"),
            "artifacts": [item.model_dump(mode="json") for item in artifacts],
            "runtime": runtime.model_dump(mode="json"),
            "attempts": [item.model_dump(mode="json") for item in attempts],
        }
    )
    projection = ExternalProjection(
        observation_set_digest=observation_digest,
        attempts=attempts,
        stages=stages,
        skips=skips,
        findings=findings,
        unknowns=unknowns,
        limitations=limitations,
        overall_status=ExternalOverallStatus.PARTIAL,
    )
    return source_identity, artifacts, runtime, projection


def verify_external_evidence(evidence: ExternalRuntimeObservationEvidence) -> None:
    source_identity, artifacts, runtime, projection = _derive_components(
        evidence.control,
        evidence.manifest,
        evidence.reference_evidence,
        evidence.source_record,
    )
    if evidence.source_identity != source_identity:
        raise OmivInputError("external source identity does not reconstruct")
    if evidence.artifacts != artifacts:
        raise OmivInputError("external artifact observations do not reconstruct")
    if evidence.runtime != runtime:
        raise OmivInputError("external runtime observation does not reconstruct")
    if evidence.projection != projection:
        raise OmivInputError("external projection does not reconstruct")


def import_external_observations(
    control: ExternalObservationControl, root: Path
) -> ExternalRuntimeObservationEvidence:
    _validate_control_privacy(control)
    root_fd, root_identity = _open_root(root)
    try:
        manifest, bindings, manifest_raw, expected_actual = _verify_manifest_root_fd(
            control, root_fd
        )
        if _required_members(control) - set(bindings):
            raise OmivInputError("control maps unlisted evidence members")

        def read(member: str, role_limit: int, label: str) -> bytes:
            return _read_bound_member(root_fd, bindings[member], control, role_limit, label)

        reference_raw = parse_bounded_json_bytes(
            read(control.reference_evidence_member, _MAX_REFERENCE_BYTES, "reference evidence"),
            source_name=control.reference_evidence_member,
            max_bytes=min(control.max_member_bytes, _MAX_REFERENCE_BYTES),
        )
        try:
            reference = ReferencePreflightEvidence.model_validate(reference_raw)
        except (ValidationError, ValueError) as exc:
            raise OmivInputError("invalid canonical reference evidence") from exc
        plan = reference.future_runtime_plan
        if (
            plan.plan_id != control.plan_id
            or plan.plan_digest != control.plan_digest
            or reference.profile_digest != control.profile_digest
        ):
            raise OmivInputError("reference plan id/digest/profile mismatch")
        source_identity = _parse_source_identity(
            control,
            read(control.source_identity_member, _MAX_SMALL_TEXT_BYTES, "source identity"),
            bindings[control.source_identity_member],
        )
        planned = {item.artifact_id: item for item in plan.artifacts}
        if set(planned) != {item.artifact_id for item in control.artifacts}:
            raise OmivInputError("control artifact set differs from canonical plan")
        artifact_records = [
            _parse_artifact(
                item,
                read(item.observation_member, _MAX_SMALL_TEXT_BYTES, "artifact report"),
                bindings[item.observation_member],
                bindings[item.payload_member] if item.payload_member is not None else None,
                planned[item.artifact_id],
            )
            for item in control.artifacts
        ]
        runtime = _parse_runtime(
            control,
            read(
                control.runtime.build_identity_member,
                _MAX_BUILD_TEXT_BYTES,
                "runtime build identity",
            ),
            read(
                control.runtime.version_member,
                _MAX_SMALL_TEXT_BYTES,
                "runtime version",
            ),
            bindings,
        )
        attempt_records = [
            _parse_attempt_source(
                item,
                root_fd,
                control,
                bindings,
                planned,
                runtime,
                plan.image_fixture,
                control.image_fixture_bytes,
                plan.image_fixture_sha256,
                plan.text_probe,
                plan.image_probe,
            )
            for item in control.attempts
        ]
        finding_records: list[FindingSourceFact] = []
        for item in control.findings:
            finding_raw = read(item.member, _MAX_FINDING_SOURCE_BYTES, "finding source evidence")
            count = _text(finding_raw, item.member).count(item.exact_text)
            if count < 1:
                raise OmivInputError(f"finding source does not contain exact evidence: {item.code}")
            finding_records.append(
                FindingSourceFact(
                    code=item.code,
                    exact_text_sha256=hashlib.sha256(item.exact_text.encode("utf-8")).hexdigest(),
                    occurrence_count=count,
                    source=bindings[item.member],
                )
            )
        source_record = CanonicalSourceRecord(
            reference_source=bindings[control.reference_evidence_member],
            reference_canonical_sha256=canonical_sha256(
                reference.model_dump(mode="json", by_alias=True)
            ),
            source_identity=source_identity,
            artifacts=artifact_records,
            runtime=runtime,
            attempts=attempt_records,
            findings=finding_records,
        )
        source_identity_out, artifacts, runtime_out, projection = _derive_components(
            control, manifest, reference, source_record
        )
        if control.complete_set and _actual_files_fd(root_fd, control.max_files) != expected_actual:
            raise OmivInputError("manifest membership changed during verification")
        if (
            _read_regular_at(
                root_fd,
                control.manifest_member,
                min(control.max_member_bytes, _MAX_MANIFEST_BYTES),
                "manifest",
            )
            != manifest_raw
        ):
            raise OmivInputError("manifest changed during verification")
        _revalidate_root(root, root_fd, root_identity)
    finally:
        os.close(root_fd)
    body: dict[str, Any] = {
        "schema": "omiv.external-runtime-observation-evidence.v2",
        "candidate_notice": "PHASE_7B2_CANDIDATE_PHASE_7_UNFROZEN",
        "control": control.model_dump(mode="json", by_alias=True),
        "manifest": manifest.model_dump(mode="json"),
        "reference_evidence": reference.model_dump(mode="json", by_alias=True),
        "source_record": source_record.model_dump(mode="json"),
        "source_identity": source_identity_out.model_dump(mode="json"),
        "artifacts": [item.model_dump(mode="json") for item in artifacts],
        "runtime": runtime_out.model_dump(mode="json"),
        "projection": projection.model_dump(mode="json"),
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    evidence = ExternalRuntimeObservationEvidence.model_validate(
        {
            **body,
            "evidence_id": f"external_runtime_observation_{digest[:32]}",
            "evidence_digest": digest,
        }
    )
    verify_external_evidence(evidence)
    return evidence


def concise_external_summary(evidence: ExternalRuntimeObservationEvidence) -> str:
    lines = [
        f"External runtime observation: {evidence.projection.overall_status.value}",
        f"evidence_id={evidence.evidence_id}",
        f"evidence_digest={evidence.evidence_digest}",
        f"observation_set_digest={evidence.projection.observation_set_digest}",
        f"capture_profile={evidence.control.capture_profile}",
        f"plan={evidence.control.plan_id} profile={evidence.control.profile_digest}",
        "",
        "Attempts:",
    ]
    for item in evidence.projection.attempts:
        retry = f" supersedes={item.supersedes}" if item.supersedes else ""
        lines.append(
            f"{item.attempt_id}: process={item.process_status.value} "
            f"predicate={item.output_predicate_status.value} exit={item.return_code} "
            f"timeout={'yes' if item.timed_out else 'no'} duration_ms={item.duration_ms}{retry}"
        )
    lines.extend(["", "Stages:"])
    lines.extend(f"{item.stage:<10} {item.status.value}" for item in evidence.projection.stages)
    if any("--single-turn" in item.argv for item in evidence.projection.attempts):
        lines.extend(
            [
                "",
                "Recommendation: retain --single-turn for the accepted direct llama.cpp path; "
                "the earlier invocation remains retained.",
            ]
        )
    if evidence.projection.skips:
        lines.append("Not run: " + ", ".join(item.target for item in evidence.projection.skips))
    lines.append("Unknowns: " + str(len(evidence.projection.unknowns)))
    return "\n".join(lines)
