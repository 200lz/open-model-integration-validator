"""Bounded non-executing observation of supplied tokenizer/configuration assets."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from omiv.canonical import canonical_json_bytes, canonical_sha256
from omiv.errors import OmivInputError
from omiv.tokenizer_parity.building import (
    build_asset_observation,
    build_configuration_observation,
    build_merge_observation,
    build_template_observation,
    build_vocabulary_observation,
)
from omiv.tokenizer_parity.models import (
    ArtifactBinding,
    CanonicalValue,
    CanonicalValueType,
    ChatTemplateObservation,
    ConfigurationFieldObservation,
    ConfigurationObservation,
    CoverageDimension,
    MergeRecord,
    MergeTableObservation,
    ObjectReference,
    ParityScope,
    PresenceState,
    TokenClassification,
    TokenizerAssetObservation,
    TokenizerConfigurationExecutionRecord,
    TokenizerConfigurationLimits,
    VocabularyEntry,
    VocabularyObservation,
    canonical_text_token,
    object_reference,
)


def safe_read_asset(
    path: Path,
    binding: ArtifactBinding,
    limits: TokenizerConfigurationLimits,
    *,
    root_before: str | None = None,
    root_after: str | None = None,
) -> tuple[bytes, tuple[str, ...]]:
    """Read one bounded regular asset while detecting stable path/file identity."""
    if path.is_symlink():
        raise OmivInputError("tokenizer/configuration asset symlink is rejected")
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise OmivInputError(f"cannot stat supplied asset {path.name}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise OmivInputError("tokenizer/configuration asset must be a regular file")
    if before.st_nlink != 1:
        raise OmivInputError("tokenizer/configuration asset hardlink alias is rejected")
    if before.st_size > limits.maximum_bytes_per_asset:
        raise OmivInputError("LIMIT_EXCEEDED:ASSET_BYTES")
    findings: list[str] = []
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                findings.append("PATH_REBOUND_DURING_OBSERVATION")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = stream.read(min(1024 * 1024, limits.maximum_bytes_per_asset + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > limits.maximum_bytes_per_asset:
                    raise OmivInputError("LIMIT_EXCEEDED:ASSET_BYTES")
                chunks.append(chunk)
            after_open = os.fstat(stream.fileno())
    except OSError as exc:
        raise OmivInputError(f"cannot read supplied asset {path.name}: {exc}") from exc
    try:
        after_path = path.stat(follow_symlinks=False)
    except OSError:
        findings.append("PATH_REBOUND_DURING_OBSERVATION")
        after_path = before
    if (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
    ) != (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_size,
        after_open.st_mtime_ns,
        after_open.st_ctime_ns,
    ):
        findings.append("OPENED_FILE_CHANGED_DURING_READ")
    if (before.st_dev, before.st_ino) != (after_path.st_dev, after_path.st_ino):
        findings.append("PATH_REBOUND_DURING_OBSERVATION")
    elif (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after_path.st_size,
        after_path.st_mtime_ns,
        after_path.st_ctime_ns,
    ):
        findings.append("OPENED_FILE_CHANGED_DURING_READ")
    if root_before is not None and root_after is not None and root_before != root_after:
        findings.append("ROOT_CHANGED_DURING_OBSERVATION")
    raw = b"".join(chunks)
    digest = hashlib.sha256(raw).hexdigest()
    if binding.file_size is not None and binding.file_size != len(raw):
        raise OmivInputError("Phase 6A asset size binding mismatch")
    if binding.payload_sha256 is not None and binding.payload_sha256 != digest:
        raise OmivInputError("Phase 6A asset payload identity mismatch")
    return raw, tuple(sorted(set(findings)))


def observe_json_configuration(
    path: Path,
    binding: ArtifactBinding,
    execution: TokenizerConfigurationExecutionRecord,
    selected_fields: Iterable[str],
    coverage: Iterable[CoverageDimension],
    *,
    limits: TokenizerConfigurationLimits | None = None,
) -> tuple[TokenizerAssetObservation, ConfigurationObservation]:
    bounds = limits or TokenizerConfigurationLimits()
    raw, races = safe_read_asset(path, binding, bounds)
    parsed = parse_configuration_json(raw, source_name=path.name, limits=bounds)
    asset = build_asset_observation(
        execution,
        binding,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=len(raw),
        format_identifier="strict.json.configuration.v1",
        format_supported=True,
        race_findings=races,
    )
    fields = tuple(
        configuration_field(parsed, field_path, object_reference(asset), binding, bounds)
        for field_path in sorted(set(selected_fields), key=lambda x: x.encode())
    )
    projection = [field.model_dump(mode="json") for field in fields]
    canonical_value = _canonical_json_value(parsed)
    observation = build_configuration_observation(
        execution,
        binding,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_json_sha256=hashlib.sha256(canonical_json_bytes(canonical_value)).hexdigest(),
        projection_sha256=canonical_sha256(projection),
        fields=fields,
        coverage=coverage,
        race_findings=races,
    )
    return asset, observation


def parse_configuration_json(
    raw: bytes,
    *,
    source_name: str,
    limits: TokenizerConfigurationLimits | None = None,
) -> dict[str, Any]:
    bounds = limits or TokenizerConfigurationLimits()
    if len(raw) > bounds.maximum_json_bytes:
        raise OmivInputError("LIMIT_EXCEEDED:JSON_BYTES")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OmivInputError(f"{source_name} is not valid UTF-8") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate object key {key!r}")
            result[key] = value
        return result

    def decimal_value(value: str) -> Decimal:
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("invalid decimal") from exc
        if not parsed.is_finite() or len(parsed.as_tuple().digits) > bounds.maximum_numeric_digits:
            raise ValueError("LIMIT_EXCEEDED:NUMERIC_DIGITS")
        if parsed != 0 and abs(parsed.adjusted()) > bounds.maximum_numeric_exponent:
            raise ValueError("LIMIT_EXCEEDED:NUMERIC_EXPONENT")
        return parsed

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=decimal_value,
            parse_int=lambda text: (
                int(text)
                if len(text.lstrip("-")) <= bounds.maximum_numeric_digits
                else (_raise("LIMIT_EXCEEDED:NUMERIC_DIGITS"))
            ),
            parse_constant=lambda value: _raise(f"non-finite JSON value {value}"),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise OmivInputError(f"invalid strict JSON in {source_name}: {exc}") from exc
    if not isinstance(value, dict):
        raise OmivInputError("configuration asset must contain a top-level object")
    _check_json_bounds(value, bounds)
    return value


def configuration_field(
    value: dict[str, Any],
    field_path: str,
    source_asset: ObjectReference,
    binding: ArtifactBinding,
    limits: TokenizerConfigurationLimits,
) -> ConfigurationFieldObservation:
    if len(field_path) > limits.maximum_field_path_length:
        raise OmivInputError("LIMIT_EXCEEDED:FIELD_PATH")
    current: Any = value
    present = True
    for part in field_path.split("."):
        if not isinstance(current, dict) or part not in current:
            present = False
            break
        current = current[part]
    if not present:
        return ConfigurationFieldObservation(
            field_path=field_path,
            presence=PresenceState.ABSENT,
            value=None,
            provenance="observed.strict-json.absence",
            semantic_role=f"declared.{binding.asset_kind.value.lower()}",
            scope=ParityScope.SELECTED_REQUIRED_FIELDS,
            source_asset=source_asset,
        )
    if current is None:
        canonical = CanonicalValue(value_type=CanonicalValueType.EXPLICIT_NULL)
        presence = PresenceState.EXPLICIT_NULL
    else:
        canonical = canonical_configuration_value(current, limits)
        presence = PresenceState.EXPLICIT_VALUE
    return ConfigurationFieldObservation(
        field_path=field_path,
        presence=presence,
        value=canonical,
        provenance="observed.strict-json.value",
        semantic_role=f"declared.{binding.asset_kind.value.lower()}",
        scope=ParityScope.SELECTED_REQUIRED_FIELDS,
        source_asset=source_asset,
    )


def canonical_configuration_value(
    value: Any, limits: TokenizerConfigurationLimits
) -> CanonicalValue:
    if value is None:
        return CanonicalValue(value_type=CanonicalValueType.EXPLICIT_NULL)
    if type(value) is bool:
        return CanonicalValue(value_type=CanonicalValueType.BOOLEAN, boolean_value=value)
    if type(value) is int:
        return CanonicalValue(value_type=CanonicalValueType.INTEGER, integer_value=value)
    if isinstance(value, Decimal):
        return CanonicalValue(
            value_type=CanonicalValueType.DECIMAL, decimal_value=_decimal_text(value)
        )
    if isinstance(value, str):
        if len(value) > limits.maximum_string_length:
            raise OmivInputError("LIMIT_EXCEEDED:STRING_LENGTH")
        return CanonicalValue(value_type=CanonicalValueType.STRING, string_value=value)
    if isinstance(value, list) and all(type(item) is int for item in value):
        return CanonicalValue(value_type=CanonicalValueType.INTEGER_LIST, integer_list=tuple(value))
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return CanonicalValue(value_type=CanonicalValueType.STRING_LIST, string_list=tuple(value))
    return CanonicalValue(
        value_type=CanonicalValueType.TYPED_OBJECT_DIGEST,
        object_digest=canonical_sha256(
            {"type": type(value).__name__, "value": _canonical_json_value(value)}
        ),
    )


def observe_vocabulary_json(
    path: Path,
    binding: ArtifactBinding,
    execution: TokenizerConfigurationExecutionRecord,
    coverage: Iterable[CoverageDimension],
    *,
    limits: TokenizerConfigurationLimits | None = None,
) -> tuple[TokenizerAssetObservation, VocabularyObservation]:
    bounds = limits or TokenizerConfigurationLimits()
    raw, races = safe_read_asset(path, binding, bounds)
    parsed = parse_configuration_json(raw, source_name=path.name, limits=bounds)
    if len(parsed) > bounds.maximum_vocabulary_entries:
        raise OmivInputError("LIMIT_EXCEEDED:VOCABULARY_ENTRIES")
    asset = build_asset_observation(
        execution,
        binding,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=len(raw),
        format_identifier="token-to-id.json.v1",
        format_supported=True,
        race_findings=races,
    )
    source = object_reference(asset)
    entries: list[VocabularyEntry] = []
    for order, (token, token_id) in enumerate(parsed.items()):
        if type(token_id) is not int or token_id < 0 or token_id > bounds.maximum_token_id:
            raise OmivInputError("invalid or excessive vocabulary token ID")
        if len(token) > bounds.maximum_token_content_units:
            raise OmivInputError("LIMIT_EXCEEDED:TOKEN_CONTENT")
        entries.append(
            VocabularyEntry(
                token=canonical_text_token(token),
                token_id=token_id,
                source_order=order,
                provenance="observed.token-to-id-json",
                classification=TokenClassification.NOT_DECLARED,
                source_asset=source,
            )
        )
    return asset, build_vocabulary_observation(execution, asset, entries, coverage)


def observe_merge_table(
    path: Path,
    binding: ArtifactBinding,
    execution: TokenizerConfigurationExecutionRecord,
    coverage: Iterable[CoverageDimension],
    *,
    limits: TokenizerConfigurationLimits | None = None,
) -> tuple[TokenizerAssetObservation, MergeTableObservation]:
    bounds = limits or TokenizerConfigurationLimits()
    raw, races = safe_read_asset(path, binding, bounds)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OmivInputError("merge table must be valid UTF-8 for selected format") from exc
    asset = build_asset_observation(
        execution,
        binding,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=len(raw),
        format_identifier="bpe.merges.text.v1",
        format_supported=True,
        race_findings=races,
    )
    lines = text.splitlines()
    if any(len(line) > (2 * bounds.maximum_merge_operand_size + 1) for line in lines):
        raise OmivInputError("LIMIT_EXCEEDED:MERGE_LINE_LENGTH")
    header = lines[0] if lines and lines[0].startswith("#version:") else None
    data = lines[1:] if header is not None else lines
    records: list[MergeRecord] = []
    malformed = 0
    for source_order, line in enumerate(data):
        if not line:
            malformed += 1
            continue
        parts = line.split(" ")
        if len(parts) != 2 or any(len(p) > bounds.maximum_merge_operand_size for p in parts):
            malformed += 1
            continue
        records.append(
            MergeRecord(
                left=canonical_text_token(parts[0]),
                right=canonical_text_token(parts[1]),
                rank=len(records),
                source_order=source_order,
                provenance="observed.bpe-merge-text",
            )
        )
        if len(records) > bounds.maximum_merge_records:
            raise OmivInputError("LIMIT_EXCEEDED:MERGE_RECORDS")
    return asset, build_merge_observation(
        execution, asset, records, coverage, header=header, malformed_count=malformed
    )


def observe_chat_template(
    path: Path,
    binding: ArtifactBinding,
    execution: TokenizerConfigurationExecutionRecord,
    *,
    language: str | None,
    limits: TokenizerConfigurationLimits | None = None,
) -> tuple[TokenizerAssetObservation, ChatTemplateObservation]:
    bounds = limits or TokenizerConfigurationLimits()
    raw, races = safe_read_asset(path, binding, bounds)
    if len(raw) > bounds.maximum_chat_template_bytes:
        raise OmivInputError("LIMIT_EXCEEDED:CHAT_TEMPLATE_BYTES")
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OmivInputError("chat template text must be valid UTF-8") from exc
    asset = build_asset_observation(
        execution,
        binding,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_size=len(raw),
        format_identifier="untrusted.template.text.v1",
        format_supported=True,
        race_findings=races,
    )
    return asset, build_template_observation(
        execution,
        asset,
        content_digest=hashlib.sha256(raw).hexdigest(),
        content_size=len(raw),
        language=language,
    )


def escape_untrusted_text(value: str) -> str:
    """Escape controls and bidi controls for deterministic Markdown/terminal display."""
    rendered: list[str] = []
    presentation_controls = {
        0x061C,
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        *range(0x200E, 0x2010),
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    }
    markdown = {
        "\\",
        "`",
        "*",
        "_",
        "{",
        "}",
        "[",
        "]",
        "(",
        ")",
        "<",
        ">",
        "#",
        "!",
        "|",
    }
    for char in value:
        code = ord(char)
        if code < 32 or 0x7F <= code <= 0x9F or code in presentation_controls:
            rendered.append(f"\\u{code:04x}")
        elif char in markdown:
            rendered.append("\\" + char)
        else:
            rendered.append(char)
    return "".join(rendered)


def _check_json_bounds(value: Any, limits: TokenizerConfigurationLimits) -> None:
    count = 0

    def walk(child: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > limits.maximum_json_members:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_MEMBER_COUNT")
        if depth > limits.maximum_json_nesting:
            raise OmivInputError("LIMIT_EXCEEDED:JSON_NESTING")
        if isinstance(child, str) and len(child) > limits.maximum_string_length:
            raise OmivInputError("LIMIT_EXCEEDED:STRING_LENGTH")
        if isinstance(child, dict):
            for key, nested in child.items():
                walk(key, depth + 1)
                walk(nested, depth + 1)
        elif isinstance(child, list):
            for nested in child:
                walk(nested, depth + 1)

    walk(value, 0)


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return {"decimal": _decimal_text(value)}
    if isinstance(value, dict):
        return {key: _canonical_json_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_canonical_json_value(child) for child in value]
    return value


def _decimal_text(value: Decimal) -> str:
    if value == 0:
        return "0"
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _raise(message: str) -> Any:
    raise ValueError(message)
