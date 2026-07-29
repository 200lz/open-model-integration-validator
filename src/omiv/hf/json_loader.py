"""Bounded strict JSON loading shared by HF config, index, and headers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from omiv.errors import OmivInputError
from omiv.hf.limits import MAX_JSON_NESTING


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_NESTING:
        raise OmivInputError(
            f"JSON nesting exceeds maximum depth {MAX_JSON_NESTING}"
        )
    if isinstance(value, dict):
        for child in value.values():
            _check_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_depth(child, depth + 1)


def parse_bounded_json_bytes(
    raw: bytes,
    *,
    source_name: str,
    max_bytes: int,
    require_object: bool = True,
) -> Any:
    if len(raw) > max_bytes:
        raise OmivInputError(
            f"{source_name} exceeds byte limit {max_bytes}: {len(raw)}"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OmivInputError(f"{source_name} is not valid UTF-8: {exc}") from exc

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise OmivInputError(f"invalid JSON in {source_name}: {exc}") from exc
    _check_depth(value)
    if require_object and not isinstance(value, dict):
        raise OmivInputError(f"{source_name} must contain a top-level object")
    return value


def load_bounded_json(
    path: Path,
    *,
    max_bytes: int,
    require_object: bool = True,
) -> tuple[Any, bytes]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise OmivInputError(f"cannot stat {path.name}: {exc}") from exc
    if size > max_bytes:
        raise OmivInputError(
            f"{path.name} exceeds byte limit {max_bytes}: {size}"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OmivInputError(f"cannot read {path.name}: {exc}") from exc
    return (
        parse_bounded_json_bytes(
            raw,
            source_name=path.name,
            max_bytes=max_bytes,
            require_object=require_object,
        ),
        raw,
    )
