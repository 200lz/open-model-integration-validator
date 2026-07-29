"""Shared deterministic JSON encoding and hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final, Literal

from omiv.errors import OmivInputError

CANONICALIZATION_ID: Final[Literal["omiv-json-v1"]] = "omiv-json-v1"


def canonical_json_bytes(value: Any) -> bytes:
    """Encode a JSON-compatible value using the OMIV canonical JSON profile."""
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OmivInputError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """Return the SHA-256 of an OMIV canonical JSON value."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_json_value(text: str) -> Any:
    """Load strict JSON, rejecting non-standard NaN and Infinity constants."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    try:
        return json.loads(text, parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise OmivInputError(f"invalid JSON: {exc}") from exc
