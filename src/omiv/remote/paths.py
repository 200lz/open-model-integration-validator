"""Validation for untrusted remote POSIX paths."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import unquote

from omiv.errors import OmivInputError

MAX_REMOTE_PATH_LENGTH = 1024
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def validate_remote_path(value: str, *, label: str = "remote path") -> str:
    if not isinstance(value, str) or not value:
        raise OmivInputError(f"{label} must be a non-empty string")
    if len(value) > MAX_REMOTE_PATH_LENGTH:
        raise OmivInputError(f"{label} exceeds {MAX_REMOTE_PATH_LENGTH} characters")
    if "\\" in value:
        raise OmivInputError(f"{label} contains a backslash")
    if _CONTROL.search(value):
        raise OmivInputError(f"{label} contains a control character")
    if value.startswith("/") or PurePosixPath(value).is_absolute():
        raise OmivInputError(f"{label} must be relative")
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    if "\\" in decoded or decoded.startswith("/") or _CONTROL.search(decoded):
        raise OmivInputError(f"{label} is unsafe after percent decoding")
    components = decoded.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise OmivInputError(f"{label} contains an empty or traversal component")
    return value


def is_within_prefix(path: str, prefix: str | None) -> bool:
    if prefix is None:
        return True
    return path == prefix or path.startswith(prefix + "/")
