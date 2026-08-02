"""Portable path policy shared by expected and observed payload records."""

from __future__ import annotations

import re
import unicodedata

from omiv.payload_integrity.models import MAX_COMPONENT_LENGTH, MAX_PATH_LENGTH

_DRIVE = re.compile(r"^[A-Za-z]:")
_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def validate_portable_path(value: str) -> str:
    if not value or len(value) > MAX_PATH_LENGTH or unicodedata.normalize("NFC", value) != value:
        raise ValueError("unsafe payload path: empty, long, or non-NFC")
    if value.startswith(("/", "//")) or _DRIVE.match(value) or "://" in value or "\\" in value:
        raise ValueError("unsafe payload path: absolute or alternate syntax")
    if "\x00" in value or any(
        ord(c) < 32
        or ord(c) == 127
        or 0xD800 <= ord(c) <= 0xDFFF
        or (ord(c) & 0xFFFF) in {0xFFFE, 0xFFFF}
        for c in value
    ):
        raise ValueError("unsafe payload path: control, surrogate, or noncharacter")
    for part in value.split("/"):
        if (
            not part
            or part in {".", ".."}
            or len(part) > MAX_COMPONENT_LENGTH
            or part.endswith((" ", "."))
        ):
            raise ValueError("unsafe payload path component")
        if part.split(".", 1)[0].casefold() in _RESERVED or ":" in part:
            raise ValueError("platform-reserved payload path component")
    return value


def validate_path_set(paths: tuple[str, ...]) -> tuple[str, ...]:
    normalized: set[str] = set()
    exact: set[str] = set()
    for path in paths:
        validate_portable_path(path)
        key = unicodedata.normalize("NFC", path).casefold()
        if path in exact or key in normalized:
            raise ValueError("duplicate or portable-colliding payload path")
        exact.add(path)
        normalized.add(key)
    for path in exact:
        parts = path.split("/")
        if any("/".join(parts[:i]) in exact for i in range(1, len(parts))):
            raise ValueError("payload file/directory prefix conflict")
    return tuple(sorted(paths, key=lambda x: x.encode("utf-8")))
