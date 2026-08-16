"""Bounded strict JSON loading shared by HF config, index, and headers."""

from __future__ import annotations

import json
import os
import stat
from contextlib import suppress
from pathlib import Path
from typing import Any

from omiv.errors import OmivInputError
from omiv.hf.limits import MAX_JSON_NESTING

_JSON_READ_CHUNK_BYTES = 64 * 1024


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _descriptor_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_NESTING:
        raise OmivInputError(f"JSON nesting exceeds maximum depth {MAX_JSON_NESTING}")
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
        raise OmivInputError(f"{source_name} exceeds byte limit {max_bytes}: {len(raw)}")
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


def _require_atomic_no_follow() -> int:
    """Return the atomic no-follow open flag or fail closed.

    A non-following ``stat`` followed by a following ``os.open`` is raceable: an
    attacker can replace the pathname with a symlink to the same inode between
    the two calls, so the device/inode comparison still passes.  There is no
    safe emulation, so the loader refuses untrusted pathnames instead.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    # The gate is checked on the exact value that becomes an open flag.  A
    # non-integer, a boolean, or a value that is truthy yet truncates to zero
    # would otherwise pass a truthiness test and still produce a following open.
    if not isinstance(nofollow, int) or isinstance(nofollow, bool) or nofollow <= 0:
        raise OmivInputError("cannot safely open JSON input without atomic no-follow support")
    return nofollow


def load_bounded_json(
    path: Path,
    *,
    max_bytes: int,
    require_object: bool = True,
) -> tuple[Any, bytes]:
    # Resolved before any open or read so an unsupported platform cannot reach
    # the filesystem at all.  A kernel that rejects the flag fails closed too:
    # the open is never retried without it.
    nofollow = _require_atomic_no_follow()
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | nofollow
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise OmivInputError("cannot safely open JSON input") from exc
    try:
        if not stat.S_ISREG(before.st_mode):
            raise OmivInputError("JSON input must be a regular non-symlink file")
        if before.st_size > max_bytes:
            raise OmivInputError(f"JSON input exceeds byte limit {max_bytes}")

        raw_buffer = bytearray()
        observation_limit = max_bytes + 1
        while len(raw_buffer) < observation_limit:
            request_bytes = min(
                _JSON_READ_CHUNK_BYTES,
                observation_limit - len(raw_buffer),
            )
            chunk = os.read(descriptor, request_bytes)
            if not chunk:
                break
            # os.read never returns more than requested.  Keep this explicit so
            # even an incoherent platform result cannot enlarge the retained
            # observation beyond max_bytes + 1.
            if len(chunk) > request_bytes:
                raise OmivInputError("JSON input returned an incoherent read")
            raw_buffer.extend(chunk)
            if len(raw_buffer) > max_bytes:
                raise OmivInputError(f"JSON input exceeds byte limit {max_bytes}")

        after = os.fstat(descriptor)
        observed_bytes = len(raw_buffer)
        if (
            _descriptor_metadata(after) != _descriptor_metadata(before)
            or observed_bytes != before.st_size
            or observed_bytes != after.st_size
        ):
            raise OmivInputError("JSON input changed during bounded read")
        raw = bytes(raw_buffer)
    except OSError as exc:
        raise OmivInputError("cannot safely read JSON input") from exc
    finally:
        with suppress(OSError):
            os.close(descriptor)

    return (
        parse_bounded_json_bytes(
            raw,
            source_name="JSON input",
            max_bytes=max_bytes,
            require_object=require_object,
        ),
        raw,
    )
