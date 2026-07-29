"""Best-effort secure atomic writes for generated report artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path

from omiv.errors import OmivInputError


def _resolved(path: Path) -> Path:
    return path.resolve(strict=False)


def validate_output_path(
    path: Path,
    *,
    forbidden_inputs: Iterable[Path] = (),
) -> None:
    """Reject unsafe destinations before any final destination is modified."""
    if path.is_symlink():
        raise OmivInputError(f"output destination must not be a symlink: {path}")
    if path.exists() and not path.is_file():
        raise OmivInputError(
            f"output destination must be a regular file or absent: {path}"
        )
    output_resolved = _resolved(path)
    if any(output_resolved == _resolved(item) for item in forbidden_inputs):
        raise OmivInputError("output destination collides with an input path")


def atomic_write_text(
    path: Path,
    content: str,
    *,
    forbidden_inputs: Iterable[Path] = (),
) -> None:
    """Atomically replace a regular destination after a complete durable temp write."""
    validate_output_path(path, forbidden_inputs=forbidden_inputs)
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_output_path(path, forbidden_inputs=forbidden_inputs)

    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            text=False,
        )
        temporary = Path(temporary_name)
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        validate_output_path(path, forbidden_inputs=forbidden_inputs)
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise OmivInputError(f"cannot write output {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                temporary.unlink()
