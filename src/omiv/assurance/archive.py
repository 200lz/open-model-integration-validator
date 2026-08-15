"""Deterministic, bounded ZIP_STORED transport for portable .omiv bundles."""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from omiv.assurance.operations import MAX_TOTAL_BYTES
from omiv.errors import OmivInputError
from omiv.payload_integrity.paths import validate_path_set, validate_portable_path

ARCHIVE_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_ARCHIVE_ENTRIES = 320


def pack_bundle(root: Path, output: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise OmivInputError("bundle root must be a regular non-symlink directory")
    if output.exists() or output.is_symlink():
        raise OmivInputError(".omiv output must not already exist")
    paths = sorted(
        (path.relative_to(root).as_posix(), path) for path in root.rglob("*") if path.is_file()
    )
    if not paths or len(paths) > MAX_ARCHIVE_ENTRIES:
        raise OmivInputError("LIMIT_EXCEEDED:ARCHIVE_ENTRY_COUNT")
    validate_path_set(tuple(name for name, _path in paths))
    if any(path.is_symlink() for _name, path in paths):
        raise OmivInputError("symbolic links are not permitted in .omiv archives")
    total = sum(path.stat().st_size for _name, path in paths)
    if total > MAX_TOTAL_BYTES:
        raise OmivInputError("LIMIT_EXCEEDED:ARCHIVE_TOTAL_BYTES")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.comment = b""
            for name, path in paths:
                info = zipfile.ZipInfo(name, ARCHIVE_TIMESTAMP)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                with path.open("rb") as source, archive.open(info, "w") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def extract_archive(archive_path: Path, destination: Path) -> None:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise OmivInputError(".omiv input must be a regular non-symlink file")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
                raise OmivInputError("LIMIT_EXCEEDED:ARCHIVE_ENTRY_COUNT")
            names = tuple(info.filename for info in infos)
            validate_path_set(names)
            total = 0
            for info in infos:
                validate_portable_path(info.filename)
                if info.is_dir() or info.compress_type != zipfile.ZIP_STORED:
                    raise OmivInputError(".omiv requires regular ZIP_STORED entries")
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in {0, 0o100000}:
                    raise OmivInputError(".omiv archive contains a non-regular entry")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise OmivInputError("LIMIT_EXCEEDED:ARCHIVE_TOTAL_BYTES")
                target = destination / Path(*info.filename.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except (OSError, zipfile.BadZipFile) as exc:
        raise OmivInputError(f"invalid .omiv archive: {exc}") from exc
