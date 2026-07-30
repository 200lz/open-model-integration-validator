"""Hugging Face Hub repository metadata adapter."""

from __future__ import annotations

import fnmatch
import importlib
import re
from typing import Any, Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from omiv.errors import OmivInputError
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.remote.models import (
    RemoteFile,
    RepositoryIdentity,
    RepositoryMetadata,
    RepositorySnapshot,
    SnapshotSelection,
    SnapshotSummary,
    StorageClass,
)
from omiv.remote.paths import is_within_prefix, validate_remote_path
from omiv.remote.split import detect_split_candidates

MAX_METADATA_BYTES = 16 * 1024 * 1024
_REPO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_COMMIT = re.compile(r"^[0-9a-f]{40,64}$")


class RepositoryMetadataClient(Protocol):
    def model_info(self, repo_id: str, revision: str) -> dict[str, Any]:
        """Return documented Hub model metadata without fetching file bodies."""


class HuggingFaceRestMetadataClient:
    """Small documented Hub REST client used when the optional SDK is absent."""

    def __init__(self, *, timeout: float = 30.0) -> None:
        if timeout <= 0:
            raise OmivInputError("metadata timeout must be positive")
        self.timeout = timeout

    def model_info(self, repo_id: str, revision: str) -> dict[str, Any]:
        encoded_repo = quote(repo_id, safe="/")
        encoded_revision = quote(revision, safe="")
        query = urlencode({"blobs": "true", "securityStatus": "true"})
        url = (
            f"https://huggingface.co/api/models/{encoded_repo}/revision/"
            f"{encoded_revision}?{query}"
        )
        request = Request(  # noqa: S310 - fixed HTTPS provider endpoint
            url,
            headers={"Accept": "application/json", "User-Agent": "omiv/0.1"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                raw = response.read(MAX_METADATA_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise OmivInputError(f"Hugging Face metadata request failed: {exc}") from exc
        value = parse_bounded_json_bytes(
            raw,
            source_name="Hugging Face model metadata",
            max_bytes=MAX_METADATA_BYTES,
        )
        assert isinstance(value, dict)
        return value


class HuggingFaceHubMetadataClient:
    """Lazy optional ``huggingface_hub`` metadata client."""

    def __init__(self) -> None:
        try:
            module = importlib.import_module("huggingface_hub")
        except ImportError as exc:
            raise OmivInputError(
                "huggingface_hub is not installed; use the documented REST metadata client"
            ) from exc
        self._api: Any = module.HfApi()

    def model_info(self, repo_id: str, revision: str) -> dict[str, Any]:
        try:
            info = self._api.model_info(
                repo_id,
                revision=revision,
                files_metadata=True,
                securityStatus=True,
            )
        except Exception as exc:  # optional SDK has a provider-specific exception tree
            raise OmivInputError(f"Hugging Face metadata request failed: {exc}") from exc
        if hasattr(info, "__dict__"):
            value = _plain_sdk_value(info)
            if isinstance(value, dict):
                return value
        raise OmivInputError("Hugging Face client returned unsupported model metadata")


def _plain_sdk_value(value: Any) -> Any:
    """Convert SDK metadata objects without retaining provider implementation types."""
    if isinstance(value, dict):
        return {str(key): _plain_sdk_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_sdk_value(child) for child in value]
    if hasattr(value, "__dict__"):
        return {
            str(key): _plain_sdk_value(child)
            for key, child in vars(value).items()
            if not str(key).startswith("_")
        }
    return value


def _optional_string(value: object, *, field: str, max_length: int = 512) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise OmivInputError(f"invalid Hugging Face {field}")
    if (
        "://" in value
        or "?" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OmivInputError(f"unsafe Hugging Face {field}")
    return value


def _file_from_sibling(sibling: dict[str, Any]) -> RemoteFile:
    raw_path = sibling.get("rfilename", sibling.get("path"))
    if not isinstance(raw_path, str):
        raise OmivInputError("Hugging Face sibling is missing rfilename")
    path = validate_remote_path(raw_path)
    lfs_value = sibling.get("lfs")
    lfs = lfs_value if isinstance(lfs_value, dict) else {}
    size_value = sibling.get("size")
    if size_value is None:
        size_value = lfs.get("size")
    if isinstance(size_value, bool) or not isinstance(size_value, int) or size_value < 0:
        raise OmivInputError(f"file metadata has invalid or missing size: {path}")
    xet_hash = _optional_string(
        sibling.get("xetHash", sibling.get("xet_hash")),
        field="xet hash",
        max_length=256,
    )
    lfs_sha256 = _optional_string(lfs.get("sha256"), field="LFS SHA-256", max_length=64)
    if lfs_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", lfs_sha256):
        raise OmivInputError(f"file metadata has invalid LFS SHA-256: {path}")
    blob_id = _optional_string(
        sibling.get("blobId", sibling.get("blob_id")),
        field="blob ID",
        max_length=256,
    )
    oid = _optional_string(sibling.get("oid"), field="OID", max_length=256)
    etag = _optional_string(sibling.get("etag"), field="ETag")
    storage = (
        StorageClass.XET
        if xet_hash is not None
        else StorageClass.LFS
        if lfs
        else StorageClass.GIT
        if blob_id is not None
        else StorageClass.UNKNOWN
    )
    return RemoteFile(
        path=path,
        byte_size=size_value,
        storage=storage,
        etag=etag,
        oid=oid or blob_id,
        xet_hash=xet_hash,
        lfs_sha256=lfs_sha256,
    )


class HuggingFaceRepositoryAdapter:
    provider = "huggingface"

    def __init__(self, metadata_client: RepositoryMetadataClient | None = None) -> None:
        self.metadata_client = metadata_client or HuggingFaceRestMetadataClient()

    def snapshot(
        self,
        *,
        repo_id: str,
        revision: str,
        path_prefix: str | None,
        patterns: list[str],
        strict_subtree: bool = True,
    ) -> RepositorySnapshot:
        if not _REPO_ID.fullmatch(repo_id):
            raise OmivInputError("Hugging Face repository ID must be OWNER/NAME")
        if not revision or len(revision) > 256 or any(ord(char) < 32 for char in revision):
            raise OmivInputError("invalid Hugging Face revision")
        prefix = (
            validate_remote_path(path_prefix, label="path prefix")
            if path_prefix is not None
            else None
        )
        if len(patterns) > 64:
            raise OmivInputError("too many selection patterns")
        for pattern in patterns:
            if not pattern or len(pattern) > 256 or "\\" in pattern or "\x00" in pattern:
                raise OmivInputError("invalid selection pattern")

        metadata = self.metadata_client.model_info(repo_id, revision)
        resolved = metadata.get("sha")
        if not isinstance(resolved, str) or not _COMMIT.fullmatch(resolved):
            raise OmivInputError("Hugging Face did not resolve a full immutable commit")
        if _COMMIT.fullmatch(revision) and resolved != revision:
            raise OmivInputError("resolved commit does not match requested pinned revision")
        raw_siblings = metadata.get("siblings")
        if not isinstance(raw_siblings, list):
            raise OmivInputError("Hugging Face metadata is missing sibling listing")

        all_files: list[RemoteFile] = []
        seen: set[str] = set()
        for raw in raw_siblings:
            if not isinstance(raw, dict):
                raise OmivInputError("invalid Hugging Face sibling metadata")
            file = _file_from_sibling(raw)
            if file.path in seen:
                raise OmivInputError(f"duplicate remote path: {file.path}")
            seen.add(file.path)
            all_files.append(file)

        selected = [
            item
            for item in all_files
            if is_within_prefix(item.path, prefix)
            and (
                not patterns
                or any(fnmatch.fnmatchcase(item.path, pattern) for pattern in patterns)
            )
        ]
        if strict_subtree and any(not is_within_prefix(item.path, prefix) for item in selected):
            raise OmivInputError("selected path escaped the strict subtree")
        selected.sort(key=lambda item: item.path)
        candidates, extras = detect_split_candidates([item.path for item in selected])
        security = metadata.get("securityStatus", metadata.get("security_status"))
        security_status = (
            security
            if isinstance(security, str)
            else security.get("status")
            if isinstance(security, dict) and isinstance(security.get("status"), str)
            else None
        )
        if security_status is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}", security_status
        ):
            raise OmivInputError("unsafe Hugging Face security status")
        gated = metadata.get("gated")
        if gated not in (None, False, True, "auto", "manual"):
            raise OmivInputError("invalid Hugging Face gated metadata")
        gated_value: bool | Literal["auto", "manual"] | None
        gated_value = (
            gated if gated in ("auto", "manual") or isinstance(gated, bool) else None
        )
        return RepositorySnapshot(
            snapshot_schema="omiv.remote-repository-snapshot.v1",
            provider="huggingface",
            repository=RepositoryIdentity(
                repo_id=repo_id,
                repo_type="model",
                requested_revision=revision,
                resolved_revision=resolved,
            ),
            repository_metadata=RepositoryMetadata(
                private=(
                    metadata.get("private")
                    if isinstance(metadata.get("private"), bool)
                    else None
                ),
                gated=gated_value,
                security_status=security_status,
            ),
            selection=SnapshotSelection(
                path_prefix=prefix,
                patterns=list(patterns),
                strict_subtree=strict_subtree,
            ),
            files=selected,
            summary=SnapshotSummary(
                file_count=len(selected),
                total_byte_size=sum(item.byte_size for item in selected),
                gguf_file_count=sum(item.path.lower().endswith(".gguf") for item in selected),
                candidate_split_sets=candidates,
                extra_gguf_files=extras,
            ),
        )
