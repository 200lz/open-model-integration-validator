from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from omiv.errors import OmivInputError
from omiv.remote.huggingface import (
    HuggingFaceHubMetadataClient,
    HuggingFaceRepositoryAdapter,
)
from omiv.remote.paths import validate_remote_path
from omiv.remote.split import detect_split_candidates

SHA = "a" * 40


class MetadataClient:
    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value
        self.calls: list[tuple[str, str]] = []

    def model_info(self, repo_id: str, revision: str) -> dict[str, Any]:
        self.calls.append((repo_id, revision))
        return self.value


def sibling(
    path: str,
    size: int = 10,
    *,
    lfs: bool = False,
    xet: bool = False,
) -> dict[str, Any]:
    value: dict[str, Any] = {"rfilename": path, "size": size, "blobId": "blob"}
    if lfs:
        value["lfs"] = {"size": size, "sha256": "b" * 64, "pointerSize": 130}
    if xet:
        value["xetHash"] = "xet-content-id"
    return value


def snapshot_for(
    siblings: list[dict[str, Any]], *, revision: str = "main"
) -> tuple[object, MetadataClient]:
    client = MetadataClient(
        {
            "sha": SHA,
            "private": False,
            "gated": False,
            "securityStatus": {"status": "safe"},
            "siblings": siblings,
        }
    )
    result = HuggingFaceRepositoryAdapter(client).snapshot(
        repo_id="owner/repo",
        revision=revision,
        path_prefix="quant",
        patterns=["*.gguf"],
    )
    return result, client


def test_mutable_revision_resolves_and_pinned_revision_stays_pinned() -> None:
    snapshot, client = snapshot_for([sibling("quant/a.gguf")])
    assert snapshot.repository.requested_revision == "main"
    assert snapshot.repository.resolved_revision == SHA
    assert client.calls == [("owner/repo", "main")]

    pinned, _ = snapshot_for([sibling("quant/a.gguf")], revision=SHA)
    assert pinned.repository.requested_revision == SHA
    with pytest.raises(OmivInputError, match="does not match"):
        bad_client = MetadataClient({"sha": "c" * 40, "siblings": []})
        HuggingFaceRepositoryAdapter(bad_client).snapshot(
            repo_id="owner/repo",
            revision=SHA,
            path_prefix=None,
            patterns=[],
        )


def test_selection_is_safe_sorted_deterministic_and_metadata_only() -> None:
    snapshot, client = snapshot_for(
        [
            sibling("outside/no.gguf", 99),
            sibling("quant/z.gguf", 12, lfs=True),
            sibling("quant/a.gguf", 11, xet=True),
            sibling("quant/readme.txt", 3),
        ]
    )
    assert [item.path for item in snapshot.files] == ["quant/a.gguf", "quant/z.gguf"]
    assert [item.storage.value for item in snapshot.files] == ["xet", "lfs"]
    assert snapshot.files[1].lfs_sha256 == "b" * 64
    assert snapshot.repository_metadata.security_status == "safe"
    assert snapshot == snapshot.model_copy(deep=True)
    assert client.calls == [("owner/repo", "main")]


def test_empty_selection_and_duplicate_path() -> None:
    snapshot, _ = snapshot_for([sibling("other/a.gguf")])
    assert snapshot.summary.file_count == 0
    with pytest.raises(OmivInputError, match="duplicate remote path"):
        snapshot_for([sibling("quant/a.gguf"), sibling("quant/a.gguf")])


@pytest.mark.parametrize(
    "path",
    [
        "/absolute",
        "a\\b",
        "a//b",
        "a/./b",
        "a/../b",
        "a/%2e%2e/b",
        "a/%252e%252e/b",
        "a/\x00b",
        "a/\x1fb",
        "a/" + "x" * 1025,
    ],
)
def test_unsafe_paths_are_rejected(path: str) -> None:
    with pytest.raises(OmivInputError):
        validate_remote_path(path)


def test_invalid_size_and_metadata_storage_parsing() -> None:
    with pytest.raises(OmivInputError, match="size"):
        snapshot_for([{"rfilename": "quant/a.gguf", "size": -1}])
    with pytest.raises(OmivInputError, match="size"):
        snapshot_for([{"rfilename": "quant/a.gguf"}])
    with pytest.raises(OmivInputError, match="LFS SHA"):
        snapshot_for(
            [
                {
                    "rfilename": "quant/a.gguf",
                    "size": 1,
                    "lfs": {"size": 1, "sha256": "bad"},
                }
            ]
        )


def test_optional_sdk_metadata_objects_are_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    info = SimpleNamespace(
        sha=SHA,
        private=False,
        gated=False,
        siblings=[
            SimpleNamespace(
                rfilename="quant/a.gguf",
                size=7,
                blob_id="blob",
                lfs=SimpleNamespace(size=7, sha256="b" * 64, pointer_size=120),
            )
        ],
    )
    api = SimpleNamespace(model_info=lambda *args, **kwargs: info)
    module = SimpleNamespace(HfApi=lambda: api)
    monkeypatch.setattr(
        "omiv.remote.huggingface.importlib.import_module",
        lambda name: module,
    )
    client = HuggingFaceHubMetadataClient()
    snapshot = HuggingFaceRepositoryAdapter(client).snapshot(
        repo_id="owner/repo",
        revision="main",
        path_prefix="quant",
        patterns=["*.gguf"],
    )
    assert snapshot.files[0].storage.value == "lfs"
    assert snapshot.files[0].oid == "blob"


def test_split_candidates_are_generic_and_report_layout_failures() -> None:
    valid, extras = detect_split_candidates(
        [f"q/model-{ordinal:05d}-of-00003.gguf" for ordinal in range(1, 4)]
    )
    assert extras == []
    assert valid[0].declared_shard_count == 3
    assert valid[0].observed_ordinals == [1, 2, 3]
    assert valid[0].complete

    missing, _ = detect_split_candidates(
        ["m-00001-of-00004.gguf", "m-00003-of-00004.gguf"]
    )
    assert missing[0].missing_ordinals == [2, 4]
    assert missing[0].non_contiguous

    duplicate, _ = detect_split_candidates(
        ["m-00001-of-00002.gguf", "m-00001-of-00002.gguf", "m-00002-of-00002.gguf"]
    )
    assert duplicate[0].duplicate_ordinals == [1]

    inconsistent, _ = detect_split_candidates(
        ["m-00001-of-00002.gguf", "m-00002-of-00003.gguf"]
    )
    assert inconsistent[0].inconsistent_declared_counts == [2, 3]

    two, unrelated = detect_split_candidates(
        [
            "a-00001-of-00001.gguf",
            "b-00001-of-00001.gguf",
            "standalone.gguf",
        ]
    )
    assert len(two) == 2
    assert unrelated == ["standalone.gguf"]
