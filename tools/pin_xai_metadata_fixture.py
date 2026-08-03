"""Normalize reviewed temporary xAI captures into minimal pinned source fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from omiv.reconciliation.reporting import pretty_json
from omiv.reconciliation_profiles.xai import FIXTURE_CLASSIFICATION, build_pinned_fixture
from omiv.safe_write import atomic_write_text

EXPECTED = {
    "grok-1": {
        "revision": "5de83eb225f49624b424f1c8aa74f96983b5885c",
        "members": 773,
        "bytes": 318_239_889_830,
    },
    "grok-2": {
        "revision": "daf4395a80ad177386cfe39641b64fc12b1d70ed",
        "members": 44,
        "bytes": 539_040_431_665,
    },
}


def normalize_capture(capture: Path, repository: str):
    expected = EXPECTED[repository]
    model_raw = (capture / "raw" / "model.json").read_bytes()
    tree_paths = sorted((capture / "raw").glob("tree-*.json"))
    if not tree_paths or [path.name for path in tree_paths] != [
        f"tree-{index:04}.json" for index in range(len(tree_paths))
    ]:
        raise ValueError("capture lacks a complete sequential normalized tree-page set")
    model = _strict_json(model_raw)
    tree_pages = [_strict_json(path.read_bytes()) for path in tree_paths]
    execution = _strict_json((capture / "execution.json").read_bytes())
    snapshot = _strict_json((capture / "snapshot.json").read_bytes())
    full_name = f"xai-org/{repository}"
    if model.get("id") != full_name or model.get("modelId") != full_name:
        raise ValueError("provider response repository identity mismatch")
    if model.get("sha") != expected["revision"]:
        raise ValueError("provider response resolved revision changed")
    if snapshot.get("resolved_revision") != expected["revision"]:
        raise ValueError("normalized snapshot resolved revision changed")
    raw_entries = [item for page in tree_pages for item in _require_list(page)]
    members = [_normalize_member(item) for item in raw_entries if item.get("type") != "directory"]
    members.sort(key=lambda item: item["path"].encode())
    paths = [item["path"] for item in members]
    if len(paths) != len(set(paths)):
        raise ValueError("provider tree contains duplicate normalized paths")
    if len(members) != expected["members"]:
        raise ValueError("provider member count changed materially")
    if sum(item["declared_size"] for item in members) != expected["bytes"]:
        raise ValueError("provider declared total bytes changed materially")
    snapshot_members = snapshot.get("members")
    if (
        not isinstance(snapshot_members, list)
        or [item["path"] for item in snapshot_members] != paths
    ):
        raise ValueError("adapter snapshot does not reconstruct raw provider paths")
    expected_urls = {
        f"https://huggingface.co/api/models/{full_name}/revision/{expected['revision']}",
        f"https://huggingface.co/api/models/{full_name}/tree/{expected['revision']}",
    }
    if set(execution.get("requested_urls", [])) != expected_urls:
        raise ValueError("request coverage or secret-safe endpoint set mismatch")
    response_bytes = len(model_raw) + sum(path.stat().st_size for path in tree_paths)
    if execution.get("response_bytes") != response_bytes:
        raise ValueError("response-byte accounting does not reconstruct retained capture")
    for key, value in {
        "request_count": 1 + len(tree_paths),
        "response_count": 1 + len(tree_paths),
        "payload_bytes_downloaded": 0,
    }.items():
        if execution.get(key) != value:
            raise ValueError(f"execution accounting mismatch: {key}")
    if execution.get("redirect_hosts") != [] or execution.get("contacted_hosts") != [
        "huggingface.co"
    ]:
        raise ValueError("capture host or redirect coverage mismatch")
    if (
        execution.get("available_at") != "NOT_RECORDED"
        or execution.get("observed_at") != "NOT_RECORDED"
    ):
        raise ValueError("capture contains an implicit or unreviewed time")
    body = {
        "schema": "omiv.pinned-public-provider-metadata-fixture.v1",
        "classification": FIXTURE_CLASSIFICATION,
        "provider": "HUGGING_FACE",
        "namespace": "xai-org",
        "repository": repository,
        "resolved_revision": expected["revision"],
        "resolved_revision_kind": "IMMUTABLE_COMMIT",
        "members": members,
        "source_endpoint_class": ("HUGGING_FACE_PUBLIC_MODEL_REVISION_AND_RECURSIVE_TREE_API"),
        "provider_listing_coverage": "COMPLETE_PINNED_PROVIDER_LISTING_SCOPE",
        "imported_tree_pages": len(tree_paths),
        "pagination_termination": "NO_NEXT_LINK_OBSERVED_BY_BOUNDED_ADAPTER",
        "request_count": execution["request_count"],
        "response_count": execution["response_count"],
        "response_bytes": execution["response_bytes"],
        "redirect_count": 0,
        "weight_file_get_count": 0,
        "payload_bytes_downloaded": 0,
        "raw_response_retention": "NOT_RETAINED",
        "availability": "NOT_RECORDED",
        "observation_time": "NOT_RECORDED",
        "publisher_authority": "NOT_ESTABLISHED",
        "payload_observation": "NOT_PERFORMED",
        "payload_comparability": "DIGEST_NOT_COMPARABLE",
        "freshness_current_state": "NOT_ESTABLISHED",
        "model_authenticity": "NOT_ESTABLISHED",
        "security_safety": "NOT_EVALUATED",
        "tokenizer_config_parity": "NOT_EVALUATED",
        "runtime_identity": "NOT_OBSERVED",
        "limitations": [
            "Normalized public provider metadata is not an official xAI attestation or "
            "publisher-authorized manifest.",
            "No model payload bytes, credentials, signed URLs, local paths, provider UI fields, "
            "or collection timestamp are retained.",
            "Provider listing completeness is separate from shard/tensor topology, local "
            "presence, payload equality, authenticity, safety, and current state.",
        ],
    }
    return build_pinned_fixture(body)


def _normalize_member(item: dict[str, Any]) -> dict[str, Any]:
    path = item.get("path")
    size = item.get("size")
    oid = item.get("oid")
    if not isinstance(path, str) or not isinstance(size, int) or size < 0:
        raise ValueError("invalid provider member path or declared size")
    if not isinstance(oid, str):
        raise ValueError("provider member lacks object identity")
    digests = [{"kind": "PROVIDER_OPAQUE_ID", "canonical_value": oid}]
    xet = item.get("xetHash")
    lfs = item.get("lfs")
    storage = "DIRECT_FILE"
    if xet is not None or lfs is not None:
        if not isinstance(xet, str) or not isinstance(lfs, dict):
            raise ValueError("partial Xet/LFS metadata cannot be pinned")
        lfs_oid = lfs.get("oid")
        if not isinstance(lfs_oid, str):
            raise ValueError("LFS metadata lacks a typed OID")
        if lfs_oid == xet or oid in {lfs_oid, xet}:
            raise ValueError("provider digest-like identifiers lost semantic distinction")
        digests.extend(
            [
                {"kind": "LFS_OID_SHA256", "canonical_value": lfs_oid},
                {"kind": "XET_OBJECT_ID", "canonical_value": xet},
            ]
        )
        storage = "XET_BACKED_OBJECT"
    digests.sort(key=lambda value: value["kind"])
    return {
        "path": path,
        "declared_size": size,
        "storage_representation": storage,
        "digests": digests,
    }


def _strict_json(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("provider tree page must contain only JSON objects")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    for repository in sorted(EXPECTED):
        fixture = normalize_capture(args.capture_root / repository, repository)
        output = args.output_root / f"{repository}.pinned-metadata.json"
        atomic_write_text(output, pretty_json(fixture))


if __name__ == "__main__":
    main()
