from __future__ import annotations

import os
from pathlib import Path

import pytest

from omiv.remote.gguf_header import RemoteGGUFHeaderParser
from omiv.remote.header_models import HeaderParserPolicy
from omiv.remote.header_reporting import (
    build_header_inventory_envelope,
    load_header_inventory,
)
from omiv.remote.huggingface import HuggingFaceRepositoryAdapter
from omiv.remote.probe import (
    gguf_prefix_probe,
    resolved_file_url,
    selected_snapshot_file,
)
from omiv.remote.range_client import BoundedRangeClient
from omiv.remote.range_source import RangeBackedByteSource
from omiv.remote.reporting import snapshot_envelope
from omiv.remote.split_aggregation import (
    aggregate_split_inventories,
    validate_reusable_inventory,
)


@pytest.mark.remote_integration
def test_real_huggingface_snapshot_and_prefix_range() -> None:
    if os.environ.get("OMIV_RUN_REMOTE_INTEGRATION") != "1":
        pytest.skip("set OMIV_RUN_REMOTE_INTEGRATION=1 to run remote integration")
    repo = os.environ.get("OMIV_HF_REPO", "unsloth/Kimi-K3-GGUF")
    revision = os.environ.get("OMIV_HF_REVISION", "main")
    prefix = os.environ.get("OMIV_HF_PATH_PREFIX", "UD-IQ1_M")
    snapshot = HuggingFaceRepositoryAdapter().snapshot(
        repo_id=repo,
        revision=revision,
        path_prefix=prefix,
        patterns=["*.gguf"],
    )
    assert snapshot.repository.resolved_revision != "main"
    complete = [item for item in snapshot.summary.candidate_split_sets if item.complete]
    assert complete
    candidate = complete[0]
    first_path = candidate.files[0]
    report = gguf_prefix_probe(
        snapshot_envelope(snapshot),
        path=first_path,
        client=BoundedRangeClient(max_response_bytes=8),
    )
    assert report.report.gguf_magic_valid
    assert report.report.bounded_range_evidence.response_byte_count == 8

    envelope = snapshot_envelope(snapshot)
    policy = HeaderParserPolicy()
    inventory_directory = Path(
        "inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M/shards"
    )
    reusable_paths = {
        item.inventory.file.path: item
        for item in (
            load_header_inventory(path)
            for path in sorted(inventory_directory.glob("*.header.inventory.json"))
        )
    }
    if first_path not in reusable_paths:
        canonical = load_header_inventory(
            Path(
                "inventories/remote/"
                "unsloth_Kimi-K3-GGUF_UD-IQ1_M_shard1.header.inventory.json"
            )
        )
        reusable_paths[first_path] = canonical
    inventories = []
    reused_count = 0
    for path in candidate.files:
        reusable = reusable_paths.get(path)
        if reusable is not None:
            validate_reusable_inventory(
                reusable,
                snapshot=envelope,
                expected_path=path,
                expected_policy_sha256=policy.digest,
            )
            inventories.append(reusable)
            reused_count += 1
            continue
        selected = selected_snapshot_file(envelope, path)
        shard_source = RangeBackedByteSource(
            url=resolved_file_url(envelope, path),
            file_size=selected.byte_size,
            client=BoundedRangeClient(max_response_bytes=policy.max_request_bytes),
            policy=policy,
        )
        parsed = RemoteGGUFHeaderParser(policy).parse(
            shard_source,
            repository=snapshot.repository,
            snapshot_sha256=envelope.integrity.sha256,
            file=selected,
        )
        assert parsed.highest_accepted_offset < parsed.payload_start_offset
        inventories.append(build_header_inventory_envelope(parsed))
    combined = aggregate_split_inventories(
        envelope, inventories, reused_inventory_count=reused_count
    )
    assert combined.shard_count == len(candidate.files)
    assert combined.aggregated_tensor_count == combined.global_tensor_count_metadata
    assert combined.payload_span_summary.invalid_count == 0
