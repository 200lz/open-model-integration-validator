from __future__ import annotations

import os

import pytest

from omiv.remote.gguf_header import RemoteGGUFHeaderParser
from omiv.remote.header_models import HeaderParserPolicy
from omiv.remote.huggingface import HuggingFaceRepositoryAdapter
from omiv.remote.probe import (
    gguf_prefix_probe,
    resolved_file_url,
    selected_snapshot_file,
)
from omiv.remote.range_client import BoundedRangeClient
from omiv.remote.range_source import RangeBackedByteSource
from omiv.remote.reporting import snapshot_envelope


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
    first_path = complete[0].files[0]
    report = gguf_prefix_probe(
        snapshot_envelope(snapshot),
        path=first_path,
        client=BoundedRangeClient(max_response_bytes=8),
    )
    assert report.report.gguf_magic_valid
    assert report.report.bounded_range_evidence.response_byte_count == 8

    envelope = snapshot_envelope(snapshot)
    file = selected_snapshot_file(envelope, first_path)
    policy = HeaderParserPolicy()
    source = RangeBackedByteSource(
        url=resolved_file_url(envelope, first_path),
        file_size=file.byte_size,
        client=BoundedRangeClient(max_response_bytes=policy.max_request_bytes),
        policy=policy,
    )
    inventory = RemoteGGUFHeaderParser(policy).parse(
        source,
        repository=snapshot.repository,
        snapshot_sha256=envelope.integrity.sha256,
        file=file,
    )
    assert inventory.metadata_count == len(inventory.metadata)
    assert inventory.tensor_count == len(inventory.tensors)
    assert inventory.total_remote_bytes_accepted <= policy.max_total_header_bytes
    assert inventory.request_count <= policy.max_request_count
    assert inventory.highest_accepted_offset < inventory.payload_start_offset
