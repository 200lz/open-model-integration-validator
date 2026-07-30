from __future__ import annotations

import os

import pytest

from omiv.remote.huggingface import HuggingFaceRepositoryAdapter
from omiv.remote.probe import gguf_prefix_probe
from omiv.remote.range_client import BoundedRangeClient
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
