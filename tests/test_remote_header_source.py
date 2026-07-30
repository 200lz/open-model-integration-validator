from __future__ import annotations

import pytest

from omiv.errors import OmivInputError
from omiv.remote.header_models import HeaderParserPolicy
from omiv.remote.range_source import MAX_U64, RangeBackedByteSource
from tests.remote_gguf_helpers import SliceClient


def source(
    data: bytes = bytes(range(128)),
    *,
    policy: HeaderParserPolicy | None = None,
) -> tuple[RangeBackedByteSource, SliceClient]:
    selected = policy or HeaderParserPolicy(
        max_total_header_bytes=128,
        max_request_bytes=32,
        read_ahead_bytes=16,
        max_request_count=8,
    )
    client = SliceClient(data)
    result = RangeBackedByteSource(
        url="https://huggingface.co/file",
        file_size=len(data),
        client=client,  # type: ignore[arg-type]
        policy=selected,
    )
    return result, client


def test_exact_read_cache_overlap_and_deterministic_intervals() -> None:
    item, client = source()
    assert item.read_exact(0, 8, safe_prefetch_bytes=16) == bytes(range(8))
    assert client.calls == [(0, 24)]
    assert item.read_exact(4, 8) == bytes(range(4, 12))
    assert item.read_exact(20, 8, safe_prefetch_bytes=4) == bytes(range(20, 28))
    assert client.calls == [(0, 24), (24, 8)]
    assert [(entry.start, entry.end) for entry in item.requested_intervals] == [
        (0, 24),
        (24, 32),
    ]
    assert item.total_remote_bytes_accepted == 32
    assert item.highest_requested_offset == 31
    assert item.highest_accepted_offset == 31


def test_request_total_and_count_caps() -> None:
    item, _ = source(
        policy=HeaderParserPolicy(
            max_total_header_bytes=24,
            max_request_bytes=24,
            read_ahead_bytes=0,
            max_request_count=1,
        )
    )
    assert item.read_exact(0, 24) == bytes(range(24))
    with pytest.raises(OmivInputError, match="request-count"):
        item.read_exact(24, 1)

    capped, _ = source(
        policy=HeaderParserPolicy(
            max_total_header_bytes=24,
            max_request_bytes=24,
            read_ahead_bytes=0,
            max_request_count=2,
        )
    )
    capped.read_exact(0, 20)
    with pytest.raises(OmivInputError, match="total accepted"):
        capped.read_exact(20, 8)

    per_request, _ = source()
    with pytest.raises(OmivInputError, match="per-request"):
        per_request.read_exact(0, 33)


def test_short_client_body_file_end_and_arithmetic_checks() -> None:
    item, client = source(b"short")
    client.data = b"x"
    with pytest.raises(OmivInputError, match="unexpected length"):
        item.read_exact(0, 2)

    bounded, _ = source(b"1234")
    with pytest.raises(OmivInputError, match="file end"):
        bounded.read_exact(3, 2)
    with pytest.raises(OmivInputError, match="overflows"):
        bounded.read_exact(MAX_U64, 2)


def test_payload_boundary_prevents_reads_and_prefetch() -> None:
    item, client = source()
    item.read_exact(0, 16, safe_prefetch_bytes=16)
    item.set_payload_start(32)
    assert client.calls == [(0, 32)]
    with pytest.raises(OmivInputError, match="payload boundary"):
        item.read_exact(31, 2)
    assert item.highest_accepted_offset == 31

    crossed, _ = source(
        policy=HeaderParserPolicy(
            max_total_header_bytes=64,
            max_request_bytes=64,
            read_ahead_bytes=0,
        )
    )
    crossed.read_exact(0, 33)
    with pytest.raises(OmivInputError, match="already accepted"):
        crossed.set_payload_start(32)
