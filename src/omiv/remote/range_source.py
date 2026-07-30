"""Bounded cache-backed random access over validated HTTP Range reads."""

from __future__ import annotations

from omiv.errors import OmivInputError
from omiv.remote.header_models import HeaderParserPolicy, RequestedInterval
from omiv.remote.range_client import BoundedRangeClient

MAX_U64 = (1 << 64) - 1


class RangeBackedByteSource:
    """A last-window cache whose intervals use half-open ``[start, end)`` semantics."""

    def __init__(
        self,
        *,
        url: str,
        file_size: int,
        client: BoundedRangeClient,
        policy: HeaderParserPolicy,
    ) -> None:
        if file_size < 0 or file_size > MAX_U64:
            raise OmivInputError("remote file size is outside unsigned 64-bit range")
        self.url = url
        self.file_size = file_size
        self.client = client
        self.policy = policy
        self._cache_start = 0
        self._cache = b""
        self._payload_start: int | None = None
        self.total_remote_bytes_accepted = 0
        self.requested_intervals: list[RequestedInterval] = []
        self.highest_requested_offset = -1
        self.highest_accepted_offset = -1

    @property
    def request_count(self) -> int:
        return len(self.requested_intervals)

    def set_payload_start(self, offset: int) -> None:
        if offset < 0 or offset > self.file_size:
            raise OmivInputError("payload start is outside the remote file")
        if self.highest_accepted_offset >= offset:
            raise OmivInputError("remote cache already accepted tensor payload bytes")
        self._payload_start = offset

    def read_exact(
        self,
        offset: int,
        length: int,
        *,
        safe_prefetch_bytes: int = 0,
    ) -> bytes:
        end = self._checked_end(offset, length)
        if end > self.file_size:
            raise OmivInputError("bounded read crosses repository-declared file end")
        if safe_prefetch_bytes < 0:
            raise OmivInputError("safe prefetch allowance must be non-negative")
        if self._payload_start is not None and end > self._payload_start:
            raise OmivInputError("bounded read crosses the tensor payload boundary")
        cache_end = self._cache_start + len(self._cache)
        if offset >= self._cache_start and end <= cache_end:
            relative = offset - self._cache_start
            return self._cache[relative : relative + length]

        prefix = b""
        fetch_start = offset
        remaining = length
        if offset >= self._cache_start and offset < cache_end:
            available = min(end, cache_end) - offset
            relative = offset - self._cache_start
            prefix = self._cache[relative : relative + available]
            fetch_start += available
            remaining -= available
        if remaining == 0:
            return prefix

        extra = min(
            safe_prefetch_bytes,
            self.policy.read_ahead_bytes,
            self.policy.max_request_bytes - remaining,
        )
        fetch_length = remaining + max(0, extra)
        upper_bound = self.file_size
        if self._payload_start is not None:
            upper_bound = min(upper_bound, self._payload_start)
        fetch_length = min(fetch_length, upper_bound - fetch_start)
        if fetch_length < remaining:
            raise OmivInputError("safe bounded read cannot satisfy requested bytes")
        if fetch_length > self.policy.max_request_bytes:
            raise OmivInputError("bounded read exceeds per-request parser cap")
        if self.request_count >= self.policy.max_request_count:
            raise OmivInputError("GGUF header request-count cap exceeded")
        if (
            self.total_remote_bytes_accepted + fetch_length
            > self.policy.max_total_header_bytes
        ):
            raise OmivInputError("GGUF total accepted header-byte cap exceeded")

        result = self.client.read(
            self.url,
            offset=fetch_start,
            length=fetch_length,
            expected_total_size=self.file_size,
        )
        if len(result.data) != fetch_length:
            raise OmivInputError("validated Range client returned an unexpected length")
        fetch_end = fetch_start + fetch_length
        self._cache_start = fetch_start
        self._cache = result.data
        self.total_remote_bytes_accepted += fetch_length
        self.requested_intervals.append(
            RequestedInterval(
                start=fetch_start,
                end=fetch_end,
                byte_count=fetch_length,
            )
        )
        self.highest_requested_offset = max(
            self.highest_requested_offset, fetch_end - 1
        )
        self.highest_accepted_offset = max(self.highest_accepted_offset, fetch_end - 1)
        return prefix + result.data[:remaining]

    @staticmethod
    def _checked_end(offset: int, length: int) -> int:
        if isinstance(offset, bool) or offset < 0 or offset > MAX_U64:
            raise OmivInputError("bounded read offset is outside unsigned 64-bit range")
        if isinstance(length, bool) or length < 1 or length > MAX_U64:
            raise OmivInputError("bounded read length is outside unsigned 64-bit range")
        if offset > MAX_U64 - length:
            raise OmivInputError("bounded read offset plus length overflows uint64")
        return offset + length
