from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from omiv.remote.gguf_header import RemoteGGUFHeaderParser
from omiv.remote.header_models import HeaderParserPolicy
from omiv.remote.models import RemoteFile, RepositoryIdentity, StorageClass
from omiv.remote.range_client import RangeReadResult
from omiv.remote.range_source import RangeBackedByteSource

TYPE_CODES = {
    "UINT8": 0,
    "INT8": 1,
    "UINT16": 2,
    "INT16": 3,
    "UINT32": 4,
    "INT32": 5,
    "FLOAT32": 6,
    "BOOL": 7,
    "STRING": 8,
    "ARRAY": 9,
    "UINT64": 10,
    "INT64": 11,
    "FLOAT64": 12,
}
FORMATS = {
    "UINT8": "<B",
    "INT8": "<b",
    "UINT16": "<H",
    "INT16": "<h",
    "UINT32": "<I",
    "INT32": "<i",
    "FLOAT32": "<f",
    "UINT64": "<Q",
    "INT64": "<q",
    "FLOAT64": "<d",
}


def gguf_string(value: str | bytes) -> bytes:
    encoded = value if isinstance(value, bytes) else value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def encoded_value(type_name: str, value: Any) -> bytes:
    if type_name == "STRING":
        return gguf_string(value)
    if type_name == "BOOL":
        return bytes([int(value)])
    return struct.pack(FORMATS[type_name], value)


def metadata_entry(key: str | bytes, type_name: str, value: Any) -> bytes:
    result = gguf_string(key)
    result += struct.pack("<I", TYPE_CODES[type_name])
    if type_name != "ARRAY":
        return result + encoded_value(type_name, value)
    element_type, elements = value
    result += struct.pack("<IQ", TYPE_CODES[element_type], len(elements))
    return result + b"".join(encoded_value(element_type, item) for item in elements)


def tensor_descriptor(
    name: str | bytes,
    dimensions: list[int],
    type_code: int,
    data_offset: int,
) -> bytes:
    return (
        gguf_string(name)
        + struct.pack("<I", len(dimensions))
        + b"".join(struct.pack("<Q", value) for value in dimensions)
        + struct.pack("<IQ", type_code, data_offset)
    )


def build_gguf(
    *,
    metadata: list[bytes] | None = None,
    tensors: list[bytes] | None = None,
    alignment: int = 32,
    payload_bytes: int = 64,
    version: int = 3,
) -> tuple[bytes, int, int]:
    metadata = metadata or []
    tensors = tensors or []
    prefix = (
        b"GGUF"
        + struct.pack("<I", version)
        + struct.pack("<Q", len(tensors))
        + struct.pack("<Q", len(metadata))
    )
    descriptor_end = len(prefix) + sum(map(len, metadata)) + sum(map(len, tensors))
    payload_start = (descriptor_end + alignment - 1) // alignment * alignment
    data = (
        prefix
        + b"".join(metadata)
        + b"".join(tensors)
        + b"\0" * (payload_start - descriptor_end)
        + b"P" * payload_bytes
    )
    return data, descriptor_end, payload_start


class SliceClient:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.calls: list[tuple[int, int]] = []

    def read(
        self,
        url: str,
        *,
        offset: int,
        length: int,
        expected_total_size: int | None = None,
        authorization: str | None = None,
    ) -> RangeReadResult:
        self.calls.append((offset, length))
        value = self.data[offset : offset + length]
        return RangeReadResult(
            data=value,
            http_status=206,
            content_range=f"bytes {offset}-{offset + length - 1}/{len(self.data)}",
            total_size=len(self.data),
            etag='"fixture"',
            redirect_count=0,
            final_host="huggingface.co",
            response_sha256="0" * 64,
        )


@dataclass
class ParsedFixture:
    inventory: Any
    source: RangeBackedByteSource
    client: SliceClient
    file: RemoteFile


def parse_fixture(
    data: bytes,
    *,
    policy: HeaderParserPolicy | None = None,
) -> ParsedFixture:
    selected_policy = policy or HeaderParserPolicy(
        max_request_bytes=64,
        read_ahead_bytes=64,
    )
    client = SliceClient(data)
    source = RangeBackedByteSource(
        url="https://huggingface.co/owner/repo/resolve/" + "a" * 40 + "/fixture.gguf",
        file_size=len(data),
        client=client,  # type: ignore[arg-type]
        policy=selected_policy,
    )
    file = RemoteFile(
        path="q/fixture.gguf",
        byte_size=len(data),
        storage=StorageClass.LFS,
        lfs_sha256="b" * 64,
    )
    inventory = RemoteGGUFHeaderParser(selected_policy).parse(
        source,
        repository=RepositoryIdentity(
            repo_id="owner/repo",
            repo_type="model",
            requested_revision="main",
            resolved_revision="a" * 40,
        ),
        snapshot_sha256="c" * 64,
        file=file,
    )
    return ParsedFixture(
        inventory=inventory,
        source=source,
        client=client,
        file=file,
    )
