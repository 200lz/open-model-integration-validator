from __future__ import annotations

import hashlib
import struct

import pytest

from omiv.errors import OmivInputError
from omiv.remote.header_models import HeaderParserPolicy, MetadataValueType
from tests.remote_gguf_helpers import (
    TYPE_CODES,
    build_gguf,
    metadata_entry,
    parse_fixture,
    tensor_descriptor,
)


def base_metadata(alignment: int = 32) -> list[bytes]:
    return [
        metadata_entry("general.alignment", "UINT32", alignment),
        metadata_entry("general.name", "STRING", "synthetic"),
    ]


def base_tensors() -> list[bytes]:
    return [
        tensor_descriptor("a.weight", [2, 3], 0, 0),
        tensor_descriptor("b.weight", [4], 1, 32),
    ]


def test_valid_v3_fixed_fields_alignment_and_boundary_are_little_endian() -> None:
    data, descriptor_end, payload_start = build_gguf(
        metadata=base_metadata(),
        tensors=base_tensors(),
    )
    parsed = parse_fixture(data)
    inventory = parsed.inventory
    assert inventory.gguf_version == 3
    assert inventory.metadata_count == 2
    assert inventory.tensor_count == 2
    assert inventory.alignment == 32
    assert inventory.metadata_and_descriptor_end == descriptor_end
    assert inventory.padding_length == payload_start - descriptor_end
    assert inventory.payload_start_offset == payload_start
    assert inventory.highest_accepted_offset < payload_start
    assert max(offset + length for offset, length in parsed.client.calls) <= payload_start
    assert inventory.tensors[0].dimensions == [2, 3]
    assert inventory.tensors[0].logical_element_count == 6


@pytest.mark.parametrize(
    ("type_name", "value"),
    [
        ("UINT8", 255),
        ("INT8", -2),
        ("UINT16", 65535),
        ("INT16", -3),
        ("UINT32", 123456),
        ("INT32", -4),
        ("FLOAT32", 1.25),
        ("BOOL", True),
        ("UINT64", 2**40),
        ("INT64", -(2**40)),
        ("FLOAT64", 2.5),
    ],
)
def test_supported_scalar_metadata(type_name: str, value: object) -> None:
    data, _, _ = build_gguf(metadata=[metadata_entry("key", type_name, value)])
    entry = parse_fixture(data).inventory.metadata[0]
    assert entry.value_type.value == type_name
    assert entry.encoded_byte_length > 0
    assert entry.encoded_sha256 == hashlib.sha256(
        data[entry.encoded_start : entry.encoded_end]
    ).hexdigest()


def test_strings_arrays_large_arrays_digest_and_bounded_preview() -> None:
    metadata = [
        metadata_entry("text", "STRING", "abcdefghijk"),
        metadata_entry("numbers", "ARRAY", ("UINT32", list(range(1000)))),
        metadata_entry("tokens", "ARRAY", ("STRING", ["one", "two", "three"])),
    ]
    data, _, _ = build_gguf(metadata=metadata)
    policy = HeaderParserPolicy(
        max_request_bytes=64,
        read_ahead_bytes=64,
        max_preview_bytes=8,
    )
    inventory = parse_fixture(data, policy=policy).inventory
    by_key = {item.key: item for item in inventory.metadata}
    assert by_key["text"].summary_value is None
    assert by_key["text"].string_preview == "abcdefgh"
    assert by_key["text"].preview_truncated
    assert by_key["numbers"].element_count == 1000
    assert by_key["numbers"].preview == [0, 1]
    assert by_key["numbers"].preview_truncated
    assert by_key["tokens"].array_element_type == MetadataValueType.STRING
    assert sum(len(value.encode("utf-8")) for value in by_key["tokens"].preview) <= 8
    assert by_key["tokens"].preview_truncated
    assert inventory.request_count < 100


def test_url_and_sensitive_string_previews_are_redacted_but_digested() -> None:
    data, _, _ = build_gguf(
        metadata=[
            metadata_entry("repo", "STRING", "https://example.test/model?Signature=x"),
            metadata_entry(
                "values",
                "ARRAY",
                ("STRING", ["safe", "Bearer secret", "/home/user/model"]),
            ),
        ]
    )
    inventory = parse_fixture(data).inventory
    encoded = str(inventory.model_dump(mode="json"))
    assert "example.test" not in encoded
    assert "Bearer secret" not in encoded
    assert "/home/user" not in encoded
    assert encoded.count("[redacted-sensitive-text]") == 3
    assert all(item.encoded_sha256 for item in inventory.metadata)


def test_default_and_custom_alignment_and_file_relations() -> None:
    default_data, default_end, default_payload = build_gguf(
        tensors=[tensor_descriptor("a", [1], 0, 0)]
    )
    default = parse_fixture(default_data).inventory
    assert default.alignment == 32
    assert default.metadata_and_descriptor_end == default_end
    assert default.payload_start_offset == default_payload
    assert default.summary.payload_relation == "payload_before_eof"

    custom_data, _, custom_payload = build_gguf(
        metadata=base_metadata(64),
        alignment=64,
        payload_bytes=0,
    )
    custom = parse_fixture(custom_data).inventory
    assert custom.alignment == 64
    assert custom.payload_start_offset == custom_payload == len(custom_data)
    assert custom.summary.payload_relation == "payload_at_eof"


@pytest.mark.parametrize("alignment", [0, 3, 8192])
def test_invalid_alignment(alignment: int) -> None:
    data, _, _ = build_gguf(
        metadata=[metadata_entry("general.alignment", "UINT32", alignment)]
    )
    with pytest.raises(OmivInputError, match="alignment"):
        parse_fixture(data)


def test_prefix_version_and_count_failures() -> None:
    data, _, _ = build_gguf()
    with pytest.raises(OmivInputError, match="magic"):
        parse_fixture(b"NOPE" + data[4:])
    with pytest.raises(OmivInputError, match="unsupported GGUF version"):
        parse_fixture(build_gguf(version=2)[0])
    with pytest.raises(OmivInputError):
        parse_fixture(data[:7])

    excessive_tensor = bytearray(data)
    excessive_tensor[8:16] = struct.pack("<Q", 5)
    with pytest.raises(OmivInputError, match="tensor count"):
        parse_fixture(
            bytes(excessive_tensor),
            policy=HeaderParserPolicy(max_tensor_count=4),
        )
    excessive_metadata = bytearray(data)
    excessive_metadata[16:24] = struct.pack("<Q", 5)
    with pytest.raises(OmivInputError, match="metadata count"):
        parse_fixture(
            bytes(excessive_metadata),
            policy=HeaderParserPolicy(max_metadata_count=4),
        )


def test_metadata_rejects_duplicate_invalid_utf8_limits_and_types() -> None:
    duplicate, _, _ = build_gguf(
        metadata=[
            metadata_entry("same", "UINT32", 1),
            metadata_entry("same", "UINT32", 2),
        ]
    )
    with pytest.raises(OmivInputError, match="duplicate"):
        parse_fixture(duplicate)

    invalid_key, _, _ = build_gguf(
        metadata=[metadata_entry(b"\xff", "UINT32", 1)]
    )
    with pytest.raises(OmivInputError, match="UTF-8"):
        parse_fixture(invalid_key)
    invalid_string, _, _ = build_gguf(
        metadata=[metadata_entry("key", "STRING", b"\xff")]
    )
    with pytest.raises(OmivInputError, match="UTF-8"):
        parse_fixture(invalid_string)

    long_key, _, _ = build_gguf(metadata=[metadata_entry("long", "UINT32", 1)])
    with pytest.raises(OmivInputError, match="key length"):
        parse_fixture(
            long_key,
            policy=HeaderParserPolicy(max_metadata_key_bytes=3),
        )
    long_string, _, _ = build_gguf(
        metadata=[metadata_entry("key", "STRING", "long")]
    )
    with pytest.raises(OmivInputError, match="string length"):
        parse_fixture(long_string, policy=HeaderParserPolicy(max_string_bytes=3))

    array, _, _ = build_gguf(
        metadata=[metadata_entry("array", "ARRAY", ("UINT8", [1, 2, 3]))]
    )
    with pytest.raises(OmivInputError, match="array count"):
        parse_fixture(array, policy=HeaderParserPolicy(max_array_elements=2))

    unsupported = (
        b"GGUF"
        + struct.pack("<IQQ", 3, 0, 1)
        + struct.pack("<Q", 1)
        + b"k"
        + struct.pack("<I", 99)
    )
    with pytest.raises(OmivInputError, match="unsupported"):
        parse_fixture(unsupported)

    nested = (
        b"GGUF"
        + struct.pack("<IQQ", 3, 0, 1)
        + struct.pack("<Q", 1)
        + b"k"
        + struct.pack("<IIQ", TYPE_CODES["ARRAY"], TYPE_CODES["ARRAY"], 0)
    )
    with pytest.raises(OmivInputError, match="nested"):
        parse_fixture(nested)


def test_tensor_descriptor_validation_and_determinism() -> None:
    data, _, _ = build_gguf(
        metadata=base_metadata(),
        tensors=base_tensors(),
    )
    first = parse_fixture(data).inventory
    second = parse_fixture(data).inventory
    assert first == second
    assert [item.name for item in first.tensors] == ["a.weight", "b.weight"]
    assert first.tensors[0].ggml_type_name == "F32"
    assert first.tensors[1].ggml_type_name == "F16"
    assert first.requested_intervals == second.requested_intervals

    newer, _, _ = build_gguf(
        tensors=[tensor_descriptor("ternary", [1], 34, 0)]
    )
    assert parse_fixture(newer).inventory.tensors[0].ggml_type_name == "TQ1_0"


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        (tensor_descriptor("zero", [], 0, 0), "dimension count"),
        (tensor_descriptor("many", [1, 1, 1, 1, 1], 0, 0), "dimension count"),
        (tensor_descriptor(b"\xff", [1], 0, 0), "UTF-8"),
        (tensor_descriptor("unknown", [1], 999, 0), "unsupported GGML"),
    ],
)
def test_tensor_descriptor_rejections(descriptor: bytes, message: str) -> None:
    data, _, _ = build_gguf(tensors=[descriptor])
    with pytest.raises(OmivInputError, match=message):
        parse_fixture(data)


def test_tensor_duplicates_overflows_offsets_and_truncation() -> None:
    duplicate, _, _ = build_gguf(
        tensors=[
            tensor_descriptor("same", [1], 0, 0),
            tensor_descriptor("same", [1], 0, 32),
        ]
    )
    with pytest.raises(OmivInputError, match="duplicate"):
        parse_fixture(duplicate)

    dimensions, _, _ = build_gguf(
        tensors=[tensor_descriptor("huge", [2**63, 3], 0, 0)]
    )
    with pytest.raises(OmivInputError, match="element count"):
        parse_fixture(dimensions)

    offset, _, _ = build_gguf(
        tensors=[tensor_descriptor("offset", [1], 0, MAX_OFFSET)]
    )
    with pytest.raises(OmivInputError, match="offset"):
        parse_fixture(offset)

    valid, _, _ = build_gguf(tensors=[tensor_descriptor("cut", [1], 0, 0)])
    with pytest.raises(OmivInputError):
        parse_fixture(valid[:40])


MAX_OFFSET = (1 << 64) - 1


def test_payload_start_greater_than_file_fails_without_payload_read() -> None:
    data, _, payload = build_gguf(
        metadata=base_metadata(64),
        alignment=64,
        payload_bytes=0,
    )
    assert payload == len(data)
    with pytest.raises(OmivInputError, match="payload start exceeds"):
        parse_fixture(data[:-1])
