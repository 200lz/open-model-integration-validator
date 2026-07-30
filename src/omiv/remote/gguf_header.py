"""Independent incremental parser for one remote GGUF v3 header."""

from __future__ import annotations

import codecs
import hashlib
import math
import re
import struct
from collections import Counter
from collections.abc import Callable
from typing import Protocol

from pydantic import JsonValue

from omiv.errors import OmivInputError
from omiv.models import json_compatible
from omiv.remote.header_models import (
    HeaderInventorySummary,
    HeaderParserPolicy,
    LargestMetadataEntry,
    MetadataValueType,
    RemoteGGUFHeaderInventory,
    RemoteMetadataEntry,
    RemoteTensorDescriptor,
    RequestedInterval,
)
from omiv.remote.models import RemoteFile, RepositoryIdentity

MAX_U64 = (1 << 64) - 1
DEFAULT_ALIGNMENT = 32
MIN_METADATA_ENTRY_BYTES = 13
MIN_TENSOR_DESCRIPTOR_BYTES = 32

VALUE_TYPES: dict[int, MetadataValueType] = {
    0: MetadataValueType.UINT8,
    1: MetadataValueType.INT8,
    2: MetadataValueType.UINT16,
    3: MetadataValueType.INT16,
    4: MetadataValueType.UINT32,
    5: MetadataValueType.INT32,
    6: MetadataValueType.FLOAT32,
    7: MetadataValueType.BOOL,
    8: MetadataValueType.STRING,
    9: MetadataValueType.ARRAY,
    10: MetadataValueType.UINT64,
    11: MetadataValueType.INT64,
    12: MetadataValueType.FLOAT64,
}

SCALAR_FORMATS: dict[MetadataValueType, tuple[str, int]] = {
    MetadataValueType.UINT8: ("<B", 1),
    MetadataValueType.INT8: ("<b", 1),
    MetadataValueType.UINT16: ("<H", 2),
    MetadataValueType.INT16: ("<h", 2),
    MetadataValueType.UINT32: ("<I", 4),
    MetadataValueType.INT32: ("<i", 4),
    MetadataValueType.FLOAT32: ("<f", 4),
    MetadataValueType.UINT64: ("<Q", 8),
    MetadataValueType.INT64: ("<q", 8),
    MetadataValueType.FLOAT64: ("<d", 8),
}

GGML_TYPES: dict[int, str] = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    6: "Q5_0",
    7: "Q5_1",
    8: "Q8_0",
    9: "Q8_1",
    10: "Q2_K",
    11: "Q3_K",
    12: "Q4_K",
    13: "Q5_K",
    14: "Q6_K",
    15: "Q8_K",
    16: "IQ2_XXS",
    17: "IQ2_XS",
    18: "IQ3_XXS",
    19: "IQ1_S",
    20: "IQ4_NL",
    21: "IQ3_S",
    22: "IQ2_S",
    23: "IQ4_XS",
    24: "I8",
    25: "I16",
    26: "I32",
    27: "I64",
    28: "F64",
    29: "IQ1_M",
    30: "BF16",
    34: "TQ1_0",
    35: "TQ2_0",
    39: "MXFP4",
    40: "NVFP4",
    41: "Q1_0",
}


class HeaderByteSource(Protocol):
    file_size: int
    total_remote_bytes_accepted: int
    requested_intervals: list[RequestedInterval]
    highest_requested_offset: int
    highest_accepted_offset: int

    @property
    def request_count(self) -> int: ...

    def read_exact(
        self, offset: int, length: int, *, safe_prefetch_bytes: int = 0
    ) -> bytes: ...

    def set_payload_start(self, offset: int) -> None: ...


class _SequentialReader:
    def __init__(self, source: HeaderByteSource, policy: HeaderParserPolicy) -> None:
        self.source = source
        self.policy = policy
        self.offset = 0

    def read(
        self,
        length: int,
        *,
        safe_after: int,
        digest: hashlib._Hash | None = None,
    ) -> bytes:
        value = self.source.read_exact(
            self.offset,
            length,
            safe_prefetch_bytes=safe_after,
        )
        self.offset = _checked_add(self.offset, length, "parser cursor")
        if digest is not None:
            digest.update(value)
        return value

    def u32(self, *, safe_after: int, digest: hashlib._Hash | None = None) -> int:
        return int.from_bytes(
            self.read(4, safe_after=safe_after, digest=digest), "little"
        )

    def u64(self, *, safe_after: int, digest: hashlib._Hash | None = None) -> int:
        return int.from_bytes(
            self.read(8, safe_after=safe_after, digest=digest), "little"
        )


def _checked_add(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or left > MAX_U64 - right:
        raise OmivInputError(f"{label} overflows unsigned 64-bit arithmetic")
    return left + right


def _checked_multiply(left: int, right: int, label: str) -> int:
    if left < 0 or right < 0 or (left and right > MAX_U64 // left):
        raise OmivInputError(f"{label} overflows unsigned 64-bit arithmetic")
    return left * right


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise OmivInputError("GGUF alignment must be a non-zero power of two")
    remainder = value % alignment
    return value if remainder == 0 else _checked_add(
        value, alignment - remainder, "aligned payload start"
    )


def _json_scalar(value: object) -> JsonValue:
    if isinstance(value, float) and not math.isfinite(value):
        if math.isnan(value):
            return "nan"
        return "infinity" if value > 0 else "-infinity"
    return json_compatible(value)


def _validate_identifier(value: str, *, label: str) -> None:
    if not value:
        raise OmivInputError(f"{label} must not be empty")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise OmivInputError(f"{label} contains a control character")


def _sanitize_preview(value: str) -> tuple[str, bool]:
    lowered = value.lower()
    sensitive_markers = (
        "://",
        "authorization",
        "bearer ",
        "x-amz-",
        "expires=",
        "signature=",
        "github_pat_",
        "ghp_",
        "/home/",
        "c:\\users",
    )
    if any(marker in lowered for marker in sensitive_markers) or re.search(
        r"\bhf_[A-Za-z0-9]{20,}", value
    ):
        return "[redacted-sensitive-text]", True
    return value, False


class RemoteGGUFHeaderParser:
    def __init__(self, policy: HeaderParserPolicy | None = None) -> None:
        self.policy = policy or HeaderParserPolicy()

    def parse(
        self,
        source: HeaderByteSource,
        *,
        repository: RepositoryIdentity,
        snapshot_sha256: str,
        file: RemoteFile,
    ) -> RemoteGGUFHeaderInventory:
        if source.file_size != file.byte_size:
            raise OmivInputError("byte source size disagrees with snapshot file size")
        reader = _SequentialReader(source, self.policy)
        fixed = reader.read(24, safe_after=0)
        if fixed[:4] != b"GGUF":
            raise OmivInputError("remote file does not begin with GGUF magic")
        version = int.from_bytes(fixed[4:8], "little")
        if version != 3:
            raise OmivInputError(f"unsupported GGUF version {version}; expected version 3")
        tensor_count = int.from_bytes(fixed[8:16], "little")
        metadata_count = int.from_bytes(fixed[16:24], "little")
        if tensor_count > self.policy.max_tensor_count:
            raise OmivInputError("GGUF tensor count exceeds parser policy")
        if metadata_count > self.policy.max_metadata_count:
            raise OmivInputError("GGUF metadata count exceeds parser policy")

        metadata: list[RemoteMetadataEntry] = []
        metadata_keys: set[str] = set()
        alignment = DEFAULT_ALIGNMENT
        for index in range(metadata_count):
            later = self._minimum_later_bytes(
                metadata_count - index - 1, tensor_count
            )
            entry, scalar_alignment = self._parse_metadata(reader, later=later)
            if entry.key in metadata_keys:
                raise OmivInputError(f"duplicate GGUF metadata key: {entry.key}")
            metadata_keys.add(entry.key)
            metadata.append(entry)
            if entry.key == "general.alignment":
                if (
                    entry.value_type != MetadataValueType.UINT32
                    or not isinstance(scalar_alignment, int)
                ):
                    raise OmivInputError(
                        "general.alignment must be a GGUF UINT32 scalar"
                    )
                alignment = scalar_alignment

        tensors: list[RemoteTensorDescriptor] = []
        tensor_names: set[str] = set()
        for index in range(tensor_count):
            later = _checked_multiply(
                tensor_count - index - 1,
                MIN_TENSOR_DESCRIPTOR_BYTES,
                "remaining tensor descriptor lower bound",
            )
            descriptor = self._parse_tensor(reader, later=later)
            if descriptor.name in tensor_names:
                raise OmivInputError(f"duplicate GGUF tensor name: {descriptor.name}")
            tensor_names.add(descriptor.name)
            tensors.append(descriptor)

        descriptor_end = reader.offset
        if (
            alignment <= 0
            or alignment > self.policy.max_alignment
            or alignment & (alignment - 1)
        ):
            raise OmivInputError("GGUF alignment is invalid or exceeds parser policy")
        payload_start = _align_up(descriptor_end, alignment)
        if payload_start > file.byte_size:
            raise OmivInputError("GGUF payload start exceeds repository file size")
        source.set_payload_start(payload_start)
        for tensor in tensors:
            absolute = _checked_add(
                payload_start, tensor.data_offset, f"tensor {tensor.name!r} data offset"
            )
            if absolute > file.byte_size:
                raise OmivInputError(
                    f"tensor {tensor.name!r} data offset exceeds remote file size"
                )
            if tensor.data_offset % alignment:
                raise OmivInputError(
                    f"tensor {tensor.name!r} data offset is not GGUF-aligned"
                )

        metadata.sort(key=lambda item: item.key)
        tensors.sort(key=lambda item: item.name)
        metadata_counts = dict(
            sorted(Counter(item.value_type.value for item in metadata).items())
        )
        tensor_counts = dict(
            sorted(Counter(item.ggml_type_name for item in tensors).items())
        )
        largest = sorted(
            metadata,
            key=lambda item: (-item.encoded_byte_length, item.key),
        )[:10]
        return RemoteGGUFHeaderInventory(
            provider="huggingface",
            repository=repository,
            snapshot_sha256=snapshot_sha256,
            file=file,
            gguf_version=3,
            tensor_count=tensor_count,
            metadata_count=metadata_count,
            alignment=alignment,
            metadata_and_descriptor_end=descriptor_end,
            header_end_offset=payload_start,
            padding_length=payload_start - descriptor_end,
            payload_start_offset=payload_start,
            header_encoded_byte_length=payload_start,
            highest_requested_offset=source.highest_requested_offset,
            highest_accepted_offset=source.highest_accepted_offset,
            total_remote_bytes_accepted=source.total_remote_bytes_accepted,
            request_count=source.request_count,
            requested_intervals=list(source.requested_intervals),
            metadata=metadata,
            tensors=tensors,
            summary=HeaderInventorySummary(
                metadata_type_counts=metadata_counts,
                tensor_type_counts=tensor_counts,
                largest_metadata_entries=[
                    LargestMetadataEntry(
                        key=item.key,
                        encoded_byte_length=item.encoded_byte_length,
                        value_type=item.value_type,
                    )
                    for item in largest
                ],
                representative_tensor_names=[item.name for item in tensors[:10]],
                payload_relation=(
                    "payload_at_eof"
                    if payload_start == file.byte_size
                    else "payload_before_eof"
                ),
            ),
            parser_policy=self.policy,
            parser_policy_sha256=self.policy.digest,
        )

    @staticmethod
    def _minimum_later_bytes(metadata_remaining: int, tensor_count: int) -> int:
        metadata_bytes = _checked_multiply(
            metadata_remaining,
            MIN_METADATA_ENTRY_BYTES,
            "remaining metadata lower bound",
        )
        tensor_bytes = _checked_multiply(
            tensor_count,
            MIN_TENSOR_DESCRIPTOR_BYTES,
            "remaining tensor lower bound",
        )
        return _checked_add(metadata_bytes, tensor_bytes, "remaining header lower bound")

    def _parse_metadata(
        self, reader: _SequentialReader, *, later: int
    ) -> tuple[RemoteMetadataEntry, object | None]:
        start = reader.offset
        digest = hashlib.sha256()
        key = self._read_identifier(
            reader,
            max_bytes=self.policy.max_metadata_key_bytes,
            label="GGUF metadata key",
            safe_after=_checked_add(later, 5, "metadata key lower bound"),
            digest=digest,
        )
        type_code = reader.u32(
            safe_after=_checked_add(later, 1, "metadata value bound"),
            digest=digest,
        )
        value_type = VALUE_TYPES.get(type_code)
        if value_type is None:
            raise OmivInputError(f"unsupported GGUF metadata value type {type_code}")
        parsed = self._parse_value(
            reader,
            value_type=value_type,
            later=later,
            digest=digest,
        )
        if parsed.string_preview is not None:
            parsed.string_preview, redacted = _sanitize_preview(parsed.string_preview)
            if redacted:
                parsed.summary_value = None
                parsed.preview_truncated = True
        sanitized_preview: list[JsonValue] = []
        preview_redacted = False
        for value in parsed.preview:
            if isinstance(value, str):
                value, redacted = _sanitize_preview(value)
                preview_redacted = preview_redacted or redacted
            sanitized_preview.append(value)
        parsed.preview = sanitized_preview
        parsed.preview_truncated = parsed.preview_truncated or preview_redacted
        end = reader.offset
        return (
            RemoteMetadataEntry(
                key=key,
                value_type=value_type,
                array_element_type=parsed.array_element_type,
                element_count=parsed.element_count,
                encoded_start=start,
                encoded_end=end,
                encoded_byte_length=end - start,
                encoded_sha256=digest.hexdigest(),
                summary_value=parsed.summary_value,
                string_preview=parsed.string_preview,
                preview=parsed.preview,
                preview_truncated=parsed.preview_truncated,
            ),
            parsed.summary_value,
        )

    def _read_identifier(
        self,
        reader: _SequentialReader,
        *,
        max_bytes: int,
        label: str,
        safe_after: int,
        digest: hashlib._Hash,
    ) -> str:
        length = reader.u64(safe_after=safe_after, digest=digest)
        if length < 1 or length > max_bytes:
            raise OmivInputError(f"{label} length exceeds configured bounds")
        remaining = length
        chunks: list[bytes] = []
        while remaining:
            chunk_length = min(remaining, self.policy.max_request_bytes)
            remaining -= chunk_length
            chunks.append(
                reader.read(
                    chunk_length,
                    safe_after=_checked_add(
                        remaining, safe_after, f"{label} remaining bytes"
                    ),
                    digest=digest,
                )
            )
        raw = b"".join(chunks)
        try:
            value = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise OmivInputError(f"{label} is not valid UTF-8") from exc
        _validate_identifier(value, label=label)
        return value

    def _parse_value(
        self,
        reader: _SequentialReader,
        *,
        value_type: MetadataValueType,
        later: int,
        digest: hashlib._Hash,
    ) -> _ParsedValue:
        if value_type == MetadataValueType.ARRAY:
            element_code = reader.u32(
                safe_after=_checked_add(later, 8, "array header"),
                digest=digest,
            )
            element_type = VALUE_TYPES.get(element_code)
            if element_type is None or element_type == MetadataValueType.ARRAY:
                raise OmivInputError("GGUF metadata array has invalid or nested element type")
            count = reader.u64(safe_after=later, digest=digest)
            if count > self.policy.max_array_elements:
                raise OmivInputError("GGUF metadata array count exceeds parser policy")
            return self._parse_array(
                reader,
                element_type=element_type,
                count=count,
                later=later,
                digest=digest,
            )
        if value_type == MetadataValueType.STRING:
            _, preview, truncated = self._read_string_value(
                reader,
                later=later,
                digest=digest,
                preview_limit=self.policy.max_preview_bytes,
            )
            return _ParsedValue(
                summary_value=preview if not truncated else None,
                string_preview=preview,
                preview_truncated=truncated,
            )
        if value_type == MetadataValueType.BOOL:
            raw = reader.read(1, safe_after=later, digest=digest)
            if raw[0] not in (0, 1):
                raise OmivInputError("GGUF BOOL scalar must be encoded as 0 or 1")
            return _ParsedValue(summary_value=bool(raw[0]))
        scalar_format = SCALAR_FORMATS.get(value_type)
        if scalar_format is None:
            raise OmivInputError(f"unsupported GGUF scalar type {value_type}")
        format_code, width = scalar_format
        raw = reader.read(width, safe_after=later, digest=digest)
        return _ParsedValue(summary_value=_json_scalar(struct.unpack(format_code, raw)[0]))

    def _parse_array(
        self,
        reader: _SequentialReader,
        *,
        element_type: MetadataValueType,
        count: int,
        later: int,
        digest: hashlib._Hash,
    ) -> _ParsedValue:
        preview: list[JsonValue] = []
        preview_budget = self.policy.max_preview_bytes
        if element_type == MetadataValueType.STRING:
            for index in range(count):
                remaining_strings = count - index - 1
                minimum_remaining = _checked_add(
                    _checked_multiply(
                        remaining_strings, 8, "remaining string-array lower bound"
                    ),
                    later,
                    "string-array lower bound",
                )
                _, value_preview, truncated = self._read_string_value(
                    reader,
                    later=minimum_remaining,
                    digest=digest,
                    preview_limit=preview_budget,
                )
                if preview_budget > 0:
                    preview.append(value_preview)
                    preview_budget = max(
                        0, preview_budget - len(value_preview.encode("utf-8"))
                    )
                if truncated:
                    preview_budget = 0
            return _ParsedValue(
                array_element_type=element_type,
                element_count=count,
                preview=preview,
                preview_truncated=len(preview) < count or preview_budget == 0,
            )

        width = 1 if element_type == MetadataValueType.BOOL else SCALAR_FORMATS[element_type][1]
        total_bytes = _checked_multiply(count, width, "metadata array byte length")
        remaining = total_bytes
        preview_elements = (
            min(count, preview_budget // width) if width and preview_budget else 0
        )
        decoded = 0
        while remaining:
            chunk_length = min(remaining, self.policy.max_request_bytes)
            chunk_length -= chunk_length % width
            if chunk_length == 0:
                chunk_length = width
            remaining -= chunk_length
            raw = reader.read(
                chunk_length,
                safe_after=_checked_add(remaining, later, "array remaining bytes"),
                digest=digest,
            )
            if element_type == MetadataValueType.BOOL:
                if any(value not in (0, 1) for value in raw):
                    raise OmivInputError("GGUF BOOL array contains a value other than 0 or 1")
                for value in raw[: max(0, preview_elements - decoded)]:
                    preview.append(bool(value))
                    decoded += 1
            elif decoded < preview_elements:
                format_code = SCALAR_FORMATS[element_type][0]
                for offset in range(0, len(raw), width):
                    if decoded >= preview_elements:
                        break
                    preview.append(
                        _json_scalar(struct.unpack(format_code, raw[offset : offset + width])[0])
                    )
                    decoded += 1
        return _ParsedValue(
            array_element_type=element_type,
            element_count=count,
            preview=preview,
            preview_truncated=len(preview) < count,
        )

    def _read_string_value(
        self,
        reader: _SequentialReader,
        *,
        later: int,
        digest: hashlib._Hash,
        preview_limit: int,
    ) -> tuple[int, str, bool]:
        length = reader.u64(safe_after=later, digest=digest)
        if length > self.policy.max_string_bytes:
            raise OmivInputError("GGUF string length exceeds parser policy")
        remaining = length
        preview_raw = bytearray()
        decoder_factory: Callable[..., codecs.IncrementalDecoder] = codecs.getincrementaldecoder(
            "utf-8"
        )
        decoder = decoder_factory(errors="strict")
        while remaining:
            chunk_length = min(remaining, self.policy.max_request_bytes)
            remaining -= chunk_length
            raw = reader.read(
                chunk_length,
                safe_after=_checked_add(remaining, later, "string remaining bytes"),
                digest=digest,
            )
            try:
                decoder.decode(raw, final=False)
            except UnicodeDecodeError as exc:
                raise OmivInputError("GGUF string is not valid UTF-8") from exc
            if len(preview_raw) < preview_limit:
                preview_raw.extend(raw[: preview_limit - len(preview_raw)])
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise OmivInputError("GGUF string is not valid UTF-8") from exc
        preview = bytes(preview_raw).decode("utf-8", errors="ignore")
        return length, preview, length > preview_limit

    def _parse_tensor(
        self, reader: _SequentialReader, *, later: int
    ) -> RemoteTensorDescriptor:
        start = reader.offset
        digest = hashlib.sha256()
        name = self._read_identifier(
            reader,
            max_bytes=self.policy.max_tensor_name_bytes,
            label="GGUF tensor name",
            safe_after=_checked_add(later, 24, "tensor name lower bound"),
            digest=digest,
        )
        dimensions_count = reader.u32(
            safe_after=_checked_add(later, 20, "tensor dimensions lower bound"),
            digest=digest,
        )
        if (
            dimensions_count < 1
            or dimensions_count > self.policy.max_tensor_dimensions
        ):
            raise OmivInputError("GGUF tensor dimension count exceeds configured bounds")
        dimensions_bytes = _checked_multiply(
            dimensions_count, 8, "tensor dimension byte length"
        )
        raw_dimensions = reader.read(
            dimensions_bytes,
            safe_after=_checked_add(later, 12, "tensor descriptor suffix"),
            digest=digest,
        )
        dimensions = [
            int.from_bytes(raw_dimensions[index : index + 8], "little")
            for index in range(0, dimensions_bytes, 8)
        ]
        element_count = 1
        for dimension in dimensions:
            if dimension < 1:
                raise OmivInputError("GGUF tensor dimension must be positive")
            element_count = _checked_multiply(
                element_count, dimension, f"tensor {name!r} logical element count"
            )
        type_code = reader.u32(safe_after=_checked_add(later, 8, "tensor offset"), digest=digest)
        type_name = GGML_TYPES.get(type_code)
        if type_name is None:
            raise OmivInputError(f"unsupported GGML tensor type code {type_code}")
        data_offset = reader.u64(safe_after=later, digest=digest)
        end = reader.offset
        return RemoteTensorDescriptor(
            name=name,
            dimensions=dimensions,
            ggml_type_code=type_code,
            ggml_type_name=type_name,
            data_offset=data_offset,
            logical_element_count=element_count,
            encoded_start=start,
            encoded_end=end,
            encoded_byte_length=end - start,
            encoded_sha256=digest.hexdigest(),
        )


class _ParsedValue:
    def __init__(
        self,
        *,
        array_element_type: MetadataValueType | None = None,
        element_count: int | None = None,
        summary_value: JsonValue = None,
        string_preview: str | None = None,
        preview: list[JsonValue] | None = None,
        preview_truncated: bool = False,
    ) -> None:
        self.array_element_type = array_element_type
        self.element_count = element_count
        self.summary_value = summary_value
        self.string_preview = string_preview
        self.preview = preview or []
        self.preview_truncated = preview_truncated
