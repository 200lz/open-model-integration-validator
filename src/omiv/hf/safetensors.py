"""Bounded Safetensors header parsing with no tensor payload reads."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omiv.errors import OmivInputError
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.hf.limits import (
    MAX_DIMENSION_VALUE,
    MAX_ELEMENT_COUNT,
    MAX_SAFETENSORS_HEADER_BYTES,
    MAX_TENSOR_COUNT,
    MAX_TENSOR_NAME_LENGTH,
    MAX_TENSOR_RANK,
)
from omiv.hf.models import HFDiagnostic

SAFETENSORS_DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "I64": 8,
    "U64": 8,
    "F64": 8,
}


@dataclass(frozen=True)
class ParsedTensor:
    name: str
    dtype: str
    shape: list[int]
    data_offsets: tuple[int, int]


@dataclass(frozen=True)
class ParsedSafetensorsShard:
    file_name: str
    byte_size: int
    header_length: int
    payload_length: int
    tensors: list[ParsedTensor]
    diagnostics: list[HFDiagnostic]


def _integer(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise OmivInputError(f"{description} must be an integer")
    return value


def _element_count(shape: list[int], name: str) -> int:
    count = 1
    for dimension in shape:
        if dimension == 0:
            count = 0
            continue
        if count > MAX_ELEMENT_COUNT // dimension:
            raise OmivInputError(f"tensor {name!r} element count overflows limit")
        count *= dimension
    return count


def parse_safetensors_header(path: Path) -> ParsedSafetensorsShard:
    try:
        file_size = path.stat().st_size
        with path.open("rb") as handle:
            prefix = handle.read(8)
            if len(prefix) != 8:
                raise OmivInputError(f"{path.name} is shorter than 8-byte header prefix")
            header_length = struct.unpack("<Q", prefix)[0]
            if header_length > MAX_SAFETENSORS_HEADER_BYTES:
                raise OmivInputError(
                    f"{path.name} header length {header_length} exceeds cap "
                    f"{MAX_SAFETENSORS_HEADER_BYTES}"
                )
            if header_length > file_size - 8:
                raise OmivInputError(
                    f"{path.name} declared header does not fit within file"
                )
            header = handle.read(header_length)
            if len(header) != header_length:
                raise OmivInputError(f"{path.name} header is truncated")
    except OSError as exc:
        raise OmivInputError(f"cannot read {path.name} header: {exc}") from exc

    raw = parse_bounded_json_bytes(
        header,
        source_name=f"{path.name} header",
        max_bytes=MAX_SAFETENSORS_HEADER_BYTES,
    )
    metadata = raw.pop("__metadata__", None)
    if metadata is not None and not isinstance(metadata, dict):
        raise OmivInputError(f"{path.name} __metadata__ must be an object")
    if len(raw) > MAX_TENSOR_COUNT:
        raise OmivInputError(
            f"{path.name} tensor count exceeds maximum {MAX_TENSOR_COUNT}"
        )
    payload_length = file_size - 8 - header_length
    tensors: list[ParsedTensor] = []
    for name, descriptor in raw.items():
        if not isinstance(name, str) or not name or len(name) > MAX_TENSOR_NAME_LENGTH:
            raise OmivInputError(f"invalid tensor name in {path.name}")
        if not isinstance(descriptor, dict):
            raise OmivInputError(f"tensor {name!r} descriptor must be an object")
        if set(descriptor) != {"dtype", "shape", "data_offsets"}:
            raise OmivInputError(
                f"tensor {name!r} descriptor fields must be dtype, shape, data_offsets"
            )
        dtype = descriptor["dtype"]
        if not isinstance(dtype, str) or dtype not in SAFETENSORS_DTYPE_BYTES:
            raise OmivInputError(f"tensor {name!r} has unsupported dtype {dtype!r}")
        shape_raw = descriptor["shape"]
        if not isinstance(shape_raw, list):
            raise OmivInputError(f"tensor {name!r} shape must be a list")
        if len(shape_raw) > MAX_TENSOR_RANK:
            raise OmivInputError(
                f"tensor {name!r} rank exceeds maximum {MAX_TENSOR_RANK}"
            )
        shape: list[int] = []
        for value in shape_raw:
            dimension = _integer(value, f"tensor {name!r} dimension")
            if dimension < 0 or dimension > MAX_DIMENSION_VALUE:
                raise OmivInputError(f"tensor {name!r} dimension is out of range")
            shape.append(dimension)
        elements = _element_count(shape, name)
        expected_span = elements * SAFETENSORS_DTYPE_BYTES[dtype]
        offsets = descriptor["data_offsets"]
        if not isinstance(offsets, list) or len(offsets) != 2:
            raise OmivInputError(f"tensor {name!r} data_offsets must have two values")
        start = _integer(offsets[0], f"tensor {name!r} offset")
        end = _integer(offsets[1], f"tensor {name!r} offset")
        if start < 0 or end < 0 or start > end:
            raise OmivInputError(f"tensor {name!r} data_offsets are invalid")
        if end > payload_length:
            raise OmivInputError(f"tensor {name!r} data_offsets exceed payload")
        if end - start != expected_span:
            raise OmivInputError(
                f"tensor {name!r} payload span does not match dtype and shape"
            )
        tensors.append(
            ParsedTensor(
                name=name,
                dtype=dtype,
                shape=shape,
                data_offsets=(start, end),
            )
        )

    diagnostics: list[HFDiagnostic] = []
    offset_order = sorted(tensors, key=lambda item: (item.data_offsets, item.name))
    cursor = 0
    for tensor in offset_order:
        start, end = tensor.data_offsets
        if start < cursor and end > start:
            raise OmivInputError(
                f"tensor {tensor.name!r} payload overlaps a preceding tensor"
            )
        if start > cursor:
            diagnostics.append(
                HFDiagnostic(
                    code="SAFETENSORS_INITIAL_GAP"
                    if cursor == 0
                    else "SAFETENSORS_INTERMEDIATE_GAP",
                    severity="warning",
                    message="Unused payload byte range observed",
                    evidence={
                        "shard": path.name,
                        "start": cursor,
                        "end": start,
                        "byte_count": start - cursor,
                    },
                )
            )
        cursor = max(cursor, end)
    if cursor < payload_length:
        diagnostics.append(
            HFDiagnostic(
                code="SAFETENSORS_TRAILING_GAP",
                severity="warning",
                message="Unused trailing payload byte range observed",
                evidence={
                    "shard": path.name,
                    "start": cursor,
                    "end": payload_length,
                    "byte_count": payload_length - cursor,
                },
            )
        )
    return ParsedSafetensorsShard(
        file_name=path.name,
        byte_size=file_size,
        header_length=header_length,
        payload_length=payload_length,
        tensors=sorted(tensors, key=lambda item: item.name),
        diagnostics=diagnostics,
    )
