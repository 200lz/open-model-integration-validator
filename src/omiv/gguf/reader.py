"""Lazy GGUFReader adapter that never accesses ReaderTensor.data."""

from __future__ import annotations

import hashlib
import importlib
import json
import struct
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

from omiv.errors import OmivInputError
from omiv.gguf.models import (
    GGUFArtifactSummary,
    GGUFHeaderSummary,
    GGUFIdentity,
    GGUFInventory,
    GGUFMetadataEntry,
    GGUFShardSummary,
    GGUFSummary,
    GGUFTensorDescriptor,
)

METADATA_ARRAY_INLINE_THRESHOLD = 16
GGUF_VALUE_TYPE_NAMES = {
    0: "UINT8",
    1: "INT8",
    2: "UINT16",
    3: "INT16",
    4: "UINT32",
    5: "INT32",
    6: "FLOAT32",
    7: "BOOL",
    8: "STRING",
    10: "UINT64",
    11: "INT64",
    12: "FLOAT64",
}
SCALAR_STRUCT_FORMATS = {
    "UINT8": ">B",
    "INT8": ">b",
    "UINT16": ">H",
    "INT16": ">h",
    "UINT32": ">I",
    "INT32": ">i",
    "UINT64": ">Q",
    "INT64": ">q",
    "FLOAT32": ">f",
    "FLOAT64": ">d",
}


def _load_gguf_module() -> ModuleType:
    try:
        return importlib.import_module("gguf")
    except ModuleNotFoundError as exc:
        raise OmivInputError(
            "GGUF support requires the optional dependency; install with "
            "`pip install 'open-model-integration-validator[gguf]'`"
        ) from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _scalar_bytes(type_name: str, value: Any) -> bytes:
    prefix = type_name.encode("ascii") + b"\0"
    if type_name == "STRING":
        if not isinstance(value, str):
            raise OmivInputError("GGUF STRING scalar must be a string")
        encoded = value.encode("utf-8")
        return prefix + struct.pack(">Q", len(encoded)) + encoded
    if type_name == "BOOL":
        if not isinstance(value, bool):
            raise OmivInputError("GGUF BOOL scalar must be a boolean")
        return prefix + (b"\1" if value else b"\0")
    scalar_format = SCALAR_STRUCT_FORMATS.get(type_name)
    if scalar_format is None:
        raise OmivInputError(f"unsupported GGUF scalar type {type_name!r}")
    try:
        return prefix + struct.pack(scalar_format, value)
    except (OverflowError, struct.error, TypeError) as exc:
        raise OmivInputError(
            f"GGUF {type_name} scalar value is outside its declared type range"
        ) from exc


def _array_digest(field: Any, element_type: str, length: int) -> str:
    digest = hashlib.sha256()
    digest.update(b"OMIV_GGUF_ARRAY_V1\0")
    digest.update(element_type.encode("ascii") + b"\0")
    digest.update(struct.pack(">Q", length))
    for index in range(length):
        digest.update(_scalar_bytes(element_type, field.contents(index)))
    return digest.hexdigest()


def canonicalize_metadata_field(key: str, field: Any) -> GGUFMetadataEntry:
    """Canonicalize one ReaderField without repr-based hashing."""
    if not field.types:
        raise OmivInputError(f"metadata field {key!r} has no GGUF value type")
    value_type = field.types[0].name
    if value_type != "ARRAY":
        value = field.contents()
        try:
            _scalar_bytes(value_type, value)
        except OmivInputError as exc:
            raise OmivInputError(f"metadata scalar {key!r}: {exc}") from exc
        return GGUFMetadataEntry(key=key, value_type=value_type, value=value)

    length = len(field.data)
    if len(field.types) >= 2:
        element_type = field.types[-1].name
    elif length == 0 and len(field.parts) >= 2:
        type_code = int(field.parts[-2].tolist()[0])
        element_type = GGUF_VALUE_TYPE_NAMES.get(type_code, "")
        if not element_type:
            raise OmivInputError(
                f"metadata array {key!r} has unsupported element type {type_code}"
            )
    else:
        raise OmivInputError(f"metadata array {key!r} has no element type")
    digest = _array_digest(field, element_type, length)
    inline: list[Any] | None = None
    if length <= METADATA_ARRAY_INLINE_THRESHOLD:
        inline = [field.contents(index) for index in range(length)]
    return GGUFMetadataEntry(
        key=key,
        value_type="ARRAY",
        value=inline,
        array_element_type=element_type,
        array_length=length,
        value_sha256=digest,
    )


def _field_value(reader: Any, key: str) -> Any:
    field = reader.fields.get(key)
    return field.contents() if field is not None else None


def _endianness(reader: Any) -> Literal["little", "big", "unknown"]:
    name = getattr(getattr(reader, "endianess", None), "name", "")
    if name == "LITTLE":
        return "little"
    if name == "BIG":
        return "big"
    return "unknown"


def read_gguf_inventory(path: Path) -> GGUFInventory:
    """Read GGUF header/metadata/tensor descriptors without tensor payload values."""
    gguf = _load_gguf_module()
    try:
        reader = gguf.GGUFReader(path, mode="r")
    except Exception as exc:
        raise OmivInputError(f"cannot read GGUF inventory: {exc}") from exc

    metadata = [
        canonicalize_metadata_field(key, field)
        for key, field in sorted(reader.fields.items())
        if not key.startswith("GGUF.")
    ]
    seen: set[str] = set()
    tensors: list[GGUFTensorDescriptor] = []
    type_counts: Counter[str] = Counter()
    layer_ids: set[int] = set()
    for tensor in reader.tensors:
        name = str(tensor.name)
        if name in seen:
            raise OmivInputError(f"duplicate GGUF tensor name: {name}")
        seen.add(name)
        try:
            type_name = gguf.GGMLQuantizationType(int(tensor.tensor_type)).name
        except (TypeError, ValueError) as exc:
            raise OmivInputError(
                f"tensor {name!r} has unsupported GGML type {tensor.tensor_type}"
            ) from exc
        shape = [int(value) for value in tensor.shape.tolist()]
        tensors.append(
            GGUFTensorDescriptor(name=name, shape=shape, ggml_type=type_name)
        )
        type_counts[type_name] += 1
        parts = name.split(".")
        if len(parts) >= 2 and parts[0] == "blk" and parts[1].isdigit():
            layer_ids.add(int(parts[1]))

    tensors.sort(key=lambda tensor: tensor.name)
    byte_size = path.stat().st_size
    sha256 = _file_sha256(path)
    version = int(_field_value(reader, "GGUF.version"))
    metadata_count = int(_field_value(reader, "GGUF.kv_count"))
    tensor_count = int(_field_value(reader, "GGUF.tensor_count"))
    if tensor_count != len(tensors):
        raise OmivInputError(
            f"GGUF tensor count mismatch: header={tensor_count}, parsed={len(tensors)}"
        )
    if metadata_count != len(metadata):
        raise OmivInputError(
            f"GGUF metadata count mismatch: header={metadata_count}, parsed={len(metadata)}"
        )

    return GGUFInventory(
        schema_version=1,
        artifact=GGUFArtifactSummary(
            kind="monolithic",
            byte_size=byte_size,
            sha256=sha256,
            shards=[
                GGUFShardSummary(
                    index=0,
                    count=1,
                    file_name=path.name,
                    byte_size=byte_size,
                    sha256=sha256,
                )
            ],
        ),
        header=GGUFHeaderSummary(
            version=version,
            endianness=_endianness(reader),
            alignment=int(reader.alignment),
            metadata_kv_count=metadata_count,
            tensor_count=tensor_count,
        ),
        identity=GGUFIdentity(
            architecture=_field_value(reader, "general.architecture"),
            model_name=_field_value(reader, "general.name"),
        ),
        metadata=metadata,
        tensors=tensors,
        summary=GGUFSummary(
            tensor_type_counts=dict(sorted(type_counts.items())),
            observed_layer_ids=sorted(layer_ids),
            duplicate_tensor_name_count=0,
            tensor_shape_order="gguf_on_disk_reader_tensor_shape",
        ),
    )


def write_gguf_inventory(inventory: GGUFInventory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(inventory.model_dump(mode="json"), indent=2, sort_keys=True)
    path.write_text(payload + "\n", encoding="utf-8")
