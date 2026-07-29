from __future__ import annotations

import struct
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.gguf.reader import (
    METADATA_ARRAY_INLINE_THRESHOLD,
    _array_digest,
    _load_gguf_module,
    _scalar_bytes,
    canonicalize_metadata_field,
    read_gguf_inventory,
    write_gguf_inventory,
)

runner = CliRunner()


class ValueType(Enum):
    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


class FakeField:
    def __init__(self, types: list[ValueType], value: Any) -> None:
        self.types = types
        self.value = value
        self.data = list(range(len(value))) if types[0] == ValueType.ARRAY else [0]

    def contents(self, index: int | slice = slice(None)) -> Any:
        if self.types[0] == ValueType.ARRAY:
            return self.value[index]
        return self.value


class FakeShape:
    def __init__(self, values: list[int]) -> None:
        self.values = values

    def tolist(self) -> list[int]:
        return self.values


class FakeTensor:
    def __init__(self, name: str, shape: list[int], tensor_type: int) -> None:
        self.name = name
        self.shape = FakeShape(shape)
        self.tensor_type = tensor_type

    @property
    def data(self) -> None:
        raise AssertionError("ReaderTensor.data must never be accessed")


def _fake_module(tensors: list[FakeTensor], fields: dict[str, FakeField]) -> Any:
    class FakeReader:
        def __init__(self, path: Path, mode: str) -> None:
            assert mode == "r"
            self.fields = fields
            self.tensors = tensors
            self.alignment = 32
            self.endianess = SimpleNamespace(name="LITTLE")

    type_names = {0: "F32", 1: "F16", 8: "Q8_0"}
    return SimpleNamespace(
        GGUFReader=FakeReader,
        GGMLQuantizationType=lambda value: SimpleNamespace(name=type_names[value]),
    )


def _fields(tensor_count: int) -> dict[str, FakeField]:
    metadata = {
        "general.architecture": FakeField([ValueType.STRING], "mock"),
        "general.name": FakeField([ValueType.STRING], "mock-model"),
        "mock.scalar": FakeField([ValueType.UINT32], 7),
        "mock.small": FakeField([ValueType.ARRAY, ValueType.UINT32], [1, 2, 3]),
    }
    return {
        "GGUF.version": FakeField([ValueType.UINT32], 3),
        "GGUF.tensor_count": FakeField([ValueType.UINT32], tensor_count),
        "GGUF.kv_count": FakeField([ValueType.UINT32], len(metadata)),
        **metadata,
    }


def test_missing_optional_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> None:
        raise ModuleNotFoundError(name)

    monkeypatch.setattr("omiv.gguf.reader.importlib.import_module", missing)
    with pytest.raises(OmivInputError, match=r"pip install.*\[gguf\]"):
        _load_gguf_module()


def test_missing_optional_dependency_cli_exit_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> None:
        raise OmivInputError(
            "install with `pip install 'open-model-integration-validator[gguf]'`"
        )

    monkeypatch.setattr("omiv.gguf.reader._load_gguf_module", unavailable)
    source = tmp_path / "model.gguf"
    source.write_bytes(b"GGUF")
    result = runner.invoke(
        app,
        [
            "gguf-normalize",
            "--input",
            str(source),
            "--output",
            str(tmp_path / "inventory.json"),
        ],
    )
    assert result.exit_code == 2
    assert "open-model-integration-validator[gguf]" in result.stderr


def test_malformed_gguf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenReader:
        def __init__(self, path: Path, mode: str) -> None:
            raise ValueError("bad magic")

    monkeypatch.setattr(
        "omiv.gguf.reader._load_gguf_module",
        lambda: SimpleNamespace(GGUFReader=BrokenReader),
    )
    path = tmp_path / "bad.gguf"
    path.write_bytes(b"not gguf")
    with pytest.raises(OmivInputError, match="bad magic"):
        read_gguf_inventory(path)


def test_scalar_and_small_array_metadata() -> None:
    scalar = canonicalize_metadata_field(
        "answer", FakeField([ValueType.UINT32], 42)
    )
    small = canonicalize_metadata_field(
        "items", FakeField([ValueType.ARRAY, ValueType.UINT32], [1, 2, 3])
    )
    assert scalar.value == 42
    assert scalar.value_type == "UINT32"
    assert small.value == [1, 2, 3]
    assert small.array_length == 3
    assert small.value_sha256 is not None


def test_float_scalars_use_their_declared_widths() -> None:
    float32 = _scalar_bytes("FLOAT32", 1.5)
    float64 = _scalar_bytes("FLOAT64", 1.5)
    assert float32 == b"FLOAT32\0" + struct.pack(">f", 1.5)
    assert float64 == b"FLOAT64\0" + struct.pack(">d", 1.5)
    assert len(float64) - len(b"FLOAT64\0") == 8
    assert len(float32) - len(b"FLOAT32\0") == 4


@pytest.mark.parametrize(
    ("type_name", "minimum", "maximum", "scalar_format"),
    [
        ("UINT8", 0, 2**8 - 1, ">B"),
        ("INT8", -(2**7), 2**7 - 1, ">b"),
        ("UINT16", 0, 2**16 - 1, ">H"),
        ("INT16", -(2**15), 2**15 - 1, ">h"),
        ("UINT32", 0, 2**32 - 1, ">I"),
        ("INT32", -(2**31), 2**31 - 1, ">i"),
        ("UINT64", 0, 2**64 - 1, ">Q"),
        ("INT64", -(2**63), 2**63 - 1, ">q"),
    ],
)
def test_integer_boundaries_are_accepted(
    type_name: str, minimum: int, maximum: int, scalar_format: str
) -> None:
    prefix = type_name.encode("ascii") + b"\0"
    assert _scalar_bytes(type_name, minimum) == prefix + struct.pack(
        scalar_format, minimum
    )
    assert _scalar_bytes(type_name, maximum) == prefix + struct.pack(
        scalar_format, maximum
    )


@pytest.mark.parametrize(
    ("type_name", "value"),
    [
        ("UINT8", -1),
        ("UINT8", 2**8),
        ("INT8", -(2**7) - 1),
        ("INT8", 2**7),
        ("UINT16", -1),
        ("UINT16", 2**16),
        ("INT16", -(2**15) - 1),
        ("INT16", 2**15),
        ("UINT32", -1),
        ("UINT32", 2**32),
        ("INT32", -(2**31) - 1),
        ("INT32", 2**31),
        ("UINT64", -1),
        ("UINT64", 2**64),
        ("INT64", -(2**63) - 1),
        ("INT64", 2**63),
    ],
)
def test_out_of_range_integers_are_rejected(type_name: str, value: int) -> None:
    with pytest.raises(OmivInputError, match="outside its declared type range"):
        _scalar_bytes(type_name, value)


def test_declared_types_produce_distinct_scalar_bytes_and_array_digests() -> None:
    uint32_field = FakeField([ValueType.ARRAY, ValueType.UINT32], [1, 2, 3])
    uint64_field = FakeField([ValueType.ARRAY, ValueType.UINT64], [1, 2, 3])
    assert _scalar_bytes("UINT32", 1) != _scalar_bytes("UINT64", 1)
    assert _array_digest(uint32_field, "UINT32", 3) != _array_digest(
        uint64_field, "UINT64", 3
    )


def test_unsupported_scalar_type_is_rejected_explicitly() -> None:
    with pytest.raises(OmivInputError, match="unsupported GGUF scalar type"):
        _scalar_bytes("ARRAY", [])


def test_large_array_digest_is_deterministic_and_not_inline() -> None:
    values = list(range(METADATA_ARRAY_INLINE_THRESHOLD + 1))
    field = FakeField([ValueType.ARRAY, ValueType.UINT32], values)
    first = canonicalize_metadata_field("large", field)
    second = canonicalize_metadata_field("large", field)
    assert first.value is None
    assert first.array_length == len(values)
    assert first.value_sha256 == second.value_sha256


def test_metadata_array_normalization_is_deterministic() -> None:
    values = [-(2**31), 0, 2**31 - 1]
    first = canonicalize_metadata_field(
        "values", FakeField([ValueType.ARRAY, ValueType.INT32], values)
    )
    second = canonicalize_metadata_field(
        "values", FakeField([ValueType.ARRAY, ValueType.INT32], list(values))
    )
    assert first == second


def test_empty_array_retains_encoded_element_type() -> None:
    field = FakeField([ValueType.ARRAY], [])
    field.parts = [FakeShape([8]), FakeShape([0])]
    entry = canonicalize_metadata_field("empty_strings", field)
    assert entry.array_element_type == "STRING"
    assert entry.array_length == 0
    assert entry.value == []


def test_tensor_sorting_shape_order_layers_and_unknown_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tensors = [
        FakeTensor("unknown.weight", [7, 3], 0),
        FakeTensor("blk.10.attn.weight", [4, 2], 1),
        FakeTensor("blk.2.ffn.weight", [8, 6], 8),
    ]
    monkeypatch.setattr(
        "omiv.gguf.reader._load_gguf_module",
        lambda: _fake_module(tensors, _fields(len(tensors))),
    )
    path = tmp_path / "mock.gguf"
    path.write_bytes(b"fixture")
    inventory = read_gguf_inventory(path)
    assert [tensor.name for tensor in inventory.tensors] == [
        "blk.10.attn.weight",
        "blk.2.ffn.weight",
        "unknown.weight",
    ]
    assert inventory.tensors[0].shape == [4, 2]
    assert inventory.summary.tensor_shape_order == "gguf_on_disk_reader_tensor_shape"
    assert inventory.summary.observed_layer_ids == [2, 10]


def test_duplicate_tensor_name_is_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tensors = [
        FakeTensor("dup.weight", [1], 0),
        FakeTensor("dup.weight", [1], 0),
    ]
    monkeypatch.setattr(
        "omiv.gguf.reader._load_gguf_module",
        lambda: _fake_module(tensors, _fields(len(tensors))),
    )
    path = tmp_path / "mock.gguf"
    path.write_bytes(b"fixture")
    with pytest.raises(OmivInputError, match="duplicate GGUF tensor name"):
        read_gguf_inventory(path)


def test_deterministic_gguf_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tensors = [FakeTensor("blk.0.weight", [2, 1], 0)]
    monkeypatch.setattr(
        "omiv.gguf.reader._load_gguf_module",
        lambda: _fake_module(tensors, _fields(len(tensors))),
    )
    source = tmp_path / "mock.gguf"
    source.write_bytes(b"fixture")
    first = read_gguf_inventory(source)
    one, two = tmp_path / "one.json", tmp_path / "two.json"
    write_gguf_inventory(first, one)
    write_gguf_inventory(read_gguf_inventory(source), two)
    assert one.read_bytes() == two.read_bytes()
