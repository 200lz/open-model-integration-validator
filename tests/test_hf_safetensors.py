from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest
from hf_helpers import descriptors_from_shapes, write_safetensors

from omiv.errors import OmivInputError
from omiv.hf.limits import (
    MAX_DIMENSION_VALUE,
    MAX_SAFETENSORS_HEADER_BYTES,
    MAX_TENSOR_RANK,
)
from omiv.hf.safetensors import parse_safetensors_header


def _one() -> dict[str, dict[str, Any]]:
    return {
        "z.weight": {"dtype": "BF16", "shape": [2], "data_offsets": [0, 4]},
        "a.weight": {"dtype": "BF16", "shape": [1], "data_offsets": [4, 6]},
    }


def test_valid_monolithic_header_and_order(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    write_safetensors(path, _one(), metadata={})
    parsed = parse_safetensors_header(path)
    assert [tensor.name for tensor in parsed.tensors] == ["a.weight", "z.weight"]
    assert parsed.payload_length == 6
    assert parsed.diagnostics == []


def test_duplicate_tensor_names_in_header(tmp_path: Path) -> None:
    header = b'{"x":{"dtype":"BF16","shape":[1],"data_offsets":[0,2]},' \
        b'"x":{"dtype":"BF16","shape":[1],"data_offsets":[2,4]}}'
    path = tmp_path / "model.safetensors"
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"\0" * 4)
    with pytest.raises(OmivInputError, match="duplicate object key"):
        parse_safetensors_header(path)


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        ({"dtype": "NOPE", "shape": [1], "data_offsets": [0, 1]}, "unsupported dtype"),
        ({"dtype": "BF16", "shape": [-1], "data_offsets": [0, 0]}, "dimension"),
        (
            {"dtype": "BF16", "shape": [1] * (MAX_TENSOR_RANK + 1), "data_offsets": [0, 2]},
            "rank exceeds",
        ),
        (
            {"dtype": "BF16", "shape": [MAX_DIMENSION_VALUE + 1], "data_offsets": [0, 0]},
            "dimension",
        ),
        (
            {
                "dtype": "BF16",
                "shape": [MAX_DIMENSION_VALUE, MAX_DIMENSION_VALUE],
                "data_offsets": [0, 0],
            },
            "overflows",
        ),
        ({"dtype": "BF16", "shape": [1], "data_offsets": [2, 1]}, "offsets are invalid"),
        ({"dtype": "BF16", "shape": [2], "data_offsets": [0, 2]}, "span does not match"),
    ],
)
def test_invalid_descriptor(
    tmp_path: Path, descriptor: dict[str, Any], message: str
) -> None:
    path = tmp_path / "model.safetensors"
    write_safetensors(path, {"x": descriptor}, payload_length=4)
    with pytest.raises(OmivInputError, match=message):
        parse_safetensors_header(path)


def test_offset_exceeds_payload(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    write_safetensors(
        path,
        {"x": {"dtype": "BF16", "shape": [2], "data_offsets": [2, 6]}},
        payload_length=4,
    )
    with pytest.raises(OmivInputError, match="exceed payload"):
        parse_safetensors_header(path)


def test_overlap(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    descriptors = {
        "a": {"dtype": "BF16", "shape": [2], "data_offsets": [0, 4]},
        "b": {"dtype": "BF16", "shape": [2], "data_offsets": [2, 6]},
    }
    write_safetensors(path, descriptors)
    with pytest.raises(OmivInputError, match="overlaps"):
        parse_safetensors_header(path)


@pytest.mark.parametrize(
    ("descriptors", "payload_length", "codes"),
    [
        (
            {"a": {"dtype": "BF16", "shape": [1], "data_offsets": [2, 4]}},
            4,
            ["SAFETENSORS_INITIAL_GAP"],
        ),
        (
            {
                "a": {"dtype": "BF16", "shape": [1], "data_offsets": [0, 2]},
                "b": {"dtype": "BF16", "shape": [1], "data_offsets": [4, 6]},
            },
            6,
            ["SAFETENSORS_INTERMEDIATE_GAP"],
        ),
        (
            {"a": {"dtype": "BF16", "shape": [1], "data_offsets": [0, 2]}},
            4,
            ["SAFETENSORS_TRAILING_GAP"],
        ),
    ],
)
def test_gap_diagnostics(
    tmp_path: Path,
    descriptors: dict[str, dict[str, Any]],
    payload_length: int,
    codes: list[str],
) -> None:
    path = tmp_path / "model.safetensors"
    write_safetensors(path, descriptors, payload_length=payload_length)
    parsed = parse_safetensors_header(path)
    assert [diagnostic.code for diagnostic in parsed.diagnostics] == codes


def test_header_larger_than_file(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    path.write_bytes(struct.pack("<Q", 100) + b"{}")
    with pytest.raises(OmivInputError, match="does not fit"):
        parse_safetensors_header(path)


def test_header_cap_exceeded(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    path.write_bytes(struct.pack("<Q", MAX_SAFETENSORS_HEADER_BYTES + 1))
    with pytest.raises(OmivInputError, match="exceeds cap"):
        parse_safetensors_header(path)


def test_payload_bytes_are_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "model.safetensors"
    write_safetensors(path, _one())
    raw = path.read_bytes()
    header_length = struct.unpack("<Q", raw[:8])[0]
    allowed = 8 + header_length
    original_open = Path.open

    class Guard:
        def __init__(self, handle: Any) -> None:
            self.handle = handle
            self.read_count = 0

        def __enter__(self) -> Guard:
            return self

        def __exit__(self, *args: Any) -> None:
            self.handle.close()

        def read(self, size: int = -1) -> bytes:
            if size < 0 or self.read_count + size > allowed:
                raise AssertionError("payload read attempted")
            value = self.handle.read(size)
            self.read_count += len(value)
            return value

    def guarded_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = original_open(self, *args, **kwargs)
        return Guard(handle) if self == path else handle

    monkeypatch.setattr(Path, "open", guarded_open)
    assert len(parse_safetensors_header(path).tensors) == 2


def test_zero_length_tensor_is_safe(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    descriptors, _ = descriptors_from_shapes({"empty": [0, 4]})
    write_safetensors(path, descriptors)
    parsed = parse_safetensors_header(path)
    assert parsed.tensors[0].data_offsets == (0, 0)
