from pathlib import Path

import pytest

from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
from omiv.hf.limits import MAX_JSON_NESTING


def test_bounded_json_valid_object(tmp_path: Path) -> None:
    path = tmp_path / "value.json"
    path.write_text('{"a": 1}', encoding="utf-8")
    value, raw = load_bounded_json(path, max_bytes=100)
    assert value == {"a": 1}
    assert raw == b'{"a": 1}'


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b'{"a":1,"a":2}', "duplicate object key"),
        (b"\xff", "not valid UTF-8"),
        (b'{"a":', "invalid JSON"),
        (b"[]", "top-level object"),
    ],
)
def test_bounded_json_rejections(raw: bytes, message: str) -> None:
    with pytest.raises(OmivInputError, match=message):
        parse_bounded_json_bytes(
            raw, source_name="test.json", max_bytes=100, require_object=True
        )


def test_bounded_json_oversized_before_parse(tmp_path: Path) -> None:
    path = tmp_path / "large.json"
    path.write_bytes(b"{" + b" " * 100)
    with pytest.raises(OmivInputError, match="exceeds byte limit"):
        load_bounded_json(path, max_bytes=10)


def test_bounded_json_excessive_nesting() -> None:
    raw = ("[" * (MAX_JSON_NESTING + 1) + "0" + "]" * (MAX_JSON_NESTING + 1)).encode()
    with pytest.raises(OmivInputError, match="nesting exceeds"):
        parse_bounded_json_bytes(
            b'{"value":' + raw + b"}",
            source_name="nested.json",
            max_bytes=10_000,
        )
