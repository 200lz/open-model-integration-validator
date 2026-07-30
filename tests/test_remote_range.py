from __future__ import annotations

from collections.abc import Mapping

import pytest

from omiv.errors import OmivInputError
from omiv.remote.range_client import (
    BoundedRangeClient,
    HostPolicy,
    RangeValidationError,
)


class Response:
    def __init__(
        self,
        status: int,
        headers: Mapping[str, str],
        body: bytes = b"",
    ) -> None:
        self.status = status
        self.headers = dict(headers)
        self.body = body
        self.position = 0
        self.read_amounts: list[int] = []
        self.closed = False

    def read(self, amount: int = -1) -> bytes:
        assert amount >= 0, "production client must never issue an unbounded read"
        self.read_amounts.append(amount)
        chunk = self.body[self.position : self.position + amount]
        self.position += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class Transport:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    def request(
        self, url: str, *, headers: Mapping[str, str], timeout: float
    ) -> Response:
        self.calls.append((url, dict(headers)))
        return self.responses.pop(0)


def response(
    body: bytes = b"GGUF\x03\x00\x00\x00",
    *,
    status: int = 206,
    content_range: str = "bytes 0-7/100",
    extra_headers: Mapping[str, str] | None = None,
) -> Response:
    headers = {
        "Content-Range": content_range,
        "Content-Length": str(len(body)),
        **dict(extra_headers or {}),
    }
    return Response(status, headers, body)


def run(single: Response, **kwargs: object) -> tuple[object, Transport]:
    transport = Transport([single])
    result = BoundedRangeClient(transport=transport, max_response_bytes=8).read(
        "https://huggingface.co/o/r/resolve/" + "a" * 40 + "/f.gguf",
        offset=0,
        length=8,
        expected_total_size=100,
        **kwargs,
    )
    return result, transport


def test_valid_206_streams_exactly_and_hashes() -> None:
    item = response(extra_headers={"ETag": '"stable"'})
    result, transport = run(item)
    assert result.data == b"GGUF\x03\x00\x00\x00"
    assert result.total_size == 100
    assert result.etag == '"stable"'
    assert transport.calls[0][1]["Range"] == "bytes=0-7"
    assert transport.calls[0][1]["Accept-Encoding"] == "identity"
    assert item.read_amounts == [9, 1]
    assert item.closed


@pytest.mark.parametrize(
    ("item", "message"),
    [
        (response(status=200), "status must be 206"),
        (response(content_range="bad"), "malformed Content-Range"),
        (response(content_range="bytes 1-8/100"), "does not match"),
        (response(body=b"short", content_range="bytes 0-7/100"), "Content-Length"),
        (response(content_range="bytes 0-7/101"), "disagrees"),
        (
            response(extra_headers={"Content-Encoding": "gzip"}),
            "compressed",
        ),
        (
            response(extra_headers={"Content-Type": "multipart/byteranges; boundary=x"}),
            "multipart",
        ),
    ],
)
def test_invalid_responses_are_rejected(item: Response, message: str) -> None:
    with pytest.raises(RangeValidationError, match=message):
        run(item)
    assert item.closed


def test_short_and_long_streaming_bodies_are_rejected() -> None:
    short = response()
    short.headers.pop("Content-Length")
    short.body = b"1234"
    with pytest.raises(RangeValidationError, match="body length"):
        run(short)

    long = response()
    long.headers.pop("Content-Length")
    long.body = b"123456789"
    with pytest.raises(RangeValidationError, match="byte cap"):
        run(long)
    assert max(long.read_amounts) <= 9
    assert long.position == 9


def test_ignored_range_200_body_is_not_consumed() -> None:
    item = response(body=b"x" * 1000, status=200)
    item.headers = {"Content-Length": "1000"}
    with pytest.raises(RangeValidationError, match="status must be 206"):
        run(item)
    assert item.read_amounts == []
    assert item.closed


def test_redirects_are_bounded_validated_and_strip_authorization() -> None:
    redirect = Response(
        302,
        {
            "Location": "https://cas-bridge.xethub.hf.co/blob?X-Amz-Signature=secret"
        },
    )
    final = response()
    transport = Transport([redirect, final])
    result = BoundedRangeClient(transport=transport, max_response_bytes=8).read(
        "https://huggingface.co/o/r/resolve/" + "a" * 40 + "/f",
        offset=0,
        length=8,
        expected_total_size=100,
        authorization="Bearer secret",
    )
    assert result.redirect_count == 1
    assert "Authorization" in transport.calls[0][1]
    assert "Authorization" not in transport.calls[1][1]
    assert "secret" not in repr(result)

    bad = Transport(
        [Response(302, {"Location": "https://evil.example/file?token=secret"})]
    )
    with pytest.raises(OmivInputError, match="not provider-approved"):
        BoundedRangeClient(transport=bad).read(
            "https://huggingface.co/file", offset=0, length=1
        )

    excess = Transport(
        [Response(302, {"Location": "https://huggingface.co/again"})]
    )
    with pytest.raises(RangeValidationError, match="redirect limit"):
        BoundedRangeClient(transport=excess, max_redirects=0).read(
            "https://huggingface.co/file", offset=0, length=1
        )


def test_http_host_headers_response_and_error_body_caps() -> None:
    assert HostPolicy().validate("https://us.aws.cdn.hf.co/file") == "us.aws.cdn.hf.co"
    with pytest.raises(OmivInputError, match="HTTPS"):
        HostPolicy().validate("http://huggingface.co/file")
    with pytest.raises(OmivInputError, match="not provider-approved"):
        HostPolicy().validate("https://huggingface.co.evil.example/file")

    huge_header = response(extra_headers={"X-Large": "x" * 100})
    with pytest.raises(RangeValidationError, match="headers"):
        client = BoundedRangeClient(
            transport=Transport([huge_header]),
            max_response_bytes=8,
            max_header_bytes=32,
        )
        client.read("https://huggingface.co/f", offset=0, length=8)

    error = Response(500, {}, b"x" * 100)
    client = BoundedRangeClient(
        transport=Transport([error]),
        max_error_body_bytes=7,
    )
    with pytest.raises(RangeValidationError, match="status"):
        client.read("https://huggingface.co/f", offset=0, length=1)
    assert error.position == 8
    assert all(amount <= 8 for amount in error.read_amounts)


def test_request_larger_than_cap_is_configuration_error() -> None:
    with pytest.raises(OmivInputError, match="maximum"):
        BoundedRangeClient(max_response_bytes=4).read(
            "https://huggingface.co/f", offset=0, length=8
        )
