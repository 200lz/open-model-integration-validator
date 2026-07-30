"""Strict streaming HTTP byte-range transport."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import HTTPMessage
from typing import Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from omiv.errors import OmivInputError

_CONTENT_RANGE = re.compile(r"^bytes ([0-9]+)-([0-9]+)/([0-9]+)$")


class RangeValidationError(RuntimeError):
    """Remote evidence failed strict bounded-range validation."""


class StreamingResponse(Protocol):
    status: int
    headers: Mapping[str, str]

    def read(self, amount: int = -1) -> bytes: ...

    def close(self) -> None: ...


class RangeTransport(Protocol):
    def request(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
    ) -> StreamingResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> None:
        return None


class UrllibRangeTransport:
    """urllib transport with redirects disabled for caller-side validation."""

    def __init__(self) -> None:
        self._opener = build_opener(_NoRedirect())

    def request(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
    ) -> StreamingResponse:
        request = Request(url, headers=dict(headers), method="GET")  # noqa: S310
        try:
            return self._opener.open(request, timeout=timeout)  # type: ignore[no-any-return]  # noqa: S310
        except HTTPError as exc:
            return cast(StreamingResponse, exc)
        except (URLError, TimeoutError, OSError) as exc:
            raise RangeValidationError("range request transport failed") from exc


@dataclass(frozen=True)
class RangeReadResult:
    data: bytes
    http_status: int
    content_range: str
    total_size: int
    etag: str | None
    redirect_count: int
    final_host: str
    response_sha256: str


class HostPolicy:
    """Explicit Hugging Face and provider storage host policy."""

    def __init__(
        self,
        *,
        exact_hosts: frozenset[str] = frozenset(
            {"huggingface.co", "cas-bridge.xethub.hf.co"}
        ),
        suffix_hosts: tuple[str, ...] = (".huggingface.co", ".cdn.hf.co"),
    ) -> None:
        self.exact_hosts = exact_hosts
        self.suffix_hosts = suffix_hosts

    def validate(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            raise OmivInputError("remote range URL must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise OmivInputError("remote range URL must not contain user information")
        try:
            port = parsed.port
        except ValueError as exc:
            raise OmivInputError("remote range URL has an invalid port") from exc
        if port not in (None, 443):
            raise OmivInputError("remote range URL must use the HTTPS default port")
        host = (parsed.hostname or "").lower()
        if not host or not (
            host in self.exact_hosts
            or any(host.endswith(suffix) and host != suffix[1:] for suffix in self.suffix_hosts)
        ):
            raise OmivInputError(f"remote range host is not provider-approved: {host or '<empty>'}")
        return host


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


class BoundedRangeClient:
    """Fetch exactly one validated byte range without full-body fallback."""

    def __init__(
        self,
        *,
        transport: RangeTransport | None = None,
        host_policy: HostPolicy | None = None,
        max_response_bytes: int = 1024 * 1024,
        max_redirects: int = 5,
        timeout: float = 30.0,
        max_header_bytes: int = 64 * 1024,
        max_error_body_bytes: int = 4096,
    ) -> None:
        if min(max_response_bytes, max_header_bytes, max_error_body_bytes) < 1:
            raise OmivInputError("range client byte limits must be positive")
        if max_redirects < 0 or timeout <= 0:
            raise OmivInputError("invalid range client redirect or timeout limit")
        self.transport = transport or UrllibRangeTransport()
        self.host_policy = host_policy or HostPolicy()
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.max_header_bytes = max_header_bytes
        self.max_error_body_bytes = max_error_body_bytes

    def read(
        self,
        url: str,
        *,
        offset: int,
        length: int,
        expected_total_size: int | None = None,
        authorization: str | None = None,
    ) -> RangeReadResult:
        if isinstance(offset, bool) or offset < 0:
            raise OmivInputError("range offset must be a non-negative integer")
        if isinstance(length, bool) or length < 1:
            raise OmivInputError("range length must be a positive integer")
        if length > self.max_response_bytes:
            raise OmivInputError("requested range exceeds maximum response bytes")
        if expected_total_size is not None and expected_total_size < 0:
            raise OmivInputError("expected artifact size must be non-negative")
        end = offset + length - 1
        current_url = url
        original_host = self.host_policy.validate(url)
        redirects = 0
        auth = authorization

        while True:
            current_host = self.host_policy.validate(current_url)
            headers = {
                "Accept": "application/octet-stream",
                "Accept-Encoding": "identity",
                "Range": f"bytes={offset}-{end}",
                "User-Agent": "omiv/0.1",
            }
            if auth is not None:
                headers["Authorization"] = auth
            response = self.transport.request(
                current_url,
                headers=headers,
                timeout=self.timeout,
            )
            try:
                self._validate_headers_size(response.headers)
                status = response.status
                if status in {301, 302, 303, 307, 308}:
                    location = _header(response.headers, "Location")
                    if not location:
                        raise RangeValidationError("redirect response is missing Location")
                    if redirects >= self.max_redirects:
                        raise RangeValidationError("range request exceeded redirect limit")
                    destination = urljoin(current_url, location)
                    destination_host = self.host_policy.validate(destination)
                    redirects += 1
                    if destination_host != original_host:
                        auth = None
                    current_url = destination
                    continue
                if status != 206:
                    if status != 200:
                        self._read_error_body(response)
                    raise RangeValidationError(
                        f"range response status must be 206, received {status}"
                    )

                encoding = (_header(response.headers, "Content-Encoding") or "identity").lower()
                if encoding not in {"", "identity"}:
                    raise RangeValidationError("compressed range response is not accepted")
                content_type = (_header(response.headers, "Content-Type") or "").lower()
                if content_type.startswith("multipart/byteranges"):
                    raise RangeValidationError("multipart range response is not supported")
                content_range = _header(response.headers, "Content-Range")
                if content_range is None:
                    raise RangeValidationError("range response is missing Content-Range")
                match = _CONTENT_RANGE.fullmatch(content_range)
                if match is None:
                    raise RangeValidationError("malformed Content-Range")
                observed_start, observed_end, total = map(int, match.groups())
                if observed_start != offset or observed_end != end:
                    raise RangeValidationError("Content-Range does not match requested range")
                if total <= observed_end:
                    raise RangeValidationError("Content-Range total is inconsistent")
                if expected_total_size is not None and total != expected_total_size:
                    raise RangeValidationError("Content-Range total disagrees with snapshot size")
                content_length = _header(response.headers, "Content-Length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError as exc:
                        raise RangeValidationError("invalid Content-Length") from exc
                    if declared_length != length:
                        raise RangeValidationError(
                            "Content-Length does not match requested range"
                        )
                data = self._read_bounded_body(response, length)
                if len(data) != length:
                    raise RangeValidationError("range body length does not match request")
                etag = self._safe_etag(_header(response.headers, "ETag"))
                return RangeReadResult(
                    data=data,
                    http_status=status,
                    content_range=content_range,
                    total_size=total,
                    etag=etag,
                    redirect_count=redirects,
                    final_host=current_host,
                    response_sha256=hashlib.sha256(data).hexdigest(),
                )
            finally:
                response.close()

    def _validate_headers_size(self, headers: Mapping[str, str]) -> None:
        size = sum(len(str(key)) + len(str(value)) + 4 for key, value in headers.items())
        if size > self.max_header_bytes:
            raise RangeValidationError("range response headers exceed configured cap")

    def _read_bounded_body(self, response: StreamingResponse, expected: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        limit = min(expected, self.max_response_bytes)
        while True:
            chunk = response.read(min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise RangeValidationError("range response exceeded the permitted byte cap")
            chunks.append(chunk)
        return b"".join(chunks)

    def _read_error_body(self, response: StreamingResponse) -> None:
        remaining = self.max_error_body_bytes + 1
        while remaining > 0:
            chunk = response.read(min(4096, remaining))
            if not chunk:
                return
            remaining -= len(chunk)

    @staticmethod
    def _safe_etag(value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) > 512 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            return None
        return value
