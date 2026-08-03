"""Bounded provider-neutral HTTP metadata collection contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from omiv.errors import OmivInputError
from omiv.reconciliation.models import CollectionLimits


@dataclass(frozen=True)
class HttpMetadataResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpMetadataTransport(Protocol):
    def request(self, url: str, *, timeout_seconds: float) -> HttpMetadataResponse: ...


@dataclass(frozen=True)
class CollectionAccounting:
    contacted_hosts: tuple[str, ...]
    requested_urls: tuple[str, ...]
    redirect_hosts: tuple[str, ...]
    request_count: int
    response_count: int
    response_bytes: int


class BoundedMetadataClient:
    """A no-payload client with injected transport and explicit accounting."""

    def __init__(
        self,
        transport: HttpMetadataTransport,
        *,
        allowed_hosts: tuple[str, ...],
        limits: CollectionLimits,
        timeout_seconds: float = 20.0,
        maximum_retries: int = 1,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise OmivInputError("metadata timeout must be in (0, 60]")
        if maximum_retries < 0 or maximum_retries > 2:
            raise OmivInputError("metadata retries must be between zero and two")
        self._transport = transport
        self._allowed_hosts = frozenset(allowed_hosts)
        self._limits = limits
        self._timeout = timeout_seconds
        self._retries = maximum_retries
        self._hosts: set[str] = set()
        self._urls: set[str] = set()
        self._redirect_hosts: set[str] = set()
        self._requests = 0
        self._responses = 0
        self._bytes = 0

    @property
    def accounting(self) -> CollectionAccounting:
        return CollectionAccounting(
            contacted_hosts=tuple(sorted(self._hosts)),
            requested_urls=tuple(sorted(self._urls)),
            redirect_hosts=tuple(sorted(self._redirect_hosts)),
            request_count=self._requests,
            response_count=self._responses,
            response_bytes=self._bytes,
        )

    def get_json_metadata(self, url: str) -> bytes:
        return self.get_json_response(url).body

    def get_json_response(self, url: str) -> HttpMetadataResponse:
        current = url
        redirects = 0
        attempts = 0
        while True:
            parsed = self._validate_url(current)
            if self._requests >= self._limits.maximum_requests:
                raise OmivInputError("LIMIT_EXCEEDED:HTTP_REQUESTS")
            self._requests += 1
            self._hosts.add(parsed.hostname or "")
            self._urls.add(_secret_safe_url(current))
            try:
                response = self._transport.request(current, timeout_seconds=self._timeout)
            except TimeoutError as exc:
                if attempts >= self._retries:
                    raise OmivInputError("bounded metadata request timed out") from exc
                attempts += 1
                continue
            self._responses += 1
            size = len(response.body)
            if size > self._limits.maximum_response_bytes:
                raise OmivInputError("LIMIT_EXCEEDED:INDIVIDUAL_RESPONSE_BYTES")
            self._bytes += size
            if self._bytes > self._limits.maximum_total_response_bytes:
                raise OmivInputError("LIMIT_EXCEEDED:TOTAL_RESPONSE_BYTES")
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location") or response.headers.get("Location")
                if not location:
                    raise OmivInputError("redirect response lacks a location")
                redirects += 1
                if redirects > self._limits.maximum_redirects_per_request:
                    raise OmivInputError("LIMIT_EXCEEDED:HTTP_REDIRECTS")
                current = urljoin(current, location)
                target = self._validate_url(current)
                self._redirect_hosts.add(target.hostname or "")
                continue
            if response.status != 200:
                raise OmivInputError(f"metadata endpoint returned HTTP {response.status}")
            content_type = response.headers.get("content-type", "").lower()
            if content_type and "json" not in content_type:
                raise OmivInputError("metadata endpoint returned non-JSON content")
            return response

    def _validate_url(self, url: str) -> SplitResult:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise OmivInputError("metadata URL must use HTTPS")
        if parsed.username or parsed.password or parsed.fragment:
            raise OmivInputError("metadata URL contains credentials or fragment")
        if parsed.hostname not in self._allowed_hosts:
            raise OmivInputError("metadata URL host is outside the allowlist")
        lowered_query = parsed.query.lower()
        if any(
            marker in lowered_query
            for marker in (
                "token=",
                "signature=",
                "x-amz-",
                "key-pair-id=",
                "credential=",
            )
        ):
            raise OmivInputError("signed or credential-bearing query is prohibited")
        lowered_path = parsed.path.lower()
        if lowered_path.endswith(
            (".safetensors", ".bin", ".gguf", ".ckpt", ".pt", ".pth", ".tar", ".zip")
        ):
            raise OmivInputError("model weight, executable, or archive GET is prohibited")
        return parsed


def _secret_safe_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
