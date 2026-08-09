"""Opt-in bounded capture of the three allowlisted Phase 6E public documents.

Raw responses are written only to an explicitly supplied directory outside the
repository. This collector never follows arbitrary links or sends credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ALLOWLIST = (
    "https://docs.x.ai/developers/release-notes",
    "https://docs.x.ai/developers/migration/may-15-retirement",
    "https://www.anthropic.com/responsible-scaling-policy/roadmap",
)
ALLOWED_HOSTS = {"docs.x.ai", "x.ai", "www.anthropic.com"}
MAX_REQUESTS = 6
MAX_REDIRECTS = 3
MAX_RESPONSE = 2 * 1024 * 1024
MAX_TOTAL = 6 * 1024 * 1024


def _request(url: str, method: str) -> tuple[str, dict[str, str], bytes, int]:
    current = url
    for redirect_count in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in ALLOWED_HOSTS
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("public-document target violates the allowlist")
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=20)
        path = parsed.path or "/"
        connection.request(method, path, headers={"Accept": "text/html"})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        if response.status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            response.read()
            connection.close()
            if not location or redirect_count >= MAX_REDIRECTS:
                raise ValueError("public-document redirect limit exceeded")
            current = urljoin(current, location)
            continue
        declared = headers.get("content-length")
        if declared is not None and int(declared) > MAX_RESPONSE:
            raise ValueError("public-document response exceeds the byte limit")
        body = response.read(MAX_RESPONSE + 1) if method == "GET" else b""
        connection.close()
        if len(body) > MAX_RESPONSE:
            raise ValueError("public-document response exceeds the byte limit")
        content_type = headers.get("content-type", "").lower()
        if not content_type.startswith("text/html"):
            raise ValueError("public-document response has unsupported content type")
        return current, headers, body, response.status
    raise ValueError("public-document redirect limit exceeded")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-network", action="store_true", required=True)
    parser.add_argument("--raw-output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.raw_output_dir.resolve()
    repository = Path.cwd().resolve()
    if output == repository or repository in output.parents:
        raise SystemExit("raw public-document responses must remain outside the repository")
    output.mkdir(parents=True, exist_ok=True)
    summaries: list[dict[str, object]] = []
    total = 0
    requests = 0
    for ordinal, url in enumerate(ALLOWLIST):
        _request(url, "HEAD")
        requests += 1
        final_url, headers, body, status = _request(url, "GET")
        requests += 1
        total += len(body)
        if requests > MAX_REQUESTS or total > MAX_TOTAL:
            raise ValueError("public-document aggregate limit exceeded")
        raw_path = output / f"phase6e-public-document-{ordinal}.html"
        raw_path.write_bytes(body)
        summaries.append(
            {
                "source_url": url,
                "final_url": final_url,
                "retrieval_method": "GET",
                "head_request_count": 1,
                "get_request_count": 1,
                "status": status,
                "content_type": headers.get("content-type"),
                "content_length": len(body),
                "response_body_sha256": hashlib.sha256(body).hexdigest(),
                "collection_time": "NOT_RECORDED",
            }
        )
    print(json.dumps({"requests": requests, "total_bytes": total, "sources": summaries}, indent=2))


if __name__ == "__main__":
    main()
