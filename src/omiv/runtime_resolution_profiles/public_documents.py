"""Offline loading of reviewed normalized public-document fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

from omiv.hf.json_loader import load_bounded_json
from omiv.runtime_resolution_profiles.models import PublicDocumentSource

EXPECTED = {
    "xai-release-notes.normalized.json": (
        "55450f91c5cf5e32197ff5d810170a38858fbdabe48998ebcc2ed604f63b7e7c",
        528275,
    ),
    "xai-may-15-retirement.normalized.json": (
        "338855e9c107c79dcb60e4affb107d85c6ec5dbf4cc83152e56e4d445dfbdef5",
        399122,
    ),
    "anthropic-roadmap.normalized.json": (
        "cbc20ac3ed7c133228efaf14ad17a6ca64d5746570434ce5a3174e7098ef101d",
        231215,
    ),
}


def load_public_document_fixture(repository: Path, name: str) -> tuple[PublicDocumentSource, str]:
    if name not in EXPECTED:
        raise ValueError("unknown Phase 6E public-document fixture")
    path = repository / "fixtures" / "runtime-resolution" / "public-documents" / name
    value, raw = load_bounded_json(path, max_bytes=64 * 1024)
    source = PublicDocumentSource.model_validate(value)
    expected_body_digest, expected_body_size = EXPECTED[name]
    if (
        source.response_body_sha256 != expected_body_digest
        or source.content_length != expected_body_size
    ):
        raise ValueError("normalized public-document body identity mismatch")
    return source, hashlib.sha256(raw).hexdigest()
