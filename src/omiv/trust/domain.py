"""Stable domain-separated byte encodings used by Phase 5D."""

from __future__ import annotations

from typing import Final

from omiv.canonical import canonical_json_bytes
from omiv.trust.models import SignaturePayloadDescriptor

SIGNED_OBJECT_DOMAIN: Final[bytes] = b"OMIV-SIGNED-OBJECT-V1"
DELEGATION_DOMAIN: Final[bytes] = b"OMIV-DELEGATION-V1"


def signed_object_bytes(descriptor: SignaturePayloadDescriptor) -> bytes:
    """Return ASCII domain, NUL, then OMIV canonical JSON descriptor bytes."""
    return (
        SIGNED_OBJECT_DOMAIN
        + b"\x00"
        + canonical_json_bytes(descriptor.model_dump(mode="json", by_alias=True))
    )


def delegation_bytes(payload: dict[str, object]) -> bytes:
    return DELEGATION_DOMAIN + b"\x00" + canonical_json_bytes(payload)
