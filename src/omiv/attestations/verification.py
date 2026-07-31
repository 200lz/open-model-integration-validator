"""Attestation and execution-record integrity verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.attestations.builder import build_attestation
from omiv.attestations.models import (
    ArtifactAttestation,
    ArtifactAttestationInput,
    ToolExecutionRecord,
)
from omiv.attestations.policy import attestation_policy
from omiv.canonical import load_json_value
from omiv.errors import OmivInputError

MAX_ATTESTATION_BYTES = 4 * 1024 * 1024


def _read(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_ATTESTATION_BYTES:
            raise OmivInputError("attestation exceeds the bounded input limit")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot read attestation: {exc}") from exc


def attestation_input_from_canonical(
    value: ArtifactAttestation,
) -> ArtifactAttestationInput:
    raw = value.model_dump(mode="json", by_alias=True)
    for field in (
        "attestation_id",
        "authenticity",
        "acquisition_outcome",
        "verification_summary",
        "policy_identity",
        "attestation_digest",
    ):
        raw.pop(field)
    raw["schema"] = "omiv.artifact-attestation-input.v1"
    return ArtifactAttestationInput.model_validate(raw)


def load_attestation(path: Path) -> ArtifactAttestation:
    try:
        value = ArtifactAttestation.model_validate(_read(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid artifact attestation: {exc}") from exc
    return value


def verify_attestation(path: Path) -> ArtifactAttestation:
    value = load_attestation(path)
    if value.policy_identity.policy_digest != attestation_policy().policy_digest:
        raise OmivInputError("attestation policy digest mismatch")
    rebuilt = build_attestation(attestation_input_from_canonical(value))
    if rebuilt != value:
        raise OmivInputError("artifact attestation does not reconstruct")
    return value


def verify_execution_record(value: ToolExecutionRecord) -> ToolExecutionRecord:
    """Pydantic canonical validators reconstruct both execution identities."""
    return ToolExecutionRecord.model_validate(value.model_dump(mode="json", by_alias=True))
