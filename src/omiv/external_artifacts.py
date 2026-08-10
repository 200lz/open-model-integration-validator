"""Explicit availability semantics for reviewed external repository artifacts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from omiv.errors import OmivInputError


class ExternalArtifactStatus(StrEnum):
    """Keep recorded identity, availability, verification, and invalidity distinct."""

    EXPECTED_IDENTITY_RECORDED = "EXPECTED_IDENTITY_RECORDED"
    PRESENT_AND_VERIFIED = "PRESENT_AND_VERIFIED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    INVALID = "INVALID"


@dataclass(frozen=True)
class ExpectedExternalArtifact:
    relative_path: str
    size_bytes: int
    sha256: str
    identity_status: ExternalArtifactStatus = ExternalArtifactStatus.EXPECTED_IDENTITY_RECORDED


@dataclass(frozen=True)
class ExternalArtifactObservation:
    expected: ExpectedExternalArtifact
    status: ExternalArtifactStatus
    observed_size_bytes: int | None
    observed_sha256: str | None

    @property
    def available(self) -> bool:
        return self.status == ExternalArtifactStatus.PRESENT_AND_VERIFIED


class ExternalArtifactUnavailable(OmivInputError):
    """A reviewed external input was not supplied in the current environment."""

    def __init__(self, expected: ExpectedExternalArtifact) -> None:
        self.expected = expected
        super().__init__(f"external artifact not available: {expected.relative_path}")


KIMI_K3_TENSOR_INVENTORY = ExpectedExternalArtifact(
    relative_path="reports/raw/kimi_k3_tensors.json",
    size_bytes=115_542_096,
    sha256="15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469",
)

EXPECTED_EXTERNAL_ARTIFACTS = {
    KIMI_K3_TENSOR_INVENTORY.relative_path: KIMI_K3_TENSOR_INVENTORY,
}


def expected_external_artifact(relative_path: str) -> ExpectedExternalArtifact | None:
    return EXPECTED_EXTERNAL_ARTIFACTS.get(relative_path)


def observe_external_artifact(
    root: Path, expected: ExpectedExternalArtifact
) -> ExternalArtifactObservation:
    """Observe an external artifact without treating absence as byte verification."""
    path = root.resolve() / expected.relative_path
    if not path.exists():
        return ExternalArtifactObservation(
            expected=expected,
            status=ExternalArtifactStatus.NOT_AVAILABLE,
            observed_size_bytes=None,
            observed_sha256=None,
        )
    if not path.is_file():
        return ExternalArtifactObservation(
            expected=expected,
            status=ExternalArtifactStatus.INVALID,
            observed_size_bytes=None,
            observed_sha256=None,
        )
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    observed_sha256 = digest.hexdigest()
    status = (
        ExternalArtifactStatus.PRESENT_AND_VERIFIED
        if size == expected.size_bytes and observed_sha256 == expected.sha256
        else ExternalArtifactStatus.INVALID
    )
    return ExternalArtifactObservation(
        expected=expected,
        status=status,
        observed_size_bytes=size,
        observed_sha256=observed_sha256,
    )


def require_external_artifact(
    root: Path, expected: ExpectedExternalArtifact
) -> ExternalArtifactObservation:
    observation = observe_external_artifact(root, expected)
    if observation.status == ExternalArtifactStatus.NOT_AVAILABLE:
        raise ExternalArtifactUnavailable(expected)
    if observation.status == ExternalArtifactStatus.INVALID:
        raise OmivInputError(f"external artifact identity mismatch: {expected.relative_path}")
    return observation
