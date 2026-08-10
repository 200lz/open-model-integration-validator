import hashlib
from pathlib import Path

import pytest

from omiv.errors import OmivInputError
from omiv.external_artifacts import (
    ExpectedExternalArtifact,
    ExternalArtifactStatus,
    ExternalArtifactUnavailable,
    observe_external_artifact,
    require_external_artifact,
)


def _expected(payload: bytes) -> ExpectedExternalArtifact:
    return ExpectedExternalArtifact(
        relative_path="external/reviewed-fixture.bin",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def test_external_artifact_absence_retains_identity_without_observing_bytes(
    tmp_path: Path,
) -> None:
    expected = _expected(b"bounded synthetic fixture\n")
    observation = observe_external_artifact(tmp_path, expected)
    assert expected.identity_status == ExternalArtifactStatus.EXPECTED_IDENTITY_RECORDED
    assert observation.status == ExternalArtifactStatus.NOT_AVAILABLE
    assert observation.observed_size_bytes is None
    assert observation.observed_sha256 is None
    with pytest.raises(ExternalArtifactUnavailable, match=expected.relative_path):
        require_external_artifact(tmp_path, expected)


def test_external_artifact_present_mode_is_exact_and_fail_closed(tmp_path: Path) -> None:
    payload = b"bounded synthetic fixture\n"
    expected = _expected(payload)
    path = tmp_path / expected.relative_path
    path.parent.mkdir(parents=True)
    path.write_bytes(payload)
    verified = require_external_artifact(tmp_path, expected)
    assert verified.status == ExternalArtifactStatus.PRESENT_AND_VERIFIED
    assert verified.observed_size_bytes == expected.size_bytes
    assert verified.observed_sha256 == expected.sha256

    path.write_bytes(payload + b"tampered")
    invalid = observe_external_artifact(tmp_path, expected)
    assert invalid.status == ExternalArtifactStatus.INVALID
    with pytest.raises(OmivInputError, match="identity mismatch"):
        require_external_artifact(tmp_path, expected)
