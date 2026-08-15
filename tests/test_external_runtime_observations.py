"""Phase 7B.2 external runtime-observation ingestion tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import string
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.reference_preflight.operations import build_reference_preflight, load_profile
from omiv.runtime_compatibility.external_models import (
    ExternalObservationControl,
    ExternalOverallStatus,
    ExternalStatus,
    ManifestObservation,
)
from omiv.runtime_compatibility.external_operations import (
    _ABSOLUTE_POSIX_PATH_RE,
    _PATH_OPTIONS,
    _VALUE_OPTIONS,
    EXTERNAL_CREDENTIAL_FAMILY_PATTERNS,
    EXTERNAL_PRIVACY_POLICY_VERSION,
    _actual_files_fd,
    _parse_manifest,
    _reject_sensitive_text,
    import_external_observations,
    load_external_evidence,
)
from omiv.runtime_compatibility.models import PROFILE_ID

ROOT = Path(__file__).resolve().parents[1]
RUNNER = CliRunner()
EMPTY_SHA = hashlib.sha256(b"").hexdigest()
RUNTIME_SHA = "2" * 64
RUNTIME_COMMIT = "f8def7fe168bab245fbf15d3f18b26dbb1ef73c8"
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
CLASSIC_CREDENTIAL = "gh" + "p_" + "A" * 36
FINE_GRAINED_CREDENTIAL = "github" + "_pat_" + "A" * 40
PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"
OPENSSH_PRIVATE_KEY_MARKER = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"

# Values are assembled from inert fragments so repository content scanners do not
# mistake regression fixtures for usable credentials.
CREDENTIAL_SIGNATURE_CASES = (
    ("aws-access-key", "AK" + "IA" + "A" * 16, "aws_access_key"),
    ("aws-temporary-key", "AS" + "IA" + "B" * 16, "aws_access_key"),
    ("github-personal", "gh" + "p_" + "C" * 24, "github_token"),
    ("github-oauth", "gh" + "o_" + "D" * 24, "github_token"),
    ("github-user", "gh" + "u_" + "E" * 24, "github_token"),
    ("github-server", "gh" + "s_" + "F" * 24, "github_token"),
    ("github-refresh", "gh" + "r_" + "G" * 24, "github_token"),
    ("github-fine-grained", "github" + "_pat_" + "H" * 24, "github_token"),
    ("hugging-face", "h" + "f_" + "I" * 24, "hugging_face_token"),
    ("openai-style", "s" + "k-" + "J" * 24, "openai_style_token"),
    ("slack-bot", "xo" + "xb-" + "K" * 16, "slack_token"),
    ("slack-app", "xo" + "xa-" + "L" * 16, "slack_token"),
    ("slack-personal", "xo" + "xp-" + "M" * 16, "slack_token"),
    ("slack-refresh", "xo" + "xr-" + "N" * 16, "slack_token"),
    ("slack-session", "xo" + "xs-" + "P" * 16, "slack_token"),
    ("private-key", "-----BEGIN " + "RSA PRIVATE KEY-----", "private_key"),
    (
        "authorization-bearer",
        "Bearer " + "Q" * 24,
        "authorization_header",
    ),
    (
        "authorization-basic",
        "Authorization" + ": " + "Basic " + "R" * 24,
        "authorization_header",
    ),
    (
        "signed-url-field",
        "Signature" + "=" + "S" * 32,
        "signed_url_or_access_field",
    ),
    (
        "api-key-assignment",
        "api_" + "key=" + "T" * 24,
        "generic_credential_assignment",
    ),
    ("google-api-key", "AI" + "za" + "U" * 35, "google_api_key"),
    (
        "google-oauth-token",
        "ya" + "29." + "V" * 24,
        "google_oauth_credential",
    ),
    (
        "google-client-secret",
        "GOC" + "SPX-" + "W" * 24,
        "google_oauth_credential",
    ),
)

HYPHEN_PREFIXED_CREDENTIAL_CASES = (
    ("openai-style-hyphen-delimited", "note,-" + "s" + "k-" + "Y" * 24),
    ("slack-bot-hyphen-delimited", "note,-" + "xo" + "xb-" + "Z" * 16),
)
CREDENTIAL_ROUTE_CASES = (
    tuple((case, value) for case, value, _family in CREDENTIAL_SIGNATURE_CASES)
    + HYPHEN_PREFIXED_CREDENTIAL_CASES
)
PRINTABLE_ASCII_PUNCTUATION = tuple(string.punctuation)
REPRESENTATIVE_UNICODE_PUNCTUATION = (
    "–",
    "—",
    "…",
    "‘",
    "’",
    "“",
    "”",
    "•",
    "·",
    "،",
    "؛",
    "؟",
    "。",
    "，",
    "：",
    "；",
    "（",
    "）",
    "【",
    "】",
    "「",
    "」",
)
WORD_BOUNDED_CREDENTIAL_FAMILIES = {
    "aws_access_key",
    "github_token",
    "hugging_face_token",
    "openai_style_token",
    "slack_token",
    "google_api_key",
    "google_oauth_credential",
}
UNDERSCORE_TERMINATED_CREDENTIAL_FAMILIES = {
    "github_token",
    "openai_style_token",
    "google_oauth_credential",
}
LEFT_WORD_BOUNDED_CREDENTIAL_FAMILIES = {
    "authorization_header",
    "signed_url_or_access_field",
    "generic_credential_assignment",
}
RELEASE_AUDIT_CREDENTIAL_PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "hugging_face_token": re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    "openai_style_token": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
}


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _put(root: Path, path: str, raw: bytes | str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw.encode("utf-8") if isinstance(raw, str) else raw)


def _digest_record(raw: bytes, name: str) -> str:
    return f"{_digest(raw)}  /external/{name}\n"


def _attempt_files(
    root: Path,
    stem: str,
    argv: list[str],
    *,
    stdout: bytes,
    return_code: int,
    timed_out: bool = False,
    dflash: bool = False,
) -> dict[str, str]:
    stderr = b""
    cap = max(16, len(stdout) + 1)
    stdout_complete = return_code == 0 and not timed_out
    stdout_overflow = False
    paths = {
        "argv_member": f"evidence/{stem}.argv.json",
        "process_member": f"evidence/{stem}.process.txt",
        "environment_member": f"evidence/{stem}.environment.txt",
        "input_identities_member": f"evidence/{stem}.identities.txt",
        "stdout_member": f"evidence/{stem}.stdout.txt",
        "stderr_member": f"evidence/{stem}.stderr.txt",
        "stdout_digest_member": f"evidence/{stem}.stdout.sha256",
        "stderr_digest_member": f"evidence/{stem}.stderr.sha256",
        "telemetry_member": f"evidence/{stem}.telemetry.csv",
    }
    _put(root, paths["argv_member"], json.dumps(argv) + "\n")
    _put(
        root,
        paths["process_member"],
        f"exit_status={return_code}\n"
        f"timeout={'true' if timed_out else 'false'}\n"
        "elapsed_ms=10\n"
        "start_utc=2026-08-15T00:00:00.000000000Z\n"
        "end_utc=2026-08-15T00:00:00.010000000Z\n"
        f"stdout_bytes={len(stdout)}\n"
        f"stderr_bytes={len(stderr)}\n"
        f"stdout_complete={'true' if stdout_complete else 'false'}\n"
        f"stdout_overflow={'true' if stdout_overflow else 'false'}\n"
        "stderr_complete=true\n"
        "stderr_overflow=false\n",
    )
    _put(
        root,
        paths["environment_member"],
        "CUDA_VISIBLE_DEVICES=UNSET\nLANG=C.UTF-8\nLC_ALL=C.UTF-8\n"
        f"stdout_stderr_file_cap_bytes={cap}\n",
    )
    artifacts = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json").artifacts
    main = next(item for item in artifacts if item.role.value == "MAIN_MODEL")
    draft = next(item for item in artifacts if item.role.value == "DRAFTER")
    identities = (
        f"model_path=/external/{main.path}\nmodel_bytes={main.declared_size}\n"
        f"model_sha256={main.provider_identity}\nprojector_path=NONE\n"
        f"draft_path={'/external/' + draft.path if dflash else 'NONE'}\n"
    )
    if dflash:
        draft = next(item for item in artifacts if item.role.value == "DRAFTER")
        identities += (
            f"draft_bytes={draft.declared_size}\ndraft_sha256={draft.provider_identity}\n"
            "spec_type=draft-dflash\n"
        )
    identities += f"executable_sha256={RUNTIME_SHA}\n"
    _put(root, paths["input_identities_member"], identities)
    _put(root, paths["stdout_member"], stdout)
    _put(root, paths["stderr_member"], stderr)
    _put(root, paths["stdout_digest_member"], _digest_record(stdout, f"{stem}.stdout"))
    _put(root, paths["stderr_digest_member"], _digest_record(stderr, f"{stem}.stderr"))
    _put(
        root,
        paths["telemetry_member"],
        "2026/08/15 00:00:00.000, 0, Synthetic GPU, GPU-synthetic, 1 MiB, 32 MiB, 50 %, 0 %\n",
    )
    return paths


def _refresh_manifest(root: Path, control_raw: dict[str, object]) -> ExternalObservationControl:
    paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    manifest = "".join(f"{_digest((root / path).read_bytes())}  {path}\n" for path in paths)
    _put(root, "SHA256SUMS", manifest)
    control_raw["manifest_sha256"] = _digest(manifest.encode("utf-8"))
    return ExternalObservationControl.model_validate(control_raw)


def _fixture(tmp_path: Path) -> tuple[Path, dict[str, object], ExternalObservationControl]:
    root = tmp_path / "root"
    root.mkdir()
    profile = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json")
    reference = build_reference_preflight(profile, profile.canonical_reference)
    _put(
        root,
        "reference.json",
        json.dumps(reference.model_dump(mode="json", by_alias=True), sort_keys=True) + "\n",
    )
    _put(
        root,
        "source.txt",
        f"https://example.invalid/source.git\n{SOURCE_COMMIT}\n{SOURCE_COMMIT}\n"
        f"{SOURCE_TREE}\ntree {SOURCE_TREE}\n",
    )
    artifact_controls: list[dict[str, object]] = []
    for item in reference.future_runtime_plan.artifacts:
        member = f"evidence/{item.artifact_id}.txt"
        _put(
            root,
            member,
            f"{item.path}\nobserved_bytes={item.declared_size}\n"
            f"observed_sha256={item.provider_identity}\ntransfer_exit=0\n"
            "source_url=https://example.invalid/artifact\n",
        )
        artifact_controls.append(
            {
                "artifact_id": item.artifact_id,
                "role": item.role.value,
                "observation_member": member,
                "observation_format": "BARE_FILENAME_V1",
            }
        )
    _put(
        root,
        "evidence/build.txt",
        f"https://example.invalid/runtime.git\n{RUNTIME_COMMIT}\nb10353\n"
        "Cuda compilation tools, release 12.8, V12.8.93\n"
        "LLAMA_BUILD_UI:BOOL=OFF\nLLAMA_USE_PREBUILT_UI:BOOL=OFF\n"
        f"{RUNTIME_SHA}  /external/llama-cli\n",
    )
    _put(root, "evidence/version.txt", "version: 51 (f8def7f)\n")
    main = next(
        item for item in reference.future_runtime_plan.artifacts if item.role.value == "MAIN_MODEL"
    )
    draft = next(
        item for item in reference.future_runtime_plan.artifacts if item.role.value == "DRAFTER"
    )
    base_argv = [
        "/external/llama-cli",
        "--model",
        f"/external/{main.path}",
        "--prompt",
        reference.future_runtime_plan.text_probe,
        "--no-mmproj",
    ]
    initial = _attempt_files(
        root,
        "initial",
        base_argv,
        stdout=b"runner says PASS",
        return_code=153,
    )
    retry = _attempt_files(
        root,
        "retry",
        [*base_argv, "--single-turn"],
        stdout=b"runner says PASS",
        return_code=0,
    )
    _put(
        root,
        retry["environment_member"],
        (root / retry["environment_member"]).read_text()
        + "correction=added --single-turn per pinned executable help after preserved attempt "
        "hit stdout cap in auto-enabled conversation mode\n",
    )
    dflash_argv = [
        *base_argv,
        "--single-turn",
        "--spec-type",
        "draft-dflash",
        "--spec-draft-model",
        f"/external/{draft.path}",
    ]
    diagnostic = _attempt_files(
        root,
        "dflash",
        dflash_argv,
        stdout=b"diagnostic",
        return_code=0,
        dflash=True,
    )
    _put(
        root,
        "evidence/dflash-activation.txt",
        f"I loading draft model '/external/{draft.path}'\n"
        "I adding speculative implementation 'draft-dflash'\n"
        "I draft acceptance = 0.85185 ( 23 accepted / 27 generated)\n",
    )
    diagnostic["positive_activation_member"] = "evidence/dflash-activation.txt"
    _put(root, "evidence/warning.txt", "special_eot_id is not in special_eog_ids\n")
    control_raw: dict[str, object] = {
        "schema": "omiv.external-runtime-observation-control.v2",
        "capture_profile": "llama.cpp-cuda-capture.v1",
        "control_id": "synthetic-external-v1",
        "manifest_member": "SHA256SUMS",
        "manifest_sha256": "0" * 64,
        "complete_set": True,
        "max_files": 128,
        "max_member_bytes": 1024 * 1024,
        "max_total_bytes": 8 * 1024 * 1024,
        "reference_evidence_member": "reference.json",
        "plan_id": reference.future_runtime_plan.plan_id,
        "plan_digest": reference.future_runtime_plan.plan_digest,
        "profile_digest": reference.profile_digest,
        "image_fixture_bytes": 4246,
        "source_identity_member": "source.txt",
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "source_signature": "UNKNOWN",
        "artifacts": artifact_controls,
        "runtime": {
            "name": "llama.cpp",
            "build_identity_member": "evidence/build.txt",
            "version_member": "evidence/version.txt",
            "executable_sha256": RUNTIME_SHA,
            "version": "b10353",
            "runtime_commit": RUNTIME_COMMIT,
            "cuda_version": "12.8.93",
            "backend": "CUDA",
        },
        "attempts": [
            {
                "attempt_id": "initial",
                "kind": "TEXT",
                "disposition": "RETAINED_FAILED",
                **initial,
            },
            {
                "attempt_id": "retry",
                "kind": "TEXT",
                "disposition": "ACCEPTED",
                **retry,
                "supersedes": "initial",
                "retry_reason": "Auto-interactive capture overflow; add --single-turn.",
                "require_single_turn": True,
                "output_predicate": {
                    "kind": "CONTAINS_EXACT_UTF8",
                    "value": "runner says PASS",
                },
            },
            {
                "attempt_id": "dflash-diagnostic",
                "kind": "DIAGNOSTIC",
                "disposition": "DIAGNOSTIC",
                **diagnostic,
                "require_single_turn": True,
            },
        ],
        "findings": [
            {
                "code": "TOKENIZER_EOT_EOG_WARNING",
                "severity": "WARN",
                "member": "evidence/warning.txt",
                "exact_text": "special_eot_id is not in special_eog_ids",
                "detail": "Synthetic retained tokenizer warning.",
            }
        ],
        "skips": [
            {"target": "DFLASH_PNG", "reason": "Not run."},
            {"target": "OLLAMA", "reason": "Not run."},
        ],
    }
    control = _refresh_manifest(root, control_raw)
    return root, control_raw, control


def _rehash_evidence(value: dict[str, Any]) -> None:
    body = {
        key: item for key, item in value.items() if key not in {"evidence_id", "evidence_digest"}
    }
    digest = canonical_sha256({"domain": value["schema"], "body": body})
    value["evidence_id"] = f"external_runtime_observation_{digest[:32]}"
    value["evidence_digest"] = digest


def _make_retry_image_attempt(root: Path, raw: dict[str, object]) -> None:
    profile = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json")
    reference = build_reference_preflight(profile, profile.canonical_reference)
    plan = reference.future_runtime_plan
    main = next(item for item in plan.artifacts if item.role.value == "MAIN_MODEL")
    projector = next(item for item in plan.artifacts if item.role.value == "PERCEPTION_ENCODER")
    argv = [
        "/external/llama-cli",
        "--model",
        f"/external/{main.path}",
        "--mmproj",
        f"/external/{projector.path}",
        "--image",
        f"/external/{plan.image_fixture.rsplit('/', 1)[-1]}",
        "--prompt",
        plan.image_probe,
        "--single-turn",
    ]
    _put(root, "evidence/retry.argv.json", json.dumps(argv) + "\n")
    identities = (
        f"model_path=/external/{main.path}\n"
        f"model_bytes={main.declared_size}\n"
        f"model_sha256={main.provider_identity}\n"
        f"projector_path=/external/{projector.path}\n"
        f"projector_bytes={projector.declared_size}\n"
        f"projector_sha256={projector.provider_identity}\n"
        f"image_path=/external/{plan.image_fixture.rsplit('/', 1)[-1]}\n"
        "image_bytes=4246\n"
        f"image_sha256={plan.image_fixture_sha256}\n"
        "draft_path=NONE\n"
        f"executable_sha256={RUNTIME_SHA}\n"
    )
    _put(root, "evidence/retry.identities.txt", identities)
    attempts = raw["attempts"]
    assert (
        isinstance(attempts, list)
        and isinstance(attempts[1], dict)
        and isinstance(attempts[2], dict)
    )
    attempts[1]["kind"] = "IMAGE"


def test_valid_import_is_deterministic_offline_and_self_reports_never_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _raw, control = _fixture(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external importer must not execute or use the network")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    evidence1 = import_external_observations(control, root)
    evidence2 = import_external_observations(control, root)
    assert evidence1 == evidence2
    assert evidence1.evidence_digest == evidence2.evidence_digest
    assert evidence1.projection.overall_status == ExternalOverallStatus.PARTIAL
    assert all(item.status == ExternalStatus.UNKNOWN for item in evidence1.projection.stages)
    assert evidence1.projection.attempts[0].process_status == ExternalStatus.INCOMPLETE
    assert evidence1.projection.attempts[1].process_status == ExternalStatus.PASS
    assert evidence1.projection.attempts[1].output_predicate_status == ExternalStatus.OBSERVED
    assert evidence1.projection.attempts[1].supersedes == "initial"
    assert evidence1.projection.attempts[2].dflash_activation is not None
    assert evidence1.projection.attempts[2].dflash_activation.accepted_draft_tokens == 23
    assert [item.target for item in evidence1.projection.skips] == ["DFLASH_PNG", "OLLAMA"]
    assert all(
        item.status == ExternalStatus.MATCHED_PLAN_OBSERVATION for item in evidence1.artifacts
    )
    assert all(not item.payload_verified for item in evidence1.artifacts)
    serialized = json.dumps(evidence1.model_dump(mode="json", by_alias=True))
    assert "Synthetic GPU" not in serialized
    assert "GPU-synthetic" not in serialized
    assert PROFILE_ID == "omiv.runtime-compatibility-profile.llama-cpp-native-output.v1"
    source = (ROOT / "src/omiv/runtime_compatibility/external_operations.py").read_text(
        encoding="utf-8"
    )
    for forbidden in ("subprocess.", "socket.", "urllib.", "requests.", "shell=True"):
        assert forbidden not in source


def test_cli_import_verify_exit_codes_and_help(tmp_path: Path) -> None:
    root, raw, control = _fixture(tmp_path)
    control_path = tmp_path / "control.json"
    control_path.write_text(json.dumps(control.model_dump(mode="json", by_alias=True)))
    output1 = tmp_path / "one.json"
    output2 = tmp_path / "two.json"
    command = [
        "runtime-compat",
        "import-external",
        "--control",
        str(control_path),
        "--manifest-root",
        str(root),
    ]
    first = RUNNER.invoke(app, [*command, "--output", str(output1)])
    second = RUNNER.invoke(app, [*command, "--output", str(output2)])
    assert first.exit_code == second.exit_code == 1
    assert output1.read_bytes() == output2.read_bytes()
    verified = RUNNER.invoke(app, ["runtime-compat", "verify-external", "--evidence", str(output1)])
    assert verified.exit_code == 1
    assert "LOAD       UNKNOWN" in verified.stdout
    assert "--single-turn" in verified.stdout
    help_result = RUNNER.invoke(app, ["runtime-compat", "--help"])
    assert help_result.exit_code == 0
    assert "import-external" in help_result.stdout and "verify-external" in help_result.stdout
    unsafe_output = RUNNER.invoke(app, [*command, "--output", str(root / "would-be-extra.json")])
    assert unsafe_output.exit_code == 2
    assert not (root / "would-be-extra.json").exists()
    raw["profile_digest"] = "f" * 64
    control_path.write_text(json.dumps(raw))
    malformed = RUNNER.invoke(app, [*command, "--output", str(tmp_path / "bad.json")])
    assert malformed.exit_code == 2


@pytest.mark.parametrize(
    "manifest",
    [
        "0" * 64 + "  source.txt\n" + "1" * 64 + "  source.txt\n",
        "not-a-manifest\n",
        "0" * 64 + "  ../escape\n",
        "0" * 64 + "  /absolute\n",
    ],
)
def test_duplicate_malformed_and_unsafe_manifest_entries(tmp_path: Path, manifest: str) -> None:
    root, raw, _control = _fixture(tmp_path)
    _put(root, "SHA256SUMS", manifest)
    raw["manifest_sha256"] = _digest(manifest.encode())
    control = ExternalObservationControl.model_validate(raw)
    with pytest.raises(OmivInputError, match="manifest|unsafe"):
        import_external_observations(control, root)


def test_manifest_digest_missing_extra_symlink_nonregular_and_tamper(tmp_path: Path) -> None:
    root, _raw, control = _fixture(tmp_path)
    bad_digest = control.model_copy(update={"manifest_sha256": "f" * 64})
    with pytest.raises(OmivInputError, match="manifest digest mismatch"):
        import_external_observations(bad_digest, root)
    (root / "evidence/warning.txt").unlink()
    with pytest.raises(OmivInputError, match="complete-set mismatch"):
        import_external_observations(control, root)
    _put(root, "evidence/warning.txt", "special_eot_id is not in special_eog_ids\n")
    _put(root, "extra.txt", "extra")
    with pytest.raises(OmivInputError, match="complete-set mismatch"):
        import_external_observations(control, root)
    (root / "extra.txt").unlink()
    target = root / "evidence/warning.txt"
    target.unlink()
    target.symlink_to("version.txt")
    with pytest.raises(OmivInputError, match="symlink"):
        import_external_observations(control, root)
    target.unlink()
    target.mkdir()
    with pytest.raises(OmivInputError, match="complete-set mismatch"):
        import_external_observations(control, root)
    target.rmdir()
    os.mkfifo(target)
    with pytest.raises(OmivInputError, match="nonregular"):
        import_external_observations(control, root)
    target.unlink()
    _put(root, "evidence/warning.txt", "tampered\n")
    with pytest.raises(OmivInputError, match="digest mismatch"):
        import_external_observations(control, root)


@pytest.mark.parametrize("field", ["plan_id", "plan_digest", "profile_digest"])
def test_plan_and_profile_mismatch(tmp_path: Path, field: str) -> None:
    root, _raw, control = _fixture(tmp_path)
    replacement = "f" * (64 if field != "plan_id" else 40)
    changed = control.model_copy(update={field: replacement})
    with pytest.raises(OmivInputError, match="plan id/digest/profile"):
        import_external_observations(changed, root)


def test_artifact_runtime_argv_process_stream_and_telemetry_fail_closed(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    cases = [
        ("evidence/main-q4-k-m.txt", "observed_bytes=16756683904", "observed_bytes=1"),
        ("evidence/build.txt", RUNTIME_SHA, "f" * 64),
        ("evidence/retry.argv.json", '"--single-turn"', '"--not-single-turn"'),
        ("evidence/retry.stdout.sha256", None, "f" * 64 + "  /external/retry.stdout\n"),
        ("evidence/retry.telemetry.csv", None, "malformed\n"),
        (
            "evidence/retry.telemetry.csv",
            "2026/08/15 00:00:00.000",
            "2026/08/15 00:01:00.000",
        ),
        ("evidence/dflash-activation.txt", "draft-dflash", "draft-other"),
    ]
    for path, old, new in cases:
        current = (root / path).read_text()
        (root / path).write_text(new if old is None else current.replace(old, new))
        control = _refresh_manifest(root, raw)
        with pytest.raises(OmivInputError):
            import_external_observations(control, root)
        (root / path).write_text(current)

    process_path = root / "evidence/retry.process.txt"
    current = process_path.read_text()
    process_path.write_text(current.replace("exit_status=0", "exit_status=7"))
    failed = import_external_observations(_refresh_manifest(root, raw), root)
    assert failed.projection.attempts[1].process_status == ExternalStatus.FAIL
    process_path.write_text(current)

    (root / "evidence/retry.telemetry.csv").unlink()
    with pytest.raises(OmivInputError, match="unlisted evidence members"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_oversized_member_and_invalid_utf8_fail_closed(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    _put(root, "evidence/warning.txt", b"x" * (1024 * 1024 + 1))
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError, match="exceeds byte limit"):
        import_external_observations(control, root)
    _put(root, "evidence/warning.txt", b"\xff")
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError, match="not UTF-8"):
        import_external_observations(control, root)


def test_rehashed_incoherent_nested_projections_are_rejected(tmp_path: Path) -> None:
    root, _raw, control = _fixture(tmp_path)
    evidence = import_external_observations(control, root)
    value = evidence.model_dump(mode="json", by_alias=True)
    value["projection"]["stages"][0]["status"] = "PASS"
    body = {
        key: item for key, item in value.items() if key not in {"evidence_id", "evidence_digest"}
    }
    digest = canonical_sha256({"domain": value["schema"], "body": body})
    value["evidence_id"] = f"external_runtime_observation_{digest[:32]}"
    value["evidence_digest"] = digest
    path = tmp_path / "incoherent.json"
    path.write_text(json.dumps(value))
    with pytest.raises(OmivInputError):
        load_external_evidence(path)


def test_reported_artifact_digest_prose_never_verifies_payload(tmp_path: Path) -> None:
    root, _raw, control = _fixture(tmp_path)
    evidence = import_external_observations(control, root)
    assert {item.status for item in evidence.artifacts} == {ExternalStatus.MATCHED_PLAN_OBSERVATION}
    assert all(
        item.payload_source is None and not item.payload_verified for item in evidence.artifacts
    )
    serialized = json.dumps(evidence.model_dump(mode="json", by_alias=True))
    assert "A matched artifact report does not verify artifact payload bytes." in serialized


@pytest.mark.parametrize("equals_form", [False, True])
@pytest.mark.parametrize("role", ["model", "projector", "image", "draft", "executable"])
def test_argv_and_typed_inputs_bind_every_exact_role(
    tmp_path: Path, role: str, equals_form: bool
) -> None:
    root, raw, _control = _fixture(tmp_path)
    if role in {"projector", "image"}:
        _make_retry_image_attempt(root, raw)
        stem = "retry"
    elif role == "draft":
        stem = "dflash"
    else:
        stem = "retry"
    argv_path = root / f"evidence/{stem}.argv.json"
    identities_path = root / f"evidence/{stem}.identities.txt"
    argv = json.loads(argv_path.read_text())
    identities = identities_path.read_text()
    option_by_role = {
        "model": "--model",
        "projector": "--mmproj",
        "image": "--image",
        "draft": "--spec-draft-model",
    }
    if role == "executable":
        argv[0] = "/external/not-llama-cli"
    else:
        option = option_by_role[role]
        index = argv.index(option)
        original = argv[index + 1]
        replacement = original.rsplit("/", 1)[0] + "/different-input.bin"
        argv[index : index + 2] = (
            [f"{option}={replacement}"] if equals_form else [option, replacement]
        )
        identity_key = {
            "model": "model_path",
            "projector": "projector_path",
            "image": "image_path",
            "draft": "draft_path",
        }[role]
        identities = identities.replace(
            f"{identity_key}={original}", f"{identity_key}={replacement}"
        )
    argv_path.write_text(json.dumps(argv) + "\n")
    identities_path.write_text(identities)
    with pytest.raises(OmivInputError, match="identity|match|path|executable"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_equals_form_is_bound_then_normalized_without_host_paths(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    argv_path = root / "evidence/retry.argv.json"
    argv = json.loads(argv_path.read_text())
    index = argv.index("--model")
    argv[index : index + 2] = [f"--model={argv[index + 1]}"]
    argv_path.write_text(json.dumps(argv) + "\n")
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    normalized = evidence.projection.attempts[1].argv
    assert "--model" in normalized
    assert normalized[normalized.index("--model") + 1] == "{artifact:main-q4-k-m}"
    assert "/external/" not in json.dumps(evidence.model_dump(mode="json", by_alias=True))


def test_missing_projector_and_extra_role_inputs_fail_closed(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    _make_retry_image_attempt(root, raw)
    identities_path = root / "evidence/retry.identities.txt"
    original = identities_path.read_text()
    identities_path.write_text(
        original.replace("projector_path=/external/", "projector_path=NONE\nignored=/external/")
    )
    with pytest.raises(OmivInputError, match="missing or extra|projector"):
        import_external_observations(_refresh_manifest(root, raw), root)
    identities_path.write_text(original + "unexpected_role_path=/external/extra.gguf\n")
    with pytest.raises(OmivInputError, match="missing or extra"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_fixed_image_size_and_digest_are_bound_to_control_and_plan(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    _make_retry_image_attempt(root, raw)
    identities_path = root / "evidence/retry.identities.txt"
    original = identities_path.read_text()
    for old, new in (
        ("image_bytes=4246", "image_bytes=1"),
        ("image_sha256=", "image_sha256=" + "f" * 64 + "#"),
    ):
        identities_path.write_text(original.replace(old, new, 1))
        with pytest.raises(OmivInputError, match="image identity|missing or extra"):
            import_external_observations(_refresh_manifest(root, raw), root)
    identities_path.write_text(original)


@pytest.mark.parametrize(
    "prefix",
    [r"C:\\Users\\alice\\models\\", r"\\\\server\\share\\models\\"],
)
def test_windows_paths_are_exactly_bound_then_removed_from_evidence(
    tmp_path: Path, prefix: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    profile = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json")
    main = next(item for item in profile.artifacts if item.role.value == "MAIN_MODEL")
    original = f"/external/{main.path}"
    replacement = prefix + main.path
    argv_path = root / "evidence/retry.argv.json"
    argv = json.loads(argv_path.read_text())
    argv[argv.index("--model") + 1] = replacement
    argv_path.write_text(json.dumps(argv) + "\n")
    identities_path = root / "evidence/retry.identities.txt"
    identities_path.write_text(identities_path.read_text().replace(original, replacement))
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    serialized = json.dumps(evidence.model_dump(mode="json", by_alias=True))
    assert prefix not in serialized
    assert replacement not in serialized


@pytest.mark.parametrize("replacement", ["../model.gguf", "https://internal/model.gguf"])
def test_traversal_and_endpoint_paths_fail_before_normalization(
    tmp_path: Path, replacement: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    profile = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json")
    main = next(item for item in profile.artifacts if item.role.value == "MAIN_MODEL")
    original = f"/external/{main.path}"
    argv_path = root / "evidence/retry.argv.json"
    argv = json.loads(argv_path.read_text())
    argv[argv.index("--model") + 1] = replacement
    argv_path.write_text(json.dumps(argv) + "\n")
    identities_path = root / "evidence/retry.identities.txt"
    identities_path.write_text(identities_path.read_text().replace(original, replacement))
    with pytest.raises(OmivInputError, match="unsafe|identity"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_duplicate_roles_and_attempts_are_rejected(tmp_path: Path) -> None:
    _root, raw, _control = _fixture(tmp_path)
    artifacts = raw["artifacts"]
    attempts = raw["attempts"]
    assert isinstance(artifacts, list) and isinstance(artifacts[1], dict)
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    artifacts[1]["role"] = "MAIN_MODEL"
    with pytest.raises(ValidationError, match="unique roles"):
        ExternalObservationControl.model_validate(raw)
    artifacts[1]["role"] = "PERCEPTION_ENCODER"
    attempts[1]["attempt_id"] = "initial"
    with pytest.raises(ValidationError, match="attempt controls must be unique"):
        ExternalObservationControl.model_validate(raw)


@pytest.mark.parametrize(
    ("target", "injected"),
    [
        ("environment", "AWS_SECRET_ACCESS_KEY=do-not-serialize\n"),
        ("environment", "HOME=/home/alice\n"),
        ("argv", "--endpoint=https://internal.invalid/credential"),
        ("argv", "--model=../../private/model.gguf"),
        ("argv", r"--model=C:\\Users\\alice\\private.gguf"),
        ("argv", r"--model=\\\\server\\share\\private.gguf"),
    ],
)
def test_private_environment_and_argv_are_rejected_without_echo(
    tmp_path: Path, target: str, injected: str
) -> None:
    root, raw, control = _fixture(tmp_path)
    control_path = tmp_path / "control.json"
    output = tmp_path / "out.json"
    if target == "environment":
        path = root / "evidence/retry.environment.txt"
        path.write_text(path.read_text() + injected)
    else:
        path = root / "evidence/retry.argv.json"
        argv = json.loads(path.read_text())
        argv.append(injected)
        path.write_text(json.dumps(argv) + "\n")
    control = _refresh_manifest(root, raw)
    control_path.write_text(json.dumps(control.model_dump(mode="json", by_alias=True)))
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert not output.exists()
    private_fragment = injected.split("=", 1)[-1].strip()
    assert private_fragment not in result.stdout
    assert "Traceback" not in result.stdout


def test_finding_text_privacy_rejected_without_secret_echo(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    findings = raw["findings"]
    assert isinstance(findings, list) and isinstance(findings[0], dict)
    secret = "AWS_SECRET_ACCESS_KEY=do-not-serialize"
    findings[0]["detail"] = secret
    control_path = tmp_path / "control.json"
    control_path.write_text(json.dumps(raw))
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 2
    assert secret not in result.stdout
    assert "Traceback" not in result.stdout


def test_descriptor_relative_open_rejects_swap_to_outside_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _raw, control = _fixture(tmp_path)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("outside bytes must not be consumed")
    target = root / "evidence/warning.txt"
    original_open = os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str], flags: int, *args: Any, **kwargs: Any
    ) -> int:
        nonlocal swapped
        if path == "warning.txt" and not swapped:
            swapped = True
            target.unlink()
            target.symlink_to(outside)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("omiv.runtime_compatibility.external_operations.os.open", swapping_open)
    with pytest.raises(OmivInputError, match="safely read|symlink|identity"):
        import_external_observations(control, root)
    assert swapped


def test_manifest_portable_collisions_rejected_in_input_and_offline_projection() -> None:
    first = "0" * 64
    second = "1" * 64
    for paths in (("A.txt", "a.txt"), ("file", "file/child")):
        raw = "".join(
            f"{digest}  {path}\n" for digest, path in zip((first, second), paths, strict=True)
        )
        with pytest.raises(OmivInputError, match="colliding|prefix"):
            _parse_manifest(raw.encode(), 10)
        members = [
            {"path": path, "size": 1, "sha256": digest}
            for path, digest in zip(paths, (first, second), strict=True)
        ]
        with pytest.raises(ValidationError, match="colliding|prefix"):
            ManifestObservation.model_validate(
                {
                    "manifest_sha256": first,
                    "member_count": 2,
                    "total_bytes": 2,
                    "members": members,
                }
            )


def test_scandir_entry_bound_stops_during_iteration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yielded = 0

    class FakeEntry:
        def __init__(self, name: str) -> None:
            self.name = name

        def stat(self, *, follow_symlinks: bool) -> os.stat_result:
            del follow_symlinks
            values = [stat.S_IFREG | 0o600, 1, 1, 1, 0, 0, 0, 0, 0, 0]
            return os.stat_result(values)

    class FakeScandir:
        def __enter__(self) -> FakeScandir:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> FakeScandir:
            return self

        def __next__(self) -> FakeEntry:
            nonlocal yielded
            yielded += 1
            return FakeEntry(f"entry-{yielded}.txt")

    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        monkeypatch.setattr(
            "omiv.runtime_compatibility.external_operations.os.scandir",
            lambda _descriptor: FakeScandir(),
        )
        with pytest.raises(OmivInputError, match="bounded entry count"):
            _actual_files_fd(root_fd, 1)
    finally:
        os.close(root_fd)
    assert yielded == 69


def test_capture_completeness_and_time_coherence(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    process_path = root / "evidence/retry.process.txt"
    original = process_path.read_text()
    cases = [
        ("end_utc=2026-08-15T00:00:00.010000000Z", "end_utc=2026-08-14T23:59:59.000000000Z"),
        ("elapsed_ms=10", "elapsed_ms=999"),
        ("start_utc=2026-08-15T00:00:00.000000000Z", "start_utc=malformed"),
    ]
    for old, new in cases:
        process_path.write_text(original.replace(old, new))
        with pytest.raises(OmivInputError, match="timestamp|duration|precedes"):
            import_external_observations(_refresh_manifest(root, raw), root)
    without_facts = (
        "\n".join(
            line
            for line in original.splitlines()
            if not line.startswith(
                ("stdout_complete=", "stdout_overflow=", "stderr_complete=", "stderr_overflow=")
            )
        )
        + "\n"
    )
    process_path.write_text(without_facts)
    incomplete = import_external_observations(_refresh_manifest(root, raw), root)
    assert incomplete.projection.attempts[1].return_code == 0
    assert incomplete.projection.attempts[1].process_status == ExternalStatus.INCOMPLETE
    process_path.write_text(original)
    environment = root / "evidence/retry.environment.txt"
    environment.write_text(
        environment.read_text().replace("file_cap_bytes=17", "file_cap_bytes=16")
    )
    with pytest.raises(OmivInputError, match="completeness facts"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_capture_profile_contract_and_cli_exit_two(tmp_path: Path) -> None:
    root, raw, control = _fixture(tmp_path)
    assert control.capture_profile == "llama.cpp-cuda-capture.v1"
    control_path = tmp_path / "unsupported.json"
    raw["capture_profile"] = "other-runtime-capture.v1"
    control_path.write_text(json.dumps(raw))
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 2
    assert "Traceback" not in result.stdout


@pytest.mark.parametrize(
    "telemetry",
    [
        '"' + ("x" * 200_000) + '"\n',
        "2026/08/15 00:00:00.000, 0, name\n",
        "2026/08/15 00:00:00.000, 0, Synthetic GPU, id, bad, 32 MiB, 50 %, 0 %\n",
    ],
)
def test_malformed_telemetry_cli_exit_two_without_traceback(tmp_path: Path, telemetry: str) -> None:
    root, raw, _control = _fixture(tmp_path)
    _put(root, "evidence/retry.telemetry.csv", telemetry)
    control = _refresh_manifest(root, raw)
    control_path = tmp_path / "control.json"
    control_path.write_text(json.dumps(control.model_dump(mode="json", by_alias=True)))
    output = tmp_path / "out.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert not output.exists()
    assert "Traceback" not in result.stdout


def test_offline_verifier_rederives_every_projection_class(tmp_path: Path) -> None:
    root, _raw, control = _fixture(tmp_path)
    evidence = import_external_observations(control, root)
    base = evidence.model_dump(mode="json", by_alias=True)
    mutators: list[Callable[[dict[str, Any]], None]] = [
        lambda value: value["projection"]["attempts"][1]["argv"].append("--log-prefix"),
        lambda value: value["projection"]["attempts"][1]["environment"].update(
            {"stream_cap_bytes": 99}
        ),
        lambda value: value["projection"]["attempts"][1].update({"return_code": 9}),
        lambda value: value["projection"]["attempts"][1]["stdout"].update({"captured_bytes": 1}),
        lambda value: value["projection"]["attempts"][1]["stdout"].update({"sha256": "f" * 64}),
        lambda value: value["projection"]["attempts"][1]["telemetry"].update({"sample_count": 9}),
        lambda value: value["projection"]["attempts"][1].update(
            {"output_predicate_status": "UNKNOWN"}
        ),
        lambda value: value["projection"]["attempts"][1].update({"supersedes": None}),
        lambda value: value["projection"]["findings"][0].update({"detail": "changed"}),
        lambda value: value["projection"]["skips"][0].update({"reason": "changed"}),
        lambda value: value["projection"]["stages"][0].update({"status": "PASS"}),
        lambda value: value["projection"]["unknowns"].append("invented"),
        lambda value: value["projection"].update({"overall_status": "NOT_VERIFIED"}),
        lambda value: value["projection"].update({"observation_set_digest": "f" * 64}),
        lambda value: value["artifacts"][0].update({"status": "VERIFIED"}),
        lambda value: value["runtime"].update({"version": "changed"}),
        lambda value: value["source_identity"].update({"commit": "f" * 40}),
        lambda value: value["source_record"]["attempts"][2]["dflash_activation"].update(
            {"draft_artifact_sha256": "f" * 64}
        ),
        lambda value: value["source_record"]["attempts"][2]["dflash_activation"].update(
            {"accepted_draft_tokens": 28, "generated_draft_tokens": 27}
        ),
        lambda value: value["source_record"]["attempts"][1]["telemetry_samples"][0].update(
            {"memory_used_mib": 31}
        ),
        lambda value: value["source_record"]["attempts"][1]["predicate"].update(
            {"occurrence_count": 0}
        ),
    ]
    for index, mutate in enumerate(mutators):
        value = json.loads(json.dumps(base))
        mutate(value)
        _rehash_evidence(value)
        path = tmp_path / f"incoherent-{index}.json"
        path.write_text(json.dumps(value))
        with pytest.raises(OmivInputError):
            load_external_evidence(path)


def test_complete_text_and_fixed_png_predicates_are_observed_never_pass(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    _make_retry_image_attempt(root, raw)
    stdout = b"The image shows a red square."
    _put(root, "evidence/retry.stdout.txt", stdout)
    _put(root, "evidence/retry.stdout.sha256", _digest_record(stdout, "retry.stdout"))
    process = root / "evidence/retry.process.txt"
    process.write_text(
        process.read_text().replace("stdout_bytes=16", f"stdout_bytes={len(stdout)}")
    )
    environment = root / "evidence/retry.environment.txt"
    environment.write_text(
        environment.read_text().replace(
            "stdout_stderr_file_cap_bytes=17", "stdout_stderr_file_cap_bytes=64"
        )
    )
    attempts = raw["attempts"]
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    attempts[1]["output_predicate"] = {
        "kind": "CONTAINS_EXACT_UTF8",
        "value": "The image shows a red square.",
    }
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    image = evidence.projection.attempts[1]
    assert image.process_status == ExternalStatus.PASS
    assert image.output_predicate_status == ExternalStatus.OBSERVED
    assert ExternalStatus.PASS not in {
        item.output_predicate_status for item in evidence.projection.attempts
    }


def test_incomplete_predicate_does_not_upgrade_and_rehashed_pass_is_rejected(
    tmp_path: Path,
) -> None:
    root, raw, _control = _fixture(tmp_path)
    process = root / "evidence/retry.process.txt"
    process.write_text(
        "\n".join(
            line
            for line in process.read_text().splitlines()
            if not line.startswith(
                ("stdout_complete=", "stdout_overflow=", "stderr_complete=", "stderr_overflow=")
            )
        )
        + "\n"
    )
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    attempt = evidence.projection.attempts[1]
    assert attempt.process_status == ExternalStatus.INCOMPLETE
    assert attempt.output_predicate_status == ExternalStatus.OBSERVED
    value = evidence.model_dump(mode="json", by_alias=True)
    value["projection"]["attempts"][1]["output_predicate_status"] = "PASS"
    _rehash_evidence(value)
    path = tmp_path / "predicate-pass.json"
    path.write_text(json.dumps(value))
    with pytest.raises(OmivInputError):
        load_external_evidence(path)


def test_retry_control_and_argv_cannot_be_downgraded_together(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    attempts[1]["require_single_turn"] = False
    argv_path = root / "evidence/retry.argv.json"
    argv = json.loads(argv_path.read_text())
    argv.remove("--single-turn")
    argv_path.write_text(json.dumps(argv) + "\n")
    with pytest.raises(ValidationError, match="must require single-turn"):
        _refresh_manifest(root, raw)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("source", "retained failed"),
        ("superseder", "must be accepted"),
        ("missing", "must follow"),
        ("forward", "must follow"),
    ],
)
def test_retry_disposition_and_target_invariants(
    tmp_path: Path, mutation: str, message: str
) -> None:
    _root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list)
    assert isinstance(attempts[0], dict) and isinstance(attempts[1], dict)
    if mutation == "source":
        attempts[0]["disposition"] = "ACCEPTED"
    elif mutation == "superseder":
        attempts[1]["disposition"] = "RETAINED_FAILED"
    elif mutation == "missing":
        attempts[1]["supersedes"] = "missing-attempt"
    else:
        attempts[1]["supersedes"] = "dflash-diagnostic"
    with pytest.raises(ValidationError, match=message):
        ExternalObservationControl.model_validate(raw)


@pytest.mark.parametrize("correction", [None, "correction=untyped prose\n"])
def test_retry_requires_exact_typed_correction_evidence(
    tmp_path: Path, correction: str | None
) -> None:
    root, raw, _control = _fixture(tmp_path)
    path = root / "evidence/retry.environment.txt"
    lines = [line for line in path.read_text().splitlines() if not line.startswith("correction=")]
    path.write_text("\n".join(lines) + "\n" + (correction or ""))
    with pytest.raises(OmivInputError, match="correction"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_non_retry_cannot_carry_correction_evidence(tmp_path: Path) -> None:
    root, raw, _control = _fixture(tmp_path)
    path = root / "evidence/initial.environment.txt"
    path.write_text(
        path.read_text()
        + "correction="
        + (
            "added --single-turn per pinned executable help after preserved attempt hit stdout cap "
            "in auto-enabled conversation mode\n"
        )
    )
    with pytest.raises(OmivInputError, match="correction"):
        import_external_observations(_refresh_manifest(root, raw), root)


@pytest.mark.parametrize("mutation", ["argv", "target"])
def test_offline_retry_incoherence_rejected_after_rehash(tmp_path: Path, mutation: str) -> None:
    root, _raw, control = _fixture(tmp_path)
    value = import_external_observations(control, root).model_dump(mode="json", by_alias=True)
    if mutation == "argv":
        value["source_record"]["attempts"][1]["argv"].remove("--single-turn")
    else:
        value["source_record"]["attempts"][1]["environment"]["correction_target"] = "initial-x"
    _rehash_evidence(value)
    path = tmp_path / f"offline-retry-{mutation}.json"
    path.write_text(json.dumps(value))
    with pytest.raises(OmivInputError):
        load_external_evidence(path)


@pytest.mark.parametrize(
    "mutation",
    ["max_files", "max_member", "manifest_member", "max_total", "count", "total"],
)
def test_offline_manifest_limits_and_relationships_reject_rehashed_objects(
    tmp_path: Path, mutation: str
) -> None:
    root, _raw, control = _fixture(tmp_path)
    value = import_external_observations(control, root).model_dump(mode="json", by_alias=True)
    members = value["manifest"]["members"]
    if mutation == "max_files":
        value["control"]["max_files"] = len(members) - 1
    elif mutation == "max_member":
        value["control"]["max_member_bytes"] = max(item["size"] for item in members) - 1
    elif mutation == "manifest_member":
        canonical_manifest_size = sum(66 + len(item["path"].encode("ascii")) for item in members)
        value["control"]["max_member_bytes"] = canonical_manifest_size - 1
    elif mutation == "max_total":
        value["control"]["max_total_bytes"] = value["manifest"]["total_bytes"] - 1
    elif mutation == "count":
        value["manifest"]["member_count"] += 1
    else:
        value["manifest"]["total_bytes"] += 1
    _rehash_evidence(value)
    path = tmp_path / f"offline-limit-{mutation}.json"
    path.write_text(json.dumps(value))
    with pytest.raises(OmivInputError):
        load_external_evidence(path)


@pytest.mark.parametrize(
    "member_key",
    [
        "telemetry_member",
        "stdout_member",
        "argv_member",
        "process_member",
        "environment_member",
        "input_identities_member",
    ],
)
def test_attempt_owned_members_cannot_be_reused(tmp_path: Path, member_key: str) -> None:
    _root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list)
    assert isinstance(attempts[0], dict) and isinstance(attempts[1], dict)
    attempts[1][member_key] = attempts[0][member_key]
    with pytest.raises(ValidationError, match="reused across attempts"):
        ExternalObservationControl.model_validate(raw)


def test_predicate_and_dflash_sources_have_exclusive_attempt_ownership(tmp_path: Path) -> None:
    _root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list)
    assert isinstance(attempts[1], dict) and isinstance(attempts[2], dict)
    attempts[2]["positive_activation_member"] = attempts[1]["stdout_member"]
    with pytest.raises(ValidationError, match="reused across attempts"):
        ExternalObservationControl.model_validate(raw)


def test_offline_rehashed_attempt_ownership_reuse_is_rejected(tmp_path: Path) -> None:
    root, _raw, control = _fixture(tmp_path)
    value = import_external_observations(control, root).model_dump(mode="json", by_alias=True)
    value["control"]["attempts"][1]["telemetry_member"] = value["control"]["attempts"][0][
        "telemetry_member"
    ]
    _rehash_evidence(value)
    path = tmp_path / "offline-duplicate-owner.json"
    path.write_text(json.dumps(value))
    with pytest.raises(OmivInputError):
        load_external_evidence(path)


def test_unused_large_member_is_hashed_but_never_retained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, raw, _control = _fixture(tmp_path)
    raw["max_member_bytes"] = 4 * 1024 * 1024
    raw["max_total_bytes"] = 16 * 1024 * 1024
    _put(root, "unused-large.bin", b"u" * (3 * 1024 * 1024))
    control = _refresh_manifest(root, raw)
    import omiv.runtime_compatibility.external_operations as operations

    original_read = operations._read_regular_at
    retained_paths: list[str] = []

    def recording_read(root_fd: int, portable: str, limit: int, label: str) -> bytes:
        retained_paths.append(portable)
        return original_read(root_fd, portable, limit, label)

    monkeypatch.setattr(operations, "_read_regular_at", recording_read)
    evidence = import_external_observations(control, root)
    assert any(item.path == "unused-large.bin" for item in evidence.manifest.members)
    assert "unused-large.bin" not in retained_paths
    assert "raw_by_path" not in Path(operations.__file__).read_text()


def test_manifest_iteration_reads_fixed_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, raw, _control = _fixture(tmp_path)
    raw["max_member_bytes"] = 4 * 1024 * 1024
    raw["max_total_bytes"] = 16 * 1024 * 1024
    _put(root, "unused-large.bin", b"u" * (3 * 1024 * 1024))
    control = _refresh_manifest(root, raw)
    original_read = os.read
    requested: list[int] = []

    def bounded_read(fd: int, size: int) -> bytes:
        requested.append(size)
        return original_read(fd, size)

    monkeypatch.setattr("omiv.runtime_compatibility.external_operations.os.read", bounded_read)
    import_external_observations(control, root)
    assert requested and max(requested) == 64 * 1024


def test_telemetry_is_not_decoded_as_a_whole_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _raw, control = _fixture(tmp_path)
    import omiv.runtime_compatibility.external_operations as operations

    original_text = operations._text

    def reject_telemetry(raw: bytes, member: str) -> str:
        if member.endswith("telemetry.csv"):
            raise AssertionError("telemetry must not use the whole-file text decoder")
        return original_text(raw, member)

    monkeypatch.setattr(operations, "_text", reject_telemetry)
    import_external_observations(control, root)


@pytest.mark.parametrize("role", ["stdout", "telemetry"])
def test_role_specific_caps_reject_oversized_selected_evidence(tmp_path: Path, role: str) -> None:
    root, raw, _control = _fixture(tmp_path)
    raw["max_member_bytes"] = 4 * 1024 * 1024
    raw["max_total_bytes"] = 16 * 1024 * 1024
    if role == "stdout":
        payload = b"x" * (2 * 1024 * 1024 + 1)
        _put(root, "evidence/retry.stdout.txt", payload)
        _put(root, "evidence/retry.stdout.sha256", _digest_record(payload, "retry.stdout"))
        process = root / "evidence/retry.process.txt"
        process.write_text(
            process.read_text().replace("stdout_bytes=16", f"stdout_bytes={len(payload)}")
        )
        environment = root / "evidence/retry.environment.txt"
        environment.write_text(
            environment.read_text().replace(
                "stdout_stderr_file_cap_bytes=17", "stdout_stderr_file_cap_bytes=4194304"
            )
        )
    else:
        _put(root, "evidence/retry.telemetry.csv", b"x" * (1024 * 1024 + 1))
    with pytest.raises(OmivInputError, match="exceeds byte limit"):
        import_external_observations(_refresh_manifest(root, raw), root)


@pytest.mark.parametrize(
    "mutation",
    ["missing_filename", "missing_size", "missing_digest", "duplicate", "unknown", "mixed"],
)
def test_bare_artifact_report_grammar_is_exact(tmp_path: Path, mutation: str) -> None:
    root, raw, _control = _fixture(tmp_path)
    path = root / "evidence/main-q4-k-m.txt"
    lines = path.read_text().splitlines()
    if mutation == "missing_filename":
        lines = lines[1:]
    elif mutation == "missing_size":
        lines = [line for line in lines if not line.startswith("observed_bytes=")]
    elif mutation == "missing_digest":
        lines = [line for line in lines if not line.startswith("observed_sha256=")]
    elif mutation == "duplicate":
        lines.insert(2, lines[1])
    elif mutation == "unknown":
        lines.append("unknown_field=value")
    else:
        lines.insert(0, "artifact_role=MAIN_MODEL")
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(OmivInputError, match="artifact"):
        import_external_observations(_refresh_manifest(root, raw), root)


def test_labeled_report_never_substitutes_plan_filename_and_rejects_trailing_content(
    tmp_path: Path,
) -> None:
    root, raw, _control = _fixture(tmp_path)
    profile = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json")
    item = next(artifact for artifact in profile.artifacts if artifact.role.value == "MAIN_MODEL")
    path = root / "evidence/main-q4-k-m.txt"
    labeled = [
        "artifact_role=MAIN_MODEL",
        f"filename={item.path}",
        "source_repository=owner/repository",
        f"pinned_revision={'c' * 40}",
        "source_url=https://example.invalid/artifact",
        "transfer_exit=0",
        f"observed_bytes={item.declared_size}",
        f"expected_bytes={item.declared_size}",
        f"observed_sha256={item.provider_identity}",
        f"expected_sha256={item.provider_identity}",
        "MATCH",
    ]
    artifacts = raw["artifacts"]
    assert isinstance(artifacts, list) and isinstance(artifacts[0], dict)
    artifacts[0]["observation_format"] = "LABELED_V1"
    for changed in (
        [line for line in labeled if not line.startswith("filename=")],
        [*labeled, "trailing=ambiguous"],
    ):
        path.write_text("\n".join(changed) + "\n")
        with pytest.raises(OmivInputError, match="labeled artifact"):
            import_external_observations(_refresh_manifest(root, raw), root)


@pytest.mark.parametrize(
    "control_id",
    [
        CLASSIC_CREDENTIAL.lower(),
        FINE_GRAINED_CREDENTIAL.lower(),
        "/home/user/private-run",
        "https://private.internal/run",
        "api-token-secret",
        "user-home",
        r"C:\\Users\\alice",
        r"\\\\server\\share",
        "private-host",
        "bad\nid",
    ],
)
def test_control_identifier_is_portable_private_safe_and_never_echoed(
    tmp_path: Path, control_id: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    raw["control_id"] = control_id
    control_path = tmp_path / "control.json"
    control_path.write_text(json.dumps(raw))
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 2
    assert control_id not in result.stdout
    assert "Traceback" not in result.stdout


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("retry_reason", "https://private.internal/retry"),
        ("predicate", "api_token=secret-value"),
        ("finding_detail", "/home/user/finding"),
        ("finding_text", r"C:\\Users\\alice\\finding"),
        ("skip_reason", "private-host.local"),
        ("artifact_id", "secret-artifact"),
        ("attempt_id", "private-host"),
        ("finding_code", "PRIVATE_HOST"),
        ("skip_target", "USER_HOME"),
        ("member_path", "evidence/api-token.txt"),
    ],
)
def test_all_serialized_free_text_rejects_sensitive_values_without_echo(
    tmp_path: Path, field: str, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    findings = raw["findings"]
    skips = raw["skips"]
    assert (
        isinstance(attempts, list)
        and isinstance(attempts[1], dict)
        and isinstance(attempts[2], dict)
    )
    assert isinstance(findings, list) and isinstance(findings[0], dict)
    assert isinstance(skips, list) and isinstance(skips[0], dict)
    if field == "retry_reason":
        attempts[1]["retry_reason"] = value
    elif field == "predicate":
        attempts[1]["output_predicate"] = {"kind": "CONTAINS_EXACT_UTF8", "value": value}
    elif field == "finding_detail":
        findings[0]["detail"] = value
    elif field == "finding_text":
        findings[0]["exact_text"] = value
    elif field == "skip_reason":
        skips[0]["reason"] = value
    elif field == "artifact_id":
        artifacts = raw["artifacts"]
        assert isinstance(artifacts, list) and isinstance(artifacts[0], dict)
        artifacts[0]["artifact_id"] = value
    elif field == "attempt_id":
        attempts[2]["attempt_id"] = value
    elif field == "finding_code":
        findings[0]["code"] = value
    elif field == "skip_target":
        skips[0]["target"] = value
    else:
        raw["source_identity_member"] = value
    control_path = tmp_path / "control.json"
    control_path.write_text(json.dumps(raw))
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(tmp_path / "out.json"),
        ],
    )
    assert result.exit_code == 2
    assert value not in result.stdout
    assert "Traceback" not in result.stdout


@pytest.mark.parametrize(
    "value",
    [
        CLASSIC_CREDENTIAL,
        FINE_GRAINED_CREDENTIAL,
        "Authorization: Basic portable-looking-value",
        "Bearer portable-looking-value",
        "https://example.invalid/object?X-Amz-Signature=private-value",
        "https://example.invalid/object?Signature=private-value",
        "https://example.invalid/object?Key-Pair-Id=private-value",
        "https://example.invalid/object?access_token=private-value",
        "api_key=private-value",
        "password=private-value",
        PRIVATE_KEY_MARKER,
        OPENSSH_PRIVATE_KEY_MARKER,
        "kubeconfig material",
        "/opt/company/run",
        "/srv/service/capture",
        "/usr/local/share/private-input",
        r"C:\\Users\\portable-looking\\capture",
        r"\\\\server\\share\\capture",
    ],
)
def test_canonical_unsafe_value_set_rejects_free_text_without_reflection(
    tmp_path: Path, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    attempts[1]["retry_reason"] = value
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError) as caught:
        import_external_observations(control, root)
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    ("attempt_index", "member", "option", "value"),
    [
        (1, "evidence/retry.argv.json", "--device", CLASSIC_CREDENTIAL),
        (
            2,
            "evidence/dflash.argv.json",
            "--spec-draft-device",
            FINE_GRAINED_CREDENTIAL,
        ),
        (1, "evidence/retry.argv.json", "--prompt", "Authorization: Basic private-value"),
    ],
)
def test_every_scalar_argv_route_uses_privacy_policy_and_cli_never_reflects(
    tmp_path: Path,
    attempt_index: int,
    member: str,
    option: str,
    value: str,
) -> None:
    root, raw, _control = _fixture(tmp_path)
    argv_path = root / member
    argv = json.loads(argv_path.read_text())
    if option == "--prompt":
        argv[argv.index(option) + 1] = value
    else:
        argv.extend((option, value))
    argv_path.write_text(json.dumps(argv) + "\n")
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError, match="argv scalar value") as caught:
        import_external_observations(control, root)
    assert value not in str(caught.value)

    control_path = tmp_path / "control.json"
    control_path.write_text(json.dumps(control.model_dump(mode="json", by_alias=True)))
    output = tmp_path / "out.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert attempt_index in {1, 2}
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


def test_all_legitimate_portable_scalar_argv_values_are_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, raw, _control = _fixture(tmp_path)
    import omiv.runtime_compatibility.external_operations as operations

    screened: list[str] = []
    original_reject = operations._reject_sensitive_text

    def recording_reject(value: str, label: str) -> None:
        if label == "argv scalar value":
            screened.append(value)
        original_reject(value, label)

    monkeypatch.setattr(operations, "_reject_sensitive_text", recording_reject)
    argv_path = root / "evidence/dflash.argv.json"
    argv = json.loads(argv_path.read_text())
    portable_values = [
        "--seed",
        "42",
        "--temp",
        "0.25",
        "--n-predict",
        "32",
        "--ctx-size",
        "4096",
        "--gpu-layers",
        "all",
        "--device",
        "CUDA0",
        "--color",
        "off",
        "--spec-draft-ngl",
        "8",
        "--spec-draft-device",
        "CUDA1",
        "--spec-draft-n-max",
        "16",
        "--log-verbosity",
        "2",
        "--log-colors",
        "off",
    ]
    argv.extend(portable_values)
    argv_path.write_text(json.dumps(argv) + "\n")
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    normalized = evidence.source_record.attempts[2].argv
    for option, value in zip(portable_values[::2], portable_values[1::2], strict=True):
        assert normalized[normalized.index(option) + 1] == value
    normalized_options = {item for item in normalized if item.startswith("--")}
    assert normalized_options >= _VALUE_OPTIONS - _PATH_OPTIONS
    scalar_values = {
        normalized[normalized.index(option) + 1] for option in _VALUE_OPTIONS - _PATH_OPTIONS
    }
    assert scalar_values <= set(screened)


def test_unused_manifest_member_credential_is_rejected_without_reflection(
    tmp_path: Path,
) -> None:
    root, raw, _control = _fixture(tmp_path)
    value = CLASSIC_CREDENTIAL
    _put(root, f"unused/{value}.txt", "unused\n")
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError) as caught:
        import_external_observations(control, root)
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--device", CLASSIC_CREDENTIAL),
        ("--device", FINE_GRAINED_CREDENTIAL),
        ("--device", "private-host"),
        ("--prompt", "Bearer private-value"),
    ],
)
def test_offline_rehashed_scalar_argv_privacy_injection_is_rejected_without_reflection(
    tmp_path: Path, option: str, value: str
) -> None:
    root, _raw, control = _fixture(tmp_path)
    evidence = import_external_observations(control, root)
    mutated = evidence.model_dump(mode="json", by_alias=True)
    argv = mutated["source_record"]["attempts"][1]["argv"]
    if option == "--prompt":
        argv[argv.index(option) + 1] = value
    else:
        argv.extend((option, value))
    _rehash_evidence(mutated)
    path = tmp_path / "offline-private-argv.json"
    path.write_text(json.dumps(mutated))
    with pytest.raises(OmivInputError, match="argv scalar value") as caught:
        load_external_evidence(path)
    assert value not in str(caught.value)
    result = RUNNER.invoke(
        app,
        ["runtime-compat", "verify-external", "--evidence", str(path)],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output


def test_offline_rehashed_unused_member_credential_is_rejected_before_reconstruction(
    tmp_path: Path,
) -> None:
    root, raw, _control = _fixture(tmp_path)
    _put(root, "unused/portable.txt", "unused\n")
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    mutated = evidence.model_dump(mode="json", by_alias=True)
    value = CLASSIC_CREDENTIAL
    member = next(
        item for item in mutated["manifest"]["members"] if item["path"] == "unused/portable.txt"
    )
    member["path"] = f"unused/{value}.txt"
    _rehash_evidence(mutated)
    path = tmp_path / "offline-private-member.json"
    path.write_text(json.dumps(mutated))
    with pytest.raises(OmivInputError, match="manifest member path") as caught:
        load_external_evidence(path)
    assert value not in str(caught.value)


def test_external_credential_inventory_mapping_is_named_versioned_and_complete() -> None:
    assert EXTERNAL_PRIVACY_POLICY_VERSION == "omiv.external-runtime-privacy.v1"
    patterns = dict(EXTERNAL_CREDENTIAL_FAMILY_PATTERNS)
    assert len(patterns) == len(EXTERNAL_CREDENTIAL_FAMILY_PATTERNS)
    assert set(patterns) == {
        "aws_access_key",
        "github_token",
        "hugging_face_token",
        "openai_style_token",
        "slack_token",
        "private_key",
        "authorization_header",
        "signed_url_or_access_field",
        "generic_credential_assignment",
        "google_api_key",
        "google_oauth_credential",
    }
    assert set(patterns) >= {
        "aws_access_key",
        "github_token",
        "hugging_face_token",
        "openai_style_token",
        "slack_token",
        "private_key",
    }
    for _case, value, family in CREDENTIAL_SIGNATURE_CASES:
        assert re.search(patterns[family], value) is not None
        with pytest.raises(OmivInputError) as caught:
            _reject_sensitive_text(value, "credential matrix value")
        assert value not in str(caught.value)


def test_every_credential_family_has_an_explicit_complete_punctuation_boundary_matrix() -> None:
    patterns = {
        family: re.compile(pattern) for family, pattern in EXTERNAL_CREDENTIAL_FAMILY_PATTERNS
    }
    punctuation = PRINTABLE_ASCII_PUNCTUATION + REPRESENTATIVE_UNICODE_PUNCTUATION
    assert tuple(string.punctuation) == PRINTABLE_ASCII_PUNCTUATION
    assert all(not character.isalnum() for character in punctuation)
    assert set(patterns) == (
        WORD_BOUNDED_CREDENTIAL_FAMILIES | LEFT_WORD_BOUNDED_CREDENTIAL_FAMILIES | {"private_key"}
    )

    for case, credential, family in CREDENTIAL_SIGNATURE_CASES:
        pattern = patterns[family]
        for delimiter in punctuation:
            # Python/release-audit word boundaries intentionally treat underscore as
            # a word character. Every other ASCII and representative Unicode
            # punctuation character is a valid left delimiter.
            expected_left = family == "private_key" or delimiter != "_"
            expected_right = (
                family not in WORD_BOUNDED_CREDENTIAL_FAMILIES
                or delimiter != "_"
                or family in UNDERSCORE_TERMINATED_CREDENTIAL_FAMILIES
            )
            assert bool(pattern.search(delimiter + credential)) is expected_left, (
                case,
                "left",
                delimiter,
            )
            assert bool(pattern.search(credential + delimiter)) is expected_right, (
                case,
                "right",
                delimiter,
            )
            if audit_pattern := RELEASE_AUDIT_CREDENTIAL_PATTERNS.get(family):
                for candidate in (
                    delimiter + credential,
                    credential + delimiter,
                    delimiter + credential + delimiter,
                ):
                    assert bool(pattern.search(candidate)) is bool(
                        audit_pattern.search(candidate)
                    ), (
                        case,
                        delimiter,
                        candidate,
                    )

        if audit_pattern := RELEASE_AUDIT_CREDENTIAL_PATTERNS.get(family):
            for word_neighbor in ("A", "7", "_", "é", "漢"):
                for candidate in (word_neighbor + credential, credential + word_neighbor):
                    assert bool(pattern.search(candidate)) is bool(
                        audit_pattern.search(candidate)
                    ), (
                        case,
                        word_neighbor,
                        candidate,
                    )


@pytest.mark.parametrize(
    ("_case", "value"),
    HYPHEN_PREFIXED_CREDENTIAL_CASES,
    ids=[item[0] for item in HYPHEN_PREFIXED_CREDENTIAL_CASES],
)
def test_hyphen_delimited_openai_and_slack_signatures_match_release_word_boundaries(
    _case: str, value: str
) -> None:
    patterns = dict(EXTERNAL_CREDENTIAL_FAMILY_PATTERNS)
    family = "openai_style_token" if "openai" in _case else "slack_token"
    assert re.search(patterns[family], value) is not None
    with pytest.raises(OmivInputError) as caught:
        _reject_sensitive_text(value, "hyphen-delimited credential")
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    ("_family", "value"),
    CREDENTIAL_ROUTE_CASES,
    ids=[item[0] for item in CREDENTIAL_ROUTE_CASES],
)
def test_external_credential_families_rejected_on_import_without_reflection(
    tmp_path: Path, _family: str, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    attempts[1]["retry_reason"] = value
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError) as caught:
        import_external_observations(control, root)
    assert value not in str(caught.value)

    control_path = tmp_path / "credential-control.json"
    control_path.write_text(json.dumps(control.model_dump(mode="json", by_alias=True)))
    output = tmp_path / "credential-output.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


@pytest.mark.parametrize(
    ("_family", "value"),
    CREDENTIAL_ROUTE_CASES,
    ids=[item[0] for item in CREDENTIAL_ROUTE_CASES],
)
def test_external_credential_families_rejected_in_every_scalar_argv_route(
    tmp_path: Path, _family: str, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    argv_path = root / "evidence/retry.argv.json"
    argv = json.loads(argv_path.read_text())
    argv.extend(("--device", value))
    argv_path.write_text(json.dumps(argv) + "\n")
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError, match="argv scalar value") as caught:
        import_external_observations(control, root)
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    ("_case", "value"),
    HYPHEN_PREFIXED_CREDENTIAL_CASES,
    ids=[item[0] for item in HYPHEN_PREFIXED_CREDENTIAL_CASES],
)
@pytest.mark.parametrize(
    ("attempt_index", "member", "option"),
    [
        (1, "evidence/retry.argv.json", "--device"),
        (2, "evidence/dflash.argv.json", "--spec-draft-device"),
        (1, "evidence/retry.argv.json", "--color"),
    ],
)
def test_hyphen_delimited_credentials_are_rejected_by_each_scalar_argv_cli_route(
    tmp_path: Path,
    _case: str,
    value: str,
    attempt_index: int,
    member: str,
    option: str,
) -> None:
    root, raw, _control = _fixture(tmp_path)
    argv_path = root / member
    argv = json.loads(argv_path.read_text())
    argv.extend((option, value))
    argv_path.write_text(json.dumps(argv) + "\n")
    control = _refresh_manifest(root, raw)
    with pytest.raises(OmivInputError, match="argv scalar value") as caught:
        import_external_observations(control, root)
    assert value not in str(caught.value)

    control_path = tmp_path / f"argv-{attempt_index}-control.json"
    control_path.write_text(json.dumps(control.model_dump(mode="json", by_alias=True)))
    output = tmp_path / f"argv-{attempt_index}-output.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


@pytest.mark.parametrize(
    ("_family", "value"),
    CREDENTIAL_ROUTE_CASES,
    ids=[item[0] for item in CREDENTIAL_ROUTE_CASES],
)
def test_external_credential_families_rejected_inside_normalized_host_path_inputs(
    tmp_path: Path, _family: str, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    profile = load_profile(ROOT / "fixtures/reference-preflight/muse-glimmer-30b.json")
    main = next(item for item in profile.artifacts if item.role.value == "MAIN_MODEL")
    original = f"/external/{main.path}"
    injected = f"/external/{value}/{main.path}"
    argv_path = root / "evidence/retry.argv.json"
    argv = json.loads(argv_path.read_text())
    argv[argv.index("--model") + 1] = injected
    argv_path.write_text(json.dumps(argv) + "\n")
    identities_path = root / "evidence/retry.identities.txt"
    identities_path.write_text(identities_path.read_text().replace(original, injected))
    with pytest.raises(OmivInputError, match="captured path value is unsafe") as caught:
        import_external_observations(_refresh_manifest(root, raw), root)
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    ("_family", "value"),
    CREDENTIAL_ROUTE_CASES,
    ids=[item[0] for item in CREDENTIAL_ROUTE_CASES],
)
def test_external_credential_families_rejected_in_portable_member_paths(
    tmp_path: Path, _family: str, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    raw["source_identity_member"] = f"evidence/{value}.txt"
    control_path = tmp_path / "member-control.json"
    control_path.write_text(json.dumps(raw))
    output = tmp_path / "member-output.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


@pytest.mark.parametrize(
    ("_family", "value"),
    CREDENTIAL_ROUTE_CASES,
    ids=[item[0] for item in CREDENTIAL_ROUTE_CASES],
)
def test_external_credential_families_rejected_after_offline_rehash(
    tmp_path: Path, _family: str, value: str
) -> None:
    root, _raw, control = _fixture(tmp_path)
    mutated = import_external_observations(control, root).model_dump(mode="json", by_alias=True)
    mutated["control"]["attempts"][1]["retry_reason"] = value
    mutated["projection"]["attempts"][1]["retry_reason"] = value
    _rehash_evidence(mutated)
    path = tmp_path / "offline-credential.json"
    path.write_text(json.dumps(mutated))
    with pytest.raises(OmivInputError) as caught:
        load_external_evidence(path)
    assert value not in str(caught.value)
    result = RUNNER.invoke(
        app,
        ["runtime-compat", "verify-external", "--evidence", str(path)],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output


def test_absolute_posix_path_uses_a_complete_non_path_token_boundary_matrix() -> None:
    delimiters = (
        "",
        " ",
        "\t",
        ",",
        ";",
        ":",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        "'",
        '"',
        "=",
        "!",
        "?",
        "#",
        "|",
        "&",
    )
    absolute_paths = (
        "/var/lib/private-run",
        "/etc/omiv/private.conf",
        "/root/private-run",
        "/home/user/private-run",
        "/tmp/private-run",
        "/usr/local/private-run",
        "/mnt/private-run",
        "/opt/company/private-run",
        "/srv/service/private-run",
        "/arbitrary-root/private-run",
    )
    for delimiter in delimiters:
        for path in absolute_paths:
            value = path if not delimiter else f"capture retained{delimiter}{path}"
            assert _ABSOLUTE_POSIX_PATH_RE.search(value) is not None
            with pytest.raises(OmivInputError) as caught:
                _reject_sensitive_text(value, "delimiter path matrix")
            assert value not in str(caught.value)


@pytest.mark.parametrize(
    "value",
    [
        "capture retained,/opt/company/private-run",
        "capture retained;/srv/service/private-run",
        "capture retained:/var/lib/private-run",
        "capture retained=(/etc/omiv/private.conf)",
    ],
)
def test_punctuation_embedded_absolute_path_import_exits_two_without_partial_output(
    tmp_path: Path, value: str
) -> None:
    root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    attempts[1]["retry_reason"] = value
    control_path = tmp_path / "path-control.json"
    control_path.write_text(json.dumps(raw))
    output = tmp_path / "path-output.json"
    result = RUNNER.invoke(
        app,
        [
            "runtime-compat",
            "import-external",
            "--control",
            str(control_path),
            "--manifest-root",
            str(root),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


def test_punctuation_embedded_absolute_path_rejected_after_coherent_offline_rehash(
    tmp_path: Path,
) -> None:
    root, _raw, control = _fixture(tmp_path)
    mutated = import_external_observations(control, root).model_dump(mode="json", by_alias=True)
    value = "capture retained;/srv/service/private-run"
    mutated["control"]["attempts"][1]["retry_reason"] = value
    mutated["projection"]["attempts"][1]["retry_reason"] = value
    _rehash_evidence(mutated)
    path = tmp_path / "offline-punctuation-path.json"
    path.write_text(json.dumps(mutated))
    with pytest.raises(OmivInputError) as caught:
        load_external_evidence(path)
    assert value not in str(caught.value)
    result = RUNNER.invoke(
        app,
        ["runtime-compat", "verify-external", "--evidence", str(path)],
    )
    assert result.exit_code == 2
    assert value not in result.output
    assert "Traceback" not in result.output


def test_portable_relative_paths_and_reviewed_scalar_values_remain_allowed(
    tmp_path: Path,
) -> None:
    safe_values = (
        "artifacts/model.gguf",
        "evidence/retry.stdout.txt",
        "evidence/member-label-v1.txt",
        "capture retained artifacts/model.gguf",
        "synthetic-label-v1",
        "42",
        "0.25",
        "all",
        "CUDA0",
        "CUDA.backend-1",
        "CUDA",
        "draft-dflash",
        "BARE_FILENAME_V1",
        "MATCHED_PLAN_OBSERVATION",
        "{artifact:main-q4-k-m}",
        "portable/image-fixture.png",
    )
    for value in safe_values:
        assert _ABSOLUTE_POSIX_PATH_RE.search(value) is None
        _reject_sensitive_text(value, "positive control")

    root, raw, _control = _fixture(tmp_path)
    attempts = raw["attempts"]
    assert isinstance(attempts, list) and isinstance(attempts[1], dict)
    attempts[1]["retry_reason"] = "Retain portable artifact artifacts/model.gguf."
    _put(root, "portable/artifacts/model.gguf", "portable reference only\n")
    evidence = import_external_observations(_refresh_manifest(root, raw), root)
    assert evidence.projection.attempts[1].retry_reason == (
        "Retain portable artifact artifacts/model.gguf."
    )
    assert any(item.path == "portable/artifacts/model.gguf" for item in evidence.manifest.members)


def test_real_a5_acceptance_when_exact_external_copy_is_available() -> None:
    root = Path("/tmp/omiv-p7b2-runtime-evidence-20260815T060125Z/input/a5-evidence")
    control_path = Path(
        "/tmp/omiv-p7b2-runtime-evidence-20260815T060125Z/validation/a5-control.json"
    )
    if not root.is_dir() or not control_path.is_file():
        pytest.skip("exact immutable A5 external acceptance input is unavailable")
    raw = json.loads(control_path.read_text())
    raw["schema"] = "omiv.external-runtime-observation-control.v2"
    raw["capture_profile"] = "llama.cpp-cuda-capture.v1"
    raw["image_fixture_bytes"] = 4246
    control = ExternalObservationControl.model_validate(raw)
    evidence = import_external_observations(control, root)
    assert evidence.manifest.manifest_sha256 == (
        "416c643a887c25f5ed3a2f8b853f5c08b41ff382190e9536f0f46a694abcf7b3"
    )
    assert evidence.projection.overall_status == ExternalOverallStatus.PARTIAL
    assert evidence.projection.attempts[0].return_code == 153
    assert evidence.projection.attempts[1].duration_ms == 9646
    assert evidence.projection.attempts[2].output_predicate_status == ExternalStatus.OBSERVED
    assert all(
        item.process_status == ExternalStatus.INCOMPLETE for item in evidence.projection.attempts
    )
    activation = evidence.projection.attempts[4].dflash_activation
    assert activation is not None
    assert (activation.accepted_draft_tokens, activation.generated_draft_tokens) == (23, 27)
