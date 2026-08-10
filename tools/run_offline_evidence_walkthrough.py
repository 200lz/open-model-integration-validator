#!/usr/bin/env python3
"""Run the bounded, offline OMIV evidence walkthrough."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 256 * 1024
MAX_PROCESS_OUTPUT_BYTES = 16 * 1024
PROCESS_TIMEOUT_SECONDS = 30
MANIFEST_PATH = Path("examples/offline-evidence-walkthrough/walkthrough.json")

R1D_PATHS = (
    "README.md",
    "docs/README.md",
    "docs/offline-evidence-walkthrough.md",
    "docs/quickstart.md",
    "docs/roadmap.md",
    "examples/offline-evidence-walkthrough/README.md",
    "examples/offline-evidence-walkthrough/walkthrough.json",
    "examples/offline-quickstart/README.md",
    "tests/test_offline_evidence_walkthrough.py",
    "tests/test_public_launch_ux.py",
    "tools/audit_offline_evidence_walkthrough.py",
    "tools/audit_public_launch_ux.py",
    "tools/run_offline_evidence_walkthrough.py",
)

LABELS = (
    "SYNTHETIC",
    "DEMONSTRATION_ONLY",
    "NOT_PROVIDER_EVIDENCE",
    "NOT_AN_ASSURANCE_BUNDLE",
    "NOT_A_SAFETY_OR_AUTHENTICITY_RESULT",
)

STEP_ORDER = (
    "version",
    "canonical-runtime-scenario",
    "phase6a-local-payload",
    "phase6b-remote-metadata",
    "phase6b-incomplete-local",
    "phase6c-sampled-fidelity",
    "phase6d-tokenizer-scope",
    "phase5-trust-boundary",
    "phase6e-resolution-receipt",
    "phase6e-partial-runtime",
)

ALLOWED_COMMANDS: dict[str, tuple[str, ...]] = {
    "version": ("omiv", "--version"),
    "canonical-runtime-scenario": (
        "omiv",
        "runtime-resolution",
        "verify",
        "runtime-resolution-parity/scenarios/immutable-pinned.json",
    ),
    "phase6a-local-payload": (
        "omiv",
        "payload",
        "verify-manifest",
        "payload-integrity/observations/local.manifest.json",
    ),
    "phase6b-remote-metadata": (
        "omiv",
        "reconcile",
        "verify",
        "reconciliation/snapshots/metadata-only.snapshot.json",
    ),
    "phase6b-incomplete-local": (
        "omiv",
        "reconcile",
        "verify",
        "reconciliation/comparisons/incomplete.json",
    ),
    "phase6c-sampled-fidelity": (
        "omiv",
        "quantization",
        "verify",
        "quantization-fidelity/evidence/sampled.json",
    ),
    "phase6d-tokenizer-scope": (
        "omiv",
        "tokenizer-config",
        "verify",
        "tokenizer-configuration-parity/evidence/synthetic.json",
    ),
    "phase5-trust-boundary": (
        "omiv",
        "trust",
        "verify",
        "--input",
        "trust/examples/trusted-transformation.signed-envelope.json",
        "--trust-bundle",
        "trust/examples/project-trust-bundle.json",
        "--policy",
        "trust/examples/project-trust-policy.json",
        "--evaluation-context",
        "trust/examples/evaluation-context.json",
    ),
    "phase6e-resolution-receipt": (
        "omiv",
        "runtime-resolution",
        "verify",
        "runtime-resolution-parity/receipts/t0.json",
    ),
    "phase6e-partial-runtime": (
        "omiv",
        "runtime-resolution",
        "verify",
        "runtime-resolution-parity/evidence.json",
    ),
}

EXPECTED_INPUTS: dict[str, str | None] = {
    "version": None,
    "canonical-runtime-scenario": ("runtime-resolution-parity/scenarios/immutable-pinned.json"),
    "phase6a-local-payload": "payload-integrity/observations/local.manifest.json",
    "phase6b-remote-metadata": ("reconciliation/snapshots/metadata-only.snapshot.json"),
    "phase6b-incomplete-local": "reconciliation/comparisons/incomplete.json",
    "phase6c-sampled-fidelity": "quantization-fidelity/evidence/sampled.json",
    "phase6d-tokenizer-scope": ("tokenizer-configuration-parity/evidence/synthetic.json"),
    "phase5-trust-boundary": ("trust/examples/trusted-transformation.signed-envelope.json"),
    "phase6e-resolution-receipt": "runtime-resolution-parity/receipts/t0.json",
    "phase6e-partial-runtime": "runtime-resolution-parity/evidence.json",
}

EXPECTED_EXITS = {
    "version": 0,
    "canonical-runtime-scenario": 0,
    "phase6a-local-payload": 0,
    "phase6b-remote-metadata": 0,
    "phase6b-incomplete-local": 1,
    "phase6c-sampled-fidelity": 0,
    "phase6d-tokenizer-scope": 0,
    "phase5-trust-boundary": 0,
    "phase6e-resolution-receipt": 0,
    "phase6e-partial-runtime": 1,
}

EXPECTED_PHASES = {
    "version": "environment",
    "canonical-runtime-scenario": "canonical-object",
    "phase6a-local-payload": "6A",
    "phase6b-remote-metadata": "6B",
    "phase6b-incomplete-local": "6B",
    "phase6c-sampled-fidelity": "6C",
    "phase6d-tokenizer-scope": "6D",
    "phase5-trust-boundary": "5",
    "phase6e-resolution-receipt": "6E",
    "phase6e-partial-runtime": "6E",
}

EXPECTED_NEXT_EVIDENCE = {
    "version": "runtime-resolution-parity/scenarios/immutable-pinned.json",
    "canonical-runtime-scenario": "payload-integrity/observations/local.manifest.json",
    "phase6a-local-payload": "reconciliation/snapshots/metadata-only.snapshot.json",
    "phase6b-remote-metadata": "reconciliation/comparisons/incomplete.json",
    "phase6b-incomplete-local": "quantization-fidelity/evidence/sampled.json",
    "phase6c-sampled-fidelity": "tokenizer-configuration-parity/evidence/synthetic.json",
    "phase6d-tokenizer-scope": "trust/examples/trusted-transformation.signed-envelope.json",
    "phase5-trust-boundary": "runtime-resolution-parity/receipts/t0.json",
    "phase6e-resolution-receipt": "runtime-resolution-parity/evidence.json",
    "phase6e-partial-runtime": "docs/offline-evidence-walkthrough.md#evidence-boundary-summary",
}

EXPECTED_SOURCE_SHA256 = {
    "payload-integrity/observations/local.manifest.json": (
        "d6c2ddbec5516d5ab57522af05aa16d9a4ce097b9370f6e4ecaeddd0d82f236c"
    ),
    "quantization-fidelity/evidence/sampled.json": (
        "2d2742074e5e76f08c9ed4e9c13a4911ba02d0620dceb4733ceac988ffcf0f95"
    ),
    "reconciliation/comparisons/incomplete.json": (
        "cb9ddcdb68e99fce5c7a0448966dead5c35a5faae0645e08c4907217dfbcd413"
    ),
    "reconciliation/snapshots/metadata-only.snapshot.json": (
        "85f88da5f3cc5b3ff673c471a7b804528f9eae811e5ad9e4d01207ae5ef5d99e"
    ),
    "runtime-resolution-parity/evidence.json": (
        "567676d16d4053b5fe90c6d840fe08ca62327e481360d569a78d0583ecf18afc"
    ),
    "runtime-resolution-parity/receipts/t0.json": (
        "b359c08dfefdbf4f809a735c66c4c6500e444b6898397724e53c311c7ce4871f"
    ),
    "runtime-resolution-parity/scenarios/immutable-pinned.json": (
        "e8f8e32edb74e233440a48a7f93914e2c23e5433d54671f99be587e1d500be7c"
    ),
    "tokenizer-configuration-parity/evidence/synthetic.json": (
        "c3496d8327e4c73644a9210b01fd0d234178ad596b1530e6fa2b16967f6cd08c"
    ),
    "trust/examples/evaluation-context.json": (
        "3e8809ec13ff19f7859ea94672a4c7b8cdc59e41c41b585b4db235d10894ccf2"
    ),
    "trust/examples/project-trust-bundle.json": (
        "bbf3ded229244cf22f8b3700e06067e3814990efe4cb3f1fad66e84ba6970edd"
    ),
    "trust/examples/project-trust-policy.json": (
        "9924ee55a65def29c5b43eca6aa6381f54abdf93d8fdee48f85a79a6e2a34d86"
    ),
    "trust/examples/trusted-transformation.signed-envelope.json": (
        "9aa28c6d70a580fa53c25cbc9185681dcffe61b15f1317b77b902be12d7d592d"
    ),
}

EXPECTED_SCHEMAS = {
    "canonical-runtime-scenario": "omiv.runtime-resolution-scenario-result.v1",
    "phase6a-local-payload": "omiv.observed-payload-manifest.v1",
    "phase6b-remote-metadata": "omiv.remote-snapshot-manifest.v1",
    "phase6b-incomplete-local": "omiv.remote-local-reconciliation-comparison.v1",
    "phase6c-sampled-fidelity": "omiv.quantization-fidelity-evidence.v1",
    "phase6d-tokenizer-scope": "omiv.tokenizer-configuration-parity-evidence.v1",
    "phase5-trust-boundary": "omiv.signed-object-envelope.v1",
    "phase6e-resolution-receipt": "omiv.registry-resolution-receipt.v1",
    "phase6e-partial-runtime": "omiv.runtime-resolution-parity-evidence.v1",
}

EXPECTED_OUTPUTS = {
    "version": "0.10.0",
    "canonical-runtime-scenario": (
        "VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT "
        "schema=omiv.runtime-resolution-scenario-result.v1"
    ),
    "phase6a-local-payload": "VALID_LOCAL_OBSERVATION",
    "phase6b-remote-metadata": (
        "VALID_CANONICAL_RECONCILIATION_OBJECT schema=omiv.remote-snapshot-manifest.v1"
    ),
    "phase6b-incomplete-local": (
        "VALID_CANONICAL_RECONCILIATION_OBJECT "
        "schema=omiv.remote-local-reconciliation-comparison.v1"
    ),
    "phase6c-sampled-fidelity": "CONFORMS_FOR_DECLARED_SCOPE",
    "phase6d-tokenizer-scope": "PARITY_ESTABLISHED_FOR_DECLARED_SCOPE",
    "phase5-trust-boundary": "TRUSTED_SIGNATURE_WITH_LIMITATIONS",
    "phase6e-resolution-receipt": (
        "VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.registry-resolution-receipt.v1"
    ),
    "phase6e-partial-runtime": "PARTIAL_FOR_DECLARED_SCOPE",
}

EXPECTED_EXACT_STDOUT = {
    "version": "0.10.0",
    "canonical-runtime-scenario": (
        "VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT "
        "schema=omiv.runtime-resolution-scenario-result.v1"
    ),
    "phase6a-local-payload": (
        "VALID_LOCAL_OBSERVATION "
        "manifest=observed_payload_741698e3c3671cbf3ccd3b4a4df7fa54 "
        "semantic_correctness=NOT_EVALUATED"
    ),
    "phase6b-remote-metadata": (
        "VALID_CANONICAL_RECONCILIATION_OBJECT "
        "schema=omiv.remote-snapshot-manifest.v1 model_safety=NOT_VERIFIED"
    ),
    "phase6b-incomplete-local": (
        "VALID_CANONICAL_RECONCILIATION_OBJECT "
        "schema=omiv.remote-local-reconciliation-comparison.v1 model_safety=NOT_VERIFIED"
    ),
    "phase6c-sampled-fidelity": (
        "CONFORMS_FOR_DECLARED_SCOPE "
        "evidence=quantization_evidence_e6d2b534a1398275c86f0b51a3373e69 "
        "numerical=SAMPLED_WITHIN_POLICY"
    ),
    "phase6d-tokenizer-scope": (
        "PARITY_ESTABLISHED_FOR_DECLARED_SCOPE "
        "evidence=tokenizer_evidence_f290ada7bb4a2cc746a6bd807b0a39da "
        "scope=COMPLETE_DECLARED_TOKENIZER_ASSET_SET"
    ),
    "phase5-trust-boundary": (
        "TRUSTED_SIGNATURE_WITH_LIMITATIONS "
        "object=att_4a6efa7aad56fc20f2b840688c0756db accepted=1 "
        "report=780a2adeecadac1fe723ac54f489064c532f0d273afd3fe87585776d8deb4515\n"
        "signature_integrity=VALID trusted_by_selected_policy=YES "
        "key=key_ed39d828050734934fcf309c611f5d9b key_status=KNOWN "
        "signer_identity=DECLARED identity_verification=UNVERIFIED "
        "signer_binding=VERIFIED_BY_TRUST_BUNDLE\n"
        "claim_authenticity=EXECUTION_VERIFIED "
        "provenance_strength=ARTIFACT_SPECIFIC_PROVENANCE "
        "claim_independently_proven=NO payload_integrity=NOT_CHECKED "
        "numerical_fidelity=NOT_CHECKED security=NOT_CHECKED runtime=NOT_CHECKED "
        "approval=NOT_AVAILABLE lifecycle_completeness=NOT_APPLICABLE"
    ),
    "phase6e-resolution-receipt": (
        "VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.registry-resolution-receipt.v1"
    ),
    "phase6e-partial-runtime": (
        "PARTIAL_FOR_DECLARED_SCOPE "
        "evidence=runtime_resolution_evidence_1b47f3d0a4c705bf80b6e79bcce019ea "
        "scope=declared.phase6e.scope"
    ),
}

INSPECTION_FIELDS: dict[str, tuple[str, ...]] = {
    "canonical-runtime-scenario": (
        "schema",
        "result_id",
        "result_digest",
        "subject.subject_id",
        "scope",
        "outcome",
    ),
    "phase6a-local-payload": (
        "schema",
        "manifest_id",
        "manifest_digest",
        "subject.subject_id",
        "logical_root",
        "completion_state",
    ),
    "phase6b-remote-metadata": (
        "schema",
        "manifest_id",
        "manifest_digest",
        "subject.subject_id",
        "requested_revision",
        "resolved_revision",
        "resolved_revision_kind",
        "observation_coverage",
    ),
    "phase6b-incomplete-local": (
        "schema",
        "comparison_id",
        "comparison_digest",
        "subject_id",
        "expectation_scope",
        "status",
        "missing_local_members",
    ),
    "phase6c-sampled-fidelity": (
        "schema",
        "evidence_id",
        "evidence_digest",
        "subject.subject_id",
        "scope",
        "expectation_scope",
        "overall_status",
        "numerical_status",
        "behavioral_parity",
        "runtime_identity",
        "authority_established",
    ),
    "phase6d-tokenizer-scope": (
        "schema",
        "evidence_id",
        "evidence_digest",
        "subject.subject_id",
        "scope",
        "overall_status",
        "behavioral_equivalence",
        "runtime_compatibility",
        "authenticity",
        "authority_status",
        "security_status",
    ),
    "phase5-trust-boundary": (
        "schema",
        "envelope_id",
        "envelope_digest",
        "signed_object_id",
        "signed_object_digest",
        "trust_policy_id",
    ),
    "phase6e-resolution-receipt": (
        "schema",
        "receipt_id",
        "receipt_digest",
        "subject.subject_id",
        "scope",
        "requested_identifier.object_id",
        "resolved_identifier",
        "resolved_identity_kind",
        "status",
        "observation_level",
        "authority",
    ),
    "phase6e-partial-runtime": (
        "schema",
        "evidence_id",
        "evidence_digest",
        "subject.subject_id",
        "scope",
        "status",
        "output_provenance.object_id",
    ),
}

ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class WalkthroughError(RuntimeError):
    """A fail-closed, non-sensitive walkthrough failure."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WalkthroughError("duplicate JSON key")
        result[key] = value
    return result


def _read_bounded_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise WalkthroughError("unsafe or missing JSON input")
        size = path.stat().st_size
        if size > MAX_JSON_BYTES:
            raise WalkthroughError("JSON input exceeds size limit")
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except WalkthroughError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WalkthroughError("invalid JSON input") from exc
    if not isinstance(value, dict):
        raise WalkthroughError("JSON input must be an object")
    return value


def _safe_relative_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise WalkthroughError("input path is not repository-relative")
    current = root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise WalkthroughError("symlink input is forbidden")
    if not current.is_file():
        raise WalkthroughError("required tracked input is unavailable")
    return current


def load_manifest(path: Path) -> dict[str, Any]:
    """Load one bounded strict-JSON manifest without following a file symlink."""

    return _read_bounded_json(path)


def validate_manifest(manifest: dict[str, Any]) -> None:
    expected_keys = {
        "classification",
        "labels",
        "title",
        "version",
        "r1d_paths",
        "steps",
        "external_artifact",
    }
    if set(manifest) != expected_keys:
        raise WalkthroughError("manifest keys do not match the fixed contract")
    if manifest["classification"] != "NON_CANONICAL_DEMONSTRATION_MANIFEST":
        raise WalkthroughError("manifest classification is invalid")
    if not isinstance(manifest["labels"], list) or tuple(manifest["labels"]) != LABELS:
        raise WalkthroughError("manifest labels are invalid")
    if manifest["title"] != "OMIV offline evidence walkthrough":
        raise WalkthroughError("manifest title is invalid")
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise WalkthroughError("manifest version is invalid")
    if not isinstance(manifest["r1d_paths"], list):
        raise WalkthroughError("manifest R1D path inventory is invalid")
    if tuple(manifest["r1d_paths"]) != R1D_PATHS:
        raise WalkthroughError("manifest version or R1D path inventory is invalid")
    steps = manifest["steps"]
    if not isinstance(steps, list) or len(steps) != len(STEP_ORDER):
        raise WalkthroughError("walkthrough step order is invalid")
    if any(not isinstance(step, dict) for step in steps):
        raise WalkthroughError("walkthrough step shape is invalid")
    if tuple(step.get("id") for step in steps) != STEP_ORDER:
        raise WalkthroughError("walkthrough step order is invalid")
    if len({step["id"] for step in steps}) != len(steps):
        raise WalkthroughError("walkthrough step IDs are not unique")
    required_step_keys = {
        "id",
        "phase",
        "input",
        "command",
        "expected_exit",
        "expected_stdout_contains",
        "next_evidence",
    }
    for step in steps:
        if not isinstance(step, dict) or set(step) != required_step_keys:
            raise WalkthroughError("walkthrough step shape is invalid")
        step_id = step["id"]
        if step_id not in ALLOWED_COMMANDS:
            raise WalkthroughError("step ID is not on the fixed allowlist")
        if step["phase"] != EXPECTED_PHASES[step_id]:
            raise WalkthroughError("step phase is invalid")
        if not isinstance(step["command"], list):
            raise WalkthroughError("step command is not a token list")
        if tuple(step["command"]) != ALLOWED_COMMANDS[step_id]:
            raise WalkthroughError("command is not on the fixed offline allowlist")
        if step["input"] != EXPECTED_INPUTS[step_id]:
            raise WalkthroughError("step input is not on the fixed allowlist")
        if step["expected_exit"] != EXPECTED_EXITS[step_id]:
            raise WalkthroughError("step exit contract is invalid")
        if step["expected_stdout_contains"] != EXPECTED_OUTPUTS[step_id]:
            raise WalkthroughError("step output invariant is invalid")
        if step["next_evidence"] != EXPECTED_NEXT_EVIDENCE[step_id]:
            raise WalkthroughError("next-evidence path is invalid")
    external = manifest["external_artifact"]
    if external != {
        "path": "reports/raw/kimi_k3_tensors.json",
        "clean_checkout_status": "NOT_AVAILABLE",
        "required_for_walkthrough": False,
        "expected_size": 115542096,
        "expected_sha256": ("15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469"),
    }:
        raise WalkthroughError("external-artifact contract is invalid")


def _decode_and_validate_raw_output(raw: bytes, repository: Path) -> str:
    if len(raw) > MAX_PROCESS_OUTPUT_BYTES:
        raise WalkthroughError("subprocess output exceeds size limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise WalkthroughError("subprocess output is not strict UTF-8") from exc
    without_ansi = ANSI_ESCAPE.sub("", text)
    if any(
        character not in "\n\t\r" and not 0x20 <= ord(character) <= 0x7E
        for character in without_ansi
    ):
        raise WalkthroughError("subprocess output contains unsafe control characters")
    absolute_patterns = (
        re.escape(str(repository)),
        r"/home/[A-Za-z0-9._-]+/",
        r"/Users/[A-Za-z0-9._-]+/",
        r"(?<![:/\w])/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]*",
        r"[A-Za-z]:\\",
    )
    if any(re.search(pattern, without_ansi) for pattern in absolute_patterns):
        raise WalkthroughError("subprocess output contains an absolute machine path")
    if "Traceback (most recent call last):" in without_ansi:
        raise WalkthroughError("subprocess output contains a traceback")
    if re.search(r"(?im)^\s*(?:warning|runtimewarning|userwarning)\s*:", without_ansi):
        raise WalkthroughError("subprocess output contains a warning")
    return text


def sanitize_output(raw: bytes, repository: Path) -> str:
    text = _decode_and_validate_raw_output(raw, repository)
    sanitized = ANSI_ESCAPE.sub("", text)
    return "\n".join(line.rstrip() for line in sanitized.splitlines()).strip()


def _child_environment() -> dict[str, str]:
    return {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "TERM": "dumb",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "OMIV_RUN_CONVERSION_INTEGRATION": "0",
        "OMIV_RUN_GGUF_INTEGRATION": "0",
        "OMIV_RUN_HF_INTEGRATION": "0",
        "OMIV_RUN_MAPPING_INTEGRATION": "0",
        "OMIV_RUN_REMOTE_INTEGRATION": "0",
    }


class _ProcessTimeout(RuntimeError):
    pass


class _ProcessOutputLimit(RuntimeError):
    pass


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _capture_process(
    arguments: Sequence[str],
    repository: Path,
    *,
    timeout_seconds: float = PROCESS_TIMEOUT_SECONDS,
    output_limit: int = MAX_PROCESS_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            list(arguments),
            cwd=repository,
            env=_child_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            shell=False,
        )
    except OSError as exc:
        raise WalkthroughError("subprocess launch failed") from exc
    if process.stdout is None or process.stderr is None:
        _terminate_process(process)
        raise WalkthroughError("subprocess pipes were unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ProcessTimeout
            events = selector.select(remaining)
            if not events:
                raise _ProcessTimeout
            for key, _mask in events:
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(chunk)
                if len(buffers["stdout"]) + len(buffers["stderr"]) > output_limit:
                    raise _ProcessOutputLimit
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProcessTimeout
        returncode = process.wait(timeout=remaining)
    except _ProcessTimeout as exc:
        _terminate_process(process)
        raise WalkthroughError("subprocess timed out and was terminated") from exc
    except _ProcessOutputLimit as exc:
        _terminate_process(process)
        raise WalkthroughError("subprocess output exceeded the capture limit") from exc
    except subprocess.TimeoutExpired as exc:
        _terminate_process(process)
        raise WalkthroughError("subprocess timed out and was terminated") from exc
    except OSError as exc:
        _terminate_process(process)
        raise WalkthroughError("subprocess capture failed") from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _execute_module(arguments: Sequence[str], repository: Path) -> tuple[int, str, str]:
    code, raw_stdout, raw_stderr = _capture_process(
        [sys.executable, "-I", "-m", "omiv", *arguments], repository
    )
    stdout = sanitize_output(raw_stdout, repository)
    stderr = sanitize_output(raw_stderr, repository)
    return code, stdout, stderr


def execute_offline_command(command: Sequence[str], repository: Path) -> tuple[int, str, str]:
    normalized = tuple(command)
    if normalized not in ALLOWED_COMMANDS.values():
        raise WalkthroughError("command is not on the fixed offline allowlist")
    return _execute_module(normalized[1:], repository)


def _field(value: dict[str, Any], dotted_path: str) -> Any:
    current: Any = value
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise WalkthroughError("required inspection field is missing")
        current = current[part]
    return current


def _display(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if len(rendered) > 512:
        raise WalkthroughError("inspection value exceeds display limit")
    return rendered


def _semantic_label(exit_code: int) -> str:
    if exit_code == 0:
        return "VALID_FOR_EXACT_COMMAND_SCOPE"
    if exit_code == 1:
        return "EXPECTED_SEMANTIC_LIMITATION"
    if exit_code == 2:
        return "EXPECTED_INVALID_INPUT"
    raise WalkthroughError("unsupported exit code")


def _source_files(repository: Path, steps: list[dict[str, Any]]) -> tuple[Path, ...]:
    relative_paths: set[str] = set()
    for step in steps:
        if step["input"] is not None:
            relative_paths.add(step["input"])
        for token in step["command"]:
            if token.endswith(".json"):
                relative_paths.add(token)
    return tuple(_safe_relative_file(repository, item) for item in sorted(relative_paths))


def _hashes(paths: Sequence[Path]) -> dict[Path, str]:
    return {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def _verify_source_contract(repository: Path, sources: Sequence[Path]) -> None:
    actual = {
        path.relative_to(repository).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sources
    }
    if actual != EXPECTED_SOURCE_SHA256:
        raise WalkthroughError("tracked source identity does not match the audited contract")


def _validate_step_object(step_id: str, value: dict[str, Any]) -> None:
    expected_schema = EXPECTED_SCHEMAS.get(step_id)
    if expected_schema is not None and value.get("schema") != expected_schema:
        raise WalkthroughError("tracked source schema does not match the audited contract")
    if step_id == "phase6b-incomplete-local" and value.get("status") != (
        "INCOMPLETE_LOCAL_OBSERVATION"
    ):
        raise WalkthroughError("exit-1 reconciliation semantics are invalid")
    if step_id == "phase6e-partial-runtime" and value.get("status") != (
        "PARTIAL_FOR_DECLARED_SCOPE"
    ):
        raise WalkthroughError("exit-1 runtime semantics are invalid")


def _validate_step_output(step_id: str, stdout: str, stderr: str) -> None:
    if stderr:
        raise WalkthroughError("command produced unexpected stderr")
    if stdout != EXPECTED_EXACT_STDOUT[step_id]:
        raise WalkthroughError("command produced unexpected output")


def _run_tamper_demo(repository: Path, temporary_directory: Path) -> str:
    if temporary_directory.is_symlink() or not temporary_directory.is_dir():
        raise WalkthroughError("temporary directory is unsafe or unavailable")
    resolved_temporary = temporary_directory.resolve(strict=True)
    try:
        resolved_temporary.relative_to(repository)
    except ValueError:
        pass
    else:
        raise WalkthroughError("temporary directory must be outside the repository")

    source = _safe_relative_file(
        repository, "runtime-resolution-parity/scenarios/immutable-pinned.json"
    )
    source_before = hashlib.sha256(source.read_bytes()).hexdigest()
    value = _read_bounded_json(source)
    if value.get("result_digest") == "0" * 64:
        raise WalkthroughError("tamper source already has the demonstration digest")
    value["result_digest"] = "0" * 64
    with tempfile.TemporaryDirectory(prefix="omiv-r1d-", dir=resolved_temporary) as work:
        tampered = Path(work) / "tampered-runtime-scenario.json"
        tampered.write_text(
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        if tampered.is_symlink() or tampered.resolve(strict=True).parent != Path(work).resolve():
            raise WalkthroughError("temporary tamper path is unsafe")
        code, stdout, stderr = _execute_module(
            ("runtime-resolution", "verify", str(tampered)), repository
        )
    if code != 2:
        raise WalkthroughError("tampered input did not produce exit 2")
    if stdout:
        raise WalkthroughError("tampered input produced unexpected stdout")
    required_failure_markers = (
        "ERROR runtime-resolution operation failed:",
        "validation error for RuntimeResolutionScenarioResult",
        "canonical identity or digest mismatch",
    )
    if not all(marker in stderr for marker in required_failure_markers):
        raise WalkthroughError("tampered input did not report an integrity mismatch")
    if hashlib.sha256(source.read_bytes()).hexdigest() != source_before:
        raise WalkthroughError("canonical source changed during tamper demonstration")
    return "MALFORMED_INPUT_DETECTED exit=2 source_unchanged=YES temporary_files_removed=YES"


Executor = Callable[[Sequence[str], Path], tuple[int, str, str]]


def run_walkthrough(
    repository: Path,
    *,
    temporary_directory: Path | None = None,
    executor: Executor = execute_offline_command,
) -> str:
    repository = repository.resolve(strict=True)
    manifest_file = _safe_relative_file(repository, MANIFEST_PATH.as_posix())
    manifest = load_manifest(manifest_file)
    validate_manifest(manifest)
    steps = manifest["steps"]
    sources = _source_files(repository, steps)
    _verify_source_contract(repository, sources)
    before = _hashes(sources)

    lines = [
        "OMIV_OFFLINE_EVIDENCE_WALKTHROUGH version=1",
        "labels=" + ",".join(LABELS),
    ]
    for number, step in enumerate(steps, start=1):
        step_id = step["id"]
        code, stdout, _stderr = executor(tuple(step["command"]), repository)
        if code != step["expected_exit"]:
            raise WalkthroughError("command returned an unexpected exit code")
        _validate_step_output(step_id, stdout, _stderr)
        if step["expected_stdout_contains"] not in stdout:
            raise WalkthroughError("command output invariant was not observed")
        first_line = stdout.splitlines()[0] if stdout else "NO_STDOUT"
        lines.extend(
            (
                f"STEP {number:02d} id={step_id} phase={step['phase']}",
                f"  input={step['input'] or 'NONE'}",
                f"  exit={code} semantic={_semantic_label(code)}",
                f"  observed={first_line}",
            )
        )
        input_path = step["input"]
        if input_path is not None:
            value = _read_bounded_json(_safe_relative_file(repository, input_path))
            _validate_step_object(step_id, value)
            lines.append(f"  input_sha256={EXPECTED_SOURCE_SHA256[input_path]}")
            for field in INSPECTION_FIELDS[step_id]:
                lines.append(f"  {field}={_display(_field(value, field))}")
        lines.append(f"  next={step['next_evidence']}")

    if _hashes(sources) != before:
        raise WalkthroughError("canonical source changed during walkthrough")
    external = manifest["external_artifact"]
    lines.append(
        "EXTERNAL_ARTIFACT "
        f"path={external['path']} clean_checkout={external['clean_checkout_status']} "
        "required=NO expected_identity=RECORDED_NOT_OBSERVED"
    )
    if temporary_directory is None:
        lines.append("MALFORMED_INPUT_DEMO status=NOT_RUN default_mode=READ_ONLY")
        malformed_status = "NOT_RUN"
    else:
        lines.append(_run_tamper_demo(repository, temporary_directory))
        malformed_status = "PASS"
    lines.extend(
        (
            "BOUNDARIES declaration!=observation metadata!=payload "
            "artifact!=runtime signature!=authority policy!=safety "
            "finite_probes!=behavior output_digest!=weight_attribution",
            "WALKTHROUGH_COMPLETE "
            f"steps={len(steps)} expected_exit_1=2 malformed_demo={malformed_status} "
            "network=NONE model_execution=NONE repository_writes=NONE",
        )
    )
    return "\n".join(lines) + "\n"


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--temporary-directory",
        type=Path,
        help="Existing directory outside the repository for the optional exit-2 demo.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    repository = Path(__file__).resolve().parents[1]
    try:
        rendered = run_walkthrough(repository, temporary_directory=arguments.temporary_directory)
    except WalkthroughError as exc:
        print(f"WALKTHROUGH_ERROR reason={exc}", file=sys.stderr)
        return 2
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
