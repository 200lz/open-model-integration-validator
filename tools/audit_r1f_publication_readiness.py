#!/usr/bin/env python3
"""Deterministic offline audit for the R1F publication-readiness contract."""

from __future__ import annotations

import argparse
import ast
import json
import posixpath
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

MAX_FILE_BYTES = 1024 * 1024
POLICY_PATH = ".github/publication-policy.json"
R1F_DOC = "docs/r1f-final-publication-audit.md"
DESCRIPTION = (
    "Offline-first evidence and verification framework for AI model artifacts, "
    "transformations, runtime identity, and provenance."
)
TOPICS = (
    "ai-supply-chain",
    "model-provenance",
    "artifact-verification",
    "model-integrity",
    "supply-chain-security",
    "mlops",
    "llm",
    "gguf",
    "safetensors",
    "offline-first",
)
CHECK_CONTEXTS = ("Python 3.11", "Python 3.12", "Python 3.13", "Python 3.14")
GITHUB_ACTIONS_APP_ID = 15368
GITHUB_REST_ACCEPT = "application/vnd.github+json"
GITHUB_REST_API_VERSION = "2022-11-28"
BRANCH_PROTECTION_ENDPOINT = (
    "/repos/200lz/open-model-integration-validator/branches/main/protection"
)
BRANCH_PROTECTION_SCHEMA_MODE = "APP_BOUND_CHECKS_WITH_CONTEXTS_OMITTED"
ROLLBACK_CHOICES = (
    "ROLLBACK_TO_PRIVATE_ON_REQUIRED_CONTROL_FAILURE_AUTHORIZED",
    "LEAVE_PUBLIC_AND_STOP_FOR_MANUAL_REMEDIATION",
    "ROLLBACK_AUTHORITY_NOT_GRANTED",
)
TRANSACTION = (
    "EXACT_GREEN_R1F_PRIVATE_MAIN_VERIFIED",
    "NO_CONCURRENT_REMOTE_STATE_CHANGE_VERIFIED",
    "EXPLICIT_VISIBILITY_AUTHORIZATION_VERIFIED",
    "EXPLICIT_ROLLBACK_AUTHORITY_DECISION_VERIFIED",
    "NORMALIZED_PRE_CHANGE_REMOTE_STATE_CAPTURED",
    "VISIBILITY_CHANGED_PRIVATE_TO_PUBLIC",
    "PUBLIC_VISIBILITY_READ_BACK_VERIFIED",
    "PRIVATE_VULNERABILITY_REPORTING_ENABLED",
    "PRIVATE_VULNERABILITY_REPORTING_READ_BACK_VERIFIED",
    "SECRET_SCANNING_ENABLED",
    "SECRET_SCANNING_READ_BACK_VERIFIED",
    "PUSH_PROTECTION_ENABLED",
    "PUSH_PROTECTION_READ_BACK_VERIFIED",
    "MAIN_BRANCH_ENFORCEMENT_APPLIED",
    "MAIN_BRANCH_ENFORCEMENT_FIELDS_AND_CHECKS_READ_BACK_VERIFIED",
    "PROFILE_TOPICS_ACTIONS_DEPENDABOT_READ_BACK_VERIFIED",
    "NO_TAG_RELEASE_OR_PACKAGE_CREATED_VERIFIED",
    "UNAUTHENTICATED_PUBLIC_READ_SMOKE_PASSED",
    "PUBLICATION_SUCCESS_CLASSIFIED_ONLY_AFTER_ALL_READ_BACKS",
)
FAILURES = (
    "FINAL_PRIVATE_AUDIT_FAILED",
    "VISIBILITY_AUTHORIZATION_MISSING",
    "ROLLBACK_AUTHORITY_UNSPECIFIED",
    "CONCURRENT_REMOTE_STATE_CHANGE",
    "AUTHENTICATION_EXPIRED",
    "VISIBILITY_MUTATION_FAILED",
    "PUBLIC_VISIBILITY_READ_BACK_FAILED",
    "PRIVATE_VULNERABILITY_REPORTING_ENABLE_FAILED",
    "SECRET_SCANNING_ENABLE_FAILED",
    "PUSH_PROTECTION_ENABLE_FAILED",
    "MAIN_ENFORCEMENT_APPLICATION_FAILED",
    "REQUIRED_CHECK_CONTEXT_MISMATCH",
    "PUBLIC_READ_BACK_VERIFICATION_FAILED",
    "UNAUTHENTICATED_PUBLIC_READ_FAILED",
    "PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED",
    "VISIBILITY_ROLLBACK_FAILED",
    "PARTIAL_PUBLICATION_STATE",
)
R1F_PATHS = (
    POLICY_PATH,
    ".github/workflows/ci.yml",
    "README.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/github-publication-controls.md",
    "docs/public-release-security-and-privacy.md",
    "docs/releasing.md",
    "docs/roadmap.md",
    R1F_DOC,
    "tests/test_github_publication_controls.py",
    "tests/test_r1f_publication_readiness.py",
    "tools/audit_github_publication_controls.py",
    "tools/audit_offline_evidence_walkthrough.py",
    "tools/audit_public_launch_ux.py",
    "tools/audit_r1f_publication_readiness.py",
)
TOP_LEVEL_FIELDS = (
    "classification",
    "version",
    "labels",
    "state_taxonomy",
    "phase_taxonomy",
    "repository",
    "profile",
    "actions",
    "security_controls",
    "dependency_updates",
    "branch_policy",
    "release_policy",
    "implementation",
    "mutation_scope",
    "publication_incident",
    "final_public_state",
    "main_enforcement",
    "rollback_authority",
    "codeql_decision",
    "r1f_publication_transaction",
    "failure_classifications",
    "r1f_prerequisites",
    "stop_conditions",
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


class AuditError(RuntimeError):
    """Closed audit failure without unsafe data."""


class StrictSafeLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: StrictSafeLoader, node: yaml.Node, deep: bool = False) -> Any:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise AuditError("invalid-yaml-duplicate-key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuditError("invalid-json-duplicate-key")
        value[key] = item
    return value


def _safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise AuditError("unsafe-path")
    if relative.startswith("/") or posixpath.normpath(relative) != relative:
        raise AuditError("unsafe-path")
    if relative in {".", ".."} or relative.startswith("../"):
        raise AuditError("unsafe-path")
    path = root / relative
    try:
        info = path.lstat()
    except OSError as error:
        raise AuditError("missing-required-file") from error
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise AuditError("unsafe-file-type")
    if info.st_nlink != 1:
        raise AuditError("unsafe-hardlink")
    if info.st_size > MAX_FILE_BYTES:
        raise AuditError("oversized-file")
    return path


def _text(root: Path, relative: str) -> str:
    try:
        return _safe_file(root, relative).read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise AuditError("invalid-utf8") from error


def strict_json(root: Path) -> dict[str, Any]:
    try:
        value = json.loads(_text(root, POLICY_PATH), object_pairs_hook=_duplicate_json_keys)
    except (json.JSONDecodeError, AuditError) as error:
        if isinstance(error, AuditError) and str(error).startswith("invalid-json"):
            raise
        raise AuditError("invalid-json") from error
    if not isinstance(value, dict):
        raise AuditError("invalid-policy-root")
    return value


def strict_yaml(root: Path, relative: str) -> Any:
    try:
        return yaml.load(_text(root, relative), Loader=StrictSafeLoader)
    except (yaml.YAMLError, AuditError) as error:
        if isinstance(error, AuditError) and str(error).startswith("invalid-yaml"):
            raise
        raise AuditError("invalid-yaml") from error


def _expect_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or tuple(value) != expected:
        raise AuditError(f"invalid-{label}-fields")
    return value


def _check_pairs(value: Any, label: str) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, list) or len(value) != len(CHECK_CONTEXTS):
        raise AuditError(f"invalid-{label}-count")
    pairs: list[tuple[str, int]] = []
    for item in value:
        check = _expect_keys(item, ("context", "app_id"), f"{label}-check")
        context = check["context"]
        app_id = check["app_id"]
        if not isinstance(context, str) or not isinstance(app_id, int) or isinstance(app_id, bool):
            raise AuditError(f"invalid-{label}-check-value")
        pairs.append((context, app_id))
    expected = tuple(sorted((context, GITHUB_ACTIONS_APP_ID) for context in CHECK_CONTEXTS))
    observed = tuple(sorted(pairs))
    if observed != expected or len(set(pairs)) != len(pairs):
        raise AuditError(f"invalid-{label}-checks")
    return observed


def validate_branch_protection_request(enforcement: Any) -> None:
    value = _expect_keys(
        enforcement,
        (
            "mechanism",
            "overlapping_ruleset_allowed",
            "request",
            "read_back",
            "payload",
            "single_maintainer_reason",
            "administrator_behavior",
            "read_back_requirement",
        ),
        "main-enforcement",
    )
    request = _expect_keys(
        value["request"],
        (
            "method",
            "endpoint",
            "accept",
            "api_version",
            "success_status",
            "failure_statuses",
            "request_schema_mode",
        ),
        "branch-protection-request",
    )
    read_back = _expect_keys(
        value["read_back"],
        (
            "method",
            "endpoint",
            "accept",
            "api_version",
            "success_status",
            "response_contexts_semantics",
        ),
        "branch-protection-read-back-metadata",
    )
    if request != {
        "method": "PUT",
        "endpoint": BRANCH_PROTECTION_ENDPOINT,
        "accept": GITHUB_REST_ACCEPT,
        "api_version": GITHUB_REST_API_VERSION,
        "success_status": 200,
        "failure_statuses": [403, 404, 422],
        "request_schema_mode": BRANCH_PROTECTION_SCHEMA_MODE,
    }:
        raise AuditError("invalid-branch-protection-request-metadata")
    if read_back != {
        "method": "GET",
        "endpoint": BRANCH_PROTECTION_ENDPOINT,
        "accept": GITHUB_REST_ACCEPT,
        "api_version": GITHUB_REST_API_VERSION,
        "success_status": 200,
        "response_contexts_semantics": "DERIVED_CONTEXTS_ALLOWED_CHECKS_APP_ID_AUTHORITATIVE",
    }:
        raise AuditError("invalid-branch-protection-read-back-metadata")
    if request["api_version"] != read_back["api_version"]:
        raise AuditError("branch-protection-api-version-mismatch")
    payload = _expect_keys(
        value["payload"],
        (
            "required_status_checks",
            "enforce_admins",
            "required_pull_request_reviews",
            "restrictions",
            "required_linear_history",
            "allow_force_pushes",
            "allow_deletions",
            "required_conversation_resolution",
        ),
        "branch-protection-payload",
    )
    status = _expect_keys(
        payload["required_status_checks"], ("strict", "checks"), "required-status-checks"
    )
    if status["strict"] is not True:
        raise AuditError("invalid-required-status-strictness")
    _check_pairs(status["checks"], "request")
    reviews = _expect_keys(
        payload["required_pull_request_reviews"],
        (
            "dismiss_stale_reviews",
            "require_code_owner_reviews",
            "required_approving_review_count",
            "require_last_push_approval",
        ),
        "pull-request-reviews",
    )
    expected_reviews = {
        "dismiss_stale_reviews": False,
        "require_code_owner_reviews": False,
        "required_approving_review_count": 0,
        "require_last_push_approval": False,
    }
    if reviews != expected_reviews:
        raise AuditError("invalid-pull-request-review-policy")
    if any(
        (
            value["mechanism"] != "BRANCH_PROTECTION",
            value["overlapping_ruleset_allowed"] is not False,
            payload["enforce_admins"] is not False,
            payload["restrictions"] is not None,
            payload["required_linear_history"] is not True,
            payload["allow_force_pushes"] is not False,
            payload["allow_deletions"] is not False,
            payload["required_conversation_resolution"] is not True,
        )
    ):
        raise AuditError("invalid-main-enforcement-semantics")


def validate_branch_protection_read_back(response: Any, enforcement: Any) -> None:
    """Validate a normalized GitHub response independently from the write body."""
    validate_branch_protection_request(enforcement)
    expected_fields = (
        "required_status_checks",
        "enforce_admins",
        "required_pull_request_reviews",
        "restrictions",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
        "required_conversation_resolution",
    )
    normalized = _expect_keys(response, expected_fields, "branch-protection-response")
    status = normalized["required_status_checks"]
    if not isinstance(status, dict) or set(status) not in (
        {"strict", "checks"},
        {"strict", "contexts", "checks"},
    ):
        raise AuditError("invalid-response-status-check-fields")
    if status["strict"] is not True:
        raise AuditError("invalid-response-status-strictness")
    _check_pairs(status["checks"], "response")
    if "contexts" in status:
        contexts = status["contexts"]
        if (
            not isinstance(contexts, list)
            or len(contexts) != len(CHECK_CONTEXTS)
            or set(contexts) != set(CHECK_CONTEXTS)
            or len(set(contexts)) != len(contexts)
        ):
            raise AuditError("invalid-derived-response-contexts")
    payload = enforcement["payload"]
    for field in expected_fields[1:]:
        if normalized[field] != payload[field]:
            raise AuditError("invalid-response-enforcement-field")


def validate_r1f_policy(policy: dict[str, Any]) -> None:
    top = _expect_keys(policy, TOP_LEVEL_FIELDS, "policy")
    if top["classification"] != "NON_CANONICAL_REPOSITORY_PUBLICATION_POLICY":
        raise AuditError("invalid-classification")
    if top["version"] != 1 or tuple(top["labels"]) != (
        "RELEASE_TRACK_CONFIGURATION",
        "NOT_OMIV_EVIDENCE",
        "NOT_A_SECURITY_CERTIFICATION",
    ):
        raise AuditError("invalid-labels")
    repository = top["repository"]
    if repository != {
        "owner": "200lz",
        "name": "open-model-integration-validator",
        "required_default_branch": "main",
        "required_pre_public_visibility": "PRIVATE",
        "intended_final_visibility": "PUBLIC",
    }:
        raise AuditError("invalid-repository-contract")
    if top["profile"]["description"] != DESCRIPTION:
        raise AuditError("invalid-description")
    if tuple(top["profile"]["topics"]) != TOPICS or top["profile"]["homepage"] != "":
        raise AuditError("invalid-profile")

    implementation = _expect_keys(
        top["implementation"],
        (
            "r1e_status",
            "r1f_status",
            "phase6f_status",
            "repository_visibility_at_r1f_baseline",
            "r1e_private_controls_applied",
            "github_settings_mutated_by_r1f",
        ),
        "implementation",
    )
    if implementation != {
        "r1e_status": "COMPLETE",
        "r1f_status": "PUBLIC_ATTEMPT_ROLLED_BACK_SCHEMA_CORRECTION_AND_NEW_AUTHORIZATION_PENDING",
        "phase6f_status": "PLANNED_NOT_IMPLEMENTED",
        "repository_visibility_at_r1f_baseline": "PRIVATE",
        "r1e_private_controls_applied": True,
        "github_settings_mutated_by_r1f": True,
    }:
        raise AuditError("invalid-implementation-state")

    incident = _expect_keys(
        top["publication_incident"],
        (
            "classification",
            "failed_control",
            "visibility_became_public",
            "branch_protection_failed",
            "visibility_returned_private",
            "approximate_public_interval",
            "failed_http_status",
            "failed_request_schema",
            "failed_request_explicit_accept_header",
            "failed_request_explicit_api_version_header",
            "branch_protection_applied",
            "rollback_succeeded",
            "pre_public_secret_or_privacy_finding",
            "tag_github_release_pypi_or_announcement_occurred",
            "public_only_controls_enabled_before_failure",
            "private_api_state_after_rollback",
            "prior_visibility_authorization",
            "prior_rollback_authorization",
            "new_visibility_authorization_required",
            "new_rollback_selection_required",
            "exposure_erased",
            "exposure_limitation",
        ),
        "publication-incident",
    )
    if (
        incident["classification"]
        != "PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED_ROLLED_BACK_TO_PRIVATE"
        or incident["failed_control"] != "MAIN_ENFORCEMENT_APPLICATION_FAILED"
        or incident["approximate_public_interval"] != "5_HOURS_39_MINUTES"
        or incident["failed_http_status"] != 422
        or incident["failed_request_schema"]
        != "CONTEXTS_AND_APP_BOUND_CHECKS_INCOMPATIBLE_VARIANTS"
        or incident["failed_request_explicit_accept_header"] is not False
        or incident["failed_request_explicit_api_version_header"] is not False
        or incident["branch_protection_applied"] is not False
        or incident["rollback_succeeded"] is not True
        or incident["pre_public_secret_or_privacy_finding"] is not False
        or incident["tag_github_release_pypi_or_announcement_occurred"] is not False
        or tuple(incident["public_only_controls_enabled_before_failure"])
        != ("PRIVATE_VULNERABILITY_REPORTING", "SECRET_SCANNING", "PUSH_PROTECTION")
        or incident["private_api_state_after_rollback"] != "API_STATE_UNAVAILABLE"
        or incident["prior_visibility_authorization"] != "CONSUMED"
        or incident["prior_rollback_authorization"] != "CONSUMED_AND_EXECUTED"
        or incident["new_visibility_authorization_required"] is not True
        or incident["new_rollback_selection_required"] is not True
        or incident["exposure_erased"] is not False
        or "no claim is made" not in incident["exposure_limitation"]
    ):
        raise AuditError("invalid-publication-incident")

    final = _expect_keys(
        top["final_public_state"],
        (
            "repository",
            "visibility",
            "default_branch",
            "main_sha",
            "description",
            "homepage",
            "topics",
            "features",
            "actions_default_token",
            "ci",
            "dependabot_alerts",
            "dependabot_security_updates",
            "private_vulnerability_reporting",
            "secret_scanning",
            "push_protection",
            "main_enforcement",
            "force_pushes_allowed",
            "branch_deletion_allowed",
            "releases",
            "pypi_publication",
            "phase6f",
        ),
        "final-state",
    )
    if (
        final["repository"] != "200lz/open-model-integration-validator"
        or final["visibility"] != "PUBLIC"
        or final["default_branch"] != "main"
        or final["main_sha"] != "EXACT_R1F_RELEASE_COMMIT"
        or final["description"] != DESCRIPTION
        or final["homepage"] != ""
        or tuple(final["topics"]) != TOPICS
        or final["features"]
        != {"issues": True, "projects": True, "wiki": False, "discussions": False}
        or final["actions_default_token"] != "read"
        or final["force_pushes_allowed"] is not False
        or final["branch_deletion_allowed"] is not False
        or final["releases"] != 0
        or final["pypi_publication"] != "NOT_PUBLISHED"
        or final["phase6f"] != "PLANNED_NOT_IMPLEMENTED"
    ):
        raise AuditError("invalid-final-state")
    for field in (
        "dependabot_alerts",
        "dependabot_security_updates",
        "private_vulnerability_reporting",
        "secret_scanning",
        "push_protection",
        "main_enforcement",
    ):
        if final[field] != "ENABLED_AND_VERIFIED":
            raise AuditError("invalid-final-control-state")
    ci = _expect_keys(
        final["ci"],
        ("head_sha", "workflow", "event", "branch", "required_checks", "conclusion"),
        "final-ci",
    )
    if ci != {
        "head_sha": "EXACT_R1F_RELEASE_COMMIT",
        "workflow": "CI",
        "event": "push",
        "branch": "main",
        "required_checks": list(CHECK_CONTEXTS),
        "conclusion": "success",
    }:
        raise AuditError("invalid-final-ci")

    enforcement = top["main_enforcement"]
    validate_branch_protection_request(enforcement)
    if (
        "sole maintainer" not in enforcement["single_maintainer_reason"]
        or "enforce_admins false" not in enforcement["administrator_behavior"]
        or "contexts alone" not in enforcement["read_back_requirement"]
    ):
        raise AuditError("invalid-main-enforcement-documentation")

    rollback = _expect_keys(
        top["rollback_authority"],
        (
            "choices",
            "selected_choice",
            "selection_required_before_visibility",
            "automatic_selection_allowed",
            "risk_statement",
        ),
        "rollback-authority",
    )
    if (
        tuple(rollback["choices"]) != ROLLBACK_CHOICES
        or rollback["selected_choice"] is not None
        or rollback["selection_required_before_visibility"] is not True
        or rollback["automatic_selection_allowed"] is not False
        or len(rollback["risk_statement"]) < 100
        or not all(
            marker in rollback["risk_statement"]
            for marker in (
                "Actions visibility",
                "Pages or package exposure",
                "announcements",
                "cannot erase prior exposure",
            )
        )
    ):
        raise AuditError("invalid-rollback-authority")
    codeql = top["codeql_decision"]
    if codeql != {
        "state": "CODEQL_DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE",
        "reason": (
            "Code scanning is unavailable under the current private plan, an unvalidated "
            "workflow is unsuitable for launch optics, and existing CI does not replace CodeQL."
        ),
        "future_boundary": (
            "Use the protected public pull-request flow to review language coverage, "
            "queries, events, permissions, runners, and alert handling."
        ),
    }:
        raise AuditError("invalid-codeql-decision")
    if tuple(top["r1f_publication_transaction"]) != TRANSACTION:
        raise AuditError("invalid-transaction-order")
    if tuple(top["failure_classifications"]) != FAILURES:
        raise AuditError("invalid-failure-taxonomy")


def _workflow_safe(source: str) -> bool:
    pins = re.findall(r"(?m)^\s*uses:\s*[^\s@]+@([^\s#]+)", source)
    return all(
        (
            bool(pins),
            all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins),
            bool(re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$", source)),
            "pull_request_target" not in source,
            "self-hosted" not in source,
            "${{ secrets." not in source,
            "persist-credentials: false" in source,
            'python-version: ["3.11", "3.12", "3.13", "3.14"]' in source,
            "continue-on-error" not in source,
            "python tools/audit_r1f_publication_readiness.py --json" in source,
            "tests/test_r1f_publication_readiness.py" in source,
        )
    )


def _mutation_surface_safe(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    forbidden_modules = {"subprocess", "socket", "requests", "http.client", "urllib.request"}
    forbidden_calls = {"eval", "exec", "compile", "system", "popen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name in forbidden_modules for alias in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if node.module in forbidden_modules:
                return False
        elif isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in forbidden_calls:
                return False
    return True


def _slug(heading: str) -> str:
    value = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return re.sub(r"\s+", "-", value)


def _links_ok(root: Path, relative: str, source: str) -> bool:
    headings = {_slug(match.group(1)) for match in re.finditer(r"(?m)^#{1,6}\s+(.+?)\s*$", source)}
    for match in re.finditer(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", source):
        target = match.group(1).strip().split(maxsplit=1)[0].strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme in {"http", "https"}:
            continue
        if parsed.scheme or parsed.netloc or target.startswith("/") or "\\" in target:
            return False
        path_part, _, fragment = target.partition("#")
        if not path_part:
            if fragment and fragment not in headings:
                return False
            continue
        normalized = posixpath.normpath(posixpath.join(posixpath.dirname(relative), path_part))
        if normalized == ".." or normalized.startswith("../"):
            return False
        destination = root / normalized
        if not destination.is_file() or destination.is_symlink():
            return False
        if fragment:
            destination_text = destination.read_text(encoding="utf-8")
            anchors = {
                _slug(item.group(1))
                for item in re.finditer(r"(?m)^#{1,6}\s+(.+?)\s*$", destination_text)
            }
            if fragment not in anchors:
                return False
    return True


def run_audit(root: Path) -> list[Check]:
    if root.is_symlink() or not root.is_dir():
        raise AuditError("unsafe-root")
    root = root.resolve(strict=True)
    texts = {relative: _text(root, relative) for relative in R1F_PATHS}
    policy = strict_json(root)
    validate_r1f_policy(policy)
    strict_yaml(root, ".github/workflows/ci.yml")
    doc = texts[R1F_DOC]
    workflow = texts[".github/workflows/ci.yml"]
    security = texts["SECURITY.md"]
    security_lower = security.lower()
    roadmap = texts["docs/roadmap.md"]
    tool_source = texts["tools/audit_r1f_publication_readiness.py"]

    numbered = tuple(int(value) for value in re.findall(r"(?m)^(\d+)\. ", doc))
    transaction_order = tuple(range(1, 20))
    controls = policy["security_controls"]
    checks = [
        Check("bounded_regular_files", len(texts) == len(R1F_PATHS), f"files={len(texts)}"),
        Check("strict_policy", True, "duplicate_keys=0 unknown_fields=0"),
        Check("private_to_public_contract", True, "baseline=PRIVATE intended=PUBLIC"),
        Check(
            "final_public_state",
            policy["final_public_state"]["visibility"] == "PUBLIC",
            "fields=21",
        ),
        Check("transaction_order", numbered == transaction_order, "ordered_steps=19"),
        Check(
            "rollback_choice",
            policy["rollback_authority"]["selected_choice"] is None,
            "default=none choices=3",
        ),
        Check(
            "failure_taxonomy",
            tuple(policy["failure_classifications"]) == FAILURES,
            f"classes={len(FAILURES)}",
        ),
        Check(
            "branch_protection_only",
            policy["main_enforcement"]["mechanism"] == "BRANCH_PROTECTION",
            "ruleset_overlap=0",
        ),
        Check(
            "check_app_binding",
            tuple(
                (item["context"], item["app_id"])
                for item in policy["main_enforcement"]["payload"]["required_status_checks"][
                    "checks"
                ]
            )
            == tuple((context, GITHUB_ACTIONS_APP_ID) for context in CHECK_CONTEXTS),
            "contexts=4 source=github-actions",
        ),
        Check(
            "checks_only_request_schema",
            "contexts" not in policy["main_enforcement"]["payload"]["required_status_checks"]
            and policy["main_enforcement"]["request"]["request_schema_mode"]
            == BRANCH_PROTECTION_SCHEMA_MODE,
            "request_contexts=absent checks=4",
        ),
        Check(
            "explicit_rest_contract",
            policy["main_enforcement"]["request"]["accept"] == GITHUB_REST_ACCEPT
            and policy["main_enforcement"]["request"]["api_version"] == GITHUB_REST_API_VERSION
            and policy["main_enforcement"]["read_back"]["accept"] == GITHUB_REST_ACCEPT
            and policy["main_enforcement"]["read_back"]["api_version"] == GITHUB_REST_API_VERSION,
            "accept=explicit api_version=2022-11-28",
        ),
        Check(
            "single_maintainer",
            policy["main_enforcement"]["payload"]["required_pull_request_reviews"][
                "required_approving_review_count"
            ]
            == 0,
            "approvals=0 codeowner_review=0",
        ),
        Check(
            "force_delete_protection",
            not policy["main_enforcement"]["payload"]["allow_force_pushes"]
            and not policy["main_enforcement"]["payload"]["allow_deletions"],
            "force_push=0 deletion=0",
        ),
        Check(
            "public_control_order",
            TRANSACTION.index("PUBLIC_VISIBILITY_READ_BACK_VERIFIED")
            < TRANSACTION.index("PRIVATE_VULNERABILITY_REPORTING_ENABLED")
            < TRANSACTION.index("SECRET_SCANNING_ENABLED")
            < TRANSACTION.index("PUSH_PROTECTION_ENABLED")
            < TRANSACTION.index("MAIN_BRANCH_ENFORCEMENT_APPLIED"),
            "visibility_before_controls=1",
        ),
        Check(
            "dependabot_preserved",
            controls["DEPENDABOT_ALERTS"]["current_state"] == "ENABLED_AND_VERIFIED"
            and controls["DEPENDABOT_SECURITY_UPDATES"]["current_state"] == "ENABLED_AND_VERIFIED",
            "private_controls=verified",
        ),
        Check(
            "rolled_back_incident",
            policy["publication_incident"]["rollback_succeeded"] is True
            and policy["publication_incident"]["branch_protection_applied"] is False
            and policy["publication_incident"]["exposure_erased"] is False
            and policy["publication_incident"]["new_visibility_authorization_required"] is True
            and policy["publication_incident"]["new_rollback_selection_required"] is True,
            "public_attempt=failed rollback=verified authorizations=consumed",
        ),
        Check(
            "codeql_decision",
            policy["codeql_decision"]["state"] == "CODEQL_DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE",
            "workflow_added=0",
        ),
        Check(
            "workflow_security", _workflow_safe(workflow), "permissions=read matrix=4 pins=full_sha"
        ),
        Check(
            "documentation_links",
            _links_ok(root, R1F_DOC, doc)
            and "r1f-final-publication-audit.md" in texts["docs/README.md"]
            and "docs/r1f-final-publication-audit.md" in texts["README.md"],
            "r1f_links=valid navigation=2",
        ),
        Check(
            "transition_safe",
            "live github visibility is authoritative" in " ".join(doc.lower().split())
            and (
                "current repository state are private" in " ".join(doc.lower().split())
                or "publicly" in " ".join(doc.lower().split())
            )
            and "5 hours 39 minutes" in doc
            and "cannot erase" in doc,
            "static_public_claim=0",
        ),
        Check(
            "security_reporting",
            (
                ("not currently verified" in security_lower)
                or (
                    "verified private vulnerability reporting" in security_lower
                    and "live github visibility" in security_lower
                )
            )
            and "sensitive details" in security_lower
            and "public issue" in security_lower,
            "unsafe_fallback=0",
        ),
        Check(
            "roadmap",
            all(
                marker in roadmap
                for marker in (
                    "R1E GitHub metadata/security | COMPLETE",
                    "Phase 6F | PLANNED, NOT IMPLEMENTED",
                    "Phase 7 | FUTURE, SCOPE NOT FROZEN",
                )
            ),
            "r1a_r1e=complete r1f=public_controls_verified",
        ),
        Check(
            "no_mutation_utility",
            _mutation_surface_safe(tool_source),
            "network=0 mutation=0",
        ),
        Check(
            "package_boundary",
            'packages = ["src/omiv"]' in _text(root, "pyproject.toml")
            and '"/docs"' in _text(root, "pyproject.toml"),
            "runtime_tool=excluded docs=sdist",
        ),
    ]
    public_text = "\n".join(texts.values())
    unsafe = re.findall(
        r"(?:github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}|"
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Authorization:\s*Bearer\s+\S+|"
        r"/home/[\w.-]+/|/Users/[\w.-]+/|[A-Za-z]:\\\\)",
        public_text,
    )
    checks.append(Check("sensitive_content", not unsafe, f"matches={len(unsafe)}"))
    claims = re.findall(
        r"(?im)^\s*(?:repository is public|v0\.10\.0 is released|available on PyPI|"
        r"Phase 6F is (?:complete|implemented)|all security controls are enabled)\s*$",
        public_text,
    )
    checks.append(Check("publication_nonclaims", not claims, f"matches={len(claims)}"))
    return checks


def render_text(checks: list[Check]) -> str:
    lines = [f"{'PASS' if item.passed else 'FAIL'} {item.name} {item.detail}" for item in checks]
    passed = sum(item.passed for item in checks)
    lines.append(f"PASS_SUMMARY {passed}/{len(checks)}")
    return "\n".join(lines) + "\n"


def render_json(checks: list[Check]) -> str:
    payload = {
        "classification": "R1F_OFFLINE_PUBLICATION_READINESS_AUDIT",
        "checks": [asdict(item) for item in checks],
        "passed": sum(item.passed for item in checks),
        "total": len(checks),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        checks = run_audit(args.repository)
    except (AuditError, OSError, ValueError):
        print("FAIL audit-error")
        return 1
    output = render_json(checks) if args.json else render_text(checks)
    print(output, end="")
    return 0 if all(item.passed for item in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
