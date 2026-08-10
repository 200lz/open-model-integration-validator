#!/usr/bin/env python3
"""Deterministic offline audit for OMIV's repository publication controls."""

from __future__ import annotations

import argparse
import json
import posixpath
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

MAX_FILE_BYTES = 1024 * 1024
POLICY_PATH = ".github/publication-policy.json"
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
LABELS = (
    "RELEASE_TRACK_CONFIGURATION",
    "NOT_OMIV_EVIDENCE",
    "NOT_A_SECURITY_CERTIFICATION",
)
STATE_TAXONOMY = (
    "ENABLED_AND_VERIFIED",
    "DISABLED",
    "NOT_CONFIGURED",
    "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
    "API_STATE_UNAVAILABLE",
    "DEFERRED_TO_R1F",
    "DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE",
    "INVALID",
)
PHASE_TAXONOMY = (
    "CONFIGURED_NOW",
    "PROPOSED_FOR_R1E_RELEASE",
    "REQUIRED_IMMEDIATELY_BEFORE_PUBLIC_VISIBILITY",
    "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE",
    "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
    "MANUALLY_DEFERRED",
    "R1F_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY",
)
SECURITY_CONTROLS = (
    "PRIVATE_VULNERABILITY_REPORTING",
    "SECRET_SCANNING",
    "PUSH_PROTECTION",
    "DEPENDABOT_ALERTS",
    "DEPENDABOT_SECURITY_UPDATES",
    "CODE_SCANNING",
    "BRANCH_PROTECTION",
    "REPOSITORY_RULESETS",
    "ACTIONS_DEFAULT_PERMISSIONS",
    "ACTION_PINNING",
    "FORCE_PUSH_PROTECTION",
    "BRANCH_DELETION_PROTECTION",
)
CONTROL_FIELDS = (
    "current_state",
    "target_state",
    "application_phase",
    "reason",
    "observation_source",
    "observation_limitation",
    "verification_method",
    "failure_behavior",
)
CONTROL_STATES = {
    "PRIVATE_VULNERABILITY_REPORTING": (
        "API_STATE_UNAVAILABLE",
        "DEFERRED_TO_R1F",
        "R1F_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY",
    ),
    "SECRET_SCANNING": (
        "DISABLED",
        "ENABLED_AND_VERIFIED",
        "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE",
    ),
    "PUSH_PROTECTION": (
        "NOT_CONFIGURED",
        "ENABLED_AND_VERIFIED",
        "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE",
    ),
    "DEPENDABOT_ALERTS": (
        "ENABLED_AND_VERIFIED",
        "ENABLED_AND_VERIFIED",
        "CONFIGURED_NOW",
    ),
    "DEPENDABOT_SECURITY_UPDATES": (
        "ENABLED_AND_VERIFIED",
        "ENABLED_AND_VERIFIED",
        "CONFIGURED_NOW",
    ),
    "CODE_SCANNING": (
        "NOT_CONFIGURED",
        "DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE",
        "MANUALLY_DEFERRED",
    ),
    "BRANCH_PROTECTION": (
        "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
        "ENABLED_AND_VERIFIED",
        "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE",
    ),
    "REPOSITORY_RULESETS": (
        "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
        "NOT_CONFIGURED",
        "MANUALLY_DEFERRED",
    ),
    "ACTIONS_DEFAULT_PERMISSIONS": (
        "ENABLED_AND_VERIFIED",
        "ENABLED_AND_VERIFIED",
        "CONFIGURED_NOW",
    ),
    "ACTION_PINNING": (
        "ENABLED_AND_VERIFIED",
        "ENABLED_AND_VERIFIED",
        "CONFIGURED_NOW",
    ),
    "FORCE_PUSH_PROTECTION": (
        "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
        "ENABLED_AND_VERIFIED",
        "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE",
    ),
    "BRANCH_DELETION_PROTECTION": (
        "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
        "ENABLED_AND_VERIFIED",
        "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE",
    ),
}
R1E_PRIVATE_MUTATIONS = (
    "REPOSITORY_PROFILE",
    "REPOSITORY_TOPICS",
    "DEPENDABOT_ALERTS",
    "DEPENDABOT_SECURITY_UPDATES",
)
R1E_PROHIBITED_MUTATIONS = (
    "VISIBILITY",
    "PRIVATE_VULNERABILITY_REPORTING",
    "SECRET_SCANNING",
    "PUSH_PROTECTION",
    "BRANCH_PROTECTION",
    "REPOSITORY_RULESETS",
    "FORCE_PUSH_PROTECTION",
    "BRANCH_DELETION_PROTECTION",
    "CODE_SCANNING",
)
R1F_PUBLICATION_TRANSACTION = (
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
FAILURE_CLASSIFICATIONS = (
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
FEATURES = (
    "issues",
    "wiki",
    "discussions",
    "projects",
    "archived",
    "template_repository",
)
R1E_PATHS = (
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    POLICY_PATH,
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/workflows/ci.yml",
    "README.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/github-publication-controls.md",
    "docs/public-release-security-and-privacy.md",
    "docs/r1f-final-publication-audit.md",
    "docs/releasing.md",
    "docs/roadmap.md",
    "tests/test_github_publication_controls.py",
    "tools/audit_github_publication_controls.py",
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


class AuditError(RuntimeError):
    """Bounded fail-closed error that does not include host data."""


class StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: StrictSafeLoader, node: yaml.Node, deep: bool = False) -> Any:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise AuditError("duplicate-yaml-key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate-json-key")
        result[key] = value
    return result


def _safe_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise AuditError("unsafe-path")
    current = root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise AuditError("symlink-path")
    try:
        stat = current.stat()
    except OSError as exc:
        raise AuditError("missing-file") from exc
    if not current.is_file() or stat.st_size > MAX_FILE_BYTES:
        raise AuditError("unsafe-file")
    return current


def _text(root: Path, relative: str) -> str:
    try:
        return _safe_file(root, relative).read_bytes().decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise AuditError("invalid-text") from exc


def strict_json(root: Path, relative: str = POLICY_PATH) -> dict[str, Any]:
    try:
        value = json.loads(_text(root, relative), object_pairs_hook=_duplicate_json_keys)
    except (json.JSONDecodeError, AuditError) as exc:
        raise AuditError("invalid-json") from exc
    if not isinstance(value, dict):
        raise AuditError("json-not-object")
    return value


def strict_yaml(root: Path, relative: str) -> Any:
    try:
        return yaml.load(_text(root, relative), Loader=StrictSafeLoader)
    except (yaml.YAMLError, AuditError) as exc:
        raise AuditError("invalid-yaml") from exc


def _expect_keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or tuple(value) != expected:
        raise AuditError(f"invalid-{label}-fields")
    return value


def _bounded(value: Any, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= 1024 and "\x00" not in value
    if value is None or isinstance(value, (bool, int)):
        return True
    if isinstance(value, list):
        return len(value) <= 64 and all(_bounded(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return len(value) <= 64 and all(
            isinstance(key, str) and _bounded(key, depth + 1) and _bounded(item, depth + 1)
            for key, item in value.items()
        )
    return False


def validate_policy(policy: dict[str, Any]) -> None:
    top = _expect_keys(
        policy,
        (
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
            "final_public_state",
            "main_enforcement",
            "rollback_authority",
            "codeql_decision",
            "r1f_publication_transaction",
            "failure_classifications",
            "r1f_prerequisites",
            "stop_conditions",
        ),
        "policy",
    )
    if not _bounded(top):
        raise AuditError("unbounded-policy")
    if top["classification"] != "NON_CANONICAL_REPOSITORY_PUBLICATION_POLICY":
        raise AuditError("invalid-classification")
    if top["version"] != 1 or tuple(top["labels"]) != LABELS:
        raise AuditError("invalid-labels-or-version")
    if tuple(top["state_taxonomy"]) != STATE_TAXONOMY:
        raise AuditError("invalid-state-taxonomy")
    if tuple(top["phase_taxonomy"]) != PHASE_TAXONOMY:
        raise AuditError("invalid-phase-taxonomy")

    repository = _expect_keys(
        top["repository"],
        (
            "owner",
            "name",
            "required_default_branch",
            "required_pre_public_visibility",
            "intended_final_visibility",
        ),
        "repository",
    )
    if repository != {
        "owner": "200lz",
        "name": "open-model-integration-validator",
        "required_default_branch": "main",
        "required_pre_public_visibility": "PRIVATE",
        "intended_final_visibility": "PUBLIC",
    }:
        raise AuditError("invalid-repository-identity")

    profile = _expect_keys(
        top["profile"],
        ("description", "topics", "homepage", "application_phase", "features"),
        "profile",
    )
    if profile["description"] != DESCRIPTION or tuple(profile["topics"]) != TOPICS:
        raise AuditError("invalid-profile")
    if profile["homepage"] != "" or profile["application_phase"] not in PHASE_TAXONOMY:
        raise AuditError("invalid-profile-boundary")
    if len(TOPICS) > 20 or len(set(TOPICS)) != len(TOPICS):
        raise AuditError("invalid-topic-count")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?", topic) for topic in TOPICS):
        raise AuditError("invalid-topic-syntax")
    if any(
        topic
        in {
            "certified",
            "secure-ai",
            "production-ready",
            "official-xai",
            "official-huggingface",
            "provable-inference",
        }
        for topic in TOPICS
    ):
        raise AuditError("misleading-topic")
    features = _expect_keys(profile["features"], FEATURES, "features")
    expected_features = {
        "issues": (True, "ENABLED_AND_VERIFIED"),
        "wiki": (False, "DISABLED"),
        "discussions": (False, "DISABLED"),
        "projects": (True, "ENABLED_AND_VERIFIED"),
        "archived": (False, "DISABLED"),
        "template_repository": (False, "DISABLED"),
    }
    for name, item in features.items():
        feature = _expect_keys(
            item, ("required", "current_state", "application_phase"), f"feature-{name}"
        )
        if (feature["required"], feature["current_state"]) != expected_features[name]:
            raise AuditError("invalid-feature-state")
        if feature["application_phase"] not in PHASE_TAXONOMY:
            raise AuditError("invalid-feature-phase")

    actions = _expect_keys(
        top["actions"],
        (
            "enabled",
            "default_workflow_permissions",
            "can_approve_pull_request_reviews",
            "workflow_permissions",
            "official_actions_full_sha_pinned",
            "self_hosted_runners_allowed",
            "pull_request_target_allowed",
            "current_state",
            "application_phase",
        ),
        "actions",
    )
    if actions != {
        "enabled": True,
        "default_workflow_permissions": "read",
        "can_approve_pull_request_reviews": False,
        "workflow_permissions": "contents:read",
        "official_actions_full_sha_pinned": True,
        "self_hosted_runners_allowed": False,
        "pull_request_target_allowed": False,
        "current_state": "ENABLED_AND_VERIFIED",
        "application_phase": "CONFIGURED_NOW",
    }:
        raise AuditError("invalid-actions-policy")

    controls = _expect_keys(top["security_controls"], SECURITY_CONTROLS, "controls")
    for name, item in controls.items():
        control = _expect_keys(item, CONTROL_FIELDS, f"control-{name}")
        if control["current_state"] not in STATE_TAXONOMY:
            raise AuditError("invalid-current-state")
        if control["target_state"] not in STATE_TAXONOMY:
            raise AuditError("invalid-target-state")
        if control["application_phase"] not in PHASE_TAXONOMY:
            raise AuditError("invalid-control-phase")
        observed = (
            control["current_state"],
            control["target_state"],
            control["application_phase"],
        )
        if observed != CONTROL_STATES[name]:
            raise AuditError("invalid-control-state-contract")
        for field in CONTROL_FIELDS[3:]:
            if not isinstance(control[field], str) or len(control[field]) < 20:
                raise AuditError("missing-control-semantics")

    dependency = _expect_keys(
        top["dependency_updates"],
        (
            "configuration",
            "ecosystems",
            "schedule",
            "target_branch",
            "open_pull_request_limits",
            "auto_merge",
            "private_registries",
            "review_and_ci_required",
            "application_phase",
        ),
        "dependency-updates",
    )
    if dependency != {
        "configuration": ".github/dependabot.yml",
        "ecosystems": ["pip", "github-actions"],
        "schedule": "monthly",
        "target_branch": "main",
        "open_pull_request_limits": {"pip": 3, "github-actions": 2},
        "auto_merge": False,
        "private_registries": False,
        "review_and_ci_required": True,
        "application_phase": "CONFIGURED_NOW",
    }:
        raise AuditError("invalid-dependency-policy")

    branch = _expect_keys(
        top["branch_policy"],
        (
            "branch",
            "normal_changes_require_pull_request",
            "required_ci_python",
            "required_ci_checks",
            "force_push_allowed",
            "deletion_allowed",
            "linear_history_required",
            "required_approving_reviews",
            "require_code_owner_reviews",
            "required_conversation_resolution",
            "single_maintainer_self_approval_not_claimed",
            "administrator_bypass",
            "enforcement",
            "application_phase",
        ),
        "branch-policy",
    )
    if branch["branch"] != "main" or tuple(branch["required_ci_python"]) != (
        "3.11",
        "3.12",
        "3.13",
        "3.14",
    ):
        raise AuditError("invalid-branch-ci")
    if tuple(branch["required_ci_checks"]) != (
        "Python 3.11",
        "Python 3.12",
        "Python 3.13",
        "Python 3.14",
    ):
        raise AuditError("invalid-branch-check-names")
    if any(
        (
            not branch["normal_changes_require_pull_request"],
            branch["force_push_allowed"],
            branch["deletion_allowed"],
            not branch["linear_history_required"],
            branch["required_approving_reviews"] != 0,
            branch["require_code_owner_reviews"],
            not branch["required_conversation_resolution"],
            not branch["single_maintainer_self_approval_not_claimed"],
        )
    ):
        raise AuditError("invalid-branch-policy")
    if branch["application_phase"] != "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE":
        raise AuditError("invalid-branch-phase")

    release = _expect_keys(
        top["release_policy"],
        (
            "future_release_tags",
            "legacy_tags",
            "github_release_state",
            "pypi_state",
            "tag_release_and_pypi_require_separate_authorization",
        ),
        "release-policy",
    )
    if release != {
        "future_release_tags": "CRYPTOGRAPHICALLY_SIGNED_TAG_REQUIRED",
        "legacy_tags": "LEGACY_UNSIGNED_TAGS_ACCEPTED_WITH_LIMITATION",
        "github_release_state": "NOT_PUBLISHED",
        "pypi_state": "NOT_PUBLISHED",
        "tag_release_and_pypi_require_separate_authorization": True,
    }:
        raise AuditError("invalid-release-policy")

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
        "r1f_status": "IMPLEMENTED_PRIVATE_RELEASE_AND_VISIBILITY_AUTHORIZATION_PENDING",
        "phase6f_status": "PLANNED_NOT_IMPLEMENTED",
        "repository_visibility_at_r1f_baseline": "PRIVATE",
        "r1e_private_controls_applied": True,
        "github_settings_mutated_by_r1f": False,
    }:
        raise AuditError("invalid-implementation-status")

    mutation_scope = _expect_keys(
        top["mutation_scope"],
        (
            "r1e_private_mutations",
            "r1e_prohibited_mutations",
            "visibility_rollback_pre_authorized",
            "r1f_must_decide_rollback_authority_before_visibility",
        ),
        "mutation-scope",
    )
    if (
        tuple(mutation_scope["r1e_private_mutations"]) != R1E_PRIVATE_MUTATIONS
        or tuple(mutation_scope["r1e_prohibited_mutations"]) != R1E_PROHIBITED_MUTATIONS
        or mutation_scope["visibility_rollback_pre_authorized"] is not False
        or mutation_scope["r1f_must_decide_rollback_authority_before_visibility"] is not True
    ):
        raise AuditError("invalid-mutation-scope")
    if tuple(top["r1f_publication_transaction"]) != R1F_PUBLICATION_TRANSACTION:
        raise AuditError("invalid-r1f-publication-transaction")
    if tuple(top["failure_classifications"]) != FAILURE_CLASSIFICATIONS:
        raise AuditError("invalid-failure-classifications")
    if not isinstance(top["r1f_prerequisites"], list) or len(top["r1f_prerequisites"]) != 6:
        raise AuditError("invalid-r1f-prerequisites")
    if not isinstance(top["stop_conditions"], list) or len(top["stop_conditions"]) != 11:
        raise AuditError("invalid-stop-conditions")


def _workflow_checks(source: str) -> tuple[bool, bool, bool, bool, int]:
    pins = re.findall(r"(?m)^\s*uses:\s*[^\s@]+@([^\s#]+)", source)
    pins_ok = bool(pins) and all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins)
    permissions_ok = bool(re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$", source))
    unsafe = bool(
        re.search(r"(?m)^\s*pull_request_target\s*:", source)
        or re.search(r"(?m)^\s*runs-on:\s*.*self-hosted", source)
        or re.search(r"(?m)^\s*[a-z][a-z-]*:\s*write\s*$", source)
        or re.search(r"(?m)^\s*permissions:\s*write-all\s*$", source)
        or re.search(r"\$\{\{\s*secrets\.", source)
        or re.search(r"(?m)^\s*continue-on-error\s*:\s*true\s*$", source)
    )
    isolation_ok = all(
        (
            "fetch-depth: 0" in source,
            "persist-credentials: false" in source,
            'python-version: ["3.11", "3.12", "3.13", "3.14"]' in source,
            'OMIV_RUN_CONVERSION_INTEGRATION: "0"' in source,
            'OMIV_RUN_GGUF_INTEGRATION: "0"' in source,
            'OMIV_RUN_HF_INTEGRATION: "0"' in source,
            'OMIV_RUN_MAPPING_INTEGRATION: "0"' in source,
            'OMIV_RUN_REMOTE_INTEGRATION: "0"' in source,
            "python tools/audit_github_publication_controls.py --json" in source,
            "tests/test_github_publication_controls.py" in source,
        )
    )
    return pins_ok, permissions_ok, not unsafe, isolation_ok, len(pins)


def _dependabot_ok(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"version", "updates"}:
        return False
    updates = value.get("updates")
    if value.get("version") != 2 or not isinstance(updates, list) or len(updates) != 2:
        return False
    expected = (("pip", 3, "deps"), ("github-actions", 2, "ci"))
    for entry, (ecosystem, limit, prefix) in zip(updates, expected, strict=True):
        if not isinstance(entry, dict) or set(entry) != {
            "package-ecosystem",
            "directory",
            "target-branch",
            "schedule",
            "open-pull-requests-limit",
            "commit-message",
        }:
            return False
        if entry != {
            "package-ecosystem": ecosystem,
            "directory": "/",
            "target-branch": "main",
            "schedule": {"interval": "monthly"},
            "open-pull-requests-limit": limit,
            "commit-message": {"prefix": prefix},
        }:
            return False
    return True


def _markdown_targets(text: str) -> tuple[str, ...]:
    return tuple(match.group(1).strip() for match in re.finditer(r"\[[^\]]+\]\(([^)]+)\)", text))


def _documentation_links_ok(root: Path, text: str, source: str) -> bool:
    source_path = Path(source)
    for target in _markdown_targets(text):
        parsed = urlsplit(target.strip("<>"))
        if parsed.scheme in {"http", "https"}:
            continue
        if parsed.scheme or parsed.netloc or parsed.path.startswith("/"):
            return False
        relative = (
            posixpath.normpath(posixpath.join(source_path.parent.as_posix(), parsed.path))
            if parsed.path
            else source
        )
        if relative == ".." or relative.startswith("../"):
            return False
        try:
            _safe_file(root, relative)
        except AuditError:
            return False
    return True


def run_audit(root: Path) -> list[Check]:
    if root.is_symlink() or not root.is_dir():
        raise AuditError("unsafe-root")
    root = root.resolve(strict=True)
    texts = {path: _text(root, path) for path in R1E_PATHS}
    policy = strict_json(root)
    validate_policy(policy)
    dependabot = strict_yaml(root, ".github/dependabot.yml")
    strict_yaml(root, ".github/workflows/ci.yml")
    strict_yaml(root, ".github/ISSUE_TEMPLATE/config.yml")

    checks: list[Check] = []
    checks.append(
        Check("bounded_regular_files", len(texts) == len(R1E_PATHS), f"files={len(texts)}")
    )
    checks.append(Check("strict_policy", True, "duplicate_keys=0 unknown_fields=0"))
    checks.append(
        Check("policy_labels", tuple(policy["labels"]) == LABELS, f"labels={len(LABELS)}")
    )
    checks.append(
        Check(
            "repository_identity", policy["repository"]["owner"] == "200lz", "repository=expected"
        )
    )
    checks.append(
        Check("description", policy["profile"]["description"] == DESCRIPTION, "description=exact")
    )
    checks.append(
        Check("topics", tuple(policy["profile"]["topics"]) == TOPICS, f"topics={len(TOPICS)}")
    )
    checks.append(Check("homepage", policy["profile"]["homepage"] == "", "homepage=empty"))
    checks.append(
        Check(
            "visibility_boundary",
            policy["repository"]["required_pre_public_visibility"] == "PRIVATE",
            "pre_public=PRIVATE",
        )
    )
    checks.append(
        Check(
            "feature_policy",
            tuple(policy["profile"]["features"]) == FEATURES,
            f"features={len(FEATURES)}",
        )
    )
    checks.append(
        Check(
            "state_taxonomy",
            tuple(policy["state_taxonomy"]) == STATE_TAXONOMY,
            f"states={len(STATE_TAXONOMY)}",
        )
    )
    checks.append(
        Check(
            "phase_taxonomy",
            tuple(policy["phase_taxonomy"]) == PHASE_TAXONOMY,
            f"phases={len(PHASE_TAXONOMY)}",
        )
    )
    checks.append(
        Check(
            "security_control_inventory",
            tuple(policy["security_controls"]) == SECURITY_CONTROLS,
            f"controls={len(SECURITY_CONTROLS)}",
        )
    )
    checks.append(
        Check(
            "api_unavailable_distinct",
            policy["security_controls"]["PRIVATE_VULNERABILITY_REPORTING"]["current_state"]
            == "API_STATE_UNAVAILABLE"
            and policy["security_controls"]["PRIVATE_VULNERABILITY_REPORTING"]["target_state"]
            == "DEFERRED_TO_R1F"
            and policy["security_controls"]["PRIVATE_VULNERABILITY_REPORTING"]["application_phase"]
            == "R1F_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY",
            "private_reporting=API_STATE_UNAVAILABLE deferred=R1F_post_public",
        )
    )
    checks.append(
        Check(
            "r1e_private_mutation_boundary",
            tuple(policy["mutation_scope"]["r1e_private_mutations"]) == R1E_PRIVATE_MUTATIONS
            and tuple(policy["mutation_scope"]["r1e_prohibited_mutations"])
            == R1E_PROHIBITED_MUTATIONS,
            "r1e_mutations=4 r1f_controls_prohibited=9",
        )
    )
    checks.append(
        Check(
            "r1f_public_control_order",
            tuple(policy["r1f_publication_transaction"]) == R1F_PUBLICATION_TRANSACTION,
            "ordered_steps=19 visibility_before_controls=1",
        )
    )
    checks.append(
        Check(
            "visibility_rollback_boundary",
            policy["mutation_scope"]["visibility_rollback_pre_authorized"] is False
            and policy["mutation_scope"]["r1f_must_decide_rollback_authority_before_visibility"]
            is True,
            "rollback_pre_authorized=0 pre_visibility_decision=required",
        )
    )
    checks.append(
        Check(
            "public_plan_deferred",
            policy["security_controls"]["REPOSITORY_RULESETS"]["current_state"]
            == "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN",
            "rulesets=unavailable",
        )
    )

    codeowners = texts[".github/CODEOWNERS"]
    checks.append(Check("codeowners", codeowners == "* @200lz\n", "owners=1"))
    checks.append(
        Check(
            "codeowners_no_email",
            "@" in codeowners and not re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", codeowners),
            "emails=0",
        )
    )
    checks.append(Check("dependabot", _dependabot_ok(dependabot), "ecosystems=2 schedule=monthly"))
    dependabot_text = texts[".github/dependabot.yml"].lower()
    checks.append(
        Check(
            "dependabot_no_bypass",
            not any(
                token in dependabot_text
                for token in ("registries:", "auto-merge", "automerge", "password", "token")
            ),
            "registries=0 auto_merge=0",
        )
    )

    workflow = texts[".github/workflows/ci.yml"]
    pins_ok, permissions_ok, safe_events, isolation_ok, pin_count = _workflow_checks(workflow)
    checks.append(Check("workflow_read_only", permissions_ok, "permissions=contents:read"))
    checks.append(Check("action_pinning", pins_ok, f"full_sha_pins={pin_count}"))
    checks.append(
        Check(
            "workflow_untrusted_code_boundary",
            safe_events,
            "pull_request_target=0 self_hosted=0 secret_refs=0",
        )
    )
    checks.append(
        Check(
            "workflow_regression_boundary",
            isolation_ok,
            "history=full credentials=off matrix=4 integrations=off",
        )
    )
    checks.append(
        Check(
            "workflow_r1e_gate",
            "audit_github_publication_controls.py" in workflow
            and "test_github_publication_controls.py" in workflow,
            "r1e_audit_and_tests=present",
        )
    )

    issue_config = texts[".github/ISSUE_TEMPLATE/config.yml"]
    expected_issue_config = {
        "blank_issues_enabled": False,
        "contact_links": [
            {
                "name": "Security reporting policy",
                "url": (
                    "https://github.com/200lz/open-model-integration-validator/"
                    "blob/main/SECURITY.md"
                ),
                "about": (
                    "Read the private vulnerability reporting instructions before "
                    "disclosing a security issue."
                ),
            }
        ],
    }
    checks.append(
        Check(
            "security_routing",
            strict_yaml(root, ".github/ISSUE_TEMPLATE/config.yml") == expected_issue_config
            and "mailto:" not in issue_config.lower(),
            "security_link=1 email=0",
        )
    )
    documentation = texts["docs/github-publication-controls.md"]
    checks.append(
        Check(
            "documentation_links",
            _documentation_links_ok(root, documentation, "docs/github-publication-controls.md"),
            "relative_links=valid",
        )
    )
    publication_markers = tuple(f"{index}." for index in range(1, 20))
    checks.append(
        Check(
            "publication_order",
            all(marker in documentation for marker in publication_markers),
            "ordered_steps=19",
        )
    )
    checks.append(
        Check(
            "single_maintainer_policy",
            policy["branch_policy"]["required_approving_reviews"] == 0
            and not policy["branch_policy"]["require_code_owner_reviews"]
            and policy["branch_policy"]["required_conversation_resolution"]
            and "zero approving reviews" in documentation
            and "Python 3.11" in documentation,
            "approvals=0 code_owner_reviews=0 checks=4",
        )
    )
    failure_markers = FAILURE_CLASSIFICATIONS
    checks.append(
        Check(
            "partial_application_semantics",
            all(marker in documentation for marker in failure_markers),
            f"classifications={len(failure_markers)}",
        )
    )
    checks.append(
        Check(
            "documentation_private_state",
            "R1F baseline is **PRIVATE**" in documentation
            and "does not authorize" in documentation
            and "not currently verified or active" in documentation,
            "visibility_claim=bounded",
        )
    )
    r1e_plan = documentation.split("## R1E private controls applied", 1)[1].split(
        "## Controlled R1F and post-public plan", 1
    )[0]
    r1f_plan = documentation.split("## Controlled R1F and post-public plan", 1)[1].split(
        "## Partial-application classifications", 1
    )[0]
    checks.append(
        Check(
            "mutation_plan_phase_isolation",
            "Private Vulnerability Reporting" not in r1e_plan
            and 'visibility":"public' not in r1e_plan
            and "Private Vulnerability Reporting" in r1f_plan
            and "visibility" in r1f_plan,
            "r1e_public_controls=0 r1f_plan=linked",
        )
    )
    security = texts["SECURITY.md"]
    checks.append(
        Check(
            "security_reporting_public_only",
            "not currently verified" in security
            and "R1F baseline is private" in security
            and "do not disclose sensitive details" in security
            and "classification is blocked" in security
            and "PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED" in documentation,
            "active_claim=0 post_public_required=1 failure_blocks=1",
        )
    )

    roadmap = texts["docs/roadmap.md"]
    checks.append(
        Check(
            "roadmap_r1e",
            "R1E GitHub metadata/security | COMPLETE" in roadmap,
            "r1e=complete",
        )
    )
    checks.append(
        Check(
            "r1f_implementation_boundary",
            "R1F final publication audit | IMPLEMENTED, PRIVATE RELEASE AND VISIBILITY "
            "AUTHORIZATION PENDING"
            in roadmap
            and policy["implementation"]["r1f_status"]
            == "IMPLEMENTED_PRIVATE_RELEASE_AND_VISIBILITY_AUTHORIZATION_PENDING",
            "r1f=implemented_private_release_pending",
        )
    )
    checks.append(
        Check(
            "phase6f_unimplemented",
            "Phase 6F | PLANNED, NOT IMPLEMENTED" in roadmap
            and policy["implementation"]["phase6f_status"] == "PLANNED_NOT_IMPLEMENTED",
            "phase6f=planned",
        )
    )

    public_text = "\n".join(
        texts[path]
        for path in (
            POLICY_PATH,
            ".github/CODEOWNERS",
            ".github/dependabot.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/workflows/ci.yml",
            "README.md",
            "SECURITY.md",
            "docs/README.md",
            "docs/github-publication-controls.md",
            "docs/public-release-security-and-privacy.md",
            "docs/releasing.md",
            "docs/roadmap.md",
        )
    )
    unsafe_paths = re.findall(r"(?:/home/[\w.-]+/|/Users/[\w.-]+/|[A-Za-z]:\\\\)", public_text)
    checks.append(Check("machine_path_safety", not unsafe_paths, f"matches={len(unsafe_paths)}"))
    credentials = re.findall(
        r"(?:github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}|"
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Authorization:\s*Bearer\s+\S+)",
        public_text,
    )
    checks.append(Check("credential_safety", not credentials, f"matches={len(credentials)}"))
    overclaims = re.findall(
        r"(?im)^\s*(?:repository is public|v0\.10\.0 is released|available on PyPI|"
        r"Phase 6F is (?:complete|implemented)|all security controls are enabled)\s*$",
        public_text,
    )
    checks.append(
        Check("release_and_security_nonclaims", not overclaims, f"matches={len(overclaims)}")
    )
    canonical_mentions = tuple(
        path
        for path in ("schemas", "src/omiv")
        if (root / path).is_dir()
        and any(
            "NON_CANONICAL_REPOSITORY_PUBLICATION_POLICY"
            in child.read_text(encoding="utf-8", errors="ignore")
            for child in sorted((root / path).rglob("*.py" if path.startswith("src") else "*.json"))
            if child.is_file() and child.stat().st_size <= MAX_FILE_BYTES
        )
    )
    checks.append(
        Check(
            "not_canonical_schema",
            not canonical_mentions,
            f"registrations={len(canonical_mentions)}",
        )
    )
    return checks


def render_text(checks: list[Check]) -> str:
    lines = [
        f"{'PASS' if check.passed else 'FAIL'} {check.name} {check.detail}" for check in checks
    ]
    passed = sum(check.passed for check in checks)
    lines.append(f"PASS_SUMMARY passed={passed} failed={len(checks) - passed} total={len(checks)}")
    return "\n".join(lines) + "\n"


def render_json(checks: list[Check]) -> str:
    value = {
        "checks": [asdict(check) for check in checks],
        "classification": "NON_CANONICAL_REPOSITORY_PUBLICATION_POLICY_AUDIT",
        "failed": sum(not check.passed for check in checks),
        "passed": sum(check.passed for check in checks),
        "total": len(checks),
    }
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        checks = run_audit(args.repository)
    except (AuditError, OSError, ValueError):
        print("FAIL audit_error bounded_fail_closed")
        return 1
    print(render_json(checks) if args.json else render_text(checks), end="")
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
