from __future__ import annotations

import json
import runpy
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "tools/audit_r1f_publication_readiness.py"
POLICY = ROOT / ".github/publication-policy.json"


def _auditor() -> dict[str, Any]:
    return runpy.run_path(str(AUDIT))


def _policy() -> dict[str, Any]:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def _candidate_copy(tmp_path: Path) -> Path:
    namespace = _auditor()
    clone = tmp_path / "candidate"
    for relative in (*namespace["R1F_PATHS"], "pyproject.toml"):
        source = ROOT / relative
        destination = clone / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return clone


def _write_policy(root: Path, policy: dict[str, Any]) -> None:
    (root / ".github/publication-policy.json").write_text(
        json.dumps(policy, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


def _assert_audit_fails(root: Path) -> None:
    namespace = _auditor()
    try:
        checks = namespace["run_audit"](root)
    except namespace["AuditError"]:
        return
    assert not all(item.passed for item in checks)


def test_policy_is_strict_and_final_contract_is_exact() -> None:
    namespace = _auditor()
    policy = namespace["strict_json"](ROOT)
    namespace["validate_r1f_policy"](policy)
    assert tuple(policy) == namespace["TOP_LEVEL_FIELDS"]
    final = policy["final_public_state"]
    assert final["repository"] == "200lz/open-model-integration-validator"
    assert final["visibility"] == "PUBLIC"
    assert final["main_sha"] == "EXACT_R1F_RELEASE_COMMIT"
    assert final["releases"] == 0
    assert final["pypi_publication"] == "NOT_PUBLISHED"
    assert final["phase6f"] == "PLANNED_NOT_IMPLEMENTED"


def test_private_baseline_is_distinct_from_intended_public_state() -> None:
    policy = _policy()
    assert policy["repository"]["required_pre_public_visibility"] == "PRIVATE"
    assert policy["final_public_state"]["visibility"] == "PUBLIC"
    assert policy["implementation"]["repository_visibility_at_r1f_baseline"] == "PRIVATE"
    assert policy["implementation"]["github_settings_mutated_by_r1f"] is False


def test_duplicate_json_key_is_rejected(tmp_path: Path) -> None:
    namespace = _auditor()
    root = tmp_path / "root"
    path = root / namespace["POLICY_PATH"]
    path.parent.mkdir(parents=True)
    path.write_text('{"version": 1, "version": 1}', encoding="utf-8")
    with pytest.raises(namespace["AuditError"], match="duplicate-key"):
        namespace["strict_json"](root)


def test_duplicate_yaml_key_is_rejected(tmp_path: Path) -> None:
    namespace = _auditor()
    root = tmp_path / "root"
    path = root / "workflow.yml"
    path.parent.mkdir(parents=True)
    path.write_text("name: one\nname: two\n", encoding="utf-8")
    with pytest.raises(namespace["AuditError"], match="duplicate-key"):
        namespace["strict_yaml"](root, "workflow.yml")


def test_unknown_top_level_and_nested_fields_are_rejected() -> None:
    namespace = _auditor()
    policy = _policy()
    policy["live_api_response"] = {}
    with pytest.raises(namespace["AuditError"], match="policy-fields"):
        namespace["validate_r1f_policy"](policy)
    policy = _policy()
    policy["final_public_state"]["timestamp"] = "mutable"
    with pytest.raises(namespace["AuditError"], match="final-state-fields"):
        namespace["validate_r1f_policy"](policy)


def test_visibility_and_rollback_authority_are_required_but_unselected() -> None:
    policy = _policy()
    transaction = tuple(policy["r1f_publication_transaction"])
    assert "EXPLICIT_VISIBILITY_AUTHORIZATION_VERIFIED" in transaction
    assert "EXPLICIT_ROLLBACK_AUTHORITY_DECISION_VERIFIED" in transaction
    rollback = policy["rollback_authority"]
    assert rollback["selected_choice"] is None
    assert rollback["selection_required_before_visibility"] is True
    assert rollback["automatic_selection_allowed"] is False
    assert tuple(rollback["choices"]) == _auditor()["ROLLBACK_CHOICES"]


def test_transaction_order_is_exact_and_all_readbacks_are_explicit() -> None:
    namespace = _auditor()
    transaction = tuple(_policy()["r1f_publication_transaction"])
    assert transaction == namespace["TRANSACTION"]
    assert len(transaction) == 19
    visibility = transaction.index("VISIBILITY_CHANGED_PRIVATE_TO_PUBLIC")
    visibility_read = transaction.index("PUBLIC_VISIBILITY_READ_BACK_VERIFIED")
    reporting = transaction.index("PRIVATE_VULNERABILITY_REPORTING_ENABLED")
    reporting_read = transaction.index("PRIVATE_VULNERABILITY_REPORTING_READ_BACK_VERIFIED")
    scanning = transaction.index("SECRET_SCANNING_ENABLED")
    scanning_read = transaction.index("SECRET_SCANNING_READ_BACK_VERIFIED")
    pushing = transaction.index("PUSH_PROTECTION_ENABLED")
    pushing_read = transaction.index("PUSH_PROTECTION_READ_BACK_VERIFIED")
    enforcement = transaction.index("MAIN_BRANCH_ENFORCEMENT_APPLIED")
    enforcement_read = transaction.index(
        "MAIN_BRANCH_ENFORCEMENT_FIELDS_AND_CHECKS_READ_BACK_VERIFIED"
    )
    assert visibility < visibility_read < reporting < reporting_read
    assert reporting_read < scanning < scanning_read < pushing < pushing_read
    assert pushing_read < enforcement < enforcement_read


def test_final_readback_and_unauthenticated_public_read_are_required() -> None:
    transaction = _policy()["r1f_publication_transaction"]
    assert "PROFILE_TOPICS_ACTIONS_DEPENDABOT_READ_BACK_VERIFIED" in transaction
    assert "NO_TAG_RELEASE_OR_PACKAGE_CREATED_VERIFIED" in transaction
    assert "UNAUTHENTICATED_PUBLIC_READ_SMOKE_PASSED" in transaction
    assert transaction[-1] == "PUBLICATION_SUCCESS_CLASSIFIED_ONLY_AFTER_ALL_READ_BACKS"


def test_rollback_risks_cover_every_public_surface() -> None:
    risk = _policy()["rollback_authority"]["risk_statement"]
    assert "Actions visibility" in risk
    assert "Pages or package exposure" in risk
    assert "announcements" in risk
    assert "cannot erase prior exposure" in risk


def test_branch_protection_is_the_only_selected_enforcement() -> None:
    policy = _policy()
    enforcement = policy["main_enforcement"]
    assert enforcement["mechanism"] == "BRANCH_PROTECTION"
    assert enforcement["overlapping_ruleset_allowed"] is False
    rulesets = policy["security_controls"]["REPOSITORY_RULESETS"]
    assert rulesets["target_state"] == "NOT_CONFIGURED"
    assert rulesets["application_phase"] == "MANUALLY_DEFERRED"


def test_branch_protection_payload_is_exact() -> None:
    namespace = _auditor()
    payload = _policy()["main_enforcement"]["payload"]
    assert payload["required_status_checks"] == {
        "strict": True,
        "contexts": [],
        "checks": [
            {"context": context, "app_id": namespace["GITHUB_ACTIONS_APP_ID"]}
            for context in namespace["CHECK_CONTEXTS"]
        ],
    }
    assert payload["enforce_admins"] is False
    assert payload["required_pull_request_reviews"] == {
        "dismiss_stale_reviews": False,
        "require_code_owner_reviews": False,
        "required_approving_review_count": 0,
        "require_last_push_approval": False,
    }
    assert payload["restrictions"] is None
    assert payload["required_linear_history"] is True
    assert payload["allow_force_pushes"] is False
    assert payload["allow_deletions"] is False
    assert payload["required_conversation_resolution"] is True


def test_ci_contexts_match_workflow_job_names() -> None:
    namespace = _auditor()
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "name: Python ${{ matrix.python-version }}" in source
    assert 'python-version: ["3.11", "3.12", "3.13", "3.14"]' in source
    assert (
        tuple(
            item["context"]
            for item in _policy()["main_enforcement"]["payload"]["required_status_checks"]["checks"]
        )
        == namespace["CHECK_CONTEXTS"]
    )
    assert {
        item["app_id"]
        for item in _policy()["main_enforcement"]["payload"]["required_status_checks"]["checks"]
    } == {namespace["GITHUB_ACTIONS_APP_ID"]}


def test_single_maintainer_policy_does_not_claim_independent_review() -> None:
    enforcement = _policy()["main_enforcement"]
    reviews = enforcement["payload"]["required_pull_request_reviews"]
    assert reviews["required_approving_review_count"] == 0
    assert reviews["require_code_owner_reviews"] is False
    assert "sole maintainer" in enforcement["single_maintainer_reason"]
    assert "independent approval" in enforcement["single_maintainer_reason"]


def test_failure_taxonomy_is_exact_and_fail_closed() -> None:
    namespace = _auditor()
    policy = _policy()
    assert tuple(policy["failure_classifications"]) == namespace["FAILURES"]
    documentation = (ROOT / "docs/r1f-final-publication-audit.md").read_text()
    assert all(value in documentation for value in namespace["FAILURES"])
    assert "prohibits announcement" in documentation
    assert "requires separate remediation authority" in documentation


def test_transition_safe_documentation_and_security_route() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    documentation = (ROOT / "docs/r1f-final-publication-audit.md").read_text(encoding="utf-8")
    assert "baseline is private" in readme
    assert "live GitHub visibility is authoritative" in readme
    assert "not currently verified" in security
    assert "do not disclose sensitive details" in security
    assert "public issue" in security
    assert "email fallback" in documentation
    assert "no response-time promise" in documentation


def test_codeql_is_explicitly_deferred_without_equivalence_claim() -> None:
    decision = _policy()["codeql_decision"]
    assert decision["state"] == "CODEQL_DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE"
    assert "existing CI does not replace CodeQL" in decision["reason"]
    assert not (ROOT / ".github/workflows/codeql.yml").exists()


def test_roadmap_preserves_release_and_engineering_boundaries() -> None:
    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    for release in (
        "R1A readiness",
        "R1B private clean-clone CI",
        "R1C launch UX",
        "R1D offline walkthrough",
        "R1E GitHub metadata/security",
    ):
        assert f"{release} | COMPLETE" in roadmap
    assert (
        "R1F final publication audit | IMPLEMENTED, PRIVATE RELEASE AND VISIBILITY "
        "AUTHORIZATION PENDING" in roadmap
    )
    assert "Phase 6F | PLANNED, NOT IMPLEMENTED" in roadmap
    assert "Phase 7 | FUTURE, SCOPE NOT FROZEN" in roadmap


@pytest.mark.parametrize(
    "mutation",
    (
        "final_visibility",
        "final_repository",
        "final_main_sha",
        "premature_release",
        "phase6f",
        "automatic_rollback",
        "missing_visibility_authorization",
        "missing_rollback_decision",
        "control_before_public_readback",
        "missing_reporting_readback",
        "missing_secret_readback",
        "missing_push_readback",
        "missing_complete_readback",
        "missing_public_smoke",
        "ruleset_mechanism",
        "overlapping_ruleset",
        "renamed_context",
        "wrong_check_app",
        "missing_check_app",
        "unbound_context_added",
        "context_only_checks",
        "approval_required",
        "codeowner_review",
        "force_push",
        "deletion",
        "nonlinear_history",
        "admin_enforcement",
        "failure_removed",
        "codeql_enabled",
        "r1f_settings_mutated",
        "dependabot_disabled",
    ),
)
def test_critical_policy_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    clone = _candidate_copy(tmp_path)
    policy = json.loads((clone / ".github/publication-policy.json").read_text())
    transaction = policy["r1f_publication_transaction"]
    payload = policy["main_enforcement"]["payload"]
    mutations: dict[str, Callable[[], None]] = {
        "final_visibility": lambda: policy["final_public_state"].__setitem__(
            "visibility", "PRIVATE"
        ),
        "final_repository": lambda: policy["final_public_state"].__setitem__(
            "repository", "another/repository"
        ),
        "final_main_sha": lambda: policy["final_public_state"].__setitem__("main_sha", "mutable"),
        "premature_release": lambda: policy["final_public_state"].__setitem__("releases", 1),
        "phase6f": lambda: policy["final_public_state"].__setitem__("phase6f", "IMPLEMENTED"),
        "automatic_rollback": lambda: policy["rollback_authority"].__setitem__(
            "selected_choice", policy["rollback_authority"]["choices"][0]
        ),
        "missing_visibility_authorization": lambda: transaction.remove(
            "EXPLICIT_VISIBILITY_AUTHORIZATION_VERIFIED"
        ),
        "missing_rollback_decision": lambda: transaction.remove(
            "EXPLICIT_ROLLBACK_AUTHORITY_DECISION_VERIFIED"
        ),
        "control_before_public_readback": lambda: transaction.__setitem__(
            6, "PRIVATE_VULNERABILITY_REPORTING_ENABLED"
        ),
        "missing_reporting_readback": lambda: transaction.remove(
            "PRIVATE_VULNERABILITY_REPORTING_READ_BACK_VERIFIED"
        ),
        "missing_secret_readback": lambda: transaction.remove("SECRET_SCANNING_READ_BACK_VERIFIED"),
        "missing_push_readback": lambda: transaction.remove("PUSH_PROTECTION_READ_BACK_VERIFIED"),
        "missing_complete_readback": lambda: transaction.remove(
            "PROFILE_TOPICS_ACTIONS_DEPENDABOT_READ_BACK_VERIFIED"
        ),
        "missing_public_smoke": lambda: transaction.remove(
            "UNAUTHENTICATED_PUBLIC_READ_SMOKE_PASSED"
        ),
        "ruleset_mechanism": lambda: policy["main_enforcement"].__setitem__(
            "mechanism", "REPOSITORY_RULESET"
        ),
        "overlapping_ruleset": lambda: policy["main_enforcement"].__setitem__(
            "overlapping_ruleset_allowed", True
        ),
        "renamed_context": lambda: payload["required_status_checks"]["checks"][0].__setitem__(
            "context", "test"
        ),
        "wrong_check_app": lambda: payload["required_status_checks"]["checks"][0].__setitem__(
            "app_id", -1
        ),
        "missing_check_app": lambda: payload["required_status_checks"]["checks"][0].pop("app_id"),
        "unbound_context_added": lambda: payload["required_status_checks"]["contexts"].append(
            "Python 3.11"
        ),
        "context_only_checks": lambda: payload.__setitem__(
            "required_status_checks",
            {"strict": True, "contexts": list(_auditor()["CHECK_CONTEXTS"])},
        ),
        "approval_required": lambda: payload["required_pull_request_reviews"].__setitem__(
            "required_approving_review_count", 1
        ),
        "codeowner_review": lambda: payload["required_pull_request_reviews"].__setitem__(
            "require_code_owner_reviews", True
        ),
        "force_push": lambda: payload.__setitem__("allow_force_pushes", True),
        "deletion": lambda: payload.__setitem__("allow_deletions", True),
        "nonlinear_history": lambda: payload.__setitem__("required_linear_history", False),
        "admin_enforcement": lambda: payload.__setitem__("enforce_admins", True),
        "failure_removed": lambda: policy["failure_classifications"].remove(
            "PARTIAL_PUBLICATION_STATE"
        ),
        "codeql_enabled": lambda: policy["codeql_decision"].__setitem__("state", "ENABLED"),
        "r1f_settings_mutated": lambda: policy["implementation"].__setitem__(
            "github_settings_mutated_by_r1f", True
        ),
        "dependabot_disabled": lambda: policy["security_controls"]["DEPENDABOT_ALERTS"].__setitem__(
            "current_state", "DISABLED"
        ),
    }
    mutations[mutation]()
    _write_policy(clone, policy)
    _assert_audit_fails(clone)


@pytest.mark.parametrize(
    ("old", "new"),
    (
        ("contents: read", "contents: write"),
        ("pull_request:\n", "pull_request_target:\n"),
        ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7"),
        ("persist-credentials: false", "persist-credentials: true"),
        (
            'python-version: ["3.11", "3.12", "3.13", "3.14"]',
            'python-version: ["3.11", "3.12", "3.13"]',
        ),
        ("timeout-minutes: 30", "timeout-minutes: 30\n    continue-on-error: true"),
        ("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
    ),
)
def test_workflow_regressions_fail_closed(tmp_path: Path, old: str, new: str) -> None:
    clone = _candidate_copy(tmp_path)
    workflow = clone / ".github/workflows/ci.yml"
    source = workflow.read_text(encoding="utf-8")
    assert old in source
    workflow.write_text(source.replace(old, new, 1), encoding="utf-8")
    _assert_audit_fails(clone)


def test_document_transaction_reordering_fails_closed(tmp_path: Path) -> None:
    clone = _candidate_copy(tmp_path)
    path = clone / "docs/r1f-final-publication-audit.md"
    source = path.read_text(encoding="utf-8")
    path.write_text(source.replace("7. Read back", "20. Read back", 1), encoding="utf-8")
    _assert_audit_fails(clone)


def test_unsafe_security_fallback_fails_closed(tmp_path: Path) -> None:
    clone = _candidate_copy(tmp_path)
    path = clone / "SECURITY.md"
    source = path.read_text(encoding="utf-8")
    path.write_text(
        source.replace(
            "do not disclose sensitive details",
            "disclose sensitive details",
            1,
        ),
        encoding="utf-8",
    )
    _assert_audit_fails(clone)


def test_mutation_executor_in_auditor_fails_closed(tmp_path: Path) -> None:
    clone = _candidate_copy(tmp_path)
    path = clone / "tools/audit_r1f_publication_readiness.py"
    path.write_text(path.read_text() + "\nimport subprocess\n", encoding="utf-8")
    _assert_audit_fails(clone)


def test_symlinked_candidate_path_is_rejected(tmp_path: Path) -> None:
    namespace = _auditor()
    clone = _candidate_copy(tmp_path)
    path = clone / "docs/r1f-final-publication-audit.md"
    path.unlink()
    try:
        path.symlink_to(ROOT / "docs/r1f-final-publication-audit.md")
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(namespace["AuditError"], match="unsafe-file-type"):
        namespace["run_audit"](clone)


def test_unsafe_paths_are_rejected(tmp_path: Path) -> None:
    namespace = _auditor()
    for value in ("/tmp/outside", "../outside", "nested\\outside"):
        with pytest.raises(namespace["AuditError"], match="unsafe-path"):
            namespace["_safe_file"](tmp_path, value)


def test_audit_is_deterministic_in_text_and_json_modes() -> None:
    for suffix in ((), ("--json",)):
        command = [sys.executable, str(AUDIT), *suffix]
        first = subprocess.run(command, cwd=ROOT, check=True, capture_output=True)
        second = subprocess.run(command, cwd=ROOT, check=True, capture_output=True)
        assert first.stdout == second.stdout
        assert first.stderr == second.stderr == b""


def test_audit_output_contains_no_absolute_repository_path(tmp_path: Path) -> None:
    clone = _candidate_copy(tmp_path)
    result = subprocess.run(
        [sys.executable, str(AUDIT), "--repository", str(clone)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert str(clone) not in result.stdout
    assert str(ROOT) not in result.stdout
    assert result.stderr == ""


def test_candidate_files_are_bounded_utf8_without_hidden_controls() -> None:
    namespace = _auditor()
    for relative in namespace["R1F_PATHS"]:
        data = (ROOT / relative).read_bytes()
        assert len(data) <= namespace["MAX_FILE_BYTES"]
        text = data.decode("utf-8")
        assert not any(ord(character) < 32 and character not in "\n\r\t" for character in text)


def test_audit_passes_all_checks() -> None:
    checks = _auditor()["run_audit"](ROOT)
    assert len(checks) >= 20
    assert all(item.passed for item in checks)
