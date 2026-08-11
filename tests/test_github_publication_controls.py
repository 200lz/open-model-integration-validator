from __future__ import annotations

import json
import re
import runpy
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "tools/audit_github_publication_controls.py"
POLICY = ROOT / ".github/publication-policy.json"


def _auditor() -> dict[str, Any]:
    return runpy.run_path(str(AUDIT))


def _policy() -> dict[str, Any]:
    return json.loads(POLICY.read_text(encoding="utf-8"))


def _candidate_copy(tmp_path: Path) -> Path:
    namespace = _auditor()
    clone = tmp_path / "candidate"
    for relative in namespace["R1E_PATHS"]:
        source = ROOT / relative
        destination = clone / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    for relative in ("schemas", "src/omiv"):
        shutil.copytree(ROOT / relative, clone / relative)
    return clone


def _write_policy(root: Path, policy: dict[str, Any]) -> None:
    (root / ".github/publication-policy.json").write_text(
        json.dumps(policy, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _assert_audit_fails(root: Path) -> None:
    namespace = _auditor()
    try:
        checks = namespace["run_audit"](root)
    except namespace["AuditError"]:
        return
    assert not all(check.passed for check in checks)


def test_policy_strict_parsing_and_exact_top_level_fields() -> None:
    namespace = _auditor()
    policy = namespace["strict_json"](ROOT)
    namespace["validate_policy"](policy)
    assert tuple(policy) == (
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


def test_duplicate_json_key_rejected(tmp_path: Path) -> None:
    namespace = _auditor()
    root = tmp_path / "root"
    path = root / namespace["POLICY_PATH"]
    path.parent.mkdir(parents=True)
    path.write_text('{"version": 1, "version": 1}', encoding="utf-8")
    with pytest.raises(namespace["AuditError"], match="invalid-json"):
        namespace["strict_json"](root)


def test_duplicate_yaml_key_rejected(tmp_path: Path) -> None:
    namespace = _auditor()
    root = tmp_path / "root"
    path = root / "duplicate.yml"
    path.parent.mkdir(parents=True)
    path.write_text("version: 2\nversion: 2\n", encoding="utf-8")
    with pytest.raises(namespace["AuditError"], match="invalid-yaml"):
        namespace["strict_yaml"](root, "duplicate.yml")


def test_unknown_policy_field_rejected() -> None:
    namespace = _auditor()
    policy = _policy()
    policy["live_api_response"] = {}
    with pytest.raises(namespace["AuditError"], match="policy-fields"):
        namespace["validate_policy"](policy)


def test_required_noncanonical_labels_are_exact() -> None:
    namespace = _auditor()
    policy = _policy()
    assert policy["classification"] == "NON_CANONICAL_REPOSITORY_PUBLICATION_POLICY"
    assert tuple(policy["labels"]) == namespace["LABELS"]


def test_repository_identity_and_visibility_boundary_are_exact() -> None:
    assert _policy()["repository"] == {
        "owner": "200lz",
        "name": "open-model-integration-validator",
        "required_default_branch": "main",
        "required_pre_public_visibility": "PRIVATE",
        "intended_final_visibility": "PUBLIC",
    }


def test_description_is_exact_and_bounded() -> None:
    namespace = _auditor()
    description = _policy()["profile"]["description"]
    assert description == namespace["DESCRIPTION"]
    assert len(description) <= 350


def test_topics_are_ordered_unique_and_github_compatible() -> None:
    namespace = _auditor()
    topics = tuple(_policy()["profile"]["topics"])
    assert topics == namespace["TOPICS"]
    assert len(topics) == len(set(topics)) <= 20
    assert all(len(topic) <= 50 for topic in topics)
    assert all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", topic) for topic in topics)


@pytest.mark.parametrize(
    "topic",
    (
        "certified",
        "secure-ai",
        "production-ready",
        "official-xai",
        "official-huggingface",
        "provable-inference",
    ),
)
def test_misleading_topics_are_prohibited(topic: str) -> None:
    assert topic not in _policy()["profile"]["topics"]


def test_feature_policy_preserves_observed_repository_profile() -> None:
    features = _policy()["profile"]["features"]
    assert features["issues"]["required"] is True
    assert features["projects"]["required"] is True
    assert features["wiki"]["required"] is False
    assert features["discussions"]["required"] is False
    assert features["archived"]["required"] is False
    assert features["template_repository"]["required"] is False


def test_security_state_taxonomy_is_closed() -> None:
    namespace = _auditor()
    policy = _policy()
    assert tuple(policy["state_taxonomy"]) == namespace["STATE_TAXONOMY"]
    for control in policy["security_controls"].values():
        assert control["current_state"] in namespace["STATE_TAXONOMY"]
        assert control["target_state"] in namespace["STATE_TAXONOMY"]


def test_every_security_control_has_observation_and_failure_semantics() -> None:
    namespace = _auditor()
    for name, control in _policy()["security_controls"].items():
        assert tuple(control) == namespace["CONTROL_FIELDS"]
        assert (
            control["current_state"],
            control["target_state"],
            control["application_phase"],
        ) == namespace["CONTROL_STATES"][name]
        for field in namespace["CONTROL_FIELDS"][3:]:
            assert len(control[field]) >= 20


def test_api_unavailable_is_not_collapsed_into_disabled_or_enabled() -> None:
    state = _policy()["security_controls"]["PRIVATE_VULNERABILITY_REPORTING"]
    assert state["current_state"] == "API_STATE_UNAVAILABLE"
    assert state["target_state"] == "DEFERRED_TO_R1F"
    assert state["application_phase"] == "R1F_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY"
    assert "404" in state["observation_source"]
    assert "does not itself prove public-only eligibility" in state["observation_limitation"]
    assert "official GitHub documentation" in state["observation_limitation"]


def test_private_reporting_is_excluded_from_r1e_private_mutations() -> None:
    namespace = _auditor()
    scope = _policy()["mutation_scope"]
    assert tuple(scope["r1e_private_mutations"]) == namespace["R1E_PRIVATE_MUTATIONS"]
    assert "PRIVATE_VULNERABILITY_REPORTING" not in scope["r1e_private_mutations"]
    assert tuple(scope["r1e_prohibited_mutations"]) == namespace["R1E_PROHIBITED_MUTATIONS"]


def test_r1f_public_control_transaction_order_is_exact() -> None:
    namespace = _auditor()
    transaction = tuple(_policy()["r1f_publication_transaction"])
    assert transaction == namespace["R1F_PUBLICATION_TRANSACTION"]
    visibility = transaction.index("VISIBILITY_CHANGED_PRIVATE_TO_PUBLIC")
    reporting = transaction.index("PRIVATE_VULNERABILITY_REPORTING_ENABLED")
    scanning = transaction.index("SECRET_SCANNING_ENABLED")
    pushing = transaction.index("PUSH_PROTECTION_ENABLED")
    branch = transaction.index("MAIN_BRANCH_ENFORCEMENT_APPLIED")
    ready = transaction.index("PUBLICATION_SUCCESS_CLASSIFIED_ONLY_AFTER_ALL_READ_BACKS")
    assert visibility < reporting < scanning < pushing < branch < ready


def test_public_control_failure_and_visibility_rollback_are_fail_closed() -> None:
    namespace = _auditor()
    policy = _policy()
    assert tuple(policy["failure_classifications"]) == namespace["FAILURE_CLASSIFICATIONS"]
    assert (
        "PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED"
        in policy["failure_classifications"]
    )
    scope = policy["mutation_scope"]
    assert scope["visibility_rollback_pre_authorized"] is False
    assert scope["r1f_must_decide_rollback_authority_before_visibility"] is True
    release = policy["release_policy"]
    assert release["github_release_state"] == "NOT_PUBLISHED"
    assert release["pypi_state"] == "NOT_PUBLISHED"


def test_private_plan_restrictions_are_deferred_until_public() -> None:
    controls = _policy()["security_controls"]
    for name in (
        "BRANCH_PROTECTION",
        "FORCE_PUSH_PROTECTION",
        "BRANCH_DELETION_PROTECTION",
    ):
        assert controls[name]["current_state"] == "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN"
        assert controls[name]["application_phase"] == (
            "REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE"
        )
    assert controls["REPOSITORY_RULESETS"]["current_state"] == (
        "UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN"
    )
    assert controls["REPOSITORY_RULESETS"]["target_state"] == "NOT_CONFIGURED"
    assert controls["REPOSITORY_RULESETS"]["application_phase"] == "MANUALLY_DEFERRED"


def test_code_scanning_manual_deferral_has_reason() -> None:
    control = _policy()["security_controls"]["CODE_SCANNING"]
    assert control["current_state"] == "NOT_CONFIGURED"
    assert control["target_state"] == "DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE"
    assert control["application_phase"] == "MANUALLY_DEFERRED"
    assert "CodeQL" in control["reason"]


def test_codeowners_is_global_account_only_and_has_no_email() -> None:
    content = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    assert content == "* @200lz\n"
    assert not re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", content)


def test_dependabot_is_low_noise_and_bounded() -> None:
    value = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text(encoding="utf-8"))
    updates = value["updates"]
    assert [item["package-ecosystem"] for item in updates] == ["pip", "github-actions"]
    assert all(item["directory"] == "/" for item in updates)
    assert all(item["target-branch"] == "main" for item in updates)
    assert all(item["schedule"] == {"interval": "monthly"} for item in updates)
    assert [item["open-pull-requests-limit"] for item in updates] == [3, 2]
    assert "registries" not in value


def test_dependabot_does_not_configure_auto_merge_or_bypass() -> None:
    source = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8").lower()
    assert "auto-merge" not in source
    assert "automerge" not in source
    assert "ignore:" not in source
    assert "token" not in source
    assert _policy()["dependency_updates"]["review_and_ci_required"] is True


def test_workflow_has_read_only_permissions_and_no_secret_reference() -> None:
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^permissions:\n  contents: read$", source)
    assert not re.search(r"\$\{\{\s*secrets\.", source)
    assert not re.search(r"(?m)^\s+\w[\w-]*:\s*write$", source)


def test_official_actions_are_full_sha_pinned() -> None:
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    pins = re.findall(r"(?m)^\s*uses:\s*[^\s@]+@([^\s#]+)", source)
    assert len(pins) == 2
    assert all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins)


def test_workflow_has_no_privileged_pr_trigger_or_self_hosted_runner() -> None:
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in source
    assert "self-hosted" not in source
    assert "runs-on: ubuntu-24.04" in source
    assert "persist-credentials: false" in source


def test_workflow_runs_r1e_audit_and_focused_tests() -> None:
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "python tools/audit_github_publication_controls.py" in source
    assert "tests/test_github_publication_controls.py" in source


def test_security_issue_routing_has_no_email_or_public_disclosure_request() -> None:
    config = (ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "SECURITY.md" in config
    assert "mailto:" not in config.lower()
    assert "Do not put vulnerability or exploit details in a public issue" in security
    assert "Security →" in security
    assert "Report a vulnerability" in security
    assert "not currently verified" in security
    assert "claimed active" in security
    assert "classification is blocked" in security
    for prohibited in (
        "credentials",
        "customer data",
        "private payloads",
        "signed URLs",
    ):
        assert prohibited in security


def test_r1e_and_r1f_documented_mutation_plans_are_isolated() -> None:
    documentation = (ROOT / "docs/github-publication-controls.md").read_text(encoding="utf-8")
    r1e = documentation.split("## R1E private controls applied", 1)[1].split(
        "## Controlled R1F and post-public plan", 1
    )[0]
    r1f = documentation.split("## Controlled R1F and post-public plan", 1)[1].split(
        "## Partial-application classifications", 1
    )[0]
    assert "Private Vulnerability Reporting" not in r1e
    assert '{"visibility":"public"}' not in r1e
    assert "Private Vulnerability Reporting" in r1f
    assert "visibility" in r1f
    assert "No tag, GitHub release, or PyPI operation" in documentation


def test_publication_failure_class_blocks_announcement_and_publication() -> None:
    documentation = (ROOT / "docs/github-publication-controls.md").read_text(encoding="utf-8")
    assert "PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED" in documentation
    assert "do not announce/tag/release/publish" in documentation
    assert "No rollback is pre-authorized" in documentation
    assert "audit tool cannot choose" in documentation


def test_branch_policy_denies_force_push_and_deletion() -> None:
    branch = _policy()["branch_policy"]
    assert branch["normal_changes_require_pull_request"] is True
    assert branch["force_push_allowed"] is False
    assert branch["deletion_allowed"] is False
    assert branch["linear_history_required"] is True
    assert branch["required_ci_checks"] == [
        "Python 3.11",
        "Python 3.12",
        "Python 3.13",
        "Python 3.14",
    ]
    assert branch["required_approving_reviews"] == 0
    assert branch["require_code_owner_reviews"] is False
    assert branch["required_conversation_resolution"] is True


def test_release_states_make_no_publication_claim() -> None:
    release = _policy()["release_policy"]
    assert release["github_release_state"] == "NOT_PUBLISHED"
    assert release["pypi_state"] == "NOT_PUBLISHED"
    assert release["tag_release_and_pypi_require_separate_authorization"] is True
    assert _policy()["repository"]["required_pre_public_visibility"] == "PRIVATE"


def test_roadmap_truth_preserves_r1f_and_phase6f_boundaries() -> None:
    roadmap = (ROOT / "docs/roadmap.md").read_text(encoding="utf-8")
    assert "R1D offline walkthrough | COMPLETE" in roadmap
    assert "R1E GitHub metadata/security | COMPLETE" in roadmap
    assert (
        "R1F final publication audit | IMPLEMENTED, PRIVATE RELEASE AND VISIBILITY "
        "AUTHORIZATION PENDING" in roadmap
    )
    assert "Phase 6F | PLANNED, NOT IMPLEMENTED" in roadmap
    assert "Phase 7 | FUTURE, SCOPE NOT FROZEN" in roadmap


def test_policy_is_not_registered_as_omiv_schema() -> None:
    marker = "NON_CANONICAL_REPOSITORY_PUBLICATION_POLICY"
    for path in sorted((ROOT / "src/omiv").rglob("*.py")):
        assert marker not in path.read_text(encoding="utf-8")
    for path in sorted((ROOT / "schemas").rglob("*.json")):
        assert marker not in path.read_text(encoding="utf-8")


def test_audit_is_deterministic_in_text_and_json_modes() -> None:
    command = [sys.executable, str(AUDIT)]
    first = subprocess.run(command, cwd=ROOT, check=True, capture_output=True)
    second = subprocess.run(command, cwd=ROOT, check=True, capture_output=True)
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    json_first = subprocess.run(command + ["--json"], cwd=ROOT, check=True, capture_output=True)
    json_second = subprocess.run(command + ["--json"], cwd=ROOT, check=True, capture_output=True)
    assert json_first.stdout == json_second.stdout
    assert json_first.stderr == json_second.stderr == b""


def test_audit_rejects_symlinked_candidate_path(tmp_path: Path) -> None:
    namespace = _auditor()
    clone = _candidate_copy(tmp_path)
    codeowners = clone / ".github/CODEOWNERS"
    codeowners.unlink()
    try:
        codeowners.symlink_to(ROOT / ".github/CODEOWNERS")
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(namespace["AuditError"], match="symlink"):
        namespace["run_audit"](clone)


def test_audit_rejects_absolute_and_traversal_paths(tmp_path: Path) -> None:
    namespace = _auditor()
    with pytest.raises(namespace["AuditError"], match="unsafe-path"):
        namespace["_safe_file"](tmp_path, "/tmp/outside")
    with pytest.raises(namespace["AuditError"], match="unsafe-path"):
        namespace["_safe_file"](tmp_path, "../outside")


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("description", "An altered description"),
        ("duplicate_topic", "ai-supply-chain"),
        ("prohibited_topic", "certified"),
        ("repository", "another-repository"),
        ("visibility", "PUBLIC"),
        ("approvals", 1),
        ("false_disabled", "DISABLED"),
    ),
)
def test_policy_semantic_mutations_fail_closed(
    tmp_path: Path, mutation: str, value: str | int
) -> None:
    clone = _candidate_copy(tmp_path)
    policy = json.loads((clone / ".github/publication-policy.json").read_text())
    if mutation == "description":
        policy["profile"]["description"] = value
    elif mutation == "duplicate_topic":
        policy["profile"]["topics"][1] = value
    elif mutation == "prohibited_topic":
        policy["profile"]["topics"][0] = value
    elif mutation == "repository":
        policy["repository"]["name"] = value
    elif mutation == "visibility":
        policy["repository"]["required_pre_public_visibility"] = value
    elif mutation == "approvals":
        policy["branch_policy"]["required_approving_reviews"] = value
    else:
        policy["security_controls"]["DEPENDABOT_ALERTS"]["current_state"] = value
    _write_policy(clone, policy)
    _assert_audit_fails(clone)


@pytest.mark.parametrize(
    "mutation",
    (
        "private_reporting_enabled",
        "private_reporting_pre_public",
        "private_reporting_in_r1e",
        "public_controls_reordered",
        "publication_without_all_controls",
        "implicit_visibility_rollback",
        "missing_public_control_failure",
    ),
)
def test_public_only_order_mutations_fail_closed(tmp_path: Path, mutation: str) -> None:
    clone = _candidate_copy(tmp_path)
    policy = json.loads((clone / ".github/publication-policy.json").read_text())
    reporting = policy["security_controls"]["PRIVATE_VULNERABILITY_REPORTING"]
    if mutation == "private_reporting_enabled":
        reporting["target_state"] = "ENABLED_AND_VERIFIED"
    elif mutation == "private_reporting_pre_public":
        reporting["application_phase"] = "REQUIRED_IMMEDIATELY_BEFORE_PUBLIC_VISIBILITY"
    elif mutation == "private_reporting_in_r1e":
        policy["mutation_scope"]["r1e_private_mutations"].append("PRIVATE_VULNERABILITY_REPORTING")
    elif mutation == "public_controls_reordered":
        transaction = policy["r1f_publication_transaction"]
        transaction[3], transaction[4] = transaction[4], transaction[3]
    elif mutation == "publication_without_all_controls":
        policy["r1f_publication_transaction"].remove(
            "PROFILE_TOPICS_ACTIONS_DEPENDABOT_READ_BACK_VERIFIED"
        )
    elif mutation == "implicit_visibility_rollback":
        policy["mutation_scope"]["visibility_rollback_pre_authorized"] = True
    else:
        policy["failure_classifications"].remove(
            "PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED"
        )
    _write_policy(clone, policy)
    _assert_audit_fails(clone)


def test_security_active_channel_claim_mutation_fails_closed(tmp_path: Path) -> None:
    clone = _candidate_copy(tmp_path)
    security = clone / "SECURITY.md"
    source = security.read_text(encoding="utf-8")
    security.write_text(
        source.replace("not currently verified", "enabled and verified", 1),
        encoding="utf-8",
    )
    _assert_audit_fails(clone)


@pytest.mark.parametrize(
    ("old", "new"),
    (
        ("contents: read", "contents: write"),
        ("pull_request:\n", "pull_request_target:\n"),
        (
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
        ),
        ("persist-credentials: false", "persist-credentials: true"),
        (
            'python-version: ["3.11", "3.12", "3.13", "3.14"]',
            'python-version: ["3.11", "3.12", "3.13"]',
        ),
        ("timeout-minutes: 30", "timeout-minutes: 30\n    continue-on-error: true"),
    ),
)
def test_workflow_security_mutations_fail_closed(tmp_path: Path, old: str, new: str) -> None:
    clone = _candidate_copy(tmp_path)
    workflow = clone / ".github/workflows/ci.yml"
    source = workflow.read_text(encoding="utf-8")
    assert old in source
    workflow.write_text(source.replace(old, new, 1), encoding="utf-8")
    _assert_audit_fails(clone)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        ("version: 2", "version: 2\nregistries:\n  unsafe: {}"),
        ("version: 2", "version: 2\nauto-merge: true"),
    ),
)
def test_dependabot_unsafe_mutations_fail_closed(
    tmp_path: Path, needle: str, replacement: str
) -> None:
    clone = _candidate_copy(tmp_path)
    path = clone / ".github/dependabot.yml"
    source = path.read_text(encoding="utf-8")
    path.write_text(source.replace(needle, replacement, 1), encoding="utf-8")
    _assert_audit_fails(clone)


@pytest.mark.parametrize("content", ("* owner@example.com\n", "not-a-pattern\n"))
def test_codeowners_unsafe_mutations_fail_closed(tmp_path: Path, content: str) -> None:
    clone = _candidate_copy(tmp_path)
    (clone / ".github/CODEOWNERS").write_text(content, encoding="utf-8")
    _assert_audit_fails(clone)


def test_security_route_to_public_issue_fails_closed(tmp_path: Path) -> None:
    clone = _candidate_copy(tmp_path)
    config = clone / ".github/ISSUE_TEMPLATE/config.yml"
    source = config.read_text(encoding="utf-8")
    config.write_text(
        source.replace("blob/main/SECURITY.md", "issues/new"),
        encoding="utf-8",
    )
    _assert_audit_fails(clone)


@pytest.mark.parametrize(
    ("old", "new"),
    (
        (
            "R1F final publication audit | IMPLEMENTED, PRIVATE RELEASE AND VISIBILITY "
            "AUTHORIZATION PENDING",
            "R1F final publication audit | COMPLETE",
        ),
        ("Phase 6F | PLANNED, NOT IMPLEMENTED", "Phase 6F | COMPLETE"),
    ),
)
def test_roadmap_overclaim_mutations_fail_closed(tmp_path: Path, old: str, new: str) -> None:
    clone = _candidate_copy(tmp_path)
    roadmap = clone / "docs/roadmap.md"
    source = roadmap.read_text(encoding="utf-8")
    assert old in source
    roadmap.write_text(source.replace(old, new, 1), encoding="utf-8")
    _assert_audit_fails(clone)


def test_audit_output_contains_no_repository_absolute_path(tmp_path: Path) -> None:
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


def test_candidate_files_are_text_bounded_and_have_no_hidden_controls() -> None:
    namespace = _auditor()
    for relative in namespace["R1E_PATHS"]:
        data = (ROOT / relative).read_bytes()
        assert len(data) <= namespace["MAX_FILE_BYTES"]
        text = data.decode("utf-8")
        assert not any(ord(character) < 32 and character not in "\n\r\t" for character in text)


def test_audit_passes_all_checks() -> None:
    namespace = _auditor()
    checks = namespace["run_audit"](ROOT)
    assert len(checks) >= 30
    assert all(check.passed for check in checks)
