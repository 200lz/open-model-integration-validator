from __future__ import annotations

import json
import runpy
import subprocess
import tomllib
from dataclasses import replace
from pathlib import Path

from typer.testing import CliRunner

from omiv import __version__
from omiv.cli import app

ROOT = Path(__file__).resolve().parents[1]


def _audit_namespace() -> dict[str, object]:
    return runpy.run_path(str(ROOT / "tools/audit_public_release_readiness.py"))


def _observation(
    namespace: dict[str, object],
    fingerprint: str,
    *,
    roles: tuple[str, ...] = ("AUTHOR",),
    refs: tuple[str, ...] = ("LOCAL_MAIN",),
    occurrences: tuple[object, ...] = (),
    valid: bool = True,
) -> object:
    observation_type = namespace["IdentityObservation"]
    return observation_type(  # type: ignore[operator]
        fingerprint=fingerprint,
        roles=roles,
        reachable_ref_classifications=refs,
        occurrences=occurrences,
        valid_record=valid,
    )


def _approved_human(namespace: dict[str, object]) -> object:
    return _observation(
        namespace,
        namespace["OWNER_APPROVED_HUMAN_IDENTITY_SHA256"],  # type: ignore[arg-type]
        roles=("AUTHOR", "COMMITTER", "TAGGER"),
        refs=("ANNOTATED_TAG", "LOCAL_MAIN"),
    )


def _reviewed_platform_fixture(namespace: dict[str, object]) -> tuple[list[object], object]:
    occurrence_type = namespace["IdentityOccurrence"]
    evidence_type = namespace["PullRequestEvidence"]
    policies = namespace["VERIFIED_PLATFORM_SERVICE_POLICIES"]
    base_sha = namespace["PR2_BASE_SHA"]
    head_sha = "1" * 40
    merge_sha = "2" * 40
    signer = namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"]
    evidence_sources = tuple(sorted(namespace["REQUIRED_PULL_REQUEST_PROVENANCE"]))
    evidence = evidence_type(  # type: ignore[operator]
        valid=True,
        repository_full_name=namespace["GITHUB_REPOSITORY_FULL_NAME"],
        repository_id=namespace["GITHUB_REPOSITORY_ID"],
        pr_number=namespace["PR2_NUMBER"],
        base_ref="main",
        base_sha=base_sha,
        head_ref=namespace["PR2_HEAD_REF"],
        head_sha=head_sha,
        merge_sha=merge_sha,
        merge_ref="refs/pull/2/merge",
        parents=(base_sha, head_sha),
        author_actor_id=namespace["GITHUB_OWNER_ACTOR_ID"],
        committer_actor_id=namespace["GITHUB_WEB_FLOW_ACTOR_ID"],
        signature_verified=True,
        signature_reason="valid",
        signature_key_ids=(signer,),
        evidence_sources=evidence_sources,
    )
    observations: list[object] = []
    for policy in sorted(policies.values(), key=lambda item: item.fingerprint):  # type: ignore[union-attr]
        occurrences: list[object] = []
        for item in policy.static_occurrences:
            refname = item.allowed_refnames[0]
            occurrences.append(
                occurrence_type(  # type: ignore[operator]
                    object_sha=item.object_sha,
                    role=item.role,
                    refnames=(refname,),
                    ref_classifications=(namespace["_ref_classification"](refname),),
                    parents=item.parents,
                    signature_key_ids=item.signature_key_ids,
                )
            )
        for item in policy.pull_request_roles:
            occurrences.append(
                occurrence_type(  # type: ignore[operator]
                    object_sha=merge_sha,
                    role=item.role,
                    refnames=("refs/pull/2/merge",),
                    ref_classifications=("PULL_REQUEST_MERGE_REF",),
                    parents=(base_sha, head_sha),
                    signature_key_ids=(signer,),
                )
            )
        observations.append(
            _observation(
                namespace,
                policy.fingerprint,
                roles=tuple(sorted({item.role for item in occurrences})),
                refs=tuple(
                    sorted(
                        {
                            ref_classification
                            for item in occurrences
                            for ref_classification in item.ref_classifications
                        }
                    )
                ),
                occurrences=tuple(occurrences),
            )
        )
    return observations, evidence


def _dynamic_observation(namespace: dict[str, object], role: str) -> tuple[object, object, object]:
    observations, evidence = _reviewed_platform_fixture(namespace)
    source = next(
        item
        for item in observations
        if any(
            occurrence.object_sha == evidence.merge_sha and occurrence.role == role
            for occurrence in item.occurrences
        )
    )
    occurrence = next(
        item
        for item in source.occurrences
        if item.object_sha == evidence.merge_sha and item.role == role
    )
    observation = _observation(
        namespace,
        source.fingerprint,
        roles=(role,),
        refs=("PULL_REQUEST_MERGE_REF",),
        occurrences=(occurrence,),
    )
    return observation, occurrence, evidence


def test_public_preview_version_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    assert project["version"] == __version__ == "0.10.0"
    assert "version: 0.10.0" in citation
    assert project["license"] == "Apache-2.0"
    assert project["authors"] == [{"name": "Linzhang Chen"}]


def test_cli_reports_public_preview_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.10.0"


def test_required_public_files_are_substantive() -> None:
    paths = [
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "SUPPORT.md",
        "THIRD_PARTY_NOTICES.md",
        "TRADEMARKS.md",
        "docs/public-commercial-boundary.md",
        "docs/public-release-security-and-privacy.md",
        "docs/releasing.md",
    ]
    for relative in paths:
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert len(text) >= 200, relative
    assert "Apache License" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_public_document_fixtures_are_bounded_and_attributed() -> None:
    root = ROOT / "fixtures/runtime-resolution/public-documents"
    for path in root.glob("*.normalized.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["source_url"].startswith("https://")
        assert len(document["response_body_sha256"]) == 64
        assert sum(claim["body_byte_length"] for claim in document["claims"]) <= 512
        assert all(len(claim["body_region_sha256"]) == 64 for claim in document["claims"])
        assert "raw response is not stored" in " ".join(document["limitations"]).lower()


def test_ci_has_read_only_permissions_and_immutable_action_pins() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "pull_request_target" not in workflow
    assert "self-hosted" not in workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in workflow
    assert "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in workflow


def test_public_release_audit_is_privacy_safe_and_passes() -> None:
    result = subprocess.run(
        ["python", "tools/audit_public_release_readiness.py", "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(result.stdout)
    assert report["classification"] == "PASS"
    assert report["privacy"]["sensitive_values_serialized"] == 0
    assert report["privacy"]["approved_historical_path_fingerprints"] == 5
    assert "@" not in result.stdout
    assert "/home/" not in result.stdout
    assert "/tmp/" not in result.stdout
    assert "\x1b" not in result.stdout
    assert report["coverage"]["history_surfaces"] == sorted(report["coverage"]["history_surfaces"])
    assert any("heuristic" in limitation for limitation in report["limitations"])

    repeated = subprocess.run(
        ["python", "tools/audit_public_release_readiness.py", "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert repeated.stdout == result.stdout


def test_public_release_audit_never_follows_candidate_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "sensitive-value"
    target.write_text("must not be read", encoding="utf-8")
    link = tmp_path / "candidate"
    link.symlink_to(target)
    namespace = runpy.run_path(str(ROOT / "tools/audit_public_release_readiness.py"))
    assert namespace["_is_safe_regular_file"](link) is False


def test_exactly_one_approved_human_identity_passes() -> None:
    namespace = _audit_namespace()
    check = namespace["_identity_classification_check"]([_approved_human(namespace)])
    assert check.passed is True
    assert "approved_humans=1" in check.detail


def test_reviewed_dependabot_author_is_limited_to_exact_commit_and_refs() -> None:
    namespace = _audit_namespace()
    observations, evidence = _reviewed_platform_fixture(namespace)
    observation = next(item for item in observations if item.fingerprint.startswith("5f65310d"))
    assert namespace["_classify_identity"](observation) == "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    first = observation.occurrences[0]
    unrelated = replace(
        first,
        refnames=("refs/remotes/origin/unrelated",),
        ref_classifications=("REMOTE_OTHER_BRANCH",),
    )
    tampered = replace(
        observation,
        occurrences=(unrelated, *observation.occurrences[1:]),
        reachable_ref_classifications=("PULL_REQUEST_MERGE_REF", "REMOTE_OTHER_BRANCH"),
    )
    assert (
        namespace["_classify_identity"](tampered, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_reviewed_web_flow_committer_requires_full_provenance() -> None:
    namespace = _audit_namespace()
    observations, evidence = _reviewed_platform_fixture(namespace)
    observation = next(item for item in observations if item.fingerprint.startswith("5a85c613"))
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    )
    policies = dict(namespace["VERIFIED_PLATFORM_SERVICE_POLICIES"])
    policies[observation.fingerprint] = replace(
        policies[observation.fingerprint], evidence_sources=()
    )
    assert (
        namespace["_classify_identity"](
            observation, platform_policies=policies, pull_request_evidence=evidence
        )
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_exact_pr_synthetic_merge_author_and_committer_pass() -> None:
    namespace = _audit_namespace()
    for role in ("AUTHOR", "COMMITTER"):
        observation, _, evidence = _dynamic_observation(namespace, role)
        assert (
            namespace["_classify_identity"](observation, pull_request_evidence=evidence)
            == "VERIFIED_PLATFORM_SERVICE_IDENTITY"
        )


def test_same_platform_fingerprint_on_unrelated_branch_fails() -> None:
    namespace = _audit_namespace()
    observation, occurrence, evidence = _dynamic_observation(namespace, "AUTHOR")
    tampered_occurrence = replace(
        occurrence,
        refnames=("refs/remotes/origin/unrelated",),
        ref_classifications=("REMOTE_OTHER_BRANCH",),
    )
    tampered = replace(
        observation,
        occurrences=(tampered_occurrence,),
        reachable_ref_classifications=("REMOTE_OTHER_BRANCH",),
    )
    assert (
        namespace["_classify_identity"](tampered, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_platform_fingerprint_in_unauthorized_role_fails() -> None:
    namespace = _audit_namespace()
    observation, occurrence, evidence = _dynamic_observation(namespace, "COMMITTER")
    tampered = replace(
        observation,
        roles=("AUTHOR",),
        occurrences=(replace(occurrence, role="AUTHOR"),),
    )
    assert (
        namespace["_classify_identity"](tampered, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_same_platform_spelling_with_different_fingerprint_fails() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](
        b"dependabot[bot]", b"different@example.invalid"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_DEPENDABOT_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_noreply_spelling_alone_fails() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](
        b"automation", b"noreply@users.noreply.github.com"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_DEPENDABOT_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_bot_like_name_alone_fails() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](
        b"unknown-automation[bot]", b"unknown@example.invalid"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_DEPENDABOT_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_unverified_pr_signature_fails() -> None:
    namespace = _audit_namespace()
    observation, _, evidence = _dynamic_observation(namespace, "AUTHOR")
    evidence = replace(evidence, signature_verified=False)
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_verified_signature_from_wrong_signer_fails() -> None:
    namespace = _audit_namespace()
    observation, occurrence, evidence = _dynamic_observation(namespace, "AUTHOR")
    wrong = "DEADBEEFDEADBEEF"
    observation = replace(
        observation,
        occurrences=(replace(occurrence, signature_key_ids=(wrong,)),),
    )
    evidence = replace(evidence, signature_key_ids=(wrong,))
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )
    actor_mismatch = replace(
        evidence,
        signature_key_ids=(namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"],),
        committer_actor_id=999999999,
    )
    assert (
        namespace["_classify_identity"](
            replace(
                observation,
                occurrences=(
                    replace(
                        occurrence,
                        signature_key_ids=(namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"],),
                    ),
                ),
            ),
            pull_request_evidence=actor_mismatch,
        )
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_wrong_repository_fails() -> None:
    namespace = _audit_namespace()
    observation, _, evidence = _dynamic_observation(namespace, "AUTHOR")
    evidence = replace(evidence, repository_full_name="example/unrelated")
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_wrong_pr_number_fails() -> None:
    namespace = _audit_namespace()
    observation, _, evidence = _dynamic_observation(namespace, "AUTHOR")
    evidence = replace(evidence, pr_number=99)
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_wrong_base_sha_fails() -> None:
    namespace = _audit_namespace()
    observation, _, evidence = _dynamic_observation(namespace, "AUTHOR")
    evidence = replace(evidence, base_sha="3" * 40)
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_wrong_head_sha_fails() -> None:
    namespace = _audit_namespace()
    observation, _, evidence = _dynamic_observation(namespace, "AUTHOR")
    evidence = replace(evidence, head_sha="3" * 40)
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_wrong_merge_sha_fails() -> None:
    namespace = _audit_namespace()
    observation, _, evidence = _dynamic_observation(namespace, "AUTHOR")
    evidence = replace(evidence, merge_sha="3" * 40)
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_reversed_or_mismatched_merge_parents_fail() -> None:
    namespace = _audit_namespace()
    observation, occurrence, evidence = _dynamic_observation(namespace, "AUTHOR")
    tampered = replace(
        observation, occurrences=(replace(occurrence, parents=tuple(reversed(occurrence.parents))),)
    )
    assert (
        namespace["_classify_identity"](tampered, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_hidden_pr_ref_without_api_correspondence_fails() -> None:
    namespace = _audit_namespace()
    observation, _, _ = _dynamic_observation(namespace, "AUTHOR")
    assert (
        namespace["_classify_identity"](observation, pull_request_evidence=None)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_unknown_human_identity_still_fails() -> None:
    namespace = _audit_namespace()
    observation = _observation(namespace, "3" * 64)
    assert namespace["_classify_identity"](observation) == "UNKNOWN_HUMAN_IDENTITY"
    assert not namespace["_identity_classification_check"](
        [_approved_human(namespace), observation]
    ).passed


def test_unknown_automation_identity_still_fails() -> None:
    namespace = _audit_namespace()
    observation = _observation(namespace, "4" * 64, refs=("PULL_REQUEST_HEAD_REF",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"
    assert not namespace["_identity_classification_check"](
        [_approved_human(namespace), observation]
    ).passed


def test_exactly_one_approved_human_invariant_remains_enforced() -> None:
    namespace = _audit_namespace()
    second = _observation(namespace, "5" * 64)
    assert not namespace["_identity_classification_check"](
        [_approved_human(namespace), second]
    ).passed
    services, evidence = _reviewed_platform_fixture(namespace)
    check = namespace["_identity_classification_check"](services, pull_request_evidence=evidence)
    assert not check.passed
    assert "approved_humans=0" in check.detail


def test_platform_service_has_no_release_or_publisher_authority() -> None:
    namespace = _audit_namespace()
    services, evidence = _reviewed_platform_fixture(namespace)
    records = namespace["_identity_report_records"](services, pull_request_evidence=evidence)
    assert all(record["category"] == "VERIFIED_PLATFORM_SERVICE_IDENTITY" for record in records)
    assert all(
        record["authority_limit"] == "NO_OWNER_PUBLISHER_MAINTAINER_RELEASE_OR_REPOSITORY_AUTHORITY"
        for record in records
    )


def test_existing_main_and_annotated_tag_privacy_behavior_is_unchanged() -> None:
    namespace = _audit_namespace()
    owner = _approved_human(namespace)
    assert namespace["_classify_identity"](owner) == "OWNER_APPROVED_HUMAN_IDENTITY"
    platform, occurrence, evidence = _dynamic_observation(namespace, "AUTHOR")
    tagged = replace(
        platform,
        reachable_ref_classifications=("ANNOTATED_TAG",),
        occurrences=(
            replace(
                occurrence,
                refnames=("refs/tags/v0.9.0",),
                ref_classifications=("ANNOTATED_TAG",),
            ),
        ),
    )
    assert (
        namespace["_classify_identity"](tagged, pull_request_evidence=evidence)
        == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
    )


def test_ref_topology_classifications_are_exact() -> None:
    namespace = _audit_namespace()
    classify = namespace["_ref_classification"]
    assert classify("refs/heads/main") == "LOCAL_MAIN"
    assert classify("refs/heads/release/v0.10.0-public-preview") == "LOCAL_RELEASE_BRANCH"
    assert classify("refs/remotes/origin/main") == "REMOTE_MAIN"
    assert classify("refs/remotes/origin/release/v0.10.0-public-preview") == "REMOTE_RELEASE_BRANCH"
    assert classify("refs/remotes/origin/dependabot/pip/main/example") == "REMOTE_DEPENDABOT_BRANCH"
    assert classify("refs/pull/2/head") == "PULL_REQUEST_HEAD_REF"
    assert classify("refs/remotes/pull/2/merge") == "PULL_REQUEST_MERGE_REF"
    assert classify("refs/tags/v0.9.0") == "ANNOTATED_TAG"
    assert classify("refs/remotes/origin/unrelated") == "REMOTE_OTHER_BRANCH"
    assert classify("refs/notes/example") == "UNKNOWN_REF_SCOPE"


def test_invalid_identity_record_fails_closed() -> None:
    namespace = _audit_namespace()
    invalid = _observation(namespace, "invalid", valid=False)
    assert namespace["_classify_identity"](invalid) == "INVALID_IDENTITY"
    assert not namespace["_identity_classification_check"](
        [_approved_human(namespace), invalid]
    ).passed


def test_identity_report_contains_no_raw_names_addresses_or_paths() -> None:
    namespace = _audit_namespace()
    services, evidence = _reviewed_platform_fixture(namespace)
    records = namespace["_identity_report_records"](
        [_approved_human(namespace), *services], pull_request_evidence=evidence
    )
    serialized = json.dumps(records, sort_keys=True)
    assert "@" not in serialized
    assert "/home/" not in serialized
    assert "/tmp/" not in serialized
    assert all(len(record["fingerprint"]) == 64 for record in records)


def test_exact_ci_identity_topology_is_valid_and_fully_visible() -> None:
    namespace = _audit_namespace()
    services, evidence = _reviewed_platform_fixture(namespace)
    observations = [_approved_human(namespace), *services]
    records = namespace["_identity_report_records"](observations, pull_request_evidence=evidence)
    assert namespace["_identity_classification_check"](
        observations, pull_request_evidence=evidence
    ).passed
    assert [record["category"] for record in records].count("OWNER_APPROVED_HUMAN_IDENTITY") == 1
    assert [record["category"] for record in records].count(
        "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    ) == 3


def test_synthetic_identity_requires_explicit_test_fingerprint() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](b"synthetic", b"synthetic@example.invalid")
    observation = _observation(namespace, fingerprint)
    assert namespace["_classify_identity"](observation) == "UNKNOWN_HUMAN_IDENTITY"
    assert (
        namespace["_classify_identity"](
            observation, synthetic_test_fingerprints=frozenset({fingerprint})
        )
        == "SYNTHETIC_TEST_IDENTITY"
    )


def test_identity_taxonomy_is_complete_and_deterministic() -> None:
    namespace = _audit_namespace()
    assert namespace["IDENTITY_CATEGORIES"] == (
        "INVALID_IDENTITY",
        "OWNER_APPROVED_HUMAN_IDENTITY",
        "SYNTHETIC_TEST_IDENTITY",
        "UNVERIFIED_PLATFORM_SERVICE_CLAIM",
        "UNKNOWN_AUTOMATION_IDENTITY",
        "UNKNOWN_HUMAN_IDENTITY",
        "VERIFIED_PLATFORM_SERVICE_IDENTITY",
    )
    services, evidence = _reviewed_platform_fixture(namespace)
    first = namespace["_identity_report_records"](
        [_approved_human(namespace), *services], pull_request_evidence=evidence
    )
    second = namespace["_identity_report_records"](
        [_approved_human(namespace), *services], pull_request_evidence=evidence
    )
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_annotated_tag_taggers_and_all_refs_remain_scanned() -> None:
    namespace = _audit_namespace()
    observations = namespace["_history_identity_observations"]()
    approved = [
        observation
        for observation in observations
        if observation.fingerprint == namespace["OWNER_APPROVED_HUMAN_IDENTITY_SHA256"]
    ]
    assert len(approved) == 1
    assert "TAGGER" in approved[0].roles
    assert "ANNOTATED_TAG" in approved[0].reachable_ref_classifications
    source = (ROOT / "tools/audit_public_release_readiness.py").read_text(encoding="utf-8")
    assert '_git("for-each-ref", "--format=%(refname)")' in source
    assert '"log",\n        "--all"' in source
    assert '"rev-list", refname' in source


def test_existing_synthetic_path_and_secret_markers_remain_non_authoritative() -> None:
    namespace = _audit_namespace()
    assert namespace["SYNTHETIC_HOME_USERS"] == {"example", "synthetic", "user"}
    fingerprint = namespace["_identity_fingerprint"](
        b"github-looking[bot]", b"github-looking@users.noreply.github.com"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_DEPENDABOT_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"
