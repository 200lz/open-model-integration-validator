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
    refs: tuple[str, ...] = ("MAIN_HISTORY",),
    valid: bool = True,
) -> object:
    observation_type = namespace["IdentityObservation"]
    return observation_type(  # type: ignore[operator]
        fingerprint=fingerprint,
        roles=roles,
        reachable_ref_classifications=refs,
        valid_record=valid,
    )


def _approved_human(namespace: dict[str, object]) -> object:
    return _observation(
        namespace,
        namespace["OWNER_APPROVED_HUMAN_IDENTITY_SHA256"],  # type: ignore[arg-type]
        roles=("AUTHOR", "COMMITTER", "TAGGER"),
        refs=("ANNOTATED_TAG", "MAIN_HISTORY"),
    )


def _reviewed_platform_observations(namespace: dict[str, object]) -> list[object]:
    policies = namespace["VERIFIED_PLATFORM_SERVICE_POLICIES"]
    return [
        _observation(
            namespace,
            policy.fingerprint,
            roles=policy.allowed_roles,
            refs=policy.allowed_ref_classifications,
        )
        for policy in sorted(policies.values(), key=lambda item: item.fingerprint)  # type: ignore[union-attr]
    ]


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


def test_approved_human_plus_reviewed_platform_identities_passes() -> None:
    namespace = _audit_namespace()
    observations = [_approved_human(namespace), *_reviewed_platform_observations(namespace)]
    check = namespace["_identity_classification_check"](observations)
    assert check.passed is True
    assert "verified_platform_services=2" in check.detail


def test_second_human_identity_fails() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](
        b"second-human", b"second-human@example.invalid"
    )
    observations = [_approved_human(namespace), _observation(namespace, fingerprint)]
    check = namespace["_identity_classification_check"](observations)
    assert check.passed is False
    assert namespace["_classify_identity"](observations[1]) == "UNKNOWN_HUMAN_IDENTITY"


def test_unknown_bot_like_identity_fails() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](
        b"unknown-automation[bot]", b"unknown@example.invalid"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_AUTOMATION_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"
    assert (
        namespace["_identity_classification_check"](
            [_approved_human(namespace), observation]
        ).passed
        is False
    )


def test_spoofed_bot_display_name_does_not_establish_platform_identity() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](b"dependabot[bot]", b"spoof@example.invalid")
    observation = _observation(namespace, fingerprint, refs=("REMOTE_AUTOMATION_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_spoofed_noreply_address_does_not_establish_platform_identity() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](
        b"automation", b"noreply@users.noreply.github.com"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_AUTOMATION_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_dependabot_looking_branch_does_not_establish_platform_identity() -> None:
    namespace = _audit_namespace()
    assert (
        namespace["_ref_classification"]("refs/remotes/origin/dependabot/pip/main/example")
        == "REMOTE_AUTOMATION_BRANCH"
    )
    observation = _observation(
        namespace,
        "1" * 64,
        refs=("REMOTE_AUTOMATION_BRANCH",),
    )
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_wrong_platform_identity_fingerprint_fails() -> None:
    namespace = _audit_namespace()
    policy = next(iter(namespace["VERIFIED_PLATFORM_SERVICE_POLICIES"].values()))
    observation = _observation(
        namespace,
        "2" * 64,
        roles=policy.allowed_roles,
        refs=policy.allowed_ref_classifications,
    )
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"


def test_platform_identity_without_reviewed_provenance_fails() -> None:
    namespace = _audit_namespace()
    policies = dict(namespace["VERIFIED_PLATFORM_SERVICE_POLICIES"])
    fingerprint, policy = next(iter(policies.items()))
    policies[fingerprint] = replace(policy, evidence_sources=())
    observation = _observation(
        namespace,
        fingerprint,
        roles=policy.allowed_roles,
        refs=policy.allowed_ref_classifications,
    )
    assert (
        namespace["_classify_identity"](observation, platform_policies=policies)
        == "UNKNOWN_AUTOMATION_IDENTITY"
    )


def test_platform_identity_cannot_satisfy_owner_approval() -> None:
    namespace = _audit_namespace()
    services = _reviewed_platform_observations(namespace)
    check = namespace["_identity_classification_check"](services)
    assert check.passed is False
    assert "approved_humans=0" in check.detail


def test_platform_identity_has_no_publisher_or_release_authority() -> None:
    namespace = _audit_namespace()
    records = namespace["_identity_report_records"](_reviewed_platform_observations(namespace))
    assert all(record["category"] == "VERIFIED_PLATFORM_SERVICE_IDENTITY" for record in records)
    assert all(
        record["authority_limit"] == "NO_OWNER_PUBLISHER_MAINTAINER_RELEASE_OR_REPOSITORY_AUTHORITY"
        for record in records
    )


def test_reviewed_author_and_committer_identities_remain_distinct() -> None:
    namespace = _audit_namespace()
    observations = _reviewed_platform_observations(namespace)
    assert len({observation.fingerprint for observation in observations}) == 2
    assert {observation.roles for observation in observations} == {
        ("AUTHOR",),
        ("COMMITTER",),
    }


def test_annotated_tag_taggers_remain_scanned() -> None:
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


def test_remote_automation_ref_is_part_of_public_identity_inventory() -> None:
    namespace = _audit_namespace()
    observation = _reviewed_platform_observations(namespace)[0]
    assert observation.reachable_ref_classifications == ("REMOTE_AUTOMATION_BRANCH",)
    record = namespace["_identity_report_records"]([observation])[0]
    assert record["reachable_ref_classifications"] == ["REMOTE_AUTOMATION_BRANCH"]


def test_main_only_scanning_cannot_replace_all_ref_scanning() -> None:
    source = (ROOT / "tools/audit_public_release_readiness.py").read_text(encoding="utf-8")
    assert '_git("for-each-ref", "--format=%(refname)")' in source
    assert '"log",\n        "--all"' in source
    assert '"rev-list", refname' in source


def test_unknown_and_invalid_classifications_fail_readiness() -> None:
    namespace = _audit_namespace()
    unknown = _observation(namespace, "3" * 64)
    invalid = _observation(namespace, "invalid", valid=False)
    for observation, expected in (
        (unknown, "UNKNOWN_HUMAN_IDENTITY"),
        (invalid, "INVALID_IDENTITY_RECORD"),
    ):
        assert namespace["_classify_identity"](observation) == expected
        assert (
            namespace["_identity_classification_check"](
                [_approved_human(namespace), observation]
            ).passed
            is False
        )


def test_identity_report_contains_no_raw_approved_values() -> None:
    namespace = _audit_namespace()
    records = namespace["_identity_report_records"](
        [_approved_human(namespace), *_reviewed_platform_observations(namespace)]
    )
    serialized = json.dumps(records, sort_keys=True)
    assert "@" not in serialized
    assert "/home/" not in serialized
    assert "/tmp/" not in serialized
    assert all(len(record["fingerprint"]) == 64 for record in records)


def test_exact_ci_identity_topology_is_valid_and_fully_visible() -> None:
    namespace = _audit_namespace()
    observations = [_approved_human(namespace), *_reviewed_platform_observations(namespace)]
    records = namespace["_identity_report_records"](observations)
    assert namespace["_identity_classification_check"](observations).passed is True
    assert [record["category"] for record in records].count("OWNER_APPROVED_HUMAN_IDENTITY") == 1
    assert [record["category"] for record in records].count(
        "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    ) == 2
    assert {role for record in records for role in record["roles"]} == {
        "AUTHOR",
        "COMMITTER",
        "TAGGER",
    }


def test_synthetic_identity_requires_explicit_test_fingerprint() -> None:
    namespace = _audit_namespace()
    fingerprint = namespace["_identity_fingerprint"](b"synthetic", b"synthetic@example.invalid")
    observation = _observation(namespace, fingerprint)
    assert namespace["_classify_identity"](observation) == "UNKNOWN_HUMAN_IDENTITY"
    assert (
        namespace["_classify_identity"](
            observation,
            synthetic_test_fingerprints=frozenset({fingerprint}),
        )
        == "SYNTHETIC_TEST_IDENTITY"
    )


def test_identity_taxonomy_is_complete_and_deterministic() -> None:
    namespace = _audit_namespace()
    assert namespace["IDENTITY_CATEGORIES"] == (
        "INVALID_IDENTITY_RECORD",
        "OWNER_APPROVED_HUMAN_IDENTITY",
        "SYNTHETIC_TEST_IDENTITY",
        "UNKNOWN_AUTOMATION_IDENTITY",
        "UNKNOWN_HUMAN_IDENTITY",
        "VERIFIED_PLATFORM_SERVICE_IDENTITY",
    )
    first = namespace["_identity_report_records"](
        [_approved_human(namespace), *_reviewed_platform_observations(namespace)]
    )
    second = namespace["_identity_report_records"](
        [_approved_human(namespace), *_reviewed_platform_observations(namespace)]
    )
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_existing_synthetic_path_and_secret_markers_remain_non_authoritative() -> None:
    namespace = _audit_namespace()
    assert namespace["SYNTHETIC_HOME_USERS"] == {"example", "synthetic", "user"}
    fingerprint = namespace["_identity_fingerprint"](
        b"github-looking[bot]", b"github-looking@users.noreply.github.com"
    )
    observation = _observation(namespace, fingerprint, refs=("REMOTE_AUTOMATION_BRANCH",))
    assert namespace["_classify_identity"](observation) == "UNKNOWN_AUTOMATION_IDENTITY"
