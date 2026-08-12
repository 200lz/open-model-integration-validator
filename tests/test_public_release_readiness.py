from __future__ import annotations

import json
import runpy
import subprocess
import tomllib
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from omiv import __version__
from omiv.cli import app

ROOT = Path(__file__).resolve().parents[1]


def _privacy_safe_audit_failure(result: subprocess.CompletedProcess[str]) -> str:
    def safe_code(value: object) -> str:
        if not isinstance(value, str) or not value:
            return "UNAVAILABLE"
        if not all(
            character.isascii() and (character.isalnum() or character == "_") for character in value
        ):
            return "REDACTED"
        return value

    try:
        report = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        report = {}
    checks = report.get("checks", []) if isinstance(report, dict) else []
    failed_checks = sorted(
        safe_code(check.get("name"))
        for check in checks
        if isinstance(check, dict) and check.get("passed") is False
    )
    privacy = report.get("privacy", {}) if isinstance(report, dict) else {}
    pull_request = privacy.get("pull_request_evidence", {}) if isinstance(privacy, dict) else {}
    if not isinstance(pull_request, dict):
        pull_request = {}
    classification = (
        safe_code(report.get("classification")) if isinstance(report, dict) else "UNAVAILABLE"
    )
    stderr_state = "EMPTY" if not result.stderr else "PRESENT_REDACTED"
    return " ".join(
        (
            f"audit_returncode={result.returncode}",
            f"classification={classification}",
            f"failed_checks={','.join(failed_checks) if failed_checks else 'UNAVAILABLE'}",
            f"pull_request_status={safe_code(pull_request.get('status'))}",
            f"pull_request_reason={safe_code(pull_request.get('reason_code'))}",
            f"stderr={stderr_state}",
        )
    )


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
    policies = namespace["VERIFIED_PLATFORM_IDENTITY_POLICIES"]
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


def _signed_squash_fixture(
    namespace: dict[str, object],
    *,
    commit_sha: str = "6" * 40,
    tree_sha: str = "7" * 40,
    parent_sha: str = "8" * 40,
    ref_classifications: tuple[str, ...] = ("LOCAL_MAIN", "REMOTE_MAIN"),
) -> tuple[list[object], tuple[object, ...]]:
    occurrence_type = namespace["IdentityOccurrence"]
    evidence_type = namespace["GithubSignedSquashCommitIdentityEvidence"]
    signer = namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"]
    author_fingerprint = namespace["GITHUB_SQUASH_AUTHOR_FINGERPRINT"]
    committer_fingerprint = namespace["GITHUB_SQUASH_COMMITTER_FINGERPRINT"]
    refnames = ("refs/heads/main", "refs/remotes/origin/main")
    evidence = evidence_type(  # type: ignore[operator]
        valid=True,
        repository_full_name=namespace["GITHUB_REPOSITORY_FULL_NAME"],
        commit_sha=commit_sha,
        tree_sha=tree_sha,
        parents=(parent_sha,),
        pr_number=17,
        author_fingerprint=author_fingerprint,
        committer_fingerprint=committer_fingerprint,
        signature_key_id=signer,
        signer_fingerprint=namespace["GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT"],
        authoritative_ref_classifications=ref_classifications,
        observed_git_identity=True,
        reviewed_github_actor_association=True,
        live_actor_observation_supplied=False,
    )
    observations = []
    for fingerprint, role in (
        (author_fingerprint, "AUTHOR"),
        (committer_fingerprint, "COMMITTER"),
    ):
        occurrence = occurrence_type(  # type: ignore[operator]
            object_sha=commit_sha,
            role=role,
            refnames=refnames,
            ref_classifications=ref_classifications,
            parents=(parent_sha,),
            signature_key_ids=(signer,),
        )
        observations.append(
            _observation(
                namespace,
                fingerprint,
                roles=(role,),
                refs=ref_classifications,
                occurrences=(occurrence,),
            )
        )
    return observations, (evidence,)


def _valid_pull_request_event(namespace: dict[str, object]) -> dict[str, Any]:
    def repository() -> dict[str, Any]:
        return {
            "id": namespace["GITHUB_REPOSITORY_ID"],
            "full_name": namespace["GITHUB_REPOSITORY_FULL_NAME"],
            "owner": {"id": namespace["GITHUB_OWNER_ACTOR_ID"], "login": "200lz"},
        }

    return {
        "number": namespace["PR2_NUMBER"],
        "repository": repository(),
        "sender": {"id": namespace["GITHUB_OWNER_ACTOR_ID"], "login": "200lz"},
        "pull_request": {
            "number": namespace["PR2_NUMBER"],
            "user": {"id": namespace["GITHUB_OWNER_ACTOR_ID"], "login": "200lz"},
            "base": {
                "ref": "main",
                "sha": namespace["PR2_BASE_SHA"],
                "repo": repository(),
            },
            "head": {
                "ref": namespace["PR2_HEAD_REF"],
                "sha": "b" * 40,
                "repo": repository(),
            },
            "merge_commit_sha": "c" * 40,
        },
    }


def _build_pull_request_evidence(
    namespace: dict[str, object],
    tmp_path: Path,
    monkeypatch: Any,
    *,
    event: dict[str, Any] | None = None,
    raw_event: str | None = None,
    env: dict[str, str] | None = None,
    event_path_available: bool = True,
    event_path_symlink: bool = False,
    git_object_available: bool = True,
    local_head: str | None = None,
    local_parents: tuple[str, ...] | None = None,
    local_ref_matches: bool = True,
    local_ref_error: bool = False,
    signature_key_ids: tuple[str, ...] | None = None,
    pr_metadata_available: bool = True,
    actor_evidence_available: bool = True,
    pr_metadata_status_code: int = 403,
    pr_metadata_reason_code: str = "HTTP_STATUS_NOT_SUCCESS",
    actor_evidence_status_code: int = 0,
    actor_evidence_reason_code: str = "NETWORK_ERROR",
    pr_api_changes: dict[str, Any] | None = None,
    commit_api_changes: dict[str, Any] | None = None,
    pr_number: int | None = None,
    base_sha: str | None = None,
    head_ref: str | None = None,
    head_sha: str | None = None,
    base_tracking_sha: str | None = "",
    head_tracking_sha: str | None = "",
    origin_repository: str | None = "",
    verified_signer: str | None = "",
) -> object:
    selected_event = _valid_pull_request_event(namespace) if event is None else event
    event_path = tmp_path / f"bounded-event-{len(tuple(tmp_path.iterdir()))}.json"
    selected_pr_number = namespace["PR2_NUMBER"] if pr_number is None else pr_number
    selected_base_sha = namespace["PR2_BASE_SHA"] if base_sha is None else base_sha
    selected_head_ref = namespace["PR2_HEAD_REF"] if head_ref is None else head_ref
    selected_head_sha = "b" * 40 if head_sha is None else head_sha
    merge_sha = "c" * 40
    if event is None:
        selected_event["number"] = selected_pr_number
        selected_event["pull_request"]["number"] = selected_pr_number
        selected_event["pull_request"]["base"]["sha"] = selected_base_sha
        selected_event["pull_request"]["head"]["ref"] = selected_head_ref
        selected_event["pull_request"]["head"]["sha"] = selected_head_sha
    if event_path_available:
        serialized_event = json.dumps(selected_event) if raw_event is None else raw_event
        if event_path_symlink:
            event_target = event_path.with_suffix(".target")
            event_target.write_text(serialized_event, encoding="utf-8")
            event_path.symlink_to(event_target)
        else:
            event_path.write_text(serialized_event, encoding="utf-8")
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REF": f"refs/pull/{selected_pr_number}/merge",
        "GITHUB_SHA": merge_sha,
        "GITHUB_HEAD_REF": selected_head_ref,
        "GITHUB_BASE_REF": "main",
        "GITHUB_REPOSITORY": namespace["GITHUB_REPOSITORY_FULL_NAME"],
        "GITHUB_REPOSITORY_ID": str(namespace["GITHUB_REPOSITORY_ID"]),
        "GITHUB_REPOSITORY_OWNER": "200lz",
        "GITHUB_REPOSITORY_OWNER_ID": str(namespace["GITHUB_OWNER_ACTOR_ID"]),
        "GITHUB_ACTOR": "200lz",
        "GITHUB_ACTOR_ID": str(namespace["GITHUB_OWNER_ACTOR_ID"]),
        "GITHUB_EVENT_PATH": str(event_path),
    }
    environment.update(env or {})
    for key, value in environment.items():
        monkeypatch.setenv(key, str(value))

    pr_api = {
        "number": selected_pr_number,
        "base": {
            "repo": {
                "id": namespace["GITHUB_REPOSITORY_ID"],
                "full_name": namespace["GITHUB_REPOSITORY_FULL_NAME"],
            },
            "ref": "main",
            "sha": selected_base_sha,
        },
        "head": {
            "repo": {
                "id": namespace["GITHUB_REPOSITORY_ID"],
                "full_name": namespace["GITHUB_REPOSITORY_FULL_NAME"],
            },
            "ref": selected_head_ref,
            "sha": selected_head_sha,
        },
        "user": {"id": namespace["GITHUB_OWNER_ACTOR_ID"]},
        "merge_commit_sha": merge_sha,
    }
    commit_api = {
        "sha": merge_sha,
        "parents": [{"sha": selected_base_sha}, {"sha": selected_head_sha}],
        "author": {"id": namespace["GITHUB_OWNER_ACTOR_ID"]},
        "committer": {"id": namespace["GITHUB_WEB_FLOW_ACTOR_ID"]},
        "commit": {"verification": {"verified": True, "reason": "valid"}},
    }

    def deep_update(target: dict[str, Any], changes: dict[str, Any]) -> None:
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                deep_update(target[key], value)
            else:
                target[key] = value

    deep_update(pr_api, pr_api_changes or {})
    deep_update(commit_api, commit_api_changes or {})
    github_result = namespace["GitHubJsonResult"]

    def fake_github_json(url: str) -> object:
        if url.endswith(f"/pulls/{selected_pr_number}"):
            if not pr_metadata_available:
                return github_result(False, pr_metadata_reason_code, pr_metadata_status_code)
            return github_result(True, "AVAILABLE", 200, pr_api)
        if not actor_evidence_available:
            return github_result(False, actor_evidence_reason_code, actor_evidence_status_code)
        return github_result(True, "AVAILABLE", 200, commit_api)

    selected_head = merge_sha if local_head is None else local_head
    selected_parents = (
        (selected_base_sha, selected_head_sha) if local_parents is None else local_parents
    )

    def fake_git(*args: str, input_bytes: bytes | None = None) -> bytes:
        del input_bytes
        if args[:2] == ("cat-file", "-e"):
            if not git_object_available:
                raise subprocess.CalledProcessError(1, args)
            return b""
        if args == ("rev-parse", "HEAD"):
            return f"{selected_head}\n".encode()
        if args[:3] == ("show", "-s", "--format=%P"):
            return (" ".join(selected_parents) + "\n").encode()
        raise AssertionError(f"unexpected git call: {args!r}")

    def fake_ref_matches(pr_number: int, candidate_merge_sha: str) -> bool:
        assert pr_number == selected_pr_number
        assert candidate_merge_sha == merge_sha
        if local_ref_error:
            raise subprocess.CalledProcessError(1, ("git", "show-ref"))
        return local_ref_matches

    builder = namespace["_current_pull_request_evidence"]
    builder_globals = builder.__wrapped__.__globals__
    builder_globals["_github_json"] = fake_github_json
    builder_globals["_git"] = fake_git
    builder_globals["_local_merge_ref_matches"] = fake_ref_matches
    selected_base_tracking_sha = selected_base_sha if base_tracking_sha == "" else base_tracking_sha
    selected_head_tracking_sha = selected_head_sha if head_tracking_sha == "" else head_tracking_sha

    def fake_tracking_ref(refname: str) -> str | None:
        if refname == "refs/remotes/origin/main":
            return selected_base_tracking_sha
        if refname == f"refs/remotes/origin/{selected_head_ref}":
            return selected_head_tracking_sha
        raise AssertionError(f"unexpected tracking ref: {refname!r}")

    builder_globals["_local_ref_sha_if_available"] = fake_tracking_ref
    builder_globals["_normalized_origin_repository"] = lambda: (
        namespace["GITHUB_REPOSITORY_FULL_NAME"] if origin_repository == "" else origin_repository
    )
    builder_globals["_commit_signature_key_ids"] = lambda _: (
        (namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"],)
        if signature_key_ids is None
        else signature_key_ids
    )
    builder_globals["_cryptographically_verified_signer"] = lambda _: (
        namespace["GITHUB_WEB_FLOW_SIGNING_KEY_FINGERPRINT"]
        if verified_signer == ""
        else verified_signer
    )
    builder.cache_clear()
    return builder()


def test_detached_actions_merge_checkout_builds_available_evidence(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch)
    assert result.status == "AVAILABLE"
    assert result.reason_code == "AVAILABLE"
    assert result.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
    assert result.live_metadata_state == "LIVE_PR_METADATA_CORROBORATED"
    assert result.merge_discrepancy == "EVENT_TEST_MERGE_SHA_MATCHES_CURRENT_CHECKOUT"
    assert result.evidence is not None
    assert result.evidence.merge_sha == "c" * 40
    assert result.evidence.parents == (namespace["PR2_BASE_SHA"], "b" * 40)
    assert result.safe_facts["detached_head_matches"] is True
    assert result.safe_facts["local_merge_ref_matches"] is True


def test_stale_event_test_merge_is_recorded_after_current_checkout_verifies(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    event = _valid_pull_request_event(namespace)
    event["pull_request"]["merge_commit_sha"] = "d" * 40
    result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, event=event)
    assert result.status == "AVAILABLE"
    assert result.reason_code == "AVAILABLE"
    assert result.merge_discrepancy == "EVENT_TEST_MERGE_SHA_DIFFERS_FROM_CURRENT_CHECKOUT"
    assert result.evidence is not None
    assert result.evidence.merge_sha == "c" * 40
    assert result.safe_facts["event_merge_matches_current_checkout"] is False
    serialized = json.dumps(asdict(result), sort_keys=True)
    assert "d" * 40 not in serialized
    assert "@" not in serialized
    assert "/home/" not in serialized
    assert "/tmp/" not in serialized
    assert "token" not in serialized.lower()


def test_absent_or_null_event_test_merge_is_advisory(tmp_path: Path, monkeypatch: Any) -> None:
    for mode in ("absent", "null"):
        namespace = _audit_namespace()
        event = _valid_pull_request_event(namespace)
        if mode == "absent":
            event["pull_request"].pop("merge_commit_sha")
        else:
            event["pull_request"]["merge_commit_sha"] = None
        result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, event=event)
        assert (result.status, result.reason_code) == ("AVAILABLE", "AVAILABLE")
        assert result.merge_discrepancy == "EVENT_TEST_MERGE_SHA_NOT_RECORDED"
        assert result.evidence is not None
        expected_missing = ("pull_request.merge_commit_sha",) if mode == "absent" else ()
        expected_null = ("pull_request.merge_commit_sha",) if mode == "null" else ()
        assert result.missing_advisory_fields == expected_missing
        assert result.null_advisory_fields == expected_null
        assert result.missing_required_fields == ()
        assert result.null_required_fields == ()


def test_malformed_non_null_event_test_merge_fails_closed(tmp_path: Path, monkeypatch: Any) -> None:
    namespace = _audit_namespace()
    event = _valid_pull_request_event(namespace)
    event["pull_request"]["merge_commit_sha"] = "not-a-sha"
    result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, event=event)
    assert (result.status, result.reason_code, result.evidence) == (
        "INVALID",
        "EVENT_FIELDS_INCOMPLETE",
        None,
    )
    assert result.safe_facts["advisory_merge_sha_malformed"] is True
    assert result.missing_advisory_fields == ()
    assert result.null_advisory_fields == ()


def test_required_event_field_diagnostics_are_sorted_and_fail_closed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    required_paths = namespace["PULL_REQUEST_REQUIRED_EVENT_FIELDS"]

    def mutate(event: dict[str, Any], path: str, *, null: bool) -> None:
        components = path.split(".")
        selected: dict[str, Any] = event
        for component in components[:-1]:
            selected = selected[component]
        if null:
            selected[components[-1]] = None
        else:
            selected.pop(components[-1])

    for path in required_paths:
        for null in (False, True):
            namespace = _audit_namespace()
            event = _valid_pull_request_event(namespace)
            mutate(event, path, null=null)
            result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, event=event)
            assert (result.status, result.reason_code, result.evidence) == (
                "INVALID",
                "EVENT_FIELDS_INCOMPLETE",
                None,
            )
            assert result.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_INCOMPLETE"
            expected = (path,)
            assert result.null_required_fields == (expected if null else ())
            assert result.missing_required_fields == (() if null else expected)
            serialized = json.dumps(asdict(result), sort_keys=True)
            assert "@" not in serialized
            assert "/home/" not in serialized
            assert "/tmp/" not in serialized
            assert "token" not in serialized.lower()


def test_current_corrective_pr_scope_builds_exact_available_evidence(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    result = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_number=3,
        base_sha="d" * 40,
        head_ref="fix/reviewed-correction",
    )
    assert (result.status, result.reason_code) == ("AVAILABLE", "AVAILABLE")
    assert result.evidence is not None
    assert result.evidence.pr_number == 3
    assert result.evidence.base_sha == "d" * 40
    assert result.evidence.head_ref == "fix/reviewed-correction"
    policies = namespace["VERIFIED_PLATFORM_IDENTITY_POLICIES"]
    assert any(
        role.current_event_scope
        and role.pr_number is None
        and role.base_sha is None
        and role.head_ref is None
        for policy in policies.values()  # type: ignore[union-attr]
        for role in policy.pull_request_roles
    )
    occurrence_type = namespace["IdentityOccurrence"]
    categories = []
    for fingerprint, role in (
        (namespace["GITHUB_SQUASH_AUTHOR_FINGERPRINT"], "AUTHOR"),
        (namespace["GITHUB_SQUASH_COMMITTER_FINGERPRINT"], "COMMITTER"),
    ):
        occurrence = occurrence_type(  # type: ignore[operator]
            object_sha="c" * 40,
            role=role,
            refnames=("refs/pull/3/merge",),
            ref_classifications=("PULL_REQUEST_MERGE_REF",),
            parents=("d" * 40, "b" * 40),
            signature_key_ids=(namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"],),
        )
        observation = _observation(
            namespace,
            fingerprint,  # type: ignore[arg-type]
            roles=(role,),
            refs=("PULL_REQUEST_MERGE_REF",),
            occurrences=(occurrence,),
        )
        categories.append(
            namespace["_classify_identity"](observation, pull_request_evidence=result.evidence)
        )
    assert categories == [
        "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
        "VERIFIED_PLATFORM_SERVICE_IDENTITY",
    ]


def test_pull_request_evidence_pre_event_reason_codes(tmp_path: Path, monkeypatch: Any) -> None:
    cases = (
        ({"GITHUB_ACTIONS": "false"}, "NOT_AVAILABLE", "NOT_GITHUB_ACTIONS"),
        ({"GITHUB_EVENT_NAME": "push"}, "NOT_AVAILABLE", "EVENT_NOT_PULL_REQUEST"),
        (
            {"GITHUB_EVENT_NAME": "pull_request_target"},
            "NOT_AVAILABLE",
            "EVENT_NOT_PULL_REQUEST",
        ),
        ({"GITHUB_REPOSITORY": "example/unrelated"}, "INVALID", "REPOSITORY_MISMATCH"),
    )
    for env, status, reason in cases:
        namespace = _audit_namespace()
        result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, env=env)
        assert (result.status, result.reason_code, result.evidence) == (status, reason, None)
        assert result.merge_discrepancy == "NOT_EVALUATED"


def test_pull_request_event_file_failures_are_typed(tmp_path: Path, monkeypatch: Any) -> None:
    namespace = _audit_namespace()
    missing = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, event_path_available=False
    )
    assert (missing.status, missing.reason_code) == (
        "NOT_AVAILABLE",
        "EVENT_PATH_NOT_AVAILABLE",
    )

    namespace = _audit_namespace()
    malformed = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, raw_event="{not-json"
    )
    assert (malformed.status, malformed.reason_code) == ("INVALID", "EVENT_JSON_INVALID")

    namespace = _audit_namespace()
    incomplete_event = _valid_pull_request_event(namespace)
    incomplete_event.pop("number")
    incomplete = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, event=incomplete_event
    )
    assert (incomplete.status, incomplete.reason_code) == (
        "INVALID",
        "EVENT_FIELDS_INCOMPLETE",
    )
    assert incomplete.missing_required_fields == ("number",)
    assert incomplete.missing_advisory_fields == ()
    assert incomplete.null_required_fields == ()
    assert incomplete.null_advisory_fields == ()

    namespace = _audit_namespace()
    oversized = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, raw_event=" " * 1_048_577
    )
    assert (oversized.status, oversized.reason_code) == ("INVALID", "LIMIT_EXCEEDED")

    namespace = _audit_namespace()
    symlinked = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, event_path_symlink=True
    )
    assert (symlinked.status, symlinked.reason_code) == (
        "INVALID",
        "EVENT_PATH_NOT_AVAILABLE",
    )

    namespace = _audit_namespace()
    invalid_sha = _valid_pull_request_event(namespace)
    invalid_sha["pull_request"]["head"]["sha"] = "not-a-sha"
    malformed_field = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, event=invalid_sha
    )
    assert (malformed_field.status, malformed_field.reason_code) == (
        "INVALID",
        "EVENT_FIELDS_INCOMPLETE",
    )


def test_pull_request_event_identity_mismatches_are_typed(tmp_path: Path, monkeypatch: Any) -> None:
    mutations = []
    namespace = _audit_namespace()
    repository = _valid_pull_request_event(namespace)
    repository["repository"]["id"] = 1
    mutations.append((repository, "REPOSITORY_MISMATCH"))
    pr_number = _valid_pull_request_event(namespace)
    pr_number["number"] = 99
    mutations.append((pr_number, "PR_NUMBER_MISMATCH"))
    base_ref = _valid_pull_request_event(namespace)
    base_ref["pull_request"]["base"]["ref"] = "other"
    mutations.append((base_ref, "BASE_REF_MISMATCH"))
    base_sha = _valid_pull_request_event(namespace)
    base_sha["pull_request"]["base"]["sha"] = "a" * 40
    mutations.append((base_sha, "CHECKOUT_SHA_MISMATCH"))
    head_ref = _valid_pull_request_event(namespace)
    head_ref["pull_request"]["head"]["ref"] = "unrelated"
    mutations.append((head_ref, "HEAD_REF_MISMATCH"))
    for event, reason in mutations:
        selected = _audit_namespace()
        result = _build_pull_request_evidence(selected, tmp_path, monkeypatch, event=event)
        assert (result.status, result.reason_code) == ("INVALID", reason)


def test_checkout_and_git_topology_failures_are_typed(tmp_path: Path, monkeypatch: Any) -> None:
    cases = (
        ({"env": {"GITHUB_BASE_REF": "unrelated"}}, "BASE_REF_MISMATCH"),
        ({"env": {"GITHUB_HEAD_REF": "unrelated"}}, "HEAD_REF_MISMATCH"),
        ({"env": {"GITHUB_REF": "refs/heads/unrelated"}}, "REF_SCOPE_MISMATCH"),
        ({"env": {"GITHUB_REF": "refs/pull/1/merge"}}, "PR_NUMBER_MISMATCH"),
        ({"env": {"GITHUB_SHA": "d" * 40}}, "CHECKOUT_SHA_MISMATCH"),
        ({"git_object_available": False}, "GIT_OBJECT_NOT_AVAILABLE"),
        ({"local_head": "d" * 40}, "CHECKOUT_SHA_MISMATCH"),
        ({"local_parents": ("a" * 40,)}, "PARENT_COUNT_INVALID"),
        ({"local_ref_matches": False}, "REF_SCOPE_MISMATCH"),
        ({"local_ref_error": True}, "INTERNAL_VALIDATION_ERROR"),
        ({"signature_key_ids": ("DEADBEEFDEADBEEF",)}, "SIGNER_MISMATCH"),
    )
    for options, reason in cases:
        namespace = _audit_namespace()
        result = _build_pull_request_evidence(
            namespace,
            tmp_path,
            monkeypatch,
            **options,  # type: ignore[arg-type]
        )
        expected_status = "INDETERMINATE" if reason == "INTERNAL_VALIDATION_ERROR" else "INVALID"
        assert (result.status, result.reason_code) == (expected_status, reason)

    namespace = _audit_namespace()
    reversed_parents = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        local_parents=("b" * 40, namespace["PR2_BASE_SHA"]),
    )
    assert (reversed_parents.status, reversed_parents.reason_code) == (
        "INVALID",
        "PARENT_ORDER_MISMATCH",
    )

    namespace = _audit_namespace()
    extra_parent = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        local_parents=(namespace["PR2_BASE_SHA"], "b" * 40, "e" * 40),
    )
    assert (extra_parent.status, extra_parent.reason_code) == (
        "INVALID",
        "PARENT_COUNT_INVALID",
    )

    namespace = _audit_namespace()
    event_head_mismatch = _valid_pull_request_event(namespace)
    event_head_mismatch["pull_request"]["head"]["sha"] = "d" * 40
    mismatched_parent_binding = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, event=event_head_mismatch
    )
    assert (
        mismatched_parent_binding.status,
        mismatched_parent_binding.reason_code,
    ) == ("INVALID", "CHECKOUT_SHA_MISMATCH")


def test_remote_metadata_failures_are_typed_without_becoming_authority(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    pr_missing = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, pr_metadata_available=False
    )
    assert (pr_missing.status, pr_missing.reason_code) == ("AVAILABLE", "AVAILABLE")
    assert pr_missing.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
    assert pr_missing.live_metadata_state == "LIVE_PR_METADATA_NOT_AVAILABLE"
    assert pr_missing.live_metadata_reason_code == "PR_HTTP_STATUS_NOT_SUCCESS"
    assert pr_missing.safe_facts["pr_metadata_status_code"] == 403
    assert pr_missing.evidence is not None

    namespace = _audit_namespace()
    actor_missing = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, actor_evidence_available=False
    )
    assert (actor_missing.status, actor_missing.reason_code) == ("AVAILABLE", "AVAILABLE")
    assert actor_missing.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
    assert actor_missing.live_metadata_state == "LIVE_PR_METADATA_NOT_AVAILABLE"
    assert actor_missing.live_metadata_reason_code == "COMMIT_NETWORK_ERROR"
    assert actor_missing.safe_facts["actor_evidence_status_code"] == 0
    assert actor_missing.evidence is not None


def test_bounded_live_pr_failures_leave_event_bound_evidence_deterministic(
    tmp_path: Path, monkeypatch: Any
) -> None:
    serialized_results = []
    for status_code, reason_code in (
        (404, "HTTP_STATUS_NOT_SUCCESS"),
        (429, "HTTP_STATUS_NOT_SUCCESS"),
        (503, "HTTP_STATUS_NOT_SUCCESS"),
        (0, "NETWORK_ERROR"),
    ):
        namespace = _audit_namespace()
        result = _build_pull_request_evidence(
            namespace,
            tmp_path,
            monkeypatch,
            pr_metadata_available=False,
            actor_evidence_available=False,
            pr_metadata_status_code=status_code,
            pr_metadata_reason_code=reason_code,
            actor_evidence_status_code=status_code,
            actor_evidence_reason_code=reason_code,
        )
        assert (result.status, result.reason_code) == ("AVAILABLE", "AVAILABLE")
        assert result.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
        assert result.live_metadata_state == "LIVE_PR_METADATA_NOT_AVAILABLE"
        assert result.evidence is not None
        serialized_results.append(json.dumps(asdict(result), sort_keys=True))

    namespace = _audit_namespace()
    first = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_metadata_available=False,
        actor_evidence_available=False,
    )
    namespace = _audit_namespace()
    second = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_metadata_available=False,
        actor_evidence_available=False,
    )
    assert json.dumps(asdict(first), sort_keys=True) == json.dumps(asdict(second), sort_keys=True)
    assert all(
        "@" not in item and "/tmp/" not in item and "token" not in item.lower()
        for item in serialized_results
    )


def test_live_authentication_and_schema_anomalies_are_typed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    authentication = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_metadata_available=False,
        pr_metadata_status_code=401,
    )
    assert (authentication.status, authentication.reason_code) == (
        "INVALID",
        "LIVE_METADATA_AUTHENTICATION_ANOMALY",
    )
    assert authentication.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
    assert authentication.live_metadata_state == "LIVE_PR_METADATA_CONFLICT"

    namespace = _audit_namespace()
    schema = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_metadata_available=False,
        pr_metadata_reason_code="RESPONSE_JSON_INVALID",
        pr_metadata_status_code=200,
    )
    assert (schema.status, schema.reason_code) == (
        "INVALID",
        "LIVE_METADATA_SCHEMA_INVALID",
    )
    assert schema.live_metadata_state == "LIVE_PR_METADATA_CONFLICT"


def test_remote_pr_and_commit_mismatches_are_typed(tmp_path: Path, monkeypatch: Any) -> None:
    namespace = _audit_namespace()
    wrong_pr_number = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={"number": 1},
    )
    assert (wrong_pr_number.status, wrong_pr_number.reason_code) == (
        "INVALID",
        "PR_NUMBER_MISMATCH",
    )

    namespace = _audit_namespace()
    wrong_repository = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={
            "base": {
                "repo": {"id": 1},
                "ref": "main",
                "sha": namespace["PR2_BASE_SHA"],
            }
        },
    )
    assert (wrong_repository.status, wrong_repository.reason_code) == (
        "INVALID",
        "REPOSITORY_MISMATCH",
    )
    assert wrong_repository.live_metadata_state == "LIVE_PR_METADATA_CONFLICT"

    namespace = _audit_namespace()
    wrong_base_ref = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={
            "base": {
                "repo": {"id": namespace["GITHUB_REPOSITORY_ID"]},
                "ref": "unrelated",
                "sha": namespace["PR2_BASE_SHA"],
            }
        },
    )
    assert (wrong_base_ref.status, wrong_base_ref.reason_code) == (
        "INVALID",
        "BASE_REF_MISMATCH",
    )

    namespace = _audit_namespace()
    wrong_base_sha = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={
            "base": {
                "repo": {"id": namespace["GITHUB_REPOSITORY_ID"]},
                "ref": "main",
                "sha": "d" * 40,
            }
        },
    )
    assert (wrong_base_sha.status, wrong_base_sha.reason_code) == (
        "INVALID",
        "BASE_SHA_MISMATCH",
    )

    namespace = _audit_namespace()
    wrong_head_ref = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={"head": {"ref": "unrelated", "sha": "b" * 40}},
    )
    assert (wrong_head_ref.status, wrong_head_ref.reason_code) == (
        "INVALID",
        "HEAD_REF_MISMATCH",
    )

    namespace = _audit_namespace()
    wrong_head = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={"head": {"ref": namespace["PR2_HEAD_REF"], "sha": "d" * 40}},
    )
    assert (wrong_head.status, wrong_head.reason_code) == ("INVALID", "HEAD_SHA_MISMATCH")

    namespace = _audit_namespace()
    wrong_merge = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={"merge_commit_sha": "d" * 40},
    )
    assert (wrong_merge.status, wrong_merge.reason_code) == ("AVAILABLE", "AVAILABLE")
    assert wrong_merge.merge_discrepancy == "EVENT_TEST_MERGE_SHA_MATCHES_CURRENT_CHECKOUT"
    assert wrong_merge.safe_facts["api_test_merge_matches_current_checkout"] is False

    for advisory_value in (None,):
        namespace = _audit_namespace()
        absent_api_merge = _build_pull_request_evidence(
            namespace,
            tmp_path,
            monkeypatch,
            pr_api_changes={"merge_commit_sha": advisory_value},
        )
        assert (absent_api_merge.status, absent_api_merge.reason_code) == (
            "AVAILABLE",
            "AVAILABLE",
        )
        assert absent_api_merge.safe_facts["api_test_merge_recorded"] is False

    namespace = _audit_namespace()
    malformed_test_merge = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        pr_api_changes={"merge_commit_sha": "not-a-sha"},
    )
    assert (malformed_test_merge.status, malformed_test_merge.reason_code) == (
        "INVALID",
        "MERGE_SHA_MISMATCH",
    )

    namespace = _audit_namespace()
    wrong_commit = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"sha": "d" * 40},
    )
    assert (wrong_commit.status, wrong_commit.reason_code) == (
        "INVALID",
        "MERGE_SHA_MISMATCH",
    )

    namespace = _audit_namespace()
    wrong_parent_count = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"parents": [{"sha": namespace["PR2_BASE_SHA"]}]},
    )
    assert (wrong_parent_count.status, wrong_parent_count.reason_code) == (
        "INVALID",
        "PARENT_COUNT_INVALID",
    )

    namespace = _audit_namespace()
    wrong_parents = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"parents": [{"sha": "b" * 40}, {"sha": namespace["PR2_BASE_SHA"]}]},
    )
    assert (wrong_parents.status, wrong_parents.reason_code) == (
        "INVALID",
        "PARENT_ORDER_MISMATCH",
    )


def test_event_repository_actor_and_branch_substitution_fail_closed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    fork = _valid_pull_request_event(namespace)
    fork["pull_request"]["head"]["repo"]["id"] = 1
    fork["pull_request"]["head"]["repo"]["full_name"] = "fork/unrelated"
    result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, event=fork)
    assert (result.status, result.reason_code) == ("INVALID", "REPOSITORY_MISMATCH")
    assert result.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_INVALID"

    namespace = _audit_namespace()
    result = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, head_tracking_sha="e" * 40
    )
    assert (result.status, result.reason_code) == ("INVALID", "HEAD_SHA_MISMATCH")

    namespace = _audit_namespace()
    result = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, base_tracking_sha="e" * 40
    )
    assert (result.status, result.reason_code) == ("INVALID", "BASE_SHA_MISMATCH")

    namespace = _audit_namespace()
    result = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, origin_repository="fork/unrelated"
    )
    assert (result.status, result.reason_code) == ("INVALID", "REPOSITORY_MISMATCH")

    namespace = _audit_namespace()
    wrong_actor = _valid_pull_request_event(namespace)
    wrong_actor["sender"]["id"] = 1
    result = _build_pull_request_evidence(namespace, tmp_path, monkeypatch, event=wrong_actor)
    assert (result.status, result.reason_code) == ("INVALID", "SIGNER_MISMATCH")


def test_live_repository_number_and_head_repository_conflicts_fail_closed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    cases = (
        ({"number": 99}, "PR_NUMBER_MISMATCH"),
        (
            {"head": {"repo": {"id": 1, "full_name": "fork/unrelated"}}},
            "REPOSITORY_MISMATCH",
        ),
    )
    for changes, reason_code in cases:
        namespace = _audit_namespace()
        result = _build_pull_request_evidence(
            namespace, tmp_path, monkeypatch, pr_api_changes=changes
        )
        assert (result.status, result.reason_code) == ("INVALID", reason_code)
        assert result.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
        assert result.live_metadata_state == "LIVE_PR_METADATA_CONFLICT"


def test_signature_and_actor_failures_are_typed(tmp_path: Path, monkeypatch: Any) -> None:
    namespace = _audit_namespace()
    unverified = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"commit": {"verification": {"verified": False, "reason": "unsigned"}}},
    )
    assert (unverified.status, unverified.reason_code) == (
        "INVALID",
        "SIGNATURE_NOT_VERIFIED",
    )

    namespace = _audit_namespace()
    wrong_actor = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"committer": {"id": 1}},
    )
    assert (wrong_actor.status, wrong_actor.reason_code) == ("INVALID", "SIGNER_MISMATCH")

    namespace = _audit_namespace()
    wrong_author = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"author": {"id": 1}},
    )
    assert (wrong_author.status, wrong_author.reason_code) == (
        "INVALID",
        "SIGNER_MISMATCH",
    )

    namespace = _audit_namespace()
    malformed_actor_evidence = _build_pull_request_evidence(
        namespace,
        tmp_path,
        monkeypatch,
        commit_api_changes={"commit": {"verification": None}},
    )
    assert (
        malformed_actor_evidence.status,
        malformed_actor_evidence.reason_code,
    ) == ("INVALID", "LIVE_METADATA_SCHEMA_INVALID")
    assert malformed_actor_evidence.event_bound_state == "EVENT_BOUND_PR_EVIDENCE_AVAILABLE"
    assert malformed_actor_evidence.live_metadata_state == "LIVE_PR_METADATA_CONFLICT"

    namespace = _audit_namespace()
    locally_unverified = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, verified_signer=None
    )
    assert (locally_unverified.status, locally_unverified.reason_code) == (
        "INVALID",
        "SIGNATURE_NOT_VERIFIED",
    )


def test_complete_event_bound_evidence_survives_live_metadata_unavailability_privacy_safely(
    tmp_path: Path, monkeypatch: Any
) -> None:
    namespace = _audit_namespace()
    result = _build_pull_request_evidence(
        namespace, tmp_path, monkeypatch, pr_metadata_available=False
    )
    assert result.evidence is not None
    services, fixture_evidence = _reviewed_platform_fixture(namespace)
    services = [
        replace(
            service,
            occurrences=tuple(
                replace(
                    occurrence,
                    object_sha=result.evidence.merge_sha,
                    refnames=(result.evidence.merge_ref,),
                    parents=result.evidence.parents,
                )
                if occurrence.object_sha == fixture_evidence.merge_sha
                and occurrence.ref_classifications == ("PULL_REQUEST_MERGE_REF",)
                else occurrence
                for occurrence in service.occurrences
            ),
        )
        for service in services
    ]
    observations = [_approved_human(namespace), *services]
    check = namespace["_identity_classification_check"](
        observations, pull_request_evidence=result.evidence
    )
    assert check.passed is True
    assert "verified_platform_mediated_accounts=1" in check.detail
    assert "unverified_platform_claims=0" in check.detail
    serialized = json.dumps(
        {
            "status": result.status,
            "reason_code": result.reason_code,
            "event_bound_state": result.event_bound_state,
            "live_metadata_state": result.live_metadata_state,
            "live_metadata_reason_code": result.live_metadata_reason_code,
            "merge_discrepancy": result.merge_discrepancy,
            "safe_facts": result.safe_facts,
            "evidence": result.evidence,
        },
        sort_keys=True,
        default=str,
    )
    assert "@" not in serialized
    assert "/home/" not in serialized
    assert "/tmp/" not in serialized
    assert "token" not in serialized.lower()
    assert "event.json" not in serialized


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
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, _privacy_safe_audit_failure(result)
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
        check=False,
        capture_output=True,
        text=True,
    )
    assert repeated.returncode == 0, _privacy_safe_audit_failure(repeated)
    assert repeated.stdout == result.stdout


def test_public_release_audit_failure_diagnostics_are_privacy_safe() -> None:
    result = subprocess.CompletedProcess(
        (),
        1,
        json.dumps(
            {
                "classification": "FAIL",
                "checks": [
                    {
                        "name": "approved_author_identity",
                        "passed": False,
                        "detail": "private@example.invalid local-private-path",
                    }
                ],
                "privacy": {
                    "pull_request_evidence": {
                        "status": "INDETERMINATE",
                        "reason_code": "ACTOR_EVIDENCE_NOT_AVAILABLE",
                        "unsafe": "github_pat_private-value",
                    }
                },
            }
        ),
        "credential=github_pat_private-value local-private-path",
    )
    diagnostic = _privacy_safe_audit_failure(result)
    assert diagnostic == (
        "audit_returncode=1 classification=FAIL "
        "failed_checks=approved_author_identity "
        "pull_request_status=INDETERMINATE "
        "pull_request_reason=ACTOR_EVIDENCE_NOT_AVAILABLE "
        "stderr=PRESENT_REDACTED"
    )
    assert "@" not in diagnostic
    assert "local-private-path" not in diagnostic
    assert "github_pat_" not in diagnostic


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
    policies = dict(namespace["VERIFIED_PLATFORM_IDENTITY_POLICIES"])
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
        expected = (
            "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY"
            if role == "AUTHOR"
            else "VERIFIED_PLATFORM_SERVICE_IDENTITY"
        )
        assert (
            namespace["_classify_identity"](observation, pull_request_evidence=evidence) == expected
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
    assert {record["category"] for record in records} == {
        "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
        "VERIFIED_PLATFORM_SERVICE_IDENTITY",
    }
    assert all(
        record["authority_limit"] == "NO_OWNER_PUBLISHER_MAINTAINER_RELEASE_OR_REPOSITORY_AUTHORITY"
        for record in records
    )


def test_signed_main_squash_identity_pair_passes_and_is_forward_safe() -> None:
    namespace = _audit_namespace()
    for commit_sha, tree_sha in (("6" * 40, "7" * 40), ("9" * 40, "a" * 40)):
        observations, evidence = _signed_squash_fixture(
            namespace, commit_sha=commit_sha, tree_sha=tree_sha
        )
        categories = [
            namespace["_classify_identity"](item, signed_squash_evidence=evidence)
            for item in observations
        ]
        assert categories == [
            "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
            "VERIFIED_PLATFORM_SERVICE_IDENTITY",
        ]
        assert namespace["_identity_classification_check"](
            [_approved_human(namespace), *observations],
            signed_squash_evidence=evidence,
        ).passed
    source = (ROOT / "tools/audit_public_release_readiness.py").read_text(encoding="utf-8")
    assert "bd53015609b7c3a08e106e0f5600dcd6c4fabc01" not in source


def test_signed_squash_roles_categories_and_authority_are_distinct() -> None:
    namespace = _audit_namespace()
    observations, evidence = _signed_squash_fixture(namespace)
    records = namespace["_identity_report_records"](observations, signed_squash_evidence=evidence)
    by_role = {record["roles"][0]: record for record in records}
    assert by_role["AUTHOR"]["category"] == "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY"
    assert by_role["COMMITTER"]["category"] == "VERIFIED_PLATFORM_SERVICE_IDENTITY"
    assert all(
        record["authority_limit"] == namespace["NO_PLATFORM_AUTHORITY"] for record in records
    )


def test_signed_squash_evidence_fails_closed_on_evidence_tampering() -> None:
    namespace = _audit_namespace()
    observations, evidence = _signed_squash_fixture(namespace)
    original = evidence[0]
    mutations = (
        {"valid": False},
        {"repository_full_name": "example/unrelated"},
        {"author_fingerprint": "1" * 64},
        {"committer_fingerprint": "2" * 64},
        {"signature_key_id": "DEADBEEFDEADBEEF"},
        {"signer_fingerprint": "3" * 40},
        {"authoritative_ref_classifications": ("REMOTE_OTHER_BRANCH",)},
        {"observed_git_identity": False},
        {"reviewed_github_actor_association": False},
        {"live_actor_observation_supplied": True},
        {"parents": ("8" * 40, "9" * 40)},
    )
    for changes in mutations:
        tampered = (replace(original, **changes),)
        categories = [
            namespace["_classify_identity"](item, signed_squash_evidence=tampered)
            for item in observations
        ]
        assert "UNVERIFIED_PLATFORM_SERVICE_CLAIM" in categories


def test_signed_squash_occurrence_fails_closed_on_role_scope_and_signature() -> None:
    namespace = _audit_namespace()
    observations, evidence = _signed_squash_fixture(namespace)
    author = observations[0]
    occurrence = author.occurrences[0]
    mutations = (
        replace(occurrence, role="COMMITTER"),
        replace(occurrence, parents=("8" * 40, "9" * 40)),
        replace(occurrence, signature_key_ids=("DEADBEEFDEADBEEF",)),
        replace(
            occurrence,
            refnames=("refs/remotes/origin/unrelated",),
            ref_classifications=("REMOTE_OTHER_BRANCH",),
        ),
    )
    for changed in mutations:
        tampered = replace(
            author,
            roles=(changed.role,),
            occurrences=(changed,),
            reachable_ref_classifications=changed.ref_classifications,
        )
        assert (
            namespace["_classify_identity"](tampered, signed_squash_evidence=evidence)
            == "UNVERIFIED_PLATFORM_SERVICE_CLAIM"
        )


def _valid_protected_squash_observation(namespace: dict[str, object]) -> dict[str, Any]:
    checks = {
        f"Python 3.{minor}": {"conclusion": "success", "app_id": 15368} for minor in range(11, 15)
    }
    return {
        "repository_full_name": namespace["GITHUB_REPOSITORY_FULL_NAME"],
        "pr_number": 17,
        "pr_state": "MERGED",
        "merged": True,
        "base_ref": "main",
        "base_sha": "1" * 40,
        "head_sha": "2" * 40,
        "head_tree": "3" * 40,
        "result_sha": "4" * 40,
        "associated_result_sha": "4" * 40,
        "result_parent": "1" * 40,
        "result_tree": "3" * 40,
        "merge_method": "squash",
        "author_actor_id": namespace["GITHUB_OWNER_ACTOR_ID"],
        "author_role": "AUTHOR",
        "committer_actor_id": namespace["GITHUB_WEB_FLOW_ACTOR_ID"],
        "committer_role": "COMMITTER",
        "signature_verified": True,
        "signature_reason": "valid",
        "signature_key_id": namespace["GITHUB_WEB_FLOW_SIGNING_KEY_ID"],
        "required_checks": checks,
        "branch_protection": {"strict": True, "required_checks": sorted(checks)},
        "observed_at": "2026-08-11T00:00:00Z",
    }


def test_protected_squash_merge_evidence_is_separate_and_fail_closed() -> None:
    namespace = _audit_namespace()
    builder = namespace["_protected_pull_request_squash_merge_evidence"]
    assert builder().status == "NOT_SUPPLIED"
    valid = _valid_protected_squash_observation(namespace)
    assert builder(valid).status == "AVAILABLE"
    mutations = (
        {"repository_full_name": "example/unrelated"},
        {"pr_state": "OPEN"},
        {"associated_result_sha": "5" * 40},
        {"head_tree": "5" * 40},
        {"result_parent": "6" * 40},
        {"merge_method": "merge"},
        {"author_actor_id": 1},
        {"author_role": "COMMITTER"},
        {"committer_actor_id": 2},
        {"committer_role": "AUTHOR"},
        {"signature_verified": False},
        {"signature_key_id": "DEADBEEFDEADBEEF"},
    )
    for changes in mutations:
        assert builder({**valid, **changes}).status == "INVALID"
    failed_checks = dict(valid["required_checks"])
    failed_checks["Python 3.11"] = {"conclusion": "failure", "app_id": 15368}
    assert builder({**valid, "required_checks": failed_checks}).status == "INVALID"
    changed_protection = dict(valid["branch_protection"])
    changed_protection["strict"] = False
    assert builder({**valid, "branch_protection": changed_protection}).status == "INVALID"


def test_real_authoritative_main_squash_evidence_is_offline_and_redacted() -> None:
    namespace = _audit_namespace()
    result = namespace["_github_signed_squash_commit_identity_evidence"]()
    assert result.status == "AVAILABLE"
    assert len(result.evidence) >= 1
    assert all(item.live_actor_observation_supplied is False for item in result.evidence)
    serialized = json.dumps(asdict(result), sort_keys=True)
    assert "@" not in serialized
    assert "/home/" not in serialized
    assert "/tmp/" not in serialized


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
    ) == 2
    assert [record["category"] for record in records].count(
        "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY"
    ) == 1


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
        "VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY",
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
