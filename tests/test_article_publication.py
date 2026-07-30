from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.article.builder import (
    build_article_index,
    build_article_package,
    build_publication_numeric_facts,
    claim_class_counts,
    validate_claim_support,
)
from omiv.article.models import (
    ArticleArtifact,
    ArticleArtifactIndex,
    ClaimClass,
    PublicClaimRegistry,
    ReproductionCommand,
)
from omiv.article.verification import (
    PublicationClaimError,
    lint_publication_text,
    verify_article_package,
    verify_claim_registry,
    verify_evidence_manifest,
)
from omiv.cli import app
from omiv.errors import OmivInputError

ROOT = Path(__file__).parents[1]
ARTICLE = ROOT / "articles/validating-kimi-k3-gguf-with-omiv.md"
REVISION = "3d4b61ab4b6789d401191c476cbb4567246db8f5"


@pytest.fixture(scope="module")
def package():
    return build_article_package(ROOT)


def test_package_reconstructs_from_canonical_evidence(package) -> None:
    claims, reproduction, manifest = package
    assert verify_claim_registry(ROOT) == claims
    assert verify_evidence_manifest(ROOT) == manifest
    index = verify_article_package(ROOT, ARTICLE)
    assert index == build_article_index(ROOT, manifest, claims, reproduction)


def test_claim_registry_has_required_claims_and_classes(package) -> None:
    claims, _, _ = package
    assert [claim.claim_id for claim in claims.claims] == [
        f"CLAIM-{number:03d}" for number in range(1, 33)
    ]
    counts = claim_class_counts(claims)
    assert counts[ClaimClass.VERIFIED_FACT.value] > 0
    assert counts[ClaimClass.STRUCTURAL_CONCLUSION.value] > 0
    assert counts[ClaimClass.LIMITATION.value] == 6


def test_verified_claim_requires_artifact_support(package) -> None:
    claims, _, _ = package
    data = claims.claims[0].model_dump(mode="json")
    data["supporting_artifact_digests"] = []
    with pytest.raises(ValidationError, match="supporting artifacts"):
        type(claims.claims[0]).model_validate(data)


def test_unsupported_claim_cannot_be_verified(package) -> None:
    claims, _, _ = package
    data = claims.claims[0].model_dump(mode="json")
    data["claim_class"] = "unsupported"
    with pytest.raises(ValidationError, match="unsupported claims"):
        type(claims.claims[0]).model_validate(data)


def test_missing_finding_support_fails_closed(package) -> None:
    claims, _, _ = package
    bad = claims.claims[0].model_copy(update={"supporting_finding_ids": ["VALIDATE-999"]})
    with pytest.raises(OmivInputError, match="missing support"):
        validate_claim_support(
            [bad],
            artifact_digests=set(bad.supporting_artifact_digests),
            finding_ids=set(),
            policy_digests=set(bad.supporting_policy_digests),
        )


def test_registry_rejects_unknown_fields(package) -> None:
    claims, _, _ = package
    data = claims.model_dump(mode="json")
    data["unexpected"] = True
    with pytest.raises(ValidationError):
        PublicClaimRegistry.model_validate(data)


def test_manifest_uses_relative_posix_paths(package) -> None:
    _, _, manifest = package
    assert manifest.canonical_artifacts
    assert all(not item.relative_path.startswith("/") for item in manifest.canonical_artifacts)
    assert all("\\" not in item.relative_path for item in manifest.canonical_artifacts)
    assert set(manifest.report_envelope_digests) == {
        "UD-IQ1_M",
        "UD-Q4_K_XL",
        "comparison",
    }


def test_absolute_artifact_path_is_rejected(package) -> None:
    _, _, manifest = package
    data = manifest.canonical_artifacts[0].model_dump(mode="json")
    data["relative_path"] = "/tmp/evidence.json"
    with pytest.raises(ValidationError, match="relative POSIX"):
        ArticleArtifact.model_validate(data)


def test_article_index_is_sorted_and_tamper_evident(package) -> None:
    claims, reproduction, manifest = package
    index = build_article_index(ROOT, manifest, claims, reproduction)
    paths = [entry.relative_path for entry in index.entries]
    assert paths == sorted(paths)
    data = index.model_dump(mode="json")
    data["entries"][0]["size_bytes"] += 1
    tampered = ArticleArtifactIndex.model_validate(data)
    assert tampered != index


def test_reproduction_manifest_is_pinned_and_offline_by_default(package) -> None:
    _, reproduction, _ = package
    assert reproduction.resolved_revision == REVISION
    assert reproduction.expected_tensor_payload_bytes_accepted == 0
    assert reproduction.commands
    online = [command for command in reproduction.commands if command.network_required]
    offline = [command for command in reproduction.commands if not command.network_required]
    assert len(online) == 2
    assert offline
    assert all(command.phase == "offline" for command in offline)
    assert all("reproductions/" in command.command for command in online)
    assert all("main" not in command.command for command in reproduction.commands)


@pytest.mark.parametrize("value", ["curl https://example.test", "Bearer secret", "/home/user/x"])
def test_reproduction_commands_reject_unsafe_inputs(value: str) -> None:
    with pytest.raises(ValidationError, match="unsafe reproduction command"):
        ReproductionCommand(
            order=1,
            phase="offline",
            command=value,
            network_required=False,
            expected_exit_code=0,
            expected_status="PASS",
        )


def test_real_article_passes_claim_lint(package) -> None:
    claims, _, _ = package
    text = ARTICLE.read_text(encoding="utf-8")
    assert lint_publication_text(text, claims, build_publication_numeric_facts(ROOT)) == []
    assert len(set(claim.claim_id for claim in claims.claims)) == 32


@pytest.mark.parametrize(
    "statement",
    [
        "The weights are correct.",
        "The published artifact was generated by the pinned converter revision.",
        "Q4 is better than IQ1_M.",
        "The validation proves benchmark performance.",
    ],
)
def test_unmarked_forbidden_claim_is_rejected(package, statement: str) -> None:
    claims, _, _ = package
    text = (
        f"# Test\n\n{REVISION}\n\n{statement}\n\n## Limitations\n\nNone.\n\n"
        "## Claims not made\n\nNot claimed.\n"
    )
    assert any("forbidden" in error for error in lint_publication_text(text, claims))


def test_forbidden_wording_is_allowed_only_in_not_claimed_context(package) -> None:
    claims, _, _ = package
    original = ARTICLE.read_text(encoding="utf-8")
    assert "## Claims not made" in original
    assert "The weights are correct." in original.split("## Claims not made", 1)[1]
    assert lint_publication_text(original, claims) == []


def test_missing_limitations_and_revision_are_rejected(package) -> None:
    claims, _, _ = package
    errors = lint_publication_text("# Article\n\n[CLAIM-001]\n", claims)
    assert any("limitations" in error for error in errors)
    assert any("immutable revision" in error for error in errors)


def test_missing_canonical_numeric_fact_is_rejected(package) -> None:
    claims, _, _ = package
    text = ARTICLE.read_text(encoding="utf-8").replace("648,872,012,448", "648,872,012,449")
    errors = lint_publication_text(text, claims, build_publication_numeric_facts(ROOT))
    assert any("reconstructed numeric fact" in error for error in errors)


def test_storage_quality_language_is_rejected(package) -> None:
    claims, _, _ = package
    text = ARTICLE.read_text(encoding="utf-8").replace(
        "## Claims not made",
        "The ratio measures quantization quality.\n\n## Claims not made",
        1,
    )
    assert any("quality" in error for error in lint_publication_text(text, claims))


def test_no_publication_text_contains_local_paths_or_signed_urls() -> None:
    for path in (ROOT / "articles").rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        assert "/home/chen1" not in text
        assert "X-Amz-" not in text
        assert "Authorization:" not in text


def test_article_preflight_cli_exit_codes(monkeypatch) -> None:
    runner = CliRunner()
    arguments = [
        "article-preflight",
        "--root",
        str(ROOT),
        "--article",
        str(ARTICLE),
    ]
    monkeypatch.setattr(
        "omiv.cli.verify_article_package",
        lambda root, article: SimpleNamespace(index_digest="0" * 64),
    )
    assert runner.invoke(app, arguments).exit_code == 0

    def claim_failure(root, article):
        raise PublicationClaimError("unsupported claim")

    monkeypatch.setattr("omiv.cli.verify_article_package", claim_failure)
    assert runner.invoke(app, arguments).exit_code == 1

    def integrity_failure(root, article):
        raise OmivInputError("integrity mismatch")

    monkeypatch.setattr("omiv.cli.verify_article_package", integrity_failure)
    assert runner.invoke(app, arguments).exit_code == 2
