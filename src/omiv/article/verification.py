"""Fail-closed loading, claim linting, and publication preflight."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypeVar, cast

from pydantic import ValidationError

from omiv.article.builder import (
    CLAIM_PATH,
    INDEX_PATH,
    MANIFEST_PATH,
    REPRO_PATH,
    build_article_index,
    build_article_package,
    build_publication_numeric_facts,
)
from omiv.article.models import (
    ArticleArtifactIndex,
    ArticleEvidenceManifest,
    ArticleReproducibilityManifest,
    PublicClaimRegistry,
)
from omiv.errors import OmivInputError

T = TypeVar("T")
MAX_ARTICLE_BYTES = 16 * 1024 * 1024


class PublicationClaimError(OmivInputError):
    """Publication text is well-formed but violates the claim policy."""


def pretty_json(value: object) -> str:
    model = value
    if not hasattr(model, "model_dump"):
        raise TypeError("article JSON serialization requires a strict model")
    return (
        json.dumps(
            model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _load(path: Path, model: type[T]) -> T:
    try:
        if path.stat().st_size > MAX_ARTICLE_BYTES:
            raise OmivInputError("article artifact exceeds size limit")
        return cast(T, model.model_validate_json(path.read_text(encoding="utf-8")))  # type: ignore[attr-defined]
    except (OSError, UnicodeError, ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid article artifact {path.name}: {exc}") from exc


def verify_claim_registry(root: Path) -> PublicClaimRegistry:
    observed = _load(root / CLAIM_PATH, PublicClaimRegistry)
    expected, _, _ = build_article_package(root)
    if observed != expected:
        raise OmivInputError("claim registry does not reconstruct from canonical evidence")
    return observed


def verify_evidence_manifest(root: Path) -> ArticleEvidenceManifest:
    claims = verify_claim_registry(root)
    reproduction = _load(root / REPRO_PATH, ArticleReproducibilityManifest)
    expected_claims, expected_reproduction, expected_manifest = build_article_package(root)
    if claims != expected_claims or reproduction != expected_reproduction:
        raise OmivInputError("article package linkage mismatch")
    observed = _load(root / MANIFEST_PATH, ArticleEvidenceManifest)
    if observed != expected_manifest:
        raise OmivInputError("evidence manifest does not reconstruct")
    for item in observed.canonical_artifacts:
        path = root / item.relative_path
        if not path.is_file() or path.stat().st_size != item.size_bytes:
            raise OmivInputError(f"evidence artifact missing or wrong size: {item.relative_path}")
    return observed


def lint_publication_fragment(text: str, registry: PublicClaimRegistry) -> list[str]:
    errors: list[str] = []
    if "/home/" in text or "Authorization:" in text or "Bearer " in text:
        errors.append("machine-local path or credential-like text is forbidden")
    claim_scope = text.split("## Claims not made", 1)[0]
    for phrase in registry.globally_forbidden_wording:
        for line in claim_scope.splitlines():
            if phrase.lower() in line.lower() and not re.search(
                r"\b(not|no|does not|do not|isn't|aren't)\b", line, re.IGNORECASE
            ):
                errors.append(f"forbidden public claim: {phrase}")
    if re.search(r"(compression|quantization) quality", claim_scope, re.IGNORECASE):
        errors.append("storage ratios cannot be described as quality")
    for line in claim_scope.splitlines():
        if re.search(
            r"\b(benchmark|perplexity|throughput)\b", line, re.IGNORECASE
        ) and not re.search(r"\b(no|not|does not|without|unverified)\b", line, re.IGNORECASE):
            errors.append("unsupported benchmark statement")
            break
    referenced = set(re.findall(r"CLAIM-[0-9]{3}", text))
    known = {item.claim_id for item in registry.claims}
    unknown = referenced - known
    if unknown:
        errors.append(f"unknown claim references: {sorted(unknown)}")
    return errors


def lint_publication_text(
    text: str,
    registry: PublicClaimRegistry,
    required_numbers: tuple[str, ...] | None = None,
) -> list[str]:
    errors = lint_publication_fragment(text, registry)
    if "## Limitations" not in text or "## Claims not made" not in text:
        errors.append("required limitations and claims-not-made sections are missing")
    if "3d4b61ab4b6789d401191c476cbb4567246db8f5" not in text:
        errors.append("immutable revision is missing")
    referenced = set(re.findall(r"CLAIM-[0-9]{3}", text))
    if len(referenced) < 20:
        errors.append("article does not reference enough registered claims")
    for value in required_numbers or ():
        if value not in text:
            errors.append(f"required reconstructed numeric fact missing: {value}")
    return errors


def verify_article_package(root: Path, article: Path) -> ArticleArtifactIndex:
    root = root.resolve()
    manifest = verify_evidence_manifest(root)
    claims = verify_claim_registry(root)
    reproduction = _load(root / REPRO_PATH, ArticleReproducibilityManifest)
    observed_index = _load(root / INDEX_PATH, ArticleArtifactIndex)
    expected_index = build_article_index(root, manifest, claims, reproduction)
    if observed_index != expected_index:
        raise OmivInputError("article artifact index does not reconstruct")
    texts = [
        article,
        root / "articles/kimi-k3-gguf-community-release.md",
        root / "articles/social/kimi-k3-gguf-x-draft.md",
        root / "articles/social/kimi-k3-gguf-linkedin-draft.md",
        root / "articles/social/kimi-k3-gguf-hn-draft.md",
    ]
    article_errors = lint_publication_text(
        article.read_text(encoding="utf-8"),
        claims,
        build_publication_numeric_facts(root),
    )
    if article_errors:
        raise PublicationClaimError("; ".join(article_errors))
    for path in texts:
        text = path.read_text(encoding="utf-8")
        fragment_errors = lint_publication_fragment(text, claims)
        if "X-Amz-" in text:
            fragment_errors.append("signed query parameter is forbidden")
        if fragment_errors:
            raise PublicationClaimError(f"{path.name}: {'; '.join(fragment_errors)}")
    return observed_index
