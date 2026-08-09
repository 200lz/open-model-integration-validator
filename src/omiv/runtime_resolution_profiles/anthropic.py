"""Offline Anthropic provable-inference roadmap practice profile."""

from __future__ import annotations

from pathlib import Path

from omiv.runtime.models import ProductSubject
from omiv.runtime_resolution.building import build_routing_statement
from omiv.runtime_resolution.models import (
    ProviderRoutingStatement,
    finalize_identity,
    object_reference,
)
from omiv.runtime_resolution_profiles.models import AnthropicProvableInferenceReadiness
from omiv.runtime_resolution_profiles.public_documents import load_public_document_fixture


def build_anthropic_practice(
    repository: Path, subject: ProductSubject
) -> tuple[ProviderRoutingStatement, AnthropicProvableInferenceReadiness]:
    roadmap, fixture_digest = load_public_document_fixture(
        repository, "anthropic-roadmap.normalized.json"
    )
    statement = build_routing_statement(
        subject,
        provider="anthropic",
        source_fixture_digest=fixture_digest,
        source_url=roadmap.source_url,
        api_surface="anthropic.public.roadmap",
        document_published_at=roadmap.document_published_at,
        document_updated_at=roadmap.document_updated_at,
        rules=(),
        kind="PROVIDER_RESEARCH_ROADMAP_STATEMENT",
    )
    body = {
        "schema": "omiv.anthropic-provable-inference-readiness.v1",
        "classification": (
            "ANTHROPIC_PROVABLE_INFERENCE_ROADMAP_SIGNAL_RECORDED_WITHOUT_"
            "PUBLIC_PROOF_FORMAT_OR_IMPLEMENTATION"
        ),
        "roadmap_statement": object_reference(statement),
        "signal": "PROVIDER_RESEARCH_ROADMAP_STATEMENT",
        "prototype": "PROTOTYPE_NOT_OBSERVED",
        "proof_format": "PUBLIC_PROOF_FORMAT_NOT_SUPPLIED",
        "verifier": "VERIFIER_NOT_AVAILABLE",
        "implementation": "PROVABLE_INFERENCE_NOT_IMPLEMENTED",
        "weight_attribution": "WEIGHT_ATTRIBUTION_NOT_ESTABLISHED",
        "observation_time": "NOT_RECORDED",
        "limitations": [
            "The roadmap target does not establish prototype completion.",
            "No public proof format, verifier, cryptographic architecture, "
            "or weight attribution is inferred.",
        ],
    }
    readiness = AnthropicProvableInferenceReadiness.model_validate(
        finalize_identity(
            body,
            "readiness_id",
            "anthropic_runtime_readiness_",
            "readiness_digest",
        )
    )
    return statement, readiness
