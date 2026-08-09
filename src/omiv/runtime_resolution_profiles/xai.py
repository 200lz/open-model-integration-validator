"""Offline xAI documented-routing practice profile."""

from __future__ import annotations

from pathlib import Path

from omiv.runtime.models import ProductSubject
from omiv.runtime_resolution.building import build_routing_statement
from omiv.runtime_resolution.models import (
    ProviderRoutingStatement,
    ResolutionMechanism,
    RoutingRule,
    finalize_identity,
    object_reference,
)
from omiv.runtime_resolution_profiles.models import XaiRuntimeResolutionReadiness
from omiv.runtime_resolution_profiles.public_documents import load_public_document_fixture


def build_xai_practice(
    repository: Path, subject: ProductSubject
) -> tuple[
    tuple[ProviderRoutingStatement, ProviderRoutingStatement], XaiRuntimeResolutionReadiness
]:
    release, release_fixture_digest = load_public_document_fixture(
        repository, "xai-release-notes.normalized.json"
    )
    retirement, retirement_fixture_digest = load_public_document_fixture(
        repository, "xai-may-15-retirement.normalized.json"
    )
    release_statement = build_routing_statement(
        subject,
        provider="xai",
        source_fixture_digest=release_fixture_digest,
        source_url=release.source_url,
        api_surface="xai.models.api",
        document_published_at=release.document_published_at,
        document_updated_at=release.document_updated_at,
        rules=(
            RoutingRule(
                requested_identifier="grok-voice-latest",
                documented_target="grok-voice-think-fast-2.0",
                mechanism=ResolutionMechanism.MODEL_ALIAS_RESOLUTION,
                api_surface="xai.models.api",
                reasoning_setting=None,
                effective_at="2026-08-05T00:00:00Z",
            ),
        ),
    )
    retirement_statement = build_routing_statement(
        subject,
        provider="xai",
        source_fixture_digest=retirement_fixture_digest,
        source_url=retirement.source_url,
        api_surface="xai.models.api",
        document_published_at=retirement.document_published_at,
        document_updated_at=retirement.document_updated_at,
        rules=(
            RoutingRule(
                requested_identifier="grok-4-fast-non-reasoning",
                documented_target="grok-4.3",
                mechanism=ResolutionMechanism.DEPRECATION_COMPATIBILITY_ROUTING,
                api_surface="xai.models.api",
                reasoning_setting="none",
                effective_at="2026-05-15T19:00:00Z",
            ),
            RoutingRule(
                requested_identifier="grok-4-fast-reasoning",
                documented_target="grok-4.3",
                mechanism=ResolutionMechanism.DEPRECATION_COMPATIBILITY_ROUTING,
                api_surface="xai.models.api",
                reasoning_setting="low",
                effective_at="2026-05-15T19:00:00Z",
            ),
            RoutingRule(
                requested_identifier="grok-code-fast-1",
                documented_target="grok-build-0.1",
                mechanism=ResolutionMechanism.DEPRECATION_COMPATIBILITY_ROUTING,
                api_surface="xai.models.api",
                reasoning_setting=None,
                effective_at="2026-05-15T19:00:00Z",
            ),
        ),
    )
    body = {
        "schema": "omiv.xai-runtime-resolution-readiness.v1",
        "classification": (
            "XAI_PROVIDER_DOCUMENTED_MUTABLE_ALIAS_AND_REDIRECT_EVIDENCE_RECORDED_"
            "WITHOUT_OBSERVED_RUNTIME_WEIGHT_IDENTITY"
        ),
        "routing_statements": [
            object_reference(release_statement),
            object_reference(retirement_statement),
        ],
        "evidence_layer": "PROVIDER_DOCUMENTED_POLICY",
        "production_request": "NOT_PERFORMED",
        "api_response": "NOT_OBSERVED",
        "artifact_identity": "UNAVAILABLE",
        "runtime_identity": "NOT_OBSERVED",
        "weight_identity": "NOT_OBSERVED",
        "publisher_authority": "NOT_ESTABLISHED",
        "authenticity": "NOT_ESTABLISHED",
        "freshness": "NOT_ESTABLISHED",
        "observation_time": "NOT_RECORDED",
        "limitations": [
            "A model name is not a model identity; this is an evidence-model principle.",
            "No production API request, runtime identity, weight identity, endorsement, "
            "or affiliation is claimed.",
        ],
    }
    readiness = XaiRuntimeResolutionReadiness.model_validate(
        finalize_identity(body, "readiness_id", "xai_runtime_readiness_", "readiness_digest")
    )
    return (release_statement, retirement_statement), readiness
