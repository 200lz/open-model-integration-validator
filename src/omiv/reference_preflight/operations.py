"""Offline construction and projection for metadata-only reference preflight."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from omiv.assurance.models import (
    AssuranceDimension,
    AssuranceRequest,
    AssuranceRequirement,
    CostClass,
    EvidencePhase,
    PlannedOperation,
    VerdictRole,
)
from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.reference_preflight.models import (
    ArtifactRole,
    FutureRuntimePlan,
    ReferencePreflightEvidence,
    ReferencePreflightProfile,
)
from omiv.safe_write import atomic_write_text

MAX_CONTROL_BYTES = 8 * 1024 * 1024


def _pretty(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def load_profile(path: Path) -> ReferencePreflightProfile:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return ReferencePreflightProfile.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid reference preflight profile: {exc}") from exc


def load_evidence(path: Path) -> ReferencePreflightEvidence:
    value, _ = load_bounded_json(path, max_bytes=MAX_CONTROL_BYTES)
    try:
        return ReferencePreflightEvidence.model_validate(value)
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid reference preflight evidence: {exc}") from exc


def _normalize_reference(profile: ReferencePreflightProfile, reference: str) -> str:
    candidate = reference.strip().removesuffix("/")
    matches = {
        alias.removesuffix("/"): profile.canonical_reference for alias in profile.reference_aliases
    }
    normalized = matches.get(candidate)
    if normalized is None:
        raise OmivInputError(
            "reference is not covered by the selected offline profile; "
            "no remote facts were inferred"
        )
    return normalized


def _build_future_plan(profile: ReferencePreflightProfile) -> FutureRuntimePlan:
    body: dict[str, Any] = {
        "schema": "omiv.reference-runtime-plan.v1",
        **profile.future_runtime_plan.model_dump(mode="json"),
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return FutureRuntimePlan.model_validate(
        {
            **body,
            "plan_id": f"reference_runtime_plan_{digest[:32]}",
            "plan_digest": digest,
        }
    )


def build_reference_preflight(
    profile: ReferencePreflightProfile, reference: str
) -> ReferencePreflightEvidence:
    canonical_reference = _normalize_reference(profile, reference)
    profile_json = profile.model_dump(mode="json", by_alias=True)
    profile_digest = canonical_sha256({"reference-preflight-profile": profile_json})
    future_plan = _build_future_plan(profile)
    companions = sorted(
        {item.role for item in profile.artifacts if item.role != ArtifactRole.MAIN_MODEL},
        key=lambda item: item.value,
    )
    body: dict[str, Any] = {
        "schema": "omiv.reference-preflight-evidence.v1",
        "candidate_notice": "P7_REFERENCE_PREFLIGHT_CANDIDATE",
        "input_reference": reference,
        "artifact_reference": canonical_reference,
        "resolved_identity_status": "REMOTE_REVISION_PINNED",
        "resolved_identity": f"{canonical_reference}@{profile.resolved_revision}",
        "payload_verification": "NOT_DOWNLOADED",
        "source_binding": "NOT_ESTABLISHED",
        "architecture_status": "DECLARED",
        "architecture": profile.configuration.architecture,
        "tokenizer_configuration": "REMOTE_METADATA_OBSERVED",
        "companion_roles": [item.value for item in companions],
        "runtime_candidates": [item.runtime for item in profile.runtime_candidates],
        "runtime_requirement": "DECLARED_OFFICIAL_REQUIREMENT",
        "runtime_probe": "NOT_RUN",
        "numerical_fidelity": "NOT_EVALUATED",
        "semantic_fidelity": "NOT_EVALUATED",
        "performance": "NOT_EVALUATED",
        "safety": "NOT_EVALUATED",
        "production_readiness": "NOT_ESTABLISHED",
        "provenance_gaps": profile.provenance_gaps,
        "profile_digest": profile_digest,
        "profile": profile_json,
        "future_runtime_plan": future_plan.model_dump(mode="json", by_alias=True),
        "limitations": profile.limitations,
    }
    digest = canonical_sha256({"domain": body["schema"], "body": body})
    return ReferencePreflightEvidence.model_validate(
        {
            **body,
            "evidence_id": f"reference_preflight_evidence_{digest[:32]}",
            "evidence_digest": digest,
        }
    )


def build_assurance_request(
    evidence: ReferencePreflightEvidence, source_path: str
) -> AssuranceRequest:
    """Preserve candidate evidence as opaque supporting bytes under Phase 6F v1."""
    return AssuranceRequest(
        request_id=f"reference-{evidence.evidence_digest[:24]}",
        subject=evidence.resolved_identity,
        requirements=[
            AssuranceRequirement(
                member_path=(
                    f"provenance/reference-preflight-{evidence.evidence_digest[:16]}.json"
                ),
                source_path=source_path,
                phase=EvidencePhase.EXTERNAL,
                required=True,
                media_type="application/octet-stream",
                expected_schema=None,
                dimension=AssuranceDimension.PROVENANCE,
                verdict_role=VerdictRole.SUPPORTING,
            )
        ],
        planned_operations=[
            PlannedOperation(
                cost_class=CostClass.GPU,
                reason=evidence.future_runtime_plan.question,
            )
        ],
    )


def write_evidence(evidence: ReferencePreflightEvidence, output: Path) -> None:
    atomic_write_text(output, _pretty(evidence))


def write_assurance_request(request: AssuranceRequest, output: Path) -> None:
    atomic_write_text(output, _pretty(request))


def concise_evidence_summary(evidence: ReferencePreflightEvidence) -> str:
    primary_requirement = evidence.profile.runtime_candidates[0].requirement
    companion_text = " + ".join(item.value for item in evidence.companion_roles)
    rows = [
        ("Artifact reference", evidence.artifact_reference),
        (
            "Resolved identity",
            f"{evidence.resolved_identity_status}: {evidence.resolved_identity}",
        ),
        ("Payload verification", evidence.payload_verification),
        ("Source binding", evidence.source_binding),
        ("Architecture", f"{evidence.architecture_status}: {evidence.architecture}"),
        ("Tokenizer/config", evidence.tokenizer_configuration),
        ("Companion artifacts", f"DECLARED: {companion_text}"),
        ("Runtime candidates", " / ".join(evidence.runtime_candidates)),
        ("Runtime requirement", f"{evidence.runtime_requirement}: {primary_requirement}"),
        ("Runtime probe", evidence.runtime_probe),
        ("Provenance gaps", f"EXPLICIT: {len(evidence.provenance_gaps)}"),
        (
            "Next step",
            f"READY_FOR_GPU: execute {evidence.future_runtime_plan.plan_id}",
        ),
    ]
    return "\n".join(f"{label:<21} {value}" for label, value in rows)
