"""Offline xAI readiness derived only from committed Phase 6B evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal, cast

from omiv.quantization.models import ObjectReference
from omiv.quantization_profiles.models import (
    PinnedMetadataReference,
    XaiQuantizationCaseStudy,
    XaiQuantizationReadiness,
    finalize_profile,
)
from omiv.reconciliation.models import RemoteSnapshotManifest

EXPECTED = {
    "grok-1": {
        "revision": "5de83eb225f49624b424f1c8aa74f96983b5885c",
        "fixture_size": 466_308,
        "fixture_sha256": "645ea0fbd09c85a1d69d4fd217bae43e580a04fcd484308d1cd71b528658ae78",
        "members": 773,
        "bytes": 318_239_889_830,
    },
    "grok-2": {
        "revision": "daf4395a80ad177386cfe39641b64fc12b1d70ed",
        "fixture_size": 27_473,
        "fixture_sha256": "ad495d2fbb3daaed25ddf8d351647254f2d7020d2d4492b89f90aea486c3a60b",
        "members": 44,
        "bytes": 539_040_431_665,
    },
}


def build_xai_readiness(
    repository: Path,
) -> tuple[XaiQuantizationReadiness, XaiQuantizationCaseStudy]:
    references: list[PinnedMetadataReference] = []
    for name in sorted(EXPECTED):
        expected = EXPECTED[name]
        fixture_path = (
            repository / "fixtures" / "reconciliation" / "xai" / f"{name}.pinned-metadata.json"
        )
        raw = fixture_path.read_bytes()
        if (
            len(raw) != expected["fixture_size"]
            or hashlib.sha256(raw).hexdigest() != expected["fixture_sha256"]
        ):
            raise ValueError(f"pinned {name} fixture identity differs from Phase 6B")
        fixture = json.loads(raw)
        snapshot_raw = json.loads(
            (
                repository / "reconciliation" / "practice" / "xai" / name / "snapshot.json"
            ).read_bytes()
        )
        snapshot = RemoteSnapshotManifest.model_validate(snapshot_raw)
        comparable = sum(
            descriptor.payload_comparable
            for member in snapshot.members
            for descriptor in member.digests
        )
        declared_bytes = sum(member.logical_size or 0 for member in snapshot.members)
        if (
            fixture["resolved_revision"] != expected["revision"]
            or snapshot.resolved_revision != expected["revision"]
            or len(snapshot.members) != expected["members"]
            or declared_bytes != expected["bytes"]
            or comparable != 0
        ):
            raise ValueError(f"pinned {name} evidence does not reconstruct reviewed Phase 6B facts")
        references.append(
            PinnedMetadataReference(
                repository=cast(Literal["grok-1", "grok-2"], name),
                resolved_revision=expected["revision"],
                fixture_size=len(raw),
                fixture_sha256=hashlib.sha256(raw).hexdigest(),
                member_count=len(snapshot.members),
                declared_total_bytes=declared_bytes,
                remote_snapshot=ObjectReference(
                    schema_id=snapshot.schema_id,
                    object_id=snapshot.manifest_id,
                    object_digest=snapshot.manifest_digest,
                ),
            )
        )
    readiness_body = {
        "schema": "omiv.xai-quantization-readiness.v1",
        "classification": (
            "XAI_QUANTIZATION_FIDELITY_READINESS_RECORDED_WITHOUT_PAYLOAD_OR_QUANTIZED_CANDIDATE"
        ),
        "pinned_metadata": tuple(references),
        "pinned_public_metadata_available": True,
        "phase6b_remote_metadata_evidence_available": True,
        "payload_comparable_members": 0,
        "source_numerical_values": "NOT_OBSERVED",
        "candidate_quantized_artifact": "NOT_SUPPLIED",
        "quantization_relationship": "NOT_ESTABLISHED",
        "quantization_codec": "NOT_ESTABLISHED",
        "tensor_quantization_parameters": "NOT_OBSERVED",
        "numerical_comparison": "NOT_PERFORMED",
        "quantization_fidelity": "NOT_EVALUATED",
        "publisher_authority": "NOT_ESTABLISHED",
        "authenticity": "NOT_ESTABLISHED",
        "freshness": "NOT_ESTABLISHED",
        "runtime_identity": "NOT_OBSERVED",
        "security": "NOT_EVALUATED",
        "behavioral_parity": "NOT_EVALUATED",
        "observation_time": "NOT_RECORDED",
        "affiliation": "NO_XAI_ENDORSEMENT_AFFILIATION_APPROVAL_OR_PRODUCTION_CLAIM",
        "future_evidence_required": (
            "Exact locally observed source and candidate Phase 6A payload manifests.",
            "Explicit source-to-candidate relationship and transformation provenance.",
            "Observed tensor identities, correspondence, codec semantics, and quantization "
            "parameters.",
            "Exact or deterministic-sample numerical values within bounded evaluation limits.",
        ),
        "limitations": (
            "Remote provider metadata identities are not tensor payload values.",
            "No filename, repository name, extension, or provider field establishes quantization.",
            "This readiness record is not xAI publisher authority, authenticity, approval, "
            "or endorsement.",
        ),
    }
    readiness = XaiQuantizationReadiness.model_validate(
        finalize_profile(
            readiness_body,
            "readiness_id",
            "xai_quantization_readiness_",
            "readiness_digest",
        )
    )
    case_body = {
        "schema": "omiv.xai-quantization-case-study.v1",
        "title": "OMIV xAI Quantization Fidelity Readiness Case Study",
        "readiness": ObjectReference(
            schema_id=readiness.schema_id,
            object_id=readiness.readiness_id,
            object_digest=readiness.readiness_digest,
        ),
        "available_evidence": (
            "Exact immutable Phase 6B revisions and complete pinned provider-listing scopes.",
            "Member paths, declared sizes, storage representations, and typed non-payload "
            "identifiers.",
        ),
        "unavailable_evidence": (
            "Source tensor values and exact Phase 6A source binding.",
            "Candidate quantized artifact, codec, parameters, correspondence, and numerical "
            "values.",
        ),
        "phase6a_future_binding": (
            "A future local pair must bind each exact payload manifest, artifact-set identity, "
            "member digest, size, and race-safe observation."
        ),
        "phase6b_provenance_context": (
            "The pinned revisions remain immutable metadata provenance; their non-comparable "
            "identifiers do not become payload digests."
        ),
        "sampled_vs_full_evaluation": (
            "A deterministic sample remains sample-scoped; complete numerical coverage requires "
            "every declared required tensor and element."
        ),
        "provider_neutral_architecture": True,
        "affiliation": "NO_XAI_ENDORSEMENT_AFFILIATION_APPROVAL_OR_PRODUCTION_CLAIM",
        "limitations": (
            "Neither Grok repository is classified as quantized or unquantized.",
            "No current provider state, behavioral parity, safety, loadability, or runtime "
            "identity is claimed.",
        ),
    }
    case_study = XaiQuantizationCaseStudy.model_validate(
        finalize_profile(
            case_body,
            "case_study_id",
            "xai_quantization_case_study_",
            "case_study_digest",
        )
    )
    return readiness, case_study


def render_xai_case_study(
    value: XaiQuantizationCaseStudy, readiness: XaiQuantizationReadiness
) -> str:
    rows = [
        "# OMIV xAI Quantization Fidelity Readiness Case Study",
        "",
        f"- Classification: **{readiness.classification}**",
    ]
    for item in readiness.pinned_metadata:
        rows.extend(
            [
                f"- `{item.namespace}/{item.repository}` revision: `{item.resolved_revision}`",
                f"  - Members: {item.member_count}",
                f"  - Declared bytes: {item.declared_total_bytes}",
                "  - Payload-comparable members: 0",
            ]
        )
    rows.extend(
        [
            "",
            "Pinned provider metadata establishes revision-specific listing provenance, not "
            "payload "
            "values or quantization semantics. No source tensor values, candidate artifact, codec, "
            "parameters, or numerical comparison are available, so fidelity is **NOT_EVALUATED**.",
            "",
            "A future local source/candidate pair must bind exact Phase 6A payload identities. The "
            "Phase 6B snapshots remain provenance context only. Deterministic sampling remains "
            "sample-scoped; full evaluation requires complete declared tensor and element "
            "coverage.",
            "",
            "No xAI endorsement, affiliation, approval, publisher authorization, authenticity, "
            "current-state, production, safety, or behavioral-parity claim is made.",
            "",
        ]
    )
    return "\n".join(rows)
