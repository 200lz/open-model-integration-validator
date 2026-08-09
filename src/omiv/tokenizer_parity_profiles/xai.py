"""Offline xAI Phase 6D readiness from committed Phase 6B evidence only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal, cast

from omiv.reconciliation.models import RemoteSnapshotManifest
from omiv.tokenizer_parity.models import ObjectReference
from omiv.tokenizer_parity.observation import escape_untrusted_text
from omiv.tokenizer_parity_profiles.models import (
    PinnedMetadataReference,
    XaiTokenizerConfigurationCaseStudy,
    XaiTokenizerConfigurationReadiness,
    finalize_profile,
)

EXPECTED = {
    "grok-1": {
        "revision": "5de83eb225f49624b424f1c8aa74f96983b5885c",
        "size": 466_308,
        "sha": "645ea0fbd09c85a1d69d4fd217bae43e580a04fcd484308d1cd71b528658ae78",
        "members": 773,
        "bytes": 318_239_889_830,
    },
    "grok-2": {
        "revision": "daf4395a80ad177386cfe39641b64fc12b1d70ed",
        "size": 27_473,
        "sha": "ad495d2fbb3daaed25ddf8d351647254f2d7020d2d4492b89f90aea486c3a60b",
        "members": 44,
        "bytes": 539_040_431_665,
    },
}


def build_xai_readiness(
    repository: Path,
) -> tuple[XaiTokenizerConfigurationReadiness, XaiTokenizerConfigurationCaseStudy]:
    refs: list[PinnedMetadataReference] = []
    for name in sorted(EXPECTED):
        expected = EXPECTED[name]
        fixture_path = (
            repository / "fixtures" / "reconciliation" / "xai" / f"{name}.pinned-metadata.json"
        )
        raw = fixture_path.read_bytes()
        if len(raw) != expected["size"] or hashlib.sha256(raw).hexdigest() != expected["sha"]:
            raise ValueError(f"pinned {name} fixture differs from reviewed Phase 6B evidence")
        fixture = json.loads(raw)
        snapshot = RemoteSnapshotManifest.model_validate(
            json.loads(
                (
                    repository / "reconciliation" / "practice" / "xai" / name / "snapshot.json"
                ).read_bytes()
            )
        )
        comparable = sum(
            d.payload_comparable for member in snapshot.members for d in member.digests
        )
        total = sum(member.logical_size or 0 for member in snapshot.members)
        if (
            fixture["resolved_revision"] != expected["revision"]
            or snapshot.resolved_revision != expected["revision"]
            or len(snapshot.members) != expected["members"]
            or total != expected["bytes"]
            or comparable != 0
        ):
            raise ValueError(f"pinned {name} Phase 6B facts do not reconstruct")
        refs.append(
            PinnedMetadataReference(
                repository=cast(Literal["grok-1", "grok-2"], name),
                resolved_revision=expected["revision"],
                fixture_size=len(raw),
                fixture_sha256=hashlib.sha256(raw).hexdigest(),
                member_count=len(snapshot.members),
                declared_total_bytes=total,
                remote_snapshot=ObjectReference(
                    schema_id=snapshot.schema_id,
                    object_id=snapshot.manifest_id,
                    object_digest=snapshot.manifest_digest,
                ),
            )
        )
    body = {
        "schema": "omiv.xai-tokenizer-configuration-readiness.v1",
        "classification": (
            "XAI_TOKENIZER_AND_CONFIGURATION_PARITY_READINESS_RECORDED_WITHOUT_"
            "REQUIRED_PAYLOAD_ASSETS"
        ),
        "pinned_metadata": refs,
        "pinned_repository_tree_metadata": "AVAILABLE",
        "historical_revisions": "AVAILABLE",
        "payload_comparable_members": 0,
        "tokenizer_configuration_asset_contents": "NOT_DOWNLOADED",
        "vocabulary": "NOT_OBSERVED",
        "added_tokens": "NOT_OBSERVED",
        "special_tokens": "NOT_OBSERVED",
        "merge_table": "NOT_OBSERVED",
        "tokenizer_pipeline": "NOT_OBSERVED",
        "chat_template": "NOT_OBSERVED",
        "configuration_fields": "NOT_OBSERVED",
        "probes": "NOT_EXECUTED",
        "parity": "NOT_EVALUATED",
        "publisher_authority": "NOT_ESTABLISHED",
        "authenticity": "NOT_ESTABLISHED",
        "freshness": "NOT_ESTABLISHED",
        "runtime_identity": "NOT_OBSERVED",
        "security": "NOT_EVALUATED",
        "model_behavior": "NOT_EVALUATED",
        "observation_time": "NOT_RECORDED",
        "affiliation": "NO_XAI_ENDORSEMENT_AFFILIATION_OR_APPROVAL_CLAIM",
        "future_evidence_required": (
            "Exact locally observed Phase 6A tokenizer and configuration asset manifests.",
            "Explicit expectation covering fields, vocabulary, merges, special tokens, "
            "pipeline, and templates.",
            "Supplied probe definitions, execution records, results, limits, and exact "
            "tokenizer identities.",
        ),
        "limitations": (
            "Phase 6B member names and provider object IDs do not establish file contents.",
            "No listed filename is interpreted as observed tokenizer/configuration content.",
            "This record makes no xAI endorsement, affiliation, approval, authenticity, "
            "or current-state claim.",
        ),
    }
    readiness = XaiTokenizerConfigurationReadiness.model_validate(
        finalize_profile(body, "readiness_id", "xai_tokenizer_readiness_", "readiness_digest")
    )
    case_body = {
        "schema": "omiv.xai-tokenizer-configuration-case-study.v1",
        "title": "OMIV xAI Tokenizer and Configuration Parity Readiness Case Study",
        "readiness": ObjectReference(
            schema_id=readiness.schema_id,
            object_id=readiness.readiness_id,
            object_digest=readiness.readiness_digest,
        ),
        "established": (
            "Immutable historical Phase 6B repository revisions and pinned "
            "response-scope member metadata.",
            "Zero payload-comparable members and zero downloaded tokenizer/configuration content.",
        ),
        "unavailable": (
            "Vocabulary, merge, added-token, special-token, pipeline, chat-template, and "
            "configuration field contents.",
            "Any supplied tokenization, decode, or template-render probe result.",
        ),
        "future_phase6a_binding": (
            "Future local assets must bind exact Phase 6A manifests, members, sizes, "
            "payload digests, paths, and race-safe reads."
        ),
        "phase6b_context": (
            "Pinned Phase 6B snapshots remain historical listing provenance; member "
            "names and provider IDs are not content."
        ),
        "phase6c_independence": (
            "A future quantized candidate may bind exact Phase 6C evidence, but weight "
            "fidelity cannot establish tokenizer/configuration parity."
        ),
        "supplied_probes_boundary": (
            "Finite supplied probes remain probe-scoped and do not establish complete "
            "tokenizer equivalence."
        ),
        "runtime_boundary": (
            "Static assets and supplied results do not establish observed runtime-loaded "
            "tokenizer identity."
        ),
        "affiliation": "NO_XAI_ENDORSEMENT_AFFILIATION_OR_APPROVAL_CLAIM",
        "limitations": (
            "No current repository state, publisher authority, authenticity, runtime "
            "compatibility, safety, or behavior is claimed.",
        ),
    }
    case = XaiTokenizerConfigurationCaseStudy.model_validate(
        finalize_profile(
            case_body, "case_study_id", "xai_tokenizer_case_study_", "case_study_digest"
        )
    )
    return readiness, case


def render_xai_case_study(
    value: XaiTokenizerConfigurationCaseStudy, readiness: XaiTokenizerConfigurationReadiness
) -> str:
    lines = [
        "# OMIV xAI Tokenizer and Configuration Parity Readiness Case Study",
        "",
        f"- Classification: **{readiness.classification}**",
    ]
    for item in readiness.pinned_metadata:
        lines.extend(
            [
                f"- `{item.namespace}/{item.repository}` revision: `{item.resolved_revision}`",
                f"  - Members: {item.member_count}",
                "  - Payload-comparable members: 0",
            ]
        )
    lines.extend(
        [
            "",
            escape_untrusted_text(value.phase6b_context),
            "",
            escape_untrusted_text(value.future_phase6a_binding),
            "",
            escape_untrusted_text(value.phase6c_independence),
            "",
            escape_untrusted_text(value.supplied_probes_boundary),
            "",
            "No xAI endorsement, affiliation, approval, publisher authority, authenticity, "
            "current state, runtime compatibility, security, or behavioral parity is claimed.",
            "",
        ]
    )
    return "\n".join(lines)
