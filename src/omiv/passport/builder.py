"""Build a compact passport from verified independent-validation evidence."""

from __future__ import annotations

from typing import Any

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.passport.models import (
    ArtifactIdentity,
    ContentIdentity,
    CustodyStatus,
    CustodySummary,
    EvidenceAvailability,
    EvidenceIdentity,
    EvidenceReference,
    FormatIdentity,
    ModelIdentity,
    ModelPassport,
    OriginIdentity,
    PassportEvidenceStage,
    PassportStageName,
    PassportStageStatus,
    PassportSubject,
    PolicyIdentity,
    ReferenceVerificationMode,
    RuntimeSummary,
    SecuritySummary,
    SummaryStatus,
    VariantIdentity,
)
from omiv.passport.policy import (
    evaluate_usage_profiles,
    passport_policy,
    profile_policy_digest,
    reconstruct_trust_summary,
)
from omiv.validation.models import EvidenceStageName, EvidenceStatus, ValidationInventory

_STATUS_MAP = {
    EvidenceStatus.PASS: PassportStageStatus.PASS,
    EvidenceStatus.WARN: PassportStageStatus.PARTIAL,
    EvidenceStatus.FAIL: PassportStageStatus.FAIL,
    EvidenceStatus.AVAILABLE: PassportStageStatus.AVAILABLE,
    EvidenceStatus.UNAVAILABLE: PassportStageStatus.UNAVAILABLE,
    EvidenceStatus.NOT_CHECKED: PassportStageStatus.NOT_CHECKED,
}

_STAGE_MAP: dict[PassportStageName, EvidenceStageName] = {
    PassportStageName.ARTIFACT_IDENTITY: EvidenceStageName.REPOSITORY_IDENTITY,
    PassportStageName.REPOSITORY_LAYOUT: EvidenceStageName.REPOSITORY_LAYOUT,
    PassportStageName.FORMAT_STRUCTURE: EvidenceStageName.COMPLETE_HEADER,
    PassportStageName.HEADER_INTEGRITY: EvidenceStageName.COMPLETE_HEADER,
    PassportStageName.SPLIT_CONTAINER: EvidenceStageName.SPLIT_CONTAINER,
    PassportStageName.PAYLOAD_SPAN_BOUNDS: EvidenceStageName.PAYLOAD_SPAN_BOUNDS,
    PassportStageName.TARGET_ONTOLOGY: EvidenceStageName.TARGET_ONTOLOGY,
    PassportStageName.SEMANTIC_MAPPING: EvidenceStageName.STRUCTURAL_SEMANTIC_MAPPING,
    PassportStageName.CONVERTER_RULE_SUPPORT: EvidenceStageName.CONVERTER_RULE_SUPPORT,
    PassportStageName.ARTIFACT_SPECIFIC_PROVENANCE: (
        EvidenceStageName.ARTIFACT_SPECIFIC_PROVENANCE
    ),
    PassportStageName.PAYLOAD_INTEGRITY: EvidenceStageName.PAYLOAD_INTEGRITY,
    PassportStageName.QUANTIZATION_FIDELITY: EvidenceStageName.QUANTIZATION_FIDELITY,
    PassportStageName.TOKENIZER_PARITY: EvidenceStageName.TOKENIZER_PARITY,
    PassportStageName.RUNTIME_PARITY: EvidenceStageName.RUNTIME_PARITY,
}

_PLACEHOLDERS = {
    PassportStageName.SECURITY_INSPECTION: (
        PassportStageStatus.NOT_CHECKED,
        "No security scanner was run in Phase 5A.",
        "Run a future policy-approved security inspection.",
    ),
    PassportStageName.CUSTODY_CHAIN: (
        PassportStageStatus.UNAVAILABLE,
        "No artifact lifecycle custody events are recorded.",
        "Record custody events in a future chain-of-custody implementation.",
    ),
    PassportStageName.APPROVAL: (
        PassportStageStatus.NOT_CHECKED,
        "No approval workflow evidence is included.",
        "Obtain an approval attestation under an applicable policy.",
    ),
    PassportStageName.DEPLOYMENT_OBSERVATION: (
        PassportStageStatus.NOT_CHECKED,
        "No deployed-artifact observation is included.",
        "Record deployment and runtime artifact identity in a future phase.",
    ),
}


def _stage_digest(digests: list[str]) -> str | None:
    if not digests:
        return None
    return digests[0] if len(digests) == 1 else canonical_sha256(sorted(digests))


def reconstruct_stages(inventory: ValidationInventory) -> list[PassportEvidenceStage]:
    source = {item.stage: item for item in inventory.evidence_stages}
    stages: list[PassportEvidenceStage] = []
    for passport_stage, validation_stage in _STAGE_MAP.items():
        item = source[validation_stage]
        stages.append(
            PassportEvidenceStage(
                stage=passport_stage,
                status=_STATUS_MAP[item.status],
                evidence_source=f"validation_stage:{validation_stage.value}",
                artifact_digest=_stage_digest(item.artifact_digests),
                finding_ids=sorted(item.finding_ids),
                scope=sorted(item.scope),
                limitations=sorted(item.limitations),
                next_step=sorted(item.next_required_evidence),
            )
        )
    for name, (status, limitation, next_step) in _PLACEHOLDERS.items():
        stages.append(
            PassportEvidenceStage(
                stage=name,
                status=status,
                evidence_source="phase_5a_placeholder",
                artifact_digest=None,
                finding_ids=[],
                scope=[],
                limitations=[limitation],
                next_step=[next_step],
            )
        )
    return sorted(stages, key=lambda item: item.stage.value)


def _security_summary() -> SecuritySummary:
    return SecuritySummary(
        status=SummaryStatus.NOT_CHECKED,
        scanner_results=[],
        unsafe_serialization=SummaryStatus.NOT_CHECKED,
        executable_code=SummaryStatus.NOT_CHECKED,
        remote_code=SummaryStatus.NOT_CHECKED,
        dependency_risk=SummaryStatus.NOT_CHECKED,
        archive_safety=SummaryStatus.NOT_CHECKED,
        malware_result=SummaryStatus.NOT_CHECKED,
        known_vulnerabilities=[],
        policy_digest=None,
    )


def _custody_summary() -> CustodySummary:
    required = [
        "acquisition",
        "transformation",
        "validation_attestation",
        "approval",
        "deployment",
        "runtime_observation",
    ]
    return CustodySummary(
        status=CustodyStatus.NOT_AVAILABLE,
        event_count=0,
        required_event_types=required,
        missing_event_types=required,
        broken_links=0,
        revoked_events=0,
        expired_attestations=0,
    )


def _runtime_summary() -> RuntimeSummary:
    return RuntimeSummary(
        status=SummaryStatus.NOT_CHECKED,
        compatibility_status=SummaryStatus.NOT_CHECKED,
    )


def _display_name(model_family: str) -> str:
    return " ".join(
        part.upper() if len(part) <= 3 else part.title()
        for part in model_family.split("-")
    )


def _origin_type(provider: str) -> str:
    return "huggingface" if provider.lower() == "huggingface" else "other"


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OmivInputError(f"validation {field} must be an integer")
    return value


def _policy_identity(inventory: ValidationInventory) -> PolicyIdentity:
    policy = passport_policy()
    return PolicyIdentity(
        passport_policy_digest=policy.policy_digest,
        profile_policy_digest=profile_policy_digest(policy),
        validation_profile_policy_digest=inventory.profile_policy.policy_digest,
        ontology_policy_digest=inventory.model_pack_identity.ontology_policy_digest,
        mapping_policy_digest=inventory.model_pack_identity.mapping_policy_digest,
    )


def _evidence_references(
    inventory: ValidationInventory, validation_reference: str | None
) -> list[EvidenceReference]:
    values = [
        EvidenceReference(
            role="artifact_index",
            schema="omiv.validation-artifact-index.v1",
            digest=inventory.artifact_index.index_digest,
            availability=EvidenceAvailability.DIGEST_ONLY,
            verification_mode=ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION,
        ),
        EvidenceReference(
            role="evidence_graph",
            schema="omiv.validation-evidence-graph.v1",
            digest=inventory.evidence_graph_digest,
            availability=EvidenceAvailability.DIGEST_ONLY,
            verification_mode=ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION,
        ),
        EvidenceReference(
            role="mapping_policy",
            schema="omiv.mapping-policy.digest",
            digest=inventory.model_pack_identity.mapping_policy_digest,
            availability=EvidenceAvailability.DIGEST_ONLY,
            verification_mode=ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION,
        ),
        EvidenceReference(
            role="model_pack",
            schema="omiv.model-pack-identity.v1",
            digest=inventory.model_pack_identity.digest,
            availability=EvidenceAvailability.DIGEST_ONLY,
            verification_mode=ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION,
        ),
        EvidenceReference(
            role="ontology_policy",
            schema="omiv.ontology-policy.digest",
            digest=inventory.model_pack_identity.ontology_policy_digest,
            availability=EvidenceAvailability.DIGEST_ONLY,
            verification_mode=ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION,
        ),
        EvidenceReference(
            role="validation_inventory",
            schema=inventory.schema_id,
            digest=inventory.inventory_digest,
            availability=(
                EvidenceAvailability.PRIVATE
                if validation_reference is not None
                else EvidenceAvailability.DIGEST_ONLY
            ),
            verification_mode=(
                ReferenceVerificationMode.FULL_VERIFICATION
                if validation_reference is not None
                else ReferenceVerificationMode.DIGEST_ONLY_VERIFICATION
            ),
            relative_path=validation_reference,
        ),
    ]
    return sorted(values, key=lambda item: (item.role, item.digest))


def _passport_id_body(
    subject: PassportSubject,
    artifact: ArtifactIdentity,
    inventory: ValidationInventory,
    policy_identity: PolicyIdentity,
) -> dict[str, Any]:
    return {
        "schema": "omiv.model-passport.v1",
        "subject": subject.model_dump(mode="json", by_alias=True),
        "artifact_identity": artifact.model_dump(mode="json", by_alias=True),
        "source_evidence_bundle_digest": inventory.inventory_digest,
        "passport_policy_digest": policy_identity.passport_policy_digest,
    }


def build_passport(
    inventory: ValidationInventory,
    *,
    validation_reference: str | None = None,
) -> ModelPassport:
    """Derive a passport without trusting stored high-level validation conclusions."""
    summary = inventory.repository_summary
    architecture = inventory.architecture_summary
    target = inventory.target_artifact_identity
    subject = PassportSubject(
        display_name=_display_name(inventory.subject.model_family),
        model_family=inventory.subject.model_family,
        artifact_variant=inventory.subject.artifact_variant,
        artifact_kind="model_artifact_set",
        artifact_scope="selected_repository_artifact_set",
    )
    artifact = ArtifactIdentity(
        origin=OriginIdentity(
            origin_type=_origin_type(inventory.repository_identity.provider),  # type: ignore[arg-type]
            provider=inventory.repository_identity.provider,
            repository=inventory.repository_identity.repository,
            repository_type="model_repository",
            resolved_revision=inventory.repository_identity.resolved_revision,
        ),
        format_identity=FormatIdentity(
            format="GGUF",
            architecture=str(architecture.get("architecture")),
            split_container=_integer(
                summary.get("selected_shard_count"), "selected_shard_count"
            )
            > 1,
        ),
        model_identity=ModelIdentity(
            model_family=inventory.subject.model_family,
            architecture=str(architecture.get("architecture")),
        ),
        variant_identity=VariantIdentity(
            variant=inventory.subject.artifact_variant,
            selection=inventory.repository_identity.selection,
        ),
        content_identity=ContentIdentity(
            file_count=_integer(
                summary.get("selected_shard_count"), "selected_shard_count"
            ),
            total_declared_bytes=_integer(
                summary.get("total_repository_bytes"), "total_repository_bytes"
            ),
            artifact_set_digest=str(target["split_inventory_digest"]),
            individual_file_digest_availability=EvidenceAvailability.UNAVAILABLE,
        ),
        model_pack=inventory.model_pack_identity.model_family,
        model_pack_version=inventory.model_pack_identity.version,
        model_pack_digest=inventory.model_pack_identity.digest,
    )
    stages = reconstruct_stages(inventory)
    statuses = {item.stage: item.status for item in stages}
    custody = _custody_summary()
    security = _security_summary()
    runtime = _runtime_summary()
    policy = passport_policy()
    identity = _policy_identity(inventory)
    evidence_identity = EvidenceIdentity(
        validation_schema=inventory.schema_id,
        validation_inventory_digest=inventory.inventory_digest,
        evidence_graph_digest=inventory.evidence_graph_digest,
        artifact_index_digest=inventory.artifact_index.index_digest,
        model_pack_digest=inventory.model_pack_identity.digest,
        ontology_policy_digest=inventory.model_pack_identity.ontology_policy_digest,
        mapping_policy_digest=inventory.model_pack_identity.mapping_policy_digest,
    )
    passport_id = "mp_" + canonical_sha256(
        _passport_id_body(subject, artifact, inventory, identity)
    )[:32]
    warnings = [
        "Payload values and individual artifact bytes have not been verified.",
        "No security inspection was performed; this passport does not establish safety.",
        "No custody chain, approval, deployment, or runtime observation is available.",
    ]
    data: dict[str, Any] = {
        "passport_id": passport_id,
        "subject": subject,
        "artifact_identity": artifact,
        "evidence_identity": evidence_identity,
        "evidence_stages": stages,
        "trust_summary": reconstruct_trust_summary(statuses, custody.status, security),
        "usage_profiles": evaluate_usage_profiles(statuses, policy),
        "custody_summary": custody,
        "security_summary": security,
        "runtime_summary": runtime,
        "limitations": sorted(set(inventory.limitations + warnings)),
        "warnings": warnings,
        "evidence_references": _evidence_references(inventory, validation_reference),
        "policy_identity": identity,
        "passport_digest": "0" * 64,
    }
    draft = ModelPassport.model_validate(data)
    digest_data = draft.model_dump(mode="json", by_alias=True)
    digest_data.pop("passport_digest")
    data["passport_digest"] = canonical_sha256(digest_data)
    return ModelPassport.model_validate(data)
