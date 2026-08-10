"""Offline verification for portable Model Passports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import canonical_sha256, load_json_value
from omiv.errors import OmivInputError
from omiv.passport.builder import build_passport
from omiv.passport.models import (
    CustodyStatus,
    ModelPassport,
    PassportStageName,
    PassportStageStatus,
    PassportVerificationResult,
    SummaryStatus,
    VerificationMode,
)
from omiv.passport.policy import (
    evaluate_usage_profiles,
    passport_policy,
    profile_policy_digest,
    reconstruct_trust_summary,
)
from omiv.validation.reporting import verify_validation_inventory_with_availability

MAX_PASSPORT_BYTES = 4 * 1024 * 1024


def _load(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_PASSPORT_BYTES:
            raise OmivInputError(f"passport exceeds {MAX_PASSPORT_BYTES} bytes")
        return load_json_value(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise OmivInputError(f"cannot load passport: {exc}") from exc


def _digest(passport: ModelPassport) -> str:
    data = passport.model_dump(mode="json", by_alias=True)
    data.pop("passport_digest")
    return canonical_sha256(data)


def _passport_id(passport: ModelPassport) -> str:
    body = {
        "schema": passport.schema_id,
        "subject": passport.subject.model_dump(mode="json", by_alias=True),
        "artifact_identity": passport.artifact_identity.model_dump(mode="json", by_alias=True),
        "source_evidence_bundle_digest": (passport.evidence_identity.validation_inventory_digest),
        "passport_policy_digest": passport.policy_identity.passport_policy_digest,
    }
    return "mp_" + canonical_sha256(body)[:32]


def _verify_internal(passport: ModelPassport) -> None:
    if _digest(passport) != passport.passport_digest:
        raise OmivInputError("passport digest mismatch")
    if _passport_id(passport) != passport.passport_id:
        raise OmivInputError("passport identity mismatch")
    policy = passport_policy()
    identity = passport.policy_identity
    if identity.passport_policy_digest != policy.policy_digest:
        raise OmivInputError("passport policy digest mismatch")
    if identity.profile_policy_digest != profile_policy_digest(policy):
        raise OmivInputError("passport profile-policy digest mismatch")
    evidence = passport.evidence_identity
    if identity.ontology_policy_digest != evidence.ontology_policy_digest:
        raise OmivInputError("ontology policy identity mismatch")
    if identity.mapping_policy_digest != evidence.mapping_policy_digest:
        raise OmivInputError("mapping policy identity mismatch")
    if passport.artifact_identity.model_pack_digest != evidence.model_pack_digest:
        raise OmivInputError("model-pack identity mismatch")
    stages = {item.stage: item.status for item in passport.evidence_stages}
    if set(stages) != set(PassportStageName):
        raise OmivInputError("passport evidence-stage set is incomplete")
    expected_trust = reconstruct_trust_summary(
        stages, passport.custody_summary.status, passport.security_summary
    )
    if passport.trust_summary != expected_trust:
        raise OmivInputError("passport trust-summary reconstruction mismatch")
    if passport.usage_profiles != evaluate_usage_profiles(stages, policy):
        raise OmivInputError("passport usage-profile reconstruction mismatch")
    references = {item.role: item for item in passport.evidence_references}
    expected = {
        "validation_inventory": evidence.validation_inventory_digest,
        "evidence_graph": evidence.evidence_graph_digest,
        "artifact_index": evidence.artifact_index_digest,
        "model_pack": evidence.model_pack_digest,
        "ontology_policy": evidence.ontology_policy_digest,
        "mapping_policy": evidence.mapping_policy_digest,
    }
    if not set(expected).issubset(references):
        raise OmivInputError("passport evidence-reference set is incomplete")
    for role, digest in expected.items():
        if references[role].digest != digest:
            raise OmivInputError(f"{role.replace('_', '-')} reference digest mismatch")
    custody_stage = stages[PassportStageName.CUSTODY_CHAIN]
    if passport.custody_summary.event_count == 0:
        if custody_stage != PassportStageStatus.UNAVAILABLE:
            raise OmivInputError("zero-event custody stage must be UNAVAILABLE")
    else:
        custody_reference = references.get("custody_chain")
        if custody_reference is None or (
            custody_reference.schema_id == "omiv.validation-evidence-graph.v1"
        ):
            raise OmivInputError("custody events require distinct custody-ledger evidence")
        if (
            passport.custody_summary.status == CustodyStatus.VERIFIED
            and custody_stage != PassportStageStatus.PASS
        ):
            raise OmivInputError("verified custody requires a PASS custody stage")
    if passport.security_summary.status == SummaryStatus.NOT_CHECKED:
        if stages[PassportStageName.SECURITY_INSPECTION] != PassportStageStatus.NOT_CHECKED:
            raise OmivInputError("unchecked security requires a NOT_CHECKED stage")
    elif "security_inspection" not in references:
        raise OmivInputError("security assessment requires scanner evidence")
    if passport.runtime_summary.status == SummaryStatus.NOT_CHECKED:
        if stages[PassportStageName.RUNTIME_PARITY] != PassportStageStatus.NOT_CHECKED:
            raise OmivInputError("unchecked runtime requires a NOT_CHECKED stage")
    elif "runtime_observation" not in references:
        raise OmivInputError("runtime assessment requires observation evidence")


def load_passport(path: Path) -> ModelPassport:
    try:
        passport = ModelPassport.model_validate(_load(path))
    except (ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid Model Passport: {exc}") from exc
    _verify_internal(passport)
    return passport


def verify_passport(
    path: Path,
    *,
    root: Path | None = None,
    digest_only: bool = False,
) -> PassportVerificationResult:
    passport = load_passport(path)
    if digest_only:
        return PassportVerificationResult(
            mode=VerificationMode.DIGEST_ONLY_VERIFICATION,
            passport_id=passport.passport_id,
            passport_digest=passport.passport_digest,
            message="Passport schema, identity, digest, policy, trust, and profiles reconstructed.",
        )
    references = [
        item for item in passport.evidence_references if item.role == "validation_inventory"
    ]
    if len(references) != 1 or references[0].relative_path is None:
        return PassportVerificationResult(
            mode=VerificationMode.UNVERIFIABLE_REFERENCE,
            passport_id=passport.passport_id,
            passport_digest=passport.passport_digest,
            message="Validation inventory reference is unavailable for full verification.",
        )
    if root is None:
        raise OmivInputError("full passport verification requires a repository root")
    validation_path = root.resolve() / references[0].relative_path
    if not validation_path.is_file():
        raise OmivInputError(
            f"referenced validation inventory is missing: {references[0].relative_path}"
        )
    verification = verify_validation_inventory_with_availability(validation_path, root.resolve())
    if not verification.external_artifacts_available:
        unavailable = next(item for item in verification.external_artifacts if not item.available)
        return PassportVerificationResult(
            mode=VerificationMode.UNVERIFIABLE_REFERENCE,
            passport_id=passport.passport_id,
            passport_digest=passport.passport_digest,
            message=(
                "Validation external artifact is NOT_AVAILABLE; expected identity is "
                "recorded but bytes were not observed: "
                f"{unavailable.expected.relative_path}"
            ),
        )
    inventory = verification.inventory
    rebuilt = build_passport(
        inventory,
        validation_reference=references[0].relative_path,
    )
    if rebuilt != passport:
        raise OmivInputError("passport does not reconstruct from verified evidence")
    return PassportVerificationResult(
        mode=VerificationMode.FULL_VERIFICATION,
        passport_id=passport.passport_id,
        passport_digest=passport.passport_digest,
        message="Passport and all referenced validation dependencies reconstructed offline.",
    )
