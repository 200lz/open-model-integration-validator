"""Backward-compatible Model Passport v2 adapter for verified custody ledgers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import canonical_sha256, load_json_value
from omiv.custody.models import (
    CustodyLedger,
    CustodyLinkedPassport,
    LedgerArtifactReference,
    LinkedCustodySummary,
)
from omiv.custody.verification import verify_custody_ledger
from omiv.errors import OmivInputError
from omiv.passport.models import (
    ModelPassport,
    PassportStageName,
    PassportStageStatus,
    TrustOutcome,
)
from omiv.passport.reporting import _safe, _size
from omiv.passport.verification import load_passport, verify_passport
from omiv.safe_write import atomic_write_text, validate_output_path


def _linked_id_body(base: ModelPassport, ledger: CustodyLedger) -> dict[str, Any]:
    return {
        "schema": "omiv.model-passport.v2",
        "base_passport_id": base.passport_id,
        "base_passport_digest": base.passport_digest,
        "subject": base.subject.model_dump(mode="json"),
        "artifact_identity": base.artifact_identity.model_dump(mode="json"),
        "custody_ledger_digest": ledger.ledger_digest,
        "passport_policy_digest": base.policy_identity.passport_policy_digest,
    }


def build_custody_linked_passport(
    base: ModelPassport,
    ledger: CustodyLedger,
    *,
    ledger_reference: str,
) -> CustodyLinkedPassport:
    if base.passport_digest != ledger.passport_reference.digest:
        raise OmivInputError("custody ledger does not reference the base passport")
    stages = [
        stage.model_copy(
            update={
                "status": PassportStageStatus.AVAILABLE,
                "evidence_source": "custody_ledger",
                "artifact_digest": ledger.ledger_digest,
                "scope": [
                    "hash-linked evidence-derived custody segment is available"
                ],
                "limitations": [
                    "lifecycle completeness remains incomplete and events are unattested"
                ],
                "next_step": [
                    item.value
                    for item in ledger.missing_event_analysis.missing_event_types
                ],
            }
        )
        if stage.stage == PassportStageName.CUSTODY_CHAIN
        else stage
        for stage in base.evidence_stages
    ]
    trust = base.trust_summary.model_copy(
        update={"custody_status": TrustOutcome.TRUST_CHAIN_INCOMPLETE}
    )
    linked_summary = LinkedCustodySummary(
        chain_id=ledger.chain_id,
        ledger_digest=ledger.ledger_digest,
        event_count=ledger.event_count,
        genesis_event_digest=ledger.genesis_event_digest,
        latest_event_digest=ledger.latest_event_digest,
        ledger_integrity=ledger.ledger_integrity,
        subject_continuity=ledger.subject_continuity,
        evidence_linkage=ledger.evidence_linkage,
        event_authenticity=ledger.event_authenticity_summary.statuses,
        lifecycle_completeness=ledger.lifecycle_completeness,
        overall_custody_status=ledger.overall_custody_status,
        missing_event_types=ledger.missing_event_analysis.missing_event_types,
    )
    data: dict[str, Any] = {
        "passport_id": "mp_"
        + canonical_sha256(_linked_id_body(base, ledger))[:32],
        "base_passport_id": base.passport_id,
        "base_passport_digest": base.passport_digest,
        "subject": base.subject,
        "artifact_identity": base.artifact_identity,
        "evidence_identity": base.evidence_identity,
        "evidence_stages": stages,
        "trust_summary": trust,
        "usage_profiles": base.usage_profiles,
        "custody_summary": linked_summary,
        "security_summary": base.security_summary,
        "runtime_summary": base.runtime_summary,
        "limitations": sorted(
            set(
                base.limitations
                + [
                    "The custody ledger is intact but lifecycle evidence is incomplete.",
                    "Evidence-derived custody events are unattested and do not "
                    "authenticate actors.",
                ]
            )
        ),
        "warnings": base.warnings,
        "custody_reference": LedgerArtifactReference(
            role="custody_ledger",
            schema=ledger.schema_id,
            digest=ledger.ledger_digest,
            relative_path=ledger_reference,
        ),
        "policy_identity": base.policy_identity,
        "passport_digest": "0" * 64,
    }
    draft = CustodyLinkedPassport.model_validate(data)
    body = draft.model_dump(mode="json", by_alias=True)
    body.pop("passport_digest")
    data["passport_digest"] = canonical_sha256(body)
    return CustodyLinkedPassport.model_validate(data)


def pretty_linked_passport_json(passport: CustodyLinkedPassport) -> str:
    return (
        json.dumps(
            passport.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_linked_passport_markdown(passport: CustodyLinkedPassport) -> str:
    origin = passport.artifact_identity.origin
    custody = passport.custody_summary
    format_identity = passport.artifact_identity.format_identity
    content_identity = passport.artifact_identity.content_identity
    authenticity = ", ".join(item.value for item in custody.event_authenticity)
    lines = [
        f"# Model Passport with Custody: {_safe(passport.subject.display_name)}",
        "",
        "This passport links an intact evidence-derived custody segment. The lifecycle "
        "record remains incomplete and its events are unattested.",
        "",
        "## Compact Summary",
        "",
        "| Item | Result |",
        "| --- | --- |",
        f"| Model | {_safe(passport.subject.display_name)} |",
        f"| Artifact variant | {_safe(passport.subject.artifact_variant)} |",
        f"| Origin | {_safe(origin.provider or origin.origin_type)} / "
        f"{_safe(origin.repository or 'not recorded')} |",
        f"| Immutable revision | `{_safe(origin.resolved_revision or 'not available')}` |",
        f"| Format | {_safe(format_identity.format)} |",
        f"| Architecture | {_safe(format_identity.architecture or 'not recorded')} |",
        f"| Artifact size | {_size(content_identity.total_declared_bytes)} |",
        "| Custody ledger availability | **AVAILABLE** |",
        f"| Ledger integrity | **{custody.ledger_integrity.value}** |",
        f"| Subject continuity | **{custody.subject_continuity.value}** |",
        f"| Evidence linkage | **{custody.evidence_linkage.value}** |",
        f"| Lifecycle completeness | **{custody.lifecycle_completeness.value}** |",
        f"| Event authenticity | **{authenticity} / UNATTESTED** |",
        "| Overall custody | **TRUST_CHAIN_INCOMPLETE** |",
        f"| Security inspection | **{passport.security_summary.status.value}** |",
        f"| Runtime verification | **{passport.runtime_summary.status.value}** |",
        "",
        "## Custody Boundary",
        "",
        "Hash linking proves integrity of the recorded sequence. It does not prove that "
        "a real-world action occurred, authenticate an actor, or establish approval.",
        "",
        "## Missing Lifecycle Events",
        "",
    ]
    lines.extend(f"- `{item.value}`" for item in custody.missing_event_types)
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_safe(item)}" for item in passport.limitations)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Base passport: `{passport.base_passport_id}` / `{passport.base_passport_digest}`",
            f"- Custody chain: `{custody.chain_id}` / `{custody.ledger_digest}`",
            f"- Linked passport ID: `{passport.passport_id}`",
            f"- Linked passport digest: `{passport.passport_digest}`",
            "",
        ]
    )
    return "\n".join(lines)


def _verify_internal(passport: CustodyLinkedPassport) -> None:
    body = passport.model_dump(mode="json", by_alias=True)
    stored = body.pop("passport_digest")
    if stored != canonical_sha256(body):
        raise OmivInputError("custody-linked passport digest mismatch")
    expected_id = "mp_" + canonical_sha256(
        {
            "schema": passport.schema_id,
            "base_passport_id": passport.base_passport_id,
            "base_passport_digest": passport.base_passport_digest,
            "subject": passport.subject.model_dump(mode="json"),
            "artifact_identity": passport.artifact_identity.model_dump(mode="json"),
            "custody_ledger_digest": passport.custody_summary.ledger_digest,
            "passport_policy_digest": passport.policy_identity.passport_policy_digest,
        }
    )[:32]
    if passport.passport_id != expected_id:
        raise OmivInputError("custody-linked passport identity mismatch")
    if passport.custody_reference.digest != passport.custody_summary.ledger_digest:
        raise OmivInputError("custody-linked passport ledger reference mismatch")
    stages = {item.stage: item for item in passport.evidence_stages}
    custody_stage = stages.get(PassportStageName.CUSTODY_CHAIN)
    if custody_stage is None or custody_stage.status != PassportStageStatus.AVAILABLE:
        raise OmivInputError("linked passport custody stage is not AVAILABLE")
    if custody_stage.artifact_digest != passport.custody_summary.ledger_digest:
        raise OmivInputError("linked passport custody stage digest mismatch")
    if passport.trust_summary.custody_status != TrustOutcome.TRUST_CHAIN_INCOMPLETE:
        raise OmivInputError("linked passport custody trust must remain incomplete")
    if passport.custody_summary.lifecycle_completeness.value == "INCOMPLETE" and (
        passport.custody_summary.overall_custody_status.value != "INCOMPLETE"
    ):
        raise OmivInputError("linked passport incomplete lifecycle verdict mismatch")
    if any(
        item.value == "SIGNED_ATTESTATION_RESERVED"
        for item in passport.custody_summary.event_authenticity
    ):
        raise OmivInputError("linked passport cannot claim signed custody events")


def load_custody_linked_passport(path: Path) -> CustodyLinkedPassport:
    try:
        raw = load_json_value(path.read_text(encoding="utf-8"))
        passport = CustodyLinkedPassport.model_validate(raw)
    except (OSError, UnicodeError, ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid custody-linked Model Passport: {exc}") from exc
    _verify_internal(passport)
    return passport


def verify_custody_linked_passport(
    path: Path, *, root: Path | None = None, digest_only: bool = False
) -> CustodyLinkedPassport:
    linked = load_custody_linked_passport(path)
    if digest_only:
        return linked
    if root is None:
        raise OmivInputError("full linked-passport verification requires a repository root")
    root = root.resolve()
    ledger_path = root / linked.custody_reference.relative_path
    ledger = verify_custody_ledger(ledger_path, root)
    base_path = root / ledger.passport_reference.relative_path
    verify_passport(base_path, root=root)
    base = load_passport(base_path)
    rebuilt = build_custody_linked_passport(
        base, ledger, ledger_reference=linked.custody_reference.relative_path
    )
    if rebuilt != linked:
        raise OmivInputError("custody-linked passport does not reconstruct")
    return linked


def write_custody_linked_passport(
    passport: CustodyLinkedPassport,
    output: Path,
    markdown_output: Path,
    *,
    forbidden_inputs: tuple[Path, ...] = (),
) -> None:
    if output.resolve() == markdown_output.resolve():
        raise OmivInputError("linked passport output paths must be distinct")
    validate_output_path(output, forbidden_inputs=forbidden_inputs)
    validate_output_path(markdown_output, forbidden_inputs=forbidden_inputs)
    atomic_write_text(
        output, pretty_linked_passport_json(passport), forbidden_inputs=forbidden_inputs
    )
    atomic_write_text(
        markdown_output,
        render_linked_passport_markdown(passport),
        forbidden_inputs=forbidden_inputs,
    )
