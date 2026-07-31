"""Generic attestation-gap summaries derived from an existing Model Passport."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_sha256, load_json_value
from omiv.errors import OmivInputError
from omiv.models import StrictModel
from omiv.passport.models import ModelPassport, PassportStageName, PassportStageStatus
from omiv.passport.verification import load_passport, verify_passport
from omiv.safe_write import atomic_write_text

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class AttestationGapReport(StrictModel):
    schema_id: Literal["omiv.artifact-attestation-gap-report.v1"] = Field(
        default="omiv.artifact-attestation-gap-report.v1", alias="schema"
    )
    subject_display_name: str
    artifact_variant: str
    passport_id: str
    passport_digest: str = Field(pattern=SHA256_PATTERN)
    source_locator_status: Literal["KNOWN", "UNAVAILABLE"]
    immutable_revision_status: Literal["KNOWN", "UNAVAILABLE"]
    remote_inspection_status: Literal["AVAILABLE", "UNAVAILABLE"]
    structural_evidence_status: Literal["AVAILABLE", "UNAVAILABLE"]
    acquisition_attestation: Literal["UNAVAILABLE"]
    transformation_attestation: Literal["UNAVAILABLE"]
    quantization_attestation: Literal["UNAVAILABLE"]
    execution_record: Literal["UNAVAILABLE"]
    issuer_identity: Literal["UNAVAILABLE"]
    signature: Literal["UNAVAILABLE"]
    artifact_specific_provenance: Literal["UNAVAILABLE"]
    limitations: list[str]
    report_digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def canonical(self) -> AttestationGapReport:
        body = self.model_dump(mode="json", by_alias=True)
        digest = body.pop("report_digest")
        if digest != canonical_sha256(body):
            raise ValueError("attestation gap report digest mismatch")
        return self


def build_attestation_gap_report(passport: ModelPassport) -> AttestationGapReport:
    stages = {item.stage: item.status for item in passport.evidence_stages}
    origin = passport.artifact_identity.origin
    body = {
        "schema": "omiv.artifact-attestation-gap-report.v1",
        "subject_display_name": passport.subject.display_name,
        "artifact_variant": passport.subject.artifact_variant,
        "passport_id": passport.passport_id,
        "passport_digest": passport.passport_digest,
        "source_locator_status": (
            "KNOWN" if origin.repository or origin.origin_type == "local_file" else "UNAVAILABLE"
        ),
        "immutable_revision_status": ("KNOWN" if origin.resolved_revision else "UNAVAILABLE"),
        "remote_inspection_status": (
            "AVAILABLE"
            if stages.get(PassportStageName.REPOSITORY_LAYOUT) == PassportStageStatus.PASS
            else "UNAVAILABLE"
        ),
        "structural_evidence_status": (
            "AVAILABLE"
            if stages.get(PassportStageName.FORMAT_STRUCTURE) == PassportStageStatus.PASS
            else "UNAVAILABLE"
        ),
        "acquisition_attestation": "UNAVAILABLE",
        "transformation_attestation": "UNAVAILABLE",
        "quantization_attestation": "UNAVAILABLE",
        "execution_record": "UNAVAILABLE",
        "issuer_identity": "UNAVAILABLE",
        "signature": "UNAVAILABLE",
        "artifact_specific_provenance": "UNAVAILABLE",
        "limitations": [
            "Remote inspection is not acquisition.",
            "Structural equivalence is not artifact-specific transformation provenance.",
            "No acquisition, transformation, quantization, execution, issuer, or "
            "signature attestation is available.",
        ],
    }
    return AttestationGapReport.model_validate({**body, "report_digest": canonical_sha256(body)})


def pretty_gap_json(value: AttestationGapReport) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_gap_markdown(value: AttestationGapReport) -> str:
    return "\n".join(
        [
            f"# Artifact Attestation Gaps: {value.subject_display_name}",
            "",
            "This report records missing attestation evidence; it is not a placeholder "
            "lifecycle event.",
            "",
            f"- Source locator: **{value.source_locator_status}**",
            f"- Immutable revision: **{value.immutable_revision_status}**",
            f"- Remote inspection evidence: **{value.remote_inspection_status}**",
            f"- Structural evidence: **{value.structural_evidence_status}**",
            "- Acquisition attestation: **UNAVAILABLE**",
            "- Transformation attestation: **UNAVAILABLE**",
            "- Quantization attestation: **UNAVAILABLE**",
            "- Execution record: **UNAVAILABLE**",
            "- Issuer identity: **UNAVAILABLE**",
            "- Signature: **UNAVAILABLE**",
            "- Artifact-specific provenance: **UNAVAILABLE**",
            "",
            "Remote inspection is not acquisition. Structural equivalence is not "
            "artifact-specific transformation provenance.",
            "",
            f"Report digest: `{value.report_digest}`",
            "",
        ]
    )


def write_gap_report(value: AttestationGapReport, output: Path, markdown: Path) -> None:
    atomic_write_text(output, pretty_gap_json(value))
    atomic_write_text(markdown, render_gap_markdown(value))


def verify_gap_report(path: Path, passport_path: Path, root: Path) -> AttestationGapReport:
    try:
        stored = AttestationGapReport.model_validate(
            load_json_value(path.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise OmivInputError(f"invalid attestation gap report: {exc}") from exc
    verify_passport(passport_path, root=root)
    expected = build_attestation_gap_report(load_passport(passport_path))
    if stored != expected:
        raise OmivInputError("attestation gap report does not reconstruct")
    return stored
