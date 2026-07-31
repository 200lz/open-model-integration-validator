"""Deterministic machine- and human-readable attestation reports."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ValidationError

from omiv.attestations.models import (
    ArtifactAttestation,
    ArtifactAttestationReport,
    ArtifactAttestationReportEnvelope,
    AttestationFinding,
    AttestationKind,
    EvidenceLinkage,
    ExecutionVerification,
)
from omiv.attestations.policy import attestation_policy
from omiv.attestations.verification import verify_attestation
from omiv.canonical import canonical_sha256, load_json_value
from omiv.errors import OmivInputError
from omiv.safe_write import atomic_write_text


def _mapping(kind: AttestationKind) -> str:
    return attestation_policy().custody_event_mapping[kind.value]


def _next_evidence(value: ArtifactAttestation) -> list[str]:
    result: list[str] = []
    summary = value.verification_summary
    if summary.evidence_linkage != EvidenceLinkage.FULLY_VERIFIED:
        result.append("fully reconstructable claim evidence")
    if (
        summary.execution_verification != ExecutionVerification.VERIFIED
        and value.attestation_kind in {AttestationKind.TRANSFORMATION, AttestationKind.QUANTIZATION}
    ):
        result.append("verified tool execution record")
    if value.issuer.issuer_status.value != "EVIDENCE_LINKED":
        result.append("issuer identity evidence")
    result.extend(["payload or numerical fidelity evidence", "signed attestation (future phase)"])
    return sorted(set(result))


def build_attestation_report(
    value: ArtifactAttestation,
) -> ArtifactAttestationReportEnvelope:
    summary = value.verification_summary
    findings = [
        AttestationFinding(
            finding_id=f"ATTEST-{index:03d}",
            status=(
                "PASS"
                if index not in {7, 13, 15}
                else value.authenticity.value
                if index == 7
                else summary.execution_verification.value
                if index == 13
                else summary.provenance_strength.value
            ),
            summary=text,
            limitation=limitation,
        )
        for index, text, limitation in (
            (1, "Strict attestation schema is valid.", None),
            (2, "Attestation identity is deterministic.", None),
            (
                3,
                "Canonical attestation digest is valid.",
                "Integrity does not prove action occurrence.",
            ),
            (4, "Artifact references are canonical.", None),
            (
                5,
                "Input/output relation is valid.",
                "Continuity does not establish semantic correctness.",
            ),
            (6, "Assertion origin is explicit.", None),
            (7, "Authenticity was reconstructed.", "Evidence linkage is not a signature."),
            (8, "Issuer status is explicit.", "Issuer identity is not authenticated."),
            (9, "Tool identity is explicit where required.", None),
            (10, "Configuration identity is deterministic.", None),
            (11, "Environment identity status is explicit.", None),
            (12, "Evidence references satisfy their recorded mode.", None),
            (
                13,
                "Execution-record status was reconstructed.",
                "Execution linkage does not prove output correctness.",
            ),
            (14, "Artifact continuity was reconstructed.", None),
            (
                15,
                "Provenance strength was reconstructed.",
                "Structural similarity alone is insufficient.",
            ),
            (16, "Custody-event mapping is explicit.", None),
            (17, "Forbidden trust escalation was prevented.", None),
            (18, "Limitations are explicit.", None),
            (19, "Canonical generation is deterministic.", None),
            (20, "Sensitive canonical fields are absent.", None),
        )
    ]
    body = {
        "schema": "omiv.artifact-attestation-report.v1",
        "attestation_id": value.attestation_id,
        "attestation_digest": value.attestation_digest,
        "attestation_kind": value.attestation_kind.value,
        "claim_type": value.claim_type.value,
        "subject": value.subject.model_dump(mode="json"),
        "inputs": [item.model_dump(mode="json") for item in value.inputs],
        "outputs": [item.model_dump(mode="json") for item in value.outputs],
        "issuer_status": value.issuer.issuer_status.value,
        "assertion_origin": value.assertion_origin.value,
        "authenticity": value.authenticity.value,
        "tool_identity_digest": (
            value.tool_identity.tool_identity_digest if value.tool_identity else None
        ),
        "configuration_digest": (
            value.configuration_identity.configuration_digest
            if value.configuration_identity
            else None
        ),
        "environment_status": value.environment_identity.status.value,
        "evidence_linkage": summary.evidence_linkage.value,
        "execution_verification": summary.execution_verification.value,
        "artifact_continuity": summary.artifact_continuity.value,
        "provenance_strength": summary.provenance_strength.value,
        "materialization_eligibility": summary.materialization_eligibility.value,
        "execution_record_integrity": summary.execution_record_integrity,
        "cryptographic_signature": summary.cryptographic_signature,
        "issuer_authentication": summary.issuer_authentication,
        "actor_authenticity": summary.actor_authenticity,
        "attestation_signature_boundary": summary.attestation_signature_boundary,
        "payload_status": summary.payload_status,
        "numerical_fidelity_status": summary.numerical_fidelity_status,
        "security_status": summary.security_status,
        "runtime_status": summary.runtime_status,
        "custody_event_mapping": _mapping(value.attestation_kind),
        "limitations": sorted(value.limitations),
        "warnings": sorted(value.warnings),
        "next_evidence_required": _next_evidence(value),
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    report = ArtifactAttestationReport.model_validate(
        {**body, "report_digest": canonical_sha256(body)}
    )
    return ArtifactAttestationReportEnvelope(
        report=report,
        integrity={
            "algorithm": "sha256",
            "canonicalization": "omiv-json-v1",
            "digest": report.report_digest,
        },
    )


def pretty_json(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"


def render_attestation_markdown(value: ArtifactAttestationReportEnvelope) -> str:
    report = value.report
    input_formats = ", ".join(item.format or "unspecified" for item in report.inputs)
    output_formats = ", ".join(item.format or "unspecified" for item in report.outputs)
    lines = [
        f"# Artifact Attestation: {report.attestation_kind.value}",
        "",
        "This is an integrity-checked structured claim. It is not a cryptographic "
        "signature or proof of issuer identity.",
        "",
        "## Claim Summary",
        "",
        "| Item | Result |",
        "| --- | --- |",
        f"| Attestation | `{report.attestation_id}` |",
        f"| Claim | `{report.claim_type.value}` |",
        f"| Input formats | {input_formats} |",
        f"| Output formats | {output_formats} |",
        f"| Assertion origin | **{report.assertion_origin.value}** |",
        f"| Authenticity | **{report.authenticity.value}** |",
        f"| Issuer | **{report.issuer_status.value}** |",
        f"| Issuer authentication | **{report.issuer_authentication}** |",
        f"| Actor authenticity | **{report.actor_authenticity}** |",
        f"| Evidence linkage | **{report.evidence_linkage.value}** |",
        f"| Execution verification | **{report.execution_verification.value}** |",
        f"| Execution record integrity | **{report.execution_record_integrity}** |",
        f"| Cryptographic signature | **{report.cryptographic_signature}** |",
        f"| Attestation boundary | **{report.attestation_signature_boundary}** |",
        f"| Artifact continuity | **{report.artifact_continuity.value}** |",
        f"| Provenance strength | **{report.provenance_strength.value}** |",
        f"| Custody materialization | **{report.materialization_eligibility.value}** |",
        f"| Custody event | `{report.custody_event_mapping}` |",
        f"| Payload correctness | **{report.payload_status}** |",
        f"| Numerical fidelity | **{report.numerical_fidelity_status}** |",
        f"| Security | **{report.security_status}** |",
        f"| Runtime behavior | **{report.runtime_status}** |",
        "",
        "A verified execution record links declared inputs, tool, configuration, and "
        "outputs. It does not prove numerical correctness, security, or runtime behavior.",
        "",
    ]
    if report.assertion_origin.value == "USER_DECLARED":
        lines.extend(
            [
                "## Declared Acquisition Boundary",
                "",
                "Acquisition claim recorded.",
                "",
                "- Claim basis: **USER_DECLARED**",
                "- Evidence status: **UNAVAILABLE**",
                "- Custody event authenticity: **UNATTESTED**",
                "- Payload equality: **NOT_CHECKED**",
                "",
            ]
        )
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in report.limitations)
    lines.extend(["", "## Next Evidence Required", ""])
    lines.extend(f"- {item}" for item in report.next_evidence_required)
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Attestation digest: `{report.attestation_digest}`",
            f"- Report digest: `{report.report_digest}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_attestation_bundle(
    attestation: ArtifactAttestation,
    report: ArtifactAttestationReportEnvelope,
    output: Path,
    report_output: Path,
    markdown_output: Path,
    *,
    forbidden_inputs: tuple[Path, ...] = (),
) -> None:
    atomic_write_text(output, pretty_json(attestation), forbidden_inputs=forbidden_inputs)
    atomic_write_text(report_output, pretty_json(report), forbidden_inputs=forbidden_inputs)
    atomic_write_text(
        markdown_output,
        render_attestation_markdown(report),
        forbidden_inputs=forbidden_inputs,
    )


def load_attestation_report(path: Path) -> ArtifactAttestationReportEnvelope:
    try:
        return ArtifactAttestationReportEnvelope.model_validate(
            load_json_value(path.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, ValidationError, ValueError) as exc:
        raise OmivInputError(f"invalid attestation report: {exc}") from exc


def verify_attestation_report(
    report_path: Path, attestation_path: Path
) -> ArtifactAttestationReportEnvelope:
    stored = load_attestation_report(report_path)
    rebuilt = build_attestation_report(verify_attestation(attestation_path))
    if stored != rebuilt:
        raise OmivInputError("attestation report does not reconstruct")
    return stored
