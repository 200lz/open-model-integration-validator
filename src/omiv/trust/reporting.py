"""Deterministic JSON and Markdown output for reconstructed trust reports."""

from __future__ import annotations

import html
import json
from pathlib import Path

from omiv.safe_write import atomic_write_text
from omiv.trust.models import SignatureReport, SignedObjectEnvelope
from omiv.trust.verification import pretty_json


def render_markdown(report: SignatureReport) -> str:
    def safe(value: object) -> str:
        return html.escape(str(value), quote=True)

    def safe_json(value: object) -> str:
        return html.escape(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True),
            quote=True,
        )

    lines = [
        "# OMIV Signed Object Trust Report",
        "",
        f"- Object: `{safe(report.signed_object_type.value)}` / `{safe(report.signed_object_id)}`",
        f"- Canonical object digest: `{report.signed_object_digest}`",
        f"- Policy: `{safe(report.policy_id)}` / `{report.policy_digest}`",
        f"- Trust bundle: `{report.trust_bundle_id}` / `{report.trust_bundle_digest}`",
        f"- Overall signed-object status: **{report.overall_status.value}**",
        f"- Accepted signatures: {report.accepted_signature_count}",
        "",
        "## Layered results",
        "",
    ]
    for result in report.signature_results:
        trusted = "YES" if result.trust_policy_status.value == "TRUSTED_BY_POLICY" else "NO"
        binding = (
            result.signer_binding_status.value
            if result.signer_binding_status is not None
            else result.signer_binding.value
        )
        lines.extend(
            [
                f"### Signature `{result.signature_id}`",
                "",
                f"- Signature integrity: **{result.signature_integrity.value}**",
                f"- Trusted by selected policy: **{trusted}**",
                f"- Key identity/status: `{result.key_id}` / **{result.key_status.value}**",
                f"- Signer identity: **{result.signer_identity_status.value}**",
                f"- Signer identity verification: **{result.signer_identity_verification.value}**",
                f"- Signer/key binding: **{binding}**",
                f"- Delegation: **{result.delegation_status.value}**",
                f"- Revocation: **{result.revocation_status.value}**",
                f"- Expiration: **{result.expiration_status.value}**",
                f"- Policy trust: **{result.trust_policy_status.value}**",
                "",
            ]
        )
        for revocation in result.revocation_records:
            lines.extend(
                [
                    "- Revocation record: "
                    f"`{revocation.revocation_id}` / **{revocation.record_validity}**",
                    f"- Revocation authority: **{revocation.authority.value}**",
                    "- Revocation scope/status: "
                    f"**{revocation.scope.value}** / **{revocation.effective_status.value}**",
                    f"- Revocation reason: **{revocation.reason.value}**",
                    "- Replacement/supersession: "
                    f"`{safe(revocation.replacement_reference or 'NONE')}`",
                    "",
                ]
            )
    lines.extend(
        [
            "## Claim-strength boundary",
            "",
            f"- Underlying claim: `{safe_json(report.underlying_claim)}`",
            "- Underlying claim authenticity: "
            f"**{safe(report.underlying_claim.get('authenticity', 'NOT_APPLICABLE'))}**",
            "- Underlying provenance strength: "
            f"**{safe(report.underlying_claim.get('provenance_strength', 'NOT_APPLICABLE'))}**",
            "- Claim content independently proven: **NO**",
            f"- Payload integrity: **{report.payload_status}**",
            f"- Numerical fidelity: **{report.numerical_fidelity_status}**",
            f"- Security: **{report.security_status}**",
            f"- Runtime: **{report.runtime_status}**",
            f"- Approval: **{report.approval_status}**",
            f"- Lifecycle completeness: **{safe(report.lifecycle_completeness)}**",
            "",
            "A valid signature proves that the holder of the corresponding private key signed a "
            "specific canonical OMIV object. It does not by itself prove the underlying real-world "
            "claim is true.",
            "",
            "## Limitations",
            "",
            *[f"- {safe(item)}" for item in report.limitations],
            "",
            f"Report digest: `{report.report_digest}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(
    envelope: SignedObjectEnvelope,
    report: SignatureReport | None,
    *,
    envelope_path: Path | None = None,
    report_path: Path | None = None,
    markdown_path: Path | None = None,
    forbidden_inputs: tuple[Path, ...] = (),
) -> None:
    if envelope_path is not None:
        atomic_write_text(envelope_path, pretty_json(envelope), forbidden_inputs=forbidden_inputs)
    if report is not None and report_path is not None:
        atomic_write_text(report_path, pretty_json(report), forbidden_inputs=forbidden_inputs)
    if report is not None and markdown_path is not None:
        atomic_write_text(markdown_path, render_markdown(report), forbidden_inputs=forbidden_inputs)
