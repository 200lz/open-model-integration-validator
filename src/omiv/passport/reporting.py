"""Deterministic JSON, Markdown, and safe writing for Model Passports."""

from __future__ import annotations

import json
from pathlib import Path

from omiv.errors import OmivInputError
from omiv.passport.models import ModelPassport, PassportStageStatus, UsageOutcome
from omiv.safe_write import atomic_write_text, validate_output_path


def pretty_passport_json(passport: ModelPassport) -> str:
    return (
        json.dumps(
            passport.model_dump(mode="json", by_alias=True),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _safe(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _size(value: int) -> str:
    units = ("bytes", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024
    return f"{amount:.2f} {unit} ({value:,} bytes)"


def render_passport_markdown(passport: ModelPassport) -> str:
    artifact = passport.artifact_identity
    origin = artifact.origin
    stages = {item.stage.value: item for item in passport.evidence_stages}
    local = next(
        item
        for item in passport.usage_profiles
        if item.profile == "local_experimentation"
    )
    overall = (
        "SUITABLE FOR LOCAL EXPERIMENTATION WITH LIMITATIONS"
        if local.outcome == UsageOutcome.SUITABLE_WITH_LIMITATIONS
        else local.outcome.value.replace("_", " ")
    )
    lines = [
        f"# Model Passport: {_safe(passport.subject.display_name)}",
        "",
        "A portable, integrity-linked summary of this artifact's identity, evidence, "
        "trust status, and known limitations.",
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
        f"| Format | {_safe(artifact.format_identity.format)} |",
        f"| Architecture | {_safe(artifact.format_identity.architecture or 'not recorded')} |",
        f"| Artifact size | {_size(artifact.content_identity.total_declared_bytes)} |",
        f"| Structural validation | **{passport.trust_summary.structural_status.value}** |",
        f"| Provenance | **{stages['artifact_specific_provenance'].status.value}** |",
        f"| Payload | **{stages['payload_integrity'].status.value}** |",
        f"| Security inspection | **{passport.security_summary.status.value}** |",
        f"| Custody chain | **{passport.custody_summary.status.value}** |",
        f"| Runtime verification | **{passport.runtime_summary.status.value}** |",
        f"| Overall usage guidance | **{overall}** |",
        "",
        "## What Is Verified",
        "",
        "The artifact identity and structural evidence are integrity-linked and valid "
        "within the recorded scope.",
        "",
        "## What Is Not Verified",
        "",
        "Payload values, numerical fidelity, security behavior, and runtime equivalence "
        "have not been established.",
        "",
        "This passport does not state that the artifact is safe to execute, numerically "
        "equivalent, runtime-compatible, or production approved.",
        "",
        "## Trust Dimensions",
        "",
        "| Dimension | Result |",
        "| --- | --- |",
    ]
    for name, value in passport.trust_summary:
        label = name.replace("_status", "").replace("_", " ").title()
        lines.append(f"| {_safe(label)} | **{value.value}** |")
    lines.extend(
        [
            "",
            "## Usage Profiles",
            "",
            "| Profile | Result | Guidance |",
            "| --- | --- | --- |",
        ]
    )
    for profile in passport.usage_profiles:
        lines.append(
            f"| {_safe(profile.profile)} | **{profile.outcome.value}** | "
            f"{_safe(profile.guidance)} |"
        )
    lines.extend(
        [
            "",
            "## Evidence Stages",
            "",
            "| Stage | Status | Scope or limitation | Next step |",
            "| --- | --- | --- | --- |",
        ]
    )
    for stage in passport.evidence_stages:
        detail = (
            stage.scope
            if stage.status == PassportStageStatus.PASS
            else stage.limitations
        )
        explanation = "; ".join(detail)
        lines.append(
            f"| {_safe(stage.stage.value)} | **{stage.status.value}** | "
            f"{_safe(explanation or '—')} | "
            f"{_safe('; '.join(stage.next_step) or '—')} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_safe(item)}" for item in passport.limitations)
    lines.extend(
        [
            "",
            "## Custody Boundary",
            "",
            "No Model Chain of Custody ledger has been recorded. This passport claims no "
            "acquisition, transformation, validation-attestation, approval, deployment, "
            "or runtime-observation custody event.",
            "",
            "The validation evidence graph records dependencies between validation "
            "artifacts; it is not a custody ledger.",
        ]
    )
    lines.extend(["", "## Evidence References", ""])
    for reference in passport.evidence_references:
        lines.append(
            f"- `{_safe(reference.role)}` — schema `{_safe(reference.schema_id)}`, digest "
            f"`{reference.digest}`, availability `{reference.availability.value}`, verification "
            f"`{reference.verification_mode.value}`"
        )
    lines.extend(
        [
            "",
            "## Passport Integrity",
            "",
            f"- Passport ID: `{passport.passport_id}`",
            f"- Passport digest: `{passport.passport_digest}`",
            f"- Passport policy digest: `{passport.policy_identity.passport_policy_digest}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_passport(
    passport: ModelPassport,
    output: Path,
    markdown_output: Path,
    *,
    forbidden_inputs: tuple[Path, ...] = (),
) -> None:
    if output.resolve() == markdown_output.resolve():
        raise OmivInputError("passport JSON and Markdown outputs must use distinct paths")
    validate_output_path(output, forbidden_inputs=forbidden_inputs)
    validate_output_path(markdown_output, forbidden_inputs=forbidden_inputs)
    atomic_write_text(output, pretty_passport_json(passport), forbidden_inputs=forbidden_inputs)
    atomic_write_text(
        markdown_output,
        render_passport_markdown(passport),
        forbidden_inputs=forbidden_inputs,
    )
