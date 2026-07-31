from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from omiv.attestations.builder import (
    build_attestation,
    build_command_identity,
    build_configuration_identity,
    build_execution_record,
)
from omiv.attestations.custody import attestation_to_custody_event_input
from omiv.attestations.examples import (
    artifact_reference,
    included_evidence,
    synthetic_declared_acquisition_input,
    synthetic_evidence_acquisition_input,
    synthetic_quantization_input,
    synthetic_transformation_input,
)
from omiv.attestations.gaps import verify_gap_report
from omiv.attestations.models import (
    ArtifactAttestation,
    ArtifactAttestationInput,
    ArtifactContinuity,
    AttestationAssertionOrigin,
    AttestationKind,
    Authenticity,
    ClaimType,
    EvidenceLinkage,
    ExecutionResult,
    ExecutionVerification,
    ProvenanceStrength,
    ToolExecutionRecordInput,
)
from omiv.attestations.passport import PassportAttestationState, summarize_attestations
from omiv.attestations.policy import attestation_policy
from omiv.attestations.reporting import (
    build_attestation_report,
    pretty_json,
    render_attestation_markdown,
    verify_attestation_report,
)
from omiv.attestations.segment import verify_attestation_custody_segment
from omiv.attestations.verification import load_attestation, verify_attestation
from omiv.canonical import canonical_sha256
from omiv.cli import app
from omiv.custody.append import append_evidence_event
from omiv.custody.models import CustodyEventType, EventAuthenticity
from omiv.custody.verification import load_custody_ledger
from omiv.errors import OmivInputError

ROOT = Path(__file__).resolve().parents[1]
IQ_LEDGER = ROOT / "custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json"
EXAMPLES = ROOT / "attestations/examples"
REPORTS = ROOT / "reports/attestations"


@pytest.fixture
def declared() -> ArtifactAttestation:
    return build_attestation(synthetic_declared_acquisition_input())


@pytest.fixture
def evidence_acquisition() -> ArtifactAttestation:
    return build_attestation(synthetic_evidence_acquisition_input())


@pytest.fixture
def transformation() -> ArtifactAttestation:
    return build_attestation(synthetic_transformation_input())


@pytest.fixture
def quantization() -> ArtifactAttestation:
    return build_attestation(synthetic_quantization_input())


def test_deterministic_attestation_identity_and_digest(declared: ArtifactAttestation) -> None:
    assert declared == build_attestation(synthetic_declared_acquisition_input())
    assert declared.attestation_id.startswith("att_")
    assert len(declared.attestation_digest) == 64


@pytest.mark.parametrize(
    "change",
    ["claim", "artifact", "evidence", "tool", "configuration", "environment"],
)
def test_meaningful_changes_change_attestation_identity(change: str) -> None:
    base = synthetic_transformation_input()
    raw = base.model_dump(mode="json", by_alias=True)
    if change == "claim":
        raw["claim_details"]["relationship"] = "changed"
    elif change == "artifact":
        raw["outputs"][0]["variant"] = "changed"
        identity = dict(raw["outputs"][0])
        identity.pop("identity_digest")
        identity.pop("passport_id")
        identity.pop("passport_digest")
        identity.pop("validation_inventory_digest")
        raw["outputs"][0]["identity_digest"] = canonical_sha256(identity)
        raw["subject"] = raw["outputs"][0]
        raw["execution_record"]["output_artifacts"] = raw["outputs"]
    elif change == "evidence":
        payload = {"changed": True}
        raw["evidence_references"][1]["included_payload"] = payload
        raw["evidence_references"][1]["digest"] = canonical_sha256(payload)
    elif change == "tool":
        raw["tool_identity"]["tool_version"] = "2.0"
        tool = dict(raw["tool_identity"])
        tool.pop("tool_identity_digest")
        raw["tool_identity"]["tool_identity_digest"] = canonical_sha256(tool)
        raw["execution_record"]["tool_identity"] = raw["tool_identity"]
    elif change == "configuration":
        config = build_configuration_identity("synthetic.changed.v1", {"mode": "changed"})
        raw["configuration_identity"] = config.model_dump(mode="json")
        raw["execution_record"]["configuration_identity"] = raw["configuration_identity"]
    else:
        raw["environment_identity"]["runtime_identity"] = "synthetic-runtime-v2"
        raw["execution_record"]["environment_identity"] = raw["environment_identity"]
    if change in {"artifact", "tool", "configuration", "environment"}:
        record = raw["execution_record"]
        record_input = dict(record)
        record_input.pop("execution_record_id")
        record_input.pop("execution_record_digest")
        record_input["schema"] = "omiv.tool-execution-record-input.v1"
        rebuilt = build_execution_record(ToolExecutionRecordInput.model_validate(record_input))
        raw["execution_record"] = rebuilt.model_dump(mode="json", by_alias=True)
    changed = build_attestation(ArtifactAttestationInput.model_validate(raw))
    original = build_attestation(base)
    assert changed.attestation_id != original.attestation_id
    assert changed.attestation_digest != original.attestation_digest


def test_policy_digest_is_stable_and_identity_relevant(declared: ArtifactAttestation) -> None:
    assert attestation_policy() == attestation_policy()
    raw = declared.model_dump(mode="json", by_alias=True)
    raw["policy_identity"]["policy_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="identity mismatch"):
        ArtifactAttestation.model_validate(raw)


@pytest.mark.parametrize(
    "value",
    [
        "/tmp/private",
        "550e8400-e29b-41d4-a716-446655440000",
        "2026-01-01T00:00:00Z",
        "Bearer secret",
        "https://example.test/object?Signature=secret",
    ],
)
def test_unsafe_canonical_values_rejected(value: str) -> None:
    raw = synthetic_declared_acquisition_input().model_dump(mode="json", by_alias=True)
    raw["claim_details"]["unsafe"] = value
    with pytest.raises(ValidationError, match="path, timestamp, UUID, or secret"):
        ArtifactAttestationInput.model_validate(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("attestation_id", "att_" + "f" * 32),
        ("attestation_digest", "f" * 64),
        ("authenticity", "EXECUTION_VERIFIED"),
        ("evidence_linkage", "FULLY_VERIFIED"),
        ("provenance_strength", "ARTIFACT_SPECIFIC_PROVENANCE"),
        ("artifact_continuity", "VALID"),
        ("materialization_eligibility", "ELIGIBLE"),
        ("execution_verification", "VERIFIED"),
        ("issuer_verification", "VERIFIED"),
        ("custody_event_status", "VERIFIED"),
    ],
)
def test_caller_cannot_inject_canonical_conclusions(field: str, value: str) -> None:
    raw = synthetic_declared_acquisition_input().model_dump(mode="json", by_alias=True)
    raw[field] = value
    with pytest.raises(ValidationError, match="Extra inputs"):
        ArtifactAttestationInput.model_validate(raw)


def test_incompatible_kind_and_claim_rejected() -> None:
    raw = synthetic_declared_acquisition_input().model_dump(mode="json", by_alias=True)
    raw["claim_type"] = "ARTIFACT_QUANTIZED"
    with pytest.raises(ValidationError, match="incompatible"):
        ArtifactAttestationInput.model_validate(raw)


def test_declared_acquisition_semantics(declared: ArtifactAttestation) -> None:
    assert declared.assertion_origin == AttestationAssertionOrigin.USER_DECLARED
    assert declared.authenticity == Authenticity.DECLARED
    assert declared.acquisition_outcome.value == "DECLARED_ONLY"
    assert declared.verification_summary.evidence_linkage == EvidenceLinkage.UNAVAILABLE
    assert (
        declared.verification_summary.provenance_strength == ProvenanceStrength.DECLARED_PROVENANCE
    )
    assert declared.verification_summary.payload_status == "NOT_CHECKED"
    markdown = render_attestation_markdown(build_attestation_report(declared))
    for wording in (
        "Acquisition claim recorded",
        "Claim basis: **USER_DECLARED**",
        "Evidence status: **UNAVAILABLE**",
        "Custody event authenticity: **UNATTESTED**",
        "Payload equality: **NOT_CHECKED**",
    ):
        assert wording in markdown
    for misleading in (
        "Artifact acquired",
        "Download verified",
        "Transfer verified",
        "Possession established",
        "Acquisition authenticated",
    ):
        assert misleading not in markdown


def test_evidence_linked_acquisition_semantics(
    evidence_acquisition: ArtifactAttestation,
) -> None:
    assert evidence_acquisition.authenticity == Authenticity.EVIDENCE_LINKED
    assert (
        evidence_acquisition.verification_summary.evidence_linkage == EvidenceLinkage.FULLY_VERIFIED
    )
    assert evidence_acquisition.acquisition_outcome.value == "REMOTE_LOCAL_MATCH_VERIFIED"
    assert (
        evidence_acquisition.verification_summary.provenance_strength
        == ProvenanceStrength.EVIDENCE_LINKED_PROVENANCE
    )


def test_source_locator_and_remote_inspection_are_not_acquisition() -> None:
    value = synthetic_declared_acquisition_input()
    raw = value.model_dump(mode="json", by_alias=True)
    raw["inputs"] = []
    with pytest.raises(ValidationError, match="explicit input and output"):
        ArtifactAttestationInput.model_validate(raw)
    assert all(ref.role != "remote_inspection" for ref in value.evidence_references)


def test_false_full_verification_and_wrong_evidence_digest_rejected() -> None:
    evidence = included_evidence("acquisition_record", {"identity": "synthetic"})
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["digest"] = "f" * 64
    with pytest.raises(ValidationError, match="digest mismatch"):
        type(evidence).model_validate(raw)
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw["availability"] = "digest_only"
    raw["included_payload"] = None
    with pytest.raises(ValidationError, match="full verification"):
        type(evidence).model_validate(raw)


def test_transfer_preserves_identity_and_rejects_conversion() -> None:
    value = synthetic_declared_acquisition_input()
    source = value.inputs[0]
    raw = value.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "attestation_kind": "TRANSFER",
            "claim_type": "ARTIFACT_TRANSFERRED",
            "acquisition_method": "COPY",
            "subject": source.model_dump(mode="json"),
            "outputs": [source.model_dump(mode="json")],
        }
    )
    transfer = build_attestation(ArtifactAttestationInput.model_validate(raw))
    assert transfer.verification_summary.artifact_continuity == ArtifactContinuity.VALID
    assert transfer.verification_summary.materialization_eligibility.value == "NOT_ELIGIBLE"
    with pytest.raises(OmivInputError, match="not eligible"):
        attestation_to_custody_event_input(
            transfer, attestation_reference="attestations/examples/transfer.json"
        )
    raw["outputs"] = value.outputs
    raw["subject"] = value.outputs[0].model_dump(mode="json")
    with pytest.raises(OmivInputError, match="continuity"):
        build_attestation(ArtifactAttestationInput.model_validate(raw))


def test_transfer_materializes_only_verified_new_custody_boundary() -> None:
    base = synthetic_declared_acquisition_input()
    source = base.inputs[0]
    raw = base.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "attestation_kind": "TRANSFER",
            "claim_type": "ARTIFACT_TRANSFERRED",
            "acquisition_method": "AIR_GAPPED_TRANSFER",
            "subject": source.model_dump(mode="json"),
            "outputs": [source.model_dump(mode="json")],
            "assertion_origin": "DERIVED_FROM_VERIFIED_EVIDENCE",
            "evidence_references": [
                included_evidence(
                    "custody_boundary_entry",
                    {
                        "source_context": "synthetic-source-boundary",
                        "destination_context": "synthetic-new-boundary",
                        "destination_identity": source.identity_digest,
                        "boundary_entry": True,
                    },
                ).model_dump(mode="json", by_alias=True)
            ],
            "claim_details": {
                "new_custody_boundary_entry": True,
                "destination_identity_status": "VERIFIED",
                "acquisition_event_requirements": "SATISFIED",
            },
        }
    )
    transfer = build_attestation(ArtifactAttestationInput.model_validate(raw))
    assert transfer.verification_summary.materialization_eligibility.value == "ELIGIBLE"
    event = attestation_to_custody_event_input(
        transfer, attestation_reference="attestations/examples/transfer.json"
    )
    assert event.event_type == CustodyEventType.ARTIFACT_ACQUISITION_RECORDED


@pytest.mark.parametrize(
    "claim_updates",
    [
        {},
        {"new_custody_boundary_entry": True},
        {
            "new_custody_boundary_entry": True,
            "destination_identity_status": "VERIFIED",
        },
    ],
)
def test_transfer_evidence_alone_does_not_satisfy_acquisition(
    claim_updates: dict[str, object],
) -> None:
    base = synthetic_declared_acquisition_input()
    source = base.inputs[0]
    raw = base.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "attestation_kind": "TRANSFER",
            "claim_type": "ARTIFACT_TRANSFERRED",
            "subject": source.model_dump(mode="json"),
            "outputs": [source.model_dump(mode="json")],
            "claim_details": claim_updates,
        }
    )
    transfer = build_attestation(ArtifactAttestationInput.model_validate(raw))
    assert transfer.verification_summary.materialization_eligibility.value == "NOT_ELIGIBLE"


def test_generic_transformation_is_execution_verified(
    transformation: ArtifactAttestation,
) -> None:
    summary = transformation.verification_summary
    assert transformation.inputs[0].format == "safetensors"
    assert transformation.outputs[0].format == "gguf"
    assert transformation.authenticity == Authenticity.EXECUTION_VERIFIED
    assert summary.execution_verification == ExecutionVerification.VERIFIED
    assert summary.artifact_continuity == ArtifactContinuity.VALID
    assert summary.provenance_strength == ProvenanceStrength.ARTIFACT_SPECIFIC_PROVENANCE
    assert (
        summary.payload_status == summary.security_status == summary.runtime_status == "NOT_CHECKED"
    )
    assert summary.execution_record_integrity == "VERIFIED"
    assert summary.cryptographic_signature == "NOT_AVAILABLE"
    assert summary.issuer_authentication == "UNVERIFIED"
    assert summary.actor_authenticity == "UNVERIFIED"
    assert summary.attestation_signature_boundary == "UNSIGNED"
    assert summary.numerical_fidelity_status == "NOT_CHECKED"


def test_quantization_is_specialized_and_no_fidelity_escalation(
    quantization: ArtifactAttestation,
) -> None:
    assert quantization.attestation_kind == AttestationKind.QUANTIZATION
    assert quantization.claim_type == ClaimType.ARTIFACT_QUANTIZED
    assert quantization.quantization is not None
    assert quantization.quantization.target_type_policy == "generic-q4"
    assert quantization.quantization.numerical_fidelity_status == "NOT_CHECKED"
    assert quantization.authenticity == Authenticity.EXECUTION_VERIFIED
    markdown = render_attestation_markdown(build_attestation_report(quantization))
    for required in (
        "Execution record integrity | **VERIFIED**",
        "Cryptographic signature | **NOT_AVAILABLE**",
        "Issuer authentication | **UNVERIFIED**",
        "Actor authenticity | **UNVERIFIED**",
        "Attestation boundary | **UNSIGNED**",
        "Payload correctness | **NOT_CHECKED**",
        "Numerical fidelity | **NOT_CHECKED**",
        "Security | **NOT_CHECKED**",
        "Runtime behavior | **NOT_CHECKED**",
    ):
        assert required in markdown


def test_missing_quantization_target_rejected() -> None:
    raw = synthetic_quantization_input().model_dump(mode="json", by_alias=True)
    raw["quantization"] = None
    with pytest.raises(ValidationError, match="quantization requires"):
        ArtifactAttestationInput.model_validate(raw)


def test_assertion_origin_trust_boundaries() -> None:
    base = synthetic_declared_acquisition_input()
    observed = base.model_copy(
        update={"assertion_origin": AttestationAssertionOrigin.SYSTEM_OBSERVED}
    )
    with pytest.raises(OmivInputError, match="observation evidence"):
        build_attestation(observed)
    derived = base.model_copy(
        update={"assertion_origin": AttestationAssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE}
    )
    with pytest.raises(OmivInputError, match="fully verified"):
        build_attestation(derived)
    raw = base.model_dump(mode="json", by_alias=True)
    raw["assertion_origin"] = "SIGNED_ATTESTATION_RESERVED"
    with pytest.raises(ValidationError, match="Phase 5D"):
        ArtifactAttestationInput.model_validate(raw)


def test_execution_record_tampering_and_failure() -> None:
    value = synthetic_transformation_input()
    assert value.execution_record is not None
    raw = value.execution_record.model_dump(mode="json", by_alias=True)
    raw["execution_result"] = "FAILED"
    with pytest.raises(ValidationError, match="execution record"):
        type(value.execution_record).model_validate(raw)
    failed_input = value.execution_record.model_dump(mode="json", by_alias=True)
    failed_input.pop("execution_record_id")
    failed_input.pop("execution_record_digest")
    failed_input["schema"] = "omiv.tool-execution-record-input.v1"
    failed_input["execution_result"] = ExecutionResult.FAILED.value
    failed = build_execution_record(ToolExecutionRecordInput.model_validate(failed_input))
    candidate = value.model_copy(update={"execution_record": failed})
    with pytest.raises(OmivInputError, match="verified execution"):
        build_attestation(candidate)


@pytest.mark.parametrize("component", ["command", "environment", "record_evidence"])
def test_artifact_specific_provenance_requires_every_execution_component(
    component: str,
) -> None:
    value = synthetic_transformation_input()
    if component == "command":
        value = value.model_copy(
            update={"command_identity": build_command_identity("other", ["--mode", "x"])}
        )
    elif component == "environment":
        value = value.model_copy(
            update={
                "environment_identity": (
                    synthetic_declared_acquisition_input().environment_identity
                )
            }
        )
    else:
        assert value.execution_record is not None
        raw = value.execution_record.model_dump(mode="json", by_alias=True)
        raw.pop("execution_record_id")
        raw.pop("execution_record_digest")
        raw["schema"] = "omiv.tool-execution-record-input.v1"
        raw["evidence_references"] = []
        record = build_execution_record(ToolExecutionRecordInput.model_validate(raw))
        value = value.model_copy(update={"execution_record": record})
    with pytest.raises(OmivInputError):
        build_attestation(value)


def test_command_and_configuration_are_deterministic_and_safe() -> None:
    command = build_command_identity("converter", ["--mode", "generic"])
    assert command == build_command_identity("converter", ["--mode", "generic"])
    with pytest.raises(ValidationError, match="secret"):
        build_command_identity("converter", ["--token", "Bearer secret"])
    config = build_configuration_identity("example.v1", {"target": "gguf"})
    changed = build_configuration_identity("example.v1", {"target": "onnx"})
    assert config.configuration_digest != changed.configuration_digest


def test_custody_event_mapping_and_authenticity(
    declared: ArtifactAttestation,
    transformation: ArtifactAttestation,
    quantization: ArtifactAttestation,
) -> None:
    acquisition_event = attestation_to_custody_event_input(
        declared, attestation_reference="attestations/examples/declared.json"
    )
    assert acquisition_event.event_type == CustodyEventType.ARTIFACT_ACQUISITION_RECORDED
    assert acquisition_event.assertion_origin.value == "USER_DECLARED"
    transform_event = attestation_to_custody_event_input(
        transformation, attestation_reference="attestations/examples/transformation.json"
    )
    assert transform_event.event_type == CustodyEventType.TRANSFORMATION_RECORDED
    quant_event = attestation_to_custody_event_input(
        quantization, attestation_reference="attestations/examples/quantization.json"
    )
    assert quant_event.event_type == CustodyEventType.QUANTIZATION_RECORDED
    assert quant_event.event_claims["execution_verification"] == "VERIFIED"


def test_append_derives_parent_and_preserves_unsigned_event() -> None:
    ledger = load_custody_ledger(IQ_LEDGER)
    value = synthetic_declared_acquisition_input().model_copy(
        update={
            "subject": ledger.subject,
            "inputs": [ledger.subject],
            "outputs": [ledger.subject],
        }
    )
    attestation = build_attestation(value)
    event_input = attestation_to_custody_event_input(
        attestation, attestation_reference="attestations/examples/synthetic.json"
    )
    updated = append_evidence_event(ledger, event_input)
    assert updated.events[-1].previous_event_digest == ledger.latest_event_digest
    assert updated.events[-1].authenticity == EventAuthenticity.USER_DECLARED
    assert updated.events[-1].attestation_status.value == "UNATTESTED"
    assert ledger.event_count + 1 == updated.event_count
    with pytest.raises(OmivInputError, match="duplicate"):
        append_evidence_event(updated, event_input)


def test_report_rendering_and_reconstruction(
    transformation: ArtifactAttestation, tmp_path: Path
) -> None:
    envelope = build_attestation_report(transformation)
    assert envelope == build_attestation_report(transformation)
    markdown = render_attestation_markdown(envelope)
    assert "not a cryptographic signature" in markdown
    assert "Payload correctness | **NOT_CHECKED**" in markdown
    assert "ARTIFACT_SPECIFIC_PROVENANCE" in markdown
    for required in (
        "Execution record integrity | **VERIFIED**",
        "Cryptographic signature | **NOT_AVAILABLE**",
        "Issuer authentication | **UNVERIFIED**",
        "Actor authenticity | **UNVERIFIED**",
        "Attestation boundary | **UNSIGNED**",
        "Numerical fidelity | **NOT_CHECKED**",
        "Security | **NOT_CHECKED**",
        "Runtime behavior | **NOT_CHECKED**",
    ):
        assert required in markdown
    attestation_path = tmp_path / "attestation.json"
    report_path = tmp_path / "report.json"
    attestation_path.write_text(pretty_json(transformation), encoding="utf-8")
    report_path.write_text(pretty_json(envelope), encoding="utf-8")
    assert verify_attestation(attestation_path) == transformation
    assert verify_attestation_report(report_path, attestation_path) == envelope
    tampered = envelope.model_dump(mode="json", by_alias=True)
    tampered["report"]["authenticity"] = "DECLARED"
    report_body = dict(tampered["report"])
    report_body.pop("report_digest")
    tampered["report"]["report_digest"] = canonical_sha256(report_body)
    tampered["integrity"]["digest"] = tampered["report"]["report_digest"]
    report_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(OmivInputError, match="does not reconstruct"):
        verify_attestation_report(report_path, attestation_path)


def test_tamper_detection(transformation: ArtifactAttestation, tmp_path: Path) -> None:
    raw = transformation.model_dump(mode="json", by_alias=True)
    raw["claim_details"]["relationship"] = "tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(OmivInputError, match="attestation (identity|digest)"):
        load_attestation(path)


def test_cli_exit_codes(tmp_path: Path) -> None:
    runner = CliRunner()
    declared_input = tmp_path / "declared-input.json"
    declared_input.write_text(pretty_json(synthetic_declared_acquisition_input()), encoding="utf-8")
    declared_output = tmp_path / "declared.json"
    result = runner.invoke(
        app,
        [
            "attestation",
            "create",
            "--input",
            str(declared_input),
            "--output",
            str(declared_output),
            "--report-output",
            str(tmp_path / "declared.report.json"),
            "--markdown-output",
            str(tmp_path / "declared.report.md"),
        ],
    )
    assert result.exit_code == 1
    transformation_input = tmp_path / "transformation-input.json"
    transformation_input.write_text(pretty_json(synthetic_transformation_input()), encoding="utf-8")
    transformation_output = tmp_path / "transformation.json"
    result = runner.invoke(
        app,
        [
            "attestation",
            "create",
            "--input",
            str(transformation_input),
            "--output",
            str(transformation_output),
            "--report-output",
            str(tmp_path / "transformation.report.json"),
            "--markdown-output",
            str(tmp_path / "transformation.report.md"),
        ],
    )
    assert result.exit_code == 0
    assert (
        runner.invoke(
            app, ["attestation", "verify", "--input", str(transformation_output)]
        ).exit_code
        == 0
    )
    show = runner.invoke(app, ["attestation", "show", "--input", str(transformation_output)])
    assert show.exit_code == 0
    assert "Trust" not in show.stdout or "not a cryptographic signature" in show.stdout
    broken = tmp_path / "broken.json"
    raw = json.loads(transformation_output.read_text(encoding="utf-8"))
    raw["attestation_digest"] = "f" * 64
    broken.write_text(json.dumps(raw), encoding="utf-8")
    assert runner.invoke(app, ["attestation", "verify", "--input", str(broken)]).exit_code == 2


@pytest.mark.parametrize("package", ["attestations", "custody", "passport"])
def test_core_has_no_kimi_dependency(package: str) -> None:
    root = ROOT / "src/omiv" / package
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "omiv.model_packs.kimi_k3" not in text


def test_generic_origins_and_artifact_without_model_pack() -> None:
    for origin in ("local_file", "s3", "oci", "internal_registry", "air_gapped"):
        artifact = artifact_reference(
            origin_type=origin,
            variant=f"{origin}-variant",
            format_name="onnx" if origin == "oci" else "safetensors",
            content_digest=canonical_sha256({"origin": origin}),
        )
        assert artifact.origin_type == origin
        assert not hasattr(artifact, "model_pack")


def test_no_false_signed_payload_security_or_runtime_claim(
    transformation: ArtifactAttestation,
) -> None:
    text = pretty_json(transformation) + render_attestation_markdown(
        build_attestation_report(transformation)
    )
    for forbidden in (
        "SIGNER VERIFIED",
        "PAYLOAD VERIFIED",
        "SECURITY PASSED",
        "RUNTIME VERIFIED",
        "/home/",
        "/tmp/",
        "github.com/200lz",
    ):
        assert forbidden not in text


@pytest.mark.parametrize(
    "name,authenticity,provenance",
    [
        ("synthetic_local_acquisition", "DECLARED", "DECLARED_PROVENANCE"),
        (
            "synthetic_evidence_linked_acquisition",
            "EVIDENCE_LINKED",
            "EVIDENCE_LINKED_PROVENANCE",
        ),
        (
            "synthetic_transformation",
            "EXECUTION_VERIFIED",
            "ARTIFACT_SPECIFIC_PROVENANCE",
        ),
        (
            "synthetic_quantization",
            "EXECUTION_VERIFIED",
            "ARTIFACT_SPECIFIC_PROVENANCE",
        ),
    ],
)
def test_generated_attestations_and_reports_verify(
    name: str, authenticity: str, provenance: str
) -> None:
    attestation_path = EXAMPLES / f"{name}.attestation.json"
    report_path = REPORTS / f"{name}.attestation.report.json"
    value = verify_attestation(attestation_path)
    assert value.authenticity.value == authenticity
    assert value.verification_summary.provenance_strength.value == provenance
    assert verify_attestation_report(report_path, attestation_path).report.attestation_id == (
        value.attestation_id
    )


@pytest.mark.parametrize(
    "name,event_type",
    [
        ("synthetic_local_acquisition", CustodyEventType.ARTIFACT_ACQUISITION_RECORDED),
        ("synthetic_transformation", CustodyEventType.TRANSFORMATION_RECORDED),
        ("synthetic_quantization", CustodyEventType.QUANTIZATION_RECORDED),
    ],
)
def test_generated_attestation_custody_segments_verify(
    name: str, event_type: CustodyEventType
) -> None:
    value = verify_attestation_custody_segment(
        ROOT / "custody/examples" / f"{name}.custody-ledger.json", ROOT
    )
    assert value.events[0].event_type == event_type
    assert value.events[0].previous_event_digest is None
    assert value.signed_event_count == 0
    assert value.unattested_event_count == 1
    assert value.lifecycle_completeness.value == "INCOMPLETE"
    assert value.genesis_semantics == "PORTABLE_SEGMENT_BEGINNING"


def test_portable_segments_cannot_be_concatenated() -> None:
    path = ROOT / "custody/examples/synthetic_transformation.custody-ledger.json"
    value = verify_attestation_custody_segment(path, ROOT)
    raw = value.model_dump(mode="json", by_alias=True)
    raw["events"].append(raw["events"][0])
    raw["event_count"] = 2
    with pytest.raises(ValidationError, match="exactly one"):
        type(value).model_validate(raw)


def test_kimi_gap_report_and_existing_artifacts_unchanged() -> None:
    passport = ROOT / "passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json"
    gap = verify_gap_report(REPORTS / "kimi_k3_attestation_gap.report.json", passport, ROOT)
    assert gap.acquisition_attestation == "UNAVAILABLE"
    assert gap.transformation_attestation == "UNAVAILABLE"
    assert gap.quantization_attestation == "UNAVAILABLE"
    assert gap.artifact_specific_provenance == "UNAVAILABLE"
    expected = {
        "passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json": (
            "2a2d48a43b5ac21d194e8ebab076a37497d3e49260becd40e70b616d7803a77b"
        ),
        "passports/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.passport.json": (
            "3cfc2049dda8de4ed34fefedfe22bfad741029c1358247e4ebcd1ab87f406b58"
        ),
        "passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport-with-custody.json": (
            "a96d9007bf1111435ae81cb711ed19bd015c5db8270a300bbb9678ddec47feb1"
        ),
        "passports/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.passport-with-custody.json": (
            "025f0ab9cfb611ae43423905713009a3f2c0712a5f71a48e0cf27026fc0445eb"
        ),
        "custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json": (
            "1feb7ab3d358b21b9e2b0765dd6cd61cd883d9311a43e0ad86956f669011839c"
        ),
        "custody/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.custody-ledger.json": (
            "6ab02739ead1c61cacdf3d922a14775418950effb42e0ef99c62ff6d1bafa7b8"
        ),
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == digest
    for ledger_path in (ROOT / "custody").glob("*.custody-ledger.json"):
        ledger = load_custody_ledger(ledger_path)
        assert all(
            event.event_type
            not in {
                CustodyEventType.ARTIFACT_ACQUISITION_RECORDED,
                CustodyEventType.TRANSFORMATION_RECORDED,
                CustodyEventType.QUANTIZATION_RECORDED,
            }
            for event in ledger.events
        )


def test_gap_report_is_analysis_only_and_non_materializable(tmp_path: Path) -> None:
    gap = REPORTS / "kimi_k3_attestation_gap.report.json"
    raw = json.loads(gap.read_text(encoding="utf-8"))
    with pytest.raises(ValidationError):
        ArtifactAttestationInput.model_validate(raw)
    with pytest.raises(OmivInputError):
        verify_attestation(gap)
    evidence = included_evidence("acquisition_record", raw)
    evidence_raw = evidence.model_dump(mode="json", by_alias=True)
    evidence_raw["schema"] = "omiv.artifact-attestation-gap-report.v1"
    with pytest.raises(ValidationError, match="analysis-only"):
        type(evidence).model_validate(evidence_raw)
    result = CliRunner().invoke(
        app,
        [
            "attestation",
            "append-custody",
            "--attestation",
            str(gap),
            "--ledger",
            str(IQ_LEDGER),
            "--output",
            str(tmp_path / "out.json"),
            "--root",
            str(ROOT),
        ],
    )
    assert result.exit_code == 2


def test_backward_compatible_passport_attestation_summary(
    declared: ArtifactAttestation, transformation: ArtifactAttestation
) -> None:
    declared_summary = summarize_attestations(declared.subject, [declared])
    assert declared_summary.acquisition_attestation == PassportAttestationState.DECLARED
    assert declared_summary.payload_status == "NOT_CHECKED"
    execution_summary = summarize_attestations(transformation.subject, [transformation])
    assert (
        execution_summary.transformation_attestation == PassportAttestationState.EXECUTION_VERIFIED
    )
    assert execution_summary.security_status == execution_summary.runtime_status == "NOT_CHECKED"
    assert execution_summary.approval_status == "NOT_CHECKED"
    assert execution_summary.signature_status == "NOT_AVAILABLE"
    assert execution_summary.issuer_authentication == "UNVERIFIED"
    assert execution_summary.actor_authenticity == "UNVERIFIED"
    with pytest.raises(OmivInputError, match="does not match"):
        summarize_attestations(declared.subject, [transformation])
