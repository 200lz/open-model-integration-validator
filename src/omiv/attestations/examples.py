"""Compact deterministic examples for generic, non-model-pack attestations."""

from __future__ import annotations

from typing import Any

from omiv.attestations.builder import (
    build_command_identity,
    build_configuration_identity,
    build_execution_record,
    build_tool_identity,
)
from omiv.attestations.models import (
    AcquisitionMethod,
    ArtifactAttestationInput,
    AttestationAssertionOrigin,
    AttestationEvidenceReference,
    AttestationKind,
    ClaimType,
    EnvironmentIdentity,
    ExecutionResult,
    IdentityStatus,
    IssuerReference,
    IssuerStatus,
    LocationReference,
    QuantizationSpecification,
    ToolExecutionRecordInput,
    TransformationKind,
)
from omiv.canonical import canonical_sha256
from omiv.custody.models import ArtifactReference
from omiv.passport.models import EvidenceAvailability, ReferenceVerificationMode


def artifact_reference(
    *,
    origin_type: str,
    variant: str,
    format_name: str,
    content_digest: str,
    repository: str | None = None,
    resolved_revision: str | None = None,
) -> ArtifactReference:
    body: dict[str, Any] = {
        "origin_type": origin_type,
        "provider": "synthetic.example" if repository else None,
        "repository": repository,
        "repository_type": "model" if repository else None,
        "resolved_revision": resolved_revision,
        "selection": variant,
        "artifact_set_digest": content_digest,
        "content_digest": content_digest,
        "format": format_name,
        "architecture": "generic-transformer",
        "variant": variant,
        "file_count": 1,
        "total_declared_bytes": 4096,
        "passport_id": None,
        "passport_digest": None,
        "validation_inventory_digest": None,
    }
    identity = dict(body)
    identity.pop("passport_id")
    identity.pop("passport_digest")
    identity.pop("validation_inventory_digest")
    return ArtifactReference.model_validate({**body, "identity_digest": canonical_sha256(identity)})


def included_evidence(role: str, payload: Any) -> AttestationEvidenceReference:
    return AttestationEvidenceReference(
        role=role,
        schema=f"omiv.synthetic-{role}.v1",
        digest=canonical_sha256(payload),
        availability=EvidenceAvailability.INCLUDED,
        verification_mode=ReferenceVerificationMode.FULL_VERIFICATION,
        finding_ids=[],
        policy_digests=[],
        source_phase="5C-synthetic",
        claim_scope=[f"synthetic {role.replace('_', ' ')} identity"],
        included_payload=payload,
    )


def unavailable_environment() -> EnvironmentIdentity:
    return EnvironmentIdentity(status=IdentityStatus.UNAVAILABLE)


def synthetic_environment() -> EnvironmentIdentity:
    payload = {
        "environment_kind": "synthetic_container",
        "runtime_identity": "synthetic-runtime-v1",
        "architecture_identity": "generic-64",
    }
    evidence = included_evidence("environment_identity", payload)
    return EnvironmentIdentity(
        status=IdentityStatus.EVIDENCE_LINKED,
        environment_kind="synthetic_container",
        environment_digest=canonical_sha256(payload),
        container_image_digest=canonical_sha256({"image": "synthetic-converter-v1"}),
        runtime_identity="synthetic-runtime-v1",
        architecture_identity="generic-64",
        dependency_lock_digest=canonical_sha256({"dependencies": ["synthetic-core-v1"]}),
        evidence_references=[evidence],
    )


def synthetic_declared_acquisition_input() -> ArtifactAttestationInput:
    digest = canonical_sha256({"synthetic_artifact": "local-acquisition-v1"})
    source = artifact_reference(
        origin_type="huggingface",
        repository="example/synthetic-model",
        resolved_revision="1" * 40,
        variant="base",
        format_name="safetensors",
        content_digest=digest,
    )
    destination = artifact_reference(
        origin_type="local_file",
        variant="base",
        format_name="safetensors",
        content_digest=digest,
    )
    return ArtifactAttestationInput(
        attestation_kind=AttestationKind.ACQUISITION,
        claim_type=ClaimType.ARTIFACT_OBTAINED,
        subject=destination,
        inputs=[source],
        outputs=[destination],
        source_location=LocationReference(
            location_kind="huggingface", stable_location_id="example/synthetic-model@revision"
        ),
        destination_location=LocationReference(
            location_kind="local", stable_location_id="synthetic-local-custody-context"
        ),
        acquisition_method=AcquisitionMethod.DOWNLOAD,
        issuer=IssuerReference(issuer_status=IssuerStatus.UNAVAILABLE),
        assertion_origin=AttestationAssertionOrigin.USER_DECLARED,
        environment_identity=unavailable_environment(),
        evidence_references=[],
        claim_details={
            "action": "artifact obtained",
            "payload_equality": "NOT_CHECKED",
            "transfer_observation": "USER_DECLARED",
        },
        limitations=[
            "The acquisition action is user-declared and not independently observed.",
            "Payload equality was not checked.",
        ],
        warnings=["Remote inspection and source location alone are not acquisition evidence."],
    )


def synthetic_evidence_acquisition_input() -> ArtifactAttestationInput:
    base = synthetic_declared_acquisition_input()
    payload = {
        "source_identity_digest": base.inputs[0].identity_digest,
        "destination_identity_digest": base.outputs[0].identity_digest,
        "content_digest": base.inputs[0].content_digest,
        "transfer_record": "synthetic-copy-record-v1",
    }
    return base.model_copy(
        update={
            "assertion_origin": AttestationAssertionOrigin.DERIVED_FROM_VERIFIED_EVIDENCE,
            "evidence_references": [included_evidence("acquisition_record", payload)],
            "claim_details": {
                "action": "artifact obtained",
                "payload_equality": "DIGEST_MATCH_VERIFIED",
                "transfer_observation": "EVIDENCE_LINKED",
            },
            "limitations": [
                "The synthetic digest evidence links source and destination identities.",
                "No issuer signature or actor authentication is present.",
            ],
        }
    )


def _execution_attestation(*, quantization: bool) -> ArtifactAttestationInput:
    input_digest = canonical_sha256(
        {"synthetic_artifact": "unquantized-v1" if quantization else "source-v1"}
    )
    output_digest = canonical_sha256(
        {"synthetic_artifact": "quantized-v1" if quantization else "converted-v1"}
    )
    source = artifact_reference(
        origin_type="internal_registry",
        repository="synthetic/source-model",
        resolved_revision="2" * 40,
        variant="source",
        format_name="safetensors",
        content_digest=input_digest,
    )
    output = artifact_reference(
        origin_type="internal_registry",
        repository="synthetic/output-model",
        resolved_revision="3" * 40,
        variant="quantized" if quantization else "converted",
        format_name="gguf",
        content_digest=output_digest,
    )
    tool = build_tool_identity("synthetic-converter", tool_version="1.0", tool_revision="4" * 40)
    parameters: dict[str, Any] = {
        "architecture": "generic-transformer",
        "output_format": "gguf",
        "tensor_mapping_policy": "synthetic-mapping-v1",
    }
    if quantization:
        parameters.update(
            {
                "quantization_family": "generic-block",
                "target_type_policy": "generic-q4",
                "mixed_precision": {"output_head": "f16"},
            }
        )
    configuration = build_configuration_identity(
        "omiv.synthetic-conversion-configuration.v1", parameters
    )
    command = build_command_identity(
        "synthetic-converter",
        [
            "--input-identity",
            source.identity_digest,
            "--output-identity",
            output.identity_digest,
            "--configuration-digest",
            configuration.configuration_digest,
        ],
    )
    environment = synthetic_environment()
    execution_payload = {
        "tool_identity_digest": tool.tool_identity_digest,
        "configuration_digest": configuration.configuration_digest,
        "input_identity": source.identity_digest,
        "output_identity": output.identity_digest,
        "result": "SUCCEEDED",
    }
    execution_evidence = included_evidence("execution_evidence", execution_payload)
    record_input = ToolExecutionRecordInput(
        tool_identity=tool,
        command_identity=command,
        configuration_identity=configuration,
        environment_identity=environment,
        input_artifacts=[source],
        output_artifacts=[output],
        execution_result=ExecutionResult.SUCCEEDED,
        evidence_references=[execution_evidence],
        limitations=[
            "Execution-record consistency does not establish output semantic correctness."
        ],
    )
    record = build_execution_record(record_input)
    structural = included_evidence(
        "structural_validation",
        {
            "output_identity": output.identity_digest,
            "format": "gguf",
            "structure": "VALID",
        },
    )
    mapping = included_evidence(
        "mapping_evidence",
        {
            "input_identity": source.identity_digest,
            "output_identity": output.identity_digest,
            "mapping_policy": "synthetic-mapping-v1",
        },
    )
    quantization_spec = None
    if quantization:
        quantization_spec = QuantizationSpecification(
            quantization_family="generic-block",
            target_type_policy="generic-q4",
            block_size=32,
            mixed_precision_policy={"output_head": "f16"},
            excluded_tensor_classes=["normalization", "output_head"],
        )
    return ArtifactAttestationInput(
        attestation_kind=(
            AttestationKind.QUANTIZATION if quantization else AttestationKind.TRANSFORMATION
        ),
        claim_type=(ClaimType.ARTIFACT_QUANTIZED if quantization else ClaimType.ARTIFACT_CONVERTED),
        subject=output,
        inputs=[source],
        outputs=[output],
        transformation_kind=(
            TransformationKind.QUANTIZATION
            if quantization
            else TransformationKind.FORMAT_CONVERSION
        ),
        quantization=quantization_spec,
        issuer=IssuerReference(issuer_status=IssuerStatus.UNAVAILABLE),
        assertion_origin=AttestationAssertionOrigin.VERIFIED_EXECUTION_RECORD,
        tool_identity=tool,
        command_identity=command,
        configuration_identity=configuration,
        environment_identity=environment,
        evidence_references=[execution_evidence, structural, mapping],
        execution_record=record,
        claim_details={
            "relationship": "explicit input/tool/configuration/output linkage",
            "payload_correctness": "NOT_CHECKED",
            "runtime": "NOT_CHECKED",
            "structural_relation": "VERIFIED",
        },
        limitations=[
            "Numerical fidelity was not checked.",
            "Payload correctness was not checked.",
            "Runtime compatibility was not checked.",
            "The execution record is unsigned and does not authenticate an issuer.",
        ],
    )


def synthetic_transformation_input() -> ArtifactAttestationInput:
    return _execution_attestation(quantization=False)


def synthetic_quantization_input() -> ArtifactAttestationInput:
    return _execution_attestation(quantization=True)
