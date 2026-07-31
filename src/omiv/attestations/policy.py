"""Static trusted policy for generic artifact attestations."""

from __future__ import annotations

from omiv.attestations.models import (
    ArtifactAttestationPolicy,
    AttestationAssertionOrigin,
    AttestationKind,
    ClaimType,
)
from omiv.canonical import canonical_sha256


def attestation_policy() -> ArtifactAttestationPolicy:
    body = {
        "schema": "omiv.artifact-attestation-policy.v1",
        "supported_kinds": sorted(item.value for item in AttestationKind),
        "supported_claim_types": sorted(item.value for item in ClaimType),
        "allowed_assertion_origins": sorted(
            item.value
            for item in AttestationAssertionOrigin
            if item != AttestationAssertionOrigin.SIGNED_ATTESTATION_RESERVED
        ),
        "required_artifact_roles": {
            "ACQUISITION": ["source", "destination"],
            "QUANTIZATION": ["input", "output"],
            "TRANSFER": ["source", "destination"],
            "TRANSFORMATION": ["input", "output"],
        },
        "evidence_link_rules": {
            "full": "all claim-relevant evidence reconstructs from included or local evidence",
            "digest_only": "digest identity is known but evidence was not reconstructed",
            "false_full_verification": "reject",
        },
        "authenticity_rules": {
            "DERIVED_FROM_VERIFIED_EVIDENCE": "EVIDENCE_LINKED",
            "IMPORTED_ATTESTATION": "UNVERIFIED unless evidence reconstructs",
            "SYSTEM_OBSERVED": "requires system-observation evidence",
            "USER_DECLARED": "DECLARED",
            "VERIFIED_EXECUTION_RECORD": "requires a verified successful execution record",
        },
        "execution_verification_requirements": [
            "successful execution result",
            "canonical tool identity",
            "canonical command identity",
            "canonical configuration identity",
            "exact ordered input and output artifact identities",
            "fully verified execution evidence",
        ],
        "artifact_continuity_rules": [
            "transfers preserve immutable artifact identity",
            "acquisition source and destination changes require explicit custody context",
            "transformations require explicit ordered inputs and outputs",
            "quantization is an explicit transformation relation",
            "structural similarity alone is not artifact-specific provenance",
        ],
        "custody_event_mapping": {
            "ACQUISITION": "ARTIFACT_ACQUISITION_RECORDED",
            "QUANTIZATION": "QUANTIZATION_RECORDED",
            "TRANSFER": "CONDITIONAL_ARTIFACT_ACQUISITION_RECORDED",
            "TRANSFORMATION": "TRANSFORMATION_RECORDED",
        },
        "materialization_eligibility": {
            "ACQUISITION": "eligible as an explicitly qualified recorded claim",
            "TRANSFER": (
                "eligible only with fully verified new-custody-boundary entry evidence, "
                "verified destination identity, valid source/destination continuity, and "
                "satisfied acquisition-event requirements"
            ),
            "TRANSFORMATION": "eligible with valid explicit input/output relation",
            "QUANTIZATION": "eligible with valid explicit quantization relation",
            "same_boundary_transfer": "not eligible",
        },
        "forbidden_trust_escalations": [
            "attestation integrity to issuer authenticity",
            "digest linkage to full evidence verification",
            "execution linkage to numerical correctness",
            "execution linkage to security or runtime verification",
            "unsigned record to signed authenticity",
        ],
        "sensitive_field_restrictions": [
            "absolute paths",
            "credentials",
            "hostnames",
            "raw command lines",
            "raw environment variables",
            "signed URLs",
            "timestamps",
            "usernames",
            "UUIDs",
        ],
        "deterministic_ordering": [
            "artifact identity digest",
            "evidence role then digest",
            "finding identifier",
            "policy digest",
        ],
    }
    return ArtifactAttestationPolicy.model_validate(
        {**body, "policy_digest": canonical_sha256(body)}
    )
