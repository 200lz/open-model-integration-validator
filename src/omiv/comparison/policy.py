"""Static trusted policies for structural artifact comparison."""

from omiv.canonical import canonical_sha256
from omiv.comparison.models import (
    ComparisonProfile,
    ComparisonProfileOutcome,
    ComparisonProfilePolicy,
    ComparisonProfileResult,
    IdentityPolicyClass,
    StructuralComparisonPolicy,
)


def structural_comparison_policy() -> StructuralComparisonPolicy:
    identity_classes = {
        "provider": IdentityPolicyClass.REQUIRED_EQUAL,
        "repository": IdentityPolicyClass.REQUIRED_EQUAL,
        "repository_type": IdentityPolicyClass.REQUIRED_EQUAL,
        "requested_revision": IdentityPolicyClass.INFORMATIONAL,
        "resolved_revision": IdentityPolicyClass.REQUIRED_EQUAL,
        "selection": IdentityPolicyClass.ALLOWED_DIFFERENT,
        "model_family": IdentityPolicyClass.REQUIRED_EQUAL,
        "architecture": IdentityPolicyClass.REQUIRED_EQUAL,
        "model_pack_version": IdentityPolicyClass.REQUIRED_EQUAL,
        "model_pack_digest": IdentityPolicyClass.REQUIRED_EQUAL,
        "ontology_policy_digest": IdentityPolicyClass.REQUIRED_EQUAL,
        "mapping_policy_digest": IdentityPolicyClass.REQUIRED_EQUAL,
        "converter_evidence_revision": IdentityPolicyClass.REQUIRED_EQUAL,
    }
    data = {
        "schema_id": "omiv.structural-comparison-policy.v1",
        "policy_id": "cross-quantization-structural-v1",
        "policy_version": 1,
        "identity_classes": {key: value.value for key, value in sorted(identity_classes.items())},
        "required_normalized_shape_equality": True,
        "require_sensitive_f32_unchanged": True,
        "allow_quantized_matrix_type_change": True,
        "allowed_quantized_target_types": [
            "IQ1_S",
            "IQ2_XXS",
            "IQ3_XXS",
            "Q4_K",
            "Q8_0",
        ],
        "family_allowed_target_types": {
            "moe.packed_down": ["MXFP4"],
            "moe.packed_gate": ["MXFP4"],
            "moe.packed_up": ["MXFP4"],
        },
        "allow_shard_layout_change": True,
        "maximum_difference_examples": 20,
    }
    return StructuralComparisonPolicy(
        schema_id="omiv.structural-comparison-policy.v1",
        policy_id="cross-quantization-structural-v1",
        policy_version=1,
        identity_classes=identity_classes,
        required_normalized_shape_equality=True,
        require_sensitive_f32_unchanged=True,
        allow_quantized_matrix_type_change=True,
        allowed_quantized_target_types=[
            "IQ1_S",
            "IQ2_XXS",
            "IQ3_XXS",
            "Q4_K",
            "Q8_0",
        ],
        family_allowed_target_types={
            "moe.packed_down": ["MXFP4"],
            "moe.packed_gate": ["MXFP4"],
            "moe.packed_up": ["MXFP4"],
        },
        allow_shard_layout_change=True,
        maximum_difference_examples=20,
        policy_digest=canonical_sha256(data),
    )


def comparison_profile_policy() -> ComparisonProfilePolicy:
    profiles = [
        ComparisonProfile(
            name="structural_equivalence",
            required_controls=[
                "identity_compatible",
                "same_immutable_revision",
                "tensor_identities_equal",
                "normalized_shapes_equal",
                "type_transitions_allowed",
                "ontology_structure_equivalent",
                "mapping_structure_equivalent",
                "spans_valid",
            ],
            warning_controls=["artifact_specific_provenance_available"],
            required_evidence_checked=["cross_quantization_structural_comparison"],
        ),
        ComparisonProfile(
            name="quantization_layout_comparison",
            required_controls=[
                "identity_compatible",
                "tensor_identities_equal",
                "normalized_shapes_equal",
                "type_transitions_allowed",
                "spans_valid",
            ],
            warning_controls=[],
            required_evidence_checked=["cross_quantization_structural_comparison"],
        ),
        ComparisonProfile(
            name="release_variant_consistency",
            required_controls=[
                "identity_compatible",
                "same_immutable_revision",
                "tensor_identities_equal",
                "ontology_structure_equivalent",
                "mapping_structure_equivalent",
                "source_accounting_equal",
                "target_accounting_equal",
            ],
            warning_controls=["artifact_specific_provenance_available"],
            required_evidence_checked=["cross_quantization_structural_comparison"],
        ),
        ComparisonProfile(
            name="full_numerical_equivalence",
            required_controls=[
                "identity_compatible",
                "same_immutable_revision",
                "tensor_identities_equal",
                "normalized_shapes_equal",
                "ontology_structure_equivalent",
                "mapping_structure_equivalent",
                "payload_equality_checked",
                "quantization_fidelity_checked",
                "tokenizer_parity_checked",
                "runtime_parity_checked",
                "artifact_specific_provenance_available",
            ],
            warning_controls=[],
            required_evidence_checked=[
                "cross_quantization_structural_comparison",
                "payload_equality",
                "quantization_numerical_fidelity",
                "tokenizer_parity",
                "runtime_parity",
            ],
        ),
    ]
    data = {
        "schema_id": "omiv.structural-comparison-profile-policy.v1",
        "profiles": [item.model_dump(mode="json") for item in profiles],
    }
    return ComparisonProfilePolicy(
        profiles=profiles,
        policy_digest=canonical_sha256(data),
    )


def evaluate_comparison_profiles(
    controls: dict[str, bool],
    checked_evidence: set[str],
    policy: ComparisonProfilePolicy,
) -> list[ComparisonProfileResult]:
    results = []
    for profile in policy.profiles:
        failed = sorted(
            [control for control in profile.required_controls if not controls.get(control, False)]
            + [
                evidence
                for evidence in profile.required_evidence_checked
                if evidence not in checked_evidence
            ]
        )
        warnings = sorted(
            control for control in profile.warning_controls if not controls.get(control, False)
        )
        outcome = (
            ComparisonProfileOutcome.NOT_SATISFIED
            if failed
            else ComparisonProfileOutcome.SATISFIED_WITH_WARNINGS
            if warnings
            else ComparisonProfileOutcome.SATISFIED
        )
        results.append(
            ComparisonProfileResult(
                profile_name=profile.name,
                outcome=outcome,
                satisfied=not failed,
                warning_controls=warnings,
                failed_controls=failed,
            )
        )
    return results
