import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from omiv.comparison.engine import (
    build_structural_comparison,
    compare_encoded_spans,
    compare_shapes,
    compare_tensor_identities,
    compare_type_transitions,
)
from omiv.comparison.models import (
    ComparisonArtifact,
    ComparisonProfileOutcome,
    EvidenceBoundaryStatus,
    StructuralComparisonInventory,
    TypeTransitionState,
)
from omiv.comparison.policy import (
    comparison_profile_policy,
    evaluate_comparison_profiles,
    structural_comparison_policy,
)
from omiv.comparison.reporting import (
    build_comparison_report,
    load_comparison_inventory,
    render_comparison_markdown,
)
from omiv.errors import OmivInputError

ROOT = Path(__file__).parents[1]
PREFIX = "unsloth_Kimi-K3-GGUF_UD-IQ1_M"
VALIDATION = ROOT / f"validations/{PREFIX}.validation.inventory.json"
SPLIT = ROOT / f"inventories/remote/{PREFIX}.split.inventory.json"
ONTOLOGY = ROOT / f"inventories/remote/{PREFIX}.kimi-k3-ontology.inventory.json"
MAPPING = ROOT / f"inventories/remote/{PREFIX}.semantic-mapping.inventory.json"


def _view(
    *,
    family: str = "output_norm",
    physical: list[int] | None = None,
    normalized: list[int] | None = None,
    ggml_type: str = "F32",
    encoded_bytes: int = 100,
    sensitive: bool = True,
) -> dict[str, object]:
    return {
        "name": "output_norm.weight",
        "family": family,
        "layer": None,
        "physical_shape": physical or [8],
        "normalized_shape": normalized or [8],
        "type": ggml_type,
        "encoded_bytes": encoded_bytes,
        "span_status": "bounded",
        "sensitive_f32": sensitive,
        "module": "model",
    }


def test_identity_shape_and_type_comparison() -> None:
    baseline = {"output_norm.weight": _view()}
    candidate = {"output_norm.weight": _view()}
    identities = compare_tensor_identities(
        baseline,
        candidate,
        duplicate_baseline_count=0,
        duplicate_candidate_count=0,
        cap=5,
    )
    shapes = compare_shapes(baseline, candidate, 5)
    transitions = compare_type_transitions(baseline, candidate)
    assert identities.matched_count == 1
    assert shapes.normalized_shape_equal_count == 1
    assert transitions.state_counts[TypeTransitionState.KEPT_UNQUANTIZED] == 1
    assert transitions.disallowed_count == 0


def test_allowed_matrix_transition_and_sensitive_vector_rejection() -> None:
    baseline = {
        "x": _view(
            family="attn_output",
            ggml_type="IQ1_S",
            sensitive=False,
        )
    }
    candidate = {
        "x": _view(
            family="attn_output",
            ggml_type="Q4_K",
            sensitive=False,
        )
    }
    result = compare_type_transitions(baseline, candidate)
    assert result.state_counts[TypeTransitionState.QUANTIZATION_FAMILY_CHANGED] == 1
    assert result.allowed_count == 1

    candidate["x"] = _view(ggml_type="Q4_K", sensitive=True)
    result = compare_type_transitions({"x": _view()}, candidate)
    assert result.disallowed_count == 1

    candidate["x"] = _view(
        family="attn_output",
        ggml_type="UNKNOWN_Q",
        sensitive=False,
    )
    result = compare_type_transitions(baseline, candidate)
    assert result.state_counts[TypeTransitionState.UNSUPPORTED] == 1


def test_mxfp4_transition_is_limited_to_packed_expert_families() -> None:
    for family in ("moe.packed_gate", "moe.packed_up", "moe.packed_down"):
        baseline = {
            "x": _view(
                family=family,
                ggml_type="IQ1_S",
                sensitive=False,
            )
        }
        candidate = {
            "x": _view(
                family=family,
                ggml_type="MXFP4",
                sensitive=False,
            )
        }
        result = compare_type_transitions(baseline, candidate)
        assert result.allowed_count == 1
        assert result.family_transitions[0].policy_rule == (
            f"family_target_type_allowlist:{family}"
        )

    baseline = {
        "x": _view(
            family="moe.shared_gate",
            ggml_type="Q8_0",
            sensitive=False,
        )
    }
    candidate = {
        "x": _view(
            family="moe.shared_gate",
            ggml_type="MXFP4",
            sensitive=False,
        )
    }
    assert compare_type_transitions(baseline, candidate).disallowed_count == 1


def test_directional_exact_span_ratio() -> None:
    class Summary:
        bounded_count = 1
        overlap_count = 0

    class Inventory:
        payload_span_summary = Summary()

    class Split:
        inventory = Inventory()

    baseline = {"x": _view(encoded_bytes=3)}
    candidate = {"x": _view(encoded_bytes=5)}
    result = compare_encoded_spans(baseline, candidate, Split(), Split())
    assert (result.ratio_numerator, result.ratio_denominator) == (5, 3)


def test_profile_policy_and_full_equivalence_boundary() -> None:
    policy = comparison_profile_policy()
    controls = {
        control: True
        for profile in policy.profiles
        for control in [*profile.required_controls, *profile.warning_controls]
    }
    for control in (
        "artifact_specific_provenance_available",
        "payload_equality_checked",
        "quantization_fidelity_checked",
        "tokenizer_parity_checked",
        "runtime_parity_checked",
    ):
        controls[control] = False
    results = {
        item.profile_name: item
        for item in evaluate_comparison_profiles(
            controls, {"cross_quantization_structural_comparison"}, policy
        )
    }
    assert results["structural_equivalence"].outcome == (
        ComparisonProfileOutcome.SATISFIED_WITH_WARNINGS
    )
    assert results["full_numerical_equivalence"].outcome == (ComparisonProfileOutcome.NOT_SATISFIED)
    assert structural_comparison_policy() == structural_comparison_policy()


@pytest.fixture(scope="module")
def real_comparison() -> StructuralComparisonInventory:
    return build_structural_comparison(
        root=ROOT,
        baseline_validation_path=VALIDATION,
        candidate_validation_path=VALIDATION,
        baseline_split_path=SPLIT,
        candidate_split_path=SPLIT,
        baseline_ontology_path=ONTOLOGY,
        candidate_ontology_path=ONTOLOGY,
        baseline_mapping_path=MAPPING,
        candidate_mapping_path=MAPPING,
        selected_profile="structural_equivalence",
    )


def test_real_verified_evidence_is_deterministic(
    real_comparison: StructuralComparisonInventory,
) -> None:
    rebuilt = build_structural_comparison(
        root=ROOT,
        baseline_validation_path=VALIDATION,
        candidate_validation_path=VALIDATION,
        baseline_split_path=SPLIT,
        candidate_split_path=SPLIT,
        baseline_ontology_path=ONTOLOGY,
        candidate_ontology_path=ONTOLOGY,
        baseline_mapping_path=MAPPING,
        candidate_mapping_path=MAPPING,
        selected_profile="structural_equivalence",
    )
    assert rebuilt == real_comparison
    assert real_comparison.payload_equality == EvidenceBoundaryStatus.NOT_CHECKED
    assert real_comparison.runtime_parity == EvidenceBoundaryStatus.NOT_CHECKED
    assert real_comparison.tensor_identity_comparison.matched_count == 2573


def test_inventory_and_report_tamper_detection(
    real_comparison: StructuralComparisonInventory, tmp_path: Path
) -> None:
    data = real_comparison.model_dump(mode="json")
    data["candidate"]["resolved_revision"] = "f" * 40
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(OmivInputError, match="digest mismatch"):
        load_comparison_inventory(path)

    report = build_comparison_report(real_comparison)
    markdown = render_comparison_markdown(report)
    assert "Payload equality: not checked" in markdown
    assert "comparative model quality" in markdown


def test_unknown_inventory_field_rejected(
    real_comparison: StructuralComparisonInventory,
) -> None:
    data = real_comparison.model_dump(mode="json")
    data["timestamp"] = "forbidden"
    with pytest.raises(ValidationError, match="Extra inputs"):
        StructuralComparisonInventory.model_validate(data)


def test_artifact_index_rejects_absolute_path() -> None:
    with pytest.raises(ValidationError, match="repository-relative POSIX"):
        ComparisonArtifact(
            role="bad",
            schema_id="synthetic",
            relative_path="/tmp/local.json",
            digest="0" * 64,
            size_bytes=1,
            required=True,
            verification_command="omiv verify",
        )
