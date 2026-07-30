"""Generic deterministic structural comparison engine."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any, cast

from omiv.canonical import canonical_sha256
from omiv.comparison.models import (
    ComparisonArtifact,
    ComparisonFinding,
    ComparisonSubject,
    ComparisonValueStatus,
    EncodedSpanComparison,
    EvidenceBoundaryStatus,
    FamilyTypeTransition,
    IdentityFieldResult,
    IdentityPolicyClass,
    MappingComparison,
    MetadataComparison,
    MetadataDifference,
    OntologyComparison,
    OverallComparisonResult,
    RepositoryComparison,
    ShapeComparison,
    StructuralComparisonInventory,
    TensorIdentityComparison,
    TypeTransitionComparison,
    TypeTransitionState,
    ValidationComparison,
)
from omiv.comparison.policy import (
    comparison_profile_policy,
    evaluate_comparison_profiles,
    structural_comparison_policy,
)
from omiv.errors import OmivInputError
from omiv.mapping.grouped_reporting import load_mapping_inventory
from omiv.model_packs.kimi_k3.gguf_ontology import (
    KimiK3GGUFOntologyPolicy,
    parse_gguf_name,
)
from omiv.model_packs.kimi_k3.gguf_reporting import (
    load_ontology_inventory,
    ontology_inventory_links_split,
)
from omiv.remote.header_reporting import load_header_inventory
from omiv.remote.split_reporting import load_split_inventory
from omiv.validation.reporting import verify_validation_inventory


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OmivInputError(message)


def _exact_ratio(numerator: int, denominator: int) -> tuple[int, int, str]:
    _require(denominator > 0, "ratio denominator must be positive")
    divisor = math.gcd(numerator, denominator)
    reduced_numerator = numerator // divisor
    reduced_denominator = denominator // divisor
    with localcontext() as context:
        context.prec = 40
        decimal = format(
            Decimal(reduced_numerator) / Decimal(reduced_denominator),
            ".12f",
        )
    return reduced_numerator, reduced_denominator, decimal


def _mapping_digest(mapping: Any) -> str:
    data = mapping.model_dump(mode="json", by_alias=True)
    stored = data.pop("inventory_digest", None)
    observed = canonical_sha256(data)
    _require(stored == observed, "semantic-mapping inventory digest mismatch")
    return observed


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise OmivInputError(f"comparison artifact is outside repository root: {path}") from exc


def _validation_entry_path(validation: Any, root: Path, role: str) -> Path:
    matches = [item for item in validation.artifact_index.entries if item.role == role]
    _require(len(matches) == 1, f"validation artifact index lacks unique role {role!r}")
    return root / cast(str, matches[0].relative_path)


def _metadata_header(validation: Any, root: Path) -> Any:
    return load_header_inventory(
        _validation_entry_path(validation, root, "shard_01_header_inventory")
    )


def _identity_values(validation: Any, split: Any, ontology: Any, mapping: Any) -> dict[str, Any]:
    return {
        "provider": validation.repository_identity.provider,
        "repository": validation.repository_identity.repository,
        "repository_type": split.inventory.repository.repo_type,
        "requested_revision": validation.repository_identity.requested_revision,
        "resolved_revision": validation.repository_identity.resolved_revision,
        "selection": validation.repository_identity.selection,
        "model_family": validation.subject.model_family,
        "architecture": validation.architecture_summary["architecture"],
        "model_pack_version": validation.model_pack_identity.version,
        "model_pack_digest": validation.model_pack_identity.digest,
        "ontology_policy_digest": ontology.inventory.ontology_policy_digest,
        "mapping_policy_digest": mapping.mapping_policy_digest,
        "converter_evidence_revision": mapping.converter_evidence_revision,
    }


def _identity_comparison(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> list[IdentityFieldResult]:
    policy = structural_comparison_policy()
    results = []
    for field, policy_class in sorted(policy.identity_classes.items()):
        left = baseline.get(field)
        right = candidate.get(field)
        if left == right:
            status = ComparisonValueStatus.EQUAL
        elif policy_class == IdentityPolicyClass.ALLOWED_DIFFERENT:
            status = ComparisonValueStatus.DIFFERENT_ALLOWED
        elif policy_class == IdentityPolicyClass.INFORMATIONAL:
            status = ComparisonValueStatus.INFORMATIONAL
        else:
            status = ComparisonValueStatus.DIFFERENT_UNEXPECTED
        results.append(
            IdentityFieldResult(
                field=field,
                policy_class=policy_class,
                baseline_value=left,
                candidate_value=right,
                status=status,
            )
        )
    return results


REQUIRED_METADATA = {
    "general.architecture",
    "kimi-k3.block_count",
    "kimi-k3.embedding_length",
    "kimi-k3.attention.head_count",
    "kimi-k3.attention.head_count_kv",
    "kimi-k3.expert_count",
    "kimi-k3.expert_used_count",
    "kimi-k3.expert_shared_count",
    "kimi-k3.expert_feed_forward_length",
    "kimi-k3.expert_latent_length",
    "kimi-k3.leading_dense_block_count",
    "kimi-k3.attn_res.block_size",
}


def _metadata_category(key: str) -> str:
    if key in REQUIRED_METADATA:
        return "required_equal"
    if key in {"general.file_type", "general.quantization_version"} or key.startswith(
        "quantize.imatrix."
    ):
        return "allowed_quantization_specific"
    if key in {
        "general.name",
        "general.basename",
        "general.size_label",
        "general.quantized_by",
    }:
        return "allowed_variant_specific"
    if key.endswith("repo_url") or key.startswith("split."):
        return "allowed_repository_specific"
    return "informational"


def compare_metadata(baseline_header: Any, candidate_header: Any, cap: int) -> MetadataComparison:
    baseline = {item.key: item for item in baseline_header.inventory.metadata}
    candidate = {item.key: item for item in candidate_header.inventory.metadata}
    details: list[MetadataDifference] = []
    counts: Counter[str] = Counter()
    all_details: list[dict[str, Any]] = []
    for key in sorted(set(baseline) | set(candidate)):
        left = baseline.get(key)
        right = candidate.get(key)
        category = _metadata_category(key)
        if left is None:
            status = ComparisonValueStatus.MISSING_BASELINE
        elif right is None:
            status = ComparisonValueStatus.MISSING_CANDIDATE
        elif left.encoded_sha256 == right.encoded_sha256:
            status = ComparisonValueStatus.EQUAL
        elif category == "required_equal":
            status = ComparisonValueStatus.DIFFERENT_UNEXPECTED
        elif category == "informational":
            status = ComparisonValueStatus.INFORMATIONAL
        else:
            status = ComparisonValueStatus.DIFFERENT_ALLOWED
        counts[status.value] += 1
        if status != ComparisonValueStatus.EQUAL:
            detail = MetadataDifference(
                key=key,
                category=category,
                status=status,
                baseline_digest=None if left is None else left.encoded_sha256,
                candidate_digest=None if right is None else right.encoded_sha256,
            )
            all_details.append(detail.model_dump(mode="json"))
            if len(details) < cap:
                details.append(detail)
    return MetadataComparison(
        compared_key_count=len(set(baseline) | set(candidate)),
        equal_count=counts[ComparisonValueStatus.EQUAL.value],
        different_allowed_count=counts[ComparisonValueStatus.DIFFERENT_ALLOWED.value],
        different_unexpected_count=counts[ComparisonValueStatus.DIFFERENT_UNEXPECTED.value],
        missing_baseline_count=counts[ComparisonValueStatus.MISSING_BASELINE.value],
        missing_candidate_count=counts[ComparisonValueStatus.MISSING_CANDIDATE.value],
        difference_digest=canonical_sha256(all_details),
        differences=details,
    )


def _tensor_views(split: Any) -> dict[str, dict[str, Any]]:
    ontology_policy = KimiK3GGUFOntologyPolicy()
    rules = {item.family_id: item for item in ontology_policy.family_rules}
    result: dict[str, dict[str, Any]] = {}
    for tensor in split.inventory.tensors:
        parsed = parse_gguf_name(tensor.name, ontology_policy)
        rule = None if parsed.family_id is None else rules.get(parsed.family_id)
        result[tensor.name] = {
            "name": tensor.name,
            "family": parsed.family_id or "<unclassified>",
            "layer": parsed.layer_id,
            "physical_shape": list(tensor.dimensions),
            "normalized_shape": (
                list(tensor.dimensions)
                if rule is None
                else rule.normalized_dimensions(list(tensor.dimensions))
            ),
            "type": tensor.ggml_type_name,
            "encoded_bytes": tensor.payload_span.encoded_byte_length,
            "span_status": str(tensor.payload_span.status),
            "sensitive_f32": (rule is not None and rule.allowed_ggml_types == ["F32"]),
            "module": None if rule is None else rule.module,
        }
    return result


def compare_tensor_identities(
    baseline: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    *,
    duplicate_baseline_count: int,
    duplicate_candidate_count: int,
    cap: int,
) -> TensorIdentityComparison:
    left = set(baseline)
    right = set(candidate)
    baseline_only = sorted(left - right)
    candidate_only = sorted(right - left)
    common = left & right
    baseline_families = Counter(baseline[name]["family"] for name in left)
    candidate_families = Counter(candidate[name]["family"] for name in right)
    baseline_layers = Counter(baseline[name]["layer"] for name in left)
    candidate_layers = Counter(candidate[name]["layer"] for name in right)
    baseline_components = Counter(
        (baseline[name]["layer"], baseline[name]["family"]) for name in left
    )
    candidate_components = Counter(
        (candidate[name]["layer"], candidate[name]["family"]) for name in right
    )
    return TensorIdentityComparison(
        baseline_count=len(left),
        candidate_count=len(right),
        matched_count=len(common),
        baseline_only_count=len(baseline_only),
        candidate_only_count=len(candidate_only),
        duplicate_baseline_count=duplicate_baseline_count,
        duplicate_candidate_count=duplicate_candidate_count,
        baseline_only_digest=canonical_sha256(baseline_only),
        candidate_only_digest=canonical_sha256(candidate_only),
        baseline_only_examples=baseline_only[:cap],
        candidate_only_examples=candidate_only[:cap],
        family_counts_equal=baseline_families == candidate_families,
        layer_coverage_equal=baseline_layers == candidate_layers,
        component_coverage_equal=baseline_components == candidate_components,
    )


def compare_shapes(
    baseline: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    cap: int,
) -> ShapeComparison:
    normalized_equal = 0
    physical_equal = 0
    physical_different_logical_equal = 0
    incompatible: list[str] = []
    unavailable = 0
    details: list[dict[str, Any]] = []
    for name in sorted(set(baseline) & set(candidate)):
        left = baseline[name]
        right = candidate[name]
        if not left["normalized_shape"] or not right["normalized_shape"]:
            unavailable += 1
            continue
        if left["normalized_shape"] == right["normalized_shape"]:
            normalized_equal += 1
            if left["physical_shape"] == right["physical_shape"]:
                physical_equal += 1
            else:
                physical_different_logical_equal += 1
                details.append(
                    {
                        "name": name,
                        "baseline": left["physical_shape"],
                        "candidate": right["physical_shape"],
                        "normalized": left["normalized_shape"],
                    }
                )
        else:
            incompatible.append(name)
            details.append(
                {
                    "name": name,
                    "baseline_normalized": left["normalized_shape"],
                    "candidate_normalized": right["normalized_shape"],
                }
            )
    return ShapeComparison(
        matched_count=len(set(baseline) & set(candidate)),
        normalized_shape_equal_count=normalized_equal,
        physical_shape_equal_count=physical_equal,
        physical_different_logically_equal_count=physical_different_logical_equal,
        incompatible_count=len(incompatible),
        unavailable_count=unavailable,
        difference_digest=canonical_sha256(details),
        incompatible_examples=incompatible[:cap],
    )


def _transition(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> tuple[TypeTransitionState, bool, str]:
    policy = structural_comparison_policy()
    left = baseline["type"]
    right = candidate["type"]
    if baseline["family"] == "<unclassified>" or candidate["family"] == "<unclassified>":
        return TypeTransitionState.INCOMPARABLE, False, "classified_family_required"
    if baseline["sensitive_f32"]:
        if left == right == "F32":
            return TypeTransitionState.KEPT_UNQUANTIZED, True, "sensitive_f32_unchanged"
        return TypeTransitionState.UNSUPPORTED, False, "sensitive_f32_unchanged"
    if left == right:
        return TypeTransitionState.UNCHANGED, True, "quantized_matrix_unchanged"
    if right == "F32":
        return (
            TypeTransitionState.UNEXPECTED_UNQUANTIZED,
            False,
            "quantized_matrix_change_only",
        )
    family_allowed = policy.family_allowed_target_types.get(
        candidate["family"], []
    )
    if (
        right not in policy.allowed_quantized_target_types
        and right not in family_allowed
    ):
        return TypeTransitionState.UNSUPPORTED, False, "known_quantized_target_type"
    if right in family_allowed:
        return (
            TypeTransitionState.QUANTIZATION_FAMILY_CHANGED,
            True,
            f"family_target_type_allowlist:{candidate['family']}",
        )
    return (
        TypeTransitionState.QUANTIZATION_FAMILY_CHANGED,
        True,
        "family_aware_quantized_matrix_change",
    )


def compare_type_transitions(
    baseline: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
) -> TypeTransitionComparison:
    grouped: Counter[tuple[str, str, str, str, bool, str]] = Counter()
    states: Counter[TypeTransitionState] = Counter()
    allowed = 0
    disallowed = 0
    for name in sorted(set(baseline) & set(candidate)):
        left = baseline[name]
        right = candidate[name]
        state, permitted, rule = _transition(left, right)
        states[state] += 1
        if permitted:
            allowed += 1
        else:
            disallowed += 1
        grouped[
            (
                left["family"],
                left["type"],
                right["type"],
                state.value,
                permitted,
                rule,
            )
        ] += 1
    family_transitions = [
        FamilyTypeTransition(
            family_id=key[0],
            baseline_type=key[1],
            candidate_type=key[2],
            state=TypeTransitionState(key[3]),
            allowed=key[4],
            count=count,
            policy_rule=key[5],
            evidence_limitation="structural type allowance is not numerical quality evidence",
        )
        for key, count in sorted(grouped.items())
    ]
    return TypeTransitionComparison(
        matched_count=len(set(baseline) & set(candidate)),
        state_counts={state: states[state] for state in TypeTransitionState},
        allowed_count=allowed,
        disallowed_count=disallowed,
        transition_digest=canonical_sha256(
            [item.model_dump(mode="json") for item in family_transitions]
        ),
        family_transitions=family_transitions,
    )


def compare_encoded_spans(
    baseline: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    baseline_split: Any,
    candidate_split: Any,
) -> EncodedSpanComparison:
    baseline_total = sum(int(item["encoded_bytes"] or 0) for item in baseline.values())
    candidate_total = sum(int(item["encoded_bytes"] or 0) for item in candidate.values())
    denominator = baseline_total or 1
    divisor = math.gcd(candidate_total, denominator)
    family_baseline: defaultdict[str, int] = defaultdict(int)
    family_candidate: defaultdict[str, int] = defaultdict(int)
    for item in baseline.values():
        family_baseline[item["family"]] += int(item["encoded_bytes"] or 0)
    for item in candidate.values():
        family_candidate[item["family"]] += int(item["encoded_bytes"] or 0)
    family_totals: list[dict[str, Any]] = [
        {
            "family_id": family,
            "baseline_encoded_bytes": family_baseline[family],
            "candidate_encoded_bytes": family_candidate[family],
        }
        for family in sorted(set(family_baseline) | set(family_candidate))
    ]
    return EncodedSpanComparison(
        baseline_total_encoded_bytes=baseline_total,
        candidate_total_encoded_bytes=candidate_total,
        ratio_numerator=candidate_total // divisor,
        ratio_denominator=denominator // divisor,
        baseline_bounded_count=baseline_split.inventory.payload_span_summary.bounded_count,
        candidate_bounded_count=candidate_split.inventory.payload_span_summary.bounded_count,
        baseline_overlap_count=baseline_split.inventory.payload_span_summary.overlap_count,
        candidate_overlap_count=candidate_split.inventory.payload_span_summary.overlap_count,
        family_totals_digest=canonical_sha256(family_totals),
        family_totals=family_totals,
    )


def _ontology_structure(ontology: Any) -> dict[str, Any]:
    inventory = ontology.inventory
    families = [
        {
            "family_id": item.family_id,
            "scope": item.scope,
            "physical_kind": item.physical_kind,
            "module": item.module,
            "expected_count": item.expected_count,
            "observed_count": item.observed_count,
            "expected_layer_ids": item.expected_layer_ids,
            "observed_layer_ids": item.observed_layer_ids,
            "shape_summaries": [
                {
                    "normalized_dimensions": shape.normalized_dimensions,
                    "dimension_roles": shape.dimension_roles,
                    "shape_relation": shape.shape_relation,
                    "observation_count": shape.observation_count,
                }
                for shape in item.shape_summaries
            ],
            "coverage_valid": item.coverage_valid,
            "shape_valid": item.shape_valid,
        }
        for item in inventory.family_summaries
    ]
    return {
        "architecture": inventory.architecture_metadata.architecture_identifier,
        "schedule": inventory.schedule.model_dump(mode="json"),
        "families": families,
        "classification": {
            key: value
            for key, value in inventory.classification.model_dump(mode="json").items()
            if key not in {"invalid_details", "unclassified_details"}
        },
    }


def compare_ontology(baseline: Any, candidate: Any) -> OntologyComparison:
    left = _ontology_structure(baseline)
    right = _ontology_structure(candidate)
    left_families = {item["family_id"]: item for item in left["families"]}
    right_families = {item["family_id"]: item for item in right["families"]}
    family_set_equal = set(left_families) == set(right_families)
    family_coverage_equal = family_set_equal and all(
        left_families[key]["observed_count"] == right_families[key]["observed_count"]
        and left_families[key]["observed_layer_ids"] == right_families[key]["observed_layer_ids"]
        for key in left_families
    )
    shape_equal = family_set_equal and all(
        left_families[key]["shape_summaries"] == right_families[key]["shape_summaries"]
        for key in left_families
    )
    classification_equal = (
        left["classification"]["total_tensor_count"]
        == right["classification"]["total_tensor_count"]
        and left["classification"]["classified_count"]
        == right["classification"]["classified_count"]
        and left["classification"]["intentionally_unclassified_count"]
        == right["classification"]["intentionally_unclassified_count"]
        and left["classification"]["invalid_count"] == right["classification"]["invalid_count"]
    )
    architecture_equal = left["architecture"] == right["architecture"]
    schedule_equal = left["schedule"] == right["schedule"]
    candidate_type_valid = all(item.type_valid for item in candidate.inventory.family_summaries)
    structure_equivalent = (
        architecture_equal
        and schedule_equal
        and family_set_equal
        and family_coverage_equal
        and classification_equal
        and shape_equal
    )
    return OntologyComparison(
        architecture_equal=architecture_equal,
        layer_schedule_equal=schedule_equal,
        family_set_equal=family_set_equal,
        family_coverage_equal=family_coverage_equal,
        classification_accounting_equal=classification_equal,
        normalized_shape_signatures_equal=shape_equal,
        baseline_type_valid=all(item.type_valid for item in baseline.inventory.family_summaries),
        candidate_type_valid_under_native_policy=candidate_type_valid,
        structure_equivalent=structure_equivalent,
        difference_digest=canonical_sha256({"baseline": left, "candidate": right}),
    )


def _mapping_structure(mapping: Any) -> dict[str, Any]:
    signatures = Counter(
        (
            item.rule_id,
            item.relation.value,
            item.source_physical_count,
            item.target_count,
            tuple(item.target_names),
            tuple(tuple(shape) for shape in item.target_shapes),
        )
        for item in mapping.mapping_results
    )
    return {
        "signatures": sorted((list(key), count) for key, count in signatures.items()),
        "source_accounting": mapping.source_accounting["states"],
        "target_accounting": mapping.target_accounting["states"],
        "coverage": {
            key: mapping.coverage[key]
            for key in (
                "direct",
                "routed",
                "shared_experts",
                "router",
                "latent_moe",
                "dense",
                "norms",
                "attention_output",
                "kda",
                "mla",
                "fused",
                "logical",
                "g_proj",
                "model_level_direct",
            )
        },
    }


def compare_mapping(baseline: Any, candidate: Any) -> MappingComparison:
    left = _mapping_structure(baseline)
    right = _mapping_structure(candidate)
    coverage_equal = left["coverage"] == right["coverage"]
    signatures_equal = left["signatures"] == right["signatures"]
    source_equal = left["source_accounting"] == right["source_accounting"]
    target_equal = left["target_accounting"] == right["target_accounting"]
    duplicates_equal = (
        baseline.coverage["duplicates"] == candidate.coverage["duplicates"]
        and baseline.coverage["ambiguities"] == candidate.coverage["ambiguities"]
    )
    return MappingComparison(
        same_source_inventory=(
            baseline.source["inventory_sha256"] == candidate.source["inventory_sha256"]
        ),
        source_accounting_equal=source_equal,
        target_accounting_structure_equal=target_equal,
        mapping_rule_identities_equal=signatures_equal,
        routed_cardinality_equal=(baseline.coverage["routed"] == candidate.coverage["routed"]),
        shared_mapping_equal=(
            baseline.coverage["shared_experts"] == candidate.coverage["shared_experts"]
        ),
        direct_mapping_equal=(baseline.coverage["direct"] == candidate.coverage["direct"]),
        fused_mapping_equal=(baseline.coverage["fused"] == candidate.coverage["fused"]),
        logical_realization_equal=(baseline.coverage["logical"] == candidate.coverage["logical"]),
        converter_revision_equal=(
            baseline.converter_evidence_revision == candidate.converter_evidence_revision
        ),
        duplicate_and_ambiguity_counts_equal=duplicates_equal,
        structure_equivalent=(
            coverage_equal
            and signatures_equal
            and source_equal
            and target_equal
            and duplicates_equal
        ),
        difference_digest=canonical_sha256({"baseline": left, "candidate": right}),
    )


def _stage_map(validation: Any) -> dict[str, str]:
    return {item.stage.value: item.status.value for item in validation.evidence_stages}


def _profile_map(validation: Any) -> dict[str, str]:
    return {item.profile_name: item.outcome.value for item in validation.profile_results}


def compare_validation(baseline: Any, candidate: Any) -> ValidationComparison:
    left_stages = _stage_map(baseline)
    right_stages = _stage_map(candidate)
    return ValidationComparison(
        evidence_stage_statuses_equal=left_stages == right_stages,
        acceptance_profile_outcomes_equal=(_profile_map(baseline) == _profile_map(candidate)),
        unavailable_stages_equal=(
            sorted(key for key, value in left_stages.items() if value == "UNAVAILABLE")
            == sorted(key for key, value in right_stages.items() if value == "UNAVAILABLE")
        ),
        not_checked_stages_equal=(
            sorted(key for key, value in left_stages.items() if value == "NOT_CHECKED")
            == sorted(key for key, value in right_stages.items() if value == "NOT_CHECKED")
        ),
        model_pack_identity_equal=(baseline.model_pack_identity == candidate.model_pack_identity),
        evidence_graphs_independently_valid=True,
        baseline_artifact_count=len(baseline.artifact_index.entries),
        candidate_artifact_count=len(candidate.artifact_index.entries),
    )


def _artifact(
    root: Path, role: str, path: Path, schema: str, digest: str, command: str
) -> ComparisonArtifact:
    return ComparisonArtifact(
        role=role,
        schema_id=schema,
        relative_path=_relative(root, path),
        digest=digest,
        size_bytes=path.stat().st_size,
        required=True,
        verification_command=command,
    )


def build_structural_comparison(
    *,
    root: Path,
    baseline_validation_path: Path,
    candidate_validation_path: Path,
    baseline_split_path: Path,
    candidate_split_path: Path,
    baseline_ontology_path: Path,
    candidate_ontology_path: Path,
    baseline_mapping_path: Path,
    candidate_mapping_path: Path,
    selected_profile: str,
) -> StructuralComparisonInventory:
    root = root.resolve()
    baseline_validation = verify_validation_inventory(baseline_validation_path, root)
    candidate_validation = verify_validation_inventory(candidate_validation_path, root)
    baseline_split = load_split_inventory(baseline_split_path)
    candidate_split = load_split_inventory(candidate_split_path)
    baseline_ontology = load_ontology_inventory(baseline_ontology_path)
    candidate_ontology = load_ontology_inventory(candidate_ontology_path)
    _require(
        ontology_inventory_links_split(baseline_ontology, baseline_split),
        "baseline ontology does not link its split inventory",
    )
    _require(
        ontology_inventory_links_split(candidate_ontology, candidate_split),
        "candidate ontology does not link its split inventory",
    )
    baseline_mapping = load_mapping_inventory(baseline_mapping_path)
    candidate_mapping = load_mapping_inventory(candidate_mapping_path)
    baseline_mapping_digest = _mapping_digest(baseline_mapping)
    candidate_mapping_digest = _mapping_digest(candidate_mapping)
    _require(
        baseline_mapping.target["split_inventory_sha256"] == baseline_split.integrity.sha256
        and candidate_mapping.target["split_inventory_sha256"] == candidate_split.integrity.sha256,
        "mapping split linkage mismatch",
    )
    _require(
        baseline_mapping.target["ontology_inventory_sha256"] == baseline_ontology.integrity.sha256
        and candidate_mapping.target["ontology_inventory_sha256"]
        == candidate_ontology.integrity.sha256,
        "mapping ontology linkage mismatch",
    )
    policy = structural_comparison_policy()
    profiles = comparison_profile_policy()
    _require(
        selected_profile in {item.name for item in profiles.profiles},
        f"unknown comparison profile: {selected_profile}",
    )

    left_identity = _identity_values(
        baseline_validation, baseline_split, baseline_ontology, baseline_mapping
    )
    right_identity = _identity_values(
        candidate_validation, candidate_split, candidate_ontology, candidate_mapping
    )
    identity = _identity_comparison(left_identity, right_identity)
    identity_compatible = all(
        item.status == ComparisonValueStatus.EQUAL
        for item in identity
        if item.policy_class == IdentityPolicyClass.REQUIRED_EQUAL
    )
    repository_ratio_numerator, repository_ratio_denominator, repository_ratio_decimal = (
        _exact_ratio(
            candidate_split.inventory.total_repository_bytes,
            baseline_split.inventory.total_repository_bytes,
        )
    )
    repository = RepositoryComparison(
        same_provider=(
            baseline_validation.repository_identity.provider
            == candidate_validation.repository_identity.provider
        ),
        same_repository=(
            baseline_validation.repository_identity.repository
            == candidate_validation.repository_identity.repository
        ),
        same_immutable_revision=(
            baseline_validation.repository_identity.resolved_revision
            == candidate_validation.repository_identity.resolved_revision
        ),
        revision_status=(
            ComparisonValueStatus.EQUAL
            if baseline_validation.repository_identity.resolved_revision
            == candidate_validation.repository_identity.resolved_revision
            else ComparisonValueStatus.DIFFERENT_UNEXPECTED
        ),
        baseline_shards=baseline_split.inventory.shard_count,
        candidate_shards=candidate_split.inventory.shard_count,
        shard_layout_status=(
            ComparisonValueStatus.EQUAL
            if [
                (item.filename_ordinal, item.file_size)
                for item in baseline_split.inventory.shard_summaries
            ]
            == [
                (item.filename_ordinal, item.file_size)
                for item in candidate_split.inventory.shard_summaries
            ]
            else ComparisonValueStatus.DIFFERENT_ALLOWED
        ),
        baseline_total_bytes=baseline_split.inventory.total_repository_bytes,
        candidate_total_bytes=candidate_split.inventory.total_repository_bytes,
        ratio_numerator_reduced=repository_ratio_numerator,
        ratio_denominator_reduced=repository_ratio_denominator,
        deterministic_decimal=repository_ratio_decimal,
        baseline_header_bytes=baseline_split.inventory.total_header_bytes_accepted,
        candidate_header_bytes=candidate_split.inventory.total_header_bytes_accepted,
        baseline_range_requests=baseline_split.inventory.total_request_count + 1,
        candidate_range_requests=candidate_split.inventory.total_request_count + 1,
        baseline_metadata_only_shards=sum(
            item.tensor_count == 0 for item in baseline_split.inventory.shard_summaries
        ),
        candidate_metadata_only_shards=sum(
            item.tensor_count == 0 for item in candidate_split.inventory.shard_summaries
        ),
        baseline_tensor_bearing_shards=sum(
            item.tensor_count > 0 for item in baseline_split.inventory.shard_summaries
        ),
        candidate_tensor_bearing_shards=sum(
            item.tensor_count > 0 for item in candidate_split.inventory.shard_summaries
        ),
        baseline_payload_bytes_accepted=0,
        candidate_payload_bytes_accepted=0,
    )
    metadata = compare_metadata(
        _metadata_header(baseline_validation, root),
        _metadata_header(candidate_validation, root),
        policy.maximum_difference_examples,
    )
    baseline_tensors = _tensor_views(baseline_split)
    candidate_tensors = _tensor_views(candidate_split)
    tensor_identity = compare_tensor_identities(
        baseline_tensors,
        candidate_tensors,
        duplicate_baseline_count=(
            baseline_split.inventory.duplicate_summary.exact_duplicate_count
            + baseline_split.inventory.duplicate_summary.conflict_count
        ),
        duplicate_candidate_count=(
            candidate_split.inventory.duplicate_summary.exact_duplicate_count
            + candidate_split.inventory.duplicate_summary.conflict_count
        ),
        cap=policy.maximum_difference_examples,
    )
    shapes = compare_shapes(baseline_tensors, candidate_tensors, policy.maximum_difference_examples)
    transitions = compare_type_transitions(baseline_tensors, candidate_tensors)
    spans = compare_encoded_spans(
        baseline_tensors, candidate_tensors, baseline_split, candidate_split
    )
    ontology = compare_ontology(baseline_ontology, candidate_ontology)
    mapping = compare_mapping(baseline_mapping, candidate_mapping)
    validation = compare_validation(baseline_validation, candidate_validation)
    provenance_available = all(
        value != "UNAVAILABLE"
        for value in (
            _stage_map(baseline_validation).get("artifact_specific_provenance"),
            _stage_map(candidate_validation).get("artifact_specific_provenance"),
        )
    )
    controls = {
        "identity_compatible": identity_compatible,
        "same_immutable_revision": repository.same_immutable_revision,
        "tensor_identities_equal": (
            tensor_identity.baseline_only_count == 0
            and tensor_identity.candidate_only_count == 0
            and tensor_identity.duplicate_baseline_count == 0
            and tensor_identity.duplicate_candidate_count == 0
        ),
        "normalized_shapes_equal": (
            shapes.incompatible_count == 0
            and shapes.unavailable_count == 0
            and shapes.normalized_shape_equal_count == shapes.matched_count
        ),
        "type_transitions_allowed": transitions.disallowed_count == 0,
        "ontology_structure_equivalent": ontology.structure_equivalent,
        "mapping_structure_equivalent": mapping.structure_equivalent,
        "source_accounting_equal": mapping.source_accounting_equal,
        "target_accounting_equal": mapping.target_accounting_structure_equal,
        "spans_valid": (
            spans.baseline_bounded_count == tensor_identity.baseline_count
            and spans.candidate_bounded_count == tensor_identity.candidate_count
            and spans.baseline_overlap_count == 0
            and spans.candidate_overlap_count == 0
        ),
        "artifact_specific_provenance_available": provenance_available,
        "payload_equality_checked": False,
        "quantization_fidelity_checked": False,
        "tokenizer_parity_checked": False,
        "runtime_parity_checked": False,
    }
    checked = {"cross_quantization_structural_comparison"}
    profile_results = evaluate_comparison_profiles(controls, checked, profiles)
    structural_controls = {
        "identity_compatible",
        "same_immutable_revision",
        "tensor_identities_equal",
        "normalized_shapes_equal",
        "type_transitions_allowed",
        "ontology_structure_equivalent",
        "mapping_structure_equivalent",
        "spans_valid",
    }
    if all(controls[item] for item in structural_controls):
        overall = (
            OverallComparisonResult.STRUCTURALLY_EQUIVALENT_WITH_QUANTIZATION_DIFFERENCES
            if any(
                item.state == TypeTransitionState.QUANTIZATION_FAMILY_CHANGED
                for item in transitions.family_transitions
            )
            else OverallComparisonResult.STRUCTURAL_EQUIVALENCE_WITH_LIMITATIONS
        )
    elif identity_compatible:
        overall = OverallComparisonResult.STRUCTURALLY_DIFFERENT
    else:
        overall = OverallComparisonResult.INCOMPARABLE

    baseline_subject = ComparisonSubject(
        role="baseline",
        model_family=baseline_validation.subject.model_family,
        variant=baseline_validation.subject.artifact_variant,
        provider=baseline_validation.repository_identity.provider,
        repository=baseline_validation.repository_identity.repository,
        requested_revision=baseline_validation.repository_identity.requested_revision,
        resolved_revision=baseline_validation.repository_identity.resolved_revision,
        validation_inventory_digest=baseline_validation.inventory_digest,
        split_inventory_digest=baseline_split.integrity.sha256,
        ontology_inventory_digest=baseline_ontology.integrity.sha256,
        mapping_inventory_digest=baseline_mapping_digest,
    )
    candidate_subject = ComparisonSubject(
        role="candidate",
        model_family=candidate_validation.subject.model_family,
        variant=candidate_validation.subject.artifact_variant,
        provider=candidate_validation.repository_identity.provider,
        repository=candidate_validation.repository_identity.repository,
        requested_revision=candidate_validation.repository_identity.requested_revision,
        resolved_revision=candidate_validation.repository_identity.resolved_revision,
        validation_inventory_digest=candidate_validation.inventory_digest,
        split_inventory_digest=candidate_split.integrity.sha256,
        ontology_inventory_digest=candidate_ontology.integrity.sha256,
        mapping_inventory_digest=candidate_mapping_digest,
    )
    inputs = [
        (
            "baseline_validation",
            baseline_validation_path,
            baseline_validation.schema_id,
            baseline_validation.inventory_digest,
            "omiv independent-validation-inventory-verify --input",
        ),
        (
            "candidate_validation",
            candidate_validation_path,
            candidate_validation.schema_id,
            candidate_validation.inventory_digest,
            "omiv independent-validation-inventory-verify --input",
        ),
        (
            "baseline_split",
            baseline_split_path,
            baseline_split.inventory.inventory_schema,
            baseline_split.integrity.sha256,
            "omiv remote-split-inventory-verify --input",
        ),
        (
            "candidate_split",
            candidate_split_path,
            candidate_split.inventory.inventory_schema,
            candidate_split.integrity.sha256,
            "omiv remote-split-inventory-verify --input",
        ),
        (
            "baseline_ontology",
            baseline_ontology_path,
            baseline_ontology.inventory.inventory_schema,
            baseline_ontology.integrity.sha256,
            "omiv kimi-k3-gguf-ontology-inventory-verify --input",
        ),
        (
            "candidate_ontology",
            candidate_ontology_path,
            candidate_ontology.inventory.inventory_schema,
            candidate_ontology.integrity.sha256,
            "omiv kimi-k3-gguf-ontology-inventory-verify --input",
        ),
        (
            "baseline_mapping",
            baseline_mapping_path,
            baseline_mapping.inventory_schema,
            baseline_mapping_digest,
            "omiv kimi-k3-semantic-mapping-inventory-verify --input",
        ),
        (
            "candidate_mapping",
            candidate_mapping_path,
            candidate_mapping.inventory_schema,
            candidate_mapping_digest,
            "omiv kimi-k3-semantic-mapping-inventory-verify --input",
        ),
    ]
    artifacts = sorted(
        [
            _artifact(
                root,
                role,
                path,
                schema,
                digest,
                f"{command} {_relative(root, path)}",
            )
            for role, path, schema, digest, command in inputs
        ],
        key=lambda item: item.role,
    )
    artifact_index_digest = canonical_sha256([item.model_dump(mode="json") for item in artifacts])

    def finding(finding_id: str, passed: bool, summary: str, **evidence: Any) -> ComparisonFinding:
        return ComparisonFinding(
            finding_id=finding_id,
            status="PASS" if passed else "FAIL",
            summary=summary,
            evidence=evidence,
        )

    findings = [
        finding("COMPARE-001", True, "Baseline evidence verifies."),
        finding("COMPARE-002", True, "Candidate evidence verifies."),
        finding("COMPARE-003", repository.same_repository, "Repository identities are compatible."),
        finding(
            "COMPARE-004", repository.same_immutable_revision, "Immutable revisions are compatible."
        ),
        finding("COMPARE-005", ontology.architecture_equal, "Architecture metadata is equivalent."),
        finding(
            "COMPARE-006",
            controls["tensor_identities_equal"],
            "Tensor identity sets are equivalent.",
        ),
        finding(
            "COMPARE-007", controls["normalized_shapes_equal"], "Normalized shapes are equivalent."
        ),
        finding(
            "COMPARE-008",
            tensor_identity.family_counts_equal and tensor_identity.layer_coverage_equal,
            "Layer and family coverage is equivalent.",
        ),
        finding(
            "COMPARE-009", controls["spans_valid"], "Both split layouts are structurally valid."
        ),
        finding(
            "COMPARE-010",
            transitions.matched_count == tensor_identity.matched_count,
            "GGML transitions are classified.",
        ),
        finding(
            "COMPARE-011",
            controls["type_transitions_allowed"],
            "Type transitions are allowed by structural policy.",
        ),
        finding(
            "COMPARE-012", ontology.structure_equivalent, "Ontology structures are equivalent."
        ),
        finding(
            "COMPARE-013",
            mapping.structure_equivalent,
            "Semantic-mapping structures are equivalent.",
        ),
        finding("COMPARE-014", mapping.source_accounting_equal, "Source accounting is equivalent."),
        finding(
            "COMPARE-015",
            mapping.target_accounting_structure_equal,
            "Target logical accounting is equivalent.",
        ),
        finding("COMPARE-016", controls["spans_valid"], "Encoded spans are structurally valid."),
        finding("COMPARE-017", True, "Acceptance profiles were reconstructed."),
        ComparisonFinding(
            finding_id="COMPARE-018",
            status="NOT_CHECKED",
            summary="Payload equality was not checked.",
        ),
        ComparisonFinding(
            finding_id="COMPARE-019",
            status="NOT_CHECKED",
            summary="Quantization numerical fidelity was not checked.",
        ),
        ComparisonFinding(
            finding_id="COMPARE-020",
            status="NOT_CHECKED",
            summary="Runtime parity was not checked.",
        ),
        finding("COMPARE-021", True, "Comparison uses deterministic canonical serialization."),
    ]
    preliminary: dict[str, Any] = {
        "baseline": baseline_subject,
        "candidate": candidate_subject,
        "policy": policy,
        "profile_policy": profiles,
        "identity_comparison": identity,
        "repository_comparison": repository,
        "metadata_comparison": metadata,
        "tensor_identity_comparison": tensor_identity,
        "shape_comparison": shapes,
        "type_transition_comparison": transitions,
        "encoded_span_comparison": spans,
        "ontology_comparison": ontology,
        "mapping_comparison": mapping,
        "validation_comparison": validation,
        "controls": controls,
        "profile_results": profile_results,
        "selected_profile": selected_profile,
        "overall_result": overall,
        "cross_quantization_structural_comparison": EvidenceBoundaryStatus.CHECKED,
        "payload_equality": EvidenceBoundaryStatus.NOT_CHECKED,
        "quantization_numerical_fidelity": EvidenceBoundaryStatus.NOT_CHECKED,
        "tokenizer_parity": EvidenceBoundaryStatus.NOT_CHECKED,
        "runtime_parity": EvidenceBoundaryStatus.NOT_CHECKED,
        "limitations": [
            "The comparison is descriptor-level and evidence-level only.",
            "Allowed GGML type transitions do not establish numerical quality.",
            "Encoded size ratios describe physical storage, not compression quality.",
            "Payload equality, tokenizer parity, and runtime parity were not checked.",
            "Artifact-specific conversion provenance remains unavailable unless "
            "independently supplied.",
        ],
        "findings": findings,
        "artifact_index": artifacts,
        "artifact_index_digest": artifact_index_digest,
        "comparison_digest": "0" * 64,
    }
    draft = StructuralComparisonInventory.model_validate(preliminary)
    digest_data = draft.model_dump(mode="json")
    digest_data.pop("comparison_digest")
    preliminary["comparison_digest"] = canonical_sha256(digest_data)
    return StructuralComparisonInventory.model_validate(preliminary)
