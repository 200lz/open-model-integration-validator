"""Build the deterministic Kimi K3 target-side GGUF ontology inventory."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from pydantic import JsonValue

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.model_packs.base import ModelPack, ModelPackCapability
from omiv.model_packs.kimi_k3.gguf_models import (
    ArchitectureMetadataItem,
    ArchitectureMetadataSummary,
    AttentionResidualSummary,
    CensusOrderingObservation,
    ClassificationAccounting,
    ClassificationDetail,
    FamilyShapeSummary,
    GProjSummary,
    KimiK3GGUFOntologyInventory,
    LayerOntologySummary,
    PackedExpertSummary,
    ScheduleSummary,
    SharedExpertSummary,
    TensorFamilySummary,
    TensorNameCensus,
    build_ontology_findings,
)
from omiv.model_packs.kimi_k3.gguf_ontology import (
    KimiK3GGUFOntologyPolicy,
    TensorFamilyRule,
    TensorScope,
    parse_gguf_name,
)
from omiv.remote.header_models import (
    HeaderInventoryEnvelope,
    MetadataValueType,
    RemoteMetadataEntry,
)
from omiv.remote.header_reporting import header_inventory_integrity_matches
from omiv.remote.split_models import (
    GlobalTensorDescriptor,
    SplitGGUFInventory,
    SplitInventoryEnvelope,
)
from omiv.remote.split_reporting import (
    split_inventory_integrity_matches,
)


@dataclass(frozen=True)
class _MetadataSpec:
    key: str
    policy_class: str
    types: frozenset[MetadataValueType]
    expected: object | None = None
    expected_element_count: int | None = None
    required: bool = True


_METADATA_SPECS = (
    _MetadataSpec(
        "general.architecture", "required", frozenset({MetadataValueType.STRING}), "kimi-k3"
    ),
    _MetadataSpec(
        "general.name", "informational", frozenset({MetadataValueType.STRING}), required=False
    ),
    _MetadataSpec(
        "general.file_type", "informational", frozenset({MetadataValueType.UINT32}), required=False
    ),
    _MetadataSpec(
        "general.quantization_version",
        "informational",
        frozenset({MetadataValueType.UINT32}),
        required=False,
    ),
    _MetadataSpec("kimi-k3.block_count", "required", frozenset({MetadataValueType.UINT32}), 93),
    _MetadataSpec(
        "kimi-k3.embedding_length", "required", frozenset({MetadataValueType.UINT32}), 7168
    ),
    _MetadataSpec(
        "kimi-k3.feed_forward_length", "required", frozenset({MetadataValueType.UINT32}), 33792
    ),
    _MetadataSpec(
        "kimi-k3.attention.head_count", "required", frozenset({MetadataValueType.UINT32}), 96
    ),
    _MetadataSpec(
        "kimi-k3.attention.head_count_kv",
        "required",
        frozenset({MetadataValueType.ARRAY}),
        expected_element_count=93,
    ),
    _MetadataSpec(
        "kimi-k3.attention.key_length", "required", frozenset({MetadataValueType.UINT32}), 576
    ),
    _MetadataSpec(
        "kimi-k3.attention.value_length", "required", frozenset({MetadataValueType.UINT32}), 74
    ),
    _MetadataSpec(
        "kimi-k3.attention.key_length_mla", "required", frozenset({MetadataValueType.UINT32}), 192
    ),
    _MetadataSpec(
        "kimi-k3.attention.value_length_mla", "required", frozenset({MetadataValueType.UINT32}), 128
    ),
    _MetadataSpec(
        "kimi-k3.attention.q_lora_rank", "required", frozenset({MetadataValueType.UINT32}), 1536
    ),
    _MetadataSpec(
        "kimi-k3.attention.kv_lora_rank", "required", frozenset({MetadataValueType.UINT32}), 512
    ),
    _MetadataSpec(
        "kimi-k3.rope.dimension_count", "required", frozenset({MetadataValueType.UINT32}), 64
    ),
    _MetadataSpec(
        "kimi-k3.rope.freq_base", "required", frozenset({MetadataValueType.FLOAT32}), 10000.0
    ),
    _MetadataSpec("kimi-k3.expert_count", "required", frozenset({MetadataValueType.UINT32}), 896),
    _MetadataSpec(
        "kimi-k3.expert_used_count", "required", frozenset({MetadataValueType.UINT32}), 16
    ),
    _MetadataSpec(
        "kimi-k3.expert_shared_count", "required", frozenset({MetadataValueType.UINT32}), 2
    ),
    _MetadataSpec(
        "kimi-k3.expert_feed_forward_length",
        "required",
        frozenset({MetadataValueType.UINT32}),
        3072,
    ),
    _MetadataSpec(
        "kimi-k3.expert_latent_length", "required", frozenset({MetadataValueType.UINT32}), 3584
    ),
    _MetadataSpec(
        "kimi-k3.leading_dense_block_count", "required", frozenset({MetadataValueType.UINT32}), 1
    ),
    _MetadataSpec("kimi-k3.kda.head_dim", "required", frozenset({MetadataValueType.UINT32}), 128),
    _MetadataSpec(
        "kimi-k3.kda.gate_lower_bound", "required", frozenset({MetadataValueType.FLOAT32}), -5.0
    ),
    _MetadataSpec("kimi-k3.ssm.conv_kernel", "required", frozenset({MetadataValueType.UINT32}), 4),
    _MetadataSpec(
        "kimi-k3.attn_res.block_size", "required", frozenset({MetadataValueType.UINT32}), 12
    ),
    _MetadataSpec(
        "split.count", "required", frozenset({MetadataValueType.UINT16, MetadataValueType.UINT32})
    ),
    _MetadataSpec(
        "split.no", "derived", frozenset({MetadataValueType.UINT16, MetadataValueType.UINT32}), 0
    ),
    _MetadataSpec(
        "split.tensors.count",
        "required",
        frozenset({MetadataValueType.INT32, MetadataValueType.UINT32}),
    ),
)


def _metadata_map(
    envelope: HeaderInventoryEnvelope,
) -> dict[str, RemoteMetadataEntry]:
    return {item.key: item for item in envelope.inventory.metadata}


def _metadata_scalar(
    metadata: dict[str, RemoteMetadataEntry],
    key: str,
) -> JsonValue:
    entry = metadata.get(key)
    return None if entry is None else entry.summary_value


def validate_metadata_inventory_linkage(
    split: SplitInventoryEnvelope,
    metadata: HeaderInventoryEnvelope,
) -> None:
    if not split_inventory_integrity_matches(split):
        raise OmivInputError("split inventory integrity mismatch")
    if not header_inventory_integrity_matches(metadata):
        raise OmivInputError("metadata header inventory integrity mismatch")
    combined = split.inventory
    header = metadata.inventory
    shard_by_path = {item.path: item for item in combined.shard_summaries}
    shard = shard_by_path.get(header.file.path)
    if shard is None:
        raise OmivInputError("metadata header file is absent from the split inventory")
    expected_primary = combined.metadata_consistency.broadest_metadata_shard
    if header.file.path != expected_primary:
        raise OmivInputError("metadata header is not the recorded broadest-metadata shard")
    failures = []
    if metadata.integrity.sha256 != shard.inventory_sha256:
        failures.append("inventory digest")
    if header.repository != combined.repository:
        failures.append("repository identity")
    if header.snapshot_sha256 != combined.snapshot_sha256:
        failures.append("snapshot digest")
    if header.file.byte_size != shard.file_size:
        failures.append("repository-declared file size")
    if header.parser_policy_sha256 != combined.header_parser_policy_sha256:
        failures.append("header parser policy")
    if failures:
        raise OmivInputError("metadata header linkage mismatch: " + ", ".join(failures))


def _architecture_metadata(
    split: SplitGGUFInventory,
    metadata_envelope: HeaderInventoryEnvelope,
) -> ArchitectureMetadataSummary:
    metadata = _metadata_map(metadata_envelope)
    items: list[ArchitectureMetadataItem] = []
    failures: list[str] = []
    for spec in _METADATA_SPECS:
        entry = metadata.get(spec.key)
        valid = entry is not None
        note: str | None = None
        if entry is None:
            if spec.required:
                failures.append(spec.key)
            note = "metadata key is absent"
        else:
            if entry.value_type not in spec.types:
                valid = False
                note = "metadata value type does not satisfy policy"
            if spec.expected is not None and entry.summary_value != spec.expected:
                valid = False
                note = "metadata scalar does not satisfy policy"
            if (
                spec.expected_element_count is not None
                and entry.element_count != spec.expected_element_count
            ):
                valid = False
                note = "metadata array count does not satisfy policy"
            if spec.key == "kimi-k3.attention.head_count_kv" and entry.array_element_type not in {
                MetadataValueType.INT32,
                MetadataValueType.UINT32,
            }:
                valid = False
                note = "KV-head schedule array must contain 32-bit integer values"
            dynamic_expected = {
                "split.count": split.shard_count,
                "split.tensors.count": split.aggregated_tensor_count,
            }.get(spec.key)
            if dynamic_expected is not None and entry.summary_value != dynamic_expected:
                valid = False
                note = "split metadata scalar does not agree with the verified inventory"
            if spec.required and not valid:
                failures.append(spec.key)
        items.append(
            ArchitectureMetadataItem(
                key=spec.key,
                policy_class=spec.policy_class,  # type: ignore[arg-type]
                evidence="direct" if entry is not None else "unavailable",
                value_type=None if entry is None else entry.value_type.value,
                summary_value=None if entry is None else entry.summary_value,
                encoded_sha256=None if entry is None else entry.encoded_sha256,
                valid=valid,
                note=note,
            )
        )
    derived = [
        (
            "derived.observed_layer_count",
            len(
                {
                    parsed.layer_id
                    for item in split.tensors
                    if (parsed := parse_gguf_name(item.name)).layer_id is not None
                }
            ),
        ),
        ("derived.aggregated_tensor_count", split.aggregated_tensor_count),
        ("derived.split_shard_count", split.shard_count),
    ]
    for key, value in derived:
        items.append(
            ArchitectureMetadataItem(
                key=key,
                policy_class="derived",
                evidence="derived",
                value_type="UINT64",
                summary_value=value,
                valid=True,
                note="derived from the verified split descriptor inventory",
            )
        )
    items.sort(key=lambda item: item.key)
    evidence_counts = Counter(item.evidence for item in items)
    return ArchitectureMetadataSummary(
        metadata_inventory_sha256=metadata_envelope.integrity.sha256,
        metadata_shard_path=metadata_envelope.inventory.file.path,
        architecture_identifier=_metadata_scalar(metadata, "general.architecture"),  # type: ignore[arg-type]
        model_name=_metadata_scalar(metadata, "general.name"),  # type: ignore[arg-type]
        items=items,
        required_failures=sorted(set(failures)),
        direct_item_count=evidence_counts["direct"],
        derived_item_count=evidence_counts["derived"],
        unavailable_item_count=evidence_counts["unavailable"],
    )


def _shape_key(dimensions: Iterable[int]) -> str:
    return "x".join(str(item) for item in dimensions)


def _scope_layers(
    policy: KimiK3GGUFOntologyPolicy,
    rule: TensorFamilyRule,
) -> set[int]:
    return set(policy.expected_layers_for(rule))


def _family_summaries(
    tensors: list[GlobalTensorDescriptor],
    policy: KimiK3GGUFOntologyPolicy,
) -> tuple[list[TensorFamilySummary], dict[str, list[GlobalTensorDescriptor]]]:
    grouped: dict[str, list[GlobalTensorDescriptor]] = defaultdict(list)
    rules = {item.family_id: item for item in policy.family_rules}
    for tensor in tensors:
        parsed = parse_gguf_name(tensor.name, policy)
        if parsed.family_id is not None:
            grouped[parsed.family_id].append(tensor)
    summaries: list[TensorFamilySummary] = []
    for family_id in sorted(rules):
        rule = rules[family_id]
        values = grouped.get(family_id, [])
        parsed_values = [(parse_gguf_name(item.name, policy), item) for item in values]
        layer_ids = sorted(item.layer_id for item, _ in parsed_values if item.layer_id is not None)
        counts = Counter(layer_ids)
        observed_layers = sorted(counts)
        expected_layers = sorted(_scope_layers(policy, rule))
        shape_counts = Counter(tuple(item.dimensions) for item in values)
        shape_summaries = [
            FamilyShapeSummary(
                physical_dimensions=list(shape),
                normalized_dimensions=rule.normalized_dimensions(list(shape)),
                shape_relation=rule.shape_relation.value,
                dimension_roles=rule.dimension_roles,
                observation_count=count,
            )
            for shape, count in sorted(shape_counts.items())
        ]
        type_counts = Counter(item.ggml_type_name for item in values)
        expected_count = 1 if rule.scope == TensorScope.MODEL else len(expected_layers)
        model_coverage = rule.scope != TensorScope.MODEL or len(values) == 1
        coverage_valid = (
            model_coverage
            and len(values) == expected_count
            and not (set(expected_layers) - set(observed_layers))
            and not (set(observed_layers) - set(expected_layers))
            and not [layer for layer, count in counts.items() if count > 1]
        )
        summaries.append(
            TensorFamilySummary(
                family_id=family_id,
                suffix=rule.expected_name_suffix,
                scope=rule.scope.value,
                physical_kind=rule.physical_kind.value,
                module=rule.module,
                observed_count=len(values),
                expected_count=expected_count,
                observed_layer_ids=observed_layers,
                expected_layer_ids=expected_layers,
                missing_layer_ids=sorted(set(expected_layers) - set(observed_layers)),
                unexpected_layer_ids=sorted(set(observed_layers) - set(expected_layers)),
                duplicate_layer_ids=sorted(layer for layer, count in counts.items() if count > 1),
                shape_summaries=shape_summaries,
                ggml_type_counts=dict(sorted(type_counts.items())),
                allowed_ggml_types=sorted(rule.allowed_ggml_types),
                shape_valid=bool(values) and set(shape_counts) == {tuple(rule.expected_dimensions)},
                type_valid=bool(values) and set(type_counts).issubset(rule.allowed_ggml_types),
                coverage_valid=coverage_valid,
            )
        )
    return summaries, grouped


def _tensor_is_valid_for_rule(
    tensor: GlobalTensorDescriptor,
    rule: TensorFamilyRule,
    layer_id: int | None,
    policy: KimiK3GGUFOntologyPolicy,
) -> tuple[bool, str | None]:
    if tensor.dimensions != rule.expected_dimensions:
        return False, "physical GGUF dimensions violate the ontology family rule"
    if tensor.ggml_type_name not in rule.allowed_ggml_types:
        return False, "GGML type violates the ontology family rule"
    expected_layers = _scope_layers(policy, rule)
    if rule.scope == TensorScope.MODEL:
        if layer_id is not None:
            return False, "model-level family unexpectedly has a layer index"
    elif layer_id not in expected_layers:
        return False, "layer index is outside the family schedule"
    return True, None


def _classification(
    tensors: list[GlobalTensorDescriptor],
    policy: KimiK3GGUFOntologyPolicy,
) -> tuple[ClassificationAccounting, str, list[str], list[str]]:
    rules = {item.family_id: item for item in policy.family_rules}
    classified = 0
    unclassified: list[ClassificationDetail] = []
    invalid: list[ClassificationDetail] = []
    assignments: list[dict[str, JsonValue]] = []
    malformed: list[str] = []
    suffixes: list[str] = []
    for tensor in tensors:
        parsed = parse_gguf_name(tensor.name, policy)
        suffixes.append(parsed.suffix)
        if parsed.malformed:
            malformed.append(tensor.name)
        if parsed.family_id is None:
            unclassified.append(
                ClassificationDetail(
                    name=tensor.name,
                    shard_path=tensor.shard_path,
                    dimensions=tensor.dimensions,
                    ggml_type_name=tensor.ggml_type_name,
                    reason=(
                        "malformed layer tensor name"
                        if parsed.malformed
                        else "name is outside the pinned target ontology vocabulary"
                    ),
                    suggested_category=("malformed_layer_name" if parsed.malformed else None),
                )
            )
            assignments.append({"name": tensor.name, "category": "intentionally_unclassified"})
            continue
        rule = rules[parsed.family_id]
        valid, reason = _tensor_is_valid_for_rule(tensor, rule, parsed.layer_id, policy)
        if not valid:
            invalid.append(
                ClassificationDetail(
                    name=tensor.name,
                    shard_path=tensor.shard_path,
                    dimensions=tensor.dimensions,
                    ggml_type_name=tensor.ggml_type_name,
                    reason=reason or "invalid ontology assignment",
                    suggested_category=parsed.family_id,
                )
            )
            assignments.append(
                {"name": tensor.name, "category": "invalid", "family_id": parsed.family_id}
            )
            continue
        classified += 1
        assignments.append(
            {"name": tensor.name, "category": "classified", "family_id": parsed.family_id}
        )
    unclassified.sort(key=lambda item: item.name)
    invalid.sort(key=lambda item: item.name)
    return (
        ClassificationAccounting(
            total_tensor_count=len(tensors),
            classified_count=classified,
            intentionally_unclassified_count=len(unclassified),
            invalid_count=len(invalid),
            duplicate_classification_count=0,
            unclassified_details=unclassified[: policy.maximum_unclassified_details],
            invalid_details=invalid[: policy.maximum_unclassified_details],
            unclassified_detail_digest=canonical_sha256(
                [item.model_dump(mode="json") for item in unclassified]
            ),
            invalid_detail_digest=canonical_sha256(
                [item.model_dump(mode="json") for item in invalid]
            ),
        ),
        canonical_sha256(assignments),
        sorted(set(malformed)),
        sorted(set(suffixes)),
    )


def _ordering_observation(
    split: SplitGGUFInventory,
) -> CensusOrderingObservation:
    by_shard: dict[str, list[GlobalTensorDescriptor]] = defaultdict(list)
    for tensor in split.tensors:
        by_shard[tensor.shard_path].append(tensor)
    offset_order = True
    gap_count = 0
    trailing = 0
    summaries = {item.path: item for item in split.shard_summaries}
    for path, shard_tensors in sorted(by_shard.items()):
        descriptor_order = sorted(shard_tensors, key=lambda item: item.descriptor_index)
        starts = [item.payload_span.absolute_start for item in descriptor_order]
        offset_order = offset_order and starts == sorted(starts)
        spans = sorted(
            (
                item.payload_span.absolute_start,
                item.payload_span.absolute_end,
            )
            for item in shard_tensors
            if item.payload_span.absolute_end is not None
        )
        cursor = summaries[path].payload_start
        for start, end in spans:
            if start > cursor:
                gap_count += 1
            cursor = max(cursor, end or cursor)
        trailing += max(0, summaries[path].file_size - cursor)
    return CensusOrderingObservation(
        descriptor_order_matches_name_order=[item.name for item in split.tensors]
        == sorted(item.name for item in split.tensors),
        payload_offset_order_matches_descriptor_order_by_shard=offset_order,
        payload_gap_count=gap_count,
        trailing_byte_count=trailing,
    )


def _layer_summaries(
    tensors: list[GlobalTensorDescriptor],
    policy: KimiK3GGUFOntologyPolicy,
) -> tuple[list[LayerOntologySummary], ScheduleSummary]:
    by_layer: dict[int, list[tuple[str | None, GlobalTensorDescriptor]]] = defaultdict(list)
    for tensor in tensors:
        parsed = parse_gguf_name(tensor.name, policy)
        if parsed.layer_id is not None:
            by_layer[parsed.layer_id].append((parsed.family_id, tensor))
    rules = {item.family_id: item for item in policy.family_rules}
    expected_by_layer: dict[int, set[str]] = defaultdict(set)
    for rule in policy.family_rules:
        for layer in policy.expected_layers_for(rule):
            expected_by_layer[layer].add(rule.family_id)
    layers: list[LayerOntologySummary] = []
    kda_observed: set[int] = set()
    mla_observed: set[int] = set()
    dense_observed: set[int] = set()
    moe_observed: set[int] = set()
    for layer_id in sorted(by_layer):
        values = by_layer[layer_id]
        observed = {family for family, _ in values if family is not None}
        modules = {rules[family].module for family in observed}
        if "kda_attention" in modules:
            kda_observed.add(layer_id)
        if "mla_attention" in modules:
            mla_observed.add(layer_id)
        if "dense_ffn" in modules:
            dense_observed.add(layer_id)
        if modules & {"routed_experts", "moe_router", "shared_experts", "latent_moe"}:
            moe_observed.add(layer_id)
        attention_kind: Literal["kda", "mla", "unknown", "conflict"] = (
            "conflict"
            if layer_id in kda_observed and layer_id in mla_observed
            else "kda"
            if layer_id in kda_observed
            else "mla"
            if layer_id in mla_observed
            else "unknown"
        )
        ffn_kind: Literal["dense", "moe", "unknown", "conflict"] = (
            "conflict"
            if layer_id in dense_observed and layer_id in moe_observed
            else "dense"
            if layer_id in dense_observed
            else "moe"
            if layer_id in moe_observed
            else "unknown"
        )
        expected_families = expected_by_layer[layer_id]
        layers.append(
            LayerOntologySummary(
                layer_id=layer_id,
                attention_kind=attention_kind,
                ffn_kind=ffn_kind,
                tensor_count=len(values),
                classified_tensor_count=sum(family is not None for family, _ in values),
                unclassified_tensor_count=sum(family is None for family, _ in values),
                family_ids=sorted(observed),
                missing_family_ids=sorted(expected_families - observed),
                unexpected_family_ids=sorted(observed - expected_families),
            )
        )
    expected_layers = set(policy.expected_layer_ids)
    observed_layers = set(by_layer)
    expected_kda = set(policy.expected_kda_layer_ids)
    expected_mla = set(policy.expected_mla_layer_ids)
    return layers, ScheduleSummary(
        expected_layer_ids=sorted(expected_layers),
        observed_layer_ids=sorted(observed_layers),
        missing_layer_ids=sorted(expected_layers - observed_layers),
        unexpected_layer_ids=sorted(observed_layers - expected_layers),
        kda_layer_ids=sorted(kda_observed),
        mla_layer_ids=sorted(mla_observed),
        dense_layer_ids=sorted(dense_observed),
        moe_layer_ids=sorted(moe_observed),
        missing_kda_layer_ids=sorted(expected_kda - kda_observed),
        unexpected_kda_layer_ids=sorted(kda_observed - expected_kda),
        missing_mla_layer_ids=sorted(expected_mla - mla_observed),
        unexpected_mla_layer_ids=sorted(mla_observed - expected_mla),
        attention_overlap_layer_ids=sorted(kda_observed & mla_observed),
    )


def _summary_by_id(
    summaries: list[TensorFamilySummary],
) -> dict[str, TensorFamilySummary]:
    return {item.family_id: item for item in summaries}


def build_kimi_k3_gguf_ontology(
    split_envelope: SplitInventoryEnvelope,
    metadata_envelope: HeaderInventoryEnvelope,
    model_pack: ModelPack,
    *,
    policy: KimiK3GGUFOntologyPolicy | None = None,
) -> KimiK3GGUFOntologyInventory:
    model_pack.require(ModelPackCapability.GGUF_ONTOLOGY)
    if model_pack.pack_id != "kimi-k3":
        raise OmivInputError("Kimi K3 GGUF ontology requires the kimi-k3 model pack")
    validate_metadata_inventory_linkage(split_envelope, metadata_envelope)
    split = split_envelope.inventory
    selected = policy or KimiK3GGUFOntologyPolicy()
    tensors = split.tensors
    classification, assignment_digest, malformed, suffixes = _classification(tensors, selected)
    family_summaries, grouped = _family_summaries(tensors, selected)
    by_family = _summary_by_id(family_summaries)
    layer_summaries, schedule = _layer_summaries(tensors, selected)
    architecture = _architecture_metadata(split, metadata_envelope)

    type_counts = Counter(item.ggml_type_name for item in tensors)
    shard_counts = Counter({item.path: 0 for item in split.shard_summaries})
    shard_counts.update(item.shard_path for item in tensors)
    layer_counts: Counter[int] = Counter()
    shape_by_family: dict[str, Counter[str]] = defaultdict(Counter)
    types_by_family: dict[str, Counter[str]] = defaultdict(Counter)
    prefix_counts: Counter[str] = Counter()
    packed_names: list[str] = []
    shared_names: list[str] = []
    residual_names: list[str] = []
    g_proj_names: list[str] = []
    non_layer: list[str] = []
    for tensor in tensors:
        parsed = parse_gguf_name(tensor.name, selected)
        prefix_counts[tensor.name.split(".", 1)[0]] += 1
        if parsed.layer_id is None:
            non_layer.append(tensor.name)
        else:
            layer_counts[parsed.layer_id] += 1
        family = parsed.family_id or "<unclassified>"
        shape_by_family[family][_shape_key(tensor.dimensions)] += 1
        types_by_family[family][tensor.ggml_type_name] += 1
        if family.startswith("moe.packed_"):
            packed_names.append(tensor.name)
        if family.startswith("moe.shared_"):
            shared_names.append(tensor.name)
        if family.startswith("attn_res."):
            residual_names.append(tensor.name)
        if family.startswith("g_proj."):
            g_proj_names.append(tensor.name)
    census = TensorNameCensus(
        total_tensor_count=len(tensors),
        unique_tensor_count=len({item.name for item in tensors}),
        top_level_prefix_counts=dict(sorted(prefix_counts.items())),
        suffix_vocabulary=suffixes,
        layer_indexed_count=sum(layer_counts.values()),
        non_layer_names=sorted(non_layer),
        observed_layer_ids=sorted(layer_counts),
        tensor_count_by_layer={str(key): value for key, value in sorted(layer_counts.items())},
        tensor_count_by_shard=dict(sorted(shard_counts.items())),
        tensor_count_by_ggml_type=dict(sorted(type_counts.items())),
        tensor_count_by_family={item.family_id: item.observed_count for item in family_summaries},
        shape_signatures_by_family={
            key: dict(sorted(value.items())) for key, value in sorted(shape_by_family.items())
        },
        ggml_types_by_family={
            key: dict(sorted(value.items())) for key, value in sorted(types_by_family.items())
        },
        malformed_names=malformed,
        packed_tensor_names=sorted(packed_names),
        shared_expert_tensor_names=sorted(shared_names),
        attention_residual_tensor_names=sorted(residual_names),
        g_proj_tensor_names=sorted(g_proj_names),
        ordering=_ordering_observation(split),
        classified_assignment_sha256=assignment_digest,
    )

    packed_ids = ["moe.packed_down", "moe.packed_gate", "moe.packed_up"]
    packed_summaries = [by_family[item] for item in packed_ids]
    expert_counts = sorted(
        {
            tensor.dimensions[2]
            for family_id in packed_ids
            for tensor in grouped[family_id]
            if len(tensor.dimensions) == 3
        }
    )
    metadata_values = _metadata_map(metadata_envelope)
    metadata_expert = _metadata_scalar(metadata_values, "kimi-k3.expert_count")
    packed = PackedExpertSummary(
        family_ids=packed_ids,
        layer_ids=sorted(set().union(*(set(item.observed_layer_ids) for item in packed_summaries))),
        missing_layer_ids=sorted(
            set().union(*(set(item.missing_layer_ids) for item in packed_summaries))
        ),
        duplicate_components=sorted(
            item.family_id for item in packed_summaries if item.duplicate_layer_ids
        ),
        structurally_encoded_expert_counts=expert_counts,
        metadata_expert_count=metadata_expert if isinstance(metadata_expert, int) else None,
        shape_valid=all(item.shape_valid for item in packed_summaries),
        type_valid=all(item.type_valid for item in packed_summaries),
    )
    shared_ids = ["moe.shared_down", "moe.shared_gate", "moe.shared_up"]
    shared_summaries = [by_family[item] for item in shared_ids]
    shared = SharedExpertSummary(
        family_ids=shared_ids,
        layer_ids=sorted(set().union(*(set(item.observed_layer_ids) for item in shared_summaries))),
        missing_layer_ids=sorted(
            set().union(*(set(item.missing_layer_ids) for item in shared_summaries))
        ),
        unexpected_layer_ids=sorted(
            set().union(*(set(item.unexpected_layer_ids) for item in shared_summaries))
        ),
        duplicate_components=sorted(
            item.family_id for item in shared_summaries if item.duplicate_layer_ids
        ),
        shape_valid=all(item.shape_valid for item in shared_summaries),
        type_valid=all(item.type_valid for item in shared_summaries),
    )
    g_ids = ["g_proj.kda", "g_proj.mla"]
    g_summaries = [by_family[item] for item in g_ids]
    combined_g_layers = sorted(set().union(*(set(item.observed_layer_ids) for item in g_summaries)))
    g_counts = Counter(layer for item in g_summaries for layer in item.observed_layer_ids)
    g_proj = GProjSummary(
        physical_family_ids=g_ids,
        kda_layer_ids=by_family["g_proj.kda"].observed_layer_ids,
        mla_layer_ids=by_family["g_proj.mla"].observed_layer_ids,
        combined_layer_ids=combined_g_layers,
        missing_layer_ids=sorted(set(selected.expected_layer_ids) - set(combined_g_layers)),
        duplicate_layer_ids=sorted(layer for layer, count in g_counts.items() if count > 1),
        shape_valid=all(item.shape_valid for item in g_summaries),
        type_valid=all(item.type_valid for item in g_summaries),
    )
    residual_ids = [
        "attn_res.attention_score",
        "attn_res.ffn_score",
        "attn_res.output_score",
    ]
    residual_summaries = [by_family[item] for item in residual_ids]
    block_value = _metadata_scalar(metadata_values, "kimi-k3.attn_res.block_size")
    residual_missing = [item.family_id for item in residual_summaries if not item.coverage_valid]
    attention_residual = AttentionResidualSummary(
        layer_family_ids=residual_ids[:2],
        model_family_ids=residual_ids[2:],
        attention_score_layer_ids=by_family[residual_ids[0]].observed_layer_ids,
        ffn_score_layer_ids=by_family[residual_ids[1]].observed_layer_ids,
        model_output_score_present=by_family[residual_ids[2]].observed_count == 1,
        metadata_block_size=block_value if isinstance(block_value, int) else None,
        expected_block_size=selected.expected_attention_residual_block_size,
        derived_checkpoint_layer_ids=list(
            range(
                0, len(selected.expected_layer_ids), selected.expected_attention_residual_block_size
            )
        ),
        missing_components=sorted(residual_missing),
        shape_valid=all(item.shape_valid for item in residual_summaries),
        type_valid=all(item.type_valid for item in residual_summaries),
    )

    inventory = KimiK3GGUFOntologyInventory.model_construct(
        model_pack="kimi-k3",
        model_pack_digest=model_pack.metadata.digest,
        ontology_policy=selected,
        ontology_policy_digest=selected.digest,
        source_split_inventory_sha256=split_envelope.integrity.sha256,
        source_split_schema=split.inventory_schema,
        repository=split.repository,
        snapshot_sha256=split.snapshot_sha256,
        split_shard_count=split.shard_count,
        split_tensor_count=split.aggregated_tensor_count,
        architecture_metadata=architecture,
        census=census,
        schedule=schedule,
        family_summaries=family_summaries,
        layer_summaries=layer_summaries,
        packed_experts=packed,
        shared_experts=shared,
        g_proj=g_proj,
        attention_residual=attention_residual,
        classification=classification,
        findings=[],
    )
    inventory.findings = build_ontology_findings(inventory)
    return KimiK3GGUFOntologyInventory.model_validate(inventory.model_dump(mode="json"))
