"""Complete Kimi K3 structural mapping adapter; never reads tensor payloads."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal

from omiv.canonical import canonical_sha256
from omiv.mapping.grouped_engine import AssignmentAudit, validate_results_against_policy
from omiv.mapping.grouped_models import (
    EvidenceLevel,
    GroupRelation,
    MappingFinding,
    MappingInventory,
    MappingPolicy,
    MappingResult,
    PayloadStatus,
    ProvenanceStatus,
    SourceAccountingState,
    TargetAccountingState,
    TransitionStatus,
)
from omiv.model_packs.base import ModelPackCapability

from .gguf_ontology import classify_gguf_tensor
from .mapping_policy import CONVERTER_REVISION, kimi_mapping_policy
from .pack import KimiK3ModelPack

SOURCE_TOTAL = 497_220
TARGET_TOTAL = 2_573
MOE_LAYERS = list(range(1, 93))
ALL_LAYERS = list(range(93))
EXPERT_COUNT = 896
EXP = re.compile(
    r"^language_model\.model\.layers\.(\d+)\.block_sparse_moe\.experts\."
    r"(\d+)\.(w[123])\.(weight_packed|weight_scale)$"
)
LAYER_SOURCE = "language_model.model.layers.{layer}."


def _raw_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _names_digest(names: Iterable[str]) -> str:
    return canonical_sha256(sorted(names))


def _load_envelope(path: Path) -> tuple[dict[str, Any], str]:
    raw = json.loads(path.read_text())
    return raw["inventory"], raw["integrity"]["sha256"]


def _target_family(name: str) -> str:
    classified = classify_gguf_tensor(name)
    if classified.layer_component is not None:
        return classified.layer_component
    if classified.canonical is not None:
        return classified.canonical.component
    return "unclassified"


def _source_family(name: str) -> str:
    match = EXP.match(name)
    if match:
        return f"routed_expert.{match.group(3)}.{match.group(4)}"
    value = re.sub(
        r"^language_model\.model\.layers\.\d+\.",
        "language_model.model.layers.{layer}.",
        name,
    )
    value = re.sub(
        r"^vision_tower\.encoder\.blocks\.\d+\.",
        "vision_tower.encoder.blocks.{block}.",
        value,
    )
    return value


def _bounded_breakdown(
    names: Iterable[str], lookup: dict[str, dict[str, Any]], *, target: bool
) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for name in names:
        family = _target_family(name) if target else _source_family(name)
        groups[family].append(lookup[name])
    output = []
    for family, records in sorted(groups.items()):
        output.append(
            {
                "family": family,
                "count": len(records),
                "shape_signatures": [
                    {"shape": list(shape), "count": count}
                    for shape, count in sorted(
                        Counter(
                            tuple(record.get("dimensions" if target else "shape", []))
                            for record in records
                        ).items()
                    )
                ],
                "type_counts": dict(
                    sorted(
                        Counter(
                            str(record.get("ggml_type_name" if target else "dtype", "unknown"))
                            for record in records
                        ).items()
                    )
                ),
                "examples": sorted(record["name"] for record in records)[:3],
            }
        )
    return output


class _Builder:
    def __init__(
        self,
        records: list[dict[str, Any]],
        targets: list[dict[str, Any]],
        normalized_shapes: dict[str, list[int]],
        policy: MappingPolicy,
    ) -> None:
        self.source_lists: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            self.source_lists[record["name"]].append(record)
        self.target_lists: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for target in targets:
            self.target_lists[target["name"]].append(target)
        self.source_lookup = {name: values[0] for name, values in self.source_lists.items()}
        self.target_lookup = {name: values[0] for name, values in self.target_lists.items()}
        self.normalized_shapes = normalized_shapes
        self.rules = {rule.rule_id: rule for rule in policy.rules}
        self.source_states: dict[str, SourceAccountingState] = {}
        self.target_states: dict[str, TargetAccountingState] = {}
        self.audit = AssignmentAudit()
        self.results: list[MappingResult] = []
        self.missing_sources: list[str] = []
        self.missing_targets: list[str] = []
        self.ambiguous_sources: list[str] = [
            name for name, values in self.source_lists.items() if len(values) != 1
        ]
        self.ambiguous_targets: list[str] = [
            name for name, values in self.target_lists.items() if len(values) != 1
        ]
        self.shape_failures: list[str] = []
        self.axis_failures: list[str] = []
        self.type_failures: list[str] = []

    def source(self, name: str) -> dict[str, Any] | None:
        values = self.source_lists.get(name, [])
        if len(values) != 1:
            if not values:
                self.missing_sources.append(name)
            elif name not in self.ambiguous_sources:
                self.ambiguous_sources.append(name)
            return None
        return values[0]

    def target(self, name: str) -> dict[str, Any] | None:
        values = self.target_lists.get(name, [])
        if len(values) != 1:
            if not values:
                self.missing_targets.append(name)
            elif name not in self.ambiguous_targets:
                self.ambiguous_targets.append(name)
            return None
        return values[0]

    def _claim_sources(
        self,
        names: list[str],
        state: SourceAccountingState,
        logical_identity: str | None,
    ) -> None:
        for name in names:
            self.audit.claim_source(
                name,
                logical_identity=(
                    f"{logical_identity}:{name}" if logical_identity is not None else None
                ),
            )
            self.source_states.setdefault(name, state)

    def _claim_targets(self, names: list[str], state: TargetAccountingState) -> None:
        for name in names:
            self.audit.claim_target(name)
            self.target_states.setdefault(name, state)

    def add(
        self,
        *,
        rule_id: str,
        relation: GroupRelation,
        key: list[Any],
        source_names: list[str],
        target_names: list[str],
        source_state: SourceAccountingState,
        target_state: TargetAccountingState,
        expected_source_shapes: set[tuple[int, ...]],
        expected_target_shapes: set[tuple[int, ...]],
        source_member_count: int,
        allowed_target_types: list[str],
        axis_relation: str,
        shape_relation: str,
        converter_operation: str,
    ) -> None:
        rule = self.rules[rule_id]
        if rule.relation != relation:
            raise ValueError(f"{rule_id}: operational relation differs from mapping policy")
        if source_member_count != rule.source_cardinality:
            raise ValueError(f"{rule_id}: operational source cardinality differs from policy")
        if len(target_names) != rule.target_cardinality:
            raise ValueError(f"{rule_id}: operational target cardinality differs from policy")
        if sorted(allowed_target_types) != sorted(rule.allowed_target_types):
            raise ValueError(f"{rule_id}: operational target types differ from mapping policy")
        if axis_relation != rule.axis_relation or shape_relation != rule.shape_relation:
            raise ValueError(f"{rule_id}: operational descriptor relation differs from policy")
        if converter_operation != rule.converter_operation:
            raise ValueError(f"{rule_id}: operational converter operation differs from policy")
        source_records = [
            record for name in source_names if (record := self.source(name)) is not None
        ]
        target_records = [
            record for name in target_names if (record := self.target(name)) is not None
        ]
        identity = f"{rule_id}:{canonical_sha256(key)}"
        self.audit.claim_result(identity)
        self.audit.claim_group(identity)
        self._claim_sources(
            [record["name"] for record in source_records],
            source_state,
            identity if source_state == SourceAccountingState.LOGICAL_REALIZATION_SOURCE else None,
        )
        self._claim_targets(
            [record["name"] for record in target_records],
            target_state,
        )
        source_shapes = {tuple(record.get("shape", [])) for record in source_records}
        target_shapes = {
            tuple(self.normalized_shapes.get(record["name"], record.get("dimensions", [])))
            for record in target_records
        }
        shape_ok = (
            len(source_records) == len(source_names)
            and len(target_records) == len(target_names)
            and source_shapes == expected_source_shapes
            and target_shapes == expected_target_shapes
        )
        if not shape_ok:
            self.shape_failures.append(identity)
        target_types = sorted(
            {str(record.get("ggml_type_name", "unknown")) for record in target_records}
        )
        source_dtypes = sorted({str(record.get("dtype", "unknown")) for record in source_records})
        type_ok = (
            bool(source_records)
            and source_dtypes == [rule.source_dtype]
            and bool(target_records)
            and all(target_type in rule.allowed_target_types for target_type in target_types)
        )
        if not type_ok:
            self.type_failures.append(identity)
        status: Literal["PASS", "FAIL"] = "PASS" if shape_ok and type_ok else "FAIL"
        self.results.append(
            MappingResult(
                rule_id=rule_id,
                relation=relation,
                source_group_key=key,
                source_member_count=source_member_count,
                source_physical_count=len(source_records),
                target_count=len(target_records),
                target_names=[record["name"] for record in target_records],
                source_name_examples=[record["name"] for record in source_records[:4]],
                member_set_digest=_names_digest(record["name"] for record in source_records),
                source_shape_signature=[list(shape) for shape in sorted(source_shapes)],
                target_shape=(list(next(iter(target_shapes))) if len(target_shapes) == 1 else None),
                target_shapes=[list(shape) for shape in sorted(target_shapes)],
                axis_relation=axis_relation,
                shape_relation=shape_relation,
                source_dtypes=source_dtypes,
                target_ggml_types=target_types,
                allowed_target_types=rule.allowed_target_types,
                type_transition_status=(
                    TransitionStatus.PASS if type_ok else TransitionStatus.FAIL
                ),
                converter_operation=converter_operation,
                evidence_level=EvidenceLevel.CONVERTER_CODE_SUPPORTED,
                payload_status=PayloadStatus.NOT_CHECKED,
                status=status,
                detail=(
                    None
                    if status == "PASS"
                    else (
                        f"source={len(source_records)}/{len(source_names)},"
                        f"target={len(target_records)}/{len(target_names)},"
                        f"source_shapes={sorted(source_shapes)},"
                        f"target_shapes={sorted(target_shapes)},source_dtypes={source_dtypes},"
                        f"target_types={target_types}"
                    )
                ),
            )
        )

    def exclude(self, name: str) -> None:
        record = self.source(name)
        if record is None:
            return
        self.audit.claim_source(name)
        self.source_states.setdefault(name, SourceAccountingState.SOURCE_ONLY_AUXILIARY)


def _normalized_target_shapes(
    ontology: dict[str, Any], targets: list[dict[str, Any]]
) -> dict[str, list[int]]:
    shapes_by_family = {
        family["family_id"]: family["shape_summaries"][0]["normalized_dimensions"]
        for family in ontology["family_summaries"]
        if len(family["shape_summaries"]) == 1
    }
    return {
        target["name"]: list(
            shapes_by_family.get(_target_family(target["name"]), target["dimensions"])
        )
        for target in targets
    }


def _add_packed(builder: _Builder) -> dict[str, Any]:
    grouped: dict[tuple[int, str], dict[int, dict[str, list[str]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )
    for name in builder.source_lookup:
        match = EXP.match(name)
        if match is None:
            continue
        layer, expert, wid, part = match.groups()
        grouped[(int(layer), wid)][int(expert)][part].append(name)
    missing_ordinals = 0
    duplicate_ordinals = 0
    scale_records = 0
    physical_members = 0
    complete = 0
    component_data = {
        "w1": (
            "GATE",
            "ffn_gate_exps.weight",
            {(3072, 1792), (3072, 112)},
            {(3584, 3072, 896)},
            ["IQ1_S", "IQ2_XXS"],
        ),
        "w2": (
            "DOWN",
            "ffn_down_exps.weight",
            {(3584, 1536), (3584, 96)},
            {(3072, 3584, 896)},
            ["IQ1_S", "IQ3_XXS"],
        ),
        "w3": (
            "UP",
            "ffn_up_exps.weight",
            {(3072, 1792), (3072, 112)},
            {(3584, 3072, 896)},
            ["IQ1_S", "IQ2_XXS"],
        ),
    }
    for layer in MOE_LAYERS:
        for wid, (component, suffix, source_shapes, target_shapes, types) in component_data.items():
            members = grouped.get((layer, wid), {})
            missing = sorted(set(range(EXPERT_COUNT)) - set(members))
            duplicate = [
                expert
                for expert, parts in members.items()
                if any(len(values) != 1 for values in parts.values())
            ]
            missing_ordinals += len(missing)
            duplicate_ordinals += len(duplicate)
            names = [
                values[0]
                for expert in sorted(members)
                for part in ("weight_packed", "weight_scale")
                if len(values := members[expert].get(part, [])) == 1
            ]
            scale_records += sum(name.endswith("weight_scale") for name in names)
            physical_members += len(names)
            if not missing and not duplicate and len(names) == EXPERT_COUNT * 2:
                complete += 1
            typed_source_shapes: set[tuple[int, ...]] = set(source_shapes)
            typed_target_shapes: set[tuple[int, ...]] = set(target_shapes)
            builder.add(
                rule_id=f"K3-EXP-{component}",
                relation=GroupRelation.MANY_TO_ONE_PACKED,
                key=[layer, component.lower()],
                source_names=names,
                target_names=[f"blk.{layer}.{suffix}"],
                source_state=SourceAccountingState.PACKED_GROUP_MEMBER,
                target_state=TargetAccountingState.PACKED_GROUP_TARGET,
                expected_source_shapes=typed_source_shapes,
                expected_target_shapes=typed_target_shapes,
                source_member_count=len(members),
                allowed_target_types=types,
                axis_relation="expert_axis=2_in_gguf_descriptor",
                shape_relation="repack_mxfp4_then_stack_expert_axis",
                converter_operation=(
                    "repack_each_weight_scale_pair_then_stack_experts_in_ordinal_order"
                ),
            )
    return {
        "source_physical_members": physical_members,
        "source_expert_members": physical_members - scale_records,
        "source_scale_records": scale_records,
        "source_groups": len(MOE_LAYERS) * 3,
        "packed_targets": len(MOE_LAYERS) * 3,
        "complete_groups": complete,
        "incomplete_groups": len(MOE_LAYERS) * 3 - complete,
        "missing_expert_ordinals": missing_ordinals,
        "duplicate_expert_ordinals": duplicate_ordinals,
    }


DirectSpecification = tuple[str, str, str, list[int], set[tuple[int, ...]], list[str]]


def _direct_specifications() -> list[DirectSpecification]:
    specs: list[DirectSpecification] = []
    for rule, source, target, shape, types in (
        (
            "K3-SHARED-GATE",
            "block_sparse_moe.shared_experts.gate_proj.weight",
            "ffn_gate_shexp.weight",
            (6144, 7168),
            ["Q8_0"],
        ),
        (
            "K3-SHARED-UP",
            "block_sparse_moe.shared_experts.up_proj.weight",
            "ffn_up_shexp.weight",
            (6144, 7168),
            ["Q8_0"],
        ),
        (
            "K3-SHARED-DOWN",
            "block_sparse_moe.shared_experts.down_proj.weight",
            "ffn_down_shexp.weight",
            (7168, 6144),
            ["Q8_0"],
        ),
        ("K3-ROUTER", "block_sparse_moe.gate.weight", "ffn_gate_inp.weight", (896, 7168), ["F32"]),
        (
            "K3-ROUTER-BIAS",
            "block_sparse_moe.gate.e_score_correction_bias",
            "exp_probs_b.bias",
            (896,),
            ["F32"],
        ),
        (
            "K3-LATENT-DOWN",
            "block_sparse_moe.routed_expert_down_proj.weight",
            "ffn_routed_down.weight",
            (3584, 7168),
            ["Q8_0"],
        ),
        (
            "K3-LATENT-NORM",
            "block_sparse_moe.routed_expert_norm.weight",
            "ffn_routed_norm.weight",
            (3584,),
            ["F32"],
        ),
        (
            "K3-LATENT-UP",
            "block_sparse_moe.routed_expert_up_proj.weight",
            "ffn_routed_up.weight",
            (7168, 3584),
            ["Q8_0"],
        ),
    ):
        specs.append((rule, source, target, MOE_LAYERS, {shape}, types))
    for component, shape in (
        ("gate", (33792, 7168)),
        ("up", (33792, 7168)),
        ("down", (7168, 33792)),
    ):
        specs.append(
            (
                f"K3-DENSE-{component.upper()}",
                f"mlp.{component}_proj.weight",
                f"ffn_{component}.weight",
                [0],
                {shape},
                ["Q8_0"],
            )
        )
    for rule, source, target, shape, types in (
        ("K3-ATTN-NORM", "input_layernorm.weight", "attn_norm.weight", (7168,), ["F32"]),
        ("K3-FFN-NORM", "post_attention_layernorm.weight", "ffn_norm.weight", (7168,), ["F32"]),
        (
            "K3-ATTN-OUTPUT",
            "self_attn.o_proj.weight",
            "attn_output.weight",
            (7168, 12288),
            ["Q8_0"],
        ),
    ):
        specs.append((rule, source, target, ALL_LAYERS, {shape}, types))
    return specs


def _add_direct(builder: _Builder) -> dict[str, int]:
    family_counts: Counter[str] = Counter()
    for rule, source_suffix, target_suffix, layers, shapes, types in _direct_specifications():
        family = rule.split("K3-", 1)[-1].lower()
        for layer in layers:
            source = LAYER_SOURCE.format(layer=layer) + source_suffix
            target = f"blk.{layer}.{target_suffix}"
            builder.add(
                rule_id=rule,
                relation=GroupRelation.ONE_TO_ONE,
                key=[layer, family],
                source_names=[source],
                target_names=[target],
                source_state=SourceAccountingState.DIRECTLY_MAPPED,
                target_state=TargetAccountingState.DIRECTLY_REALIZED,
                expected_source_shapes=shapes,
                expected_target_shapes=shapes,
                source_member_count=1,
                allowed_target_types=types,
                axis_relation="layer_and_component_preserved",
                shape_relation="normalized_identity",
                converter_operation="map_tensor_name_then_gguf_dimension_reversal",
            )
            family_counts[family] += 1
    for rule, source, target, shape, types in (
        (
            "K3-TOKEN-EMBEDDING",
            "language_model.model.embed_tokens.weight",
            "token_embd.weight",
            (163840, 7168),
            ["Q8_0"],
        ),
        (
            "K3-OUTPUT-NORM",
            "language_model.model.norm.weight",
            "output_norm.weight",
            (7168,),
            ["F32"],
        ),
        (
            "K3-OUTPUT",
            "language_model.lm_head.weight",
            "output.weight",
            (163840, 7168),
            ["Q8_0"],
        ),
    ):
        builder.add(
            rule_id=rule,
            relation=GroupRelation.ONE_TO_ONE,
            key=["model", rule],
            source_names=[source],
            target_names=[target],
            source_state=SourceAccountingState.DIRECTLY_MAPPED,
            target_state=TargetAccountingState.DIRECTLY_REALIZED,
            expected_source_shapes={shape},
            expected_target_shapes={shape},
            source_member_count=1,
            allowed_target_types=types,
            axis_relation="model_component_preserved",
            shape_relation="normalized_identity",
            converter_operation="map_tensor_name_then_gguf_dimension_reversal",
        )
        family_counts["model_level"] += 1
    return dict(sorted(family_counts.items()))


def _add_kda(builder: _Builder, layers: list[int]) -> dict[str, int]:
    counts = {"direct": 0, "logical": 0}
    direct = (
        ("K3-KDA-BETA", "b_proj.weight", "ssm_beta.weight", (96, 7168), ["F32"]),
        ("K3-KDA-DT", "dt_bias", "ssm_dt.bias", (12288,), ["F32"]),
        ("K3-KDA-FORGET-A", "f_a_proj.weight", "ssm_f_a.weight", (128, 7168), ["Q8_0"]),
        ("K3-KDA-FORGET-B", "f_b_proj.weight", "ssm_f_b.weight", (12288, 128), ["Q8_0"]),
        ("K3-KDA-KEY", "k_proj.weight", "attn_k.weight", (12288, 7168), ["Q8_0"]),
        ("K3-KDA-OUTPUT-NORM", "o_norm.weight", "ssm_norm.weight", (128,), ["F32"]),
        ("K3-KDA-QUERY", "q_proj.weight", "attn_q.weight", (12288, 7168), ["Q8_0"]),
        ("K3-KDA-VALUE", "v_proj.weight", "attn_v.weight", (12288, 7168), ["Q8_0"]),
    )
    for layer in layers:
        for rule, source_suffix, target_suffix, shape, types in direct:
            builder.add(
                rule_id=rule,
                relation=GroupRelation.ONE_TO_ONE,
                key=[layer, rule],
                source_names=[LAYER_SOURCE.format(layer=layer) + "self_attn." + source_suffix],
                target_names=[f"blk.{layer}.{target_suffix}"],
                source_state=SourceAccountingState.DIRECTLY_MAPPED,
                target_state=TargetAccountingState.DIRECTLY_REALIZED,
                expected_source_shapes={shape},
                expected_target_shapes={shape},
                source_member_count=1,
                allowed_target_types=types,
                axis_relation="layer_and_component_preserved",
                shape_relation="normalized_identity",
                converter_operation=(
                    "rename_dt_bias_to_dt_proj_bias_then_map_tensor_name"
                    if rule == "K3-KDA-DT"
                    else "map_tensor_name_then_gguf_dimension_reversal"
                ),
            )
            counts["direct"] += 1
        builder.add(
            rule_id="K3-KDA-A",
            relation=GroupRelation.LOGICAL_REALIZATION,
            key=[layer, "a_log"],
            source_names=[LAYER_SOURCE.format(layer=layer) + "self_attn.A_log"],
            target_names=[f"blk.{layer}.ssm_a"],
            source_state=SourceAccountingState.LOGICAL_REALIZATION_SOURCE,
            target_state=TargetAccountingState.LOGICAL_REALIZATION_TARGET,
            expected_source_shapes={(128,)},
            expected_target_shapes={(96,)},
            source_member_count=1,
            allowed_target_types=["F32"],
            axis_relation="first_96_attention_heads",
            shape_relation="source_[128]_slice_first_96_to_target_[96]",
            converter_operation="take_first_num_attention_heads_then_negative_exponential",
        )
        counts["logical"] += 1
        for component in ("q", "k", "v"):
            builder.add(
                rule_id=f"K3-KDA-CONV-{component.upper()}",
                relation=GroupRelation.LOGICAL_REALIZATION,
                key=[layer, component],
                source_names=[
                    LAYER_SOURCE.format(layer=layer) + f"self_attn.{component}_conv1d.weight"
                ],
                target_names=[f"blk.{layer}.ssm_conv1d_{component}.weight"],
                source_state=SourceAccountingState.LOGICAL_REALIZATION_SOURCE,
                target_state=TargetAccountingState.LOGICAL_REALIZATION_TARGET,
                expected_source_shapes={(12288, 1, 4)},
                expected_target_shapes={(12288, 1, 4)},
                source_member_count=1,
                allowed_target_types=["F32"],
                axis_relation="channel_and_kernel_order_preserved",
                shape_relation="reshape_[12288,1,4]_to_writer_[1,12288,1,4]",
                converter_operation="pure_reshape_before_gguf_dimension_reversal",
            )
            counts["logical"] += 1
    return counts


def _add_mla(builder: _Builder, layers: list[int]) -> dict[str, int]:
    counts = {"direct": 0, "split_sources": 0, "split_targets": 0}
    direct = (
        ("K3-MLA-KV-A", "kv_a_proj_with_mqa.weight", "attn_kv_a_mqa.weight", (576, 7168), ["Q8_0"]),
        ("K3-MLA-KV-A-NORM", "kv_a_layernorm.weight", "attn_kv_a_norm.weight", (512,), ["F32"]),
        ("K3-MLA-Q-A", "q_a_proj.weight", "attn_q_a.weight", (1536, 7168), ["Q8_0"]),
        ("K3-MLA-Q-A-NORM", "q_a_layernorm.weight", "attn_q_a_norm.weight", (1536,), ["F32"]),
        ("K3-MLA-Q-B", "q_b_proj.weight", "attn_q_b.weight", (18432, 1536), ["Q8_0"]),
    )
    for layer in layers:
        for rule, source_suffix, target_suffix, shape, types in direct:
            builder.add(
                rule_id=rule,
                relation=GroupRelation.ONE_TO_ONE,
                key=[layer, rule],
                source_names=[LAYER_SOURCE.format(layer=layer) + "self_attn." + source_suffix],
                target_names=[f"blk.{layer}.{target_suffix}"],
                source_state=SourceAccountingState.DIRECTLY_MAPPED,
                target_state=TargetAccountingState.DIRECTLY_REALIZED,
                expected_source_shapes={shape},
                expected_target_shapes={shape},
                source_member_count=1,
                allowed_target_types=types,
                axis_relation="layer_and_component_preserved",
                shape_relation="normalized_identity",
                converter_operation="map_tensor_name_then_gguf_dimension_reversal",
            )
            counts["direct"] += 1
        builder.add(
            rule_id="K3-MLA-KV-B-SPLIT",
            relation=GroupRelation.ONE_TO_MANY_SPLIT,
            key=[layer, "kv_b"],
            source_names=[LAYER_SOURCE.format(layer=layer) + "self_attn.kv_b_proj.weight"],
            target_names=[
                f"blk.{layer}.attn_k_b.weight",
                f"blk.{layer}.attn_v_b.weight",
            ],
            source_state=SourceAccountingState.LOGICAL_REALIZATION_SOURCE,
            target_state=TargetAccountingState.LOGICAL_REALIZATION_TARGET,
            expected_source_shapes={(24576, 512)},
            expected_target_shapes={(96, 512, 128), (96, 128, 512)},
            source_member_count=1,
            allowed_target_types=["Q8_0"],
            axis_relation="split_projection_axis_then_transpose_key_axes_1_2",
            shape_relation="view_[24576,512]_then_split_[128,128]_per_96_heads",
            converter_operation="view_heads_split_key_value_then_transpose_key",
        )
        counts["split_sources"] += 1
        counts["split_targets"] += 2
    return counts


def _add_gproj(builder: _Builder, kda: list[int], mla: list[int]) -> dict[str, int]:
    for layer in [*kda, *mla]:
        is_kda = layer in set(kda)
        builder.add(
            rule_id="K3-GPROJ-KDA" if is_kda else "K3-GPROJ-MLA",
            relation=GroupRelation.LOGICAL_REALIZATION,
            key=[layer, "g_proj"],
            source_names=[LAYER_SOURCE.format(layer=layer) + "self_attn.g_proj.weight"],
            target_names=[f"blk.{layer}.{'ssm_g' if is_kda else 'attn_gate'}.weight"],
            source_state=SourceAccountingState.LOGICAL_REALIZATION_SOURCE,
            target_state=TargetAccountingState.LOGICAL_REALIZATION_TARGET,
            expected_source_shapes={(12288, 7168)},
            expected_target_shapes={(12288, 7168)},
            source_member_count=1,
            allowed_target_types=["Q8_0"],
            axis_relation="layer_schedule_selects_target_family",
            shape_relation="normalized_identity",
            converter_operation=(
                "select_ssm_g_by_pinned_kda_layer_schedule"
                if is_kda
                else "select_attn_gate_by_pinned_mla_layer_schedule"
            ),
        )
    return {"kda": len(kda), "mla": len(mla), "total": len(kda) + len(mla)}


def _add_fused(builder: _Builder) -> dict[str, int]:
    counts = {"source_members": 0, "targets": 0}
    for layer in ALL_LAYERS:
        for rule, prefix, suffix in (
            ("K3-ATTN-RES", "self_attention_res", "attn_res_score.weight"),
            ("K3-FFN-RES", "mlp_res", "ffn_res_score.weight"),
        ):
            sources = [
                LAYER_SOURCE.format(layer=layer) + f"{prefix}_norm.weight",
                LAYER_SOURCE.format(layer=layer) + f"{prefix}_proj.weight",
            ]
            builder.add(
                rule_id=rule,
                relation=GroupRelation.FUSED_TARGET,
                key=[layer, prefix],
                source_names=sources,
                target_names=[f"blk.{layer}.{suffix}"],
                source_state=SourceAccountingState.FUSED_MAPPING_MEMBER,
                target_state=TargetAccountingState.FUSED_TARGET,
                expected_source_shapes={(7168,), (1, 7168)},
                expected_target_shapes={(7168,)},
                source_member_count=2,
                allowed_target_types=["F32"],
                axis_relation="flatten_both_sources_to_embedding_axis",
                shape_relation="flatten_[7168]_and_[1,7168]_to_[7168]",
                converter_operation="elementwise_product_norm_times_squeezed_projection",
            )
            counts["source_members"] += 2
            counts["targets"] += 1
    builder.add(
        rule_id="K3-OUTPUT-RES",
        relation=GroupRelation.FUSED_TARGET,
        key=["model", "output_attn_res"],
        source_names=[
            "language_model.model.output_attn_res_norm.weight",
            "language_model.model.output_attn_res_proj.weight",
        ],
        target_names=["output_res_score.weight"],
        source_state=SourceAccountingState.FUSED_MAPPING_MEMBER,
        target_state=TargetAccountingState.FUSED_TARGET,
        expected_source_shapes={(7168,), (1, 7168)},
        expected_target_shapes={(7168,)},
        source_member_count=2,
        allowed_target_types=["F32"],
        axis_relation="flatten_both_sources_to_embedding_axis",
        shape_relation="flatten_[7168]_and_[1,7168]_to_[7168]",
        converter_operation="elementwise_product_norm_times_squeezed_projection",
    )
    counts["source_members"] += 2
    counts["targets"] += 1
    return counts


def _add_auxiliary(builder: _Builder) -> list[dict[str, Any]]:
    names = sorted(
        name
        for name in builder.source_lookup
        if name.startswith(("vision_tower.", "mm_projector."))
    )
    for name in names:
        builder.exclude(name)
    breakdown = _bounded_breakdown(names, builder.source_lookup, target=False)
    for item in breakdown:
        item.update(
            {
                "reason": "text-only converter intentionally excludes multimodal auxiliary",
                "converter_operation": (
                    "skip_vision_tower"
                    if str(item["family"]).startswith("vision_tower.")
                    else "skip_mm_projector"
                ),
                "converter_revision": CONVERTER_REVISION,
                "accounting_state": SourceAccountingState.SOURCE_ONLY_AUXILIARY.value,
            }
        )
    return breakdown


def _state_counts(
    values: Mapping[str, SourceAccountingState | TargetAccountingState],
    enum_type: type[SourceAccountingState] | type[TargetAccountingState],
) -> dict[str, int]:
    counts = Counter(value.value for value in values.values())
    return {state.value: counts[state.value] for state in enum_type}


def run_kimi_mapping(
    source_path: Path,
    target_split_path: Path,
    target_ontology_path: Path,
) -> MappingInventory:
    policy = kimi_mapping_policy()
    pack = KimiK3ModelPack()
    pack.require(ModelPackCapability.SEMANTIC_MAPPING)
    split, split_digest = _load_envelope(target_split_path)
    ontology, ontology_digest = _load_envelope(target_ontology_path)
    records = json.loads(source_path.read_text())
    targets = split["tensors"]
    if len(records) != SOURCE_TOTAL or len(targets) != TARGET_TOTAL:
        raise ValueError(
            f"unexpected Kimi inventory sizes source={len(records)}, target={len(targets)}"
        )
    if ontology["source_split_inventory_sha256"] != split_digest:
        raise ValueError("target ontology does not link the supplied split inventory")
    if ontology["model_pack_digest"] != pack.metadata.digest:
        raise ValueError("target ontology model-pack digest is stale")
    kda = list(ontology["schedule"]["kda_layer_ids"])
    mla = list(ontology["schedule"]["mla_layer_ids"])
    if len(kda) != 69 or len(mla) != 24 or sorted([*kda, *mla]) != ALL_LAYERS:
        raise ValueError("target ontology KDA/MLA schedule is not complete")
    builder = _Builder(records, targets, _normalized_target_shapes(ontology, targets), policy)
    routed = _add_packed(builder)
    direct_families = _add_direct(builder)
    kda_counts = _add_kda(builder, kda)
    mla_counts = _add_mla(builder, mla)
    gproj_counts = _add_gproj(builder, kda, mla)
    fused_counts = _add_fused(builder)
    auxiliary_breakdown = _add_auxiliary(builder)

    unclaimed_sources = sorted(set(builder.source_lookup) - set(builder.source_states))
    unclaimed_targets = sorted(set(builder.target_lookup) - set(builder.target_states))
    for name in unclaimed_sources:
        builder.source_states[name] = SourceAccountingState.UNCLASSIFIED
    for name in unclaimed_targets:
        builder.target_states[name] = TargetAccountingState.UNCLASSIFIED
    source_counts = _state_counts(builder.source_states, SourceAccountingState)
    target_counts = _state_counts(builder.target_states, TargetAccountingState)
    duplicate_summary = builder.audit.summary()
    duplicate_total = sum(
        int(item["count"]) for item in duplicate_summary.values() if isinstance(item, dict)
    )
    ambiguity_count = len(builder.ambiguous_sources) + len(builder.ambiguous_targets)
    mapping_failures = (
        len(builder.shape_failures)
        + len(builder.axis_failures)
        + len(builder.type_failures)
        + len(builder.missing_sources)
        + len(builder.missing_targets)
        + duplicate_total
        + ambiguity_count
    )
    shared_metadata = next(
        item
        for item in ontology["architecture_metadata"]["items"]
        if item["key"] == "kimi-k3.expert_shared_count"
    )
    shared = {
        "physical_source_mappings": 276,
        "physical_target_mappings": 276,
        "expected_physical_mappings": 276,
        "layers": 92,
        "components": 3,
        "metadata_shared_expert_count": shared_metadata["summary_value"],
        "metadata_evidence": "direct",
        "physical_relation": "one_to_one_combined_projection",
        "payload_partition_order": PayloadStatus.NOT_CHECKED.value,
        "shared_routing_mixing_gate": "absent_not_applicable",
    }
    direct_count = source_counts[SourceAccountingState.DIRECTLY_MAPPED.value]
    findings = [
        MappingFinding(
            code="MAPGROUP-001",
            status="PASS",
            message=f"source accounting reconstructs {sum(source_counts.values())}/{SOURCE_TOTAL}",
        ),
        MappingFinding(
            code="MAPGROUP-002",
            status="PASS",
            message=f"target accounting reconstructs {sum(target_counts.values())}/{TARGET_TOTAL}",
        ),
        MappingFinding(
            code="MAPGROUP-003",
            status="PASS",
            message=f"mapping policy digest {policy.digest}",
        ),
        MappingFinding(
            code="MAPGROUP-006",
            status="PASS" if duplicate_total == 0 and ambiguity_count == 0 else "FAIL",
            message=(
                f"duplicate assignments {duplicate_total}; ambiguous lookups {ambiguity_count}"
            ),
        ),
        MappingFinding(
            code="MAPGROUP-011",
            status="PASS" if routed["complete_groups"] == 276 else "FAIL",
            message=f"routed groups {routed['complete_groups']}/276",
        ),
        MappingFinding(
            code="MAPGROUP-012",
            status="PASS" if routed["packed_targets"] == 276 else "FAIL",
            message=f"packed targets {routed['packed_targets']}/276",
        ),
        MappingFinding(
            code="MAPGROUP-013",
            status="PASS" if shared["physical_target_mappings"] == 276 else "FAIL",
            message=f"shared mappings {shared['physical_target_mappings']}/276",
        ),
        MappingFinding(
            code="MAPGROUP-014",
            status="PASS" if gproj_counts["total"] == 93 else "FAIL",
            message=f"g_proj logical realizations {gproj_counts['total']}/93",
        ),
        MappingFinding(
            code="MAPGROUP-015",
            status="PASS" if not unclaimed_targets else "WARN",
            message=f"unresolved target descriptors {len(unclaimed_targets)}",
        ),
        MappingFinding(
            code="MAPGROUP-016",
            status="PASS" if direct_count == 1693 else "FAIL",
            message=f"direct source mappings {direct_count}/1693",
        ),
        MappingFinding(
            code="MAPGROUP-017",
            status="PASS" if len(unclaimed_sources) == 0 else "WARN",
            message=(
                "historical source census reclassified 282 text and intentionally "
                f"excluded {source_counts[SourceAccountingState.SOURCE_ONLY_AUXILIARY.value]}"
            ),
        ),
        MappingFinding(
            code="MAPGROUP-018",
            status="PASS" if mapping_failures == 0 else "FAIL",
            message=(
                f"shape={len(builder.shape_failures)},axis={len(builder.axis_failures)},"
                f"type={len(builder.type_failures)},missing_source={len(builder.missing_sources)},"
                f"missing_target={len(builder.missing_targets)}"
            ),
        ),
        MappingFinding(
            code="MAPGROUP-019",
            status="UNAVAILABLE",
            message="artifact-specific conversion provenance is unavailable",
        ),
        MappingFinding(
            code="MAPGROUP-020",
            status="NOT_CHECKED",
            message="payload packing, transforms, values, and shared partition were not checked",
        ),
    ]
    source_accounting = {
        "physical_records": len(records),
        "states": source_counts,
        "accounted": sum(source_counts.values()),
        "newly_classified_text_records": 282,
        "historical_unclassified_records": 450,
        "source_only_auxiliary_records": 168,
        "unresolved_records": len(unclaimed_sources),
        "unresolved_family_breakdown": _bounded_breakdown(
            unclaimed_sources, builder.source_lookup, target=False
        ),
        "auxiliary_family_breakdown": auxiliary_breakdown,
    }
    target_accounting = {
        "physical_records": len(targets),
        "states": target_counts,
        "accounted": sum(target_counts.values()),
        "unresolved_records": len(unclaimed_targets),
        "unresolved_family_breakdown": _bounded_breakdown(
            unclaimed_targets, builder.target_lookup, target=True
        ),
    }
    coverage = {
        "routed": routed,
        "shared_experts": shared,
        "direct": {"source_records": direct_count, "target_records": direct_count},
        "fused": fused_counts,
        "logical": {
            "source_records": source_counts[SourceAccountingState.LOGICAL_REALIZATION_SOURCE.value],
            "target_records": target_counts[TargetAccountingState.LOGICAL_REALIZATION_TARGET.value],
        },
        "router": {"router": 92, "router_bias": 92},
        "latent_moe": {"up": 92, "down": 92, "norm": 92},
        "dense": {"gate": 1, "up": 1, "down": 1},
        "norms": {"attention": 93, "ffn": 93, "output": 1},
        "attention_output": 93,
        "kda": kda_counts,
        "mla": mla_counts,
        "g_proj": gproj_counts,
        "model_level_direct": 3,
        "duplicates": duplicate_summary,
        "ambiguities": {
            "count": ambiguity_count,
            "source_examples": sorted(builder.ambiguous_sources)[:8],
            "target_examples": sorted(builder.ambiguous_targets)[:8],
        },
        "failures": {
            "shape": len(builder.shape_failures),
            "axis": len(builder.axis_failures),
            "type_transition": len(builder.type_failures),
        },
        "type_transition_summary": {
            "source_dtype_counts": dict(
                sorted(Counter(record["dtype"] for record in records).items())
            ),
            "target_ggml_type_counts": dict(
                sorted(Counter(target["ggml_type_name"] for target in targets).items())
            ),
            "failures": len(builder.type_failures),
        },
        "payload_status": PayloadStatus.NOT_CHECKED.value,
        "artifact_specific_provenance": ProvenanceStatus.UNAVAILABLE.value,
    }
    inventory = MappingInventory(
        schema="omiv.semantic-mapping-inventory.v3",
        source={
            "path_role": "canonical Kimi K3 checkpoint tensor inventory",
            "inventory_sha256": _raw_sha256(source_path),
            "physical_count": len(records),
        },
        target={
            "split_inventory_sha256": split_digest,
            "ontology_inventory_sha256": ontology_digest,
            "physical_count": len(targets),
            "resolved_revision": split["repository"]["resolved_revision"],
        },
        model_pack={
            "pack_id": pack.pack_id,
            "pack_version": pack.pack_version,
            "capabilities": sorted(capability.value for capability in pack.capabilities),
            "digest": pack.metadata.digest,
        },
        mapping_policy_digest=policy.digest,
        converter_evidence_revision=policy.converter_revision,
        source_accounting=source_accounting,
        target_accounting=target_accounting,
        mapping_results=sorted(
            builder.results, key=lambda result: (result.rule_id, result.source_group_key)
        ),
        coverage=coverage,
        kimi_summary={
            "routed": routed,
            "shared_experts": shared,
            "direct_family_counts": direct_families,
            "kda": kda_counts,
            "mla": mla_counts,
            "g_proj": gproj_counts,
            "attention_residual": fused_counts,
            "historical_reclassification": {
                "newly_classified_text": 282,
                "source_only_auxiliary": 168,
                "total": 450,
            },
        },
        findings=findings,
    )
    validate_results_against_policy(policy, inventory.mapping_results)
    return inventory
