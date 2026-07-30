"""Complete trusted Kimi K3 source-to-GGUF structural mapping policy."""

from __future__ import annotations

from omiv.mapping.grouped_models import (
    GroupRelation,
    MappingPolicy,
    MappingRule,
)

CONVERTER_REVISION = "cf67f0d24511864d2d3da0769108fd6fc16d00d1"


def _rule(
    rule_id: str,
    source_family: str,
    target_family: str,
    relation: GroupRelation,
    scope: str,
    source_pattern: str,
    target_patterns: list[str],
    source_dtype: str,
    target_types: list[str],
    *,
    source_cardinality: int = 1,
    target_cardinality: int = 1,
    shape: str = "normalized_identity",
    axis: str = "layer_and_component_preserved",
    operation: str = "map_tensor_name_then_gguf_dimension_reversal",
    ordering: str = "layer_then_component",
) -> MappingRule:
    return MappingRule(
        rule_id=rule_id,
        source_family=source_family,
        target_family=target_family,
        relation=relation,
        grouping_key=["layer", "component"] if scope != "model" else ["component"],
        layer_scope=scope,
        source_name_pattern=source_pattern,
        target_name_patterns=target_patterns,
        member_ordering=ordering,
        source_cardinality=source_cardinality,
        target_cardinality=target_cardinality,
        shape_relation=shape,
        axis_relation=axis,
        source_dtype=source_dtype,
        allowed_target_types=target_types,
        converter_operation=operation,
        evidence_source=CONVERTER_REVISION,
        authorized_target_count=target_cardinality,
    )


def _direct_rules() -> list[MappingRule]:
    layer = r"language_model\.model\.layers\.{layer}\."
    target = r"blk\.{layer}\."
    rules = [
        _rule(
            "K3-SHARED-GATE",
            "moe.shared_gate",
            "moe.shared_gate",
            GroupRelation.ONE_TO_ONE,
            "moe_layers:1-92",
            layer + r"block_sparse_moe\.shared_experts\.gate_proj\.weight",
            [target + r"ffn_gate_shexp\.weight"],
            "BF16",
            ["Q8_0"],
        ),
        _rule(
            "K3-SHARED-UP",
            "moe.shared_up",
            "moe.shared_up",
            GroupRelation.ONE_TO_ONE,
            "moe_layers:1-92",
            layer + r"block_sparse_moe\.shared_experts\.up_proj\.weight",
            [target + r"ffn_up_shexp\.weight"],
            "BF16",
            ["Q8_0"],
        ),
        _rule(
            "K3-SHARED-DOWN",
            "moe.shared_down",
            "moe.shared_down",
            GroupRelation.ONE_TO_ONE,
            "moe_layers:1-92",
            layer + r"block_sparse_moe\.shared_experts\.down_proj\.weight",
            [target + r"ffn_down_shexp\.weight"],
            "BF16",
            ["Q8_0"],
        ),
        _rule(
            "K3-ROUTER",
            "moe.router",
            "moe.router",
            GroupRelation.ONE_TO_ONE,
            "moe_layers:1-92",
            layer + r"block_sparse_moe\.gate\.weight",
            [target + r"ffn_gate_inp\.weight"],
            "BF16",
            ["F32"],
        ),
        _rule(
            "K3-ROUTER-BIAS",
            "moe.router_bias",
            "moe.router_bias",
            GroupRelation.ONE_TO_ONE,
            "moe_layers:1-92",
            layer + r"block_sparse_moe\.gate\.e_score_correction_bias",
            [target + r"exp_probs_b\.bias"],
            "F32",
            ["F32"],
        ),
    ]
    for component, source, suffix, target_types in (
        ("DOWN", "routed_expert_down_proj.weight", "ffn_routed_down.weight", ["Q8_0"]),
        ("NORM", "routed_expert_norm.weight", "ffn_routed_norm.weight", ["F32"]),
        ("UP", "routed_expert_up_proj.weight", "ffn_routed_up.weight", ["Q8_0"]),
    ):
        escaped_source = source.replace(".", r"\.")
        rules.append(
            _rule(
                f"K3-LATENT-{component}",
                f"moe.latent_{component.lower()}",
                f"moe.latent_{component.lower()}",
                GroupRelation.ONE_TO_ONE,
                "moe_layers:1-92",
                layer + rf"block_sparse_moe\.{escaped_source}",
                [target + suffix.replace(".", r"\.")],
                "BF16",
                target_types,
            )
        )
    for component in ("gate", "up", "down"):
        rules.append(
            _rule(
                f"K3-DENSE-{component.upper()}",
                f"dense.{component}",
                f"dense.{component}",
                GroupRelation.ONE_TO_ONE,
                "dense_layer:0",
                layer + rf"mlp\.{component}_proj\.weight",
                [target + rf"ffn_{component}\.weight"],
                "BF16",
                ["Q8_0"],
            )
        )
    for rule_id, source_family, target_family, source_suffix, target_suffix, types in (
        (
            "K3-ATTN-NORM",
            "attention.input_norm",
            "attention.input_norm",
            "input_layernorm.weight",
            "attn_norm.weight",
            ["F32"],
        ),
        (
            "K3-FFN-NORM",
            "ffn.input_norm",
            "ffn.input_norm",
            "post_attention_layernorm.weight",
            "ffn_norm.weight",
            ["F32"],
        ),
        (
            "K3-ATTN-OUTPUT",
            "attention.output",
            "attention.output",
            "self_attn.o_proj.weight",
            "attn_output.weight",
            ["Q8_0"],
        ),
    ):
        rules.append(
            _rule(
                rule_id,
                source_family,
                target_family,
                GroupRelation.ONE_TO_ONE,
                "all_layers:0-92",
                layer + source_suffix.replace(".", r"\."),
                [target + target_suffix.replace(".", r"\.")],
                "BF16",
                types,
            )
        )
    for rule_id, source_family, target_family, source_name, target_name, target_types in (
        (
            "K3-TOKEN-EMBEDDING",
            "model.token_embedding",
            "model.token_embedding",
            r"language_model\.model\.embed_tokens\.weight",
            r"token_embd\.weight",
            ["Q8_0"],
        ),
        (
            "K3-OUTPUT-NORM",
            "model.output_norm",
            "model.output_norm",
            r"language_model\.model\.norm\.weight",
            r"output_norm\.weight",
            ["F32"],
        ),
        (
            "K3-OUTPUT",
            "model.output_projection",
            "model.output_projection",
            r"language_model\.lm_head\.weight",
            r"output\.weight",
            ["Q8_0"],
        ),
    ):
        rules.append(
            _rule(
                rule_id,
                source_family,
                target_family,
                GroupRelation.ONE_TO_ONE,
                "model",
                source_name,
                [target_name],
                "BF16",
                target_types,
                axis="model_component_preserved",
            )
        )
    kda_direct = (
        ("BETA", "b_proj.weight", "ssm_beta.weight", "kda.beta", ["F32"], "BF16"),
        ("DT", "dt_bias", "ssm_dt.bias", "kda.dt_bias", ["F32"], "F32"),
        ("FORGET-A", "f_a_proj.weight", "ssm_f_a.weight", "kda.forget_a", ["Q8_0"], "BF16"),
        ("FORGET-B", "f_b_proj.weight", "ssm_f_b.weight", "kda.forget_b", ["Q8_0"], "BF16"),
        ("KEY", "k_proj.weight", "attn_k.weight", "kda.key", ["Q8_0"], "BF16"),
        ("OUTPUT-NORM", "o_norm.weight", "ssm_norm.weight", "kda.output_norm", ["F32"], "F32"),
        ("QUERY", "q_proj.weight", "attn_q.weight", "kda.query", ["Q8_0"], "BF16"),
        ("VALUE", "v_proj.weight", "attn_v.weight", "kda.value", ["Q8_0"], "BF16"),
    )
    for rid, source_suffix, target_suffix, family, types, dtype in kda_direct:
        rules.append(
            _rule(
                f"K3-KDA-{rid}",
                family,
                family,
                GroupRelation.ONE_TO_ONE,
                "kda_layers:69",
                layer + "self_attn\\." + source_suffix.replace(".", r"\."),
                [target + target_suffix.replace(".", r"\.")],
                dtype,
                types,
                operation=(
                    "rename_dt_bias_to_dt_proj_bias_then_map_tensor_name"
                    if rid == "DT"
                    else "map_tensor_name_then_gguf_dimension_reversal"
                ),
            )
        )
    mla_direct = (
        ("KV-A", "kv_a_proj_with_mqa.weight", "attn_kv_a_mqa.weight", "mla.kv_a_mqa", ["Q8_0"]),
        ("KV-A-NORM", "kv_a_layernorm.weight", "attn_kv_a_norm.weight", "mla.kv_a_norm", ["F32"]),
        ("Q-A", "q_a_proj.weight", "attn_q_a.weight", "mla.query_a", ["Q8_0"]),
        ("Q-A-NORM", "q_a_layernorm.weight", "attn_q_a_norm.weight", "mla.query_a_norm", ["F32"]),
        ("Q-B", "q_b_proj.weight", "attn_q_b.weight", "mla.query_b", ["Q8_0"]),
    )
    for rid, source_suffix, target_suffix, family, types in mla_direct:
        rules.append(
            _rule(
                f"K3-MLA-{rid}",
                family,
                family,
                GroupRelation.ONE_TO_ONE,
                "mla_layers:24",
                layer + "self_attn\\." + source_suffix.replace(".", r"\."),
                [target + target_suffix.replace(".", r"\.")],
                "BF16",
                types,
            )
        )
    return rules


def _transform_rules() -> list[MappingRule]:
    layer = r"language_model\.model\.layers\.{layer}\."
    target = r"blk\.{layer}\."
    rules = [
        _rule(
            "K3-KDA-A",
            "kda.a_log",
            "kda.a",
            GroupRelation.LOGICAL_REALIZATION,
            "kda_layers:69",
            layer + r"self_attn\.A_log",
            [target + r"ssm_a"],
            "F32",
            ["F32"],
            shape="source_[128]_slice_first_96_to_target_[96]",
            axis="first_96_attention_heads",
            operation="take_first_num_attention_heads_then_negative_exponential",
        )
    ]
    for component in ("q", "k", "v"):
        rules.append(
            _rule(
                f"K3-KDA-CONV-{component.upper()}",
                f"kda.{component}_conv",
                {
                    "q": "kda.query_conv",
                    "k": "kda.key_conv",
                    "v": "kda.value_conv",
                }[component],
                GroupRelation.LOGICAL_REALIZATION,
                "kda_layers:69",
                layer + rf"self_attn\.{component}_conv1d\.weight",
                [target + rf"ssm_conv1d_{component}\.weight"],
                "F32",
                ["F32"],
                shape="reshape_[12288,1,4]_to_writer_[1,12288,1,4]",
                axis="channel_and_kernel_order_preserved",
                operation="pure_reshape_before_gguf_dimension_reversal",
            )
        )
    rules.extend(
        [
            _rule(
                "K3-GPROJ-KDA",
                "attention.g_proj",
                "g_proj.kda",
                GroupRelation.LOGICAL_REALIZATION,
                "kda_layers:69",
                layer + r"self_attn\.g_proj\.weight",
                [target + r"ssm_g\.weight"],
                "BF16",
                ["Q8_0"],
                axis="layer_schedule_selects_target_family",
                operation="select_ssm_g_by_pinned_kda_layer_schedule",
            ),
            _rule(
                "K3-GPROJ-MLA",
                "attention.g_proj",
                "g_proj.mla",
                GroupRelation.LOGICAL_REALIZATION,
                "mla_layers:24",
                layer + r"self_attn\.g_proj\.weight",
                [target + r"attn_gate\.weight"],
                "BF16",
                ["Q8_0"],
                axis="layer_schedule_selects_target_family",
                operation="select_attn_gate_by_pinned_mla_layer_schedule",
            ),
            _rule(
                "K3-MLA-KV-B-SPLIT",
                "mla.kv_b",
                "mla.key_b+value_b",
                GroupRelation.ONE_TO_MANY_SPLIT,
                "mla_layers:24",
                layer + r"self_attn\.kv_b_proj\.weight",
                [target + r"attn_k_b\.weight", target + r"attn_v_b\.weight"],
                "BF16",
                ["Q8_0"],
                target_cardinality=2,
                shape="view_[24576,512]_then_split_[128,128]_per_96_heads",
                axis="split_projection_axis_then_transpose_key_axes_1_2",
                operation="view_heads_split_key_value_then_transpose_key",
            ),
        ]
    )
    for rid, prefix, target_suffix, scope in (
        ("K3-ATTN-RES", "self_attention_res", "attn_res_score.weight", "all_layers:0-92"),
        ("K3-FFN-RES", "mlp_res", "ffn_res_score.weight", "all_layers:0-92"),
    ):
        rules.append(
            _rule(
                rid,
                f"attn_res.{prefix}",
                f"attn_res.{prefix}",
                GroupRelation.FUSED_TARGET,
                scope,
                layer + rf"{prefix}_(norm|proj)\.weight",
                [target + target_suffix.replace(".", r"\.")],
                "BF16",
                ["F32"],
                source_cardinality=2,
                shape="flatten_[7168]_and_[1,7168]_to_[7168]",
                axis="flatten_both_sources_to_embedding_axis",
                operation="elementwise_product_norm_times_squeezed_projection",
                ordering="norm_then_proj",
            )
        )
    rules.append(
        _rule(
            "K3-OUTPUT-RES",
            "attn_res.output",
            "attn_res.output_score",
            GroupRelation.FUSED_TARGET,
            "model",
            r"language_model\.model\.output_attn_res_(norm|proj)\.weight",
            [r"output_res_score\.weight"],
            "BF16",
            ["F32"],
            source_cardinality=2,
            shape="flatten_[7168]_and_[1,7168]_to_[7168]",
            axis="flatten_both_sources_to_embedding_axis",
            operation="elementwise_product_norm_times_squeezed_projection",
            ordering="norm_then_proj",
        )
    )
    return rules


def _packed_rules() -> list[MappingRule]:
    rules = []
    for wid, component, target_suffix, types in (
        ("w1", "gate", "ffn_gate_exps.weight", ["IQ1_S", "IQ2_XXS"]),
        ("w2", "down", "ffn_down_exps.weight", ["IQ1_S", "IQ3_XXS"]),
        ("w3", "up", "ffn_up_exps.weight", ["IQ1_S", "IQ2_XXS"]),
    ):
        escaped_target_suffix = target_suffix.replace(".", r"\.")
        rules.append(
            _rule(
                f"K3-EXP-{component.upper()}",
                f"routed_expert.{wid}",
                f"moe.packed_{component}",
                GroupRelation.MANY_TO_ONE_PACKED,
                "moe_layers:1-92",
                (
                    r"language_model\.model\.layers\.{layer}\.block_sparse_moe\."
                    rf"experts\.{{expert}}\.{wid}\.(weight_packed|weight_scale)"
                ),
                [rf"blk\.{{layer}}\.{escaped_target_suffix}"],
                "U8",
                types,
                source_cardinality=896,
                shape="repack_mxfp4_then_stack_expert_axis",
                axis="expert_axis=2_in_gguf_descriptor",
                operation="repack_each_weight_scale_pair_then_stack_experts_in_ordinal_order",
                ordering="expert_ordinal_0_through_895_weight_then_scale",
            )
        )
    return rules


def _exclusion_rules() -> list[MappingRule]:
    return [
        _rule(
            "K3-EXCLUDE-VISION",
            "source_auxiliary.vision_tower",
            "none",
            GroupRelation.INTENTIONALLY_EXCLUDED,
            "model_auxiliary",
            r"vision_tower\..+",
            [],
            "BF16",
            [],
            target_cardinality=0,
            shape="not_applicable",
            axis="not_applicable",
            operation="text_only_converter_skips_vision_tower",
        ),
        _rule(
            "K3-EXCLUDE-PROJECTOR",
            "source_auxiliary.mm_projector",
            "none",
            GroupRelation.INTENTIONALLY_EXCLUDED,
            "model_auxiliary",
            r"mm_projector\..+",
            [],
            "BF16",
            [],
            target_cardinality=0,
            shape="not_applicable",
            axis="not_applicable",
            operation="text_only_converter_skips_mm_projector",
        ),
    ]


def kimi_mapping_policy() -> MappingPolicy:
    return MappingPolicy(
        source_model_pack="kimi-k3",
        target_model_pack="kimi-k3",
        converter_revision=CONVERTER_REVISION,
        converter_evidence_role=(
            "pinned Kimi K3 tensor naming, transforms, exclusions, and routed-expert packing"
        ),
        rules=[*_packed_rules(), *_direct_rules(), *_transform_rules()],
        exclusion_rules=_exclusion_rules(),
    )
