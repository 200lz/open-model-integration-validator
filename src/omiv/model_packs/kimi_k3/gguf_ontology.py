"""Pinned target-side GGUF ontology for Kimi K3.

The vocabulary and loader-order dimensions are grounded in the observed pinned
UD-IQ1_M split inventory and llama.cpp commit
``cf67f0d24511864d2d3da0769108fd6fc16d00d1``.  This module deliberately
classifies physical GGUF tensors only; it does not describe a source-to-target
mapping.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from omiv.canonical import canonical_sha256
from omiv.hf.models import CanonicalTensorIdentity
from omiv.model_packs.base import TensorClassification
from omiv.models import StrictModel

PINNED_LLAMA_CPP_REVISION = "cf67f0d24511864d2d3da0769108fd6fc16d00d1"
LAYER_NAME_RE = re.compile(
    r"^blk\.(?P<layer>0|[1-9][0-9]*)\."
    r"(?P<component>[a-z][a-z0-9_]*)(?:\.(?P<parameter>weight|bias))?$"
)


class TensorScope(StrEnum):
    MODEL = "model"
    ALL_LAYERS = "all_layers"
    KDA_LAYERS = "kda_layers"
    MLA_LAYERS = "mla_layers"
    DENSE_LAYERS = "dense_layers"
    MOE_LAYERS = "moe_layers"


class PhysicalTensorKind(StrEnum):
    MODEL = "model_level"
    LAYER = "layer_level"
    PACKED = "packed_tensor_family"


class ShapeRelation(StrEnum):
    IDENTITY = "identity"
    REVERSE_GGUF_DIMENSIONS = "reverse_gguf_dimensions"


class TensorFamilyRule(StrictModel):
    family_id: str
    component: str
    parameter: Literal["weight", "bias", "none"]
    scope: TensorScope
    physical_kind: PhysicalTensorKind
    module: str
    expected_dimensions: list[int]
    shape_relation: ShapeRelation
    dimension_roles: list[str]
    allowed_ggml_types: list[str]

    @model_validator(mode="after")
    def consistent(self) -> TensorFamilyRule:
        if len(self.expected_dimensions) != len(self.dimension_roles):
            raise ValueError("dimension roles must match the physical rank")
        if len(self.allowed_ggml_types) != len(set(self.allowed_ggml_types)):
            raise ValueError("GGML type policy contains duplicates")
        return self

    @property
    def expected_name_suffix(self) -> str:
        return self.component if self.parameter == "none" else f"{self.component}.{self.parameter}"

    def normalized_dimensions(self, dimensions: list[int]) -> list[int]:
        if self.shape_relation == ShapeRelation.REVERSE_GGUF_DIMENSIONS:
            return list(reversed(dimensions))
        return list(dimensions)


def _r(
    family_id: str,
    component: str,
    parameter: Literal["weight", "bias", "none"],
    scope: TensorScope,
    kind: PhysicalTensorKind,
    module: str,
    dimensions: tuple[int, ...],
    roles: tuple[str, ...],
    types: tuple[str, ...],
    shape_relation: ShapeRelation | None = None,
) -> TensorFamilyRule:
    relation = shape_relation or (
        ShapeRelation.IDENTITY
        if len(dimensions) == 1
        else ShapeRelation.REVERSE_GGUF_DIMENSIONS
    )
    return TensorFamilyRule(
        family_id=family_id,
        component=component,
        parameter=parameter,
        scope=scope,
        physical_kind=kind,
        module=module,
        expected_dimensions=list(dimensions),
        shape_relation=relation,
        dimension_roles=list(roles),
        allowed_ggml_types=list(types),
    )


def _default_rules() -> list[TensorFamilyRule]:
    f32 = ("F32",)
    q8 = ("Q8_0",)
    matrix_roles = ("input", "output")
    rules = [
        _r(
            "model.token_embedding",
            "token_embd",
            "weight",
            TensorScope.MODEL,
            PhysicalTensorKind.MODEL,
            "embedding",
            (7168, 163840),
            ("embedding", "vocabulary"),
            q8,
        ),
        _r(
            "model.output_projection",
            "output",
            "weight",
            TensorScope.MODEL,
            PhysicalTensorKind.MODEL,
            "output",
            (7168, 163840),
            ("embedding", "vocabulary"),
            q8,
        ),
        _r(
            "model.output_norm",
            "output_norm",
            "weight",
            TensorScope.MODEL,
            PhysicalTensorKind.MODEL,
            "normalization",
            (7168,),
            ("embedding",),
            f32,
        ),
        _r(
            "attn_res.output_score",
            "output_res_score",
            "weight",
            TensorScope.MODEL,
            PhysicalTensorKind.MODEL,
            "attention_residual",
            (7168,),
            ("embedding",),
            f32,
        ),
        _r(
            "attention.input_norm",
            "attn_norm",
            "weight",
            TensorScope.ALL_LAYERS,
            PhysicalTensorKind.LAYER,
            "attention",
            (7168,),
            ("embedding",),
            f32,
        ),
        _r(
            "attention.output",
            "attn_output",
            "weight",
            TensorScope.ALL_LAYERS,
            PhysicalTensorKind.LAYER,
            "attention",
            (12288, 7168),
            matrix_roles,
            q8,
        ),
        _r(
            "ffn.input_norm",
            "ffn_norm",
            "weight",
            TensorScope.ALL_LAYERS,
            PhysicalTensorKind.LAYER,
            "ffn",
            (7168,),
            ("embedding",),
            f32,
        ),
        _r(
            "attn_res.attention_score",
            "attn_res_score",
            "weight",
            TensorScope.ALL_LAYERS,
            PhysicalTensorKind.LAYER,
            "attention_residual",
            (7168,),
            ("embedding",),
            f32,
        ),
        _r(
            "attn_res.ffn_score",
            "ffn_res_score",
            "weight",
            TensorScope.ALL_LAYERS,
            PhysicalTensorKind.LAYER,
            "attention_residual",
            (7168,),
            ("embedding",),
            f32,
        ),
        _r(
            "kda.query",
            "attn_q",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (7168, 12288),
            matrix_roles,
            q8,
        ),
        _r(
            "kda.key",
            "attn_k",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (7168, 12288),
            matrix_roles,
            q8,
        ),
        _r(
            "kda.value",
            "attn_v",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (7168, 12288),
            matrix_roles,
            q8,
        ),
        _r(
            "kda.a",
            "ssm_a",
            "none",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (96,),
            ("attention_head",),
            f32,
        ),
        _r(
            "kda.beta",
            "ssm_beta",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (7168, 96),
            matrix_roles,
            f32,
        ),
        _r(
            "kda.query_conv",
            "ssm_conv1d_q",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (4, 1, 12288),
            ("kernel", "channel_group", "inner"),
            f32,
        ),
        _r(
            "kda.key_conv",
            "ssm_conv1d_k",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (4, 1, 12288),
            ("kernel", "channel_group", "inner"),
            f32,
        ),
        _r(
            "kda.value_conv",
            "ssm_conv1d_v",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (4, 1, 12288),
            ("kernel", "channel_group", "inner"),
            f32,
        ),
        _r(
            "kda.dt_bias",
            "ssm_dt",
            "bias",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (12288,),
            ("inner",),
            f32,
        ),
        _r(
            "kda.forget_a",
            "ssm_f_a",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (7168, 128),
            matrix_roles,
            q8,
        ),
        _r(
            "kda.forget_b",
            "ssm_f_b",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (128, 12288),
            matrix_roles,
            q8,
        ),
        _r(
            "g_proj.kda",
            "ssm_g",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "g_proj",
            (7168, 12288),
            matrix_roles,
            q8,
        ),
        _r(
            "kda.output_norm",
            "ssm_norm",
            "weight",
            TensorScope.KDA_LAYERS,
            PhysicalTensorKind.LAYER,
            "kda_attention",
            (128,),
            ("head_dimension",),
            f32,
        ),
        _r(
            "g_proj.mla",
            "attn_gate",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "g_proj",
            (7168, 12288),
            matrix_roles,
            q8,
        ),
        _r(
            "mla.key_b",
            "attn_k_b",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (128, 512, 96),
            ("value_head_dimension", "kv_rank", "head"),
            q8,
        ),
        _r(
            "mla.kv_a_mqa",
            "attn_kv_a_mqa",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (7168, 576),
            matrix_roles,
            q8,
        ),
        _r(
            "mla.kv_a_norm",
            "attn_kv_a_norm",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (512,),
            ("kv_rank",),
            f32,
        ),
        _r(
            "mla.query_a",
            "attn_q_a",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (7168, 1536),
            matrix_roles,
            q8,
        ),
        _r(
            "mla.query_a_norm",
            "attn_q_a_norm",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (1536,),
            ("query_rank",),
            f32,
        ),
        _r(
            "mla.query_b",
            "attn_q_b",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (1536, 18432),
            matrix_roles,
            q8,
        ),
        _r(
            "mla.value_b",
            "attn_v_b",
            "weight",
            TensorScope.MLA_LAYERS,
            PhysicalTensorKind.LAYER,
            "mla_attention",
            (512, 128, 96),
            ("kv_rank", "value_head_dimension", "head"),
            q8,
        ),
        _r(
            "dense.down",
            "ffn_down",
            "weight",
            TensorScope.DENSE_LAYERS,
            PhysicalTensorKind.LAYER,
            "dense_ffn",
            (33792, 7168),
            matrix_roles,
            q8,
        ),
        _r(
            "dense.gate",
            "ffn_gate",
            "weight",
            TensorScope.DENSE_LAYERS,
            PhysicalTensorKind.LAYER,
            "dense_ffn",
            (7168, 33792),
            matrix_roles,
            q8,
        ),
        _r(
            "dense.up",
            "ffn_up",
            "weight",
            TensorScope.DENSE_LAYERS,
            PhysicalTensorKind.LAYER,
            "dense_ffn",
            (7168, 33792),
            matrix_roles,
            q8,
        ),
        _r(
            "moe.router_bias",
            "exp_probs_b",
            "bias",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "moe_router",
            (896,),
            ("expert",),
            f32,
        ),
        _r(
            "moe.router",
            "ffn_gate_inp",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "moe_router",
            (7168, 896),
            matrix_roles,
            f32,
        ),
        _r(
            "moe.packed_down",
            "ffn_down_exps",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.PACKED,
            "routed_experts",
            (3072, 3584, 896),
            ("expert_intermediate", "expert_latent", "expert"),
            ("IQ1_S", "IQ3_XXS"),
            ShapeRelation.IDENTITY,
        ),
        _r(
            "moe.packed_gate",
            "ffn_gate_exps",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.PACKED,
            "routed_experts",
            (3584, 3072, 896),
            ("expert_latent", "expert_intermediate", "expert"),
            ("IQ1_S", "IQ2_XXS"),
            ShapeRelation.IDENTITY,
        ),
        _r(
            "moe.packed_up",
            "ffn_up_exps",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.PACKED,
            "routed_experts",
            (3584, 3072, 896),
            ("expert_latent", "expert_intermediate", "expert"),
            ("IQ1_S", "IQ2_XXS"),
            ShapeRelation.IDENTITY,
        ),
        _r(
            "moe.shared_down",
            "ffn_down_shexp",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "shared_experts",
            (6144, 7168),
            matrix_roles,
            q8,
        ),
        _r(
            "moe.shared_gate",
            "ffn_gate_shexp",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "shared_experts",
            (7168, 6144),
            matrix_roles,
            q8,
        ),
        _r(
            "moe.shared_up",
            "ffn_up_shexp",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "shared_experts",
            (7168, 6144),
            matrix_roles,
            q8,
        ),
        _r(
            "moe.latent_down",
            "ffn_routed_down",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "latent_moe",
            (7168, 3584),
            matrix_roles,
            q8,
        ),
        _r(
            "moe.latent_norm",
            "ffn_routed_norm",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "latent_moe",
            (3584,),
            ("expert_latent",),
            f32,
        ),
        _r(
            "moe.latent_up",
            "ffn_routed_up",
            "weight",
            TensorScope.MOE_LAYERS,
            PhysicalTensorKind.LAYER,
            "latent_moe",
            (3584, 7168),
            matrix_roles,
            q8,
        ),
    ]
    return sorted(rules, key=lambda item: item.family_id)


class KimiK3GGUFOntologyPolicy(StrictModel):
    policy_schema: Literal["omiv.kimi-k3-gguf-ontology-policy.v1"] = (
        "omiv.kimi-k3-gguf-ontology-policy.v1"
    )
    policy_id: Literal["omiv.kimi-k3.gguf-target-ontology.v1"] = (
        "omiv.kimi-k3.gguf-target-ontology.v1"
    )
    evidence_sources: list[str] = Field(
        default_factory=lambda: [
            "omiv.kimi-k3.checkpoint-ontology.v2",
            f"llama.cpp@{PINNED_LLAMA_CPP_REVISION}:kimi-k3-loader-and-tensor-names",
            "unsloth/Kimi-K3-GGUF@3d4b61ab4b6789d401191c476cbb4567246db8f5:"
            "UD-IQ1_M-header-descriptors",
        ]
    )
    expected_architecture: Literal["kimi-k3"] = "kimi-k3"
    expected_layer_ids: list[int] = Field(default_factory=lambda: list(range(93)))
    expected_dense_layer_ids: list[int] = Field(default_factory=lambda: [0])
    expected_moe_layer_ids: list[int] = Field(default_factory=lambda: list(range(1, 93)))
    expected_mla_layer_ids: list[int] = Field(default_factory=lambda: [*range(3, 92, 4), 92])
    expected_kda_layer_ids: list[int] = Field(
        default_factory=lambda: [
            layer for layer in range(93) if layer not in {*range(3, 92, 4), 92}
        ]
    )
    expected_expert_count: int = 896
    expected_attention_residual_block_size: int = 12
    family_rules: list[TensorFamilyRule] = Field(default_factory=_default_rules)
    maximum_unclassified_details: int = 100

    @model_validator(mode="after")
    def consistent(self) -> KimiK3GGUFOntologyPolicy:
        expected = set(self.expected_layer_ids)
        kda = set(self.expected_kda_layer_ids)
        mla = set(self.expected_mla_layer_ids)
        if kda & mla or kda | mla != expected:
            raise ValueError("KDA and MLA schedules must be disjoint and complete")
        if len(kda) != 69 or len(mla) != 24 or {91, 92} - mla:
            raise ValueError("Kimi K3 KDA/MLA schedule contract is invalid")
        if set(self.expected_dense_layer_ids) | set(self.expected_moe_layer_ids) != expected:
            raise ValueError("dense and MoE schedules must cover every layer")
        if set(self.expected_dense_layer_ids) & set(self.expected_moe_layer_ids):
            raise ValueError("dense and MoE schedules must be disjoint")
        family_ids = [item.family_id for item in self.family_rules]
        suffixes = [item.expected_name_suffix for item in self.family_rules]
        if len(family_ids) != len(set(family_ids)) or len(suffixes) != len(set(suffixes)):
            raise ValueError("ontology family rules must have unique IDs and names")
        return self

    @property
    def digest(self) -> str:
        return canonical_sha256(self.model_dump(mode="json"))

    def rule_by_suffix(self) -> dict[str, TensorFamilyRule]:
        return {item.expected_name_suffix: item for item in self.family_rules}

    def expected_layers_for(self, rule: TensorFamilyRule) -> list[int]:
        return {
            TensorScope.MODEL: [],
            TensorScope.ALL_LAYERS: self.expected_layer_ids,
            TensorScope.KDA_LAYERS: self.expected_kda_layer_ids,
            TensorScope.MLA_LAYERS: self.expected_mla_layer_ids,
            TensorScope.DENSE_LAYERS: self.expected_dense_layer_ids,
            TensorScope.MOE_LAYERS: self.expected_moe_layer_ids,
        }[rule.scope]


class ParsedGGUFName(StrictModel):
    name: str
    layer_id: int | None
    suffix: str
    family_id: str | None
    malformed: bool


def parse_gguf_name(
    name: str,
    policy: KimiK3GGUFOntologyPolicy | None = None,
) -> ParsedGGUFName:
    selected = policy or KimiK3GGUFOntologyPolicy()
    rules = selected.rule_by_suffix()
    model_rule = rules.get(name)
    if model_rule is not None and model_rule.scope == TensorScope.MODEL:
        return ParsedGGUFName(
            name=name,
            layer_id=None,
            suffix=name,
            family_id=model_rule.family_id,
            malformed=False,
        )
    match = LAYER_NAME_RE.fullmatch(name)
    if match is None:
        return ParsedGGUFName(
            name=name,
            layer_id=None,
            suffix=name,
            family_id=None,
            malformed=name.startswith("blk."),
        )
    suffix = match.group("component")
    parameter = match.group("parameter")
    if parameter is not None:
        suffix = f"{suffix}.{parameter}"
    rule = rules.get(suffix)
    return ParsedGGUFName(
        name=name,
        layer_id=int(match.group("layer")),
        suffix=suffix,
        family_id=None if rule is None else rule.family_id,
        malformed=False,
    )


def classify_gguf_tensor(name: str) -> TensorClassification:
    policy = KimiK3GGUFOntologyPolicy()
    parsed = parse_gguf_name(name, policy)
    if parsed.family_id is None:
        return TensorClassification(canonical=None)
    rule = next(item for item in policy.family_rules if item.family_id == parsed.family_id)
    parameter: Literal["weight", "bias"] = "bias" if rule.parameter == "bias" else "weight"
    identity = (
        f"kimi-k3.{rule.family_id}"
        if parsed.layer_id is None
        else f"kimi-k3.layer.{parsed.layer_id}.{rule.family_id}"
    )
    return TensorClassification(
        canonical=CanonicalTensorIdentity(
            identity=identity,
            scope="model" if parsed.layer_id is None else "layer",
            layer_id=parsed.layer_id,
            module=rule.module,
            component=rule.family_id,
            parameter=parameter,
        ),
        layer_component=None if parsed.layer_id is None else rule.family_id,
    )
