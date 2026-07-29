"""Fixed Phase 1 schema vocabulary shared by normalization and validation."""

from typing import Literal

ExpertSetPolicy = Literal["derive_from_observed_consensus"]
UnclassifiedTensorPolicy = Literal["warn"]
DuplicateTensorPolicy = Literal["reject"]
DescriptorConsistencyPolicy = Literal["require_unanimous"]
ExpertComponent = Literal[
    "w1.weight_packed",
    "w1.weight_scale",
    "w2.weight_packed",
    "w2.weight_scale",
    "w3.weight_packed",
    "w3.weight_scale",
]

PHASE1_EXPERT_COMPONENTS: tuple[ExpertComponent, ...] = (
    "w1.weight_packed",
    "w1.weight_scale",
    "w2.weight_packed",
    "w2.weight_scale",
    "w3.weight_packed",
    "w3.weight_scale",
)
PHASE1_EXPERT_COMPONENT_SET = frozenset(PHASE1_EXPERT_COMPONENTS)

SharedExpertComponent = Literal[
    "gate_proj.weight",
    "up_proj.weight",
    "down_proj.weight",
]
SHARED_EXPERT_COMPONENTS: tuple[SharedExpertComponent, ...] = (
    "gate_proj.weight",
    "up_proj.weight",
    "down_proj.weight",
)
SHARED_EXPERT_COMPONENT_SET = frozenset(SHARED_EXPERT_COMPONENTS)

AttentionResidualComponent = Literal[
    "self_attention_res_proj.weight",
    "self_attention_res_norm.weight",
    "mlp_res_proj.weight",
    "mlp_res_norm.weight",
]
ATTENTION_RESIDUAL_COMPONENTS: tuple[AttentionResidualComponent, ...] = (
    "self_attention_res_proj.weight",
    "self_attention_res_norm.weight",
    "mlp_res_proj.weight",
    "mlp_res_norm.weight",
)
ATTENTION_RESIDUAL_COMPONENT_SET = frozenset(ATTENTION_RESIDUAL_COMPONENTS)

ModelAttentionResidualComponent = Literal[
    "output_attn_res_proj.weight",
    "output_attn_res_norm.weight",
]
MODEL_ATTENTION_RESIDUAL_COMPONENTS: tuple[ModelAttentionResidualComponent, ...] = (
    "output_attn_res_proj.weight",
    "output_attn_res_norm.weight",
)
MODEL_ATTENTION_RESIDUAL_COMPONENT_SET = frozenset(
    MODEL_ATTENTION_RESIDUAL_COMPONENTS
)
