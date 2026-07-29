"""Load the evidence-bounded Kimi K3 validation schema."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError, model_validator

from omiv.errors import OmivInputError
from omiv.model_packs.kimi_k3.contracts import (
    ATTENTION_RESIDUAL_COMPONENT_SET,
    MODEL_ATTENTION_RESIDUAL_COMPONENT_SET,
    PHASE1_EXPERT_COMPONENT_SET,
    SHARED_EXPERT_COMPONENT_SET,
    AttentionResidualComponent,
    DescriptorConsistencyPolicy,
    DuplicateTensorPolicy,
    ExpertComponent,
    ExpertSetPolicy,
    ModelAttentionResidualComponent,
    SharedExpertComponent,
    UnclassifiedTensorPolicy,
)


class KimiK3Schema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    model: str
    expected_layer_ids: list[int]
    expected_dense_layer_ids: list[int]
    expected_moe_layer_ids: list[int]
    required_mla_tail_layers: list[int]
    expert_set_policy: ExpertSetPolicy
    required_expert_components: list[ExpertComponent]
    required_shared_expert_components: list[SharedExpertComponent]
    require_g_proj: StrictBool
    required_attention_residual_components: list[AttentionResidualComponent]
    required_model_attention_residual_components: list[ModelAttentionResidualComponent]
    unclassified_tensor_policy: UnclassifiedTensorPolicy
    duplicate_tensor_policy: DuplicateTensorPolicy
    descriptor_consistency_policy: DescriptorConsistencyPolicy

    @model_validator(mode="after")
    def validate_contract(self) -> "KimiK3Schema":
        for field_name in (
            "expected_layer_ids",
            "expected_dense_layer_ids",
            "expected_moe_layer_ids",
            "required_mla_tail_layers",
            "required_expert_components",
            "required_shared_expert_components",
            "required_attention_residual_components",
            "required_model_attention_residual_components",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} contains duplicates")
        if set(self.required_expert_components) != PHASE1_EXPERT_COMPONENT_SET:
            raise ValueError(
                "required_expert_components must contain exactly the Phase 1 "
                "expert-component vocabulary"
            )
        if (
            set(self.required_shared_expert_components)
            != SHARED_EXPERT_COMPONENT_SET
        ):
            raise ValueError(
                "required_shared_expert_components must contain exactly the "
                "Phase 2 shared-expert vocabulary"
            )
        if (
            set(self.required_attention_residual_components)
            != ATTENTION_RESIDUAL_COMPONENT_SET
        ):
            raise ValueError(
                "required_attention_residual_components must contain exactly the "
                "Phase 2 per-layer Attention Residual vocabulary"
            )
        if (
            set(self.required_model_attention_residual_components)
            != MODEL_ATTENTION_RESIDUAL_COMPONENT_SET
        ):
            raise ValueError(
                "required_model_attention_residual_components must contain exactly "
                "the Phase 2 model Attention Residual vocabulary"
            )
        if self.require_g_proj is not True:
            raise ValueError("require_g_proj must be true for the Phase 2 contract")
        return self


def load_schema(path: Path) -> KimiK3Schema:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return KimiK3Schema.model_validate(raw)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise OmivInputError(f"invalid schema: {exc}") from exc
