"""Load the evidence-bounded Kimi K3 validation schema."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from omiv.contracts import (
    PHASE1_EXPERT_COMPONENT_SET,
    ExpertComponent,
    ExpertSetPolicy,
)
from omiv.errors import OmivInputError


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

    @model_validator(mode="after")
    def validate_contract(self) -> "KimiK3Schema":
        for field_name in (
            "expected_layer_ids",
            "expected_dense_layer_ids",
            "expected_moe_layer_ids",
            "required_mla_tail_layers",
            "required_expert_components",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} contains duplicates")
        if set(self.required_expert_components) != PHASE1_EXPERT_COMPONENT_SET:
            raise ValueError(
                "required_expert_components must contain exactly the Phase 1 "
                "expert-component vocabulary"
            )
        return self


def load_schema(path: Path) -> KimiK3Schema:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return KimiK3Schema.model_validate(raw)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise OmivInputError(f"invalid schema: {exc}") from exc
