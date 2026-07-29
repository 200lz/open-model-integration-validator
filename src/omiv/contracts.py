"""Fixed Phase 1 schema vocabulary shared by normalization and validation."""

from typing import Literal

ExpertSetPolicy = Literal["derive_from_observed_consensus"]
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
