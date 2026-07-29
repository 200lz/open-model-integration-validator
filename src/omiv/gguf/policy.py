"""Load and validate GGUF comparison policies."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFComparisonPolicy


def load_gguf_policy(path: Path) -> GGUFComparisonPolicy:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        policy = GGUFComparisonPolicy.model_validate(raw)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise OmivInputError(f"invalid GGUF comparison policy: {exc}") from exc

    metadata_keys = [rule.key for rule in policy.metadata_rules]
    if len(metadata_keys) != len(set(metadata_keys)):
        raise OmivInputError("invalid GGUF comparison policy: duplicate metadata rule")
    architecture_rule = next(
        (rule for rule in policy.metadata_rules if rule.key == "general.architecture"),
        None,
    )
    if architecture_rule is not None and architecture_rule.action != "require_equal":
        raise OmivInputError(
            "invalid GGUF comparison policy: general.architecture cannot be "
            "ordinary allowed, ignored, or warning drift"
        )
    transitions = [
        (rule.source_type, rule.target_type, rule.selector)
        for rule in policy.type_transition_rules
    ]
    if len(transitions) != len(set(transitions)):
        raise OmivInputError(
            "invalid GGUF comparison policy: duplicate type transition rule"
        )
    return policy
