"""Load and validate GGUF comparison policies."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFComparisonPolicy


def _reject_duplicate_mapping_keys(node: Any) -> None:
    if isinstance(node, yaml.MappingNode):
        scalar_keys = [
            key.value
            for key, _ in node.value
            if isinstance(key, yaml.ScalarNode)
        ]
        if len(scalar_keys) != len(set(scalar_keys)):
            raise OmivInputError(
                "invalid GGUF comparison policy: duplicate mapping key"
            )
        for key, value in node.value:
            _reject_duplicate_mapping_keys(key)
            _reject_duplicate_mapping_keys(value)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _reject_duplicate_mapping_keys(item)


def load_gguf_policy(path: Path) -> GGUFComparisonPolicy:
    try:
        text = path.read_text(encoding="utf-8")
        _reject_duplicate_mapping_keys(yaml.compose(text))
        raw = yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise OmivInputError("policy must be a mapping")
        if "policy_schema_version" not in raw or "policy_id" not in raw:
            raise OmivInputError(
                "policy requires explicit policy_schema_version and policy_id"
            )
        policy = GGUFComparisonPolicy.model_validate(raw)
    except OmivInputError:
        raise
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
