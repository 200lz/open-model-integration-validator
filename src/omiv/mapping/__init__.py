"""Declarative cross-format semantic tensor mapping validation."""

from omiv.mapping.manifest import load_mapping_manifest
from omiv.mapping.validator import validate_semantic_mapping

__all__ = ["load_mapping_manifest", "validate_semantic_mapping"]
