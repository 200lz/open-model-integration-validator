"""Declarative cross-format semantic tensor mapping validation."""

from __future__ import annotations

from typing import Any

__all__ = ["load_mapping_manifest", "validate_semantic_mapping"]


def __getattr__(name: str) -> Any:
    if name == "load_mapping_manifest":
        from omiv.mapping.manifest import load_mapping_manifest

        return load_mapping_manifest
    if name == "validate_semantic_mapping":
        from omiv.mapping.validator import validate_semantic_mapping

        return validate_semantic_mapping
    raise AttributeError(name)
