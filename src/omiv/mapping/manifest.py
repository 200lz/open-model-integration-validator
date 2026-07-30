"""Bounded safe loading for untrusted semantic mapping manifests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.mapping.models import (
    BackendFallbackRealization,
    FormatAliasRealization,
    MappingManifest,
    MappingSelector,
    MaterializedRealization,
    SynthesizedRealization,
)
from omiv.model_packs.base import ModelPack, ModelPackCapability
from omiv.model_packs.registry import detect_model_pack, get_model_pack

MAX_MANIFEST_BYTES = 256 * 1024
MAX_PATTERN_LENGTH = 256
ALLOWED_PLACEHOLDERS = {"layer"}


def _inspect_yaml(node: yaml.Node | None) -> None:
    if node is None:
        return
    if isinstance(node, yaml.MappingNode):
        keys: set[str] = set()
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                raise OmivInputError("invalid mapping manifest: mapping keys must be scalars")
            if key.value in keys:
                raise OmivInputError("invalid mapping manifest: duplicate mapping key")
            keys.add(key.value)
            _inspect_yaml(value)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _inspect_yaml(item)


def _validate_pattern(value: str, *, field: str) -> None:
    if len(value) > MAX_PATTERN_LENGTH:
        raise OmivInputError(f"invalid mapping manifest: {field} exceeds pattern limit")
    if any(character in value for character in ("\\", "/", "\0", "*", "?", "[", "]")):
        raise OmivInputError(f"invalid mapping manifest: {field} contains path or glob syntax")
    cursor = 0
    while "{" in value[cursor:] or "}" in value[cursor:]:
        opening = value.find("{", cursor)
        closing = value.find("}", cursor)
        if opening == -1 or closing == -1 or closing < opening:
            raise OmivInputError(f"invalid mapping manifest: invalid placeholder in {field}")
        placeholder = value[opening + 1 : closing]
        if placeholder not in ALLOWED_PLACEHOLDERS:
            raise OmivInputError(
                f"invalid mapping manifest: unsupported placeholder {{{placeholder}}}"
            )
        cursor = closing + 1


def _validate_selectors(manifest: MappingManifest) -> None:
    selectors: list[tuple[str, MappingSelector]] = []
    for rule in manifest.rules:
        selectors.extend(
            ((f"{rule.rule_id}.source", rule.source), (f"{rule.rule_id}.target", rule.target))
        )
        if rule.target.realization is not None:
            for alternative in rule.target.realization.alternatives:
                prefix = f"{rule.rule_id}.{alternative.realization_id}"
                if isinstance(alternative, MaterializedRealization | SynthesizedRealization):
                    selectors.append((f"{prefix}.tensor", alternative.tensor))
                elif isinstance(alternative, FormatAliasRealization):
                    selectors.extend(
                        (
                            (f"{prefix}.alias_tensor", alternative.alias_tensor),
                            (f"{prefix}.backing_tensor", alternative.backing_tensor),
                        )
                    )
                elif isinstance(alternative, BackendFallbackRealization):
                    selectors.extend(
                        (
                            (f"{prefix}.omitted_tensor", alternative.omitted_tensor),
                            (f"{prefix}.fallback_tensor", alternative.fallback_tensor),
                        )
                    )
    selectors.extend(
        (f"ignored_sources[{index}]", item.selector)
        for index, item in enumerate(manifest.ignored_sources)
    )
    for field, selector in selectors:
        _validate_pattern(selector.canonical_identity, field=field)
        if selector.tensor_name is not None:
            _validate_pattern(selector.tensor_name, field=f"{field}.tensor_name")


def load_mapping_manifest(
    path: Path,
    *,
    requested_pack_id: str | None = None,
) -> MappingManifest:
    try:
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            raise OmivInputError(
                f"mapping manifest exceeds byte limit {MAX_MANIFEST_BYTES}: {size}"
            )
        text = path.read_text(encoding="utf-8")
        if any(
            isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
            for token in yaml.scan(text, Loader=yaml.SafeLoader)
        ):
            raise OmivInputError("invalid mapping manifest: YAML aliases/anchors are forbidden")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        _inspect_yaml(node)
        raw: Any = yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise OmivInputError("mapping manifest must be a mapping")
        manifest = MappingManifest.model_validate(raw)
        _validate_selectors(manifest)
        pack = resolve_manifest_model_pack(
            manifest, requested_pack_id=requested_pack_id
        )
        trusted_ids = {item.evidence_id for item in pack.provide_realization_evidence()}
        for rule in manifest.rules:
            if rule.target.realization is None:
                continue
            for alternative in rule.target.realization.alternatives:
                if (
                    isinstance(alternative, BackendFallbackRealization)
                    and alternative.backend_policy.evidence_id not in trusted_ids
                ):
                    raise OmivInputError(
                        "unsupported realization evidence ID: "
                        f"{alternative.backend_policy.evidence_id!r}"
                    )
        return manifest
    except OmivInputError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise OmivInputError(f"invalid mapping manifest: {exc}") from exc


def resolve_manifest_model_pack(
    manifest: MappingManifest,
    *,
    requested_pack_id: str | None = None,
) -> ModelPack:
    """Resolve and verify explicit or metadata-bounded pack selection."""
    reference = manifest.model_pack
    if requested_pack_id is not None:
        pack = get_model_pack(requested_pack_id)
        if reference is not None and reference.pack_id != pack.pack_id:
            raise OmivInputError("requested model pack does not match mapping manifest model_pack")
    elif reference is not None:
        pack = get_model_pack(reference.pack_id)
    else:
        pack = detect_model_pack(
            model_family=manifest.model_family,
            capability=ModelPackCapability.SEMANTIC_MAPPING,
        )
    pack.require(ModelPackCapability.SEMANTIC_MAPPING)
    if pack.model_family != manifest.model_family:
        raise OmivInputError("model pack family does not match mapping manifest model_family")
    if reference is not None:
        if reference.pack_schema_version != pack.pack_schema_version:
            raise OmivInputError("unsupported model-pack schema version")
        if pack.pack_version < reference.minimum_pack_version:
            raise OmivInputError("installed model-pack version is too old")
    if manifest.source_format not in pack.supported_source_formats:
        raise OmivInputError("model pack does not support mapping source format")
    if manifest.target_format not in pack.supported_target_formats:
        raise OmivInputError("model pack does not support mapping target format")
    return pack
