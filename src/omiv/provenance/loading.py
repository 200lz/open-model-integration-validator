"""Bounded duplicate-key-safe provenance and conversion-spec loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any, TypeVar, cast

import yaml
from pydantic import BaseModel, ValidationError

from omiv.errors import OmivInputError
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.provenance.models import ProvenanceEnvelope

MAX_PROVENANCE_BYTES = 2 * 1024 * 1024
ModelT = TypeVar("ModelT", bound=BaseModel)


def _inspect_yaml(node: yaml.Node | None) -> None:
    if node is None:
        return
    if isinstance(node, yaml.MappingNode):
        keys: set[str] = set()
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                raise OmivInputError("mapping keys must be scalar strings")
            if key.value in keys:
                raise OmivInputError(f"duplicate mapping key {key.value!r}")
            keys.add(key.value)
            _inspect_yaml(value)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _inspect_yaml(item)


def load_data_file(path: Path, *, max_bytes: int = MAX_PROVENANCE_BYTES) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OmivInputError(f"cannot read {path.name}: {exc}") from exc
    if len(raw) > max_bytes:
        raise OmivInputError(f"{path.name} exceeds byte limit {max_bytes}: {len(raw)}")
    if path.suffix.lower() == ".json":
        value = parse_bounded_json_bytes(
            raw,
            source_name=path.name,
            max_bytes=max_bytes,
        )
        return cast(dict[str, Any], value)
    try:
        text = raw.decode("utf-8", errors="strict")
        if any(
            isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
            for token in yaml.scan(text, Loader=yaml.SafeLoader)
        ):
            raise OmivInputError("YAML aliases and anchors are forbidden")
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        _inspect_yaml(node)
        value = yaml.safe_load(text)
    except UnicodeError as exc:
        raise OmivInputError(f"{path.name} is not valid UTF-8: {exc}") from exc
    except yaml.YAMLError as exc:
        raise OmivInputError(f"invalid YAML in {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise OmivInputError(f"{path.name} must contain a top-level object")
    return value


def load_model(path: Path, model_type: type[ModelT], *, label: str) -> ModelT:
    try:
        return model_type.model_validate(load_data_file(path))
    except ValidationError as exc:
        raise OmivInputError(f"invalid {label}: {exc}") from exc


def load_provenance_envelope(path: Path) -> ProvenanceEnvelope:
    value = load_data_file(path)
    provenance = value.get("provenance")
    if not isinstance(provenance, dict):
        raise OmivInputError("invalid provenance: missing provenance payload")
    if provenance.get("provenance_schema") != "omiv.conversion-provenance.v1":
        raise OmivInputError("unsupported provenance schema")
    try:
        return ProvenanceEnvelope.model_validate(value)
    except ValidationError as exc:
        raise OmivInputError(f"invalid provenance: {exc}") from exc
