"""Secure local HF Safetensors inventory construction."""

from __future__ import annotations

import json
import os
import stat
from collections import Counter
from pathlib import Path
from typing import Any

from omiv.canonical import CANONICALIZATION_ID, canonical_sha256
from omiv.errors import OmivInputError
from omiv.hf.json_loader import load_bounded_json
from omiv.hf.limits import (
    MAX_CONFIG_BYTES,
    MAX_INDEX_BYTES,
    MAX_PROVENANCE_BYTES,
    MAX_SHARD_COUNT,
    MAX_TENSOR_COUNT,
    MAX_TENSOR_NAME_LENGTH,
)
from omiv.hf.models import (
    HFArtifactSummary,
    HFDiagnostic,
    HFInventory,
    HFProvenance,
    HFShardSummary,
    HFSmallFileSummary,
    HFSummary,
    HFTensorDescriptor,
)
from omiv.hf.safetensors import ParsedSafetensorsShard, parse_safetensors_header
from omiv.model_packs.base import ModelPack, ModelPackCapability
from omiv.model_packs.registry import detect_model_pack
from omiv.models import json_compatible

PROVENANCE_KEYS = {"repository", "revision", "source", "purpose"}


def _safe_shard_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise OmivInputError("index shard name must be a non-empty string")
    if (
        os.path.isabs(value)
        or "/" in value
        or "\\" in value
        or ".." in value
        or Path(value).name != value
    ):
        raise OmivInputError(f"unsafe index shard basename: {value!r}")
    if not value.endswith(".safetensors"):
        raise OmivInputError(f"unsupported shard file name: {value!r}")
    return value


def _resolve_regular_shard(root: Path, basename: str) -> Path:
    candidate = root / basename
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise OmivInputError(
            f"shard is missing or resolves outside model directory: {basename}"
        ) from exc
    try:
        mode = candidate.stat().st_mode
    except OSError as exc:
        raise OmivInputError(f"cannot stat shard {basename}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise OmivInputError(f"shard is not a regular file: {basename}")
    return candidate


def _load_layout(
    root: Path,
) -> tuple[
    LiteralLayout,
    list[Path],
    dict[str, str] | None,
    HFSmallFileSummary | None,
]:
    monolithic = root / "model.safetensors"
    index_path = root / "model.safetensors.index.json"
    if monolithic.exists() and index_path.exists():
        raise OmivInputError("both monolithic and indexed Safetensors layouts are present")
    if monolithic.exists():
        shard = _resolve_regular_shard(root, monolithic.name)
        extras = sorted(
            item.name
            for item in root.iterdir()
            if item.name != monolithic.name and item.name.endswith(".safetensors")
        )
        if extras:
            raise OmivInputError(f"undeclared Safetensors files in monolithic layout: {extras}")
        return "monolithic", [shard], None, None
    if not index_path.exists():
        raise OmivInputError("no supported Safetensors checkpoint layout found")

    index_raw, index_bytes = load_bounded_json(index_path, max_bytes=MAX_INDEX_BYTES)
    if set(index_raw) - {"metadata", "weight_map"}:
        raise OmivInputError("index contains unsupported top-level fields")
    weight_map_raw = index_raw.get("weight_map")
    if not isinstance(weight_map_raw, dict):
        raise OmivInputError("index weight_map must be an object")
    if len(weight_map_raw) > MAX_TENSOR_COUNT:
        raise OmivInputError("index weight_map exceeds tensor count limit")
    metadata = index_raw.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise OmivInputError("index metadata must be an object")
    weight_map: dict[str, str] = {}
    for tensor_name, shard_value in weight_map_raw.items():
        if (
            not isinstance(tensor_name, str)
            or not tensor_name
            or len(tensor_name) > MAX_TENSOR_NAME_LENGTH
        ):
            raise OmivInputError("index contains an invalid tensor name")
        weight_map[tensor_name] = _safe_shard_name(shard_value)
    basenames = sorted(set(weight_map.values()))
    if not basenames or len(basenames) > MAX_SHARD_COUNT:
        raise OmivInputError("index declares an invalid shard count")
    declared = set(basenames)
    actual = {item.name for item in root.iterdir() if item.name.endswith(".safetensors")}
    undeclared = sorted(actual - declared)
    if undeclared:
        raise OmivInputError(f"undeclared Safetensors shards: {undeclared}")
    shards = [_resolve_regular_shard(root, basename) for basename in basenames]
    index_summary = HFSmallFileSummary(
        file_name=index_path.name,
        byte_size=len(index_bytes),
        sha256=canonical_sha256(index_raw),
    )
    return "sharded", shards, weight_map, index_summary


LiteralLayout = str


def _parse_provenance(path: Path | None) -> HFProvenance:
    if path is None:
        return HFProvenance(available=False)
    raw, _ = load_bounded_json(path, max_bytes=MAX_PROVENANCE_BYTES)
    unexpected = set(raw) - PROVENANCE_KEYS
    if unexpected:
        raise OmivInputError(f"unsupported provenance keys: {sorted(unexpected)}")
    values: dict[str, str | None] = {}
    for key in PROVENANCE_KEYS:
        value = raw.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            raise OmivInputError(f"provenance {key} must be a non-empty string")
        if isinstance(value, str) and (os.path.isabs(value) or value.startswith("file:")):
            raise OmivInputError(f"provenance {key} must not contain an absolute path")
        values[key] = value
    return HFProvenance(available=True, **values)


def read_hf_inventory(
    model_dir: Path,
    *,
    provenance_path: Path | None = None,
    model_pack: ModelPack | None = None,
) -> HFInventory:
    try:
        root = model_dir.resolve(strict=True)
    except OSError as exc:
        raise OmivInputError(f"model directory does not exist: {model_dir}") from exc
    if not root.is_dir():
        raise OmivInputError("model-dir must be a directory")
    config_path = root / "config.json"
    if not config_path.is_file():
        raise OmivInputError("config.json is missing or not a regular file")
    config_raw, config_bytes = load_bounded_json(config_path, max_bytes=MAX_CONFIG_BYTES)
    if model_pack is None:
        model_family = config_raw.get("model_type")
        if not isinstance(model_family, str) or not model_family:
            raise OmivInputError("config model_type is required for model-pack detection")
        model_pack = detect_model_pack(
            model_family=model_family,
            capability=ModelPackCapability.HF_ONTOLOGY,
        )
    model_pack.require(ModelPackCapability.HF_ONTOLOGY)
    config = model_pack.validate_hf_config(config_raw)
    kind, shard_paths, weight_map, index_summary = _load_layout(root)
    parsed_shards = [parse_safetensors_header(path) for path in shard_paths]

    observed_shards: dict[str, str] = {}
    parsed_by_name: dict[str, tuple[ParsedSafetensorsShard, Any]] = {}
    diagnostics: list[HFDiagnostic] = []
    for shard in parsed_shards:
        diagnostics.extend(shard.diagnostics)
        for tensor in shard.tensors:
            if tensor.name in parsed_by_name:
                raise OmivInputError(f"duplicate tensor name across shards: {tensor.name}")
            parsed_by_name[tensor.name] = (shard, tensor)
            observed_shards[tensor.name] = shard.file_name
    if weight_map is not None:
        missing = sorted(set(weight_map) - set(parsed_by_name))
        undeclared = sorted(set(parsed_by_name) - set(weight_map))
        wrong_shard = sorted(
            name
            for name in set(weight_map) & set(parsed_by_name)
            if weight_map[name] != observed_shards[name]
        )
        if missing or undeclared or wrong_shard:
            raise OmivInputError(
                "index/header tensor mapping mismatch: "
                f"missing={missing[:10]}, undeclared={undeclared[:10]}, "
                f"wrong_shard={wrong_shard[:10]}"
            )
        index_raw, _ = load_bounded_json(
            root / "model.safetensors.index.json", max_bytes=MAX_INDEX_BYTES
        )
        metadata = index_raw.get("metadata") or {}
        total_size = metadata.get("total_size")
        if total_size is not None:
            if not isinstance(total_size, int) or isinstance(total_size, bool) or total_size < 0:
                raise OmivInputError("index metadata total_size must be nonnegative integer")
            measured = sum(
                tensor.data_offsets[1] - tensor.data_offsets[0]
                for _, tensor in parsed_by_name.values()
            )
            if total_size != measured:
                raise OmivInputError(
                    f"index total_size mismatch: declared={total_size}, measured={measured}"
                )

    tensors: list[HFTensorDescriptor] = []
    for name, (shard, tensor) in sorted(parsed_by_name.items()):
        classification = model_pack.classify_hf_tensor(name)
        tensors.append(
            HFTensorDescriptor(
                source_name=name,
                canonical=classification.canonical,
                classification=(
                    "classified" if classification.canonical is not None else "unclassified"
                ),
                dtype=tensor.dtype,
                shape=tensor.shape,
                shape_order="huggingface_safetensors",
                shard_file=shard.file_name,
                data_offsets=tensor.data_offsets,
                payload_byte_length=tensor.data_offsets[1] - tensor.data_offsets[0],
            )
        )
    ties, structural_diagnostics = model_pack.validate_hf_structure(tensors, config)
    diagnostics.extend(structural_diagnostics)
    unclassified = [tensor.source_name for tensor in tensors if tensor.canonical is None]
    if unclassified:
        diagnostics.append(
            HFDiagnostic(
                code="UNCLASSIFIED_TENSORS",
                severity="info",
                message="Physical tensors outside the selected ontology were retained",
                evidence={
                    "count": len(unclassified),
                    "examples": json_compatible(unclassified[:10]),
                },
            )
        )
    diagnostics.sort(
        key=lambda item: (
            item.code,
            item.message,
            json.dumps(item.evidence, sort_keys=True, separators=(",", ":")),
        )
    )
    shard_summaries = [
        HFShardSummary(
            index=index,
            count=len(parsed_shards),
            file_name=shard.file_name,
            byte_size=shard.byte_size,
            header_length=shard.header_length,
            payload_length=shard.payload_length,
        )
        for index, shard in enumerate(sorted(parsed_shards, key=lambda item: item.file_name))
    ]
    dtype_counts = Counter(tensor.dtype for tensor in tensors)
    layer_ids = sorted(
        {
            tensor.canonical.layer_id
            for tensor in tensors
            if tensor.canonical is not None and tensor.canonical.layer_id is not None
        }
    )
    inventory = HFInventory(
        schema="omiv.hf-inventory.v1",
        canonicalization=CANONICALIZATION_ID,
        canonical_sha256="",
        artifact=HFArtifactSummary(
            kind=kind,  # type: ignore[arg-type]
            config_file=HFSmallFileSummary(
                file_name=config_path.name,
                byte_size=len(config_bytes),
                sha256=canonical_sha256(config_raw),
            ),
            index_file=index_summary,
            shards=shard_summaries,
        ),
        provenance=_parse_provenance(provenance_path),
        config=config,
        tensors=tensors,
        logical_ties=ties,
        summary=HFSummary(
            physical_tensor_count=len(tensors),
            logical_tie_count=len(ties),
            dtype_counts=dict(sorted(dtype_counts.items())),
            observed_layer_ids=layer_ids,
            classified_tensor_count=len(tensors) - len(unclassified),
            unclassified_tensor_count=len(unclassified),
            gap_count=sum(
                diagnostic.code.startswith("SAFETENSORS_") and diagnostic.code.endswith("GAP")
                for diagnostic in diagnostics
            ),
            overlap_count=0,
        ),
        diagnostics=diagnostics,
    )
    payload = inventory.model_dump(mode="json", by_alias=True)
    payload.pop("canonical_sha256")
    return inventory.model_copy(update={"canonical_sha256": canonical_sha256(payload)})


def pretty_hf_inventory(inventory: HFInventory) -> str:
    return (
        json.dumps(
            inventory.model_dump(mode="json", by_alias=True),
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
    )
