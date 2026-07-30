"""Format adapters that expose generic inventory and artifact identity evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from omiv.canonical import canonical_sha256
from omiv.errors import OmivInputError
from omiv.gguf.models import GGUFInventory
from omiv.gguf.reader import read_gguf_inventory
from omiv.gguf.reporting import inventory_sha256 as gguf_inventory_sha256
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.hf.models import HFInventory
from omiv.mapping.reporting import source_inventory_sha256
from omiv.provenance.models import InventoryEvidence, ObservedArtifact

MAX_INVENTORY_BYTES = 64 * 1024 * 1024


def _hf_evidence(inventory: HFInventory) -> InventoryEvidence:
    artifacts: dict[str, ObservedArtifact] = {
        "config": ObservedArtifact(
            artifact_id=inventory.artifact.config_file.file_name,
            byte_size=inventory.artifact.config_file.byte_size,
            sha256=inventory.artifact.config_file.sha256,
            full_artifact_digest=True,
        )
    }
    if inventory.artifact.index_file is not None:
        artifacts["index"] = ObservedArtifact(
            artifact_id=inventory.artifact.index_file.file_name,
            byte_size=inventory.artifact.index_file.byte_size,
            sha256=inventory.artifact.index_file.sha256,
            full_artifact_digest=True,
        )
    return InventoryEvidence(
        format="huggingface-safetensors",
        inventory_schema=inventory.schema_id,
        inventory_sha256=source_inventory_sha256(inventory),
        model_family=inventory.config.model_type,
        repository=inventory.provenance.repository,
        revision=inventory.provenance.revision,
        artifacts=artifacts,
    )


def _gguf_evidence(inventory: GGUFInventory) -> InventoryEvidence:
    artifacts: dict[str, ObservedArtifact] = {}
    if inventory.artifact.shards:
        for shard in inventory.artifact.shards:
            artifacts[shard.file_name] = ObservedArtifact(
                artifact_id=shard.file_name,
                byte_size=shard.byte_size,
                sha256=shard.sha256,
                full_artifact_digest=True,
            )
    return InventoryEvidence(
        format="gguf",
        inventory_schema="omiv.gguf-inventory.v1",
        inventory_sha256=gguf_inventory_sha256(inventory),
        model_family=inventory.identity.architecture,
        architecture=inventory.identity.architecture,
        artifacts=artifacts,
    )


def inventory_evidence_from_value(value: dict[str, Any]) -> InventoryEvidence:
    """Select a static built-in inventory adapter by its schema discriminator."""
    try:
        if value.get("schema") == "omiv.hf-inventory.v1":
            return _hf_evidence(HFInventory.model_validate(value))
        if value.get("schema_version") == 1 and isinstance(value.get("artifact"), dict):
            return _gguf_evidence(GGUFInventory.model_validate(value))
    except (ValidationError, OmivInputError) as exc:
        raise OmivInputError(f"invalid inventory: {exc}") from exc
    raise OmivInputError("unsupported inventory schema")


def load_inventory_evidence(path: Path) -> InventoryEvidence:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OmivInputError(f"cannot read inventory {path.name}: {exc}") from exc
    value = parse_bounded_json_bytes(
        raw,
        source_name=path.name,
        max_bytes=MAX_INVENTORY_BYTES,
    )
    return inventory_evidence_from_value(value)


def inventory_sha256_from_raw_value(value: dict[str, Any]) -> str:
    """Canonical digest helper for future adapters without embedded integrity."""
    return canonical_sha256(value)


def generate_target_inventory(
    format_id: str,
    artifact_path: Path,
) -> tuple[dict[str, Any], InventoryEvidence]:
    """Generate a canonical descriptor inventory through a static format adapter."""
    if format_id == "gguf":
        inventory = read_gguf_inventory(artifact_path)
        value = inventory.model_dump(mode="json")
        return value, _gguf_evidence(inventory)
    raise OmivInputError(f"no target inventory adapter for format {format_id!r}")
