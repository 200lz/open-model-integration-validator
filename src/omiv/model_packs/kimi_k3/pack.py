"""Built-in Kimi K3 checkpoint model pack."""

from __future__ import annotations

from pathlib import Path

from omiv.model_packs.base import ModelPack, ModelPackCapability
from omiv.model_packs.kimi_k3.checkpoint import normalize_inventory
from omiv.model_packs.kimi_k3.schema import KimiK3Schema
from omiv.model_packs.kimi_k3.validator import validate_inventory
from omiv.models import ModelInventory, ValidationReport


class KimiK3ModelPack(ModelPack):
    pack_id = "kimi-k3"
    pack_version = 1
    model_family = "kimi-k3"
    description = "Production Kimi K3 checkpoint schema and tensor ontology."
    capabilities = frozenset(
        {
            ModelPackCapability.CHECKPOINT_SCHEMA,
            ModelPackCapability.CHECKPOINT_ONTOLOGY,
        }
    )
    supported_source_formats = frozenset({"safetensors-header-inventory"})
    supported_target_formats = frozenset()

    def normalize_checkpoint(self, path: Path) -> ModelInventory:
        return normalize_inventory(path)

    def validate_checkpoint(self, inventory: ModelInventory, schema: object) -> ValidationReport:
        if not isinstance(schema, KimiK3Schema):
            raise TypeError("Kimi K3 validation requires KimiK3Schema")
        return validate_inventory(inventory, schema)
