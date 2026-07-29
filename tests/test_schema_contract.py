from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from omiv.cli import app
from omiv.errors import OmivInputError
from omiv.models import ModelInventory
from omiv.schema.loader import load_schema

runner = CliRunner()


def _schema_data() -> dict[str, Any]:
    return yaml.safe_load(Path("schemas/kimi_k3.yaml").read_text(encoding="utf-8"))


def _write_schema(path: Path, data: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _validate_cli(
    tmp_path: Path, inventory: ModelInventory, schema_data: dict[str, Any]
) -> Any:
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps(inventory.model_dump(mode="json")),
        encoding="utf-8",
    )
    schema_path = tmp_path / "schema.yaml"
    _write_schema(schema_path, schema_data)
    return runner.invoke(
        app,
        [
            "validate",
            "--inventory",
            str(inventory_path),
            "--schema",
            str(schema_path),
        ],
    )


def test_current_kimi_k3_schema_passes(
    tmp_path: Path, valid_inventory: ModelInventory
) -> None:
    result = _validate_cli(tmp_path, valid_inventory, _schema_data())
    assert result.exit_code == 0


def test_unsupported_expert_set_policy_is_configuration_error(
    tmp_path: Path, valid_inventory: ModelInventory
) -> None:
    data = _schema_data()
    data["expert_set_policy"] = "derive_from_largest_set"
    schema_path = tmp_path / "schema.yaml"
    _write_schema(schema_path, data)
    with pytest.raises(OmivInputError, match="invalid schema"):
        load_schema(schema_path)
    result = _validate_cli(tmp_path, valid_inventory, data)
    assert result.exit_code == 2


def test_misspelled_required_component_is_configuration_error(
    tmp_path: Path, valid_inventory: ModelInventory
) -> None:
    data = _schema_data()
    data["required_expert_components"][0] = "w1.weight_packd"
    schema_path = tmp_path / "schema.yaml"
    _write_schema(schema_path, data)
    with pytest.raises(OmivInputError, match="invalid schema"):
        load_schema(schema_path)
    result = _validate_cli(tmp_path, valid_inventory, data)
    assert result.exit_code == 2


def test_removed_required_component_is_rejected_for_compact_contract(
    tmp_path: Path, valid_inventory: ModelInventory
) -> None:
    data = _schema_data()
    data["required_expert_components"].pop()
    result = _validate_cli(tmp_path, valid_inventory, data)
    assert result.exit_code == 2
    assert "Phase 1 expert-component vocabulary" in result.stderr


def test_duplicate_required_component_is_configuration_error(tmp_path: Path) -> None:
    data = _schema_data()
    data["required_expert_components"].append(data["required_expert_components"][0])
    schema_path = tmp_path / "schema.yaml"
    _write_schema(schema_path, data)
    with pytest.raises(OmivInputError, match="contains duplicates"):
        load_schema(schema_path)
