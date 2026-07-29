import json
from pathlib import Path

from typer.testing import CliRunner

from omiv.cli import app
from omiv.models import FfnKind, ModelInventory

runner = CliRunner()


def _write_inventory(path: Path, inventory: ModelInventory) -> None:
    path.write_text(
        json.dumps(inventory.model_dump(mode="json")),
        encoding="utf-8",
    )


def test_validate_cli_exit_zero(valid_inventory: ModelInventory, tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    _write_inventory(path, valid_inventory)
    result = runner.invoke(
        app,
        ["validate", "--inventory", str(path), "--schema", "schemas/kimi_k3.yaml"],
    )
    assert result.exit_code == 0
    assert "PASS K3-MOE-001" in result.stdout


def test_validate_cli_exit_one(valid_inventory: ModelInventory, tmp_path: Path) -> None:
    layers = list(valid_inventory.layers)
    layers[0] = layers[0].model_copy(
        update={"ffn": layers[0].ffn.model_copy(update={"kind": FfnKind.UNKNOWN})}
    )
    invalid = valid_inventory.model_copy(update={"layers": layers})
    path = tmp_path / "inventory.json"
    _write_inventory(path, invalid)
    result = runner.invoke(
        app,
        ["validate", "--inventory", str(path), "--schema", "schemas/kimi_k3.yaml"],
    )
    assert result.exit_code == 1
    assert "FAIL K3-LAYER-001" in result.stdout
    assert "evidence:" in result.stdout


def test_normalize_cli_exit_two_for_invalid_input(tmp_path: Path) -> None:
    raw = tmp_path / "raw.json"
    output = tmp_path / "canonical.json"
    raw.write_text('{"not": "an array"}', encoding="utf-8")
    result = runner.invoke(
        app,
        ["normalize", "--input", str(raw), "--output", str(output)],
    )
    assert result.exit_code == 2
    assert "top-level JSON array" in result.stderr
    assert not output.exists()
