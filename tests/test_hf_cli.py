from __future__ import annotations

import json
from pathlib import Path

from hf_helpers import make_monolithic
from typer.testing import CliRunner

from omiv.canonical import canonical_sha256
from omiv.cli import app

runner = CliRunner()


def _invoke(model_dir: Path, output: Path, provenance: Path | None = None) -> object:
    args = [
        "hf-normalize",
        "--model-dir",
        str(model_dir),
        "--output",
        str(output),
    ]
    if provenance is not None:
        args.extend(["--provenance", str(provenance)])
    return runner.invoke(app, args)


def test_hf_normalize_cli_success_and_determinism(tmp_path: Path) -> None:
    model_dir = tmp_path / "model"
    make_monolithic(model_dir)
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    one = _invoke(model_dir, first)
    two = _invoke(model_dir, second)
    assert one.exit_code == 0  # type: ignore[attr-defined]
    assert two.exit_code == 0  # type: ignore[attr-defined]
    assert first.read_bytes() == second.read_bytes()
    assert str(model_dir.resolve()) not in first.read_text(encoding="utf-8")
    value = json.loads(first.read_text(encoding="utf-8"))
    digest = value.pop("canonical_sha256")
    assert digest == canonical_sha256(value)
    assert value["provenance"]["available"] is False


def test_hf_normalize_cli_malformed_exit_two_and_atomic_output(
    tmp_path: Path,
) -> None:
    model_dir = tmp_path / "model"
    make_monolithic(model_dir)
    (model_dir / "config.json").write_text("{", encoding="utf-8")
    output = tmp_path / "inventory.json"
    output.write_text("existing", encoding="utf-8")
    result = _invoke(model_dir, output)
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert output.read_text(encoding="utf-8") == "existing"


def test_hf_optional_provenance(tmp_path: Path) -> None:
    model_dir = tmp_path / "model"
    make_monolithic(model_dir)
    provenance = tmp_path / "source.json"
    provenance.write_text(
        json.dumps(
            {
                "repository": "example/model",
                "revision": "abc123",
                "source": "local",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "inventory.json"
    result = _invoke(model_dir, output, provenance)
    assert result.exit_code == 0  # type: ignore[attr-defined]
    value = json.loads(output.read_text())
    assert value["provenance"]["available"]
    assert value["provenance"]["repository"] == "example/model"


def test_hf_provenance_rejects_absolute_path(tmp_path: Path) -> None:
    model_dir = tmp_path / "model"
    make_monolithic(model_dir)
    provenance = tmp_path / "source.json"
    provenance.write_text('{"source":"/secret/path"}', encoding="utf-8")
    result = _invoke(model_dir, tmp_path / "inventory.json", provenance)
    assert result.exit_code == 2  # type: ignore[attr-defined]


def test_hf_source_output_collision_rejected(tmp_path: Path) -> None:
    model_dir = tmp_path / "model"
    make_monolithic(model_dir)
    source = model_dir / "model.safetensors"
    before = source.stat().st_size
    result = _invoke(model_dir, source)
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert source.stat().st_size == before
