"""Command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from omiv.errors import OmivInputError
from omiv.gguf.compare import compare_gguf_inventories, format_gguf_report
from omiv.gguf.models import GGUFInventory
from omiv.gguf.policy import load_gguf_policy
from omiv.gguf.reader import read_gguf_inventory, write_gguf_inventory
from omiv.models import ModelInventory
from omiv.normalizer import normalize_inventory, write_inventory
from omiv.reporters.console import format_report
from omiv.schema.loader import load_schema
from omiv.validators.kimi_k3 import validate_inventory

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)


@app.command()
def normalize(
    input_path: Annotated[
        Path, typer.Option("--input", exists=True, dir_okay=False)
    ],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Compact a local Kimi K3 raw header inventory."""
    try:
        inventory = normalize_inventory(input_path)
        write_inventory(inventory, output_path)
    except (OSError, UnicodeError, OmivInputError) as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def validate(
    inventory_path: Annotated[
        Path, typer.Option("--inventory", exists=True, dir_okay=False)
    ],
    schema_path: Annotated[
        Path, typer.Option("--schema", exists=True, dir_okay=False)
    ],
) -> None:
    """Validate a canonical inventory against the Kimi K3 Phase 1 schema."""
    try:
        raw = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory = ModelInventory.model_validate(raw)
        schema = load_schema(schema_path)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValidationError,
        OmivInputError,
    ) as exc:
        typer.echo(f"ERROR invalid input: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    report = validate_inventory(inventory, schema)
    typer.echo(format_report(report))
    if not report.passed:
        raise typer.Exit(code=1)


@app.command()
def gguf_normalize(
    input_path: Annotated[
        Path, typer.Option("--input", exists=True, dir_okay=False)
    ],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Create a deterministic GGUF descriptor inventory without reading tensor data."""
    try:
        inventory = read_gguf_inventory(input_path)
        write_gguf_inventory(inventory, output_path)
    except (OSError, UnicodeError, OmivInputError) as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def gguf_diff(
    source_path: Annotated[
        Path, typer.Option("--source", exists=True, dir_okay=False)
    ],
    target_path: Annotated[
        Path, typer.Option("--target", exists=True, dir_okay=False)
    ],
    policy_path: Annotated[
        Path, typer.Option("--policy", exists=True, dir_okay=False)
    ],
) -> None:
    """Compare two canonical GGUF inventories under an explicit policy."""
    try:
        source = GGUFInventory.model_validate_json(
            source_path.read_text(encoding="utf-8")
        )
        target = GGUFInventory.model_validate_json(
            target_path.read_text(encoding="utf-8")
        )
        policy = load_gguf_policy(policy_path)
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid input: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    report = compare_gguf_inventories(source, target, policy)
    typer.echo(format_gguf_report(report))
    if not report.passed:
        raise typer.Exit(code=1)
