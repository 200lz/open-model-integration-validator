"""Command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from omiv.canonical import load_json_value
from omiv.errors import OmivInputError
from omiv.gguf.compare import compare_gguf_inventories, format_gguf_report
from omiv.gguf.models import GGUFInventory
from omiv.gguf.policy import load_gguf_policy
from omiv.gguf.reader import read_gguf_inventory, write_gguf_inventory
from omiv.gguf.reporting import (
    build_report_envelope,
    load_report_envelope,
    pretty_report_json,
    render_markdown,
    report_integrity_matches,
)
from omiv.models import ModelInventory
from omiv.normalizer import normalize_inventory, write_inventory
from omiv.reporters.console import format_report
from omiv.safe_write import atomic_write_text, validate_output_path
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
    json_output: Annotated[
        Path | None, typer.Option("--json-output", dir_okay=False)
    ] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
) -> None:
    """Compare two canonical GGUF inventories under an explicit policy."""
    input_paths = (source_path, target_path, policy_path)
    try:
        source = GGUFInventory.model_validate(
            load_json_value(source_path.read_text(encoding="utf-8"))
        )
        target = GGUFInventory.model_validate(
            load_json_value(target_path.read_text(encoding="utf-8"))
        )
        policy = load_gguf_policy(policy_path)
        comparison = compare_gguf_inventories(source, target, policy)
        if json_output is not None or markdown_output is not None:
            envelope = build_report_envelope(source, target, policy, comparison)
            json_content = (
                pretty_report_json(envelope) if json_output is not None else None
            )
            markdown_content = (
                render_markdown(envelope) if markdown_output is not None else None
            )
            if json_output is not None:
                validate_output_path(json_output, forbidden_inputs=input_paths)
            if markdown_output is not None:
                validate_output_path(markdown_output, forbidden_inputs=input_paths)
            if (
                json_output is not None
                and markdown_output is not None
                and json_output.resolve(strict=False)
                == markdown_output.resolve(strict=False)
            ):
                raise OmivInputError("JSON and Markdown outputs must be different paths")
            if json_output is not None and json_content is not None:
                atomic_write_text(
                    json_output,
                    json_content,
                    forbidden_inputs=input_paths,
                )
            if markdown_output is not None and markdown_content is not None:
                atomic_write_text(
                    markdown_output,
                    markdown_content,
                    forbidden_inputs=input_paths,
                )
    except (
        OSError,
        UnicodeError,
        ValidationError,
        OmivInputError,
    ) as exc:
        typer.echo(f"ERROR invalid input: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(format_gguf_report(comparison))
    if not comparison.passed:
        raise typer.Exit(code=1)


@app.command("report")
def report_command(
    input_path: Annotated[
        Path, typer.Option("--input", exists=True, dir_okay=False)
    ],
    output_format: Annotated[
        str, typer.Option("--format")
    ],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Render a validated versioned report in another supported format."""
    try:
        if output_format != "markdown":
            raise OmivInputError("unsupported report format; expected markdown")
        envelope = load_report_envelope(input_path)
        if not report_integrity_matches(envelope):
            raise OmivInputError("report integrity mismatch")
        content = render_markdown(envelope)
        atomic_write_text(output_path, content, forbidden_inputs=(input_path,))
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("report-verify")
def report_verify(
    input_path: Annotated[
        Path, typer.Option("--input", exists=True, dir_okay=False)
    ],
) -> None:
    """Verify report schema and payload integrity without original artifacts."""
    try:
        envelope = load_report_envelope(input_path)
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not report_integrity_matches(envelope):
        typer.echo("FAIL report integrity mismatch")
        raise typer.Exit(code=1)
    typer.echo(f"PASS report integrity {envelope.integrity.sha256}")
