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
from omiv.hf.json_loader import parse_bounded_json_bytes
from omiv.hf.models import HFInventory
from omiv.hf.reader import pretty_hf_inventory, read_hf_inventory
from omiv.mapping.manifest import load_mapping_manifest
from omiv.mapping.reporting import (
    MAPPING_REPORT_SCHEMA_ID,
    build_mapping_report_envelope,
    load_mapping_report_envelope,
    mapping_report_integrity_matches,
    pretty_mapping_report_json,
    render_mapping_markdown,
)
from omiv.mapping.validator import format_mapping_report, validate_semantic_mapping
from omiv.model_packs.registry import get_model_pack, list_model_packs
from omiv.models import ModelInventory
from omiv.normalizer import normalize_inventory, write_inventory
from omiv.reporters.console import format_report
from omiv.safe_write import atomic_write_text, validate_output_path
from omiv.schema.loader import load_schema
from omiv.validators.kimi_k3 import validate_inventory

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)
model_packs_app = typer.Typer(no_args_is_help=True)
app.add_typer(model_packs_app, name="model-packs")
MAX_CANONICAL_INVENTORY_BYTES = 64 * 1024 * 1024


def _read_report_schema(path: Path) -> str | None:
    raw = parse_bounded_json_bytes(
        path.read_bytes(),
        source_name=path.name,
        max_bytes=16 * 1024 * 1024,
    )
    if not isinstance(raw, dict) or not isinstance(raw.get("report"), dict):
        return None
    schema = raw["report"].get("report_schema")
    return schema if isinstance(schema, str) else None


@app.command()
def normalize(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
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
    inventory_path: Annotated[Path, typer.Option("--inventory", exists=True, dir_okay=False)],
    schema_path: Annotated[Path, typer.Option("--schema", exists=True, dir_okay=False)],
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
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
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
    source_path: Annotated[Path, typer.Option("--source", exists=True, dir_okay=False)],
    target_path: Annotated[Path, typer.Option("--target", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    json_output: Annotated[Path | None, typer.Option("--json-output", dir_okay=False)] = None,
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
            json_content = pretty_report_json(envelope) if json_output is not None else None
            markdown_content = render_markdown(envelope) if markdown_output is not None else None
            if json_output is not None:
                validate_output_path(json_output, forbidden_inputs=input_paths)
            if markdown_output is not None:
                validate_output_path(markdown_output, forbidden_inputs=input_paths)
            if (
                json_output is not None
                and markdown_output is not None
                and json_output.resolve(strict=False) == markdown_output.resolve(strict=False)
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


@app.command("mapping-validate")
def mapping_validate(
    source_path: Annotated[Path, typer.Option("--source", exists=True, dir_okay=False)],
    target_path: Annotated[Path, typer.Option("--target", exists=True, dir_okay=False)],
    mapping_path: Annotated[Path, typer.Option("--mapping", exists=True, dir_okay=False)],
    json_output: Annotated[Path | None, typer.Option("--json-output", dir_okay=False)] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
    model_pack_id: Annotated[str | None, typer.Option("--model-pack")] = None,
) -> None:
    """Validate a static HF-to-GGUF semantic mapping manifest."""
    input_paths = (source_path, target_path, mapping_path)
    try:
        source_raw = parse_bounded_json_bytes(
            source_path.read_bytes(),
            source_name=source_path.name,
            max_bytes=MAX_CANONICAL_INVENTORY_BYTES,
        )
        target_raw = parse_bounded_json_bytes(
            target_path.read_bytes(),
            source_name=target_path.name,
            max_bytes=MAX_CANONICAL_INVENTORY_BYTES,
        )
        source = HFInventory.model_validate(source_raw)
        target = GGUFInventory.model_validate(target_raw)
        manifest = load_mapping_manifest(
            mapping_path, requested_pack_id=model_pack_id
        )
        model_pack = None if model_pack_id is None else get_model_pack(model_pack_id)
        validation = validate_semantic_mapping(source, target, manifest, model_pack=model_pack)
        if json_output is not None or markdown_output is not None:
            envelope = build_mapping_report_envelope(source, target, manifest, validation)
            if json_output is not None:
                validate_output_path(json_output, forbidden_inputs=input_paths)
            if markdown_output is not None:
                validate_output_path(markdown_output, forbidden_inputs=input_paths)
            if (
                json_output is not None
                and markdown_output is not None
                and json_output.resolve(strict=False) == markdown_output.resolve(strict=False)
            ):
                raise OmivInputError("JSON and Markdown outputs must be different paths")
            if json_output is not None:
                atomic_write_text(
                    json_output,
                    pretty_mapping_report_json(envelope),
                    forbidden_inputs=input_paths,
                )
            if markdown_output is not None:
                atomic_write_text(
                    markdown_output,
                    render_mapping_markdown(envelope),
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
    typer.echo(format_mapping_report(validation))
    if not validation.passed:
        raise typer.Exit(code=1)


@app.command("report")
def report_command(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output_format: Annotated[str, typer.Option("--format")],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Render a validated versioned report in another supported format."""
    try:
        if output_format != "markdown":
            raise OmivInputError("unsupported report format; expected markdown")
        schema = _read_report_schema(input_path)
        if schema == MAPPING_REPORT_SCHEMA_ID:
            mapping_envelope = load_mapping_report_envelope(input_path)
            if not mapping_report_integrity_matches(mapping_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_mapping_markdown(mapping_envelope)
        else:
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
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify report schema and payload integrity without original artifacts."""
    try:
        schema = _read_report_schema(input_path)
        if schema == MAPPING_REPORT_SCHEMA_ID:
            mapping_envelope = load_mapping_report_envelope(input_path)
            if not mapping_report_integrity_matches(mapping_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {mapping_envelope.integrity.sha256}")
            return
        envelope = load_report_envelope(input_path)
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not report_integrity_matches(envelope):
        typer.echo("FAIL report integrity mismatch")
        raise typer.Exit(code=1)
    typer.echo(f"PASS report integrity {envelope.integrity.sha256}")


@app.command()
def hf_normalize(
    model_dir: Annotated[Path, typer.Option("--model-dir", exists=True, file_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    provenance_path: Annotated[
        Path | None, typer.Option("--provenance", exists=True, dir_okay=False)
    ] = None,
    model_pack_id: Annotated[str | None, typer.Option("--model-pack")] = None,
) -> None:
    """Create a secure local Safetensors structural inventory."""
    try:
        inputs = [
            model_dir / "config.json",
            model_dir / "model.safetensors",
            model_dir / "model.safetensors.index.json",
            *model_dir.glob("*.safetensors"),
        ]
        if provenance_path is not None:
            inputs.append(provenance_path)
        validate_output_path(output_path, forbidden_inputs=inputs)
        inventory = read_hf_inventory(
            model_dir,
            provenance_path=provenance_path,
            model_pack=(None if model_pack_id is None else get_model_pack(model_pack_id)),
        )
        atomic_write_text(
            output_path,
            pretty_hf_inventory(inventory),
            forbidden_inputs=inputs,
        )
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid input: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _pack_line(metadata: object) -> str:
    from omiv.model_packs.base import ModelPackMetadata

    pack = ModelPackMetadata.model_validate(metadata)
    capabilities = ",".join(capability.value for capability in pack.capabilities)
    return (
        f"{pack.pack_id}\t{pack.pack_version}\t{pack.model_family}\t"
        f"{capabilities}\tproduction_supported={str(pack.production_supported).lower()}"
    )


@model_packs_app.command("list")
def model_packs_list(
    include_test_packs: Annotated[bool, typer.Option("--include-test-packs")] = False,
) -> None:
    """List statically registered built-in model packs."""
    for metadata in list_model_packs(include_test_packs=include_test_packs):
        typer.echo(_pack_line(metadata))


@model_packs_app.command("show")
def model_packs_show(
    pack_id: Annotated[str, typer.Option("--pack")],
) -> None:
    """Show canonical metadata for one built-in model pack."""
    try:
        metadata = get_model_pack(pack_id).metadata
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    payload = metadata.model_dump(mode="json")
    payload["metadata_sha256"] = metadata.digest
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
