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
from omiv.provenance.adapters import load_inventory_evidence
from omiv.provenance.capture import ConversionRunFailed, run_conversion
from omiv.provenance.loading import load_provenance_envelope
from omiv.provenance.reporting import (
    PROVENANCE_REPORT_SCHEMA_ID,
    build_provenance_report_envelope,
    load_provenance_report_envelope,
    pretty_provenance_report_json,
    provenance_integrity_matches,
    provenance_report_integrity_matches,
    render_provenance_markdown,
)
from omiv.provenance.validator import (
    ProvenanceValidationContext,
    format_provenance_report,
    validate_provenance,
)
from omiv.remote.gguf_header import RemoteGGUFHeaderParser
from omiv.remote.header_models import (
    HEADER_REPORT_SCHEMA,
    HeaderInventoryEnvelope,
    HeaderParserPolicy,
)
from omiv.remote.header_reporting import (
    build_header_inventory_envelope,
    build_header_report,
    header_report_integrity_matches,
    load_header_inventory,
    load_header_report,
    pretty_header_json,
    render_header_markdown,
)
from omiv.remote.huggingface import HuggingFaceRepositoryAdapter
from omiv.remote.probe import (
    gguf_prefix_probe,
    range_probe,
    resolved_file_url,
    selected_snapshot_file,
)
from omiv.remote.range_client import BoundedRangeClient, RangeValidationError
from omiv.remote.range_source import RangeBackedByteSource
from omiv.remote.reporting import (
    build_snapshot_report,
    load_remote_report,
    load_snapshot,
    snapshot_envelope,
)
from omiv.remote.reporting import (
    pretty_json as pretty_remote_json,
)
from omiv.remote.reporting import (
    render_markdown as render_remote_markdown,
)
from omiv.remote.reporting import (
    report_integrity_matches as remote_report_integrity_matches,
)
from omiv.remote.split_aggregation import (
    aggregate_split_inventories,
    validate_reusable_inventory,
)
from omiv.remote.split_models import (
    SPLIT_REPORT_SCHEMA,
    SplitAggregationLimits,
)
from omiv.remote.split_reporting import (
    build_split_inventory_envelope,
    build_split_report,
    load_split_inventory,
    load_split_report,
    pretty_split_json,
    render_split_markdown,
    split_inventory_integrity_matches,
    split_report_integrity_matches,
)
from omiv.reporters.console import format_report
from omiv.safe_write import atomic_write_text, validate_output_path
from omiv.schema.loader import load_schema
from omiv.validators.kimi_k3 import validate_inventory

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)
model_packs_app = typer.Typer(no_args_is_help=True)
app.add_typer(model_packs_app, name="model-packs")
MAX_CANONICAL_INVENTORY_BYTES = 64 * 1024 * 1024
REMOTE_REPORT_SCHEMAS = {
    "omiv.remote-snapshot-report.v1",
    "omiv.remote-range-probe-report.v1",
    "omiv.remote-gguf-prefix-report.v1",
}
MAX_REPORT_DISPATCH_BYTES = 1024 * 1024 * 1024


def _read_report_schema(path: Path) -> str | None:
    raw = parse_bounded_json_bytes(
        path.read_bytes(),
        source_name=path.name,
        max_bytes=MAX_REPORT_DISPATCH_BYTES,
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
    provenance_report_path: Annotated[
        Path | None, typer.Option("--provenance-report", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Validate a static HF-to-GGUF semantic mapping manifest."""
    input_paths = tuple(
        item
        for item in (source_path, target_path, mapping_path, provenance_report_path)
        if item is not None
    )
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
        manifest = load_mapping_manifest(mapping_path, requested_pack_id=model_pack_id)
        model_pack = None if model_pack_id is None else get_model_pack(model_pack_id)
        provenance_validation = None
        conversion_provenance = None
        if provenance_report_path is not None:
            provenance_report = load_provenance_report_envelope(provenance_report_path)
            if not provenance_report_integrity_matches(provenance_report):
                raise OmivInputError("provenance report integrity mismatch")
            selected_pack = (
                model_pack
                if model_pack is not None
                else get_model_pack(
                    provenance_report.report.provenance.interpretation.model_pack.pack_id
                )
            )
            provenance_validation = validate_provenance(
                provenance_report.report.provenance,
                ProvenanceValidationContext(
                    source_inventory=load_inventory_evidence(source_path),
                    target_inventory=load_inventory_evidence(target_path),
                    mapping=manifest,
                    model_pack=selected_pack,
                ),
            )
            conversion_provenance = provenance_report.report.provenance
        validation = validate_semantic_mapping(
            source,
            target,
            manifest,
            model_pack=model_pack,
            provenance_validation=provenance_validation,
            conversion_provenance=conversion_provenance,
        )
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


def _role_paths(values: list[str] | None, *, option: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values or []:
        role, separator, raw_path = value.partition("=")
        if not separator or not role or not raw_path:
            raise OmivInputError(f"{option} must use ROLE=PATH")
        if role in result:
            raise OmivInputError(f"duplicate {option} role: {role}")
        path = Path(raw_path)
        if not path.exists() or not path.is_file() or path.is_symlink():
            raise OmivInputError(f"{option} path must be a regular non-symlink file")
        result[role] = path
    return result


@app.command("provenance-validate")
def provenance_validate(
    provenance_path: Annotated[Path, typer.Option("--provenance", exists=True, dir_okay=False)],
    source_inventory_path: Annotated[
        Path, typer.Option("--source-inventory", exists=True, dir_okay=False)
    ],
    target_inventory_path: Annotated[
        Path, typer.Option("--target-inventory", exists=True, dir_okay=False)
    ],
    mapping_path: Annotated[Path, typer.Option("--mapping", exists=True, dir_okay=False)],
    model_pack_id: Annotated[str, typer.Option("--model-pack")],
    source_artifact: Annotated[list[str] | None, typer.Option("--source-artifact")] = None,
    target_artifact: Annotated[list[str] | None, typer.Option("--target-artifact")] = None,
    json_output: Annotated[Path | None, typer.Option("--json-output", dir_okay=False)] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
) -> None:
    """Validate a deterministic conversion provenance chain."""
    try:
        envelope = load_provenance_envelope(provenance_path)
        if not provenance_integrity_matches(envelope):
            raise OmivInputError("provenance integrity mismatch")
        source_paths = _role_paths(source_artifact, option="--source-artifact")
        target_paths = _role_paths(target_artifact, option="--target-artifact")
        pack = get_model_pack(model_pack_id)
        manifest = load_mapping_manifest(
            mapping_path,
            requested_pack_id=model_pack_id,
        )
        validation = validate_provenance(
            envelope.provenance,
            ProvenanceValidationContext(
                source_inventory=load_inventory_evidence(source_inventory_path),
                target_inventory=load_inventory_evidence(target_inventory_path),
                mapping=manifest,
                model_pack=pack,
                source_artifacts=source_paths,
                target_artifacts=target_paths,
            ),
        )
        report_envelope = build_provenance_report_envelope(
            envelope.provenance,
            validation,
        )
        inputs = (
            provenance_path,
            source_inventory_path,
            target_inventory_path,
            mapping_path,
            *source_paths.values(),
            *target_paths.values(),
        )
        if json_output is not None:
            validate_output_path(json_output, forbidden_inputs=inputs)
        if markdown_output is not None:
            validate_output_path(markdown_output, forbidden_inputs=inputs)
        if (
            json_output is not None
            and markdown_output is not None
            and json_output.resolve(strict=False) == markdown_output.resolve(strict=False)
        ):
            raise OmivInputError("JSON and Markdown outputs must be different paths")
        if json_output is not None:
            atomic_write_text(
                json_output,
                pretty_provenance_report_json(report_envelope),
                forbidden_inputs=inputs,
            )
        if markdown_output is not None:
            atomic_write_text(
                markdown_output,
                render_provenance_markdown(report_envelope),
                forbidden_inputs=inputs,
            )
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid input: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(format_provenance_report(validation))
    if not validation.passed:
        raise typer.Exit(code=1)


@app.command("conversion-run")
def conversion_run(
    spec_path: Annotated[Path, typer.Option("--spec", exists=True, dir_okay=False)],
) -> None:
    """Run a strict shell-free conversion spec and capture validated lineage."""
    try:
        provenance = run_conversion(spec_path)
    except ConversionRunFailed as exc:
        typer.echo(f"FAIL conversion process exit code {exc.exit_code}", err=True)
        raise typer.Exit(code=1) from exc
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid conversion configuration: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS conversion provenance {provenance.provenance_id}")


def _require_online(offline: bool) -> None:
    if offline:
        raise OmivInputError("remote commands cannot run with --offline")


@app.command("remote-snapshot")
def remote_snapshot(
    provider: Annotated[str, typer.Option("--provider")],
    repo_id: Annotated[str, typer.Option("--repo")],
    revision: Annotated[str, typer.Option("--revision")],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    path_prefix: Annotated[str | None, typer.Option("--path-prefix")] = None,
    patterns: Annotated[list[str] | None, typer.Option("--pattern")] = None,
    report_output: Annotated[
        Path | None, typer.Option("--report-output", dir_okay=False)
    ] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
    offline: Annotated[bool, typer.Option("--offline")] = False,
) -> None:
    """Resolve and enumerate a pinned remote repository without file downloads."""
    try:
        _require_online(offline)
        if provider != "huggingface":
            raise OmivInputError("unsupported remote provider; expected huggingface")
        outputs = [item for item in (output_path, report_output, markdown_output) if item]
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("remote snapshot outputs must use distinct paths")
        for item in outputs:
            validate_output_path(item)
        snapshot = HuggingFaceRepositoryAdapter().snapshot(
            repo_id=repo_id,
            revision=revision,
            path_prefix=path_prefix,
            patterns=patterns or [],
        )
        envelope = snapshot_envelope(snapshot)
        report = build_snapshot_report(envelope)
        atomic_write_text(output_path, pretty_remote_json(envelope))
        if report_output is not None:
            atomic_write_text(report_output, pretty_remote_json(report))
        if markdown_output is not None:
            atomic_write_text(markdown_output, render_remote_markdown(report))
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid remote configuration or evidence: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{report.report.execution.result.value.upper()} remote snapshot "
        f"{envelope.integrity.sha256}"
    )
    if report.report.execution.exit_code:
        raise typer.Exit(code=1)


@app.command("remote-range-probe")
def remote_range_probe(
    snapshot_path: Annotated[
        Path, typer.Option("--snapshot", exists=True, dir_okay=False)
    ],
    file_path: Annotated[str, typer.Option("--file")],
    offset: Annotated[int, typer.Option("--offset", min=0)],
    length: Annotated[int, typer.Option("--length", min=1)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    hex_preview: Annotated[bool, typer.Option("--hex-preview")] = False,
    offline: Annotated[bool, typer.Option("--offline")] = False,
) -> None:
    """Retrieve and validate exactly one bounded remote byte range."""
    try:
        _require_online(offline)
        validate_output_path(output_path, forbidden_inputs=(snapshot_path,))
        snapshot = load_snapshot(snapshot_path)
        report = range_probe(
            snapshot,
            path=file_path,
            offset=offset,
            length=length,
            client=BoundedRangeClient(),
            include_hex_preview=hex_preview,
        )
        atomic_write_text(
            output_path,
            pretty_remote_json(report),
            forbidden_inputs=(snapshot_path,),
        )
    except RangeValidationError as exc:
        typer.echo(f"FAIL bounded range validation: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid remote configuration or snapshot: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS bounded range {report.integrity.sha256}")


@app.command("remote-gguf-prefix")
def remote_gguf_prefix(
    snapshot_path: Annotated[
        Path, typer.Option("--snapshot", exists=True, dir_okay=False)
    ],
    file_path: Annotated[str, typer.Option("--file")],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
    offline: Annotated[bool, typer.Option("--offline")] = False,
) -> None:
    """Validate only the eight-byte GGUF magic/version prefix."""
    try:
        _require_online(offline)
        outputs = [output_path] + ([markdown_output] if markdown_output else [])
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("prefix report outputs must use distinct paths")
        for item in outputs:
            validate_output_path(item, forbidden_inputs=(snapshot_path,))
        snapshot = load_snapshot(snapshot_path)
        report = gguf_prefix_probe(
            snapshot,
            path=file_path,
            client=BoundedRangeClient(),
        )
        atomic_write_text(
            output_path,
            pretty_remote_json(report),
            forbidden_inputs=(snapshot_path,),
        )
        if markdown_output is not None:
            atomic_write_text(
                markdown_output,
                render_remote_markdown(report),
                forbidden_inputs=(snapshot_path,),
            )
    except RangeValidationError as exc:
        typer.echo(f"FAIL bounded prefix validation: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR invalid remote configuration or snapshot: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{report.report.execution.result.value.upper()} GGUF prefix "
        f"{report.integrity.sha256}"
    )
    if report.report.execution.exit_code:
        raise typer.Exit(code=1)


@app.command("remote-gguf-header")
def remote_gguf_header(
    snapshot_path: Annotated[
        Path, typer.Option("--snapshot", exists=True, dir_okay=False)
    ],
    file_path: Annotated[str, typer.Option("--file")],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[
        Path, typer.Option("--report-output", dir_okay=False)
    ],
    markdown_output: Annotated[
        Path, typer.Option("--markdown-output", dir_okay=False)
    ],
    max_header_bytes: Annotated[
        int, typer.Option("--max-header-bytes", min=24)
    ] = 64 * 1024 * 1024,
    max_request_bytes: Annotated[
        int, typer.Option("--max-request-bytes", min=24)
    ] = 256 * 1024,
    read_ahead_bytes: Annotated[
        int, typer.Option("--read-ahead-bytes", min=0)
    ] = 256 * 1024,
    max_metadata_count: Annotated[
        int, typer.Option("--max-metadata-count", min=0)
    ] = 1_000_000,
    max_tensor_count: Annotated[
        int, typer.Option("--max-tensor-count", min=0)
    ] = 1_000_000,
    max_string_bytes: Annotated[
        int, typer.Option("--max-string-bytes", min=0)
    ] = 16 * 1024 * 1024,
    max_metadata_key_bytes: Annotated[
        int, typer.Option("--max-metadata-key-bytes", min=1)
    ] = 1024,
    max_array_elements: Annotated[
        int, typer.Option("--max-array-elements", min=0)
    ] = 10_000_000,
    max_tensor_name_bytes: Annotated[
        int, typer.Option("--max-tensor-name-bytes", min=1)
    ] = 4096,
    max_tensor_dimensions: Annotated[
        int, typer.Option("--max-tensor-dimensions", min=1, max=64)
    ] = 4,
    max_alignment: Annotated[
        int, typer.Option("--max-alignment", min=1)
    ] = 4096,
    max_request_count: Annotated[
        int, typer.Option("--max-request-count", min=1)
    ] = 4096,
    max_preview_bytes: Annotated[
        int, typer.Option("--max-preview-bytes", min=0, max=65536)
    ] = 256,
    offline: Annotated[bool, typer.Option("--offline")] = False,
) -> None:
    """Parse one complete pinned GGUF v3 header without accepting payload bytes."""
    inputs = (snapshot_path,)
    try:
        _require_online(offline)
        outputs = (output_path, report_output, markdown_output)
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("header inventory and report outputs must be distinct")
        for item in outputs:
            validate_output_path(item, forbidden_inputs=inputs)
        snapshot = load_snapshot(snapshot_path)
        file = selected_snapshot_file(snapshot, file_path)
        policy = HeaderParserPolicy(
            max_total_header_bytes=max_header_bytes,
            max_request_bytes=max_request_bytes,
            read_ahead_bytes=read_ahead_bytes,
            max_metadata_count=max_metadata_count,
            max_tensor_count=max_tensor_count,
            max_string_bytes=max_string_bytes,
            max_metadata_key_bytes=max_metadata_key_bytes,
            max_array_elements=max_array_elements,
            max_tensor_name_bytes=max_tensor_name_bytes,
            max_tensor_dimensions=max_tensor_dimensions,
            max_alignment=max_alignment,
            max_request_count=max_request_count,
            max_preview_bytes=max_preview_bytes,
        )
        client = BoundedRangeClient(max_response_bytes=policy.max_request_bytes)
        source = RangeBackedByteSource(
            url=resolved_file_url(snapshot, file.path),
            file_size=file.byte_size,
            client=client,
            policy=policy,
        )
        inventory = RemoteGGUFHeaderParser(policy).parse(
            source,
            repository=snapshot.snapshot.repository,
            snapshot_sha256=snapshot.integrity.sha256,
            file=file,
        )
        inventory_envelope = build_header_inventory_envelope(inventory)
        report_envelope = build_header_report(inventory_envelope)
        atomic_write_text(
            output_path,
            pretty_header_json(inventory_envelope),
            forbidden_inputs=inputs,
        )
        atomic_write_text(
            report_output,
            pretty_header_json(report_envelope),
            forbidden_inputs=inputs,
        )
        atomic_write_text(
            markdown_output,
            render_header_markdown(report_envelope),
            forbidden_inputs=inputs,
        )
    except (
        OSError,
        UnicodeError,
        ValidationError,
        OmivInputError,
        RangeValidationError,
    ) as exc:
        typer.echo(f"ERROR remote GGUF header parse failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS remote GGUF header {inventory_envelope.integrity.sha256} "
        f"bytes={inventory.total_remote_bytes_accepted} "
        f"requests={inventory.request_count}"
    )


@app.command("remote-split-gguf")
def remote_split_gguf(
    snapshot_path: Annotated[
        Path, typer.Option("--snapshot", exists=True, dir_okay=False)
    ],
    inventory_dir: Annotated[Path, typer.Option("--inventory-dir", file_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[
        Path, typer.Option("--report-output", dir_okay=False)
    ],
    markdown_output: Annotated[
        Path, typer.Option("--markdown-output", dir_okay=False)
    ],
    regenerate: Annotated[bool, typer.Option("--regenerate")] = False,
    max_shards: Annotated[int, typer.Option("--max-shards", min=1)] = 256,
    max_total_header_bytes: Annotated[
        int, typer.Option("--max-total-header-bytes", min=24)
    ] = 1024 * 1024 * 1024,
    max_total_requests: Annotated[
        int, typer.Option("--max-total-requests", min=1)
    ] = 65536,
    max_total_metadata: Annotated[
        int, typer.Option("--max-total-metadata", min=1)
    ] = 2_000_000,
    max_total_tensors: Annotated[
        int, typer.Option("--max-total-tensors", min=1)
    ] = 5_000_000,
    max_inventory_bytes: Annotated[
        int, typer.Option("--max-inventory-bytes", min=1024)
    ] = 1024 * 1024 * 1024,
    offline: Annotated[bool, typer.Option("--offline")] = False,
) -> None:
    """Aggregate a pinned split GGUF without reading tensor payload bytes."""
    inputs = (snapshot_path,)
    try:
        _require_online(offline)
        outputs = (output_path, report_output, markdown_output)
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("split inventory and report outputs must be distinct")
        for item in outputs:
            validate_output_path(item, forbidden_inputs=inputs)
        snapshot = load_snapshot(snapshot_path)
        candidates = snapshot.snapshot.summary.candidate_split_sets
        if len(candidates) != 1 or not candidates[0].complete:
            raise OmivInputError("snapshot must have exactly one complete split candidate")
        paths = candidates[0].files
        if len(paths) > max_shards:
            raise OmivInputError("split shard count exceeds aggregation policy")
        policy = HeaderParserPolicy()
        limits = SplitAggregationLimits(
            max_shard_count=max_shards,
            max_total_header_bytes=max_total_header_bytes,
            max_total_request_count=max_total_requests,
            max_total_metadata_records=max_total_metadata,
            max_total_tensor_descriptors=max_total_tensors,
            max_serialized_inventory_bytes=max_inventory_bytes,
        )
        reusable: dict[str, HeaderInventoryEnvelope] = {}
        if not regenerate:
            search_paths = sorted(
                inventory_dir.glob("*.header.inventory.json")
            ) + sorted(output_path.parent.glob("*.header.inventory.json"))
            for inventory_path in search_paths:
                envelope = load_header_inventory(inventory_path)
                remote_path = envelope.inventory.file.path
                if remote_path not in paths:
                    continue
                if remote_path in reusable:
                    if reusable[remote_path].integrity != envelope.integrity:
                        raise OmivInputError(
                            f"conflicting reusable inventories found for {remote_path}"
                        )
                    continue
                validate_reusable_inventory(
                    envelope,
                    snapshot=snapshot,
                    expected_path=remote_path,
                    expected_policy_sha256=policy.digest,
                )
                reusable[remote_path] = envelope

        inventory_dir.mkdir(parents=True, exist_ok=True)
        inventories = []
        reused_count = 0
        client = BoundedRangeClient(max_response_bytes=policy.max_request_bytes)
        for candidate_path in paths:
            shard_output = inventory_dir / (
                candidate_path.rsplit("/", 1)[-1][:-5]
                + ".header.inventory.json"
            )
            existing = reusable.get(candidate_path)
            if existing is not None:
                if not shard_output.is_file():
                    atomic_write_text(
                        shard_output,
                        pretty_header_json(existing),
                        forbidden_inputs=inputs,
                    )
                inventories.append(existing)
                reused_count += 1
                continue
            file = selected_snapshot_file(snapshot, candidate_path)
            source = RangeBackedByteSource(
                url=resolved_file_url(snapshot, candidate_path),
                file_size=file.byte_size,
                client=client,
                policy=policy,
            )
            parsed = RemoteGGUFHeaderParser(policy).parse(
                source,
                repository=snapshot.snapshot.repository,
                snapshot_sha256=snapshot.integrity.sha256,
                file=file,
            )
            envelope = build_header_inventory_envelope(parsed)
            atomic_write_text(
                shard_output,
                pretty_header_json(envelope),
                forbidden_inputs=inputs,
            )
            inventories.append(envelope)
        combined = aggregate_split_inventories(
            snapshot,
            inventories,
            reused_inventory_count=reused_count,
            limits=limits,
        )
        inventory_envelope = build_split_inventory_envelope(combined)
        report_envelope = build_split_report(inventory_envelope)
        atomic_write_text(
            output_path,
            pretty_split_json(inventory_envelope),
            forbidden_inputs=inputs,
        )
        atomic_write_text(
            report_output,
            pretty_split_json(report_envelope),
            forbidden_inputs=inputs,
        )
        atomic_write_text(
            markdown_output,
            render_split_markdown(report_envelope),
            forbidden_inputs=inputs,
        )
    except (
        OSError,
        UnicodeError,
        ValidationError,
        OmivInputError,
        RangeValidationError,
    ) as exc:
        typer.echo(f"ERROR remote split GGUF aggregation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{report_envelope.report.execution.result.value.upper()} remote split GGUF "
        f"{inventory_envelope.integrity.sha256} shards={combined.shard_count} "
        f"tensors={combined.aggregated_tensor_count}"
    )
    if report_envelope.report.execution.exit_code:
        raise typer.Exit(code=1)


@app.command("remote-split-inventory-verify")
def remote_split_inventory_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify a combined split GGUF inventory and all recorded policy linkages."""
    try:
        envelope = load_split_inventory(input_path)
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not split_inventory_integrity_matches(envelope):
        typer.echo("FAIL split inventory integrity mismatch")
        raise typer.Exit(code=1)
    typer.echo(f"PASS split inventory integrity {envelope.integrity.sha256}")


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
        if schema == SPLIT_REPORT_SCHEMA:
            split_envelope = load_split_report(input_path)
            if not split_report_integrity_matches(split_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_split_markdown(split_envelope)
        elif schema == HEADER_REPORT_SCHEMA:
            header_envelope = load_header_report(input_path)
            if not header_report_integrity_matches(header_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_header_markdown(header_envelope)
        elif schema == MAPPING_REPORT_SCHEMA_ID:
            mapping_envelope = load_mapping_report_envelope(input_path)
            if not mapping_report_integrity_matches(mapping_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_mapping_markdown(mapping_envelope)
        elif schema == PROVENANCE_REPORT_SCHEMA_ID:
            provenance_envelope = load_provenance_report_envelope(input_path)
            if not provenance_report_integrity_matches(provenance_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_provenance_markdown(provenance_envelope)
        elif schema in REMOTE_REPORT_SCHEMAS:
            remote_envelope = load_remote_report(input_path)
            if not remote_report_integrity_matches(remote_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_remote_markdown(remote_envelope)
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
        if schema == SPLIT_REPORT_SCHEMA:
            split_envelope = load_split_report(input_path)
            if not split_report_integrity_matches(split_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {split_envelope.integrity.sha256}")
            return
        if schema == HEADER_REPORT_SCHEMA:
            header_envelope = load_header_report(input_path)
            if not header_report_integrity_matches(header_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {header_envelope.integrity.sha256}")
            return
        if schema == MAPPING_REPORT_SCHEMA_ID:
            mapping_envelope = load_mapping_report_envelope(input_path)
            if not mapping_report_integrity_matches(mapping_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {mapping_envelope.integrity.sha256}")
            return
        if schema == PROVENANCE_REPORT_SCHEMA_ID:
            provenance_envelope = load_provenance_report_envelope(input_path)
            if not provenance_report_integrity_matches(provenance_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {provenance_envelope.integrity.sha256}")
            return
        if schema in REMOTE_REPORT_SCHEMAS:
            remote_envelope = load_remote_report(input_path)
            if not remote_report_integrity_matches(remote_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {remote_envelope.integrity.sha256}")
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
