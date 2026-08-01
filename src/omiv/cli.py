"""Command-line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from omiv.article.builder import (
    CLAIM_PATH,
    INDEX_PATH,
    MANIFEST_PATH,
    REPRO_PATH,
    build_article_index,
    build_article_package,
)
from omiv.article.verification import (
    PublicationClaimError,
    verify_article_package,
    verify_claim_registry,
    verify_evidence_manifest,
)
from omiv.article.verification import (
    pretty_json as pretty_article_json,
)
from omiv.attestations.builder import build_attestation
from omiv.attestations.custody import append_attestation_to_ledger
from omiv.attestations.models import (
    ArtifactAttestationInput,
)
from omiv.attestations.models import (
    Authenticity as AttestationAuthenticity,
)
from omiv.attestations.reporting import (
    build_attestation_report,
    render_attestation_markdown,
    verify_attestation_report,
    write_attestation_bundle,
)
from omiv.attestations.segment import verify_attestation_custody_segment
from omiv.attestations.verification import load_attestation, verify_attestation
from omiv.canonical import canonical_sha256, load_json_value
from omiv.comparison.engine import build_structural_comparison
from omiv.comparison.models import COMPARISON_REPORT_SCHEMA
from omiv.comparison.reporting import (
    render_comparison_markdown,
    selected_profile_exit_code,
    verify_comparison_inventory,
    verify_comparison_report,
    write_comparison_bundle,
)
from omiv.custody.append import append_event
from omiv.custody.builder import build_evidence_custody_ledger
from omiv.custody.models import CustodyEventInput, LifecycleCompleteness
from omiv.custody.passport import (
    build_custody_linked_passport,
    load_custody_linked_passport,
    render_linked_passport_markdown,
    verify_custody_linked_passport,
    write_custody_linked_passport,
)
from omiv.custody.policy import selected_profile_result as custody_profile_result
from omiv.custody.reporting import (
    build_custody_report,
    render_custody_markdown,
    verify_custody_report,
    write_custody_bundle,
)
from omiv.custody.reporting import (
    pretty_json as pretty_custody_json,
)
from omiv.custody.verification import load_custody_ledger, verify_custody_ledger
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
from omiv.mapping.grouped_reporting import load_mapping_report, write_mapping_artifacts
from omiv.mapping.grouped_reporting import (
    mapping_report_integrity_matches as grouped_mapping_report_integrity_matches,
)
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
from omiv.model_packs.kimi_k3.gguf_models import ONTOLOGY_REPORT_SCHEMA
from omiv.model_packs.kimi_k3.gguf_reporting import (
    build_ontology_inventory_envelope,
    build_ontology_report,
    load_ontology_inventory,
    load_ontology_report,
    ontology_inventory_integrity_matches,
    ontology_inventory_links_split,
    ontology_report_integrity_matches,
    pretty_ontology_json,
    render_ontology_markdown,
)
from omiv.model_packs.kimi_k3.gguf_validator import (
    build_kimi_k3_gguf_ontology,
)
from omiv.model_packs.kimi_k3.semantic_mapping import run_kimi_mapping
from omiv.model_packs.registry import get_model_pack, list_model_packs
from omiv.models import ModelInventory
from omiv.normalizer import normalize_inventory, write_inventory
from omiv.passport.builder import build_passport
from omiv.passport.models import UsageOutcome, VerificationMode
from omiv.passport.policy import selected_profile_result
from omiv.passport.reporting import render_passport_markdown, write_passport
from omiv.passport.verification import load_passport, verify_passport
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
    header_inventory_integrity_matches,
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
    snapshot_integrity_matches,
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
from omiv.trust.algorithms import load_private_key, load_public_key, raw_public_key
from omiv.trust.models import (
    SignaturePurpose,
    SignatureReport,
    SignedObjectType,
)
from omiv.trust.reporting import render_markdown as render_trust_markdown
from omiv.trust.reporting import write_outputs as write_trust_outputs
from omiv.trust.signing import (
    build_descriptor,
    build_key_identity_from_public,
    build_signature_record,
    build_signed_envelope,
)
from omiv.trust.verification import (
    load_bundle as load_trust_bundle,
)
from omiv.trust.verification import (
    load_context as load_evaluation_context,
)
from omiv.trust.verification import load_delegation as load_delegation_record
from omiv.trust.verification import (
    load_envelope as load_signed_envelope,
)
from omiv.trust.verification import (
    load_policy as load_trust_policy,
)
from omiv.trust.verification import load_revocation as load_revocation_record
from omiv.trust.verification import (
    pretty_json as pretty_trust_json,
)
from omiv.trust.verification import verify_bundle as verify_static_trust_bundle
from omiv.trust.verification import verify_delegation_record
from omiv.trust.verification import (
    verify_envelope as verify_signed_envelope,
)
from omiv.trust.verification import (
    verify_report as verify_signature_report,
)
from omiv.validation.builder import build_independent_validation
from omiv.validation.models import VALIDATION_REPORT_SCHEMA
from omiv.validation.reporting import (
    render_validation_markdown,
    verify_validation_inventory,
    verify_validation_report,
    write_validation_bundle,
)
from omiv.validators.kimi_k3 import validate_inventory

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)
model_packs_app = typer.Typer(no_args_is_help=True)
passport_app = typer.Typer(no_args_is_help=True)
custody_app = typer.Typer(no_args_is_help=True)
attestation_app = typer.Typer(no_args_is_help=True)
trust_app = typer.Typer(no_args_is_help=True)
app.add_typer(model_packs_app, name="model-packs")
app.add_typer(passport_app, name="passport")
app.add_typer(custody_app, name="custody")
app.add_typer(attestation_app, name="attestation")
app.add_typer(trust_app, name="trust")
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
    report_output: Annotated[Path | None, typer.Option("--report-output", dir_okay=False)] = None,
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


@app.command("remote-snapshot-verify")
def remote_snapshot_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify a canonical repository snapshot envelope offline."""
    try:
        envelope = load_snapshot(input_path)
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not snapshot_integrity_matches(envelope):
        typer.echo("FAIL snapshot integrity mismatch")
        raise typer.Exit(code=1)
    typer.echo(f"PASS snapshot integrity {envelope.integrity.sha256}")


@app.command("remote-range-probe")
def remote_range_probe(
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
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
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
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
        f"{report.report.execution.result.value.upper()} GGUF prefix {report.integrity.sha256}"
    )
    if report.report.execution.exit_code:
        raise typer.Exit(code=1)


@app.command("remote-gguf-header")
def remote_gguf_header(
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
    file_path: Annotated[str, typer.Option("--file")],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
    max_header_bytes: Annotated[int, typer.Option("--max-header-bytes", min=24)] = 64 * 1024 * 1024,
    max_request_bytes: Annotated[int, typer.Option("--max-request-bytes", min=24)] = 256 * 1024,
    read_ahead_bytes: Annotated[int, typer.Option("--read-ahead-bytes", min=0)] = 256 * 1024,
    max_metadata_count: Annotated[int, typer.Option("--max-metadata-count", min=0)] = 1_000_000,
    max_tensor_count: Annotated[int, typer.Option("--max-tensor-count", min=0)] = 1_000_000,
    max_string_bytes: Annotated[int, typer.Option("--max-string-bytes", min=0)] = 16 * 1024 * 1024,
    max_metadata_key_bytes: Annotated[int, typer.Option("--max-metadata-key-bytes", min=1)] = 1024,
    max_array_elements: Annotated[int, typer.Option("--max-array-elements", min=0)] = 10_000_000,
    max_tensor_name_bytes: Annotated[int, typer.Option("--max-tensor-name-bytes", min=1)] = 4096,
    max_tensor_dimensions: Annotated[
        int, typer.Option("--max-tensor-dimensions", min=1, max=64)
    ] = 4,
    max_alignment: Annotated[int, typer.Option("--max-alignment", min=1)] = 4096,
    max_request_count: Annotated[int, typer.Option("--max-request-count", min=1)] = 4096,
    max_preview_bytes: Annotated[int, typer.Option("--max-preview-bytes", min=0, max=65536)] = 256,
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


@app.command("remote-gguf-header-inventory-verify")
def remote_gguf_header_inventory_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify one canonical remote GGUF complete-header inventory offline."""
    try:
        envelope = load_header_inventory(input_path)
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if not header_inventory_integrity_matches(envelope):
        typer.echo("FAIL header inventory integrity mismatch")
        raise typer.Exit(code=1)
    typer.echo(f"PASS header inventory integrity {envelope.integrity.sha256}")


@app.command("remote-split-gguf")
def remote_split_gguf(
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
    inventory_dir: Annotated[Path, typer.Option("--inventory-dir", file_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
    regenerate: Annotated[bool, typer.Option("--regenerate")] = False,
    max_shards: Annotated[int, typer.Option("--max-shards", min=1)] = 256,
    max_total_header_bytes: Annotated[int, typer.Option("--max-total-header-bytes", min=24)] = 1024
    * 1024
    * 1024,
    max_total_requests: Annotated[int, typer.Option("--max-total-requests", min=1)] = 65536,
    max_total_metadata: Annotated[int, typer.Option("--max-total-metadata", min=1)] = 2_000_000,
    max_total_tensors: Annotated[int, typer.Option("--max-total-tensors", min=1)] = 5_000_000,
    max_inventory_bytes: Annotated[int, typer.Option("--max-inventory-bytes", min=1024)] = 1024
    * 1024
    * 1024,
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
            search_paths = sorted(inventory_dir.glob("*.header.inventory.json")) + sorted(
                output_path.parent.glob("*.header.inventory.json")
            )
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
                candidate_path.rsplit("/", 1)[-1][:-5] + ".header.inventory.json"
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


def _default_split_metadata_inventory(split_path: Path, remote_path: str) -> Path:
    suffix = ".split.inventory.json"
    if not split_path.name.endswith(suffix):
        raise OmivInputError("cannot derive metadata inventory path; use --metadata-inventory")
    collection = split_path.name[: -len(suffix)]
    file_name = remote_path.rsplit("/", 1)[-1]
    if not file_name.endswith(".gguf"):
        raise OmivInputError("broadest metadata shard is not a GGUF file")
    return split_path.parent / collection / "shards" / f"{file_name[:-5]}.header.inventory.json"


@app.command("kimi-k3-gguf-ontology")
def kimi_k3_gguf_ontology(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output_path: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
    model_pack_id: Annotated[str, typer.Option("--model-pack")] = "kimi-k3",
    metadata_inventory: Annotated[
        Path | None, typer.Option("--metadata-inventory", dir_okay=False)
    ] = None,
) -> None:
    """Validate a verified split inventory against the Kimi K3 target ontology."""
    try:
        split = load_split_inventory(input_path)
        metadata_path = metadata_inventory or _default_split_metadata_inventory(
            input_path,
            split.inventory.metadata_consistency.broadest_metadata_shard,
        )
        if not metadata_path.is_file():
            raise OmivInputError(
                f"linked broadest-metadata header inventory not found: {metadata_path.name}"
            )
        inputs = (input_path, metadata_path)
        outputs = (output_path, report_output, markdown_output)
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("ontology inventory and report outputs must be distinct")
        for output in outputs:
            validate_output_path(output, forbidden_inputs=inputs)
        header = load_header_inventory(metadata_path)
        pack = get_model_pack(model_pack_id)
        inventory = build_kimi_k3_gguf_ontology(split, header, pack)
        inventory_envelope = build_ontology_inventory_envelope(inventory)
        report_envelope = build_ontology_report(inventory_envelope)
        atomic_write_text(
            output_path,
            pretty_ontology_json(inventory_envelope),
            forbidden_inputs=inputs,
        )
        atomic_write_text(
            report_output,
            pretty_ontology_json(report_envelope),
            forbidden_inputs=inputs,
        )
        atomic_write_text(
            markdown_output,
            render_ontology_markdown(report_envelope),
            forbidden_inputs=inputs,
        )
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR Kimi K3 GGUF ontology failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{report_envelope.report.execution.result.value.upper()} Kimi K3 GGUF ontology "
        f"{inventory_envelope.integrity.sha256} "
        f"tensors={inventory.classification.total_tensor_count} "
        f"classified={inventory.classification.classified_count}"
    )
    if report_envelope.report.execution.exit_code:
        raise typer.Exit(code=1)


@app.command("kimi-k3-gguf-ontology-inventory-verify")
def kimi_k3_gguf_ontology_inventory_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    source_path: Annotated[
        Path | None, typer.Option("--source", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Verify ontology integrity, policies, and optional source-split linkage."""
    try:
        envelope = load_ontology_inventory(input_path)
        if not ontology_inventory_integrity_matches(envelope):
            typer.echo("FAIL ontology inventory integrity mismatch")
            raise typer.Exit(code=1)
        if source_path is not None:
            split = load_split_inventory(source_path)
            if not ontology_inventory_links_split(envelope, split):
                typer.echo("FAIL ontology source split linkage mismatch")
                raise typer.Exit(code=1)
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS ontology inventory integrity {envelope.integrity.sha256}"
        + (" source-linkage=verified" if source_path is not None else "")
    )


@app.command("kimi-k3-semantic-mapping")
def kimi_k3_semantic_mapping(
    source_inventory: Annotated[
        Path, typer.Option("--source-inventory", exists=True, dir_okay=False)
    ],
    target_split_inventory: Annotated[
        Path, typer.Option("--target-split-inventory", exists=True, dir_okay=False)
    ],
    target_ontology_inventory: Annotated[
        Path, typer.Option("--target-ontology-inventory", exists=True, dir_okay=False)
    ],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
) -> None:
    """Map verified Kimi checkpoint identities to target GGUF descriptors offline."""
    try:
        inv = run_kimi_mapping(source_inventory, target_split_inventory, target_ontology_inventory)
        inv, env = write_mapping_artifacts(inv, output, report_output, markdown_output)
        typer.echo(f"mapping inventory {inv.inventory_digest}")
        if any(f.status == "FAIL" for f in inv.findings):
            raise typer.Exit(code=1)
    except (OmivInputError, ValidationError, ValueError, OSError) as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("kimi-k3-semantic-mapping-inventory-verify")
def kimi_k3_semantic_mapping_inventory_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify a compact grouped mapping inventory digest."""
    try:
        from omiv.mapping.grouped_engine import validate_results_against_policy
        from omiv.mapping.grouped_reporting import load_mapping_inventory
        from omiv.model_packs.kimi_k3.mapping_policy import kimi_mapping_policy
        from omiv.model_packs.kimi_k3.pack import KimiK3ModelPack

        inv = load_mapping_inventory(input_path)
        policy = kimi_mapping_policy()
        pack = KimiK3ModelPack()
        expected_pack = {
            "pack_id": pack.pack_id,
            "pack_version": pack.pack_version,
            "capabilities": sorted(capability.value for capability in pack.capabilities),
            "digest": pack.metadata.digest,
        }
        if inv.model_pack != expected_pack:
            raise ValueError("mapping inventory model-pack identity is not canonical")
        if inv.mapping_policy_digest != policy.digest:
            raise ValueError("mapping inventory policy digest is not canonical")
        if inv.converter_evidence_revision != policy.converter_revision:
            raise ValueError("mapping inventory converter revision is not canonical")
        validate_results_against_policy(policy, inv.mapping_results)
        expected = inv.inventory_digest
        actual = canonical_sha256(
            {
                k: v
                for k, v in inv.model_dump(mode="json", by_alias=True).items()
                if k != "inventory_digest"
            }
        )
        if expected != actual:
            typer.echo("FAIL mapping inventory integrity mismatch")
            raise typer.Exit(code=1)
        typer.echo(f"PASS mapping inventory integrity {actual}")
    except (OmivInputError, ValidationError, ValueError, OSError) as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("independent-validation")
def independent_validation(
    subject: Annotated[str, typer.Option("--subject")],
    variant: Annotated[str, typer.Option("--variant")],
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
    split_inventory: Annotated[
        Path, typer.Option("--split-inventory", exists=True, dir_okay=False)
    ],
    ontology_inventory: Annotated[
        Path, typer.Option("--ontology-inventory", exists=True, dir_okay=False)
    ],
    mapping_inventory: Annotated[
        Path, typer.Option("--mapping-inventory", exists=True, dir_okay=False)
    ],
    profile: Annotated[str, typer.Option("--profile")],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
) -> None:
    """Compose a deterministic independent validation bundle entirely offline."""
    try:
        inventory = build_independent_validation(
            root=Path.cwd(),
            subject=subject,
            variant=variant,
            snapshot_path=snapshot_path,
            split_path=split_inventory,
            ontology_path=ontology_inventory,
            mapping_path=mapping_inventory,
            selected_profile=profile,
        )
        report = write_validation_bundle(
            inventory,
            output,
            report_output,
            markdown_output,
            forbidden_inputs=tuple(
                Path.cwd() / entry.relative_path for entry in inventory.artifact_index.entries
            ),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR independent validation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    selected = next(item for item in inventory.profile_results if item.profile_name == profile)
    typer.echo(
        f"{selected.outcome.value} independent validation "
        f"inventory={inventory.inventory_digest} "
        f"report={report.report.report_digest}"
    )
    if not selected.satisfied:
        raise typer.Exit(code=1)


@app.command("independent-validation-inventory-verify")
def independent_validation_inventory_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    artifact_root: Annotated[Path, typer.Option("--artifact-root", file_okay=False)] = Path("."),
) -> None:
    """Reconstruct a validation inventory from all canonical dependencies offline."""
    try:
        inventory = verify_validation_inventory(input_path, artifact_root)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS independent validation inventory {inventory.inventory_digest}")


@passport_app.command("create")
def passport_create(
    validation: Annotated[Path, typer.Option("--validation", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    custody_ledger: Annotated[
        Path | None, typer.Option("--custody-ledger", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Create JSON and Markdown passports from verified validation evidence offline."""
    try:
        root = root.resolve()
        validation_path = validation.resolve()
        reference = validation_path.relative_to(root).as_posix()
        inventory = verify_validation_inventory(validation_path, root)
        passport = build_passport(inventory, validation_reference=reference)
        if profile is not None:
            selected = selected_profile_result(passport.usage_profiles, profile)
        if custody_ledger is None:
            write_passport(
                passport,
                output,
                markdown_output,
                forbidden_inputs=(validation_path,),
            )
            passport_id = passport.passport_id
            passport_digest = passport.passport_digest
        else:
            ledger_path = custody_ledger.resolve()
            ledger = verify_custody_ledger(ledger_path, root)
            ledger_reference = ledger_path.relative_to(root).as_posix()
            linked = build_custody_linked_passport(
                passport, ledger, ledger_reference=ledger_reference
            )
            write_custody_linked_passport(
                linked,
                output,
                markdown_output,
                forbidden_inputs=(validation_path, ledger_path),
            )
            passport_id = linked.passport_id
            passport_digest = linked.passport_digest
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR passport creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS Model Passport id={passport_id} digest={passport_digest}")
    if profile is not None and selected.outcome not in {
        UsageOutcome.SUITABLE_WITH_LIMITATIONS,
    }:
        raise typer.Exit(code=1)


@passport_app.command("verify")
def passport_verify_command(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
    digest_only: Annotated[bool, typer.Option("--digest-only")] = False,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
) -> None:
    """Verify a passport's integrity and, by default, all evidence dependencies offline."""
    try:
        schema = load_json_value(input_path.read_text(encoding="utf-8")).get("schema")
        if schema == "omiv.model-passport.v2":
            linked = verify_custody_linked_passport(input_path, root=root, digest_only=digest_only)
            mode = "digest_only_verification" if digest_only else "full_verification"
            passport_id = linked.passport_id
            passport_digest = linked.passport_digest
            profiles = linked.usage_profiles
        else:
            result = verify_passport(input_path, root=root, digest_only=digest_only)
            passport = load_passport(input_path)
            mode = result.mode.value
            passport_id = result.passport_id
            passport_digest = result.passport_digest
            profiles = passport.usage_profiles
        if profile is not None:
            selected = selected_profile_result(profiles, profile)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR passport verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    label = "PASS" if mode != VerificationMode.UNVERIFIABLE_REFERENCE.value else "UNVERIFIABLE"
    typer.echo(f"{label} Model Passport mode={mode} id={passport_id} digest={passport_digest}")
    if mode == VerificationMode.UNVERIFIABLE_REFERENCE.value:
        raise typer.Exit(code=2)
    if profile is not None and selected.outcome != UsageOutcome.SUITABLE_WITH_LIMITATIONS:
        raise typer.Exit(code=1)


@passport_app.command("show")
def passport_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Render a tamper-checked passport as a compact personal summary."""
    try:
        schema = load_json_value(input_path.read_text(encoding="utf-8")).get("schema")
        if schema == "omiv.model-passport.v2":
            text = render_linked_passport_markdown(load_custody_linked_passport(input_path))
        else:
            text = render_passport_markdown(load_passport(input_path))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR passport display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(text, nl=False)


@custody_app.command("create")
def custody_create(
    passport_path: Annotated[Path, typer.Option("--passport", exists=True, dir_okay=False)],
    validation: Annotated[Path, typer.Option("--validation", exists=True, dir_okay=False)],
    profile: Annotated[str, typer.Option("--profile")],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Build an evidence-derived, hash-linked custody segment offline."""
    try:
        root = root.resolve()
        passport_file = passport_path.resolve()
        validation_file = validation.resolve()
        verify_passport(passport_file, root=root)
        passport = load_passport(passport_file)
        inventory = verify_validation_inventory(validation_file, root)
        ledger = build_evidence_custody_ledger(
            passport,
            inventory,
            passport_reference=passport_file.relative_to(root).as_posix(),
            validation_reference=validation_file.relative_to(root).as_posix(),
            selected_profile=profile,
        )
        report = write_custody_bundle(
            ledger,
            output,
            report_output,
            markdown_output,
            forbidden_inputs=(passport_file, validation_file),
        )
        selected = custody_profile_result(ledger.missing_event_analysis)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR custody creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS custody chain={ledger.chain_id} ledger={ledger.ledger_digest} "
        f"report={report.report.report_digest} profile={selected.status.value}"
    )
    if selected.status != LifecycleCompleteness.COMPLETE:
        raise typer.Exit(code=1)


@custody_app.command("append")
def custody_append(
    ledger_path: Annotated[Path, typer.Option("--ledger", exists=True, dir_okay=False)],
    event_path: Annotated[Path, typer.Option("--event", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Append one strict user-declared event without mutating the source ledger."""
    try:
        if output.resolve() == ledger_path.resolve():
            raise OmivInputError("in-place custody ledger overwrite is not allowed")
        ledger = verify_custody_ledger(ledger_path, root.resolve())
        raw = load_json_value(event_path.read_text(encoding="utf-8"))
        event_input = CustodyEventInput.model_validate(raw)
        updated = append_event(ledger, event_input)
        atomic_write_text(
            output,
            pretty_custody_json(updated),
            forbidden_inputs=(ledger_path.resolve(), event_path.resolve()),
        )
        selected = custody_profile_result(updated.missing_event_analysis)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR custody append failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS custody append event={updated.events[-1].event_id}")
    if selected.status != LifecycleCompleteness.COMPLETE:
        raise typer.Exit(code=1)


@custody_app.command("verify")
def custody_verify_command(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Fully verify ledger hashes, links, policy, and canonical evidence offline."""
    try:
        ledger = verify_custody_ledger(input_path, root.resolve())
        selected = custody_profile_result(ledger.missing_event_analysis)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR custody verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS custody mode=full_verification chain={ledger.chain_id} "
        f"integrity={ledger.ledger_integrity.value} profile={selected.status.value}"
    )
    if selected.status != LifecycleCompleteness.COMPLETE:
        raise typer.Exit(code=1)


@custody_app.command("show")
def custody_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Show an integrity-checked custody ledger as compact Markdown."""
    try:
        ledger = load_custody_ledger(input_path)
        text = render_custody_markdown(build_custody_report(ledger))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR custody display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(text, nl=False)


@custody_app.command("report-verify")
def custody_report_verify_command(
    report: Annotated[Path, typer.Option("--report", exists=True, dir_okay=False)],
    ledger: Annotated[Path, typer.Option("--ledger", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Reconstruct a custody report from its fully verified ledger."""
    try:
        envelope = verify_custody_report(report, ledger, root.resolve())
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR custody report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS custody report {envelope.report.report_digest}")


def _attestation_exit_incomplete(authenticity: AttestationAuthenticity) -> bool:
    return authenticity in {
        AttestationAuthenticity.DECLARED,
        AttestationAuthenticity.UNATTESTED,
        AttestationAuthenticity.UNVERIFIED,
    }


@attestation_app.command("create")
def attestation_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
) -> None:
    """Build a canonical artifact attestation and deterministic report offline."""
    try:
        raw = load_json_value(input_path.read_text(encoding="utf-8"))
        value = build_attestation(ArtifactAttestationInput.model_validate(raw))
        report = build_attestation_report(value)
        write_attestation_bundle(
            value,
            report,
            output,
            report_output,
            markdown_output,
            forbidden_inputs=(input_path,),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR attestation creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS attestation id={value.attestation_id} digest={value.attestation_digest} "
        f"authenticity={value.authenticity.value} "
        f"signature={value.verification_summary.cryptographic_signature} "
        f"issuer={value.verification_summary.issuer_authentication} "
        f"payload={value.verification_summary.payload_status} "
        f"runtime={value.verification_summary.runtime_status}"
    )
    if _attestation_exit_incomplete(value.authenticity):
        raise typer.Exit(code=1)


@attestation_app.command("verify")
def attestation_verify_command(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify schema, policy, canonical identity, digest, and reconstructed trust."""
    try:
        value = verify_attestation(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR attestation verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS attestation id={value.attestation_id} integrity=VALID "
        f"authenticity={value.authenticity.value} "
        f"provenance={value.verification_summary.provenance_strength.value} "
        f"signature={value.verification_summary.cryptographic_signature} "
        f"issuer={value.verification_summary.issuer_authentication} "
        f"payload={value.verification_summary.payload_status} "
        f"runtime={value.verification_summary.runtime_status}"
    )
    if _attestation_exit_incomplete(value.authenticity):
        raise typer.Exit(code=1)


@attestation_app.command("show")
def attestation_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Show a strict attestation with its trust boundaries in Markdown."""
    try:
        value = load_attestation(input_path)
        text = render_attestation_markdown(build_attestation_report(value))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR attestation display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(text, nl=False)


@attestation_app.command("report-verify")
def attestation_report_verify_command(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    attestation: Annotated[Path, typer.Option("--attestation", exists=True, dir_okay=False)],
) -> None:
    """Reconstruct an attestation report from its canonical attestation."""
    try:
        report = verify_attestation_report(input_path, attestation)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR attestation report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS attestation report {report.report.report_digest}")


@attestation_app.command("append-custody")
def attestation_append_custody(
    attestation: Annotated[Path, typer.Option("--attestation", exists=True, dir_okay=False)],
    ledger: Annotated[Path, typer.Option("--ledger", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Verify an attestation and append its mapped event to a verified ledger."""
    try:
        updated = append_attestation_to_ledger(
            attestation_path=attestation,
            ledger_path=ledger,
            output_path=output,
            root=root.resolve(),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR attestation custody append failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS attestation custody append event={updated.events[-1].event_id} "
        f"ledger={updated.ledger_digest}"
    )


@attestation_app.command("custody-verify")
def attestation_custody_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Verify a portable v2 custody segment reconstructed from one attestation."""
    try:
        value = verify_attestation_custody_segment(input_path, root.resolve())
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR attestation custody verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS attestation custody chain={value.chain_id} "
        f"ledger={value.ledger_digest} completeness={value.lifecycle_completeness.value} "
        "genesis=PORTABLE_SEGMENT_BEGINNING signed_events=0"
    )
    if value.lifecycle_completeness != LifecycleCompleteness.COMPLETE:
        raise typer.Exit(code=1)


@trust_app.command("key-inspect")
def trust_key_inspect(
    public_key_path: Annotated[Path, typer.Option("--public-key", exists=True, dir_okay=False)],
) -> None:
    """Inspect an Ed25519 public key and print a deterministic public-only identity."""
    try:
        public_key = load_public_key(public_key_path)
        key = build_key_identity_from_public(
            public_key,
            allowed_object_types=list(SignedObjectType),
            allowed_purposes=[
                SignaturePurpose.ATTESTATION_ISSUANCE,
                SignaturePurpose.EXECUTION_RECORD_ISSUANCE,
                SignaturePurpose.CUSTODY_EVENT_ISSUANCE,
                SignaturePurpose.CUSTODY_SEGMENT_ISSUANCE,
                SignaturePurpose.PASSPORT_ISSUANCE,
            ],
            limitations=[
                "Inspection records public material only; trust and signer identity "
                "are not inferred."
            ],
        )
    except (OSError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR public-key inspection failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(pretty_trust_json(key), nl=False)


@trust_app.command("sign")
def trust_sign(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    object_type: Annotated[SignedObjectType, typer.Option("--object-type")],
    purpose: Annotated[SignaturePurpose, typer.Option("--purpose")],
    private_key_path: Annotated[Path, typer.Option("--private-key", exists=True, dir_okay=False)],
    public_key_path: Annotated[Path, typer.Option("--public-key", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    policy_path: Annotated[
        Path | None, typer.Option("--policy", exists=True, dir_okay=False)
    ] = None,
    trust_bundle_path: Annotated[
        Path | None, typer.Option("--trust-bundle", exists=True, dir_okay=False)
    ] = None,
    evaluation_context_path: Annotated[
        Path | None, typer.Option("--evaluation-context", exists=True, dir_okay=False)
    ] = None,
    report_output: Annotated[Path | None, typer.Option("--report-output", dir_okay=False)] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
    namespace: Annotated[str | None, typer.Option("--namespace")] = None,
    provider_artifact_scope: Annotated[
        str | None, typer.Option("--provider-artifact-scope")
    ] = None,
    binding_id: Annotated[str | None, typer.Option("--binding-id")] = None,
) -> None:
    """Create a detached Ed25519 signature envelope for one canonical OMIV object."""
    inputs = tuple(
        item
        for item in (
            input_path,
            private_key_path,
            public_key_path,
            policy_path,
            trust_bundle_path,
            evaluation_context_path,
        )
        if item is not None
    )
    try:
        raw = load_json_value(input_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise OmivInputError("signed input must be a canonical JSON object")
        private_key = load_private_key(private_key_path)
        public_key = load_public_key(public_key_path)
        if raw_public_key(private_key.public_key()) != raw_public_key(public_key):
            raise OmivInputError("private and public keys do not correspond")
        policy = load_trust_policy(policy_path) if policy_path else None
        bundle = load_trust_bundle(trust_bundle_path) if trust_bundle_path else None
        matching_keys = (
            [item for item in bundle.keys if item.public_key == raw_public_key(public_key).hex()]
            if bundle
            else []
        )
        if len(matching_keys) > 1:
            raise OmivInputError("trust bundle contains conflicting matching public keys")
        key = (
            matching_keys[0]
            if matching_keys
            else build_key_identity_from_public(
                public_key,
                allowed_object_types=[object_type],
                allowed_purposes=[purpose],
                namespaces=[namespace] if namespace else [],
                provider_artifact_scopes=(
                    [provider_artifact_scope] if provider_artifact_scope else []
                ),
            )
        )
        descriptor = build_descriptor(
            raw,
            object_type,
            purpose,
            policy_id=policy.policy_id if policy else None,
            namespace=namespace,
            provider_artifact_scope=provider_artifact_scope,
        )
        record = build_signature_record(descriptor, private_key, key, binding_id=binding_id)
        envelope = build_signed_envelope(raw, object_type, [record], keys=[key])
        report = None
        if report_output is not None or markdown_output is not None:
            if policy is None or trust_bundle_path is None:
                raise OmivInputError("report outputs require both --policy and --trust-bundle")
            if bundle is None:
                raise OmivInputError("trust bundle is unavailable")
            context = (
                load_evaluation_context(evaluation_context_path)
                if evaluation_context_path
                else None
            )
            report = verify_signed_envelope(envelope, bundle, policy, context)
        outputs = [item for item in (output, report_output, markdown_output) if item]
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("trust outputs must use distinct paths")
        write_trust_outputs(
            envelope,
            report,
            envelope_path=output,
            report_path=report_output,
            markdown_path=markdown_output,
            forbidden_inputs=inputs,
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR signing failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS signed object={envelope.signed_object_id} envelope={envelope.envelope_id} "
        f"signature={record.signature_id} key={key.key_id}"
    )


def _trust_report_exit(report: SignatureReport) -> int:
    status = report.overall_status.value
    if status == "TRUSTED_SIGNATURE_WITH_LIMITATIONS":
        return 0
    if status in {
        "INVALID_SIGNATURE",
        "REVOKED",
        "EXPIRED",
        "NOT_YET_VALID",
        "EXPIRATION_NOT_EVALUATED",
        "REVOCATION_NOT_EVALUATED",
        "UNSUPPORTED",
    }:
        return 2
    return 1


@trust_app.command("verify")
def trust_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    trust_bundle_path: Annotated[Path, typer.Option("--trust-bundle", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    evaluation_context_path: Annotated[
        Path | None, typer.Option("--evaluation-context", exists=True, dir_okay=False)
    ] = None,
    report_output: Annotated[Path | None, typer.Option("--report-output", dir_okay=False)] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
) -> None:
    """Verify signature integrity and policy trust entirely offline."""
    try:
        envelope = load_signed_envelope(input_path)
        bundle = load_trust_bundle(trust_bundle_path)
        policy = load_trust_policy(policy_path)
        context = (
            load_evaluation_context(evaluation_context_path) if evaluation_context_path else None
        )
        report = verify_signed_envelope(envelope, bundle, policy, context)
        if report_output is not None:
            atomic_write_text(
                report_output,
                pretty_trust_json(report),
                forbidden_inputs=(input_path, trust_bundle_path, policy_path),
            )
        if markdown_output is not None:
            atomic_write_text(
                markdown_output,
                render_trust_markdown(report),
                forbidden_inputs=(input_path, trust_bundle_path, policy_path),
            )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR trust verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{report.overall_status.value} object={report.signed_object_id} "
        f"accepted={report.accepted_signature_count} report={report.report_digest}"
    )
    for result in report.signature_results:
        binding_status = (
            result.signer_binding_status.value
            if result.signer_binding_status
            else result.signer_binding.value
        )
        typer.echo(
            f"signature_integrity={result.signature_integrity.value} "
            f"trusted_by_selected_policy="
            f"{'YES' if result.trust_policy_status.value == 'TRUSTED_BY_POLICY' else 'NO'} "
            f"key={result.key_id} key_status={result.key_status.value} "
            f"signer_identity={result.signer_identity_status.value} "
            f"identity_verification={result.signer_identity_verification.value} "
            f"signer_binding={binding_status}"
        )
    typer.echo(
        f"claim_authenticity={report.underlying_claim.get('authenticity', 'NOT_APPLICABLE')} "
        f"provenance_strength="
        f"{report.underlying_claim.get('provenance_strength', 'NOT_APPLICABLE')} "
        f"claim_independently_proven=NO payload_integrity={report.payload_status} "
        f"numerical_fidelity={report.numerical_fidelity_status} "
        f"security={report.security_status} runtime={report.runtime_status} "
        f"approval={report.approval_status} "
        f"lifecycle_completeness={report.lifecycle_completeness}"
    )
    code = _trust_report_exit(report)
    if code:
        raise typer.Exit(code=code)


@trust_app.command("show")
def trust_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Show signed-envelope identities without asserting policy trust."""
    try:
        envelope = load_signed_envelope(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR signed-envelope display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"Object: {envelope.signed_object_type.value} {envelope.signed_object_id}\n"
        f"Canonical digest: {envelope.signed_object_digest}\n"
        f"Envelope: {envelope.envelope_id} {envelope.envelope_digest}\n"
        "Trust: NOT_EVALUATED\n"
        + "\n".join(
            f"Signature: {item.signature_id} key={item.key_id} purpose={item.purpose.value}"
            for item in envelope.signatures
        )
    )


@trust_app.command("bundle-verify")
def trust_bundle_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify a deterministic static trust bundle."""
    try:
        bundle = load_trust_bundle(input_path)
        verify_static_trust_bundle(bundle)
    except (OSError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR trust-bundle verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS trust bundle {bundle.bundle_id} {bundle.bundle_digest}")


@trust_app.command("report-verify")
def trust_report_verify(
    report_path: Annotated[Path, typer.Option("--report", exists=True, dir_okay=False)],
    envelope_path: Annotated[Path, typer.Option("--envelope", exists=True, dir_okay=False)],
    trust_bundle_path: Annotated[Path, typer.Option("--trust-bundle", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    evaluation_context_path: Annotated[
        Path | None, typer.Option("--evaluation-context", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Reconstruct a report from its signed envelope, bundle, policy, and context."""
    try:
        envelope = load_signed_envelope(envelope_path)
        bundle = load_trust_bundle(trust_bundle_path)
        policy = load_trust_policy(policy_path)
        context = (
            load_evaluation_context(evaluation_context_path) if evaluation_context_path else None
        )
        report = verify_signature_report(report_path, envelope, bundle, policy, context)
    except (OSError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR signature-report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS signature report {report.report_digest}")


@trust_app.command("delegation-verify")
def trust_delegation_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    trust_bundle_path: Annotated[Path, typer.Option("--trust-bundle", exists=True, dir_okay=False)],
) -> None:
    """Verify delegation identity, authorization signature, and bounded authority."""
    try:
        value = load_delegation_record(input_path)
        bundle = load_trust_bundle(trust_bundle_path)
        verify_delegation_record(value, bundle)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR delegation verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS delegation record {value.delegation_id} {value.delegation_digest}")


@trust_app.command("revocation-verify")
def trust_revocation_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Verify strict static revocation-record schema and identity."""
    try:
        value = load_revocation_record(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR revocation verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS revocation record-integrity {value.revocation_id} "
        f"{value.revocation_digest} authority=NOT_EVALUATED"
    )


@app.command("structural-compare")
def structural_compare(
    baseline_validation: Annotated[
        Path, typer.Option("--baseline-validation", exists=True, dir_okay=False)
    ],
    candidate_validation: Annotated[
        Path, typer.Option("--candidate-validation", exists=True, dir_okay=False)
    ],
    baseline_split: Annotated[Path, typer.Option("--baseline-split", exists=True, dir_okay=False)],
    candidate_split: Annotated[
        Path, typer.Option("--candidate-split", exists=True, dir_okay=False)
    ],
    baseline_ontology: Annotated[
        Path, typer.Option("--baseline-ontology", exists=True, dir_okay=False)
    ],
    candidate_ontology: Annotated[
        Path, typer.Option("--candidate-ontology", exists=True, dir_okay=False)
    ],
    baseline_mapping: Annotated[
        Path, typer.Option("--baseline-mapping", exists=True, dir_okay=False)
    ],
    candidate_mapping: Annotated[
        Path, typer.Option("--candidate-mapping", exists=True, dir_okay=False)
    ],
    profile: Annotated[str, typer.Option("--profile")],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
) -> None:
    """Compare two independently verified model artifacts entirely offline."""
    try:
        inventory = build_structural_comparison(
            root=Path.cwd(),
            baseline_validation_path=baseline_validation,
            candidate_validation_path=candidate_validation,
            baseline_split_path=baseline_split,
            candidate_split_path=candidate_split,
            baseline_ontology_path=baseline_ontology,
            candidate_ontology_path=candidate_ontology,
            baseline_mapping_path=baseline_mapping,
            candidate_mapping_path=candidate_mapping,
            selected_profile=profile,
        )
        report = write_comparison_bundle(inventory, output, report_output, markdown_output)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR structural comparison failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    selected = next(item for item in inventory.profile_results if item.profile_name == profile)
    typer.echo(
        f"{selected.outcome.value} structural comparison "
        f"inventory={inventory.comparison_digest} "
        f"report={report.report.report_digest}"
    )
    exit_code = selected_profile_exit_code(inventory)
    if exit_code:
        raise typer.Exit(code=exit_code)


@app.command("structural-comparison-inventory-verify")
def structural_comparison_inventory_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    artifact_root: Annotated[Path, typer.Option("--artifact-root", file_okay=False)] = Path("."),
) -> None:
    """Reconstruct a structural comparison from all verified dependencies."""
    try:
        inventory = verify_comparison_inventory(input_path, artifact_root)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS structural comparison inventory {inventory.comparison_digest}")


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
        if schema == COMPARISON_REPORT_SCHEMA:
            comparison_envelope = verify_comparison_report(input_path, Path.cwd())
            content = render_comparison_markdown(comparison_envelope)
        elif schema == VALIDATION_REPORT_SCHEMA:
            validation_envelope = verify_validation_report(input_path, Path.cwd())
            content = render_validation_markdown(validation_envelope)
        elif schema == ONTOLOGY_REPORT_SCHEMA:
            ontology_envelope = load_ontology_report(input_path)
            if not ontology_report_integrity_matches(ontology_envelope):
                raise OmivInputError("report integrity mismatch")
            content = render_ontology_markdown(ontology_envelope)
        elif schema == SPLIT_REPORT_SCHEMA:
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
        if schema == COMPARISON_REPORT_SCHEMA:
            comparison_envelope = verify_comparison_report(input_path, Path.cwd())
            typer.echo(f"PASS report integrity {comparison_envelope.integrity['sha256']}")
            return
        if schema == VALIDATION_REPORT_SCHEMA:
            validation_envelope = verify_validation_report(input_path, Path.cwd())
            typer.echo(f"PASS report integrity {validation_envelope.integrity['sha256']}")
            return
        if schema in {
            "omiv.semantic-mapping-report.v2",
            "omiv.semantic-mapping-report.v3",
        }:
            grouped_envelope = load_mapping_report(input_path)
            if not grouped_mapping_report_integrity_matches(grouped_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            if schema == "omiv.semantic-mapping-report.v3":
                from omiv.model_packs.kimi_k3.mapping_policy import kimi_mapping_policy
                from omiv.model_packs.kimi_k3.pack import KimiK3ModelPack

                pack = KimiK3ModelPack()
                expected_pack = {
                    "pack_id": pack.pack_id,
                    "pack_version": pack.pack_version,
                    "capabilities": sorted(capability.value for capability in pack.capabilities),
                    "digest": pack.metadata.digest,
                }
                if grouped_envelope.report.model_pack != expected_pack:
                    raise ValueError("mapping report model-pack identity is not canonical")
                if grouped_envelope.report.mapping_policy_digest != kimi_mapping_policy().digest:
                    raise ValueError("mapping report policy digest is not canonical")
            typer.echo(f"PASS report integrity {grouped_envelope.integrity['sha256']}")
            return
        if schema == ONTOLOGY_REPORT_SCHEMA:
            ontology_envelope = load_ontology_report(input_path)
            if not ontology_report_integrity_matches(ontology_envelope):
                typer.echo("FAIL report integrity mismatch")
                raise typer.Exit(code=1)
            typer.echo(f"PASS report integrity {ontology_envelope.integrity.sha256}")
            return
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


@app.command("article-package-generate")
def article_package_generate(
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Generate deterministic article evidence JSON from verified canonical artifacts."""
    try:
        root = root.resolve()
        claims, reproduction, manifest = build_article_package(root)
        outputs = {
            CLAIM_PATH: claims,
            REPRO_PATH: reproduction,
            MANIFEST_PATH: manifest,
        }
        for relative, model in outputs.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(path, pretty_article_json(model))
        index = build_article_index(root, manifest, claims, reproduction)
        index_path = root / INDEX_PATH
        index_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(index_path, pretty_article_json(index))
    except (OSError, UnicodeError, ValidationError, OmivInputError) as exc:
        typer.echo(f"ERROR article package generation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS article package claims={claims.registry_digest} "
        f"manifest={manifest.manifest_digest} index={index.index_digest}"
    )


@app.command("article-evidence-verify")
def article_evidence_verify(
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Reconstruct and verify the publication evidence manifest offline."""
    try:
        manifest = verify_evidence_manifest(root.resolve())
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS article evidence {manifest.manifest_digest}")


@app.command("article-claims-verify")
def article_claims_verify(
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Reconstruct and verify every registered public claim offline."""
    try:
        registry = verify_claim_registry(root.resolve())
    except OmivInputError as exc:
        typer.echo(f"ERROR {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS article claims {registry.registry_digest}")


@app.command("article-preflight")
def article_preflight(
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
    article: Annotated[Path, typer.Option("--article", exists=True, dir_okay=False)] = Path(
        "articles/validating-kimi-k3-gguf-with-omiv.md"
    ),
) -> None:
    """Verify evidence, claims, publication text, and artifact index offline."""
    try:
        root = root.resolve()
        article_path = article if article.is_absolute() else root / article
        index = verify_article_package(root, article_path)
    except PublicationClaimError as exc:
        typer.echo(f"FAIL article preflight: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (OSError, UnicodeError, OmivInputError) as exc:
        typer.echo(f"ERROR article preflight failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS article preflight {index.index_digest}")


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
