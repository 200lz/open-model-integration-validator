"""Command-line interface."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, cast

import typer
from pydantic import BaseModel, ValidationError

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
from omiv.continuous_trust.bundles import verify_bundle_directory
from omiv.continuous_trust.models import (
    AuditBundleManifest,
    AuditBundleReport,
    AuditBundleVerificationResult,
    CustodyHistoricalLinkage,
    GovernanceHistoricalAdapter,
    HistoricalEvaluationResult,
    HistoricalEvent,
    PassportHistoricalSummary,
    RenewalRecord,
    RevocationPropagationResult,
    SupersessionGraph,
    TrustSnapshot,
    TrustTimeline,
    TrustTransition,
)
from omiv.continuous_trust.reporting import (
    pretty_audit_json,
    render_audit_markdown,
    verify_audit_report,
)
from omiv.continuous_trust.schema import SCHEMA_MODELS as AUDIT_SCHEMA_MODELS
from omiv.continuous_trust.schema import load_audit
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
from omiv.governance.evaluation import (
    build_approval_record as build_governance_approval_record,
)
from omiv.governance.evaluation import (
    build_approval_request as build_governance_approval_request,
)
from omiv.governance.evaluation import build_governance_report, verify_policy_decision
from omiv.governance.evaluation import build_policy_decision as build_governance_decision
from omiv.governance.evaluation import (
    build_promotion_decision as build_governance_promotion_decision,
)
from omiv.governance.models import DecisionOutcome, GovernanceSubject, PromotionOutcome
from omiv.governance.reporting import load_approval as load_governance_approval
from omiv.governance.reporting import (
    load_approval_input,
    load_approval_request_input,
    load_quorum_result,
    load_separation_result,
)
from omiv.governance.reporting import (
    load_approval_request as load_governance_approval_request,
)
from omiv.governance.reporting import load_candidate as load_release_candidate
from omiv.governance.reporting import load_decision as load_governance_decision
from omiv.governance.reporting import load_evaluation_input as load_governance_input
from omiv.governance.reporting import load_gate_policy as load_promotion_gate_policy
from omiv.governance.reporting import load_policy as load_governance_policy
from omiv.governance.reporting import (
    load_promotion_decision as load_governance_promotion_decision,
)
from omiv.governance.reporting import load_rejection as load_governance_rejection
from omiv.governance.reporting import load_target as load_promotion_target
from omiv.governance.reporting import pretty_json as pretty_governance_json
from omiv.governance.reporting import render_markdown as render_governance_markdown
from omiv.governance.reporting import verify_report_file as verify_governance_report_file
from omiv.governance.signing import approval_linkage, decision_linkage
from omiv.hf.json_loader import load_bounded_json, parse_bounded_json_bytes
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
from omiv.payload_integrity.building import (
    build_plan as build_payload_plan,
)
from omiv.payload_integrity.building import (
    build_report as build_payload_report,
)
from omiv.payload_integrity.building import (
    compare_manifests as compare_payload_manifests,
)
from omiv.payload_integrity.building import (
    evaluate_evidence as evaluate_payload_evidence,
)
from omiv.payload_integrity.models import (
    ComparisonStatus as PayloadComparisonStatus,
)
from omiv.payload_integrity.models import (
    ObservedPayloadManifest,
    PayloadExpectation,
)
from omiv.payload_integrity.models import (
    RootMode as PayloadRootMode,
)
from omiv.payload_integrity.observation import observe_payload
from omiv.payload_integrity.reporting import (
    load_payload,
)
from omiv.payload_integrity.reporting import (
    pretty_json as pretty_payload_json,
)
from omiv.payload_integrity.reporting import (
    render_markdown as render_payload_markdown,
)
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
from omiv.quantization.artifact_index import verify_quantization_artifact_index
from omiv.quantization.models import (
    NumericalStatus as QuantizationNumericalStatus,
)
from omiv.quantization.models import (
    QuantizationArtifactIndex,
    QuantizationFidelityComparison,
    QuantizationFidelityEvidence,
    QuantizationFidelityReport,
)
from omiv.quantization.reporting import pretty_json as pretty_quantization_json
from omiv.quantization.reporting import render_markdown as render_quantization_markdown
from omiv.quantization.sampling import build_sample_definition
from omiv.quantization.schema import load_quantization
from omiv.quantization_profiles.xai import build_xai_readiness
from omiv.reconciliation.building import (
    build_locator as build_remote_locator,
)
from omiv.reconciliation.building import (
    build_plan as build_remote_plan,
)
from omiv.reconciliation.building import (
    compare_remote_to_local,
)
from omiv.reconciliation.indexes import build_topology_from_indexes, load_shard_index
from omiv.reconciliation.models import (
    CollectionMode as RemoteCollectionMode,
)
from omiv.reconciliation.models import (
    ProviderKind as RemoteProviderKind,
)
from omiv.reconciliation.models import (
    RemoteLocalReconciliationComparison,
    RemoteSnapshotExpectation,
    RemoteSnapshotManifest,
)
from omiv.reconciliation.models import (
    RequestedRevisionKind as RemoteRequestedRevisionKind,
)
from omiv.reconciliation.reporting import pretty_json as pretty_reconciliation_json
from omiv.reconciliation.schema import load_any_reconciliation, load_reconciliation
from omiv.reconciliation_profiles.huggingface import collect_huggingface_metadata
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
from omiv.runtime.adapters import adapt_governance_runtime, build_custody_runtime_linkage
from omiv.runtime.building import build_product_subject, synthetic_scope
from omiv.runtime.continuity import evaluate_continuity
from omiv.runtime.models import (
    ContinuityEvaluation,
    ContinuityPolicy,
    ContinuityVerdict,
    DeploymentIntent,
    DeploymentManifest,
    DeploymentRecord,
    DeploymentRuntimeReport,
    ProductSubject,
    ProductSubjectClass,
    RuntimeObservation,
    RuntimeObservationPlan,
    RuntimeObserverIdentity,
)
from omiv.runtime.reporting import (
    LOADABLE_MODELS,
    load_runtime,
    render_runtime_markdown,
    verify_runtime_report,
)
from omiv.runtime.reporting import (
    pretty_json as pretty_runtime_json,
)
from omiv.runtime_resolution.artifact_index import verify_runtime_resolution_artifact_index
from omiv.runtime_resolution.models import (
    EvidenceStatus as RuntimeResolutionEvidenceStatus,
)
from omiv.runtime_resolution.models import (
    RuntimeResolutionArtifactIndex,
    RuntimeResolutionParityEvidence,
    RuntimeResolutionReport,
)
from omiv.runtime_resolution.reporting import pretty_json as pretty_runtime_resolution_json
from omiv.runtime_resolution.reporting import render_markdown as render_runtime_resolution_markdown
from omiv.runtime_resolution.schema import load_runtime_resolution
from omiv.runtime_resolution_profiles.anthropic import build_anthropic_practice
from omiv.runtime_resolution_profiles.xai import build_xai_practice
from omiv.safe_write import atomic_write_text, validate_output_path
from omiv.schema.loader import load_schema
from omiv.security.adapters import (
    adapt_governance_security_evidence,
    build_custody_security_linkage,
)
from omiv.security.building import build_plan, builtin_scanner_identity
from omiv.security.evaluation import evaluate_security_bundle
from omiv.security.models import (
    InspectionBounds,
    SecurityEvidencePolicy,
    SecurityInspectionScope,
    SecurityVerdict,
)
from omiv.security.policy import get_security_policy
from omiv.security.reporting import (
    build_security_report,
    render_security_markdown,
    verify_security_report,
)
from omiv.security.reporting import (
    load_bundle as load_security_bundle,
)
from omiv.security.reporting import (
    load_evaluation as load_security_evaluation,
)
from omiv.security.reporting import (
    load_plan as load_security_plan,
)
from omiv.security.reporting import (
    load_policy as load_security_policy,
)
from omiv.security.reporting import (
    load_report as load_security_report,
)
from omiv.security.reporting import (
    pretty_json as pretty_security_json,
)
from omiv.security.scanning import describe_local_artifact, inspect_local_artifact
from omiv.tokenizer_parity.artifact_index import (
    verify_tokenizer_configuration_artifact_index,
)
from omiv.tokenizer_parity.models import (
    OverallParityStatus as TokenizerParityStatus,
)
from omiv.tokenizer_parity.models import (
    TokenizerConfigurationArtifactIndex,
    TokenizerConfigurationComparison,
    TokenizerConfigurationParityEvidence,
    TokenizerConfigurationReport,
)
from omiv.tokenizer_parity.reporting import pretty_json as pretty_tokenizer_configuration_json
from omiv.tokenizer_parity.reporting import (
    render_markdown as render_tokenizer_configuration_markdown,
)
from omiv.tokenizer_parity.schema import load_tokenizer_configuration
from omiv.tokenizer_parity_profiles.xai import (
    build_xai_readiness as build_xai_tokenizer_configuration_readiness,
)
from omiv.trust.algorithms import load_private_key, load_public_key, raw_public_key
from omiv.trust.models import (
    ACTIVE_PURPOSES,
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
from omiv.trust.verification import load_report as load_signature_report
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
governance_app = typer.Typer(no_args_is_help=True)
security_app = typer.Typer(no_args_is_help=True)
runtime_app = typer.Typer(no_args_is_help=True)
audit_app = typer.Typer(no_args_is_help=True)
payload_app = typer.Typer(no_args_is_help=True)
reconcile_app = typer.Typer(no_args_is_help=True)
quantization_app = typer.Typer(no_args_is_help=True)
tokenizer_configuration_app = typer.Typer(no_args_is_help=True)
runtime_resolution_app = typer.Typer(no_args_is_help=True)
app.add_typer(model_packs_app, name="model-packs")
app.add_typer(passport_app, name="passport")
app.add_typer(custody_app, name="custody")
app.add_typer(attestation_app, name="attestation")
app.add_typer(trust_app, name="trust")
app.add_typer(governance_app, name="governance")
app.add_typer(security_app, name="security")
app.add_typer(runtime_app, name="runtime")
app.add_typer(audit_app, name="audit")
app.add_typer(payload_app, name="payload")
app.add_typer(reconcile_app, name="reconcile")
app.add_typer(quantization_app, name="quantization")
app.add_typer(tokenizer_configuration_app, name="tokenizer-config")
app.add_typer(runtime_resolution_app, name="runtime-resolution")
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
            allowed_purposes=sorted(ACTIVE_PURPOSES, key=lambda item: item.value),
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


def _governance_decision_exit(outcome: DecisionOutcome) -> int:
    if outcome == DecisionOutcome.ALLOW:
        return 0
    if outcome in {DecisionOutcome.ALLOW_WITH_LIMITATIONS, DecisionOutcome.REVIEW_REQUIRED}:
        return 1
    return 2


def _governance_promotion_exit(outcome: PromotionOutcome) -> int:
    if outcome == PromotionOutcome.PROMOTION_ALLOWED:
        return 0
    if outcome in {
        PromotionOutcome.PROMOTION_ALLOWED_WITH_CONDITIONS,
        PromotionOutcome.REVIEW_REQUIRED,
    }:
        return 1
    return 2


@governance_app.command("evaluate")
def governance_evaluate(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    report_output: Annotated[Path, typer.Option("--report-output", dir_okay=False)],
    markdown_output: Annotated[Path, typer.Option("--markdown-output", dir_okay=False)],
) -> None:
    """Evaluate supplied evidence and write a reconstructed offline decision and report."""
    inputs = (input_path, policy_path)
    try:
        value = load_governance_input(input_path)
        policy = load_governance_policy(policy_path)
        decision = build_governance_decision(value, policy)
        report = build_governance_report(decision)
        outputs = (output, report_output, markdown_output)
        if len({item.resolve(strict=False) for item in outputs}) != len(outputs):
            raise OmivInputError("governance outputs must use distinct paths")
        for path in outputs:
            validate_output_path(path, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_governance_json(decision), forbidden_inputs=inputs)
        atomic_write_text(report_output, pretty_governance_json(report), forbidden_inputs=inputs)
        atomic_write_text(
            markdown_output,
            render_governance_markdown(report),
            forbidden_inputs=inputs,
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR governance evaluation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{decision.decision_outcome.value} decision={decision.decision_id} "
        f"report={report.report_id} deployment=NOT_PERFORMED runtime=NOT_CHECKED"
    )
    code = _governance_decision_exit(decision.decision_outcome)
    if code:
        raise typer.Exit(code=code)


@governance_app.command("decision-verify")
def governance_decision_verify(
    decision_path: Annotated[Path, typer.Option("--decision", exists=True, dir_okay=False)],
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
) -> None:
    """Reconstruct a policy decision from the supplied policy and evidence references."""
    try:
        observed = load_governance_decision(decision_path)
        value = load_governance_input(input_path)
        policy = load_governance_policy(policy_path)
        decision = verify_policy_decision(observed, value, policy)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR governance decision verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS decision={decision.decision_id} outcome={decision.decision_outcome.value} "
        "claim_truth=NOT_PROVEN"
    )


@governance_app.command("decision-show")
def governance_decision_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Display a decision without adding approval, promotion, or deployment claims."""
    try:
        decision = load_governance_decision(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR governance decision display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"Decision: {decision.decision_id}\n"
        f"Policy: {decision.policy_id} {decision.policy_digest}\n"
        f"Outcome: {decision.decision_outcome.value}\n"
        "Underlying claims independently proven: NO\n"
        "Approval: NOT_INFERRED\nPromotion: NOT_PERFORMED\n"
        "Deployment: NOT_PERFORMED\nRuntime: NOT_CHECKED"
    )


@governance_app.command("approval-request-create")
def governance_approval_request_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    decision_path: Annotated[Path, typer.Option("--decision", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Create an offline approval request; no notification or approval occurs."""
    inputs = (input_path, decision_path, policy_path)
    try:
        value = load_approval_request_input(input_path)
        decision = load_governance_decision(decision_path)
        policy = load_governance_policy(policy_path)
        request = build_governance_approval_request(
            decision,
            policy,
            requested_action=value.requested_action,
            requester_role=value.requester_role,
            requester=value.requester,
            requested_target_id=value.requested_target_id,
            requested_scope=value.requested_scope,
            evidence_ids=value.evidence_ids,
        )
        atomic_write_text(output, pretty_governance_json(request), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR approval request creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS approval request={request.approval_request_id} approval=NOT_GRANTED")


@governance_app.command("approval-create")
def governance_approval_create(
    request_path: Annotated[Path, typer.Option("--request", exists=True, dir_okay=False)],
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Create an explicit unsigned approval record for later independent signing."""
    inputs = (request_path, input_path)
    try:
        request = load_governance_approval_request(request_path)
        value = load_approval_input(input_path)
        approval = build_governance_approval_record(
            request,
            approver_role=value.approver_role,
            approver=value.approver,
            outcome=value.outcome,
            scope=value.scope,
            conditions=value.conditions,
            evidence_ids=value.evidence_ids,
            validity_not_after=value.validity_not_after,
        )
        atomic_write_text(output, pretty_governance_json(approval), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR approval creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS approval={approval.approval_id} outcome={approval.outcome.value} "
        "signature=NOT_EVALUATED deployment=NOT_PERFORMED"
    )


@governance_app.command("approval-verify")
def governance_approval_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    request_path: Annotated[Path, typer.Option("--request", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    envelope_path: Annotated[
        Path | None, typer.Option("--envelope", exists=True, dir_okay=False)
    ] = None,
    trust_bundle_path: Annotated[
        Path | None, typer.Option("--trust-bundle", exists=True, dir_okay=False)
    ] = None,
    trust_policy_path: Annotated[
        Path | None, typer.Option("--trust-policy", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Verify approval structure/scope and optionally reconstruct its signature trust."""
    try:
        approval = load_governance_approval(input_path)
        request = load_governance_approval_request(request_path)
        policy = load_governance_policy(policy_path)
        if (
            approval.approval_request_id != request.approval_request_id
            or approval.request_digest != request.request_digest
            or approval.subject_id != request.subject.subject_id
            or approval.policy_id != policy.policy_id
            or approval.policy_digest != policy.policy_digest
        ):
            raise OmivInputError("approval does not match request subject or governance policy")
        signed = False
        signature_inputs = (envelope_path, trust_bundle_path, trust_policy_path)
        if any(signature_inputs):
            if not all(signature_inputs):
                raise OmivInputError("signed approval verification requires all trust inputs")
            envelope = load_signed_envelope(envelope_path)  # type: ignore[arg-type]
            bundle = load_trust_bundle(trust_bundle_path)  # type: ignore[arg-type]
            trust_policy = load_trust_policy(trust_policy_path)  # type: ignore[arg-type]
            trust_report = verify_signed_envelope(envelope, bundle, trust_policy)
            if envelope.signed_object != approval.model_dump(mode="json", by_alias=True):
                raise OmivInputError("signed envelope contains a different approval record")
            signed = approval_linkage(envelope, trust_report).trust_status == "TRUSTED_BY_POLICY"
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR approval verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS approval={approval.approval_id} scope={approval.scope} "
        f"signature_trusted={'YES' if signed else 'NOT_EVALUATED'} deployment=NOT_PERFORMED"
    )
    if policy.approval_policy and policy.approval_policy.require_signed_approval and not signed:
        raise typer.Exit(code=1)


@governance_app.command("approval-show")
def governance_approval_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Show scoped approval evidence without inferring signature trust or deployment."""
    try:
        approval = load_governance_approval(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR approval display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"Approval: {approval.approval_id}\nOutcome: {approval.outcome.value}\n"
        f"Scope: {approval.scope}\nPolicy: {approval.policy_id}\n"
        "Signature trust: NOT_EVALUATED\nSecurity: NOT_PROVEN\n"
        "Promotion: NOT_PERFORMED\nDeployment: NOT_PERFORMED"
    )


def _trusted_governance_decision(
    envelope_path: Path | None,
    bundle_path: Path | None,
    policy_path: Path | None,
) -> bool:
    values = (envelope_path, bundle_path, policy_path)
    if not any(values):
        return False
    if not all(values):
        raise OmivInputError("decision signature evaluation requires all trust inputs")
    envelope = load_signed_envelope(envelope_path)  # type: ignore[arg-type]
    bundle = load_trust_bundle(bundle_path)  # type: ignore[arg-type]
    policy = load_trust_policy(policy_path)  # type: ignore[arg-type]
    report = verify_signed_envelope(envelope, bundle, policy)
    return decision_linkage(envelope, report).trust_status == "TRUSTED_BY_POLICY"


@governance_app.command("promotion-evaluate")
def governance_promotion_evaluate(
    candidate_path: Annotated[Path, typer.Option("--candidate", exists=True, dir_okay=False)],
    target_path: Annotated[Path, typer.Option("--target", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    decision_path: Annotated[Path, typer.Option("--decision", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    quorum_path: Annotated[
        Path | None, typer.Option("--quorum", exists=True, dir_okay=False)
    ] = None,
    separation_path: Annotated[
        Path | None, typer.Option("--separation", exists=True, dir_okay=False)
    ] = None,
    decision_envelope_path: Annotated[
        Path | None, typer.Option("--decision-envelope", exists=True, dir_okay=False)
    ] = None,
    trust_bundle_path: Annotated[
        Path | None, typer.Option("--trust-bundle", exists=True, dir_okay=False)
    ] = None,
    trust_policy_path: Annotated[
        Path | None, typer.Option("--trust-policy", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Evaluate a logical promotion gate without contacting or modifying a registry."""
    try:
        candidate = load_release_candidate(candidate_path)
        target = load_promotion_target(target_path)
        gate_policy = load_promotion_gate_policy(policy_path)
        decision = load_governance_decision(decision_path)
        quorum = load_quorum_result(quorum_path) if quorum_path else None
        separation = load_separation_result(separation_path) if separation_path else None
        trusted = _trusted_governance_decision(
            decision_envelope_path, trust_bundle_path, trust_policy_path
        )
        promotion = build_governance_promotion_decision(
            candidate,
            target,
            gate_policy,
            decision,
            quorum=quorum,
            separation=separation,
            trusted_decision_signature=trusted,
        )
        atomic_write_text(
            output,
            pretty_governance_json(promotion),
            forbidden_inputs=(candidate_path, target_path, policy_path, decision_path),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR promotion evaluation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"Logical promotion permission: {promotion.gate_result.outcome.value} "
        f"promotion={promotion.promotion_decision_id} target={promotion.target_id} "
        f"conditions={','.join(promotion.conditions) or 'NONE'} "
        f"registry_write={promotion.registry_write} promotion_performed="
        f"{promotion.promotion_performed} security={promotion.security_status} "
        f"deployment={promotion.deployment_status} runtime={promotion.runtime_status}"
    )
    code = _governance_promotion_exit(promotion.gate_result.outcome)
    if code:
        raise typer.Exit(code=code)


@governance_app.command("promotion-verify")
def governance_promotion_verify(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    candidate_path: Annotated[Path, typer.Option("--candidate", exists=True, dir_okay=False)],
    target_path: Annotated[Path, typer.Option("--target", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    decision_path: Annotated[Path, typer.Option("--decision", exists=True, dir_okay=False)],
    quorum_path: Annotated[
        Path | None, typer.Option("--quorum", exists=True, dir_okay=False)
    ] = None,
    separation_path: Annotated[
        Path | None, typer.Option("--separation", exists=True, dir_okay=False)
    ] = None,
    decision_envelope_path: Annotated[
        Path | None, typer.Option("--decision-envelope", exists=True, dir_okay=False)
    ] = None,
    trust_bundle_path: Annotated[
        Path | None, typer.Option("--trust-bundle", exists=True, dir_okay=False)
    ] = None,
    trust_policy_path: Annotated[
        Path | None, typer.Option("--trust-policy", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Reconstruct a promotion decision without executing promotion."""
    try:
        observed = load_governance_promotion_decision(input_path)
        trusted = _trusted_governance_decision(
            decision_envelope_path, trust_bundle_path, trust_policy_path
        )
        reconstructed = build_governance_promotion_decision(
            load_release_candidate(candidate_path),
            load_promotion_target(target_path),
            load_promotion_gate_policy(policy_path),
            load_governance_decision(decision_path),
            quorum=load_quorum_result(quorum_path) if quorum_path else None,
            separation=load_separation_result(separation_path) if separation_path else None,
            trusted_decision_signature=trusted,
        )
        if observed != reconstructed:
            raise OmivInputError("promotion decision does not match reconstructed gate state")
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR promotion decision verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS promotion={observed.promotion_decision_id} "
        f"outcome={observed.gate_result.outcome.value} action_performed=NO"
    )


@governance_app.command("report-verify")
def governance_report_verify(
    report_path: Annotated[Path, typer.Option("--report", exists=True, dir_okay=False)],
    decision_path: Annotated[Path, typer.Option("--decision", exists=True, dir_okay=False)],
    approval_request_path: Annotated[
        Path | None, typer.Option("--approval-request", exists=True, dir_okay=False)
    ] = None,
    approval_path: Annotated[
        Path | None, typer.Option("--approval", exists=True, dir_okay=False)
    ] = None,
    rejection_path: Annotated[
        Path | None, typer.Option("--rejection", exists=True, dir_okay=False)
    ] = None,
    quorum_path: Annotated[
        Path | None, typer.Option("--quorum", exists=True, dir_okay=False)
    ] = None,
    separation_path: Annotated[
        Path | None, typer.Option("--separation", exists=True, dir_okay=False)
    ] = None,
    target_path: Annotated[
        Path | None, typer.Option("--target", exists=True, dir_okay=False)
    ] = None,
    promotion_path: Annotated[
        Path | None, typer.Option("--promotion", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Reconstruct governance report summaries from canonical dependency records."""
    try:
        decision = load_governance_decision(decision_path)
        report = verify_governance_report_file(
            report_path,
            decision,
            approval_request=(
                load_governance_approval_request(approval_request_path)
                if approval_request_path
                else None
            ),
            approvals=[load_governance_approval(approval_path)] if approval_path else [],
            rejections=[load_governance_rejection(rejection_path)] if rejection_path else [],
            quorum=load_quorum_result(quorum_path) if quorum_path else None,
            separation=load_separation_result(separation_path) if separation_path else None,
            target=load_promotion_target(target_path) if target_path else None,
            promotion=(
                load_governance_promotion_decision(promotion_path) if promotion_path else None
            ),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR governance report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"PASS governance report={report.report_id} outcome={report.decision_outcome.value} "
        "deployment=NOT_PERFORMED runtime=NOT_CHECKED"
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


def _security_exit(verdict: SecurityVerdict) -> int:
    if verdict == SecurityVerdict.PASS:
        return 0
    if verdict in {
        SecurityVerdict.PASS_WITH_LIMITATIONS,
        SecurityVerdict.REVIEW_REQUIRED,
        SecurityVerdict.NOT_EVALUATED,
    }:
        return 1
    return 2


@security_app.command("plan-create")
def security_plan_create(
    artifact: Annotated[Path, typer.Option("--artifact", exists=True)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    maximum_file_count: Annotated[int, typer.Option("--maximum-file-count")] = 10000,
    maximum_total_bytes: Annotated[int, typer.Option("--maximum-total-bytes-read")] = 268435456,
    maximum_bytes_per_file: Annotated[int, typer.Option("--maximum-bytes-per-file")] = 8388608,
    maximum_archive_entries: Annotated[int, typer.Option("--maximum-archive-entry-count")] = 10000,
    maximum_recursion_depth: Annotated[int, typer.Option("--maximum-recursion-depth")] = 16,
) -> None:
    """Create a deterministic bounded plan for an explicit local artifact."""
    try:
        bounds = InspectionBounds(
            maximum_file_count=maximum_file_count,
            maximum_total_bytes_read=maximum_total_bytes,
            maximum_bytes_per_file=maximum_bytes_per_file,
            maximum_archive_entry_count=maximum_archive_entries,
            maximum_metadata_bytes=4 * 1024 * 1024,
            maximum_finding_count=1000,
            maximum_evidence_snippet_length=256,
            maximum_recursion_depth=maximum_recursion_depth,
        )
        subject, items = describe_local_artifact(artifact)
        if (
            len(items) > bounds.maximum_file_count
            or subject.total_declared_bytes > bounds.maximum_total_bytes_read
        ):
            raise OmivInputError("artifact exceeds requested inspection-plan bounds")
        scope = SecurityInspectionScope(
            logical_paths=sorted(item.logical_path for item in items),
            mandatory_paths=sorted(item.logical_path for item in items),
            declared_file_count=len(items),
            declared_total_bytes=sum(item.size for item in items),
            include_archive_metadata=any(item.path.suffix.lower() == ".zip" for item in items),
        )
        scanner = builtin_scanner_identity()
        plan = build_plan(subject, scope, scanner.capability.methods, bounds)
        validate_output_path(output, forbidden_inputs=(artifact,))
        atomic_write_text(output, pretty_security_json(plan), forbidden_inputs=(artifact,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security plan creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"PASS plan={plan.plan_id} subject={plan.subject.identity_digest}")


@security_app.command("inspect")
def security_inspect(
    plan_path: Annotated[Path, typer.Option("--plan", exists=True, dir_okay=False)],
    artifact: Annotated[Path, typer.Option("--artifact", exists=True)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    bundle_output: Annotated[Path, typer.Option("--bundle-output", dir_okay=False)],
    report_output: Annotated[Path | None, typer.Option("--report-output", dir_okay=False)] = None,
    markdown_output: Annotated[
        Path | None, typer.Option("--markdown-output", dir_okay=False)
    ] = None,
) -> None:
    """Run the bounded OMIV static inspector without executing artifact code."""
    try:
        plan = load_security_plan(plan_path)
        scanner = builtin_scanner_identity()
        bundle = inspect_local_artifact(artifact, plan, scanner)
        execution = bundle.execution_records[0]
        policy = get_security_policy("personal_local_security_review")
        evaluation = evaluate_security_bundle(bundle, policy)
        report = build_security_report(bundle, evaluation)
        outputs = [output, bundle_output, *(x for x in (report_output, markdown_output) if x)]
        if len({x.resolve(strict=False) for x in outputs}) != len(outputs):
            raise OmivInputError("security outputs must use distinct paths")
        inputs = (plan_path, artifact)
        for target in outputs:
            validate_output_path(target, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_security_json(execution), forbidden_inputs=inputs)
        atomic_write_text(bundle_output, pretty_security_json(bundle), forbidden_inputs=inputs)
        if report_output:
            atomic_write_text(report_output, pretty_security_json(report), forbidden_inputs=inputs)
        if markdown_output:
            atomic_write_text(
                markdown_output, render_security_markdown(report), forbidden_inputs=inputs
            )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security inspection failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{evaluation.verdict.value} execution={execution.execution_id} bundle={bundle.bundle_id} "
        f"scope=DECLARED_ONLY coverage={evaluation.coverage_result.value} "
        f"scanner_trust={evaluation.scanner_trust.value} code_execution=NO network=NO "
        "payload_integrity=NOT_VERIFIED runtime_safety=NOT_VERIFIED"
    )
    code = _security_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


@security_app.command("evidence-verify")
def security_evidence_verify(
    bundle_path: Annotated[Path, typer.Option("--bundle", exists=True, dir_okay=False)],
) -> None:
    """Verify canonical bundle identity, links, findings, coverage, and limitations."""
    try:
        bundle = load_security_bundle(bundle_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security evidence verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"VALID bundle={bundle.bundle_id} verdict=NOT_EVALUATED "
        f"scope=DECLARED_ONLY coverage={bundle.coverage.status.value} "
        "universal_safety=NOT_PROVEN"
    )
    raise typer.Exit(code=1)


def _cli_security_policy(value: str) -> SecurityEvidencePolicy:
    path = Path(value)
    return load_security_policy(path) if path.is_file() else get_security_policy(value)


@security_app.command("evaluate")
def security_evaluate(
    bundle_path: Annotated[Path, typer.Option("--bundle", exists=True, dir_okay=False)],
    policy_value: Annotated[str, typer.Option("--policy")],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    evaluation_context: Annotated[
        Path | None, typer.Option("--evaluation-context", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Evaluate verified evidence against a static policy with fail-closed precedence."""
    try:
        bundle = load_security_bundle(bundle_path)
        policy = _cli_security_policy(policy_value)
        context_digest = None
        if evaluation_context:
            raw, _ = load_bounded_json(evaluation_context, max_bytes=1024 * 1024)
            context_digest = canonical_sha256(raw)
        evaluation = evaluate_security_bundle(
            bundle,
            policy,
            evaluation_context_digest=context_digest,
        )
        inputs = tuple(
            x
            for x in (
                bundle_path,
                evaluation_context,
                Path(policy_value) if Path(policy_value).is_file() else None,
            )
            if x
        )
        validate_output_path(output, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_security_json(evaluation), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security evaluation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{evaluation.verdict.value} evaluation={evaluation.evaluation_id} "
        f"policy={evaluation.policy_id} scope=DECLARED_ONLY "
        f"coverage={evaluation.coverage_result.value} "
        f"scanner_trust={evaluation.scanner_trust.value} "
        "payload_integrity=NOT_VERIFIED runtime_safety=NOT_VERIFIED"
    )
    code = _security_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


@security_app.command("show")
def security_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Display a canonical security bundle, evaluation, or report without upgrading claims."""
    try:
        raw, _ = load_bounded_json(input_path, max_bytes=16 * 1024 * 1024)
        schema = raw.get("schema")
        if schema == "omiv.security-evidence-bundle.v1":
            displayed_bundle = load_security_bundle(input_path)
            typer.echo(
                f"Bundle: {displayed_bundle.bundle_id}\n"
                f"Coverage: {displayed_bundle.coverage.status.value}\n"
                "Verdict: NOT_EVALUATED"
            )
        elif schema == "omiv.security-evaluation.v1":
            displayed_evaluation = load_security_evaluation(input_path)
            typer.echo(
                f"Evaluation: {displayed_evaluation.evaluation_id}\n"
                f"Verdict: {displayed_evaluation.verdict.value}\n"
                f"Policy: {displayed_evaluation.policy_id}\n"
                f"Coverage: {displayed_evaluation.coverage_result.value}\n"
                f"Scanner trust: {displayed_evaluation.scanner_trust.value}\n"
                "Scope: DECLARED_ONLY\n"
                "Payload integrity: NOT_VERIFIED\n"
                "Runtime safety: NOT_VERIFIED\n"
                "Universal safety: NOT_PROVEN"
            )
        elif schema == "omiv.security-report.v1":
            displayed_report = load_security_report(input_path)
            typer.echo(render_security_markdown(displayed_report))
        else:
            raise OmivInputError("unsupported security object schema")
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@security_app.command("report-verify")
def security_report_verify(
    report_path: Annotated[Path, typer.Option("--report", exists=True, dir_okay=False)],
    bundle_path: Annotated[Path, typer.Option("--bundle", exists=True, dir_okay=False)],
    evaluation_path: Annotated[Path, typer.Option("--evaluation", exists=True, dir_okay=False)],
) -> None:
    """Reconstruct a JSON report and reject altered summaries."""
    try:
        report = load_security_report(report_path)
        bundle = load_security_bundle(bundle_path)
        evaluation = load_security_evaluation(evaluation_path)
        verify_security_report(report, bundle, evaluation)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"VALID_REPORT report={report.report_id} summary=reconstructed "
        f"verdict={evaluation.verdict.value}"
    )
    code = _security_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


@security_app.command("governance-adapt")
def security_governance_adapt(
    bundle_path: Annotated[Path, typer.Option("--bundle", exists=True, dir_okay=False)],
    evaluation_path: Annotated[Path, typer.Option("--evaluation", exists=True, dir_okay=False)],
    policy_value: Annotated[str, typer.Option("--policy")],
    governance_subject_path: Annotated[
        Path, typer.Option("--governance-subject", exists=True, dir_okay=False)
    ],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    evidence_output: Annotated[Path, typer.Option("--evidence-output", dir_okay=False)],
    signature_report_path: Annotated[
        Path | None, typer.Option("--signature-report", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Create a strict Phase 5E security requirement adapter and evidence reference."""
    try:
        bundle = load_security_bundle(bundle_path)
        evaluation = load_security_evaluation(evaluation_path)
        policy = _cli_security_policy(policy_value)
        signature_report = (
            load_signature_report(signature_report_path) if signature_report_path else None
        )
        raw, _ = load_bounded_json(governance_subject_path, max_bytes=1024 * 1024)
        subject = GovernanceSubject.model_validate(raw.get("subject", raw))
        adapter, evidence = adapt_governance_security_evidence(
            subject,
            bundle,
            evaluation,
            policy,
            signature_report=signature_report,
        )
        inputs = tuple(
            item
            for item in (
                bundle_path,
                evaluation_path,
                governance_subject_path,
                signature_report_path,
                Path(policy_value) if Path(policy_value).is_file() else None,
            )
            if item is not None
        )
        validate_output_path(output, forbidden_inputs=inputs)
        validate_output_path(evidence_output, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_security_json(adapter), forbidden_inputs=inputs)
        atomic_write_text(evidence_output, pretty_security_json(evidence), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security governance adaptation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{adapter.requirement_outcome} adapter={adapter.adapter_id} "
        f"policy={adapter.policy_id} verdict={adapter.verdict.value} "
        f"scope=DECLARED_ONLY limitations={len(adapter.limitations)}"
    )
    if adapter.requirement_outcome == "SATISFIED_WITH_LIMITATIONS":
        raise typer.Exit(code=1)
    if adapter.requirement_outcome != "SATISFIED":
        raise typer.Exit(code=2)


@security_app.command("custody-link")
def security_custody_link(
    ledger_path: Annotated[Path, typer.Option("--ledger", exists=True, dir_okay=False)],
    bundle_path: Annotated[Path, typer.Option("--bundle", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    evaluation_path: Annotated[
        Path | None, typer.Option("--evaluation", exists=True, dir_okay=False)
    ] = None,
) -> None:
    """Link security evidence to custody without fabricating approval or deployment."""
    try:
        ledger = load_custody_ledger(ledger_path).model_dump(mode="json", by_alias=True)
        bundle = load_security_bundle(bundle_path)
        evaluation = load_security_evaluation(evaluation_path) if evaluation_path else None
        linkage = build_custody_security_linkage(ledger, bundle, evaluation)
        inputs = tuple(x for x in (ledger_path, bundle_path, evaluation_path) if x)
        validate_output_path(output, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_security_json(linkage), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR security custody linkage failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"RECORDED linkage={linkage.linkage_id} lifecycle=UNCHANGED_INCOMPLETE")
    if evaluation is None:
        raise typer.Exit(code=1)
    code = _security_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


def _runtime_exit(verdict: ContinuityVerdict) -> int:
    if verdict == ContinuityVerdict.PASS:
        return 0
    if verdict in {
        ContinuityVerdict.PASS_WITH_LIMITATIONS,
        ContinuityVerdict.PARTIAL_CONTINUITY,
        ContinuityVerdict.IDENTITY_PROXY_MATCH,
        ContinuityVerdict.STALE,
        ContinuityVerdict.NOT_EVALUATED,
    }:
        return 1
    return 2


def _runtime_copy(input_path: Path, output: Path, model: type[BaseModel]) -> BaseModel:
    value = load_runtime(input_path, model)
    validate_output_path(output, forbidden_inputs=(input_path,))
    atomic_write_text(output, pretty_runtime_json(value), forbidden_inputs=(input_path,))
    return value


def _runtime_create_command(input_path: Path, output: Path, model: type[BaseModel]) -> None:
    try:
        value = _runtime_copy(input_path, output, model)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR runtime record creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"CREATED schema={value.model_dump(mode='json', by_alias=True)['schema']}")


@runtime_app.command("intent-create")
def runtime_intent_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Validate and write an explicit local deployment intent; never deploy."""
    _runtime_create_command(input_path, output, DeploymentIntent)


@runtime_app.command("manifest-create")
def runtime_manifest_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Validate and write explicit intended state; never contact a platform."""
    _runtime_create_command(input_path, output, DeploymentManifest)


@runtime_app.command("deployment-record-create")
def runtime_deployment_record_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Normalize an explicit deployment record without performing deployment."""
    _runtime_create_command(input_path, output, DeploymentRecord)


@runtime_app.command("observation-plan-create")
def runtime_observation_plan_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Validate an explicit offline observation plan."""
    _runtime_create_command(input_path, output, RuntimeObservationPlan)


@runtime_app.command("observation-create")
def runtime_observation_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Normalize supplied local observation evidence without contacting a runtime."""
    _runtime_create_command(input_path, output, RuntimeObservation)


@runtime_app.command("deployment-verify")
def runtime_deployment_verify(
    record_path: Annotated[Path, typer.Option("--record", exists=True, dir_okay=False)],
) -> None:
    """Verify deployment-record structure while preserving its evidence origin."""
    try:
        record = load_runtime(record_path, DeploymentRecord)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR deployment record verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"VALID record={record.record_id} status={record.status.value} "
        f"origin={record.assertion.origin.value} deployment_success=NOT_INFERRED"
    )
    if record.status.value.endswith("DECLARED") or record.status.value == "NOT_OBSERVED":
        raise typer.Exit(code=1)


@runtime_app.command("observation-verify")
def runtime_observation_verify(
    observation_path: Annotated[Path, typer.Option("--observation", exists=True, dir_okay=False)],
) -> None:
    """Verify observation structure without claiming observer correctness."""
    try:
        observation = load_runtime(observation_path, RuntimeObservation)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR runtime observation verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"VALID observation={observation.observation_id} status={observation.status.value} "
        f"coverage={observation.coverage.status.value} observer_correctness=NOT_PROVEN"
    )
    if observation.status.value != "COMPLETED":
        raise typer.Exit(code=1)


@runtime_app.command("continuity-evaluate")
def runtime_continuity_evaluate(
    subject_path: Annotated[Path, typer.Option("--subject", exists=True, dir_okay=False)],
    intent_path: Annotated[Path, typer.Option("--intent", exists=True, dir_okay=False)],
    manifest_path: Annotated[Path, typer.Option("--manifest", exists=True, dir_okay=False)],
    record_path: Annotated[Path, typer.Option("--record", exists=True, dir_okay=False)],
    observer_path: Annotated[Path, typer.Option("--observer", exists=True, dir_okay=False)],
    plan_path: Annotated[Path, typer.Option("--plan", exists=True, dir_okay=False)],
    observation_path: Annotated[Path, typer.Option("--observation", exists=True, dir_okay=False)],
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, dir_okay=False)],
    evaluation_sequence: Annotated[int, typer.Option("--evaluation-sequence")],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Evaluate point-in-time continuity from explicit local canonical records."""
    inputs = (
        subject_path,
        intent_path,
        manifest_path,
        record_path,
        observer_path,
        plan_path,
        observation_path,
        policy_path,
    )
    try:
        evaluation = evaluate_continuity(
            load_runtime(subject_path, ProductSubject),
            load_runtime(intent_path, DeploymentIntent),
            load_runtime(manifest_path, DeploymentManifest),
            load_runtime(record_path, DeploymentRecord),
            load_runtime(observer_path, RuntimeObserverIdentity),
            load_runtime(plan_path, RuntimeObservationPlan),
            load_runtime(observation_path, RuntimeObservation),
            load_runtime(policy_path, ContinuityPolicy),
            evaluation_sequence=evaluation_sequence,
        )
        validate_output_path(output, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_runtime_json(evaluation), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR continuity evaluation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{evaluation.verdict.value} evaluation={evaluation.evaluation_id} "
        "snapshot=YES behavior=NOT_CHECKED runtime_safety=NOT_VERIFIED continuous=NO"
    )
    code = _runtime_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


@runtime_app.command("show")
def runtime_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    """Display a canonical Phase 5G object without upgrading its claim."""
    try:
        raw, _ = load_bounded_json(input_path, max_bytes=16 * 1024 * 1024)
        schema = raw.get("schema")
        model = LOADABLE_MODELS.get(schema)
        if model is None:
            raise OmivInputError("unsupported runtime object schema")
        value = load_runtime(input_path, model)
        if isinstance(value, DeploymentRuntimeReport):
            typer.echo(render_runtime_markdown(value))
        else:
            typer.echo(pretty_runtime_json(value))
            typer.echo(
                "Snapshot only: YES\nBehavioral parity: NOT_CHECKED\n"
                "Runtime safety: NOT_VERIFIED\nContinuous continuity: NOT_ESTABLISHED"
            )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR runtime display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@runtime_app.command("report-verify")
def runtime_report_verify(
    report_path: Annotated[Path, typer.Option("--report", exists=True, dir_okay=False)],
    subject_path: Annotated[Path, typer.Option("--subject", exists=True, dir_okay=False)],
    manifest_path: Annotated[Path, typer.Option("--manifest", exists=True, dir_okay=False)],
    record_path: Annotated[Path, typer.Option("--record", exists=True, dir_okay=False)],
    observer_path: Annotated[Path, typer.Option("--observer", exists=True, dir_okay=False)],
    observation_path: Annotated[Path, typer.Option("--observation", exists=True, dir_okay=False)],
    evaluation_path: Annotated[Path, typer.Option("--evaluation", exists=True, dir_okay=False)],
) -> None:
    """Reconstruct a runtime report and reject altered summaries."""
    try:
        report = load_runtime(report_path, DeploymentRuntimeReport)
        evaluation = load_runtime(evaluation_path, ContinuityEvaluation)
        verify_runtime_report(
            report,
            load_runtime(subject_path, ProductSubject),
            load_runtime(manifest_path, DeploymentManifest),
            load_runtime(record_path, DeploymentRecord),
            load_runtime(observer_path, RuntimeObserverIdentity),
            load_runtime(observation_path, RuntimeObservation),
            evaluation,
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR runtime report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"VALID_REPORT report={report.report_id} verdict={evaluation.verdict.value}")
    code = _runtime_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


@runtime_app.command("governance-adapt")
def runtime_governance_adapt(
    evaluation_path: Annotated[Path, typer.Option("--evaluation", exists=True, dir_okay=False)],
    security_verdict: Annotated[str, typer.Option("--security-verdict")],
    allow_limited_security: Annotated[bool, typer.Option("--allow-limited-security")] = False,
    output: Annotated[Path, typer.Option("--output", dir_okay=False)] = Path(
        "governance-runtime-adapter.json"
    ),
) -> None:
    """Map verified continuity while preserving source-security limitations."""
    try:
        evaluation = load_runtime(evaluation_path, ContinuityEvaluation)
        adapter = adapt_governance_runtime(
            evaluation,
            source_security_verdict=security_verdict,
            source_security_limitations=["Source security evidence remains policy-scoped."],
            allow_limited_security=allow_limited_security,
        )
        validate_output_path(output, forbidden_inputs=(evaluation_path,))
        atomic_write_text(output, pretty_runtime_json(adapter), forbidden_inputs=(evaluation_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR runtime governance adaptation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{adapter.continuity_outcome} adapter={adapter.adapter_id} "
        f"source_security={adapter.source_security_verdict}"
    )
    code = _runtime_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


@runtime_app.command("custody-link")
def runtime_custody_link(
    chain_id: Annotated[str, typer.Option("--chain-id")],
    ledger_digest: Annotated[str, typer.Option("--ledger-digest")],
    record_path: Annotated[Path, typer.Option("--record", exists=True, dir_okay=False)],
    observation_path: Annotated[Path, typer.Option("--observation", exists=True, dir_okay=False)],
    evaluation_path: Annotated[Path, typer.Option("--evaluation", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Create a custody linkage without fabricating behavior, safety, or deployment."""
    inputs = (record_path, observation_path, evaluation_path)
    try:
        evaluation = load_runtime(evaluation_path, ContinuityEvaluation)
        linkage = build_custody_runtime_linkage(
            chain_id,
            ledger_digest,
            load_runtime(record_path, DeploymentRecord),
            load_runtime(observation_path, RuntimeObservation),
            evaluation,
        )
        validate_output_path(output, forbidden_inputs=inputs)
        atomic_write_text(output, pretty_runtime_json(linkage), forbidden_inputs=inputs)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR runtime custody linkage failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"RECORDED linkage={linkage.linkage_id} snapshot=YES behavior=NOT_CHECKED")
    code = _runtime_exit(evaluation.verdict)
    if code:
        raise typer.Exit(code=code)


def _audit_exit(value: object) -> int:
    text = str(getattr(value, "value", value))
    if text in {
        "VERIFIED",
        "COMPLETE_FOR_PURPOSE",
        "TRUSTED_FOR_SCOPED_USE",
        "UNCHANGED",
        "STRENGTHENED",
    }:
        return 0
    if text in {
        "VERIFIED_WITH_LIMITATIONS",
        "COMPLETE_WITH_LIMITATIONS",
        "PARTIAL",
        "STALE",
        "TRUSTED_WITH_LIMITATIONS",
        "REVIEW_REQUIRED",
    }:
        return 1
    return 2


def _audit_copy(input_path: Path, output: Path, model: type[BaseModel]) -> BaseModel:
    value = load_audit(input_path, model)
    validate_output_path(output, forbidden_inputs=(input_path,))
    atomic_write_text(output, pretty_audit_json(value), forbidden_inputs=(input_path,))
    return value


def _audit_create(input_path: Path, output: Path, model: type[BaseModel]) -> None:
    try:
        value = _audit_copy(input_path, output, model)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR audit record creation failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"CREATED schema={value.model_dump(mode='json', by_alias=True)['schema']} "
        "continuous=NOT_IMPLEMENTED"
    )


@audit_app.command("snapshot-create")
def audit_snapshot_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Validate an explicitly supplied immutable snapshot without inferring current state."""
    _audit_create(input_path, output, TrustSnapshot)


@audit_app.command("snapshot-verify")
def audit_snapshot_verify(
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
) -> None:
    try:
        value = load_audit(snapshot_path, TrustSnapshot)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR snapshot verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"VALID snapshot={value.snapshot_id} state={value.overall_state.value} "
        "latest_supplied=YES current_real_world=NOT_INFERRED"
    )
    code = _audit_exit(value.overall_state)
    if code:
        raise typer.Exit(code=code)


@audit_app.command("event-create")
def audit_event_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, HistoricalEvent)


@audit_app.command("timeline-build")
def audit_timeline_build(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, TrustTimeline)


@audit_app.command("timeline-verify")
def audit_timeline_verify(
    timeline_path: Annotated[Path, typer.Option("--timeline", exists=True, dir_okay=False)],
) -> None:
    try:
        value = load_audit(timeline_path, TrustTimeline)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR timeline verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{value.completeness.value} timeline={value.timeline_id} continuous=NOT_ESTABLISHED"
    )
    code = _audit_exit(value.completeness)
    if code:
        raise typer.Exit(code=code)


@audit_app.command("transition-evaluate")
def audit_transition_evaluate(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, TrustTransition)


@audit_app.command("reevaluate")
def audit_reevaluate(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, HistoricalEvaluationResult)


@audit_app.command("revocation-propagate")
def audit_revocation_propagate(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, RevocationPropagationResult)


@audit_app.command("supersession-build")
def audit_supersession_build(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, SupersessionGraph)


@audit_app.command("renewal-create")
def audit_renewal_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, RenewalRecord)


@audit_app.command("bundle-create")
def audit_bundle_create(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, AuditBundleManifest)


@audit_app.command("bundle-verify")
def audit_bundle_verify(
    bundle_root: Annotated[Path, typer.Option("--bundle-root", exists=True, file_okay=False)],
    manifest_path: Annotated[Path, typer.Option("--manifest", exists=True, dir_okay=False)],
) -> None:
    try:
        manifest = load_audit(manifest_path, AuditBundleManifest)
        result = verify_bundle_directory(bundle_root, manifest)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR bundle verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"{result.outcome.value} bundle={result.bundle_id} network=NO model_payload=NO")
    code = _audit_exit(result.outcome)
    if code:
        raise typer.Exit(code=code)


@audit_app.command("bundle-show")
def audit_bundle_show(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
) -> None:
    try:
        raw, _ = load_bounded_json(input_path, max_bytes=16 * 1024 * 1024)
        model = AUDIT_SCHEMA_MODELS.get(raw.get("schema"))
        if model is None:
            raise OmivInputError("unsupported audit object schema")
        value = load_audit(input_path, model)
        typer.echo(
            render_audit_markdown(value)
            if isinstance(value, AuditBundleReport)
            else pretty_audit_json(value)
        )
        typer.echo(
            "Latest supplied state only; current real-world state=NOT_INFERRED "
            "continuous_monitoring=NOT_IMPLEMENTED"
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR audit display failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@audit_app.command("report-verify")
def audit_report_verify(
    report_path: Annotated[Path, typer.Option("--report", exists=True, dir_okay=False)],
    bundle_path: Annotated[Path, typer.Option("--bundle", exists=True, dir_okay=False)],
    completeness_path: Annotated[Path, typer.Option("--completeness", exists=True, dir_okay=False)],
    verification_path: Annotated[Path, typer.Option("--verification", exists=True, dir_okay=False)],
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
) -> None:
    from omiv.continuous_trust.models import AuditBundleCompleteness

    try:
        report = load_audit(report_path, AuditBundleReport)
        verify_audit_report(
            report,
            load_audit(bundle_path, AuditBundleManifest),
            load_audit(completeness_path, AuditBundleCompleteness),
            load_audit(verification_path, AuditBundleVerificationResult),
            load_audit(snapshot_path, TrustSnapshot),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        typer.echo(f"ERROR audit report verification failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"VALID_REPORT report={report.report_id} current_real_world=NOT_INFERRED")


@audit_app.command("passport-summary")
def audit_passport_summary(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, PassportHistoricalSummary)


@audit_app.command("custody-link")
def audit_custody_link(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, CustodyHistoricalLinkage)


@audit_app.command("governance-adapt")
def audit_governance_adapt(
    input_path: Annotated[Path, typer.Option("--input", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    _audit_create(input_path, output, GovernanceHistoricalAdapter)


def _payload_failure(exc: Exception) -> None:
    typer.echo(f"ERROR local payload operation failed: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@payload_app.command("manifest")
def payload_manifest(
    local_path: Annotated[Path, typer.Argument(exists=True)],
    subject_path: Annotated[Path, typer.Option("--subject", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    root_mode: Annotated[PayloadRootMode, typer.Option("--root-mode")],
    logical_root: Annotated[str, typer.Option("--logical-root")],
    logical_name: Annotated[str | None, typer.Option("--logical-name")] = None,
    chunk_size: Annotated[int, typer.Option("--chunk-size")] = 1024 * 1024,
) -> None:
    """Observe local regular-file bytes without format parsing or network use."""
    try:
        subject = load_runtime(subject_path, ProductSubject)
        plan = build_payload_plan(
            subject,
            root_mode,
            logical_root,
            logical_name=logical_name,
            chunk_size=chunk_size,
        )
        manifest, _ = observe_payload(local_path, plan)
        validate_output_path(output, forbidden_inputs=(local_path, subject_path))
        atomic_write_text(
            output,
            pretty_payload_json(manifest),
            forbidden_inputs=(local_path, subject_path),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _payload_failure(exc)
    typer.echo(
        f"{manifest.completion_state.value} manifest={manifest.manifest_id} "
        "network=NONE model_execution=NOT_PERFORMED"
    )
    if manifest.completion_state.value != "COMPLETE_FOR_DECLARED_LOCAL_SCOPE":
        raise typer.Exit(code=1)


@payload_app.command("compare")
def payload_compare(
    expected_path: Annotated[Path, typer.Option("--expected", exists=True, dir_okay=False)],
    observed_path: Annotated[Path, typer.Option("--observed", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
) -> None:
    """Compare canonical expected and observed local payload manifests."""
    try:
        expected = load_payload(expected_path, PayloadExpectation)
        observed = load_payload(observed_path, ObservedPayloadManifest)
        comparison = compare_payload_manifests(expected, observed)
        validate_output_path(output, forbidden_inputs=(expected_path, observed_path))
        atomic_write_text(
            output,
            pretty_payload_json(comparison),
            forbidden_inputs=(expected_path, observed_path),
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _payload_failure(exc)
    typer.echo(f"{comparison.status.value} comparison={comparison.comparison_id}")
    if (
        comparison.status != PayloadComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE
        or comparison.expectation_scope.value != "COMPLETE_DECLARED_FILE_SET"
    ):
        raise typer.Exit(code=1)


@payload_app.command("verify")
def payload_verify(
    local_path: Annotated[Path, typer.Argument(exists=True)],
    subject_path: Annotated[Path, typer.Option("--subject", exists=True, dir_okay=False)],
    expected_path: Annotated[Path, typer.Option("--expected", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    root_mode: Annotated[PayloadRootMode, typer.Option("--root-mode")],
    logical_root: Annotated[str, typer.Option("--logical-root")],
    logical_name: Annotated[str | None, typer.Option("--logical-name")] = None,
    markdown: Annotated[Path | None, typer.Option("--markdown", dir_okay=False)] = None,
) -> None:
    """Observe and compare local bytes against an explicit local expectation."""
    try:
        subject = load_runtime(subject_path, ProductSubject)
        expectation = load_payload(expected_path, PayloadExpectation)
        plan = build_payload_plan(subject, root_mode, logical_root, logical_name=logical_name)
        manifest, execution = observe_payload(local_path, plan)
        comparison = compare_payload_manifests(expectation, manifest)
        evidence = evaluate_payload_evidence(
            manifest, execution.execution_id, comparison, expectation
        )
        report = build_payload_report(evidence, comparison)
        forbidden = (local_path, subject_path, expected_path)
        validate_output_path(output, forbidden_inputs=forbidden)
        atomic_write_text(output, pretty_payload_json(report), forbidden_inputs=forbidden)
        if markdown is not None:
            validate_output_path(markdown, forbidden_inputs=forbidden)
            atomic_write_text(markdown, render_payload_markdown(report), forbidden_inputs=forbidden)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _payload_failure(exc)
    typer.echo(
        f"{comparison.status.value}: LOCAL PAYLOAD BYTES MATCH ONLY THE DECLARED "
        "EXPECTATION SCOPE WHEN STATUS IS EXACT; network=NONE"
    )
    if (
        comparison.status != PayloadComparisonStatus.EXACT_MATCH_FOR_EXPECTATION_SCOPE
        or expectation.expectation_scope.value != "COMPLETE_DECLARED_FILE_SET"
    ):
        raise typer.Exit(code=1)


@payload_app.command("verify-manifest")
def payload_verify_manifest(
    manifest_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Reconstruct a canonical observed-manifest identity without touching payload bytes."""
    try:
        manifest = load_payload(manifest_path, ObservedPayloadManifest)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _payload_failure(exc)
    typer.echo(
        f"VALID_LOCAL_OBSERVATION manifest={manifest.manifest_id} "
        "semantic_correctness=NOT_EVALUATED"
    )
    if manifest.completion_state.value != "COMPLETE_FOR_DECLARED_LOCAL_SCOPE":
        raise typer.Exit(code=1)


def _reconciliation_failure(exc: Exception) -> None:
    typer.echo(f"ERROR reconciliation operation failed: {exc}", err=True)
    raise typer.Exit(code=2) from exc


def _emit_reconciliation(value: BaseModel, output: Path | None, inputs: tuple[Path, ...]) -> None:
    rendered = pretty_reconciliation_json(value)
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        validate_output_path(output, forbidden_inputs=inputs)
        atomic_write_text(output, rendered, forbidden_inputs=inputs)


@reconcile_app.command("import-snapshot")
def reconcile_import_snapshot(
    snapshot_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Validate and normalize an already collected provider-neutral snapshot."""
    try:
        snapshot = cast(
            RemoteSnapshotManifest,
            load_reconciliation(snapshot_path, RemoteSnapshotManifest),
        )
        _emit_reconciliation(snapshot, output, (snapshot_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _reconciliation_failure(exc)
    if snapshot.resolved_revision_kind.value not in {
        "IMMUTABLE_COMMIT",
        "IMMUTABLE_CONTENT_DIGEST",
        "PROVIDER_IMMUTABLE_SNAPSHOT",
    }:
        raise typer.Exit(code=1)


@reconcile_app.command("inspect-index")
def reconcile_inspect_index(
    index_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Safely inspect declarations in a bounded JSON shard index."""
    try:
        index = load_shard_index(index_path)
        typer.echo(
            json.dumps(
                {
                    "declared_shards": list(index.declared_shards),
                    "logical_mapping_count": len(index.mappings),
                    "metadata_present": index.metadata_present,
                    "source_sha256": index.source_sha256,
                    "limitations": [
                        "Declarations only; shard contents and tensor keys were not opened or "
                        "verified."
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _reconciliation_failure(exc)


@reconcile_app.command("shards")
def reconcile_shards(
    snapshot_path: Annotated[Path, typer.Option("--snapshot", exists=True, dir_okay=False)],
    index_path: Annotated[Path, typer.Option("--index", exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Build explicit shard topology without opening shard payloads."""
    try:
        snapshot = cast(
            RemoteSnapshotManifest,
            load_reconciliation(snapshot_path, RemoteSnapshotManifest),
        )
        topology = build_topology_from_indexes(snapshot, (load_shard_index(index_path),))
        _emit_reconciliation(topology, output, (snapshot_path, index_path))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _reconciliation_failure(exc)
    if (
        topology.status.value != "EXPLICIT_TOPOLOGY_AVAILABLE"
        or topology.missing_referenced_remote_members
    ):
        raise typer.Exit(code=1)


@reconcile_app.command("local")
def reconcile_local(
    expectation_path: Annotated[Path, typer.Option("--expectation", exists=True, dir_okay=False)],
    local_manifest_path: Annotated[
        Path, typer.Option("--local-manifest", exists=True, dir_okay=False)
    ],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Compare one exact remote expectation with one Phase 6A local manifest."""
    try:
        expectation = cast(
            RemoteSnapshotExpectation,
            load_reconciliation(expectation_path, RemoteSnapshotExpectation),
        )
        local = load_payload(local_manifest_path, ObservedPayloadManifest)
        comparison = compare_remote_to_local(expectation, local)
        _emit_reconciliation(comparison, output, (expectation_path, local_manifest_path))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _reconciliation_failure(exc)
    typer.echo(
        f"{comparison.status.value} payload_safety=NOT_ESTABLISHED",
        err=True,
    )
    if comparison.status.value != "EXACT_MATCH_FOR_RECONCILIATION_SCOPE":
        raise typer.Exit(code=1)


@reconcile_app.command("verify")
def reconcile_verify(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Reconstruct a canonical Phase 6B object identity offline."""
    try:
        value = load_any_reconciliation(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _reconciliation_failure(exc)
    typer.echo(
        f"VALID_CANONICAL_RECONCILIATION_OBJECT schema={value.model_dump(by_alias=True)['schema']} "
        "model_safety=NOT_VERIFIED"
    )
    if isinstance(value, RemoteLocalReconciliationComparison) and (
        value.status.value != "EXACT_MATCH_FOR_RECONCILIATION_SCOPE"
    ):
        raise typer.Exit(code=1)


@reconcile_app.command("collect-hf-metadata")
def reconcile_collect_hf_metadata(
    repository: Annotated[str, typer.Option("--repo")],
    revision: Annotated[str, typer.Option("--revision")],
    subject_path: Annotated[Path, typer.Option("--subject", exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    execution_output: Annotated[Path, typer.Option("--execution-output", dir_okay=False)],
    observed_at: Annotated[str, typer.Option("--observed-at")],
    raw_response_dir: Annotated[
        Path | None, typer.Option("--raw-response-dir", file_okay=False)
    ] = None,
    revision_kind: Annotated[
        RemoteRequestedRevisionKind, typer.Option("--revision-kind")
    ] = RemoteRequestedRevisionKind.BRANCH,
    allow_network: Annotated[bool, typer.Option("--allow-network")] = False,
    metadata_only: Annotated[bool, typer.Option("--metadata-only")] = False,
    no_payload: Annotated[bool, typer.Option("--no-payload")] = False,
) -> None:
    """Explicitly opt in to bounded public Hugging Face metadata collection."""
    try:
        if not allow_network:
            raise OmivInputError("bounded live collection requires --allow-network")
        if not metadata_only or not no_payload:
            raise OmivInputError("live collection requires --metadata-only and --no-payload")
        parts = repository.split("/")
        if len(parts) != 2 or not all(parts):
            raise OmivInputError("repository must be exactly namespace/name")
        subject = load_runtime(subject_path, ProductSubject)
        locator = build_remote_locator(
            subject,
            provider_kind=RemoteProviderKind.HUGGING_FACE,
            provider_instance="huggingface.co",
            namespace=parts[0],
            artifact_name=parts[1],
            artifact_kind="artifact.model-repository",
            requested_revision=revision,
            requested_revision_kind=revision_kind,
        )
        plan = build_remote_plan(
            locator,
            collection_mode=RemoteCollectionMode.BOUNDED_PUBLIC_METADATA_COLLECTION,
            adapter_id="omiv.adapter.huggingface-metadata",
            allowed_hosts=("huggingface.co",),
            available_at=observed_at,
            observed_at=observed_at,
        )
        raw_sink: Callable[[str, bytes], None] | None = None
        if raw_response_dir is not None:

            def write_raw(label: str, raw: bytes) -> None:
                try:
                    text = raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise OmivInputError("raw metadata response is not strict UTF-8") from exc
                atomic_write_text(raw_response_dir / f"{label}.json", text)

            raw_sink = write_raw
        execution, snapshot = collect_huggingface_metadata(
            locator,
            plan,
            observed_at=observed_at,
            raw_response_sink=raw_sink,
        )
        forbidden = (subject_path,)
        validate_output_path(output, forbidden_inputs=forbidden)
        validate_output_path(execution_output, forbidden_inputs=forbidden)
        if output == execution_output:
            raise OmivInputError("snapshot and execution outputs must be distinct")
        atomic_write_text(
            execution_output,
            pretty_reconciliation_json(execution),
            forbidden_inputs=forbidden,
        )
        atomic_write_text(
            output,
            pretty_reconciliation_json(snapshot),
            forbidden_inputs=forbidden,
        )
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _reconciliation_failure(exc)
    typer.echo(
        "PUBLIC_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD "
        f"revision={snapshot.resolved_revision} members={len(snapshot.members)} "
        f"requests={execution.request_count} response_bytes={execution.response_bytes} "
        "payload_bytes=0"
    )


def _quantization_failure(exc: Exception) -> None:
    typer.echo(f"ERROR quantization operation failed: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@quantization_app.command("inspect")
def quantization_inspect(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Strictly validate and canonically render one offline Phase 6C object."""
    try:
        value = load_quantization(input_path)
        rendered = pretty_quantization_json(value)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output, forbidden_inputs=(input_path,))
            atomic_write_text(output, rendered, forbidden_inputs=(input_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _quantization_failure(exc)


@quantization_app.command("sample")
def quantization_sample(
    source_tensor_id: Annotated[str, typer.Option("--source-tensor-id")],
    candidate_tensor_id: Annotated[str, typer.Option("--candidate-tensor-id")],
    population: Annotated[int, typer.Option("--population", min=0)],
    count: Annotated[int, typer.Option("--count", min=0)],
    seed: Annotated[str, typer.Option("--seed")],
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    maximum_count: Annotated[int, typer.Option("--maximum-count", min=0)] = 100_000,
) -> None:
    """Build a deterministic identity-bound sample without payload or network access."""
    try:
        sample = build_sample_definition(
            seed=seed,
            source_tensor_id=source_tensor_id,
            candidate_tensor_id=candidate_tensor_id,
            population_count=population,
            requested_count=count,
            maximum_count=maximum_count,
        )
        validate_output_path(output)
        atomic_write_text(output, pretty_quantization_json(sample))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _quantization_failure(exc)
    typer.echo(f"{sample.status} sample={sample.sample_id} actual={sample.actual_sample_count}")
    if sample.status == "LIMIT_EXCEEDED":
        raise typer.Exit(code=2)


@quantization_app.command("verify")
def quantization_verify(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Verify canonical identity and return a scope-qualified semantic exit status."""
    try:
        value = load_quantization(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _quantization_failure(exc)
    if isinstance(value, QuantizationFidelityEvidence):
        typer.echo(
            f"{value.overall_status.value} evidence={value.evidence_id} "
            f"numerical={value.numerical_status.value}"
        )
        if value.overall_status.value != "CONFORMS_FOR_DECLARED_SCOPE":
            raise typer.Exit(code=1)
    elif isinstance(value, QuantizationFidelityComparison):
        typer.echo(
            f"{value.structural_status.value} numerical={value.numerical_status.value} "
            f"scope={value.expectation_scope.value}"
        )
        if value.numerical_status not in {
            QuantizationNumericalStatus.EXACT_FOR_EVALUATED_SCOPE,
            QuantizationNumericalStatus.WITHIN_POLICY_FOR_EVALUATED_SCOPE,
            QuantizationNumericalStatus.SAMPLED_WITHIN_POLICY,
        }:
            raise typer.Exit(code=1)
    else:
        schema = value.model_dump(by_alias=True)["schema"]
        typer.echo(f"VALID_CANONICAL_QUANTIZATION_OBJECT schema={schema}")


@quantization_app.command("report")
def quantization_report(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Render a bounded derived report without changing canonical evidence identity."""
    try:
        value = load_quantization(input_path, QuantizationFidelityReport)
        report = cast(QuantizationFidelityReport, value)
        rendered = render_quantization_markdown(report)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output, forbidden_inputs=(input_path,))
            atomic_write_text(output, rendered, forbidden_inputs=(input_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _quantization_failure(exc)
    if report.overall_status.value != "CONFORMS_FOR_DECLARED_SCOPE":
        raise typer.Exit(code=1)


@quantization_app.command("verify-index")
def quantization_verify_index(
    index_path: Annotated[Path, typer.Option("--index", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Verify the external self-excluding Phase 6C artifact index."""
    try:
        index = cast(
            QuantizationArtifactIndex,
            load_quantization(index_path, QuantizationArtifactIndex),
        )
        verify_quantization_artifact_index(root, index)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _quantization_failure(exc)
    typer.echo(f"VALID_EXTERNAL_INDEX indexed_artifacts={len(index.entries)} self_inclusion=0")


@quantization_app.command("practice-xai")
def quantization_practice_xai(
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Reconstruct xAI readiness solely from committed Phase 6B fixtures."""
    try:
        readiness, _case_study = build_xai_readiness(Path.cwd())
        rendered = pretty_quantization_json(readiness)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output)
            atomic_write_text(output, rendered)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _quantization_failure(exc)
    typer.echo(
        f"{readiness.classification} payload_comparable_members=0 numerical_fidelity=NOT_EVALUATED",
        err=True,
    )
    raise typer.Exit(code=1)


def _tokenizer_configuration_failure(exc: Exception) -> None:
    typer.echo(f"ERROR tokenizer/configuration operation failed: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@tokenizer_configuration_app.command("inspect")
def tokenizer_configuration_inspect(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Strictly validate and canonically render one offline Phase 6D object."""
    try:
        value = load_tokenizer_configuration(input_path)
        rendered = pretty_tokenizer_configuration_json(value)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output, forbidden_inputs=(input_path,))
            atomic_write_text(output, rendered, forbidden_inputs=(input_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _tokenizer_configuration_failure(exc)


@tokenizer_configuration_app.command("verify")
def tokenizer_configuration_verify(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Verify canonical identity and return a scope-qualified semantic exit status."""
    try:
        value = load_tokenizer_configuration(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _tokenizer_configuration_failure(exc)
    if isinstance(value, TokenizerConfigurationParityEvidence):
        typer.echo(
            f"{value.overall_status.value} evidence={value.evidence_id} scope={value.scope.value}"
        )
        if value.overall_status != TokenizerParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE:
            raise typer.Exit(code=1)
    elif isinstance(value, TokenizerConfigurationComparison):
        typer.echo(f"{value.raw_status.value} scope={value.scope.value}")
        if value.raw_status != TokenizerParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE:
            raise typer.Exit(code=1)
    else:
        schema = value.model_dump(by_alias=True)["schema"]
        typer.echo(f"VALID_CANONICAL_TOKENIZER_CONFIGURATION_OBJECT schema={schema}")


@tokenizer_configuration_app.command("report")
def tokenizer_configuration_report(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Render a bounded derived report without executing assets or probes."""
    try:
        report = cast(
            TokenizerConfigurationReport,
            load_tokenizer_configuration(input_path, TokenizerConfigurationReport),
        )
        rendered = render_tokenizer_configuration_markdown(report)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output, forbidden_inputs=(input_path,))
            atomic_write_text(output, rendered, forbidden_inputs=(input_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _tokenizer_configuration_failure(exc)
    if report.overall_status != TokenizerParityStatus.PARITY_ESTABLISHED_FOR_DECLARED_SCOPE:
        raise typer.Exit(code=1)


@tokenizer_configuration_app.command("verify-index")
def tokenizer_configuration_verify_index(
    index_path: Annotated[Path, typer.Option("--index", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Verify the external self-excluding Phase 6D artifact index."""
    try:
        index = cast(
            TokenizerConfigurationArtifactIndex,
            load_tokenizer_configuration(index_path, TokenizerConfigurationArtifactIndex),
        )
        verify_tokenizer_configuration_artifact_index(root, index)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _tokenizer_configuration_failure(exc)
    typer.echo(f"VALID_EXTERNAL_INDEX indexed_artifacts={len(index.entries)} self_inclusion=0")


@tokenizer_configuration_app.command("practice-xai")
def tokenizer_configuration_practice_xai(
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Reconstruct xAI readiness solely from committed Phase 6B evidence."""
    try:
        readiness, _case_study = build_xai_tokenizer_configuration_readiness(Path.cwd())
        rendered = pretty_tokenizer_configuration_json(readiness)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output)
            atomic_write_text(output, rendered)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _tokenizer_configuration_failure(exc)
    typer.echo(
        f"{readiness.classification} payload_comparable_members=0 parity=NOT_EVALUATED",
        err=True,
    )
    raise typer.Exit(code=1)


def _runtime_resolution_failure(exc: Exception) -> None:
    typer.echo(f"ERROR runtime-resolution operation failed: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@runtime_resolution_app.command("inspect")
def runtime_resolution_inspect(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Strictly validate and render one offline Phase 6E object."""
    try:
        value = load_runtime_resolution(input_path)
        rendered = pretty_runtime_resolution_json(value)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output, forbidden_inputs=(input_path,))
            atomic_write_text(output, rendered, forbidden_inputs=(input_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _runtime_resolution_failure(exc)


@runtime_resolution_app.command("verify")
def runtime_resolution_verify(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Verify canonical identity and emit a scope-qualified exit status."""
    try:
        value = load_runtime_resolution(input_path)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _runtime_resolution_failure(exc)
    if isinstance(value, RuntimeResolutionParityEvidence):
        typer.echo(f"{value.status.value} evidence={value.evidence_id} scope={value.scope}")
        if value.status != RuntimeResolutionEvidenceStatus.SATISFACTORY_FOR_DECLARED_SCOPE:
            raise typer.Exit(code=1)
    else:
        schema = value.model_dump(by_alias=True)["schema"]
        typer.echo(f"VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema={schema}")


@runtime_resolution_app.command("report")
def runtime_resolution_report(
    input_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
) -> None:
    """Render a bounded derived report without inference or template execution."""
    try:
        report = cast(
            RuntimeResolutionReport,
            load_runtime_resolution(input_path, RuntimeResolutionReport),
        )
        rendered = render_runtime_resolution_markdown(report)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            validate_output_path(output, forbidden_inputs=(input_path,))
            atomic_write_text(output, rendered, forbidden_inputs=(input_path,))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _runtime_resolution_failure(exc)
    if report.status != RuntimeResolutionEvidenceStatus.SATISFACTORY_FOR_DECLARED_SCOPE:
        raise typer.Exit(code=1)


@runtime_resolution_app.command("verify-index")
def runtime_resolution_verify_index(
    index_path: Annotated[Path, typer.Option("--index", exists=True, dir_okay=False)],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = Path("."),
) -> None:
    """Verify the external self-excluding Phase 6E artifact index."""
    try:
        index = cast(
            RuntimeResolutionArtifactIndex,
            load_runtime_resolution(index_path, RuntimeResolutionArtifactIndex),
        )
        verify_runtime_resolution_artifact_index(root, index)
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _runtime_resolution_failure(exc)
    typer.echo(f"VALID_EXTERNAL_INDEX indexed_artifacts={len(index.entries)} self_inclusion=0")


@runtime_resolution_app.command("practice-xai")
def runtime_resolution_practice_xai() -> None:
    """Reconstruct provider-document-scoped xAI practice evidence offline."""
    try:
        subject = build_product_subject(
            ProductSubjectClass.DEPLOYMENT_PACKAGE,
            "runtime-resolution.phase6e-practice",
            synthetic_scope(
                project="project.runtime-resolution", environment="environment.offline"
            ),
        )
        _statements, readiness = build_xai_practice(Path.cwd(), subject)
        typer.echo(json.dumps(readiness.model_dump(mode="json", by_alias=True), sort_keys=True))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _runtime_resolution_failure(exc)
    raise typer.Exit(code=1)


@runtime_resolution_app.command("practice-anthropic")
def runtime_resolution_practice_anthropic() -> None:
    """Reconstruct Anthropic roadmap-scoped practice evidence offline."""
    try:
        subject = build_product_subject(
            ProductSubjectClass.DEPLOYMENT_PACKAGE,
            "runtime-resolution.phase6e-practice",
            synthetic_scope(
                project="project.runtime-resolution", environment="environment.offline"
            ),
        )
        _statement, readiness = build_anthropic_practice(Path.cwd(), subject)
        typer.echo(json.dumps(readiness.model_dump(mode="json", by_alias=True), sort_keys=True))
    except (OSError, UnicodeError, ValidationError, ValueError, OmivInputError) as exc:
        _runtime_resolution_failure(exc)
    raise typer.Exit(code=1)
